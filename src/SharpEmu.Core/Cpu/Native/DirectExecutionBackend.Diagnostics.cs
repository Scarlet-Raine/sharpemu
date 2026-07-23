// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using SharpEmu.Core.Cpu.Disasm;
using SharpEmu.HLE;
using SharpEmu.Logging;

namespace SharpEmu.Core.Cpu.Native;

public sealed partial class DirectExecutionBackend
{
	private static readonly ConcurrentDictionary<ulong, byte> _knownExecutablePages = new();

	private static readonly bool _perfHleHistogram =
		string.Equals(System.Environment.GetEnvironmentVariable("SHARPEMU_PERF_HLE"), "1", System.StringComparison.Ordinal);
	private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _perfHleCounts = new();
	private static long _perfHleTotal;
	private static long _perfHleDispatchTicks;

	private static void RecordPerfHleDispatchTime(long ticks)
	{
		var total = System.Threading.Interlocked.Add(ref _perfHleDispatchTicks, ticks);
		var calls = System.Threading.Interlocked.Read(ref _perfHleTotal);
		if (calls > 0 && calls % 500000 == 0)
		{
			var avgUs = (double)total / System.Diagnostics.Stopwatch.Frequency * 1_000_000.0 / calls;
			System.Console.Error.WriteLine($"[PERF][HLE] managed_dispatch_avg={avgUs:F3}us total_managed_s={(double)total / System.Diagnostics.Stopwatch.Frequency:F2}");
		}
	}

	private static readonly bool _perfHleNoDict =
		string.Equals(System.Environment.GetEnvironmentVariable("SHARPEMU_PERF_HLE_NODICT"), "1", System.StringComparison.Ordinal);

	private static void RecordPerfHleCall(string name)
	{
		var total = System.Threading.Interlocked.Increment(ref _perfHleTotal);
		if (!_perfHleNoDict)
		{
			_perfHleCounts.AddOrUpdate(name, 1, static (_, v) => v + 1);
		}

		if (total % 500000 == 0 && !_perfHleNoDict)
		{
			// Snapshot via foreach (a safe moving enumerator) before sorting.
			// LINQ over a ConcurrentDictionary uses ICollection.CopyTo, which
			// throws ArgumentException if another thread adds a key between the
			// Count read and the copy — that exception was being swallowed into
			// a CPU_TRAP return and crashing the guest.
			var snapshot = new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, long>>(_perfHleCounts.Count + 16);
			foreach (var kvp in _perfHleCounts)
			{
				snapshot.Add(kvp);
			}

			var top = snapshot
				.OrderByDescending(kvp => kvp.Value)
				.Take(20)
				.Select(kvp => $"{kvp.Key}={kvp.Value}");
			System.Console.Error.WriteLine($"[PERF][HLE] total={total} top: {string.Join(", ", top)}");
		}
	}

	private void RecordRecentImportTrace(
		long dispatchIndex,
		string nid,
		ulong returnRip,
		ulong arg0,
		ulong arg1,
		ulong arg2)
	{
		var trace = _recentImportTrace;
		trace[_recentImportTraceWriteIndex] = new RecentImportTraceEntry(
			dispatchIndex,
			nid,
			returnRip,
			arg0,
			arg1,
			arg2,
			GuestThreadExecution.CurrentGuestThreadHandle,
			Environment.CurrentManagedThreadId);
		_recentImportTraceWriteIndex = (_recentImportTraceWriteIndex + 1) % trace.Length;
		if (_recentImportTraceCount < trace.Length)
		{
			_recentImportTraceCount++;
		}
	}

	private void DumpRecentImportTrace()
	{
		var trace = _recentImportTrace;
		if (trace is null || _recentImportTraceCount == 0)
		{
			return;
		}
		Log.Info($"   Recent import calls for managed={Environment.CurrentManagedThreadId} guest=0x{GuestThreadExecution.CurrentGuestThreadHandle:X16} ({_recentImportTraceCount}):");
		int num = (_recentImportTraceWriteIndex - _recentImportTraceCount + trace.Length) % trace.Length;
		for (int i = 0; i < _recentImportTraceCount; i++)
		{
			int num2 = (num + i) % trace.Length;
			var entry = trace[num2];
			if (!string.IsNullOrEmpty(entry.Nid))
			{
				Log.Info(
					$"     #{entry.DispatchIndex} managed={entry.ManagedThreadId} guest=0x{entry.GuestThreadHandle:X16} nid={entry.Nid} ret=0x{entry.ReturnRip:X16} " +
					$"rdi=0x{entry.Arg0:X16} rsi=0x{entry.Arg1:X16} rdx=0x{entry.Arg2:X16}");
			}
		}
	}

	private unsafe static List<ulong> ScanSuspiciousResolverPointers(ulong scanStart, ulong scanEnd)
	{
		if (scanEnd <= scanStart)
		{
			return new List<ulong>(0);
		}
		int num = 0;
		int num2 = 0;
		List<ulong> list = new List<ulong>(16);
		ulong num3 = scanStart;
		MEMORY_BASIC_INFORMATION64 lpBuffer;
		while (num3 < scanEnd && VirtualQuery((void*)num3, out lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) != 0)
		{
			ulong baseAddress = lpBuffer.BaseAddress;
			ulong num4 = baseAddress + lpBuffer.RegionSize;
			if (num4 <= num3)
			{
				break;
			}
			ulong value = Math.Max(num3, baseAddress);
			ulong num5 = Math.Min(num4, scanEnd);
			if (lpBuffer.State == 4096 && IsReadableProtection(lpBuffer.Protect) && !IsExecutableProtection(lpBuffer.Protect))
			{
				ulong num6 = AlignUp(value, 8uL);
				for (ulong num7 = num6; num7 + 8 <= num5; num7 += 8)
				{
					ulong value2 = *(ulong*)num7;
					if (IsUnresolvedSentinel(value2))
					{
						num++;
						list.Add(num7);
						if (num2 < 32)
						{
							Log.Info($"Suspicious unresolved pointer: slot=0x{num7:X16} value=0x{value2:X16}");
							num2++;
						}
						if (num >= 16384)
						{
							Log.Warning($"Suspicious unresolved pointer scan reached cap ({16384}); truncating.");
							return list;
						}
					}
				}
			}
			num3 = num5;
		}
		if (num != 0)
		{
			Log.Warning($"Suspicious unresolved pointer hits: {num}");
		}
		return list;
	}

	private void ProbeReturnRip(ulong returnRip, long dispatchIndex)
	{
		var cpuContext = ActiveCpuContext;
		if (cpuContext == null || returnRip == 0)
		{
			return;
		}
		const int preludeSize = 192;
		Span<byte> prelude = stackalloc byte[preludeSize];
		if (returnRip >= preludeSize && cpuContext.Memory.TryRead(returnRip - preludeSize, prelude))
		{
			Console.Error.WriteLine(
				$"[LOADER][TRACE] Import#{dispatchIndex} pre-return bytes @0x{returnRip - preludeSize:X16}: " +
				BitConverter.ToString(prelude.ToArray()).Replace("-", " "));

			List<DecodedInst>? bestCallChain = null;
			var preludeAddress = returnRip - preludeSize;
			for (var startOffset = 0; startOffset < preludeSize; startOffset++)
			{
				var cursor = preludeAddress + (ulong)startOffset;
				var candidate = new List<DecodedInst>();
				while (cursor < returnRip && candidate.Count < 96 &&
					IcedDecoder.TryReadGuestBytes(cpuContext.Memory, cursor, 15, out var instructionBytes) &&
					IcedDecoder.TryDecode(cursor, instructionBytes, out var instruction) &&
					instruction.Length > 0 &&
					cursor + (ulong)instruction.Length <= returnRip)
				{
					candidate.Add(instruction);
					cursor += (ulong)instruction.Length;
				}

				if (cursor == returnRip &&
					candidate.Count > 0 &&
					string.Equals(candidate[^1].Mnemonic, "Call", StringComparison.OrdinalIgnoreCase) &&
					(bestCallChain is null || candidate.Count > bestCallChain.Count))
				{
					bestCallChain = candidate;
				}
			}

			if (bestCallChain is not null)
			{
				Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} pre-return disassembly:");
				foreach (var instruction in bestCallChain.TakeLast(32))
				{
					Console.Error.WriteLine(
						$"[LOADER][TRACE]   0x{instruction.Rip:X16}: {instruction.Text} " +
						$"bytes={IcedDecoder.FormatBytes(instruction.Bytes)}");
					if (instruction.Bytes.Length == 5 && instruction.Bytes[0] == 0xE8)
					{
						var displacement = BitConverter.ToInt32(instruction.Bytes, 1);
						var target = unchecked((ulong)((long)instruction.Rip + instruction.Bytes.Length + displacement));
						if (IcedDecoder.TryReadGuestBytes(cpuContext.Memory, target, 32, out var directTargetBytes) &&
							IcedDecoder.TryDecode(target, directTargetBytes, out var targetInstruction))
						{
							Console.Error.WriteLine(
								$"[LOADER][TRACE]     call target 0x{target:X16}: {targetInstruction.Text} " +
								$"bytes={IcedDecoder.FormatBytes(targetInstruction.Bytes)}");
							if (targetInstruction.Bytes.Length == 6 && targetInstruction.Bytes[0] == 0xFF &&
								targetInstruction.Bytes[1] == 0x25)
							{
								var slotDisplacement = BitConverter.ToInt32(targetInstruction.Bytes, 2);
								var slot = unchecked((ulong)((long)target + 6 + slotDisplacement));
								if (cpuContext.TryReadUInt64(slot, out var slotValue))
								{
									Console.Error.WriteLine(
										$"[LOADER][TRACE]       thunk slot 0x{slot:X16} -> 0x{slotValue:X16}");
									for (int importIndex = 0; importIndex < _importEntries.Length; importIndex++)
									{
										if (_importEntries[importIndex].Address != slotValue)
										{
											continue;
										}

										var nid = _importEntries[importIndex].Nid;
										var exportName = _moduleManager.TryGetExport(nid, out var export)
											? $"{export.LibraryName}:{export.Name}"
											: "unresolved";
										Console.Error.WriteLine(
											$"[LOADER][TRACE]       thunk import: {exportName} ({nid})");
										break;
									}
								}
							}
						}
					}
				}
			}
		}
		Span<byte> destination = stackalloc byte[128];
		if (!cpuContext.Memory.TryRead(returnRip, destination))
		{
			Log.Debug($"Import#{dispatchIndex} return-rip probe: unreadable @0x{returnRip:X16}");
			return;
		}
		string value = BitConverter.ToString(destination.ToArray()).Replace("-", " ");
		Log.Debug($"Import#{dispatchIndex} return-rip bytes @0x{returnRip:X16}: {value}");
		if (destination[0] == byte.MaxValue && (destination[1] == 21 || destination[1] == 37))
		{
			int num = BitConverter.ToInt32(destination.Slice(2, 4));
			ulong num2 = returnRip + 6 + (ulong)num;
			if (cpuContext.TryReadUInt64(num2, out var value2))
			{
				Log.Debug($"Import#{dispatchIndex} return-rip slot: [0x{num2:X16}] = 0x{value2:X16}");
			}
		}
		if (destination[0] == 72 && destination[1] == 139 && destination[2] == 5)
		{
			int num3 = BitConverter.ToInt32(destination.Slice(3, 4));
			ulong num4 = returnRip + 7 + (ulong)num3;
			if (cpuContext.TryReadUInt64(num4, out var value3))
			{
				Log.Debug($"Import#{dispatchIndex} return-rip mov-slot: [0x{num4:X16}] = 0x{value3:X16}");
			}
		}
		for (int i = 0; i + 6 <= destination.Length; i++)
		{
			if (destination[i] == byte.MaxValue && (destination[i + 1] == 21 || destination[i + 1] == 37))
			{
				int num5 = BitConverter.ToInt32(destination.Slice(i + 2, 4));
				ulong num6 = returnRip + (ulong)i;
				ulong num7 = num6 + 6 + (ulong)num5;
				if (cpuContext.TryReadUInt64(num7, out var value4))
				{
					Log.Debug($"Import#{dispatchIndex} near-indirect @{num6:X16}: slot=0x{num7:X16} val=0x{value4:X16}");
				}
			}
		}
		Span<byte> targetBytes = stackalloc byte[32];
		for (int i = 0; i + 5 <= destination.Length; i++)
		{
			if (destination[i] != 0xE8)
			{
				continue;
			}

			int rel32 = BitConverter.ToInt32(destination.Slice(i + 1, 4));
			ulong callRip = returnRip + (ulong)i;
			ulong target = unchecked((ulong)((long)(callRip + 5) + rel32));
			Log.Debug($"Import#{dispatchIndex} near-call @{callRip:X16}: target=0x{target:X16}");
			for (int importIndex = 0; importIndex < _importEntries.Length; importIndex++)
			{
				if (_importEntries[importIndex].Address != target)
				{
					continue;
				}

				string nid = _importEntries[importIndex].Nid;
				if (_moduleManager.TryGetExport(nid, out var export))
				{
					Log.Debug(
						$"Import#{dispatchIndex} near-call import: index={importIndex} {export.LibraryName}:{export.Name} ({nid})");
				}
				else
				{
					Log.Debug(
						$"Import#{dispatchIndex} near-call import: index={importIndex} nid={nid}");
				}
				break;
			}

			if (cpuContext.Memory.TryRead(target, targetBytes))
			{
				Log.Debug(
					$"Import#{dispatchIndex} near-call target bytes @0x{target:X16}: " +
					BitConverter.ToString(targetBytes.ToArray()).Replace("-", " "));
				if (targetBytes[0] == 0xFF && targetBytes[1] == 0x25)
				{
					int slotRel32 = BitConverter.ToInt32(targetBytes.Slice(2, 4));
					ulong slot = unchecked((ulong)((long)(target + 6) + slotRel32));
					if (cpuContext.TryReadUInt64(slot, out var slotTarget))
					{
						Log.Debug(
							$"Import#{dispatchIndex} near-call PLT slot: [0x{slot:X16}] = 0x{slotTarget:X16}");
						for (int importIndex = 0; importIndex < _importEntries.Length; importIndex++)
						{
							if (_importEntries[importIndex].Address != slotTarget)
							{
								continue;
							}

							string nid = _importEntries[importIndex].Nid;
							if (_moduleManager.TryGetExport(nid, out var export))
							{
								Log.Debug(
									$"Import#{dispatchIndex} near-call PLT import: index={importIndex} {export.LibraryName}:{export.Name} ({nid})");
							}
							else
							{
								Log.Debug(
									$"Import#{dispatchIndex} near-call PLT import: index={importIndex} nid={nid}");
							}
							break;
						}
					}
				}
			}
		}
	}

	private void TraceImportReturnSnapshot(
		string phase,
		string nid,
		long dispatchIndex,
		CpuContext cpuContext)
	{
		var metadata = cpuContext[CpuRegister.R14];
		Console.Error.WriteLine(
			$"[LOADER][TRACE] import-return {phase}: #{dispatchIndex} nid={nid} " +
			$"rax=0x{cpuContext[CpuRegister.Rax]:X16} r12=0x{cpuContext[CpuRegister.R12]:X16} " +
			$"r13=0x{cpuContext[CpuRegister.R13]:X16} r14=0x{metadata:X16} " +
			$"r15=0x{cpuContext[CpuRegister.R15]:X16}");
		if (metadata < 0x10000)
		{
			return;
		}

		Span<byte> window = stackalloc byte[64];
		if (cpuContext.Memory.TryRead(metadata, window))
		{
			Console.Error.WriteLine(
				$"[LOADER][TRACE] import-return {phase}: metadata[0x{metadata:X16}]=" +
				BitConverter.ToString(window.ToArray()).Replace("-", " "));
		}
	}

	private void ConfigureGuestRipSampler()
	{
		StopGuestRipSampler();
		var armReturnRip = ParseOptionalHexAddress(
			Environment.GetEnvironmentVariable("SHARPEMU_SAMPLE_GUEST_AFTER_IMPORT_RET"));
		if (armReturnRip == 0)
		{
			return;
		}

		if (!OperatingSystem.IsWindows())
		{
			Console.Error.WriteLine(
				"[LOADER][WARN] Guest RIP sampling requires Windows thread-context capture.");
			return;
		}

		var minimumRip = ParseOptionalHexAddress(
			Environment.GetEnvironmentVariable("SHARPEMU_SAMPLE_GUEST_RIP_MIN"));
		var maximumRip = ParseOptionalHexAddress(
			Environment.GetEnvironmentVariable("SHARPEMU_SAMPLE_GUEST_RIP_MAX"));
		minimumRip = minimumRip == 0 ? 0x0000000800000000UL : minimumRip;
		maximumRip = maximumRip == 0 ? 0x0000001000000000UL : maximumRip;
		if (maximumRip <= minimumRip)
		{
			Console.Error.WriteLine(
				$"[LOADER][WARN] Guest RIP sampling range is invalid: 0x{minimumRip:X16}-0x{maximumRip:X16}");
			return;
		}

		var maximumSamples = ParsePositiveInt(
			Environment.GetEnvironmentVariable("SHARPEMU_SAMPLE_GUEST_MAX_SNAPSHOTS"),
			64,
			512);
		_guestRipSampler = new GuestRipSampler(this, armReturnRip, minimumRip, maximumRip, maximumSamples);
		Console.Error.WriteLine(
			$"[LOADER][TRACE] guest-rip-sampler configured: after_ret=0x{armReturnRip:X16} " +
			$"range=0x{minimumRip:X16}-0x{maximumRip:X16} max={maximumSamples}");
	}

	private void ArmGuestRipSampler(ulong returnRip)
	{
		_guestRipSampler?.Arm(returnRip, GetCurrentThreadId());
	}

	private void StopGuestRipSampler()
	{
		var sampler = Interlocked.Exchange(ref _guestRipSampler, null);
		sampler?.Dispose();
	}

	private static int ParsePositiveInt(string? value, int fallback, int maximum)
	{
		return int.TryParse(value, out var parsed) && parsed > 0
			? Math.Min(parsed, maximum)
			: fallback;
	}

	/// <summary>
	/// Captures a bounded series of worker-thread contexts after a selected HLE
	/// return. The sampler only reads contexts; it never changes debug registers,
	/// instruction bytes, or the resumed context.
	/// </summary>
	private sealed class GuestRipSampler : IDisposable
	{
		private readonly DirectExecutionBackend _backend;
		private readonly ulong _armReturnRip;
		private readonly ulong _minimumRip;
		private readonly ulong _maximumRip;
		private readonly int _maximumSamples;
		private readonly AutoResetEvent _armed = new(false);
		private readonly Thread _thread;
		private int _hostThreadId;
		private int _armedOnce;
		private volatile bool _stopping;

		public GuestRipSampler(
			DirectExecutionBackend backend,
			ulong armReturnRip,
			ulong minimumRip,
			ulong maximumRip,
			int maximumSamples)
		{
			_backend = backend;
			_armReturnRip = armReturnRip;
			_minimumRip = minimumRip;
			_maximumRip = maximumRip;
			_maximumSamples = maximumSamples;
			_thread = new Thread(ThreadMain)
			{
				IsBackground = true,
				Name = "GuestRipSampler",
			};
			_thread.Start();
		}

		public void Arm(ulong returnRip, uint hostThreadId)
		{
			if (returnRip != _armReturnRip ||
				Interlocked.CompareExchange(ref _armedOnce, 1, 0) != 0)
			{
				return;
			}

			Volatile.Write(ref _hostThreadId, unchecked((int)hostThreadId));
			Console.Error.WriteLine(
				$"[LOADER][TRACE] guest-rip-sampler armed: ret=0x{returnRip:X16} host_tid={hostThreadId}");
			_armed.Set();
		}

		private void ThreadMain()
		{
			_armed.WaitOne();
			if (_stopping)
			{
				return;
			}

			var hostThreadId = Volatile.Read(ref _hostThreadId);
			var maximumAttempts = Math.Max(_maximumSamples * 128, 1024);
			var captured = 0;
			var attempts = 0;
			while (!_stopping && captured < _maximumSamples && attempts++ < maximumAttempts)
			{
				if (TryCaptureHostThreadContext(hostThreadId, out var snapshot) &&
					snapshot.Rip >= _minimumRip && snapshot.Rip < _maximumRip)
				{
					captured++;
					Console.Error.WriteLine(
						$"[LOADER][TRACE] guest-rip-sample #{captured}: rip=0x{snapshot.Rip:X16} " +
						$"rsp=0x{snapshot.Rsp:X16} rbp=0x{snapshot.Rbp:X16} " +
						$"rax=0x{snapshot.Rax:X16} rdi=0x{snapshot.Rdi:X16} " +
						$"r12=0x{snapshot.R12:X16} r14=0x{snapshot.R14:X16}");
				}

				Thread.SpinWait(128);
			}

			Console.Error.WriteLine(
				$"[LOADER][TRACE] guest-rip-sampler complete: samples={captured} attempts={attempts}");
		}

		public void Dispose()
		{
			_stopping = true;
			_armed.Set();
			if (!ReferenceEquals(Thread.CurrentThread, _thread))
			{
				_thread.Join(500);
			}
			_armed.Dispose();
		}
	}

	private static bool IsUnresolvedSentinel(ulong value)
	{
		return value == 65534 || value == 4294967294u || value == 18446744073709551614uL;
	}

	private static ulong ParseOptionalHexAddress(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return 0;
		}

		var text = value.Trim();
		if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			text = text[2..];
		}

		return ulong.TryParse(
			text,
			System.Globalization.NumberStyles.HexNumber,
			System.Globalization.CultureInfo.InvariantCulture,
			out var address)
			? address
			: 0;
	}

	private static bool IsPlausibleReturnAddress(ulong address)
	{
		return address >= 12884901888L && address < 17592186044416L && !IsUnresolvedSentinel(address);
	}

	private static bool TryGetPlausibleReturnFromStack(ulong rsp, out ulong returnRip, out ulong nextRsp)
	{
		returnRip = 0uL;
		nextRsp = rsp;
		if (rsp <= 65536 || rsp >= 140737488355328L)
		{
			return false;
		}
		ulong num = rsp & 0xFFFFFFFFFFFFFFF8uL;
		ulong num2 = ((num >= 8) ? (num - 8) : num);
		for (int i = 0; i < 24; i++)
		{
			ulong num3 = num2 + (ulong)((long)i * 8L);
			if (TryReadStackU64(num3, out var value) && IsLikelyReturnAddress(value))
			{
				returnRip = value;
				nextRsp = num3 + 8;
				return true;
			}
		}
		for (ulong num4 = 1uL; num4 < 8; num4++)
		{
			for (int j = 0; j < 24; j++)
			{
				ulong num5 = rsp + num4 + (ulong)((long)j * 8L);
				if (TryReadStackU64(num5, out var value2) && IsLikelyReturnAddress(value2))
				{
					returnRip = value2;
					ulong num6 = num5 + 8;
					nextRsp = (num6 + 7) & 0xFFFFFFFFFFFFFFF8uL;
					return true;
				}
			}
		}
		return false;
	}

	private unsafe static bool TryReadStackU64(ulong address, out ulong value)
	{
		value = 0uL;
		if (address <= 65536 || address >= 140737488355328L)
		{
			return false;
		}
		if (VirtualQuery((void*)address, out var lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) == 0)
		{
			return false;
		}
		ulong num = lpBuffer.BaseAddress + lpBuffer.RegionSize;
		if (num < lpBuffer.BaseAddress || address > num - 8)
		{
			return false;
		}
		if (lpBuffer.State != 4096 || !IsReadableProtection(lpBuffer.Protect))
		{
			return false;
		}
		try
		{
			value = *(ulong*)address;
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsLikelyReturnAddress(ulong address)
	{
		if (!IsPlausibleReturnAddress(address))
		{
			return false;
		}
		return IsExecutableAddress(address);
	}

	private unsafe static bool IsExecutableAddress(ulong address)
	{
		var pageAddress = address & ~0xFFFUL;
		if (_knownExecutablePages.ContainsKey(pageAddress))
		{
			return true;
		}

		if (VirtualQuery((void*)address, out var lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) == 0)
		{
			return false;
		}

		var executable = lpBuffer.State == 4096 && IsExecutableProtection(lpBuffer.Protect);
		if (executable)
		{
			_knownExecutablePages.TryAdd(pageAddress, 0);
		}

		return executable;
	}

	private static ulong AlignUp(ulong value, ulong alignment)
	{
		if (alignment == 0)
		{
			return value;
		}
		ulong num = alignment - 1;
		return (value + num) & ~num;
	}

	private static bool IsReadableProtection(uint protect)
	{
		if ((protect & 0x100) != 0 || (protect & 1) != 0)
		{
			return false;
		}
		return (protect & 0xEE) != 0;
	}

	private static bool IsExecutableProtection(uint protect)
	{
		return (protect & 0xF0) != 0;
	}
}
