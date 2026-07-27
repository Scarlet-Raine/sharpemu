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
		// Forward disassembly from the resume RIP: reconstructs the live code
		// the guest executes AFTER the import returns.  The on-disk eboot text
		// can differ from the live guest (runtime-decoded/relocated code), so
		// decode the real bytes the CPU will run.  This reveals spin-loop bodies
		// that a static IDA view cannot show.
		if (string.Equals(
			Environment.GetEnvironmentVariable("SHARPEMU_PROBE_IMPORT_RET_FORWARD"),
			"1",
			StringComparison.Ordinal))
		{
			// Allow an explicit start address override so conditional-branch targets
			// unreachable by sequential fall-through can be disassembled live.
			var forwardStart = returnRip;
			var fwdAddrEnv = Environment.GetEnvironmentVariable("SHARPEMU_PROBE_IMPORT_RET_FORWARD_ADDR");
			if (!string.IsNullOrEmpty(fwdAddrEnv) &&
				ulong.TryParse(fwdAddrEnv.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? fwdAddrEnv[2..] : fwdAddrEnv,
					System.Globalization.NumberStyles.HexNumber, null, out var fwdAddrOverride))
			{
				forwardStart = fwdAddrOverride;
			}
			Console.Error.WriteLine(
				$"[LOADER][TRACE] Import#{dispatchIndex} forward disassembly @0x{forwardStart:X16}:");
			var forwardCursor = forwardStart;
			var forwardLimit = forwardStart + 0x400;
			var forwardVisited = new HashSet<ulong>();
			for (var forwardIndex = 0; forwardIndex < 96; forwardIndex++)
			{
				if (!forwardVisited.Add(forwardCursor))
				{
					Console.Error.WriteLine(
						$"[LOADER][TRACE]   0x{forwardCursor:X16}: <loop revisit>");
					break;
				}
				if (!IcedDecoder.TryReadGuestBytes(cpuContext.Memory, forwardCursor, 15, out var forwardBytes) ||
					!IcedDecoder.TryDecode(forwardCursor, forwardBytes, out var forwardInstruction) ||
					forwardInstruction.Length <= 0)
				{
					Console.Error.WriteLine(
						$"[LOADER][TRACE]   0x{forwardCursor:X16}: <undecodable>");
					break;
				}
				Console.Error.WriteLine(
					$"[LOADER][TRACE]   0x{forwardInstruction.Rip:X16}: {forwardInstruction.Text} " +
					$"bytes={IcedDecoder.FormatBytes(forwardInstruction.Bytes)}");
				var forwardMnemonic = forwardInstruction.Mnemonic;
				var nextCursor = forwardCursor + (ulong)forwardInstruction.Length;
				// Follow unconditional near/short jumps within the function so the
				// full spin-loop body is reconstructed.
				if (forwardInstruction.FlowControl == Iced.Intel.FlowControl.UnconditionalBranch &&
					forwardInstruction.NearBranchTarget is { } jumpTarget)
				{
					if (jumpTarget >= forwardStart && jumpTarget < forwardLimit)
					{
						forwardCursor = jumpTarget;
						continue;
					}
					break;
				}
				forwardCursor = nextCursor;
				if (string.Equals(forwardMnemonic, "Ret", StringComparison.OrdinalIgnoreCase) ||
					string.Equals(forwardMnemonic, "Int3", StringComparison.OrdinalIgnoreCase))
				{
					break;
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

		if (phase == "after" &&
			string.Equals(
				Environment.GetEnvironmentVariable("SHARPEMU_PROBE_IMPORT_RET_POINTER_GRAPH"),
				"1",
				StringComparison.Ordinal))
		{
			DumpImportReturnPointerGraph(cpuContext, metadata);
		}
	}

	private static void DumpImportReturnPointerGraph(CpuContext cpuContext, ulong root)
	{
		const int rootLength = 0x80;
		const int childLength = 0x40;
		Span<byte> rootBytes = stackalloc byte[rootLength];
		if (!cpuContext.Memory.TryRead(root, rootBytes))
		{
			return;
		}

		DumpPointerGraphLines("pointer-root", root, rootBytes);

		var dumped = new HashSet<ulong> { root };
		var pending = new Queue<(ulong Address, int Depth, string Via)>();
		EnqueueDataPointers(rootBytes, depth: 1, "root", dumped, pending);
		Span<byte> childBytes = stackalloc byte[childLength];
		while (pending.Count != 0 && dumped.Count <= 48)
		{
			var node = pending.Dequeue();
			if (!cpuContext.Memory.TryRead(node.Address, childBytes))
			{
				continue;
			}

			DumpPointerGraphLines(
				$"pointer depth={node.Depth} via={node.Via}",
				node.Address,
				childBytes);
			if (node.Depth < 3)
			{
				EnqueueDataPointers(
					childBytes,
					node.Depth + 1,
					$"0x{node.Address:X}",
					dumped,
					pending);
			}
		}
	}

	private static void EnqueueDataPointers(
		ReadOnlySpan<byte> bytes,
		int depth,
		string parent,
		HashSet<ulong> dumped,
		Queue<(ulong Address, int Depth, string Via)> pending)
	{
		for (var offset = 0; offset < bytes.Length; offset += sizeof(ulong))
		{
			var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(
				bytes.Slice(offset, sizeof(ulong)));
			var isGuestCode = value is > 0x8_0000_0000 and < 0x9_0000_0000;
			var isGuestData = value is >= 0x10_0000_0000 and < 0x100_0000_0000;
			if ((isGuestData || (isGuestCode && depth >= 3)) && dumped.Add(value))
			{
				pending.Enqueue((value, depth, $"{parent}+0x{offset:X}"));
			}
		}
	}

	private static void DumpPointerGraphLines(
		string label,
		ulong address,
		ReadOnlySpan<byte> bytes)
	{
		const int bytesPerLine = 4 * sizeof(ulong);
		for (var offset = 0; offset < bytes.Length; offset += bytesPerLine)
		{
			var line = bytes.Slice(offset, Math.Min(bytesPerLine, bytes.Length - offset));
			var values = new string[line.Length / sizeof(ulong)];
			for (var valueOffset = 0; valueOffset < line.Length; valueOffset += sizeof(ulong))
			{
				var value = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(
					line.Slice(valueOffset, sizeof(ulong)));
				values[valueOffset / sizeof(ulong)] = $"0x{value:X16}";
			}

			Console.Error.WriteLine(
				$"[LOADER][TRACE] import-return {label}=0x{address:X16}+0x{offset:X2} " +
				string.Join(' ', values));
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
		var mediaPumpOnly = string.Equals(
			Environment.GetEnvironmentVariable("SHARPEMU_SAMPLE_MEDIA_PUMP_ONLY"),
			"1",
			StringComparison.Ordinal);
		_guestRipSampler = new GuestRipSampler(
			this,
			armReturnRip,
			minimumRip,
			maximumRip,
			maximumSamples,
			mediaPumpOnly);
		Console.Error.WriteLine(
			$"[LOADER][TRACE] guest-rip-sampler configured: after_ret=0x{armReturnRip:X16} " +
			$"range=0x{minimumRip:X16}-0x{maximumRip:X16} max={maximumSamples} " +
			$"media_pump_only={mediaPumpOnly}");
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

	internal static bool ShouldArmGuestRipSampler(bool mediaPumpOnly, ulong currentThreadHandle) =>
		!mediaPumpOnly || GuestThreadExecution.IsMediaPumpThread(currentThreadHandle);

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
		private readonly bool _mediaPumpOnly;
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
			int maximumSamples,
			bool mediaPumpOnly)
		{
			_backend = backend;
			_armReturnRip = armReturnRip;
			_minimumRip = minimumRip;
			_maximumRip = maximumRip;
			_maximumSamples = maximumSamples;
			_mediaPumpOnly = mediaPumpOnly;
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
				!ShouldArmGuestRipSampler(
					_mediaPumpOnly,
					GuestThreadExecution.CurrentGuestThreadHandle) ||
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
						$"rcx=0x{snapshot.Rcx:X16}('{DescribeGuestText(snapshot.Rcx)}') " +
						$"rdx=0x{snapshot.Rdx:X16}('{DescribeGuestText(snapshot.Rdx)}') " +
						$"r12=0x{snapshot.R12:X16} r14=0x{snapshot.R14:X16} " +
						$"[r14]={DescribeGuestQwords(snapshot.R14, 12)} " +
						$"{DescribeWorkSource(snapshot.R14)} " +
						$"code=[{DescribeGuestCode(snapshot.Rip, 5)}]");
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

	// Diagnostic: dump up to 8 qwords at a guest address (guest VA == host VA) so
	// the sampler can reveal the polled object's fields. Returns "" when
	// unreadable. Only used by the guest-RIP sampler log.
	private static string DescribeGuestQwords(ulong address, int count)
	{
		if (count <= 0 || count > 12)
		{
			count = 12;
		}

		var builder = new System.Text.StringBuilder();
		for (var i = 0; i < count; i++)
		{
			if (i != 0)
			{
				builder.Append(' ');
			}

			if (TryReadStackU64(address + (ulong)(i * 8), out var value))
			{
				builder.Append("0x").Append(value.ToString("X16"));
			}
			else
			{
				builder.Append("--");
			}
		}

		return builder.ToString();
	}

	// Diagnostic: follow the media-ticker work-source pointer at [mediaObj+0x50],
	// read its vtable and the first 6 method pointers (relocated runtime VAs), so
	// method[4] (the dequeue/wait) can be mapped to IDA and decompiled.
	private static string DescribeWorkSource(ulong mediaObj)
	{
		if (!TryReadStackU64(mediaObj + 0x50, out var ws) || ws == 0)
		{
			return "ws=null";
		}

		var builder = new System.Text.StringBuilder();
		builder.Append("ws=0x").Append(ws.ToString("X16"));
		if (TryReadStackU64(ws, out var vt) && vt != 0)
		{
			builder.Append(" vt=0x").Append(vt.ToString("X16"));
			for (var i = 0; i < 6; i++)
			{
				builder.Append(" m").Append(i).Append("=0x");
				builder.Append(TryReadStackU64(vt + (ulong)(i * 8), out var m) ? m.ToString("X16") : "--");
			}
		}

		return builder.ToString();
	}

	// Diagnostic: disassemble a few instructions at a guest RIP (guest VA == host
	// VA) so the sampler shows the exact compare/branch and the object field
	// offset the media-tick loop tests. Returns "" when unreadable.
	private static string DescribeGuestCode(ulong rip, int instructionCount)
	{
		Span<byte> code = stackalloc byte[32];
		for (var i = 0; i < 4; i++)
		{
			if (!TryReadStackU64(rip + (ulong)(i * 8), out var value))
			{
				return string.Empty;
			}

			System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(code[(i * 8)..], value);
		}

		var builder = new System.Text.StringBuilder();
		var cursor = rip;
		var consumed = 0;
		for (var n = 0; n < instructionCount && consumed < 32; n++)
		{
			if (!SharpEmu.Core.Cpu.Disasm.IcedDecoder.TryDecode(cursor, code[consumed..], out var inst) ||
				inst.Length <= 0)
			{
				break;
			}

			if (n != 0)
			{
				builder.Append(" ; ");
			}

			builder.Append(inst.Text);
			consumed += inst.Length;
			cursor += (ulong)inst.Length;
		}

		return builder.ToString();
	}

	// Diagnostic: safely read a short string at a guest address (guest VA == host
	// VA). Tries UTF-16 (RAGE/Scaleform FName keys are wide) then ASCII; returns
	// "" when unreadable/non-textual. Only used by the guest-RIP sampler log.
	private unsafe static string DescribeGuestText(ulong address)
	{
		if (address <= 65536 || address >= 140737488355328L)
		{
			return string.Empty;
		}

		if (VirtualQuery((void*)address, out var info, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) == 0 ||
			info.State != 4096 || !IsReadableProtection(info.Protect))
		{
			return string.Empty;
		}

		var regionEnd = info.BaseAddress + info.RegionSize;
		if (regionEnd <= address)
		{
			return string.Empty;
		}

		var max = (int)Math.Min(96uL, regionEnd - address);
		Span<byte> bytes = stackalloc byte[96];
		bytes = bytes[..max];
		try
		{
			fixed (byte* destination = bytes)
			{
				Buffer.MemoryCopy((void*)address, destination, max, max);
			}
		}
		catch
		{
			return string.Empty;
		}

		// UTF-16: printable low byte with a zero high byte at even offsets.
		var wide = new System.Text.StringBuilder();
		for (var i = 0; i + 1 < max; i += 2)
		{
			var lo = bytes[i];
			var hi = bytes[i + 1];
			if (lo == 0 && hi == 0) break;
			if (hi != 0 || lo < 0x20 || lo > 0x7E) { wide.Clear(); break; }
			wide.Append((char)lo);
		}

		if (wide.Length >= 3)
		{
			return wide.ToString();
		}

		var ascii = new System.Text.StringBuilder();
		foreach (var b in bytes)
		{
			if (b == 0) break;
			if (b < 0x20 || b > 0x7E) { ascii.Clear(); break; }
			ascii.Append((char)b);
		}

		return ascii.Length >= 3 ? ascii.ToString() : string.Empty;
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
