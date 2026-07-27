// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Iced.Intel;
using SharpEmu.HLE;

namespace SharpEmu.Libs.Kernel;

internal static class LiveFunctionExtractor
{
    internal const int MaximumCaptureBytes = 1024 * 1024;
    internal const int CodeWindowLength = 0x1000;
    internal const int MinimumCodeWindowLength = 0x800;
    internal const string PollerWaitCaptureKind = "poller-wait";
    internal const string TriggerSignalCaptureKind = "trigger-signal";
    private const int StackWindowLength = 0x1000;
    private const int MaximumRootSeeds = 32;
    private const int MaximumCallsPerRoot = 64;
    private const ulong GuestTextMinimum = 0x8_0000_0000;
    private const ulong GuestTextMaximum = 0x8_8000_0000;

    private static readonly object CaptureGate = new();
    private static readonly ConcurrentDictionary<string, byte> CapturesStarted = new();
    private static int _bytesCapturedAcrossKinds;

    internal static bool IsEnabled =>
        string.Equals(
            Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_CAPTURE"),
            "1",
            StringComparison.Ordinal);

    internal static bool IsTriggerCaptureEnabled =>
        IsEnabled &&
        string.Equals(
            Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_TRIGGER_CAPTURE"),
            "1",
            StringComparison.Ordinal);

    internal static void TryCapture(
        ICpuMemory memory,
        ulong resumeRsp,
        ulong returnRip,
        string captureKind = PollerWaitCaptureKind)
    {
        var enabled = captureKind == TriggerSignalCaptureKind
            ? IsTriggerCaptureEnabled
            : IsEnabled;
        if (!enabled || !CapturesStarted.TryAdd(captureKind, 0))
        {
            return;
        }

        lock (CaptureGate)
        {
            try
            {
                var configuredSeeds = ParseSeeds(
                    Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_SEEDS"));
                var totalBudget = ParseCaptureBudget(
                    Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_MAX_BYTES"));
                var requestedBudget = totalBudget - Volatile.Read(ref _bytesCapturedAcrossKinds);
                if (requestedBudget < MinimumCodeWindowLength)
                {
                    Console.Error.WriteLine(
                        $"[LIVE-CODE] kind={captureKind} skipped: shared byte budget exhausted");
                    return;
                }

                var capture = BuildCapture(
                    memory,
                    resumeRsp,
                    returnRip,
                    configuredSeeds,
                    requestedBudget,
                    captureKind);
                var manifest = WriteCapture(capture);
                Interlocked.Add(ref _bytesCapturedAcrossKinds, capture.BytesCaptured);
                Console.Error.WriteLine(
                    $"[LIVE-CODE] kind={captureKind} windows={capture.CodeWindows.Count} " +
                    $"bytes={capture.BytesCaptured} truncated={capture.Truncated} manifest={manifest}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"[LIVE-CODE] capture failed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    internal static LiveCodeCapture BuildCapture(
        ICpuMemory memory,
        ulong resumeRsp,
        ulong returnRip,
        IReadOnlyList<ulong> configuredSeeds,
        int byteBudget = MaximumCaptureBytes,
        string captureKind = PollerWaitCaptureKind)
    {
        ArgumentNullException.ThrowIfNull(memory);
        byteBudget = Math.Clamp(byteBudget, MinimumCodeWindowLength, MaximumCaptureBytes);

        var stackBytes = ReadBestEffortWindow(memory, resumeRsp, StackWindowLength, MinimumCodeWindowLength);
        var autoSeeds = FindStackCodePointers(stackBytes, returnRip);
        var frame = FindGlueFrame(memory, resumeRsp, stackBytes);
        var roots = configuredSeeds
            .Concat(autoSeeds)
            .Where(IsGuestTextAddress)
            .Distinct()
            .Take(MaximumRootSeeds)
            .ToArray();

        var windows = new List<LiveCodeWindow>();
        var queued = new Queue<PendingSeed>();
        foreach (var seed in roots)
        {
            queued.Enqueue(new PendingSeed(seed, 0, null));
        }

        var capturedBases = new HashSet<ulong>();
        var bytesCaptured = stackBytes.Length;
        var truncated = false;
        while (queued.Count != 0)
        {
            var pending = queued.Dequeue();
            var start = FindWindowStart(memory, pending.Address);
            if (!capturedBases.Add(start))
            {
                continue;
            }

            var remaining = byteBudget - bytesCaptured;
            if (remaining < MinimumCodeWindowLength)
            {
                truncated = true;
                break;
            }

            var desiredLength = Math.Min(CodeWindowLength, remaining);
            var bytes = ReadBestEffortWindow(memory, start, desiredLength, MinimumCodeWindowLength);
            if (bytes.Length < MinimumCodeWindowLength)
            {
                continue;
            }

            if (bytes.Length < CodeWindowLength)
            {
                truncated = true;
            }

            var calls = FindDirectCallTargets(start, bytes)
                .Where(IsGuestTextAddress)
                .Distinct()
                .Take(MaximumCallsPerRoot)
                .ToArray();
            windows.Add(new LiveCodeWindow(
                pending.Address,
                start,
                pending.Depth,
                pending.ParentSeed,
                bytes,
                calls));
            bytesCaptured += bytes.Length;

            if (pending.Depth == 0)
            {
                foreach (var target in calls)
                {
                    queued.Enqueue(new PendingSeed(target, 1, pending.Address));
                }
            }
        }

        if (queued.Count != 0)
        {
            truncated = true;
        }

        return new LiveCodeCapture(
            captureKind,
            resumeRsp,
            returnRip,
            stackBytes,
            frame,
            roots,
            windows,
            bytesCaptured,
            byteBudget,
            truncated);
    }

    internal static IReadOnlyList<ulong> ParseSeeds(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<ulong>();
        }

        var seeds = new List<ulong>();
        foreach (var part in value.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            var text = part.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? part[2..]
                : part;
            if (ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var seed) &&
                seed != 0)
            {
                seeds.Add(seed);
            }
        }

        return seeds;
    }

    internal static IReadOnlyList<ulong> FindDirectCallTargets(ulong windowBase, byte[] bytes)
    {
        var targets = new List<ulong>();
        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes));
        decoder.IP = windowBase;
        var windowEnd = windowBase + (ulong)bytes.Length;
        for (var decodedBytes = 0; decoder.IP < windowEnd && decodedBytes < bytes.Length;)
        {
            var instructionIp = decoder.IP;
            decoder.Decode(out var instruction);
            if (decoder.IP <= instructionIp)
            {
                break;
            }

            decodedBytes += checked((int)(decoder.IP - instructionIp));
            if (instruction.Code == Code.INVALID)
            {
                continue;
            }

            if (instruction.Mnemonic == Mnemonic.Call &&
                instruction.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
            {
                targets.Add(instruction.NearBranchTarget);
            }
        }

        return targets;
    }

    private static int ParseCaptureBudget(string? value)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var requested)
            ? Math.Clamp(requested, MinimumCodeWindowLength, MaximumCaptureBytes)
            : MaximumCaptureBytes;
    }

    private static byte[] ReadBestEffortWindow(
        ICpuMemory memory,
        ulong start,
        int desiredLength,
        int minimumLength)
    {
        var length = desiredLength & ~0xFF;
        while (length >= minimumLength)
        {
            var bytes = new byte[length];
            if (memory.TryRead(start, bytes))
            {
                return bytes;
            }

            length -= 0x100;
        }

        return Array.Empty<byte>();
    }

    private static ulong FindWindowStart(ICpuMemory memory, ulong seed)
    {
        var fallback = seed >= 0x100 ? (seed - 0x100) & ~0xFUL : seed & ~0xFUL;
        var scanStart = seed >= 0x400 ? seed - 0x400 : 0;
        var scanLength = checked((int)(seed - scanStart + 1));
        var bytes = new byte[scanLength];
        if (!memory.TryRead(scanStart, bytes))
        {
            return fallback;
        }

        for (var offset = bytes.Length - 1; offset >= 0; offset--)
        {
            if (LooksLikeFunctionPrologue(bytes.AsSpan(offset)))
            {
                return scanStart + (ulong)offset;
            }
        }

        return fallback;
    }

    private static bool LooksLikeFunctionPrologue(ReadOnlySpan<byte> bytes)
    {
        return bytes.StartsWith(new byte[] { 0x55, 0x48, 0x89, 0xE5 }) ||
            bytes.StartsWith(new byte[] { 0xF3, 0x0F, 0x1E, 0xFA, 0x55 }) ||
            bytes.StartsWith(new byte[] { 0x40, 0x53, 0x48, 0x83, 0xEC }) ||
            bytes.StartsWith(new byte[] { 0x48, 0x89, 0x5C, 0x24 }) ||
            bytes.StartsWith(new byte[] { 0x48, 0x83, 0xEC }) ||
            bytes.StartsWith(new byte[] { 0x48, 0x81, 0xEC });
    }

    private static IReadOnlyList<ulong> FindStackCodePointers(byte[] stackBytes, ulong returnRip)
    {
        var seeds = new List<ulong>();
        if (IsGuestTextAddress(returnRip))
        {
            seeds.Add(returnRip);
        }

        for (var offset = 0; offset + sizeof(ulong) <= stackBytes.Length; offset += sizeof(ulong))
        {
            var candidate = BinaryPrimitives.ReadUInt64LittleEndian(stackBytes.AsSpan(offset, sizeof(ulong)));
            if (IsGuestTextAddress(candidate))
            {
                seeds.Add(candidate);
            }
        }

        return seeds.Distinct().Take(MaximumRootSeeds).ToArray();
    }

    private static LiveCodeFrame? FindGlueFrame(ICpuMemory memory, ulong resumeRsp, byte[] stackBytes)
    {
        Span<byte> valueBytes = stackalloc byte[sizeof(ulong)];
        for (var offset = 0; offset + 2 * sizeof(ulong) <= stackBytes.Length; offset += sizeof(ulong))
        {
            var framePointer = BinaryPrimitives.ReadUInt64LittleEndian(
                stackBytes.AsSpan(offset, sizeof(ulong)));
            var frameReturn = BinaryPrimitives.ReadUInt64LittleEndian(
                stackBytes.AsSpan(offset + sizeof(ulong), sizeof(ulong)));
            if (framePointer <= resumeRsp ||
                framePointer >= resumeRsp + 0x8000 ||
                !IsGuestTextAddress(frameReturn))
            {
                continue;
            }

            var slots = new Dictionary<string, LiveCodeSlot>();
            foreach (var displacement in new[] { -0x90, -0x80, -0x78, -0x70 })
            {
                var address = unchecked((ulong)((long)framePointer + displacement));
                if (!memory.TryRead(address, valueBytes))
                {
                    continue;
                }

                var value = BinaryPrimitives.ReadUInt64LittleEndian(valueBytes);
                slots[$"rbp-{Math.Abs(displacement):X}"] = new LiveCodeSlot(
                    address,
                    value,
                    BitConverter.Int64BitsToDouble(unchecked((long)value)));
            }

            return new LiveCodeFrame(framePointer, frameReturn, slots);
        }

        return null;
    }

    private static bool IsGuestTextAddress(ulong address)
    {
        return address > GuestTextMinimum && address < GuestTextMaximum;
    }

    private static string WriteCapture(LiveCodeCapture capture)
    {
        var outputRoot = Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_OUTPUT");
        if (string.IsNullOrWhiteSpace(outputRoot))
        {
            outputRoot = Path.Combine(Environment.CurrentDirectory, "artifacts", "live-code");
        }

        var configuredRunId = Environment.GetEnvironmentVariable("SHARPEMU_LIVE_CODE_RUN_ID");
        var runId = SanitizeRunId(configuredRunId);
        if (string.IsNullOrEmpty(runId))
        {
            runId = $"{DateTime.UtcNow:yyyyMMddTHHmmssfffZ}-p{Environment.ProcessId}";
        }

        if (capture.CaptureKind != PollerWaitCaptureKind)
        {
            runId = $"{runId}-{SanitizeRunId(capture.CaptureKind)}";
        }

        return WriteCapture(capture, outputRoot, runId);
    }

    internal static string WriteCapture(LiveCodeCapture capture, string outputRoot, string runId)
    {
        ArgumentNullException.ThrowIfNull(capture);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputRoot);
        runId = SanitizeRunId(runId);
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);

        var runDirectory = Path.Combine(Path.GetFullPath(outputRoot), runId);
        Directory.CreateDirectory(runDirectory);

        var stackFile = "stack.bin";
        File.WriteAllBytes(Path.Combine(runDirectory, stackFile), capture.StackBytes);
        var manifestWindows = new List<object>();
        foreach (var window in capture.CodeWindows)
        {
            var file = $"code-d{window.Depth}-0x{window.GuestBase:X16}.bin";
            File.WriteAllBytes(Path.Combine(runDirectory, file), window.Bytes);
            manifestWindows.Add(new
            {
                seed = $"0x{window.Seed:X}",
                guest_base = $"0x{window.GuestBase:X}",
                length = window.Bytes.Length,
                depth = window.Depth,
                parent_seed = window.ParentSeed is ulong parent ? $"0x{parent:X}" : null,
                direct_calls = window.DirectCalls.Select(target => $"0x{target:X}").ToArray(),
                file,
            });
        }

        var manifest = new
        {
            format_version = 1,
            run_id = runId,
            capture_kind = capture.CaptureKind,
            created_utc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            process_id = Environment.ProcessId,
            resume_rsp = $"0x{capture.ResumeRsp:X}",
            return_rip = $"0x{capture.ReturnRip:X}",
            frame = capture.Frame is null
                ? null
                : new
                {
                    rbp = $"0x{capture.Frame.FramePointer:X}",
                    return_rip = $"0x{capture.Frame.ReturnRip:X}",
                    slots = capture.Frame.Slots.ToDictionary(
                        pair => pair.Key,
                        pair => new
                        {
                            address = $"0x{pair.Value.Address:X}",
                            value_u64 = $"0x{pair.Value.Value:X16}",
                            value_f64 = pair.Value.DoubleValue,
                        }),
                },
            stack = new
            {
                guest_base = $"0x{capture.ResumeRsp:X}",
                length = capture.StackBytes.Length,
                file = stackFile,
            },
            seeds = capture.RootSeeds.Select(seed => $"0x{seed:X}").ToArray(),
            byte_budget = capture.ByteBudget,
            bytes_captured = capture.BytesCaptured,
            truncated = capture.Truncated,
            windows = manifestWindows,
        };

        var manifestPath = Path.Combine(runDirectory, "manifest.json");
        File.WriteAllText(
            manifestPath,
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
        return manifestPath;
    }

    private static string SanitizeRunId(string? runId)
    {
        if (string.IsNullOrWhiteSpace(runId))
        {
            return string.Empty;
        }

        var invalid = Path.GetInvalidFileNameChars();
        return new string(runId.Where(character => !invalid.Contains(character)).ToArray());
    }

    private sealed record PendingSeed(ulong Address, int Depth, ulong? ParentSeed);
}

internal sealed record LiveCodeCapture(
    string CaptureKind,
    ulong ResumeRsp,
    ulong ReturnRip,
    byte[] StackBytes,
    LiveCodeFrame? Frame,
    IReadOnlyList<ulong> RootSeeds,
    IReadOnlyList<LiveCodeWindow> CodeWindows,
    int BytesCaptured,
    int ByteBudget,
    bool Truncated);

internal sealed record LiveCodeWindow(
    ulong Seed,
    ulong GuestBase,
    int Depth,
    ulong? ParentSeed,
    byte[] Bytes,
    IReadOnlyList<ulong> DirectCalls);

internal sealed record LiveCodeFrame(
    ulong FramePointer,
    ulong ReturnRip,
    IReadOnlyDictionary<string, LiveCodeSlot> Slots);

internal sealed record LiveCodeSlot(ulong Address, ulong Value, double DoubleValue);
