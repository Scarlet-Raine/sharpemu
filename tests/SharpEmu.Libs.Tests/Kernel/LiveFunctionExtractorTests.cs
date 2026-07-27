// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using System.Text.Json;
using SharpEmu.HLE;
using SharpEmu.Libs.Kernel;
using Xunit;

namespace SharpEmu.Libs.Tests.Kernel;

public sealed class LiveFunctionExtractorTests
{
    [Fact]
    public void ParseSeedsAcceptsCommonHexSeparators()
    {
        var seeds = LiveFunctionExtractor.ParseSeeds("0x800001000, 800002000;0X800003000");

        Assert.Equal(
            [0x8_0000_1000UL, 0x8_0000_2000UL, 0x8_0000_3000UL],
            seeds);
    }

    [Fact]
    public void BuildCaptureFollowsDirectCallsOneLevelAndRecordsFrameSlots()
    {
        const ulong rootBase = 0x8_0000_1000;
        const ulong rootSeed = rootBase + 0x100;
        const ulong childBase = 0x8_0000_4000;
        const ulong childSeed = childBase + 0x100;
        const ulong grandchildSeed = 0x8_0000_7100;
        const ulong stackBase = 0x1_F000_0000;
        const ulong framePointer = stackBase + 0x300;

        var memory = new SparseCpuMemory();
        var rootCode = memory.AddRegion(rootBase, 0x1000);
        var childCode = memory.AddRegion(childBase, 0x1000);
        var stack = memory.AddRegion(stackBase, 0x1000);
        WriteNearCall(rootCode, rootBase, 0x120, childSeed);
        WriteNearCall(childCode, childBase, 0x140, grandchildSeed);

        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x20), framePointer);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x28), rootSeed);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x280), 0x1111);
        BinaryPrimitives.WriteUInt64LittleEndian(stack.AsSpan(0x290), 0x2222);

        var capture = LiveFunctionExtractor.BuildCapture(
            memory,
            stackBase,
            rootSeed,
            [rootSeed],
            0x3000);

        Assert.False(capture.Truncated);
        Assert.Equal(0x3000, capture.BytesCaptured);
        Assert.Collection(
            capture.CodeWindows.OrderBy(window => window.Depth),
            root =>
            {
                Assert.Equal(0, root.Depth);
                Assert.Equal(rootBase, root.GuestBase);
                Assert.Contains(childSeed, root.DirectCalls);
            },
            child =>
            {
                Assert.Equal(1, child.Depth);
                Assert.Equal(childBase, child.GuestBase);
                Assert.Contains(grandchildSeed, child.DirectCalls);
            });
        Assert.NotNull(capture.Frame);
        Assert.Equal(framePointer, capture.Frame.FramePointer);
        Assert.Equal(0x1111UL, capture.Frame.Slots["rbp-80"].Value);
        Assert.Equal(0x2222UL, capture.Frame.Slots["rbp-70"].Value);
    }

    [Fact]
    public void BuildCaptureHonorsRawByteBudget()
    {
        const ulong codeBase = 0x8_0000_1000;
        const ulong stackBase = 0x1_F000_0000;
        var memory = new SparseCpuMemory();
        memory.AddRegion(codeBase, 0x1000);
        memory.AddRegion(stackBase, 0x1000);

        var capture = LiveFunctionExtractor.BuildCapture(
            memory,
            stackBase,
            codeBase + 0x100,
            [codeBase + 0x100],
            0x1800);

        Assert.True(capture.Truncated);
        Assert.Equal(0x1800, capture.BytesCaptured);
        Assert.Single(capture.CodeWindows);
        Assert.Equal(0x800, capture.CodeWindows[0].Bytes.Length);
    }

    [Fact]
    public void WriteCaptureCreatesBinaryWindowsAndSelfDescribingManifest()
    {
        const ulong codeBase = 0x8_0000_1000;
        const ulong stackBase = 0x1_F000_0000;
        var memory = new SparseCpuMemory();
        memory.AddRegion(codeBase, 0x1000);
        memory.AddRegion(stackBase, 0x1000);
        var capture = LiveFunctionExtractor.BuildCapture(
            memory,
            stackBase,
            codeBase + 0x100,
            [codeBase + 0x100],
            0x2000,
            LiveFunctionExtractor.TriggerSignalCaptureKind);
        var outputRoot = Path.Combine(
            AppContext.BaseDirectory,
            $"live-code-test-{Guid.NewGuid():N}");

        try
        {
            var manifestPath = LiveFunctionExtractor.WriteCapture(capture, outputRoot, "unit-run");

            Assert.True(File.Exists(manifestPath));
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = document.RootElement;
            Assert.Equal("unit-run", root.GetProperty("run_id").GetString());
            Assert.Equal(
                LiveFunctionExtractor.TriggerSignalCaptureKind,
                root.GetProperty("capture_kind").GetString());
            Assert.Equal(0x2000, root.GetProperty("bytes_captured").GetInt32());
            var window = Assert.Single(root.GetProperty("windows").EnumerateArray());
            Assert.Equal($"0x{codeBase:X}", window.GetProperty("guest_base").GetString());
            Assert.True(File.Exists(Path.Combine(
                Path.GetDirectoryName(manifestPath)!,
                window.GetProperty("file").GetString()!)));
            Assert.True(File.Exists(Path.Combine(
                Path.GetDirectoryName(manifestPath)!,
                root.GetProperty("stack").GetProperty("file").GetString()!)));
        }
        finally
        {
            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, recursive: true);
            }
        }
    }

    private static void WriteNearCall(byte[] code, ulong codeBase, int offset, ulong target)
    {
        code[offset] = 0xE8;
        var nextRip = codeBase + (ulong)offset + 5;
        var displacement = checked((int)((long)target - (long)nextRip));
        BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(offset + 1), displacement);
    }

    private sealed class SparseCpuMemory : ICpuMemory
    {
        private readonly List<(ulong Base, byte[] Bytes)> _regions = [];

        public byte[] AddRegion(ulong baseAddress, int length)
        {
            var bytes = new byte[length];
            _regions.Add((baseAddress, bytes));
            return bytes;
        }

        public bool TryRead(ulong virtualAddress, Span<byte> destination)
        {
            foreach (var region in _regions)
            {
                if (virtualAddress < region.Base)
                {
                    continue;
                }

                var offset = virtualAddress - region.Base;
                if (offset + (ulong)destination.Length > (ulong)region.Bytes.Length)
                {
                    continue;
                }

                region.Bytes.AsSpan((int)offset, destination.Length).CopyTo(destination);
                return true;
            }

            return false;
        }

        public bool TryWrite(ulong virtualAddress, ReadOnlySpan<byte> source)
        {
            foreach (var region in _regions)
            {
                if (virtualAddress < region.Base)
                {
                    continue;
                }

                var offset = virtualAddress - region.Base;
                if (offset + (ulong)source.Length > (ulong)region.Bytes.Length)
                {
                    continue;
                }

                source.CopyTo(region.Bytes.AsSpan((int)offset, source.Length));
                return true;
            }

            return false;
        }
    }
}
