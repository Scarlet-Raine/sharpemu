// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System;
using System.Runtime.InteropServices;
using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

public sealed class FaultInstructionCaptureTests
{
    [Fact]
    public unsafe void ReadableMappedWindow_IsCapturedWithoutAllocation()
    {
        const int windowSize = 16;
        var memory = NativeMemory.Alloc(windowSize);
        try
        {
            var source = new Span<byte>(memory, windowSize);
            for (var i = 0; i < source.Length; i++)
            {
                source[i] = (byte)(0x80 + i);
            }

            Span<byte> captured = stackalloc byte[windowSize];
            Assert.True(DirectExecutionBackend.TryCaptureFaultInstructionWindow(
                unchecked((ulong)memory),
                captured));
            Assert.True(source.SequenceEqual(captured));
        }
        finally
        {
            NativeMemory.Free(memory);
        }
    }

    [Fact]
    public void InvalidLowAddress_IsRejected()
    {
        Span<byte> captured = stackalloc byte[16];

        Assert.False(DirectExecutionBackend.TryCaptureFaultInstructionWindow(0x1000, captured));
    }
}
