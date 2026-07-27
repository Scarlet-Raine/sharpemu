// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

public sealed class VehEntryLockEncodingTests
{
    // Regression guard for the VEH managed-entry spinlock acquire. The lock word
    // is addressed through r9 by the whole sequence; the acquire compare-exchange
    // must therefore encode `lock cmpxchg [r9], r10`. Emitting REX 0x4C instead of
    // 0x4D drops REX.B and silently retargets the CAS at [rcx] (stack garbage),
    // which spins forever on a free lock — the movie/cutscene freeze.
    [Fact]
    public unsafe void LockCmpxchgAcquireTargetsR9NotRcx()
    {
        Span<byte> expected = [0xF0, 0x4D, 0x0F, 0xB1, 0x11];
        byte* code = stackalloc byte[16];
        int offset = 0;

        DirectExecutionBackend.EmitLockCmpxchgR9WithR10(code, ref offset);

        Assert.Equal(expected.Length, offset);
        for (var i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i], code[i]);
        }

        // REX byte: W(0x08) for 64-bit, R(0x04) selects r10 source, B(0x01)
        // selects r9 as the memory base. REX.B set is what distinguishes the
        // correct [r9] target from the buggy [rcx].
        const byte rex = 0x4D;
        Assert.Equal(rex, code[1]);
        Assert.True((code[1] & 0x01) != 0, "REX.B must be set so the CAS targets [r9], not [rcx].");
        Assert.True((code[1] & 0x04) != 0, "REX.R must be set so the CAS source is r10.");
    }
}
