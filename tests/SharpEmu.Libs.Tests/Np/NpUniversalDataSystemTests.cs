// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.Libs.Np;
using Xunit;

namespace SharpEmu.Libs.Tests.Np;

// sceNpUniversalDataSystemCreateContext takes a pointer-sized out-slot that
// callers seed with -1 before the call. A partial (4-byte) handle write left
// the stale high dword in place; when the slot previously held a heap pointer
// the mangled value later reached the guest allocator as an invalid free
// (observed as FMallocBinned3 "free an unrecognized block 0x1000000001").
// These tests pin the full-slot overwrite behaviour.
public sealed class NpUniversalDataSystemTests
{
    private const ulong BaseAddress = 0x1_0000_0000;
    private const int MemorySize = 0x1000;

    [Fact]
    public void CreateContext_SlotSeededWithSentinel_OverwritesAllEightBytes()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);

        const ulong slotAddress = BaseAddress + 0x100;
        WriteUInt64(memory, slotAddress, ulong.MaxValue);

        ctx[CpuRegister.Rdi] = slotAddress;
        var result = NpUniversalDataSystemExports.NpUniversalDataSystemCreateContext(ctx);
        Assert.Equal(0, result);

        var handle = ReadUInt64(memory, slotAddress);
        Assert.NotEqual(0UL, handle);
        // No byte of the -1 seed may survive the write.
        Assert.Equal(0UL, handle & 0xFFFF_FFFF_0000_0000);
    }

    [Fact]
    public void CreateContext_SlotSeededWithStaleHeapPointer_LeavesNoStaleHighDword()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);

        // A stale allocator pointer in the 0x10_0000_0000 band; a 4-byte write
        // of a small handle would turn this into 0x00000010_0000000N.
        const ulong slotAddress = BaseAddress + 0x200;
        const ulong stalePointer = 0x0000_0010_DEAD_BEEF;
        WriteUInt64(memory, slotAddress, stalePointer);

        ctx[CpuRegister.Rdi] = slotAddress;
        var result = NpUniversalDataSystemExports.NpUniversalDataSystemCreateContext(ctx);
        Assert.Equal(0, result);

        var handle = ReadUInt64(memory, slotAddress);
        Assert.NotEqual(0UL, handle);
        Assert.Equal(0UL, handle & 0xFFFF_FFFF_0000_0000);
    }

    [Fact]
    public void CreateContext_ConsecutiveCalls_ReturnDistinctHandles()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);

        const ulong slotAddress = BaseAddress + 0x300;

        ctx[CpuRegister.Rdi] = slotAddress;
        Assert.Equal(0, NpUniversalDataSystemExports.NpUniversalDataSystemCreateContext(ctx));
        var first = ReadUInt64(memory, slotAddress);

        Assert.Equal(0, NpUniversalDataSystemExports.NpUniversalDataSystemCreateContext(ctx));
        var second = ReadUInt64(memory, slotAddress);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void CreateContext_NullSlot_ReturnsOkWithoutWriting()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);

        ctx[CpuRegister.Rdi] = 0;
        Assert.Equal(0, NpUniversalDataSystemExports.NpUniversalDataSystemCreateContext(ctx));
    }

    private static ulong ReadUInt64(FakeCpuMemory memory, ulong address)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(memory.TryRead(address, buffer));
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer);
    }

    private static void WriteUInt64(FakeCpuMemory memory, ulong address, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        Assert.True(memory.TryWrite(address, buffer));
    }
}
