// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.Libs.Kernel;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// A RELEASE_MEM packet with the interrupt field set asks the CP to raise an
// end-of-pipe interrupt after the release action lands; the AGC driver routes
// it to the eq event registered under the packet's interrupt context id.
// Titles pace their frame loop on this event (GTA SA DE requests interrupt=2
// with context id 0 on its per-frame fence and registers eventId 0), so the
// delivery must hit exactly the matching ident and nothing else — landing it
// on a completion ident would inflate the guest's retire count (see
// AgcVblankEventTests for that failure mode).
// The equeue registry is process-global static state, so this class shares
// the collection that serializes graphics-equeue tests.
[Collection("agc-equeue-global-state")]
public sealed class AgcEopInterruptTests
{
    private const ulong BaseAddress = 0x2_0000_0000;
    private const int MemorySize = 0x2000;

    [Fact]
    public void TriggerAgcEopInterruptEvents_DeliversOnlyToMatchingIdent()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        // GTA SA DE registration pattern: completion ident plus ident 0.
        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x20,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));
        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x0,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));

        const ulong fenceAddress = 0xBEEF_2000;
        var triggered = KernelEventQueueCompatExports.TriggerAgcEopInterruptEvents(
            0, fenceAddress);
        Assert.Equal(1, triggered);

        var events = WaitEqueue(ctx, memory, handle);
        var interruptEvent = Assert.Single(events);
        Assert.Equal(0UL, interruptEvent.Ident);
        Assert.Equal(fenceAddress, interruptEvent.Data);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerAgcEopInterruptEvents_NonzeroContextId_RoutesToThatIdent()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x40,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));

        var triggered = KernelEventQueueCompatExports.TriggerAgcEopInterruptEvents(
            0x40, 0xBEEF_3000);
        Assert.Equal(1, triggered);

        var events = WaitEqueue(ctx, memory, handle);
        var interruptEvent = Assert.Single(events);
        Assert.Equal(0x40UL, interruptEvent.Ident);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerAgcEopInterruptEvents_NoMatchingIdent_DeliversNothing()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x20,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));

        var triggered = KernelEventQueueCompatExports.TriggerAgcEopInterruptEvents(
            0x7, 0xBEEF_4000);

        Assert.Equal(0, triggered);
        DeleteEqueue(ctx, handle);
    }

    private static void DeleteEqueue(CpuContext ctx, ulong handle)
    {
        // Registrations live in shared static state; drop the queue so one
        // test's registration cannot satisfy another test's trigger.
        ctx[CpuRegister.Rdi] = handle;
        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_OK,
            KernelEventQueueCompatExports.KernelDeleteEqueue(ctx));
    }

    private static ulong CreateEqueue(CpuContext ctx, FakeCpuMemory memory)
    {
        const ulong handleOutAddress = BaseAddress + 0x100;
        ctx[CpuRegister.Rdi] = handleOutAddress;
        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_OK,
            KernelEventQueueCompatExports.KernelCreateEqueue(ctx));
        return ReadUInt64(memory, handleOutAddress);
    }

    private static List<(ulong Ident, ulong Data, uint Fflags)> WaitEqueue(
        CpuContext ctx,
        FakeCpuMemory memory,
        ulong handle)
    {
        const ulong eventsAddress = BaseAddress + 0x200;
        const ulong outCountAddress = BaseAddress + 0x300;
        const ulong timeoutAddress = BaseAddress + 0x400;

        WriteUInt64(memory, timeoutAddress, 0);
        ctx[CpuRegister.Rdi] = handle;
        ctx[CpuRegister.Rsi] = eventsAddress;
        ctx[CpuRegister.Rdx] = 4;
        ctx[CpuRegister.Rcx] = outCountAddress;
        ctx[CpuRegister.R8] = timeoutAddress;
        Assert.Equal(
            (int)OrbisGen2Result.ORBIS_GEN2_OK,
            KernelEventQueueCompatExports.KernelWaitEqueue(ctx));

        var count = ReadUInt32(memory, outCountAddress);
        var events = new List<(ulong Ident, ulong Data, uint Fflags)>();
        for (uint index = 0; index < count; index++)
        {
            var entry = eventsAddress + (index * 0x20UL);
            events.Add((
                ReadUInt64(memory, entry + 0x00),
                ReadUInt64(memory, entry + 0x10),
                ReadUInt32(memory, entry + 0x0C)));
        }

        return events;
    }

    private static ulong ReadUInt64(FakeCpuMemory memory, ulong address)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(memory.TryRead(address, buffer));
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer);
    }

    private static uint ReadUInt32(FakeCpuMemory memory, ulong address)
    {
        Span<byte> buffer = stackalloc byte[4];
        Assert.True(memory.TryRead(address, buffer));
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }

    private static void WriteUInt64(FakeCpuMemory memory, ulong address, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        Assert.True(memory.TryWrite(address, buffer));
    }
}
