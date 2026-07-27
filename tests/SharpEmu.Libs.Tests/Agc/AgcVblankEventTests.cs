// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Buffers.Binary;
using SharpEmu.HLE;
using SharpEmu.Libs.Kernel;
using Xunit;

namespace SharpEmu.Libs.Tests.Agc;

// The AGC driver registers separate eventIds per interrupt source (GTA SA DE
// registers 0x20 and 0x00 on one equeue). Pending events coalesce per
// (ident, filter) with counting fflags, so a synthetic vblank landed on a
// nonzero ident inflates the guest's submission-completion count and
// overwrites the completion payload, which made the guest retire command and
// label memory before the ordered GPU-side writes finished (FMallocBinned3
// "unrecognized block" heap fault). TriggerAgcVblankEvents must therefore
// deliver only to the ident-0 graphics registration and stay silent on
// queues that lack one.
// The equeue registry is process-global static state, so every test that
// registers a graphics event shares this collection to serialize against
// other graphics-equeue tests.
[Collection("agc-equeue-global-state")]
public sealed class AgcVblankEventTests
{
    private const ulong BaseAddress = 0x2_0000_0000;
    private const int MemorySize = 0x2000;

    [Fact]
    public void TriggerAgcVblankEvents_DeliversOnlyToIdentZeroRegistration()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        // GTA SA DE registration pattern: completion ident first, then 0.
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

        const ulong vblankData = 0x1234;
        var triggered = KernelEventQueueCompatExports.TriggerAgcVblankEvents(vblankData);
        Assert.Equal(1, triggered);

        var events = WaitEqueue(ctx, memory, handle);
        var queuedEvent = Assert.Single(events);
        Assert.Equal(0UL, queuedEvent.Ident);
        Assert.Equal(vblankData, queuedEvent.Data);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerAgcVblankEvents_PendingCompletionPayloadSurvives()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

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

        // A DCB completion is pending with the command address as payload.
        const ulong commandAddress = 0xBEEF_0000;
        KernelEventQueueCompatExports.TriggerRegisteredEventsDistinct(
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            commandAddress);

        // A vblank tick before the guest dequeues must not touch the
        // completion event's count or payload on the nonzero ident.
        KernelEventQueueCompatExports.TriggerAgcVblankEvents(0x9999);

        var events = WaitEqueue(ctx, memory, handle);
        var completion = Assert.Single(events, e => e.Ident == 0x20);
        Assert.Equal(commandAddress, completion.Data);
        Assert.Equal(1u, completion.Fflags);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerAgcVblankEvents_NoIdentZeroRegistration_DeliversNothing()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        // Completion-only registration (issue #173 titles): a fabricated
        // vblank here would be indistinguishable from a completion.
        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x20,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));

        var triggered = KernelEventQueueCompatExports.TriggerAgcVblankEvents(0x1234);

        Assert.Equal(0, triggered);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerRegisteredEventsDistinct_SkipsIdentZeroWhenCompletionIdentExists()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

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

        // One submission completion must retire exactly one event; a copy on
        // the ident-0 pacing registration doubles the guest's retire count.
        const ulong commandAddress = 0xBEEF_1000;
        var triggered = KernelEventQueueCompatExports.TriggerRegisteredEventsDistinct(
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            commandAddress);

        Assert.Equal(1, triggered);
        var events = WaitEqueue(ctx, memory, handle);
        var completion = Assert.Single(events);
        Assert.Equal(0x20UL, completion.Ident);
        Assert.Equal(commandAddress, completion.Data);
        DeleteEqueue(ctx, handle);
    }

    [Fact]
    public void TriggerRegisteredEventsDistinct_IdentZeroOnly_StillDelivers()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var ctx = new CpuContext(memory, Generation.Gen5);
        var handle = CreateEqueue(ctx, memory);

        // A title whose sole graphics registration uses eventId 0 must keep
        // receiving completions there.
        Assert.True(KernelEventQueueCompatExports.RegisterEvent(
            handle,
            0x0,
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0));

        var triggered = KernelEventQueueCompatExports.TriggerRegisteredEventsDistinct(
            KernelEventQueueCompatExports.KernelEventFilterGraphics,
            0xCAFE);

        Assert.Equal(1, triggered);
        var events = WaitEqueue(ctx, memory, handle);
        var completion = Assert.Single(events);
        Assert.Equal(0UL, completion.Ident);
        Assert.Equal(0xCAFEUL, completion.Data);
        DeleteEqueue(ctx, handle);
    }

    private static void DeleteEqueue(CpuContext ctx, ulong handle)
    {
        // Registrations live in shared static state; drop the queue so one
        // test's ident-0 registration cannot satisfy another test's trigger.
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
