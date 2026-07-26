// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using SharpEmu.Libs.AvPlayer;
using Xunit;

namespace SharpEmu.Libs.Tests.AvPlayer;

/// <summary>
/// Hardware sceAvPlayer is a realtime pipeline: playback reaches end-of-stream
/// on its own clock and STATE_STOP is reported through the event callback no
/// matter how the title pumps frames. The HLE decoder is pull-based, so the
/// player must end when either the consumed streams drain to their real
/// content end or the realtime duration elapses — whichever comes first. UE
/// titles loop their startup movie until the background load finishes, so a
/// player that never ends holds the whole loading flow hostage (the original
/// GTA SA:DE frozen-intro wedge).
/// </summary>
public sealed class AvPlayerEndOfStreamTests
{
    private const ulong BaseAddress = 0x1_0000_0000;
    private const int MemorySize = 0x2000;
    // Far from AvPlayerStreamInfoTests' Handle: that suite probes Handle+1 as
    // an unknown player and the registry is process-global across parallel
    // test classes.
    private const ulong Handle = 0xA0_0000_1000;

    [Fact]
    public void IsActiveRetiresStreamOnceRealtimeDurationElapses()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        AvPlayerExports.RegisterPlayerForTest(Handle, 1920, 1080, durationMilliseconds: 1);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle);
            Thread.Sleep(50);

            context[CpuRegister.Rdi] = Handle;
            Assert.Equal(0, AvPlayerExports.AvPlayerIsActive(context));

            // The transition is latched: later polls stay inactive.
            Assert.Equal(0, AvPlayerExports.AvPlayerIsActive(context));
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }

    [Fact]
    public void IsActiveRetiresStreamOnceAllConsumedStreamsEnd()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        // Long duration: only the natural content end can retire the player.
        AvPlayerExports.RegisterPlayerForTest(
            Handle, 1920, 1080, durationMilliseconds: 10UL * 60 * 1000);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle);
            AvPlayerExports.MarkStreamsEndedForTest(Handle);

            context[CpuRegister.Rdi] = Handle;
            Assert.Equal(0, AvPlayerExports.AvPlayerIsActive(context));
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }

    [Fact]
    public void IsActiveStaysActiveWhileRealtimeDurationRemains()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        AvPlayerExports.RegisterPlayerForTest(
            Handle, 1920, 1080, durationMilliseconds: 10UL * 60 * 1000);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle);

            context[CpuRegister.Rdi] = Handle;
            Assert.Equal(1, AvPlayerExports.AvPlayerIsActive(context));
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }

    [Fact]
    public void IsActiveKeepsLoopingStreamActivePastItsDuration()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        AvPlayerExports.RegisterPlayerForTest(Handle, 1920, 1080, durationMilliseconds: 1);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle, looping: true);
            Thread.Sleep(50);

            context[CpuRegister.Rdi] = Handle;
            Assert.Equal(1, AvPlayerExports.AvPlayerIsActive(context));
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }

    [Fact]
    public void CurrentTimeFollowsDeliveredAudioInAudioMasterPlayback()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        AvPlayerExports.RegisterPlayerForTest(
            Handle, 1920, 1080, durationMilliseconds: 10UL * 60 * 1000);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle);
            AvPlayerExports.SetDeliveredAudioForTest(Handle, 512);

            // Hardware reports the audio presentation position, not the wall
            // clock racing ahead of the delivered samples.
            context[CpuRegister.Rdi] = Handle;
            Assert.Equal(512, AvPlayerExports.AvPlayerCurrentTime(context));
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }

    [Fact]
    public void CurrentTimeFallsBackToClockForVideoOnlyPlayback()
    {
        var memory = new FakeCpuMemory(BaseAddress, MemorySize);
        var context = new CpuContext(memory, Generation.Gen5);

        AvPlayerExports.RegisterPlayerForTest(
            Handle, 1920, 1080, durationMilliseconds: 10UL * 60 * 1000);
        try
        {
            AvPlayerExports.StartPlayerForTest(Handle);
            Thread.Sleep(50);

            context[CpuRegister.Rdi] = Handle;
            Assert.True(AvPlayerExports.AvPlayerCurrentTime(context) >= 25);
        }
        finally
        {
            AvPlayerExports.RemovePlayerForTest(Handle);
        }
    }
}
