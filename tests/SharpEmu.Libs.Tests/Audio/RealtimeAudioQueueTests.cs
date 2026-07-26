// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Audio;
using Xunit;

namespace SharpEmu.Libs.Tests.Audio;

public sealed class RealtimeAudioQueueTests
{
    // 480 frames per grain at 48 kHz = 10 ms; with a 1000-tick/second clock
    // that is exactly 10 ticks per grain, so the arithmetic is exact.
    private static RealtimeAudioQueue NewQueue(uint depth) =>
        new(frequency: 48000, grainSamples: 480, depth: depth, stopwatchFrequency: 1000);

    [Fact]
    public void EmptyQueueReportsFullCapacity()
    {
        var queue = NewQueue(depth: 2);

        queue.Sample(0, out var level, out var available);

        Assert.Equal(0u, level);
        Assert.Equal(2u, available);
    }

    [Fact]
    public void PushingToCapacityDropsAvailableToZero()
    {
        var queue = NewQueue(depth: 2);
        queue.Sample(0, out _, out _); // prime the clock

        queue.RecordPush(0);
        queue.RecordPush(0);

        queue.Sample(0, out var level, out var available);
        Assert.Equal(2u, level);
        Assert.Equal(0u, available);
    }

    [Fact]
    public void PushClampsAtDepth()
    {
        var queue = NewQueue(depth: 2);
        queue.Sample(0, out _, out _);

        for (var i = 0; i < 5; i++)
        {
            queue.RecordPush(0);
        }

        queue.Sample(0, out var level, out var available);
        Assert.Equal(2u, level);
        Assert.Equal(0u, available);
    }

    [Fact]
    public void OneGrainPeriodDrainsOneGrain()
    {
        var queue = NewQueue(depth: 2);
        queue.Sample(0, out _, out _);
        queue.RecordPush(0);
        queue.RecordPush(0);

        // 10 ticks == one grain period => one grain has played.
        queue.Sample(10, out var level, out var available);
        Assert.Equal(1u, level);
        Assert.Equal(1u, available);
    }

    [Fact]
    public void QueueRecoversToEmptyAfterIdle()
    {
        // Regression: the level must never be reported permanently full. Once the
        // producer stops pushing, occupancy must decay back to zero so a title
        // that keeps polling GetQueueLevel is never stalled forever.
        var queue = NewQueue(depth: 2);
        queue.Sample(0, out _, out _);
        queue.RecordPush(0);
        queue.RecordPush(0);

        // Idle for well beyond depth grain periods.
        queue.Sample(1000, out var level, out var available);
        Assert.Equal(0u, level);
        Assert.Equal(2u, available);
    }

    [Fact]
    public void FractionalDrainRoundsUpPendingGrain()
    {
        var queue = NewQueue(depth: 4);
        queue.Sample(0, out _, out _);
        for (var i = 0; i < 4; i++)
        {
            queue.RecordPush(0);
        }

        // Half a grain period: 0.5 grains played, 3.5 remain => ceil == 4.
        queue.Sample(5, out var level, out var available);
        Assert.Equal(4u, level);
        Assert.Equal(0u, available);

        // A full grain period after the start: 1.0 played, 3.0 remain.
        queue.Sample(10, out level, out available);
        Assert.Equal(3u, level);
        Assert.Equal(1u, available);
    }

    [Fact]
    public void DegenerateParametersDoNotThrow()
    {
        var queue = new RealtimeAudioQueue(frequency: 0, grainSamples: 0, depth: 0, stopwatchFrequency: 0);
        queue.Sample(0, out var level, out var available);

        Assert.Equal(0u, level);
        Assert.Equal(1u, available); // depth defaults to 1
    }

    [Fact]
    public void TryEnqueueFillsThenReportsFullWithWait()
    {
        var queue = NewQueue(depth: 2);

        Assert.True(queue.TryEnqueue(0, out var w1));
        Assert.Equal(0L, w1);
        Assert.True(queue.TryEnqueue(0, out var w2));
        Assert.Equal(0L, w2);

        // Queue is now full: the third push must block until a grain drains.
        Assert.False(queue.TryEnqueue(0, out var w3));
        Assert.Equal(10L, w3); // one grain period at 480/48kHz on a 1000-tick clock
    }

    [Fact]
    public void TryEnqueueGainsRoomAfterAGrainDrains()
    {
        var queue = NewQueue(depth: 2);
        queue.TryEnqueue(0, out _);
        queue.TryEnqueue(0, out _);
        Assert.False(queue.TryEnqueue(0, out _));

        // After one grain period a slot frees up and the push succeeds.
        Assert.True(queue.TryEnqueue(10, out var wait));
        Assert.Equal(0L, wait);
    }
}
