// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System;

namespace SharpEmu.Libs.Audio;

/// <summary>
/// A time-based model of an <c>sceAudioOut2</c> context's output grain queue.
///
/// Real hardware exposes a small ring of grain buffers (double/triple
/// buffered). The DAC consumes one grain every <c>grainSamples / frequency</c>
/// seconds, so an application that renders faster than realtime eventually
/// observes <c>available == 0</c> from <c>sceAudioOut2ContextGetQueueLevel</c>
/// and stops rendering until a grain has played. That backpressure is what
/// paces the audio mixer to the DAC clock.
///
/// SharpEmu's default model reports the queue as permanently empty
/// (<c>level = 0</c>, <c>available = depth</c>). That removes all pacing, so a
/// mixer render thread rendered against this model runs as fast as the host
/// CPU allows. When the mixer outruns the game's audio producer it can drain a
/// source ahead of time, mark it inactive, and stop consuming it — after which
/// the producer's ring fills and its writer thread blocks forever.
///
/// This class restores the realtime pacing by tracking modeled queue occupancy
/// and draining it against a monotonic clock. It never reports a permanent full
/// queue: occupancy decays to zero within <c>depth</c> grain periods once the
/// producer stops pushing, so a title that polls the level always recovers.
/// The clock is injected so the behaviour is deterministically testable.
/// </summary>
internal sealed class RealtimeAudioQueue
{
    private readonly object _gate = new();
    private readonly double _grainTicks;
    private readonly uint _depth;
    private double _queuedGrains;
    private long _lastTimestamp;
    private bool _started;

    /// <param name="frequency">Output sample rate in Hz.</param>
    /// <param name="grainSamples">Frames per grain (one push).</param>
    /// <param name="depth">Queue capacity in grains (>= 1).</param>
    /// <param name="stopwatchFrequency">Ticks per second of the injected clock.</param>
    public RealtimeAudioQueue(uint frequency, uint grainSamples, uint depth, long stopwatchFrequency)
    {
        var freq = frequency == 0 ? 48000u : frequency;
        var grain = grainSamples == 0 ? 256u : grainSamples;
        var ticksPerSecond = stopwatchFrequency <= 0 ? 1 : stopwatchFrequency;
        // Stopwatch ticks the DAC needs to consume a single grain.
        _grainTicks = Math.Max(1.0, ticksPerSecond * (double)grain / freq);
        _depth = depth == 0 ? 1u : depth;
    }

    /// <summary>Enqueue one grain, first accounting for any playback since the last update.</summary>
    public void RecordPush(long now)
    {
        lock (_gate)
        {
            Drain(now);
            _queuedGrains = Math.Min(_depth, _queuedGrains + 1.0);
        }
    }

    /// <summary>
    /// Attempt to enqueue one grain, draining for elapsed realtime first.
    /// Returns <see langword="true"/> and increments occupancy when the queue
    /// has room. When the queue is full it returns <see langword="false"/> and
    /// sets <paramref name="waitTicks"/> to the clock-tick interval until one
    /// grain will have drained, so a blocking <c>sceAudioOut2ContextPush</c> can
    /// pace itself to the DAC without busy-waiting. This models the hardware
    /// push contract: the render thread blocks here until a buffer frees up,
    /// which is what keeps it synchronised to the audio clock.
    /// </summary>
    public bool TryEnqueue(long now, out long waitTicks)
    {
        lock (_gate)
        {
            Drain(now);
            if (Math.Ceiling(_queuedGrains) < _depth)
            {
                _queuedGrains = Math.Min(_depth, _queuedGrains + 1.0);
                waitTicks = 0;
                return true;
            }

            // Full: wait until occupancy falls to depth-1 (one grain drains).
            var over = _queuedGrains - (_depth - 1);
            if (over < 0.0)
            {
                over = 0.0;
            }

            var ticks = (long)Math.Ceiling(over * _grainTicks);
            waitTicks = ticks < 1 ? 1 : ticks;
            return false;
        }
    }

    /// <summary>
    /// Sample the queue after draining for elapsed realtime.
    /// <paramref name="level"/> is the number of grains still awaiting playback
    /// (clamped to the depth); <paramref name="available"/> is the free capacity.
    /// </summary>
    public void Sample(long now, out uint level, out uint available)
    {
        lock (_gate)
        {
            Drain(now);
            var pending = (long)Math.Ceiling(_queuedGrains);
            if (pending < 0)
            {
                pending = 0;
            }

            level = pending > _depth ? _depth : (uint)pending;
            available = _depth - level;
        }
    }

    private void Drain(long now)
    {
        if (!_started)
        {
            _started = true;
            _lastTimestamp = now;
            return;
        }

        var elapsed = now - _lastTimestamp;
        _lastTimestamp = now;
        if (elapsed <= 0)
        {
            return;
        }

        var drained = elapsed / _grainTicks;
        _queuedGrains = drained >= _queuedGrains ? 0.0 : _queuedGrains - drained;
    }
}
