// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Threading;

namespace SharpEmu.Libs.Kernel;

public static class KernelEventQueueCompatExports
{
    private const int KernelEventSize = 0x20;
    public const short KernelEventFilterGraphics = -14;
    public const short KernelEventFilterUser = -11;
    public const short KernelEventFilterAmpr = -16;
    public const short KernelEventFilterAmprSystem = -17;

    private static readonly object _eventQueueGate = new();
    private static readonly HashSet<ulong> _eventQueues = new();
    private static readonly Dictionary<ulong, KernelEventDeque> _pendingEvents = new();
    private static readonly Dictionary<ulong, Dictionary<(ulong Ident, short Filter), KernelEventRegistration>> _registeredEvents = new();
    private static long _nextEventQueueHandle = 1;

    public readonly record struct KernelQueuedEvent(
        ulong Ident,
        short Filter,
        ushort Flags,
        uint Fflags,
        ulong Data,
        ulong UserData);

    private readonly record struct KernelEventRegistration(
        ulong Ident,
        short Filter,
        ulong UserData);

    // Grow-only ring buffer standing in for LinkedList<KernelQueuedEvent>, which
    // allocated a node per enqueue — steady churn at one enqueue per vblank/flip edge
    // per registered queue. Mutated only under _eventQueueGate.
    private sealed class KernelEventDeque
    {
        private KernelQueuedEvent[] _items = new KernelQueuedEvent[4];
        private int _head;

        public int Count { get; private set; }

        public KernelQueuedEvent this[int index]
        {
            get => _items[(_head + index) % _items.Length];
            set => _items[(_head + index) % _items.Length] = value;
        }

        public void AddLast(in KernelQueuedEvent item)
        {
            if (Count == _items.Length)
            {
                var grown = new KernelQueuedEvent[_items.Length * 2];
                for (var i = 0; i < Count; i++)
                {
                    grown[i] = this[i];
                }

                _items = grown;
                _head = 0;
            }

            _items[(_head + Count) % _items.Length] = item;
            Count++;
        }

        public KernelQueuedEvent RemoveFirst()
        {
            var value = _items[_head];
            _head = (_head + 1) % _items.Length;
            Count--;
            return value;
        }

        public int FindIndex(ulong ident, short filter)
        {
            for (var i = 0; i < Count; i++)
            {
                var candidate = this[i];
                if (candidate.Ident == ident && candidate.Filter == filter)
                {
                    return i;
                }
            }

            return -1;
        }
    }

    private sealed class EqueueWaiter : IGuestThreadBlockWaiter
    {
        public required CpuContext Ctx { get; init; }
        public required ulong Handle { get; init; }
        public required ulong EventsAddress { get; init; }
        public required int EventCapacity { get; init; }
        public required ulong OutCountAddress { get; init; }

        public int Resume() => ResumeWaitEqueue(Ctx, Handle, EventsAddress, EventCapacity, OutCountAddress);

        public bool TryWake() => HasPendingEvents(Handle);
    }

    [SysAbiExport(
        Nid = "D0OdFMjp46I",
        ExportName = "sceKernelCreateEqueue",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelCreateEqueue(CpuContext ctx)
    {
        var outAddress = ctx[CpuRegister.Rdi];
        if (outAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var handle = unchecked((ulong)Interlocked.Increment(ref _nextEventQueueHandle));
        lock (_eventQueueGate)
        {
            _eventQueues.Add(handle);
            _pendingEvents[handle] = new KernelEventDeque();
            _registeredEvents[handle] = new Dictionary<(ulong Ident, short Filter), KernelEventRegistration>();
        }

        if (!ctx.TryWriteUInt64(outAddress, handle))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        TraceEventQueue(ctx, "create", handle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "jpFjmgAC5AE",
        ExportName = "sceKernelDeleteEqueue",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelDeleteEqueue(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        lock (_eventQueueGate)
        {
            _eventQueues.Remove(handle);
            _pendingEvents.Remove(handle);
            _registeredEvents.Remove(handle);
        }

        _wakeKeys.TryRemove(handle, out _);

        TraceEventQueue(ctx, "delete", handle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "WDszmSbWuDk",
        ExportName = "sceKernelAddUserEventEdge",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAddUserEventEdge(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var registered = RegisterEvent(
            handle,
            ctx[CpuRegister.Rsi],
            KernelEventFilterUser,
            0);
        TraceEventQueue(ctx, "add_user_edge", handle);
        return registered
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "4R6-OvI2cEA",
        ExportName = "sceKernelAddUserEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAddUserEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var registered = RegisterEvent(
            handle,
            ctx[CpuRegister.Rsi],
            KernelEventFilterUser,
            0);
        TraceEventQueue(ctx, "add_user", handle);
        return registered
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "LJDwdSNTnDg",
        ExportName = "sceKernelDeleteUserEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelDeleteUserEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var deleted = DeleteRegisteredEvent(
            handle,
            ctx[CpuRegister.Rsi],
            KernelEventFilterUser);
        TraceEventQueue(ctx, "delete_user", handle);
        return deleted
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "F6e0kwo4cnk",
        ExportName = "sceKernelTriggerUserEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelTriggerUserEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var triggered = TriggerRegisteredEvent(
            handle,
            ctx[CpuRegister.Rsi],
            KernelEventFilterUser,
            flags: 0x21,
            fflags: 0,
            data: ctx[CpuRegister.Rdx]);
        TraceEventQueue(ctx, "trigger_user", handle);
        return triggered
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "bBfz7kMF2Ho",
        ExportName = "sceKernelAddAmprEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAddAmprEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var registered = RegisterEvent(
            handle,
            unchecked((uint)ctx[CpuRegister.Rsi]),
            KernelEventFilterAmpr,
            ctx[CpuRegister.Rdx]);
        TraceEventQueue(ctx, "add_ampr", handle);
        return registered
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "vuae5JPNt9A",
        ExportName = "sceKernelAddAmprSystemEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelAddAmprSystemEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var registered = RegisterEvent(
            handle,
            unchecked((uint)ctx[CpuRegister.Rsi]),
            KernelEventFilterAmprSystem,
            ctx[CpuRegister.Rdx]);
        TraceEventQueue(ctx, "add_ampr_system", handle);
        return registered
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "bMmid3pfyjo",
        ExportName = "sceKernelDeleteAmprEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelDeleteAmprEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var deleted = DeleteRegisteredEvent(
            handle,
            unchecked((uint)ctx[CpuRegister.Rsi]),
            KernelEventFilterAmpr);
        TraceEventQueue(ctx, "delete_ampr", handle);
        return deleted
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "Ij+ryuEClXQ",
        ExportName = "sceKernelDeleteAmprSystemEvent",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelDeleteAmprSystemEvent(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var deleted = DeleteRegisteredEvent(
            handle,
            unchecked((uint)ctx[CpuRegister.Rsi]),
            KernelEventFilterAmprSystem);
        TraceEventQueue(ctx, "delete_ampr_system", handle);
        return deleted
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
    }

    [SysAbiExport(
        Nid = "QyrxcdBrb0M",
        ExportName = "sceKernelGetKqueueFromEqueue",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetKqueueFromEqueue(CpuContext ctx)
    {
        ctx[CpuRegister.Rax] = ctx[CpuRegister.Rdi];
        TraceEventQueue(ctx, "get_kqueue", ctx[CpuRegister.Rdi]);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "vz+pg2zdopI",
        ExportName = "sceKernelGetEventUserData",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetEventUserData(CpuContext ctx)
    {
        _ = ctx.TryReadUInt64(ctx[CpuRegister.Rdi] + 0x18, out var userData);
        ctx[CpuRegister.Rax] = userData;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "mJ7aghmgvfc",
        ExportName = "sceKernelGetEventId",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetEventId(CpuContext ctx)
    {
        _ = ctx.TryReadUInt64(ctx[CpuRegister.Rdi], out var ident);
        ctx[CpuRegister.Rax] = ident;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "23CPPI1tyBY",
        ExportName = "sceKernelGetEventFilter",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetEventFilter(CpuContext ctx)
    {
        Span<byte> filterBytes = stackalloc byte[sizeof(short)];
        var filter = ctx.Memory.TryRead(ctx[CpuRegister.Rdi] + 0x08, filterBytes)
            ? BinaryPrimitives.ReadInt16LittleEndian(filterBytes)
            : (short)0;
        ctx[CpuRegister.Rax] = unchecked((uint)filter);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "kwGyyjohI50",
        ExportName = "sceKernelGetEventData",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelGetEventData(CpuContext ctx)
    {
        _ = ctx.TryReadUInt64(ctx[CpuRegister.Rdi] + 0x10, out var data);
        ctx[CpuRegister.Rax] = data;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "fzyMKs9kim0",
        ExportName = "sceKernelWaitEqueue",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int KernelWaitEqueue(CpuContext ctx)
    {
        var handle = ctx[CpuRegister.Rdi];
        var eventsAddress = ctx[CpuRegister.Rsi];
        var eventCapacity = (int)Math.Min(ctx[CpuRegister.Rdx], int.MaxValue);
        var outCountAddress = ctx[CpuRegister.Rcx];
        var timeoutAddress = ctx[CpuRegister.R8];

        if (!IsValidEqueue(handle))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        if (eventsAddress == 0 || eventCapacity < 1)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        uint timeoutUsec = 0;
        if (timeoutAddress != 0 && !TryReadUInt32(ctx, timeoutAddress, out timeoutUsec))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        var deliveredCount = DequeueEvents(ctx, handle, eventsAddress, eventCapacity);
        if (outCountAddress != 0 && !TryWriteUInt32(ctx, outCountAddress, (uint)deliveredCount))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (deliveredCount > 0)
        {
            TraceEventQueue(ctx, "wait-deliver", handle);
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (timeoutAddress == 0 &&
            GuestThreadExecution.RequestCurrentThreadBlock(
                ctx,
                "sceKernelWaitEqueue",
                GetEventQueueWakeKey(handle),
                new EqueueWaiter
                {
                    Ctx = ctx,
                    Handle = handle,
                    EventsAddress = eventsAddress,
                    EventCapacity = eventCapacity,
                    OutCountAddress = outCountAddress,
                }))
        {
            TraceEventQueue(ctx, "wait-block", handle);
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (timeoutAddress != 0 && ctx.TryReadUInt64(timeoutAddress, out var timeoutRaw))
        {
            var timeoutMicros = timeoutRaw & 0xFFFF_FFFFUL;
            var deadline = Environment.TickCount64 +
                Math.Max(1L, (long)Math.Min(timeoutMicros / 1000, int.MaxValue));
            lock (_eventQueueGate)
            {
                while (!HasPendingEvents(handle))
                {
                    var remaining = deadline - Environment.TickCount64;
                    if (remaining <= 0)
                    {
                        break;
                    }

                    Monitor.Wait(_eventQueueGate, (int)Math.Min(remaining, 100));
                }
            }

            deliveredCount = DequeueEvents(ctx, handle, eventsAddress, eventCapacity);
            if (outCountAddress != 0 && !TryWriteUInt32(ctx, outCountAddress, (uint)deliveredCount))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
            }

            if (deliveredCount > 0)
            {
                TraceEventQueue(ctx, "wait-timed-deliver", handle);
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }

            TraceEventQueue(ctx, "wait-timeout", handle);
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_TIMED_OUT;
        }

        TraceEventQueue(ctx, "wait", handle);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    public static bool IsValidEqueue(ulong handle)
    {
        lock (_eventQueueGate)
        {
            return _eventQueues.Contains(handle);
        }
    }

    public static bool EnqueueEvent(ulong handle, KernelQueuedEvent queuedEvent)
    {
        var queued = false;
        lock (_eventQueueGate)
        {
            if (!_eventQueues.Contains(handle))
            {
                return false;
            }

            if (!_pendingEvents.TryGetValue(handle, out var queue))
            {
                queue = new KernelEventDeque();
                _pendingEvents[handle] = queue;
            }

            queue.AddLast(queuedEvent);
            queued = true;
            Monitor.PulseAll(_eventQueueGate);
        }

        if (queued)
        {
            if (_logEqueue)
            {
                Console.Error.WriteLine(
                    $"[LOADER][TRACE] equeue.enqueue: handle=0x{handle:X16} ident=0x{queuedEvent.Ident:X16} " +
                    $"filter={queuedEvent.Filter} pending={PendingCount(handle)}");
            }
            WakeEventQueue(handle);
        }

        return queued;
    }

    private static int PendingCount(ulong handle)
    {
        lock (_eventQueueGate)
        {
            return _pendingEvents.TryGetValue(handle, out var q) ? q.Count : 0;
        }
    }

    public static bool RegisterEvent(
        ulong handle,
        ulong ident,
        short filter,
        ulong userData)
    {
        lock (_eventQueueGate)
        {
            if (!_eventQueues.Contains(handle))
            {
                return false;
            }

            if (!_registeredEvents.TryGetValue(handle, out var events))
            {
                events = new Dictionary<(ulong Ident, short Filter), KernelEventRegistration>();
                _registeredEvents[handle] = events;
            }

            events[(ident, filter)] = new KernelEventRegistration(ident, filter, userData);
            return true;
        }
    }

    public static bool DeleteRegisteredEvent(
        ulong handle,
        ulong ident,
        short filter)
    {
        lock (_eventQueueGate)
        {
            return _registeredEvents.TryGetValue(handle, out var events) &&
                   events.Remove((ident, filter));
        }
    }

    public static int TriggerRegisteredEvents(
        ulong ident,
        short filter,
        ulong data)
    {
        List<ulong>? wakeHandles = null;
        var triggeredCount = 0;
        lock (_eventQueueGate)
        {
            foreach (var (handle, registrations) in _registeredEvents)
            {
                if (!registrations.TryGetValue((ident, filter), out var registration))
                {
                    continue;
                }

                if (!_pendingEvents.TryGetValue(handle, out var queue))
                {
                    queue = new KernelEventDeque();
                    _pendingEvents[handle] = queue;
                }

                QueueOrUpdateEvent(
                    queue,
                    new KernelQueuedEvent(
                        registration.Ident,
                        registration.Filter,
                        0,
                        1,
                        data,
                        registration.UserData));
                (wakeHandles ??= new List<ulong>()).Add(handle);
                triggeredCount++;
            }
        }

        if (wakeHandles is not null)
        {
            foreach (var handle in wakeHandles)
            {
                WakeEventQueue(handle);
            }
        }

        return triggeredCount;
    }

    /// <summary>
    /// Triggers every registered event on every queue that matches <paramref name="filter"/>
    /// regardless of the registration's <c>ident</c>. This is a workaround for PS5 AGC command
    /// buffers, where <c>IT_EVENT_WRITE</c> carries a hardware <c>EVENT_TYPE</c> that does not
    /// match the <c>eventId</c> the guest registered with <c>sceAgcDriverAddEqEvent</c>.
    /// See issue #173.
    /// </summary>
    public static int TriggerRegisteredEventsByFilter(
        short filter,
        ulong data)
    {
        List<ulong>? wakeHandles = null;
        var triggeredCount = 0;
        lock (_eventQueueGate)
        {
            foreach (var (handle, registrations) in _registeredEvents)
            {
                foreach (var registration in registrations.Values)
                {
                    if (registration.Filter != filter)
                    {
                        continue;
                    }

                    if (!_pendingEvents.TryGetValue(handle, out var queue))
                    {
                        queue = new KernelEventDeque();
                        _pendingEvents[handle] = queue;
                    }

                    QueueOrUpdateEvent(
                        queue,
                        new KernelQueuedEvent(
                            registration.Ident,
                            registration.Filter,
                            0,
                            1,
                            data,
                            registration.UserData));
                    (wakeHandles ??= new List<ulong>()).Add(handle);
                    triggeredCount++;

                    // A single queue only needs to be woken once, even if multiple
                    // registrations matched.
                    break;
                }
            }
        }

        if (wakeHandles is not null)
        {
            foreach (var handle in wakeHandles)
            {
                WakeEventQueue(handle);
            }
        }

        return triggeredCount;
    }

    /// <summary>
    /// Triggers vblank events on every equeue that has an ident-0
    /// graphics-filter registration. PS5 titles that use the AGC driver
    /// rely on it to signal vblank internally; the guest never calls
    /// <c>sceVideoOutAddVblankEvent</c>, so the standard vblank path does
    /// not reach their event queue. Delivering a graphics-filter event at
    /// the display cadence unblocks the game's interrupt thread so it can
    /// pace the next frame.
    /// Only the ident-0 registration may carry this synthetic event: the
    /// AGC driver registers separate eventIds per interrupt source, and
    /// pending events coalesce per (ident, filter) with counting fflags
    /// (see <see cref="QueueOrUpdateEvent"/>). Landing fabricated events
    /// on a nonzero ident inflates the guest's submission-completion count
    /// and overwrites the pending completion payload, which makes the
    /// driver retire command/label memory before the ordered GPU-side
    /// writes have landed (observed as an FMallocBinned3 "unrecognized
    /// block" heap fault in GTA SA DE). Queues without an ident-0
    /// registration receive nothing rather than a forged completion.
    /// </summary>
    public static int TriggerAgcVblankEvents(ulong data)
    {
        List<ulong>? wakeHandles = null;
        var triggeredCount = 0;
        lock (_eventQueueGate)
        {
            foreach (var (handle, registrations) in _registeredEvents)
            {
                if (!registrations.TryGetValue(
                        (0UL, KernelEventFilterGraphics),
                        out var registration))
                {
                    continue;
                }

                if (!_pendingEvents.TryGetValue(handle, out var queue))
                {
                    queue = new KernelEventDeque();
                    _pendingEvents[handle] = queue;
                }

                QueueOrUpdateEvent(
                    queue,
                    new KernelQueuedEvent(
                        registration.Ident,
                        registration.Filter,
                        0,
                        1,
                        data,
                        registration.UserData));
                (wakeHandles ??= new List<ulong>()).Add(handle);
                triggeredCount++;
            }
        }

        if (wakeHandles is not null)
        {
            foreach (var handle in wakeHandles)
            {
                WakeEventQueue(handle);
            }
        }

        return triggeredCount;
    }

    /// <summary>
    /// Delivers a RELEASE_MEM end-of-pipe interrupt to every equeue with a
    /// graphics-filter registration whose eventId equals the packet's
    /// interrupt context id. On hardware the AGC driver routes the EOP
    /// interrupt to the eq event registered under that id; titles gate their
    /// frame loop on this event (GTA SA DE requests interrupt=2 with context
    /// id 0 on its per-frame fence and registers eventId 0 for it), so
    /// dropping the interrupt freezes the game after the first frame even
    /// though the fence memory write itself landed. Exact-ident routing keeps
    /// this distinct from whole-submission completions
    /// (<see cref="TriggerRegisteredEventsDistinct"/>), which prefer nonzero
    /// idents precisely so the pacing ident is left to interrupt sources.
    /// </summary>
    public static int TriggerAgcEopInterruptEvents(ulong ident, ulong data)
    {
        List<ulong>? wakeHandles = null;
        var triggeredCount = 0;
        lock (_eventQueueGate)
        {
            foreach (var (handle, registrations) in _registeredEvents)
            {
                if (!registrations.TryGetValue(
                        (ident, KernelEventFilterGraphics),
                        out var registration))
                {
                    continue;
                }

                if (!_pendingEvents.TryGetValue(handle, out var queue))
                {
                    queue = new KernelEventDeque();
                    _pendingEvents[handle] = queue;
                }

                QueueOrUpdateEvent(
                    queue,
                    new KernelQueuedEvent(
                        registration.Ident,
                        registration.Filter,
                        0,
                        1,
                        data,
                        registration.UserData));
                (wakeHandles ??= new List<ulong>()).Add(handle);
                triggeredCount++;
            }
        }

        if (wakeHandles is not null)
        {
            foreach (var handle in wakeHandles)
            {
                WakeEventQueue(handle);
            }
        }

        return triggeredCount;
    }

    /// <summary>
    /// Queues one event for every registration using <paramref name="filter"/>.
    /// Unlike <see cref="TriggerRegisteredEvents"/>, this preserves distinct
    /// event identifiers registered on the same queue. AGC driver completion
    /// queues use this form because the driver, rather than a packet-provided
    /// identifier, announces that the whole submission reached end-of-pipe.
    /// The <paramref name="data"/> parameter carries the submission-specific
    /// payload (e.g. the DCB command buffer address) so the guest can identify
    /// which submission completed.
    /// A completion is one hardware interrupt, so it must land on exactly one
    /// registration per queue. Titles that register several eventIds on one
    /// queue (GTA SA DE: 0x20 and 0x00) reserve ident 0 for the vblank-style
    /// pacing source, and delivering the completion there too doubles the
    /// guest's retire count: it frees the next submission's command and label
    /// memory while the ordered release_mem write is still queued, and that
    /// stale write lands in recycled heap (FMallocBinned3 "unrecognized
    /// block"). Prefer a nonzero-ident registration; fall back to ident 0
    /// only when it is the queue's sole graphics registration.
    /// </summary>
    public static int TriggerRegisteredEventsDistinct(short filter, ulong data = 0)
    {
        HashSet<ulong>? wakeHandles = null;
        var triggeredCount = 0;
        lock (_eventQueueGate)
        {
            foreach (var (handle, registrations) in _registeredEvents)
            {
                var deliveredCompletion = false;
                var hasIdentZero = false;
                foreach (var registration in registrations.Values)
                {
                    if (registration.Filter != filter)
                    {
                        continue;
                    }

                    if (registration.Ident == 0)
                    {
                        hasIdentZero = true;
                        continue;
                    }

                    QueueCompletionEventLocked(handle, registration, data, ref wakeHandles);
                    deliveredCompletion = true;
                    triggeredCount++;
                }

                if (!deliveredCompletion &&
                    hasIdentZero &&
                    registrations.TryGetValue((0UL, filter), out var identZero))
                {
                    QueueCompletionEventLocked(handle, identZero, data, ref wakeHandles);
                    triggeredCount++;
                }
            }
        }

        if (wakeHandles is not null)
        {
            foreach (var handle in wakeHandles)
            {
                WakeEventQueue(handle);
            }
        }

        return triggeredCount;
    }

    private static void QueueCompletionEventLocked(
        ulong handle,
        KernelEventRegistration registration,
        ulong data,
        ref HashSet<ulong>? wakeHandles)
    {
        if (!_pendingEvents.TryGetValue(handle, out var queue))
        {
            queue = new KernelEventDeque();
            _pendingEvents[handle] = queue;
        }

        QueueOrUpdateEvent(
            queue,
            new KernelQueuedEvent(
                registration.Ident,
                registration.Filter,
                0,
                1,
                data,
                registration.UserData));
        (wakeHandles ??= []).Add(handle);
    }

    private static bool TriggerRegisteredEvent(
        ulong handle,
        ulong ident,
        short filter,
        ushort flags,
        uint fflags,
        ulong data)
    {
        lock (_eventQueueGate)
        {
            if (!_registeredEvents.TryGetValue(handle, out var registrations) ||
                !registrations.TryGetValue((ident, filter), out var registration))
            {
                return false;
            }

            if (!_pendingEvents.TryGetValue(handle, out var queue))
            {
                queue = new KernelEventDeque();
                _pendingEvents[handle] = queue;
            }

            QueueOrUpdateEvent(
                queue,
                new KernelQueuedEvent(
                    registration.Ident,
                    registration.Filter,
                    flags,
                    fflags,
                    data,
                    registration.UserData));
        }

        WakeEventQueue(handle);
        return true;
    }

    public static bool TriggerDisplayEvent(
        ulong handle,
        ulong ident,
        short filter,
        ulong eventHint,
        ulong userData)
    {
        var triggered = false;
        lock (_eventQueueGate)
        {
            if (!_eventQueues.Contains(handle))
            {
                return false;
            }

            if (!_pendingEvents.TryGetValue(handle, out var events))
            {
                events = new KernelEventDeque();
                _pendingEvents[handle] = events;
            }

            var count = 1UL;
            var pendingIndex = events.FindIndex(ident, filter);
            if (pendingIndex >= 0)
            {
                count = Math.Min(((events[pendingIndex].Data >> 12) & 0xFUL) + 1, 0xFUL);
            }

            var timeBits = unchecked((ulong)Environment.TickCount64) & 0xFFFUL;
            var eventData = timeBits | (count << 12) | (eventHint & 0xFFFF_FFFF_FFFF_0000UL);
            var triggeredEvent = new KernelQueuedEvent(
                ident,
                filter,
                0x20,
                0,
                eventData,
                userData);

            if (pendingIndex >= 0)
            {
                events[pendingIndex] = triggeredEvent;
            }
            else
            {
                events.AddLast(triggeredEvent);
            }

            triggered = true;
        }

        if (triggered)
        {
            WakeEventQueue(handle);
        }

        return triggered;
    }

    private static int ResumeWaitEqueue(
        CpuContext ctx,
        ulong handle,
        ulong eventsAddress,
        int eventCapacity,
        ulong outCountAddress)
    {
        var deliveredCount = DequeueEvents(ctx, handle, eventsAddress, eventCapacity);
        if (_logEqueue)
        {
            Console.Error.WriteLine(
                $"[LOADER][TRACE] equeue.resume: handle=0x{handle:X16} delivered={deliveredCount} capacity={eventCapacity}");
        }
        if (outCountAddress != 0 && !TryWriteUInt32(ctx, outCountAddress, (uint)deliveredCount))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        return deliveredCount > 0
            ? (int)OrbisGen2Result.ORBIS_GEN2_OK
            : (int)OrbisGen2Result.ORBIS_GEN2_ERROR_TIMED_OUT;
    }

    private static bool HasPendingEvents(ulong handle)
    {
        lock (_eventQueueGate)
        {
            return _pendingEvents.TryGetValue(handle, out var events) && events.Count != 0;
        }
    }

    private static void QueueOrUpdateEvent(
        KernelEventDeque queue,
        KernelQueuedEvent queuedEvent)
    {
        var pendingIndex = queue.FindIndex(queuedEvent.Ident, queuedEvent.Filter);
        if (pendingIndex < 0)
        {
            queue.AddLast(queuedEvent);
            return;
        }

        queue[pendingIndex] = queuedEvent with
        {
            Fflags = Math.Max(queue[pendingIndex].Fflags + 1, queuedEvent.Fflags),
        };
    }

    // Wake keys are formatted once per handle: WakeEventQueue runs on every event
    // enqueue (vblank/flip edges included), so formatting there is steady string churn.
    private static readonly ConcurrentDictionary<ulong, string> _wakeKeys = new();

    private static string GetEventQueueWakeKey(ulong handle) =>
        _wakeKeys.GetOrAdd(handle, static h => $"sceKernelWaitEqueue:{h:X16}");

    private static void WakeEventQueue(ulong handle)
    {
        var wakeCount = GuestThreadExecution.Scheduler?.WakeBlockedThreads(GetEventQueueWakeKey(handle)) ?? 0;
        if (_logEqueue)
        {
            Console.Error.WriteLine(
                $"[LOADER][TRACE] equeue.wake: handle=0x{handle:X16} woke={wakeCount}");
        }
    }

    private static int DequeueEvents(CpuContext ctx, ulong handle, ulong eventsAddress, int eventCapacity)
    {
        if (eventsAddress == 0 || eventCapacity <= 0)
        {
            return 0;
        }

        // Engines wait on the vblank/flip equeue every frame, so the delivery buffer
        // (usually a single event) comes from the pool instead of a per-call array.
        KernelQueuedEvent[] events;
        int count;
        lock (_eventQueueGate)
        {
            if (!_pendingEvents.TryGetValue(handle, out var queue) || queue.Count == 0)
            {
                return 0;
            }

            count = Math.Min(eventCapacity, queue.Count);
            events = ArrayPool<KernelQueuedEvent>.Shared.Rent(count);
            for (var i = 0; i < count; i++)
            {
                events[i] = queue.RemoveFirst();
            }
        }

        try
        {
            for (var i = 0; i < count; i++)
            {
                if (!WriteKernelEvent(ctx, eventsAddress + ((ulong)i * KernelEventSize), events[i]))
                {
                    return i;
                }
            }
        }
        finally
        {
            ArrayPool<KernelQueuedEvent>.Shared.Return(events);
        }

        return count;
    }

    private static bool WriteKernelEvent(CpuContext ctx, ulong address, KernelQueuedEvent queuedEvent)
    {
        Span<byte> eventBytes = stackalloc byte[KernelEventSize];
        BinaryPrimitives.WriteUInt64LittleEndian(eventBytes[0x00..], queuedEvent.Ident);
        BinaryPrimitives.WriteInt16LittleEndian(eventBytes[0x08..], queuedEvent.Filter);
        BinaryPrimitives.WriteUInt16LittleEndian(eventBytes[0x0A..], queuedEvent.Flags);
        BinaryPrimitives.WriteUInt32LittleEndian(eventBytes[0x0C..], queuedEvent.Fflags);
        BinaryPrimitives.WriteUInt64LittleEndian(eventBytes[0x10..], queuedEvent.Data);
        BinaryPrimitives.WriteUInt64LittleEndian(eventBytes[0x18..], queuedEvent.UserData);
        return ctx.Memory.TryWrite(address, eventBytes);
    }

    private static readonly bool _logEqueue =
        string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_EQUEUE"), "1", StringComparison.Ordinal);

    private static void TraceEventQueue(CpuContext ctx, string operation, ulong handle)
    {
        if (!_logEqueue)
        {
            return;
        }

        var returnRip = 0UL;
        _ = ctx.TryReadUInt64(ctx[CpuRegister.Rsp], out returnRip);
        Console.Error.WriteLine(
            $"[LOADER][TRACE] equeue.{operation}: handle=0x{handle:X16} rsi=0x{ctx[CpuRegister.Rsi]:X16} rdx=0x{ctx[CpuRegister.Rdx]:X16} ret=0x{returnRip:X16}");
    }

    private static bool TryWriteUInt32(CpuContext ctx, ulong address, uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        return ctx.Memory.TryWrite(address, buffer);
    }

    private static bool TryReadUInt32(CpuContext ctx, ulong address, out uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        if (!ctx.Memory.TryRead(address, buffer))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        return true;
    }
}
