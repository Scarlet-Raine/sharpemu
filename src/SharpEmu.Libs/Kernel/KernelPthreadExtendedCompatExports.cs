// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.HLE;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace SharpEmu.Libs.Kernel;

public static class KernelPthreadExtendedCompatExports
{
    private const int DefaultThreadPriority = 700;
    private const ulong DefaultThreadAffinityMask = 0x7FUL;
    private const int DefaultDetachState = 0;
    private const ulong DefaultGuardSize = 0x1000UL;
    private const ulong DefaultStackSize = 0x1_00000UL;
    private const ulong NativeGuestStackSize = 0x20_0000UL;
    private const ulong NativeGuestStackStride = 0x100_0000UL;
    private const int DefaultInheritSched = 4;
    private const int DefaultSchedPolicy = 1;
    private const int DefaultSchedPriority = DefaultThreadPriority;
    private const ulong SyntheticRwlockHandleBase = 0x00006003_0000_0000;
    private const ulong SyntheticPthreadAttrHandleBase = 0x00006004_0000_0000;
    private const ulong SyntheticRwlockAttrHandleBase = 0x00006005_0000_0000;

    private static readonly object _stateGate = new();
    private static readonly Dictionary<ulong, ThreadState> _threadStates = new();
    private static readonly Dictionary<ulong, PthreadAttrState> _attrStates = new();
    private static readonly Dictionary<ulong, PthreadRwlockState> _rwlockStates = new();
    private static readonly ConcurrentDictionary<int, TlsKeyState> _tlsKeys = new();
    private static int _nextTlsKey = 1;
    private static long _nextSyntheticRwlockHandleId = 1;
    private static long _nextSyntheticPthreadAttrHandleId = 1;
    private static long _nextSyntheticRwlockAttrHandleId = 1;
    private static readonly bool _strictRwlockWriterPreference =
        string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_STRICT_RWLOCK_WRITER_PREFERENCE"), "1", StringComparison.Ordinal);

    private static readonly ConcurrentDictionary<ulong, ConcurrentDictionary<int, ulong>> _threadLocalSpecific = new();

    /// <summary>
    /// Returns true if <paramref name="address"/> matches any TLS value stored for
    /// the current thread. HLE exports that write to guest-provided output pointers
    /// can use this to avoid corrupting per-thread structures (e.g. the allocator
    /// cache stored under TLS key 8) when the game passes a stale/wrong pointer.
    /// </summary>
    internal static bool IsCurrentThreadTlsValue(ulong address)
    {
        if (address == 0)
        {
            return false;
        }

        var handle = KernelPthreadState.GetCurrentThreadHandle();
        if (_threadLocalSpecific.TryGetValue(handle, out var values))
        {
            foreach (var kvp in values)
            {
                if (kvp.Value == address)
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal static void GetThreadStartScheduling(
        CpuContext ctx,
        ulong attrAddress,
        out int priority,
        out ulong affinityMask)
    {
        if (attrAddress == 0)
        {
            priority = DefaultThreadPriority;
            affinityMask = DefaultThreadAffinityMask;
            return;
        }

        var resolvedAddress = ResolvePthreadAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            var attributes = GetOrCreateAttrStateLocked(resolvedAddress);
            priority = attributes.SchedPriority;
            affinityMask = attributes.AffinityMask;
        }
    }

    internal static void RegisterThreadStart(
        ulong thread,
        string name,
        int priority,
        ulong affinityMask)
    {
        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.Name = name;
            state.Priority = priority;
            state.AffinityMask = affinityMask;
            state.Attributes = state.Attributes with
            {
                SchedPriority = priority,
                AffinityMask = affinityMask,
            };
        }
    }

    private sealed class ThreadState
    {
        public string Name { get; set; } = string.Empty;
        public int Priority { get; set; } = DefaultThreadPriority;
        public ulong AffinityMask { get; set; } = DefaultThreadAffinityMask;
        public int DetachState { get; set; } = DefaultDetachState;
        public PthreadAttrState Attributes { get; set; } = PthreadAttrState.Default;
    }

    // On the outer class deliberately: a static on the nested state class gives it a type
    // initializer that first runs on a guest thread and fail-fasts the CLR.
    private static long _nextRwlockWakeId;

    private sealed class PthreadRwlockState
    {
        public object SyncRoot { get; } = new();
        public Dictionary<ulong, int> ReaderCounts { get; } = new();
        public Dictionary<ulong, int> CompatWriterCounts { get; } = new();
        public int ReaderTotalCount { get; set; }
        public int CompatWriterTotalCount { get; set; }
        public ulong WriterThreadId { get; set; }
        public int WaitingWriters { get; set; }

        // See PthreadMutexState.WakeKey.
        public string WakeKey { get; } = "pthread_rwlock#" + Interlocked.Increment(ref _nextRwlockWakeId).ToString("X");

        public int GetReaderCount(ulong threadId)
        {
            return ReaderCounts.TryGetValue(threadId, out var count) ? count : 0;
        }

        public void AddReader(ulong threadId)
        {
            ReaderCounts.TryGetValue(threadId, out var currentCount);
            ReaderCounts[threadId] = currentCount + 1;
            ReaderTotalCount++;
        }

        public void AddCompatWriter(ulong threadId)
        {
            CompatWriterCounts.TryGetValue(threadId, out var currentCount);
            CompatWriterCounts[threadId] = currentCount + 1;
            CompatWriterTotalCount++;
        }

        public bool RemoveCompatWriter(ulong threadId)
        {
            if (!CompatWriterCounts.TryGetValue(threadId, out var currentCount) || currentCount <= 0)
            {
                return false;
            }

            if (currentCount == 1)
            {
                CompatWriterCounts.Remove(threadId);
            }
            else
            {
                CompatWriterCounts[threadId] = currentCount - 1;
            }

            CompatWriterTotalCount = Math.Max(0, CompatWriterTotalCount - 1);
            return true;
        }

        public bool RemoveReader(ulong threadId)
        {
            if (!ReaderCounts.TryGetValue(threadId, out var currentCount) || currentCount <= 0)
            {
                return false;
            }

            if (currentCount == 1)
            {
                ReaderCounts.Remove(threadId);
            }
            else
            {
                ReaderCounts[threadId] = currentCount - 1;
            }

            ReaderTotalCount = Math.Max(0, ReaderTotalCount - 1);
            return true;
        }
    }

    private sealed class RwlockWaiter : IGuestThreadBlockWaiter
    {
        public required PthreadRwlockState Rwlock { get; init; }
        public required ulong ThreadId { get; init; }
        public required bool Write { get; init; }

        public int Resume() => (int)OrbisGen2Result.ORBIS_GEN2_OK;

        public bool TryWake() => TryAcquireBlockedRwlock(Rwlock, ThreadId, Write);
    }

    private readonly record struct TlsKeyState(ulong Destructor);

    private readonly record struct PthreadAttrState(
        ulong AffinityMask,
        int DetachState,
        ulong StackAddress,
        ulong StackSize,
        ulong GuardSize,
        int InheritSched,
        int SchedPolicy,
        int SchedPriority)
    {
        public static PthreadAttrState Default =>
            new(
                DefaultThreadAffinityMask,
                DefaultDetachState,
                0,
                DefaultStackSize,
                DefaultGuardSize,
                DefaultInheritSched,
                DefaultSchedPolicy,
                DefaultSchedPriority);
    }

    [SysAbiExport(
        Nid = "4qGrR6eoP9Y",
        ExportName = "scePthreadDetach",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadDetach(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.DetachState = 1;
            state.Attributes = state.Attributes with { DetachState = 1 };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "+U1R4WtXvoc",
        ExportName = "pthread_detach",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadDetach(CpuContext ctx) => PthreadDetach(ctx);

    [SysAbiExport(
        Nid = "How7B8Oet6k",
        ExportName = "scePthreadGetname",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetname(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outNameAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outNameAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        string name;
        lock (_stateGate)
        {
            name = GetOrCreateThreadStateLocked(thread).Name;
        }

        if (!TryWriteFixedUtf8CString(ctx, outNameAddress, name, 32))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "bt3CTBKmGyI",
        ExportName = "scePthreadSetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetaffinity(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var mask = ctx[CpuRegister.Rsi];
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.AffinityMask = mask;
            state.Attributes = state.Attributes with { AffinityMask = mask };
        }

        _ = GuestThreadExecution.Scheduler?.TrySetGuestThreadAffinity(thread, mask);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "rcrVFJsQWRY",
        ExportName = "scePthreadGetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetaffinity(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outMaskAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outMaskAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        ulong affinityMask;
        lock (_stateGate)
        {
            affinityMask = GetOrCreateThreadStateLocked(thread).AffinityMask;
        }

        if (!ctx.TryWriteUInt64(outMaskAddress, affinityMask))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "1tKyG7RlMJo",
        ExportName = "scePthreadGetprio",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetprio(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outPriorityAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outPriorityAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        int priority;
        lock (_stateGate)
        {
            priority = GetOrCreateThreadStateLocked(thread).Priority;
        }

        if (!TryWriteInt32(ctx, outPriorityAddress, priority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((uint)priority);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "W0Hpm2X0uPE",
        ExportName = "scePthreadSetprio",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetprio(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var priority = unchecked((int)ctx[CpuRegister.Rsi]);
        if (thread == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            GetOrCreateThreadStateLocked(thread).Priority = priority;
        }

        // Apply to the live scheduler thread so runtime priority changes take
        // effect, not just the local bookkeeping snapshot.
        _ = GuestThreadExecution.Scheduler?.TrySetGuestThreadPriority(thread, priority);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Xs9hdiD7sAA",
        ExportName = "pthread_setschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadSetschedparam(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var policy = unchecked((int)ctx[CpuRegister.Rsi]);
        var schedParamAddress = ctx[CpuRegister.Rdx];
        if (thread == 0 || schedParamAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryReadInt32(ctx, schedParamAddress, out var schedPriority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            state.Priority = schedPriority;
            state.Attributes = state.Attributes with
            {
                SchedPolicy = policy,
                SchedPriority = schedPriority,
            };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "oIRFTjoILbg",
        ExportName = "scePthreadSetschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetschedparam(CpuContext ctx) => PosixPthreadSetschedparam(ctx);

    [SysAbiExport(
        Nid = "P41kTWUS3EI",
        ExportName = "scePthreadGetschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetschedparam(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var policyAddress = ctx[CpuRegister.Rsi];
        var schedParamAddress = ctx[CpuRegister.Rdx];
        if (thread == 0 || policyAddress == 0 || schedParamAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        int policy;
        int priority;
        lock (_stateGate)
        {
            var state = GetOrCreateThreadStateLocked(thread);
            policy = state.Attributes.SchedPolicy;
            priority = state.Priority;
        }

        if (!TryWriteInt32(ctx, policyAddress, policy) ||
            !TryWriteInt32(ctx, schedParamAddress, priority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "nsYoNRywwNg",
        ExportName = "scePthreadAttrInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrInit(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var syntheticHandle = AllocateSyntheticHandle(SyntheticPthreadAttrHandleBase, ref _nextSyntheticPthreadAttrHandleId);
        if (!ctx.TryWriteUInt64(attrAddress, syntheticHandle))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        lock (_stateGate)
        {
            _attrStates[attrAddress] = PthreadAttrState.Default;
            _attrStates[syntheticHandle] = PthreadAttrState.Default;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "wtkt-teR1so",
        ExportName = "pthread_attr_init",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadAttrInit(CpuContext ctx)
    {
        return PthreadAttrInit(ctx);
    }

    [SysAbiExport(
        Nid = "62KCwEMmzcM",
        ExportName = "scePthreadAttrDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrDestroy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolvePthreadAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            _attrStates.Remove(attrAddress);
            if (resolvedAddress != attrAddress)
            {
                _attrStates.Remove(resolvedAddress);
            }
        }

        _ = ctx.TryWriteUInt64(attrAddress, 0);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "zHchY8ft5pk",
        ExportName = "pthread_attr_destroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadAttrDestroy(CpuContext ctx)
    {
        return PthreadAttrDestroy(ctx);
    }

    [SysAbiExport(
        Nid = "x1X76arYMxU",
        ExportName = "scePthreadAttrGet",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGet(CpuContext ctx)
    {
        var thread = ctx[CpuRegister.Rdi];
        var outAttrAddress = ctx[CpuRegister.Rsi];
        if (thread == 0 || outAttrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var threadState = GetOrCreateThreadStateLocked(thread);

			// The native executor maps guest pthread stacks itself, after the
			// kernel-facing thread object has been created.  Report that live
			// mapping when a thread asks for its own attributes.  IL2CPP's
			// conservative collector uses these two fields to register the stack;
			// returning the default null address lets it recycle objects that are
			// still reachable only from guest registers/stack frames.
			if (thread == KernelPthreadState.GetCurrentThreadHandle() &&
				TryInferNativeGuestStack(ctx[CpuRegister.Rsp], out var stackAddress))
			{
				threadState.Attributes = threadState.Attributes with
				{
					StackAddress = stackAddress,
					StackSize = NativeGuestStackSize,
				};
			}
            _attrStates[outAttrAddress] = threadState.Attributes;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

	private static bool TryInferNativeGuestStack(ulong stackPointer, out ulong stackAddress)
	{
		stackAddress = 0;
		var candidate = stackPointer & ~(NativeGuestStackStride - 1);
		if (stackPointer - candidate >= NativeGuestStackSize)
		{
			return false;
		}

		var highestStack = OperatingSystem.IsWindows()
			? 0x00007FFF_F000_0000UL
			: 0x00006FFF_F000_0000UL;
		var lowestStack = highestStack - (63 * NativeGuestStackStride);
		if (candidate < lowestStack || candidate > highestStack)
		{
			return false;
		}

		stackAddress = candidate;
		return true;
	}

    [SysAbiExport(
        Nid = "8+s5BzZjxSg",
        ExportName = "scePthreadAttrGetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetaffinity(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outMaskAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outMaskAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outMaskAddress, state.AffinityMask))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.AffinityMask;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "JaRMy+QcpeU",
        ExportName = "scePthreadAttrGetdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetdetachstate(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStateAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStateAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!TryWriteInt32(ctx, outStateAddress, state.DetachState))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = unchecked((uint)state.DetachState);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "txHtngJ+eyc",
        ExportName = "scePthreadAttrGetguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetguardsize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outGuardSizeAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outGuardSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outGuardSizeAddress, state.GuardSize))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.GuardSize;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "Ru36fiTtJzA",
        ExportName = "scePthreadAttrGetstackaddr",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstackaddr(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStackAddressPointer = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStackAddressPointer == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outStackAddressPointer, state.StackAddress))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.StackAddress;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "-quPa4SEJUw",
        ExportName = "scePthreadAttrGetstack",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstack(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStackAddressPointer = ctx[CpuRegister.Rsi];
        var outStackSizeAddress = ctx[CpuRegister.Rdx];
        if (attrAddress == 0 || outStackAddressPointer == 0 || outStackSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outStackAddressPointer, state.StackAddress) ||
            !ctx.TryWriteUInt64(outStackSizeAddress, state.StackSize))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "-fA+7ZlGDQs",
        ExportName = "scePthreadAttrGetstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstacksize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var outStackSizeAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || outStackSizeAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!ctx.TryWriteUInt64(outStackSizeAddress, state.StackSize))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = state.StackSize;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "3qxgM4ezETA",
        ExportName = "scePthreadAttrSetaffinity",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetaffinity(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var mask = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { AffinityMask = mask };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "-Wreprtu0Qs",
        ExportName = "scePthreadAttrSetdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetdetachstate(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var detachState = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { DetachState = detachState };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "El+cQ20DynU",
        ExportName = "scePthreadAttrSetguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetguardsize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var guardSize = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { GuardSize = guardSize };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "eXbUSpEaTsA",
        ExportName = "scePthreadAttrSetinheritsched",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetinheritsched(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var inheritSched = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { InheritSched = inheritSched };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    /// <summary>
    /// The POSIX-named alias of <see cref="PthreadAttrGetschedparam"/>. libKernel
    /// exports the same routine under two NIDs; middleware compiled against the
    /// plain POSIX headers links this one rather than scePthreadAttrGetschedparam.
    /// </summary>
    [SysAbiExport(
        Nid = "qlk9pSLsUmM",
        ExportName = "pthread_attr_getschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetschedparamPOSIX(CpuContext ctx) => PthreadAttrGetschedparam(ctx);

    [SysAbiExport(
        Nid = "FXPWHNk8Of0",
        ExportName = "scePthreadAttrGetschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetschedparam(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var schedParamAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || schedParamAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        PthreadAttrState state;
        lock (_stateGate)
        {
            state = GetOrCreateAttrStateLocked(attrAddress);
        }

        if (!TryWriteInt32(ctx, schedParamAddress, state.SchedPriority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "DzES9hQF4f4",
        ExportName = "scePthreadAttrSetschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedparam(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var schedParamAddress = ctx[CpuRegister.Rsi];
        if (attrAddress == 0 || schedParamAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryReadInt32(ctx, schedParamAddress, out var schedPriority))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { SchedPriority = schedPriority };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "4+h9EzwKF4I",
        ExportName = "scePthreadAttrSetschedpolicy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedpolicy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var policy = unchecked((int)ctx[CpuRegister.Rsi]);
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(attrAddress);
            _attrStates[attrAddress] = state with { SchedPolicy = policy };
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "UTXzJbWhhTE",
        ExportName = "scePthreadAttrSetstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetstacksize(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var stackSize = ctx[CpuRegister.Rsi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolvePthreadAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(resolvedAddress);
            var updated = state with { StackSize = stackSize };
            _attrStates[resolvedAddress] = updated;
            if (resolvedAddress != attrAddress)
            {
                _attrStates[attrAddress] = updated;
            }
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "2Q0z6rnBrTE",
        ExportName = "pthread_attr_setstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadAttrSetstacksize(CpuContext ctx)
    {
        return PthreadAttrSetstacksize(ctx);
    }

    [SysAbiExport(
        Nid = "Bvn74vj6oLo",
        ExportName = "scePthreadAttrSetstack",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetstack(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        var stackAddress = ctx[CpuRegister.Rsi];
        var stackSize = ctx[CpuRegister.Rdx];
        if (attrAddress == 0 || stackAddress == 0 || stackSize == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolvePthreadAttrHandle(ctx, attrAddress);
        lock (_stateGate)
        {
            var state = GetOrCreateAttrStateLocked(resolvedAddress);
            var updated = state with { StackAddress = stackAddress, StackSize = stackSize };
            _attrStates[resolvedAddress] = updated;
            if (resolvedAddress != attrAddress)
            {
                _attrStates[attrAddress] = updated;
            }
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "6ULAa0fq4jA",
        ExportName = "scePthreadRwlockInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockInit(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var syntheticHandle = AllocateSyntheticHandle(SyntheticRwlockHandleBase, ref _nextSyntheticRwlockHandleId);
        lock (_stateGate)
        {
            var resolvedAddress = ResolveRwlockHandle(ctx, rwlockAddress);
            if (_rwlockStates.Remove(resolvedAddress, out var existing))
            {
            }

            var rwlock = new PthreadRwlockState();
            _rwlockStates[rwlockAddress] = rwlock;
            _rwlockStates[syntheticHandle] = rwlock;
        }

        _ = KernelMemoryCompatExports.TryWriteUInt64Compat(ctx, rwlockAddress, syntheticHandle);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "ytQULN-nhL4",
        ExportName = "pthread_rwlock_init",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockInit(CpuContext ctx) => PthreadRwlockInit(ctx);

    [SysAbiExport(
        Nid = "BB+kb08Tl9A",
        ExportName = "scePthreadRwlockDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockDestroy(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var resolvedAddress = ResolveRwlockHandle(ctx, rwlockAddress);
        PthreadRwlockState? state;
        lock (_stateGate)
        {
            _rwlockStates.TryGetValue(resolvedAddress, out state);
        }

        if (state is null)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        lock (state.SyncRoot)
        {
            if (state.WriterThreadId != 0 || state.ReaderTotalCount != 0 || state.WaitingWriters != 0 || state.CompatWriterTotalCount != 0)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY;
            }
        }

        lock (_stateGate)
        {
            _rwlockStates.Remove(resolvedAddress);
            if (resolvedAddress != rwlockAddress)
            {
                _rwlockStates.Remove(rwlockAddress);
            }
        }

        _ = KernelMemoryCompatExports.TryWriteUInt64Compat(ctx, rwlockAddress, 0);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "1471ajPzxh0",
        ExportName = "pthread_rwlock_destroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockDestroy(CpuContext ctx) => PthreadRwlockDestroy(ctx);

    [SysAbiExport(
        Nid = "Ox9i0c7L5w0",
        ExportName = "scePthreadRwlockRdlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockRdlock(CpuContext ctx) => PthreadRwlockLockCore(ctx, ctx[CpuRegister.Rdi], write: false);

    [SysAbiExport(
        Nid = "iGjsr1WAtI0",
        ExportName = "pthread_rwlock_rdlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockRdlock(CpuContext ctx) => PthreadRwlockRdlock(ctx);

    [SysAbiExport(
        Nid = "mqdNorrB+gI",
        ExportName = "scePthreadRwlockWrlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockWrlock(CpuContext ctx) => PthreadRwlockLockCore(ctx, ctx[CpuRegister.Rdi], write: true);

    [SysAbiExport(
        Nid = "sIlRvQqsN2Y",
        ExportName = "pthread_rwlock_wrlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockWrlock(CpuContext ctx) => PthreadRwlockWrlock(ctx);

    [SysAbiExport(
        Nid = "SFxTMOfuCkE",
        ExportName = "pthread_rwlock_tryrdlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockTryrdlock(CpuContext ctx) =>
        PthreadRwlockTryLockCore(ctx, ctx[CpuRegister.Rdi], write: false);

    [SysAbiExport(
        Nid = "XhWHn6P5R7U",
        ExportName = "pthread_rwlock_trywrlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockTrywrlock(CpuContext ctx) =>
        PthreadRwlockTryLockCore(ctx, ctx[CpuRegister.Rdi], write: true);

    /// <summary>
    /// Non-blocking counterpart of <see cref="PthreadRwlockLockCore"/>: acquires
    /// only if the lock is free right now, otherwise reports BUSY.
    /// </summary>
    /// <remarks>
    /// Deliberately not routed through TryAcquireBlockedRwlock. That helper exists
    /// for the scheduler resume path and decrements WaitingWriters on success,
    /// which is correct only for a thread that previously incremented it. A fresh
    /// try never did, so reusing it would silently consume another thread's
    /// waiter count and let a queued writer be skipped.
    /// </remarks>
    private static int PthreadRwlockTryLockCore(CpuContext ctx, ulong rwlockAddress, bool write)
    {
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveRwlockState(ctx, rwlockAddress, createIfZero: true, out var resolvedAddress, out var rwlock))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadHandle();
        lock (rwlock.SyncRoot)
        {
            if (write)
            {
                if (rwlock.WriterThreadId == currentThreadId || rwlock.GetReaderCount(currentThreadId) > 0)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_DEADLOCK;
                }

                // Mirrors the blocking path's re-entrant compat-writer grant so the
                // two agree on what counts as already owning the lock.
                if (rwlock.CompatWriterCounts.GetValueOrDefault(currentThreadId) > 0)
                {
                    rwlock.AddCompatWriter(currentThreadId);
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                if (rwlock.WriterThreadId != 0 ||
                    rwlock.ReaderTotalCount != 0 ||
                    rwlock.CompatWriterTotalCount != 0)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY;
                }

                DetectRwlockWriterConflict(resolvedAddress, rwlock, currentThreadId, "trywrlock");
                rwlock.WriterThreadId = currentThreadId;
                return (int)OrbisGen2Result.ORBIS_GEN2_OK;
            }

            if (rwlock.WriterThreadId == currentThreadId)
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_DEADLOCK;
            }

            if (ReaderMustWaitForRwlock(rwlock, currentThreadId))
            {
                return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_BUSY;
            }

            rwlock.AddReader(currentThreadId);
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }
    }

    [SysAbiExport(
        Nid = "+L98PIbGttk",
        ExportName = "scePthreadRwlockUnlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockUnlock(CpuContext ctx)
    {
        var rwlockAddress = ctx[CpuRegister.Rdi];
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveRwlockState(ctx, rwlockAddress, createIfZero: false, out var resolvedAddress, out var rwlock))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadHandle();

        try
        {
            lock (rwlock.SyncRoot)
            {
                if (rwlock.RemoveCompatWriter(currentThreadId))
                {
                    Monitor.PulseAll(rwlock.SyncRoot);
                }
                else if (rwlock.WriterThreadId == currentThreadId)
                {
                    rwlock.WriterThreadId = 0;
                    Monitor.PulseAll(rwlock.SyncRoot);
                }
                else if (rwlock.RemoveReader(currentThreadId))
                {
                    if (rwlock.ReaderTotalCount == 0 || rwlock.WaitingWriters > 0)
                    {
                        Monitor.PulseAll(rwlock.SyncRoot);
                    }
                }
                else
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_PERMISSION_DENIED;
                }
            }
        }
        catch (SynchronizationLockException)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_PERMISSION_DENIED;
        }

        _ = GuestThreadExecution.Scheduler?.WakeBlockedThreads(rwlock.WakeKey);
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "EgmLo6EWgso",
        ExportName = "pthread_rwlock_unlock",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadRwlockUnlock(CpuContext ctx) => PthreadRwlockUnlock(ctx);

    [SysAbiExport(
        Nid = "yOfGg-I1ZII",
        ExportName = "scePthreadRwlockattrInit",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockattrInit(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        var syntheticHandle = AllocateSyntheticHandle(SyntheticRwlockAttrHandleBase, ref _nextSyntheticRwlockAttrHandleId);
        if (!KernelMemoryCompatExports.TryWriteUInt64Compat(ctx, attrAddress, syntheticHandle))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "i2ifZ3fS2fo",
        ExportName = "scePthreadRwlockattrDestroy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadRwlockattrDestroy(CpuContext ctx)
    {
        var attrAddress = ctx[CpuRegister.Rdi];
        if (attrAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        _ = KernelMemoryCompatExports.TryWriteUInt64Compat(ctx, attrAddress, 0);
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "mqULNdimTn0",
        ExportName = "pthread_key_create",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadKeyCreate(CpuContext ctx)
    {
        var outKeyAddress = ctx[CpuRegister.Rdi];
        var destructor = ctx[CpuRegister.Rsi];
        if (outKeyAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        int key;
        while (true)
        {
            key = Interlocked.Increment(ref _nextTlsKey) - 1;
            if (_tlsKeys.TryAdd(key, new TlsKeyState(destructor)))
            {
                break;
            }
        }

        if (!TryWriteInt32(ctx, outKeyAddress, key))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_MEMORY_FAULT;
        }

        if (_logTlsKey8 && key == 8)
        {
            Console.Error.WriteLine($"[LOADER][TRACE] tls.key_create: key=8 destructor=0x{destructor:X16}");
        }
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "geDaqgH9lTg",
        ExportName = "scePthreadKeyCreate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int OrbisPthreadKeyCreate(CpuContext ctx) => PosixPthreadKeyCreate(ctx);

    [SysAbiExport(
        Nid = "6BpEZuDT7YI",
        ExportName = "pthread_key_delete",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadKeyDelete(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        if (!_tlsKeys.TryRemove(key, out _))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        foreach (var values in _threadLocalSpecific.Values)
        {
            values.TryRemove(key, out _);
        }

        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "PrdHuuDekhY",
        ExportName = "scePthreadKeyDelete",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int OrbisPthreadKeyDelete(CpuContext ctx) => PosixPthreadKeyDelete(ctx);

    private static readonly bool _logTlsKey8 =
        string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_TLS_KEY8"), "1", StringComparison.Ordinal);

    private static readonly bool _dumpTls8Struct =
        string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_DUMP_TLS8_STRUCT"), "1", StringComparison.Ordinal);

    private static int _dumpTls8StructCount;

    // Spin-wait breaker: when a thread calls pthread_getspecific at a very high
    // rate (task-graph drain loop), periodically pump the scheduler and
    // force-wake blocked cooperative waiters.  This breaks the circular
    // dependency where the main thread spins waiting for workers to complete
    // tasks, but workers are blocked on condvars that the main thread never
    // reaches the code to signal.  Rate-limited to avoid overhead on normal
    // TLS lookups.
    private static int _getspecificSpinCount;
    private static long _lastSpinPumpTimestamp;
    private static int _spinPumpLogCount;

    [SysAbiExport(
        Nid = "WrOLvHU0yQM",
        ExportName = "pthread_setspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadSetspecific(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        var value = ctx[CpuRegister.Rsi];
        var currentThreadHandle = KernelPthreadState.GetCurrentThreadHandle();
        if (!_tlsKeys.ContainsKey(key))
        {
            if (_logTlsKey8 && key == 8)
            {
                Console.Error.WriteLine($"[LOADER][TRACE] tls.setspecific: key=8 MISSING_KEY thread=0x{currentThreadHandle:X16} value=0x{value:X16}");
            }
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var values = _threadLocalSpecific.GetOrAdd(
            currentThreadHandle,
            static _ => new ConcurrentDictionary<int, ulong>());
        values[key] = value;
        if (_logTlsKey8 && key == 8)
        {
            Console.Error.WriteLine($"[LOADER][TRACE] tls.setspecific: key=8 thread=0x{currentThreadHandle:X16} value=0x{value:X16}");
        }
        ctx[CpuRegister.Rax] = 0;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "+BzXYkqYeLE",
        ExportName = "scePthreadSetspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int OrbisPthreadSetspecific(CpuContext ctx) => PosixPthreadSetspecific(ctx);

    [SysAbiExport(
        Nid = "0-KXaS70xy4",
        ExportName = "pthread_getspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PosixPthreadGetspecific(CpuContext ctx)
    {
        var key = unchecked((int)ctx[CpuRegister.Rdi]);
        var currentThreadHandle = KernelPthreadState.GetCurrentThreadHandle();
        ulong value = 0;
        if (!_tlsKeys.ContainsKey(key))
        {
            if (_logTlsKey8 && key == 8)
            {
                Console.Error.WriteLine($"[LOADER][TRACE] tls.getspecific: key=8 MISSING_KEY thread=0x{currentThreadHandle:X16} -> 0");
            }
            ctx[CpuRegister.Rax] = 0;
            return (int)OrbisGen2Result.ORBIS_GEN2_OK;
        }

        if (_threadLocalSpecific.TryGetValue(currentThreadHandle, out var values) &&
            values.TryGetValue(key, out var storedValue))
        {
            value = storedValue;
        }

        if (_logTlsKey8 && key == 8)
        {
            Console.Error.WriteLine($"[LOADER][TRACE] tls.getspecific: key=8 thread=0x{currentThreadHandle:X16} -> 0x{value:X16}");
        }
        if (_dumpTls8Struct && key == 8 && value != 0)
        {
            var seq = Interlocked.Increment(ref _dumpTls8StructCount);
            // Dump at reads 1-2 (early init), 50000-50001 (during spin), and
            // every 100000 reads thereafter to track counter over time.
            if (seq <= 2 || seq == 50000 || seq == 50001 ||
                (seq >= 100000 && seq % 100000 == 0))
            {
                var sb = new System.Text.StringBuilder();
                sb.Append($"[LOADER][DIAG] tls8_struct@0x{value:X16} (seq={seq}):");
                for (uint off = 0; off < 320; off += 8)
                {
                    if (ctx.TryReadUInt64(value + off, out var qword))
                        sb.Append($" +0x{off:X3}=0x{qword:X16}");
                    else
                        sb.Append($" +0x{off:X3}=<fault>");
                }
                Console.Error.WriteLine(sb.ToString());
                // Dump the allocator bin-index table and pool base for size=32.
                // Bin table at 0x806886430: byte[(size+15)/16] = bin_index.
                // Pool base at 0x806886420.
                if (seq == 50000)
                {
                    var binSb = new System.Text.StringBuilder();
                    binSb.Append("[LOADER][DIAG] allocator_bin_table:");
                    for (uint sz = 16; sz <= 128; sz += 16)
                    {
                        var tableIdx = (sz + 15) / 16;
                        if (ctx.TryReadByte(0x806886430UL + tableIdx, out var binIdx))
                            binSb.Append($" size={sz}->bin={binIdx}");
                    }
                    if (ctx.TryReadUInt64(0x806886420, out var poolBase))
                        binSb.Append($" pool_base=0x{poolBase:X16}");
                    Console.Error.WriteLine(binSb.ToString());
                    // Dump the specific cache entry for size=32's bin.
                    if (ctx.TryReadByte(0x806886430UL + ((32 + 15) / 16), out var bin32) &&
                        ctx.TryReadUInt64(value + (uint)(bin32 * 32), out var flHead) &&
                        ctx.TryReadUInt64(value + (uint)(bin32 * 32) + 8, out var flCountRaw) &&
                        ctx.TryReadUInt64(value + (uint)(bin32 * 32) + 0x10, out var poolPtr))
                    {
                        Console.Error.WriteLine(
                            $"[LOADER][DIAG] allocator_bin32: bin={bin32} entry_off=0x{bin32 * 32:X3} " +
                            $"freelist_head=0x{flHead:X16} count={flCountRaw & 0xFFFFFFFF} " +
                            $"pool_ptr=0x{poolPtr:X16}");
                    }
                }
                // Dump slot 2 task entries (48-byte stride) to see their state.
                if (ctx.TryReadUInt64(value + 0x40, out var slot2Ptr) && slot2Ptr != 0 &&
                    ctx.TryReadUInt64(value + 0x48, out var slot2CountRaw))
                {
                    var slot2Count = (int)(slot2CountRaw & 0xFFFF);
                    if (slot2Count > 0 && slot2Count <= 256)
                    {
                        // Dump first 3 entries (48 bytes each = 6 qwords per entry)
                        var dumpEntries = Math.Min(slot2Count, 3);
                        for (int e = 0; e < dumpEntries; e++)
                        {
                            var entryBase = slot2Ptr + (uint)(e * 48);
                            var sb3 = new System.Text.StringBuilder();
                            sb3.Append($"[LOADER][DIAG] tls8_slot2_entry[{e}]@0x{entryBase:X16}:");
                            for (uint off = 0; off < 48; off += 8)
                            {
                                if (ctx.TryReadUInt64(entryBase + off, out var qword))
                                    sb3.Append($" +0x{off:X2}=0x{qword:X16}");
                                else
                                    sb3.Append($" +0x{off:X2}=<fault>");
                            }
                            Console.Error.WriteLine(sb3.ToString());
                        }
                    }
                }
            }
        }
        // Spin-wait breaker (DISABLED): the force-wake + Thread.Sleep(1) inside
        // the getspecific hot path disrupted the game's task-graph dispatch cadence.
        // The main thread's spin loop is timing-sensitive: it must poll the task
        // queue and dispatch workers at full speed.  Inserting a 1 ms sleep every
        // 8192 calls prevented the dispatch code from running at the expected rate,
        // causing workers to never receive tasks and the game to stall at 1 frame.
        // The original diagnosis (workers never signaled) was incorrect — the working
        // trace proves the game thread exits the spin loop on its own and dispatches
        // tasks without external help.
        // if ((Interlocked.Increment(ref _getspecificSpinCount) & 0x1FFF) == 0) { ... }
        ctx[CpuRegister.Rax] = value;
        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    [SysAbiExport(
        Nid = "eoht7mQOCmo",
        ExportName = "scePthreadGetspecific",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int OrbisPthreadGetspecific(CpuContext ctx) => PosixPthreadGetspecific(ctx);

    private const int PthreadDestructorIterations = 4;

    /// <summary>
    /// Runs the current thread's pthread TLS-key destructors, as POSIX
    /// requires on thread exit. Each key holding a non-null value with a
    /// registered destructor has its value cleared first and the destructor
    /// then invoked with the previous value; this repeats up to
    /// PTHREAD_DESTRUCTOR_ITERATIONS times so destructors that set new
    /// thread-local values are themselves cleaned up. Called on the exiting
    /// guest thread while it is still executable.
    /// </summary>
    public static void RunThreadLocalDestructors(CpuContext ctx)
    {
        var scheduler = GuestThreadExecution.Scheduler;
        if (scheduler is null)
        {
            return;
        }

        var threadHandle = KernelPthreadState.GetCurrentThreadHandle();
        if (!_threadLocalSpecific.TryGetValue(threadHandle, out var values))
        {
            return;
        }

        for (var iteration = 0; iteration < PthreadDestructorIterations; iteration++)
        {
            var ranAny = false;
            foreach (var entry in values)
            {
                var value = entry.Value;
                if (value == 0 ||
                    !_tlsKeys.TryGetValue(entry.Key, out var keyState) ||
                    keyState.Destructor == 0)
                {
                    continue;
                }

                // Clear before invoking, per POSIX, so a destructor that
                // re-sets the key is handled on the next iteration.
                if (!values.TryUpdate(entry.Key, 0, value))
                {
                    continue;
                }

                ranAny = true;
                _ = scheduler.TryCallGuestFunction(
                    ctx,
                    keyState.Destructor,
                    value,
                    0,
                    0,
                    0,
                    "pthread_tls_destructor",
                    out _);
            }

            if (!ranAny)
            {
                break;
            }
        }

        _threadLocalSpecific.TryRemove(threadHandle, out _);
    }

    private static int PthreadRwlockLockCore(CpuContext ctx, ulong rwlockAddress, bool write)
    {
        if (rwlockAddress == 0)
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_INVALID_ARGUMENT;
        }

        if (!TryResolveRwlockState(ctx, rwlockAddress, createIfZero: true, out var resolvedAddress, out var rwlock))
        {
            return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_NOT_FOUND;
        }

        var currentThreadId = KernelPthreadState.GetCurrentThreadHandle();
        lock (rwlock.SyncRoot)
        {
            if (write)
            {
                if (rwlock.WriterThreadId == currentThreadId || rwlock.GetReaderCount(currentThreadId) > 0)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_DEADLOCK;
                }

                if (rwlock.CompatWriterCounts.GetValueOrDefault(currentThreadId) > 0)
                {
                    rwlock.AddCompatWriter(currentThreadId);
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                if (GuestThreadExecution.IsGuestThread &&
                    !_strictRwlockWriterPreference &&
                    rwlock.WriterThreadId == 0 &&
                    rwlock.ReaderTotalCount == 0 &&
                    rwlock.CompatWriterTotalCount == 0)
                {
                    rwlock.AddCompatWriter(currentThreadId);
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                if (rwlock.WriterThreadId == 0 && rwlock.ReaderTotalCount == 0 && rwlock.CompatWriterTotalCount == 0)
                {
                    DetectRwlockWriterConflict(resolvedAddress, rwlock, currentThreadId, "wrlock");
                    rwlock.WriterThreadId = currentThreadId;
                    return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                }

                rwlock.WaitingWriters++;
                var transferredToScheduler = false;
                try
                {
                    if (GuestThreadExecution.IsGuestThread &&
                        GuestThreadExecution.TryGetCurrentImportCallFrame(out _) &&
                        GuestThreadExecution.RequestCurrentThreadBlock(
                            ctx,
                            "pthread_rwlock_wrlock",
                            rwlock.WakeKey,
                            new RwlockWaiter { Rwlock = rwlock, ThreadId = currentThreadId, Write = true }))
                    {
                        transferredToScheduler = true;
                        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                    }

                    while (rwlock.WriterThreadId != 0 || rwlock.ReaderTotalCount != 0 || rwlock.CompatWriterTotalCount != 0)
                    {
                        Monitor.Wait(rwlock.SyncRoot);
                    }

                    rwlock.WriterThreadId = currentThreadId;
                }
                finally
                {
                    if (!transferredToScheduler)
                    {
                        rwlock.WaitingWriters = Math.Max(0, rwlock.WaitingWriters - 1);
                    }
                }
            }
            else
            {
                if (rwlock.WriterThreadId == currentThreadId)
                {
                    return (int)OrbisGen2Result.ORBIS_GEN2_ERROR_DEADLOCK;
                }

                while (ReaderMustWaitForRwlock(rwlock, currentThreadId))
                {
                    if (GuestThreadExecution.IsGuestThread &&
                        GuestThreadExecution.TryGetCurrentImportCallFrame(out _) &&
                        GuestThreadExecution.RequestCurrentThreadBlock(
                            ctx,
                            "pthread_rwlock_rdlock",
                            rwlock.WakeKey,
                            new RwlockWaiter { Rwlock = rwlock, ThreadId = currentThreadId, Write = false }))
                    {
                        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
                    }

                    Monitor.Wait(rwlock.SyncRoot);
                }

                if (rwlock.WriterThreadId != 0 ||
                    rwlock.CompatWriterTotalCount > rwlock.CompatWriterCounts.GetValueOrDefault(currentThreadId))
                {
                    Console.Error.WriteLine(
                        $"[LOADER][ERROR] RWLOCK READER/WRITER COEXIST: resolved=0x{resolvedAddress:X} reader=0x{currentThreadId:X} " +
                        $"writer=0x{rwlock.WriterThreadId:X} compat_total={rwlock.CompatWriterTotalCount} readers_total={rwlock.ReaderTotalCount}");
                }
                rwlock.AddReader(currentThreadId);
            }
        }

        return (int)OrbisGen2Result.ORBIS_GEN2_OK;
    }

    private static bool TryAcquireBlockedRwlock(PthreadRwlockState rwlock, ulong currentThreadId, bool write)
    {
        lock (rwlock.SyncRoot)
        {
            if (write)
            {
                if (rwlock.WriterThreadId != 0 || rwlock.ReaderTotalCount != 0 || rwlock.CompatWriterTotalCount != 0)
                {
                    return false;
                }

                DetectRwlockWriterConflict(0, rwlock, currentThreadId, "wrlock-resume");
                rwlock.WriterThreadId = currentThreadId;
                rwlock.WaitingWriters = Math.Max(0, rwlock.WaitingWriters - 1);
                return true;
            }

            if (ReaderMustWaitForRwlock(rwlock, currentThreadId))
            {
                return false;
            }

            rwlock.AddReader(currentThreadId);
            return true;
        }
    }

    // Call while holding lock(rwlock.SyncRoot): an existing reader/writer here means a
    // writer would share the rwlock with another holder — a data race.
    private static void DetectRwlockWriterConflict(ulong resolvedAddress, PthreadRwlockState rwlock, ulong currentThreadId, string site)
    {
        if (rwlock.WriterThreadId != 0 ||
            rwlock.ReaderTotalCount != 0 ||
            rwlock.CompatWriterTotalCount > rwlock.CompatWriterCounts.GetValueOrDefault(currentThreadId))
        {
            Console.Error.WriteLine(
                $"[LOADER][ERROR] RWLOCK WRITER CONFLICT at {site}: resolved=0x{resolvedAddress:X} writer=0x{currentThreadId:X} " +
                $"existing_writer=0x{rwlock.WriterThreadId:X} readers_total={rwlock.ReaderTotalCount} compat_total={rwlock.CompatWriterTotalCount}");
        }
    }

    private static bool ReaderMustWaitForRwlock(PthreadRwlockState rwlock, ulong currentThreadId)
    {
        if (rwlock.WriterThreadId != 0)
        {
            return true;
        }

        if (rwlock.CompatWriterTotalCount > rwlock.CompatWriterCounts.GetValueOrDefault(currentThreadId))
        {
            return true;
        }

        return rwlock.WaitingWriters > 0 &&
               rwlock.GetReaderCount(currentThreadId) == 0;
    }

    private static string GetRwlockWakeKey(ulong rwlockAddress) => $"pthread_rwlock:0x{rwlockAddress:X16}";

    public static string? DumpRwlockStateForStall(ulong rwlockAddress)
    {
        PthreadRwlockState? rwlock;
        lock (_stateGate)
        {
            if (!_rwlockStates.TryGetValue(rwlockAddress, out rwlock))
            {
                return null;
            }
        }

        lock (rwlock.SyncRoot)
        {
            var readers = string.Join(",", rwlock.ReaderCounts.Select(pair => $"0x{pair.Key:X}x{pair.Value}"));
            var compatWriters = string.Join(",", rwlock.CompatWriterCounts.Select(pair => $"0x{pair.Key:X}x{pair.Value}"));
            return $"rwlock=0x{rwlockAddress:X16} writer=0x{rwlock.WriterThreadId:X} waiting_writers={rwlock.WaitingWriters} " +
                   $"readers_total={rwlock.ReaderTotalCount} readers=[{readers}] " +
                   $"compat_writers_total={rwlock.CompatWriterTotalCount} compat_writers=[{compatWriters}]";
        }
    }

    private static ulong ResolveRwlockHandle(CpuContext ctx, ulong rwlockAddress)
    {
        if (rwlockAddress == 0)
        {
            return 0;
        }

        lock (_stateGate)
        {
            if (_rwlockStates.ContainsKey(rwlockAddress))
            {
                return rwlockAddress;
            }
        }

        if (KernelMemoryCompatExports.TryReadUInt64Compat(ctx, rwlockAddress, out var pointedHandle) && pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_rwlockStates.ContainsKey(pointedHandle))
                {
                    return pointedHandle;
                }
            }
        }

        return rwlockAddress;
    }

    private static bool TryResolveRwlockState(CpuContext ctx, ulong rwlockAddress, bool createIfZero, out ulong resolvedAddress, [NotNullWhen(true)] out PthreadRwlockState? rwlock)
    {
        resolvedAddress = 0;
        rwlock = null;
        if (rwlockAddress == 0)
        {
            return false;
        }

        lock (_stateGate)
        {
            if (_rwlockStates.TryGetValue(rwlockAddress, out rwlock))
            {
                resolvedAddress = rwlockAddress;
                return true;
            }
        }

        if (!KernelMemoryCompatExports.TryReadUInt64Compat(ctx, rwlockAddress, out var pointedHandle))
        {
            return false;
        }

        if (pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_rwlockStates.TryGetValue(pointedHandle, out rwlock))
                {
                    _rwlockStates[rwlockAddress] = rwlock;
                    resolvedAddress = pointedHandle;
                    return true;
                }
            }

            resolvedAddress = pointedHandle;
            return false;
        }

        if (!createIfZero)
        {
            resolvedAddress = rwlockAddress;
            return false;
        }

        var createdRwlock = new PthreadRwlockState();
        var syntheticHandle = AllocateSyntheticHandle(SyntheticRwlockHandleBase, ref _nextSyntheticRwlockHandleId);
        lock (_stateGate)
        {
            _rwlockStates[rwlockAddress] = createdRwlock;
            _rwlockStates[syntheticHandle] = createdRwlock;
        }

        _ = KernelMemoryCompatExports.TryWriteUInt64Compat(ctx, rwlockAddress, syntheticHandle);
        resolvedAddress = syntheticHandle;
        rwlock = createdRwlock;
        return true;
    }

    private static ulong AllocateSyntheticHandle(ulong baseAddress, ref long nextId)
    {
        var id = unchecked((ulong)Interlocked.Increment(ref nextId));
        return baseAddress + (id << 4);
    }

    private static ThreadState GetOrCreateThreadStateLocked(ulong thread)
    {
        if (_threadStates.TryGetValue(thread, out var state))
        {
            return state;
        }

        var name = KernelPthreadState.TryGetThreadIdentity(thread, out var identity)
            ? identity.Name
            : $"Thread-{thread:X}";

        state = new ThreadState
        {
            Name = name,
            Priority = DefaultThreadPriority,
            AffinityMask = DefaultThreadAffinityMask,
            DetachState = DefaultDetachState,
            Attributes = PthreadAttrState.Default,
        };
        _threadStates[thread] = state;
        return state;
    }

    private static PthreadAttrState GetOrCreateAttrStateLocked(ulong attrAddress)
    {
        if (_attrStates.TryGetValue(attrAddress, out var state))
        {
            return state;
        }

        state = PthreadAttrState.Default;
        _attrStates[attrAddress] = state;
        return state;
    }

    private static ulong ResolvePthreadAttrHandle(CpuContext ctx, ulong attrAddress)
    {
        if (attrAddress == 0)
        {
            return 0;
        }

        lock (_stateGate)
        {
            if (_attrStates.ContainsKey(attrAddress))
            {
                return attrAddress;
            }
        }

        if (ctx.TryReadUInt64(attrAddress, out var pointedHandle) && pointedHandle != 0)
        {
            lock (_stateGate)
            {
                if (_attrStates.ContainsKey(pointedHandle))
                {
                    return pointedHandle;
                }
            }
        }

        return attrAddress;
    }

    private static bool TryWriteFixedUtf8CString(CpuContext ctx, ulong address, string value, int maxBytes)
    {
        if (maxBytes <= 0)
        {
            return false;
        }

        var utf8 = Encoding.UTF8.GetBytes(value);
        var payloadLength = Math.Min(utf8.Length, maxBytes - 1);
        var payload = new byte[payloadLength + 1];
        utf8.AsSpan(0, payloadLength).CopyTo(payload);
        payload[^1] = 0;
        return ctx.Memory.TryWrite(address, payload);
    }

    private static bool TryReadInt32(CpuContext ctx, ulong address, out int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        if (!ctx.Memory.TryRead(address, bytes))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        return true;
    }

    private static bool TryWriteInt32(CpuContext ctx, ulong address, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return ctx.Memory.TryWrite(address, bytes);
    }

    // POSIX-named aliases. libKernel exports each of these routines under two
    // NIDs -- a scePthread* name and the plain POSIX name -- and middleware
    // compiled against POSIX headers links the latter. Both take identical
    // arguments and, per the convention already used by scePthreadOnce's alias,
    // return the same OrbisGen2Result rather than translating to errno.

    [SysAbiExport(
        Nid = "a2P9wYGeZvc",
        ExportName = "pthread_setprio",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadSetprioPOSIX(CpuContext ctx) => PthreadSetprio(ctx);

    [SysAbiExport(
        Nid = "FIs3-UQT9sg",
        ExportName = "pthread_getschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadGetschedparamPOSIX(CpuContext ctx) => PthreadGetschedparam(ctx);

    [SysAbiExport(
        Nid = "vQm4fDEsWi8",
        ExportName = "pthread_attr_getstack",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstackPOSIX(CpuContext ctx) => PthreadAttrGetstack(ctx);

    [SysAbiExport(
        Nid = "Ucsu-OK+els",
        ExportName = "pthread_attr_get_np",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetNpPOSIX(CpuContext ctx) => PthreadAttrGet(ctx);

    [SysAbiExport(
        Nid = "JarMIy8kKEY",
        ExportName = "pthread_attr_setschedpolicy",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedpolicyPOSIX(CpuContext ctx) => PthreadAttrSetschedpolicy(ctx);

    [SysAbiExport(
        Nid = "E+tyo3lp5Lw",
        ExportName = "pthread_attr_setdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetdetachstatePOSIX(CpuContext ctx) => PthreadAttrSetdetachstate(ctx);

    [SysAbiExport(
        Nid = "euKRgm0Vn2M",
        ExportName = "pthread_attr_setschedparam",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetschedparamPOSIX(CpuContext ctx) => PthreadAttrSetschedparam(ctx);

    [SysAbiExport(
        Nid = "7ZlAakEf0Qg",
        ExportName = "pthread_attr_setinheritsched",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetinheritschedPOSIX(CpuContext ctx) => PthreadAttrSetinheritsched(ctx);

    [SysAbiExport(
        Nid = "0qOtCR-ZHck",
        ExportName = "pthread_attr_getstacksize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetstacksizePOSIX(CpuContext ctx) => PthreadAttrGetstacksize(ctx);

    [SysAbiExport(
        Nid = "VUT1ZSrHT0I",
        ExportName = "pthread_attr_getdetachstate",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetdetachstatePOSIX(CpuContext ctx) => PthreadAttrGetdetachstate(ctx);

    [SysAbiExport(
        Nid = "JKyG3SWyA10",
        ExportName = "pthread_attr_setguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrSetguardsizePOSIX(CpuContext ctx) => PthreadAttrSetguardsize(ctx);

    [SysAbiExport(
        Nid = "JNkVVsVDmOk",
        ExportName = "pthread_attr_getguardsize",
        Target = Generation.Gen4 | Generation.Gen5,
        LibraryName = "libKernel")]
    public static int PthreadAttrGetguardsizePOSIX(CpuContext ctx) => PthreadAttrGetguardsize(ctx);
}
