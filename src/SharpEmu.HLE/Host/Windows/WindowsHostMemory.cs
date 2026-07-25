// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System.Runtime.InteropServices;

namespace SharpEmu.HLE.Host.Windows;

/// <summary>
/// Windows implementation over VirtualAlloc/VirtualFree/VirtualProtect/VirtualQuery.
/// Sealed so the JIT can devirtualize interface calls on fault-handling hot paths.
/// </summary>
internal sealed unsafe partial class WindowsHostMemory : ISharedMemoryMappingHost, IReplaceableReservationHost
{
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint MEM_FREE = 0x10000;
    private const uint MEM_RESERVE_PLACEHOLDER = 0x40000;
    private const uint MEM_REPLACE_PLACEHOLDER = 0x4000;
    private const uint MEM_PRESERVE_PLACEHOLDER = 0x2;
    private const int ERROR_INVALID_ADDRESS = 487;

    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint SEC_COMMIT = 0x08000000;
    private const uint FILE_MAP_WRITE = 0x0002;
    private const uint FILE_MAP_EXECUTE = 0x0020;
    private const ulong AllocationGranularity = 0x10000;
    private static readonly object SharedViewGate = new();
    private static readonly HashSet<ulong> SharedViewBases = [];

    public ulong Allocate(ulong desiredAddress, ulong size, HostPageProtection protection)
    {
        return (ulong)VirtualAlloc((void*)desiredAddress, (nuint)size, MEM_COMMIT | MEM_RESERVE, ToNativeProtection(protection));
    }

    public ulong Reserve(ulong desiredAddress, ulong size, HostPageProtection protection)
    {
        return (ulong)VirtualAlloc((void*)desiredAddress, (nuint)size, MEM_RESERVE, ToNativeProtection(protection));
    }

    public bool Commit(ulong address, ulong size, HostPageProtection protection)
    {
        if (VirtualAlloc((void*)address, (nuint)size, MEM_COMMIT, ToNativeProtection(protection)) != null)
        {
            return true;
        }

        // MEM_COMMIT is rejected on MEM_RESERVE_PLACEHOLDER pages, which back
        // the guest's reserve-only windows (kept replaceable so direct-memory
        // aliases can map into them). A fixed mapping such as sceKernelBatchMap
        // or a lazy fault commit inside such a window must still succeed:
        // split each placeholder run to the requested range and replace it
        // with a committed private allocation.
        return TryCommitReplacingPlaceholders(address, size, ToNativeProtection(protection));
    }

    private static bool TryCommitReplacingPlaceholders(ulong address, ulong size, uint nativeProtection)
    {
        if (size == 0)
        {
            return false;
        }

        var end = ulong.MaxValue - address < size ? ulong.MaxValue : address + size;
        var cursor = address;
        while (cursor < end)
        {
            if (VirtualQuery((void*)cursor, out var info, (nuint)sizeof(MemoryBasicInformation64)) == 0)
            {
                return false;
            }

            var regionEnd = ulong.MaxValue - info.BaseAddress < info.RegionSize
                ? ulong.MaxValue
                : info.BaseAddress + info.RegionSize;
            if (regionEnd <= cursor)
            {
                return false;
            }

            var runEnd = Math.Min(end, regionEnd);
            if (info.State == MEM_COMMIT)
            {
                cursor = runEnd;
                continue;
            }

            if (info.State != MEM_RESERVE)
            {
                return false;
            }

            if (info.AllocationProtect != PAGE_NOACCESS)
            {
                // An ordinary reservation: a plain commit of this run works.
                if (VirtualAlloc((void*)cursor, (nuint)(runEnd - cursor), MEM_COMMIT, nativeProtection) == null)
                {
                    return false;
                }

                cursor = runEnd;
                continue;
            }

            // Placeholder run. Splitting operates at allocation granularity and
            // the placeholder's own bounds are granularity-aligned, so widening
            // the request to granularity stays inside this run.
            var replaceStart = Math.Max(info.BaseAddress, cursor & ~(AllocationGranularity - 1));
            var replaceEnd = Math.Min(
                regionEnd,
                (runEnd + AllocationGranularity - 1) & ~(AllocationGranularity - 1));
            if (!TryPartitionPlaceholder(replaceStart, replaceEnd - replaceStart, out _))
            {
                return false;
            }

            if (VirtualAlloc2(
                    GetCurrentProcess(),
                    (void*)replaceStart,
                    (nuint)(replaceEnd - replaceStart),
                    MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                    nativeProtection,
                    null,
                    0) == null)
            {
                return false;
            }

            cursor = runEnd;
        }

        return true;
    }

    public bool Free(ulong address)
    {
        lock (SharedViewGate)
        {
            if (SharedViewBases.Remove(address))
            {
                return UnmapViewOfFile((void*)address);
            }
        }

        return VirtualFree((void*)address, 0, MEM_RELEASE);
    }

    public ulong ReservePlaceholder(ulong desiredAddress, ulong size)
    {
        return (ulong)VirtualAlloc2(
            GetCurrentProcess(),
            (void*)desiredAddress,
            (nuint)size,
            MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS,
            null,
            0);
    }

    public bool TryMapShared(ulong firstAddress, ulong secondAddress, ulong size, HostPageProtection protection)
    {
        if (firstAddress == 0 || secondAddress == 0 || firstAddress == secondAddress ||
            size == 0 || (firstAddress % AllocationGranularity) != 0 ||
            (secondAddress % AllocationGranularity) != 0 || (size % AllocationGranularity) != 0)
        {
            return false;
        }

        var mapping = CreateFileMapping(
            new nint(-1),
            nint.Zero,
            ToNativeProtection(protection) | SEC_COMMIT,
            (uint)(size >> 32),
            (uint)size,
            null);
        if (mapping == 0)
        {
            TraceSharedMappingFailure("section", firstAddress, secondAddress, size, Marshal.GetLastPInvokeError());
            return false;
        }

        try
        {
            var access = FILE_MAP_WRITE |
                (protection is HostPageProtection.Execute or HostPageProtection.ReadExecute or HostPageProtection.ReadWriteExecute
                    ? FILE_MAP_EXECUTE
                    : 0);
            var first = MapViewOfFileEx(mapping, access, 0, 0, (nuint)size, (void*)firstAddress);
            if (first != (void*)firstAddress)
            {
                TraceSharedMappingFailure("first-view", firstAddress, secondAddress, size, Marshal.GetLastPInvokeError());
                if (first != null)
                {
                    _ = UnmapViewOfFile(first);
                }

                return false;
            }

            var second = MapViewOfFileEx(mapping, access, 0, 0, (nuint)size, (void*)secondAddress);
            if (second == null)
            {
                if (!TryPartitionPlaceholder(secondAddress, size, out var placeholderError))
                {
                    TraceSharedMappingFailure("partition-placeholder", firstAddress, secondAddress, size, placeholderError);
                }
                else
                {
                    second = MapViewOfFile3(
                        mapping,
                        GetCurrentProcess(),
                        (void*)secondAddress,
                        0,
                        (nuint)size,
                        MEM_REPLACE_PLACEHOLDER,
                        ToNativeProtection(protection),
                        null,
                        0);
                    if (second == null)
                    {
                        TraceSharedMappingFailure("replace-placeholder", firstAddress, secondAddress, size, Marshal.GetLastPInvokeError());
                    }
                }
            }
            if (second != (void*)secondAddress)
            {
                TraceSharedMappingFailure("second-view", firstAddress, secondAddress, size, Marshal.GetLastPInvokeError());
                if (second != null)
                {
                    _ = UnmapViewOfFile(second);
                }

                _ = UnmapViewOfFile(first);
                return false;
            }

            lock (SharedViewGate)
            {
                SharedViewBases.Add(firstAddress);
                SharedViewBases.Add(secondAddress);
            }

            return true;
        }
        finally
        {
            _ = CloseHandle(mapping);
        }
    }

    /// <summary>
    /// Isolates an exact range inside a placeholder so it can be replaced by a
    /// section view. VirtualFree splits from a placeholder's base, rather than
    /// from an arbitrary interior address.
    /// </summary>
    private static bool TryPartitionPlaceholder(ulong address, ulong size, out int error)
    {
        error = ERROR_INVALID_ADDRESS;
        if (VirtualQuery((void*)address, out var info, (nuint)sizeof(MemoryBasicInformation64)) == 0 ||
            info.State != MEM_RESERVE ||
            info.AllocationProtect != PAGE_NOACCESS ||
            info.BaseAddress > address ||
            ulong.MaxValue - info.BaseAddress < info.RegionSize)
        {
            return false;
        }

        var placeholderEnd = info.BaseAddress + info.RegionSize;
        if (ulong.MaxValue - address < size || address + size > placeholderEnd)
        {
            return false;
        }

        if (info.BaseAddress != address &&
            !VirtualFree(
                (void*)info.BaseAddress,
                (nuint)(address - info.BaseAddress),
                MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER))
        {
            error = Marshal.GetLastPInvokeError();
            return false;
        }

        if (address + size != placeholderEnd &&
            !VirtualFree(
                (void*)address,
                (nuint)size,
                MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER))
        {
            error = Marshal.GetLastPInvokeError();
            return false;
        }

        return true;
    }

    private static void TraceSharedMappingFailure(
        string phase,
        ulong firstAddress,
        ulong secondAddress,
        ulong size,
        int error)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SHARPEMU_LOG_SHARED_MEMORY_MAP"), "1", StringComparison.Ordinal))
        {
            return;
        }

        Console.Error.WriteLine(
            $"[LOADER][TRACE] shared_map {phase}: first=0x{firstAddress:X16} " +
            $"second=0x{secondAddress:X16} size=0x{size:X16} error={error}");
    }

    public bool Protect(ulong address, ulong size, HostPageProtection protection, out uint rawOldProtection)
    {
        return VirtualProtect((void*)address, (nuint)size, ToNativeProtection(protection), out rawOldProtection);
    }

    public bool ProtectRaw(ulong address, ulong size, uint rawProtection, out uint rawOldProtection)
    {
        return VirtualProtect((void*)address, (nuint)size, rawProtection, out rawOldProtection);
    }

    public bool Query(ulong address, out HostRegionInfo info)
    {
        if (VirtualQuery((void*)address, out var mbi, (nuint)sizeof(MemoryBasicInformation64)) == 0)
        {
            info = default;
            return false;
        }

        info = new HostRegionInfo(
            mbi.BaseAddress,
            mbi.AllocationBase,
            mbi.RegionSize,
            ToRegionState(mbi.State),
            mbi.State,
            ToHostProtection(mbi.Protect),
            mbi.Protect,
            mbi.AllocationProtect);
        return true;
    }

    public void FlushInstructionCache(ulong address, ulong size)
    {
        FlushInstructionCache(GetCurrentProcess(), (void*)address, (nuint)size);
    }

    private static uint ToNativeProtection(HostPageProtection protection) => protection switch
    {
        HostPageProtection.NoAccess => PAGE_NOACCESS,
        HostPageProtection.ReadOnly => PAGE_READONLY,
        HostPageProtection.ReadWrite => PAGE_READWRITE,
        HostPageProtection.Execute => PAGE_EXECUTE,
        HostPageProtection.ReadExecute => PAGE_EXECUTE_READ,
        HostPageProtection.ReadWriteExecute => PAGE_EXECUTE_READWRITE,
        HostPageProtection.ExecuteWriteCopy => PAGE_EXECUTE_WRITECOPY,
        _ => throw new ArgumentOutOfRangeException(nameof(protection), protection, null),
    };

    private static HostRegionState ToRegionState(uint state) => state switch
    {
        MEM_COMMIT => HostRegionState.Committed,
        MEM_RESERVE => HostRegionState.Reserved,
        MEM_FREE => HostRegionState.Free,
        _ => HostRegionState.Free,
    };

    private static HostPageProtection ToHostProtection(uint rawProtection)
    {
        // Strip PAGE_GUARD/PAGE_NOCACHE/PAGE_WRITECOMBINE modifiers; callers needing
        // them compare HostRegionInfo.RawProtection directly.
        return (rawProtection & 0xFF) switch
        {
            PAGE_READONLY => HostPageProtection.ReadOnly,
            PAGE_READWRITE => HostPageProtection.ReadWrite,
            PAGE_WRITECOPY => HostPageProtection.ReadWrite,
            PAGE_EXECUTE => HostPageProtection.Execute,
            PAGE_EXECUTE_READ => HostPageProtection.ReadExecute,
            PAGE_EXECUTE_READWRITE => HostPageProtection.ReadWriteExecute,
            PAGE_EXECUTE_WRITECOPY => HostPageProtection.ExecuteWriteCopy,
            _ => HostPageProtection.NoAccess,
        };
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial void* VirtualAlloc(void* lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [LibraryImport("kernelbase.dll", SetLastError = true)]
    private static partial void* VirtualAlloc2(
        void* process,
        void* baseAddress,
        nuint size,
        uint allocationType,
        uint pageProtection,
        void* extendedParameters,
        uint parameterCount);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileMappingW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateFileMapping(
        nint hFile,
        nint lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string? lpName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial void* MapViewOfFileEx(
        nint hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        nuint dwNumberOfBytesToMap,
        void* lpBaseAddress);

    [LibraryImport("kernelbase.dll", SetLastError = true)]
    private static partial void* MapViewOfFile3(
        nint hFileMappingObject,
        void* process,
        void* baseAddress,
        ulong offset,
        nuint viewSize,
        uint allocationType,
        uint pageProtection,
        void* extendedParameters,
        uint parameterCount);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UnmapViewOfFile(void* lpBaseAddress);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualFree(void* lpAddress, nuint dwSize, uint dwFreeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualProtect(void* lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [LibraryImport("kernel32.dll")]
    private static partial nuint VirtualQuery(void* lpAddress, out MemoryBasicInformation64 lpBuffer, nuint dwLength);

    [LibraryImport("kernel32.dll")]
    private static partial void* GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlushInstructionCache(void* hProcess, void* lpBaseAddress, nuint dwSize);

    private struct MemoryBasicInformation64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint Alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint Alignment2;
    }
}
