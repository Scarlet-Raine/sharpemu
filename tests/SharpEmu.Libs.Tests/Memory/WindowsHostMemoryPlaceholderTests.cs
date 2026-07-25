// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Memory;
using SharpEmu.HLE.Host;
using SharpEmu.HLE.Host.Windows;
using Xunit;

namespace SharpEmu.Libs.Tests.Memory;

/// <summary>
/// Reserve-only guest windows are backed by MEM_RESERVE_PLACEHOLDER regions so
/// direct-memory aliases can replace parts of them. Plain VirtualAlloc
/// MEM_COMMIT is rejected on placeholders, which used to fail every fixed
/// mapping (sceKernelBatchMap) and lazy fault commit inside such a window —
/// the guest then aborted with "sceKernelBatchMap failed with error code:
/// 0x80020002". Commit must transparently split and replace placeholder runs.
/// </summary>
public sealed class WindowsHostMemoryPlaceholderTests
{
    private const ulong AllocationGranularity = 0x10000;

    [Fact]
    public unsafe void CommitReplacesInteriorPlaceholderRun()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var host = new WindowsHostMemory();
        var placeholderBase = host.ReservePlaceholder(0, 8 * AllocationGranularity);
        Assert.NotEqual(0UL, placeholderBase);

        try
        {
            // Interior, granularity-misaligned run: forces the commit path to
            // widen to allocation granularity, split the placeholder, and
            // replace the split with a committed private allocation.
            var commitAddress = placeholderBase + 0x11000;
            Assert.True(host.Commit(commitAddress, 0x2000, HostPageProtection.ReadWrite));

            *(byte*)commitAddress = 0x5A;
            Assert.Equal(0x5A, *(byte*)commitAddress);

            // Committing the same run again stays idempotent.
            Assert.True(host.Commit(commitAddress, 0x2000, HostPageProtection.ReadWrite));
        }
        finally
        {
            _ = host.Free(placeholderBase);
        }
    }

    [Fact]
    public void TryBackFixedRangeCommitsInsideReserveOnlyPlaceholder()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // 8 GiB is above both reserve-only thresholds, so the exact claim
        // takes the ReservePlaceholder path — the same shape as the guest's
        // sceKernelReserveVirtualRange window.
        const ulong size = 8UL << 30;
        using var memory = new PhysicalVirtualMemory(new WindowsHostMemory());
        var reserved = 0UL;
        foreach (var candidate in new[]
                 {
                     0x0000_5800_0000_0000UL,
                     0x0000_6200_0000_0000UL,
                     0x0000_6C00_0000_0000UL,
                 })
        {
            if (memory.TryAllocateAtExact(candidate, size, executable: false, out reserved))
            {
                break;
            }
        }

        Assert.NotEqual(0UL, reserved);

        // A fixed mapping inside the reservation (sceKernelBatchMap) must
        // succeed, and the pages must be usable through the guest memory API.
        var fixedBase = reserved + 0x0010_0000;
        Assert.True(memory.TryBackFixedRange(fixedBase, 0x30000, executable: false));

        ReadOnlySpan<byte> payload = [0xDE, 0xAD, 0xBE, 0xEF];
        Assert.True(memory.TryWrite(fixedBase + 0x1234, payload));
        Span<byte> readback = stackalloc byte[4];
        Assert.True(memory.TryRead(fixedBase + 0x1234, readback));
        Assert.True(readback.SequenceEqual(payload));
    }
}
