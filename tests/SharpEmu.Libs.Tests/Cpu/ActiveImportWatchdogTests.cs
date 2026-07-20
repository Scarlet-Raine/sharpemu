// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Core.Cpu.Native;
using Xunit;

namespace SharpEmu.Libs.Tests.Cpu;

public sealed class ActiveImportWatchdogTests
{
    [Theory]
    [InlineData(0, 100L, 150L, 100L)]
    [InlineData(1, 0L, 150L, 100L)]
    [InlineData(1, 100L, 150L, 0L)]
    public void MissingActiveImportState_DoesNotReceiveGrace(
        int activeCount,
        long startTimestamp,
        long currentTimestamp,
        long graceTicks)
    {
        Assert.False(DirectExecutionBackend.IsActiveImportWithinWatchdogGrace(
            activeCount,
            startTimestamp,
            currentTimestamp,
            graceTicks));
    }

    [Fact]
    public void ActiveImportWithinBound_ReceivesGrace()
    {
        Assert.True(DirectExecutionBackend.IsActiveImportWithinWatchdogGrace(
            activeImportCount: 1,
            activeImportStartTimestamp: 100,
            currentTimestamp: 199,
            graceTicks: 100));
    }

    [Theory]
    [InlineData(200L)]
    [InlineData(250L)]
    public void ActiveImportAtOrBeyondBound_DoesNotReceiveGrace(long currentTimestamp)
    {
        Assert.False(DirectExecutionBackend.IsActiveImportWithinWatchdogGrace(
            activeImportCount: 1,
            activeImportStartTimestamp: 100,
            currentTimestamp,
            graceTicks: 100));
    }
}
