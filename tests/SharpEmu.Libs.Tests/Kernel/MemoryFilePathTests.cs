// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using SharpEmu.Libs.Kernel;
using Xunit;

namespace SharpEmu.Libs.Tests.Kernel;

public sealed class MemoryFilePathTests
{
    [Fact]
    public void ParsesRageMemoryDevicePath()
    {
        var ok = KernelMemoryCompatExports.TryParseMemoryFilePath(
            "memory:$0x14D4060000,101371,0:00158_hud_reticle.gfx",
            out var address,
            out var size);

        Assert.True(ok);
        Assert.Equal(0x14D4060000UL, address);
        Assert.Equal(101371L, size);
    }

    [Fact]
    public void ParsesWithoutHexPrefixAndTrailingName()
    {
        var ok = KernelMemoryCompatExports.TryParseMemoryFilePath(
            "memory:$1546DC0000,168790,0:00035_frontend_landing.gfx",
            out var address,
            out var size);

        Assert.True(ok);
        Assert.Equal(0x1546DC0000UL, address);
        Assert.Equal(168790L, size);
    }

    [Theory]
    [InlineData("/app0/common/data/foo.xml")]
    [InlineData("host:app0/eboot.bin")]
    [InlineData("memory:$0x1234")]          // no size field
    [InlineData("memory:$,123,0:x")]         // empty address
    [InlineData("")]
    public void RejectsNonMemoryOrMalformedPaths(string path)
    {
        Assert.False(KernelMemoryCompatExports.TryParseMemoryFilePath(path, out _, out _));
    }
}
