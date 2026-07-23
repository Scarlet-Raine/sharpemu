// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE;

/// <summary>
/// Supports direct-memory physical and virtual aliases backed by the same pages.
/// </summary>
public interface IDirectMemoryAliasSpace
{
    bool TryMapDirectMemoryAlias(
        ulong physicalAddress,
        ulong virtualAddress,
        ulong size,
        bool executable);
}
