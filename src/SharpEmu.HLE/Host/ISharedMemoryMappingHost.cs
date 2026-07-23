// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

namespace SharpEmu.HLE.Host;

/// <summary>
/// Creates two exact-address views of the same anonymous host backing.
/// </summary>
public interface ISharedMemoryMappingHost : IHostMemory
{
    bool TryMapShared(ulong firstAddress, ulong secondAddress, ulong size, HostPageProtection protection);
}
