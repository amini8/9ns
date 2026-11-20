#pragma once

#include <windows.h>

namespace setup {

// Pure screening predicate for an allow ACE. Inherit-only ACEs do not apply to
// this ancestor. Do not treat READ_CONTROL/SYNCHRONIZE in generic file rights
// as write access. At a drive root, adding unrelated children is permitted.
inline bool ancestorAceAllowsMutation(DWORD mask, BYTE flags, bool driveRoot) {
    if (flags & INHERIT_ONLY_ACE) return false;
    const DWORD mutation = driveRoot
        ? GENERIC_ALL | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD
        : GENERIC_WRITE | GENERIC_ALL | DELETE | WRITE_DAC | WRITE_OWNER |
          FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
    return (mask & mutation) != 0;
}

}  // namespace setup
