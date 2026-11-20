#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <string>
#include <cwchar>

#include "core/ProtectedDirectory.h"
#include "core/Text.h"

namespace protected_runtime {
namespace {

// SYSTEM and BUILTIN\Administrators are the only trusted owners. Files created
// by an elevated but non-SYSTEM run are owned by the administrator account and
// get repaired below, so a tree pre-created by a standard user can never keep
// its ownership.
bool isTrustedOwner(PSID owner) {
    if (!owner || !IsValidSid(owner)) {
        return false;
    }
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(buffer);
    if (CreateWellKnownSid(WinLocalSystemSid, nullptr, buffer, &size) && EqualSid(owner, buffer)) {
        return true;
    }
    size = sizeof(buffer);
    return CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, buffer, &size) && EqualSid(owner, buffer);
}

// Assigns ownership to BUILTIN\Administrators. Runs elevated (GUI, service and
// watchdog all do), so SeTakeOwnershipPrivilege can be enabled and the caller's
// Administrators membership satisfies the owner assignment rules.
bool setTrustedOwner(const std::wstring& path) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_PRIVILEGES privileges{};
    bool ok = LookupPrivilegeValueW(nullptr, SE_TAKE_OWNERSHIP_NAME, &privileges.Privileges[0].Luid) != 0;
    if (ok) {
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) != 0 &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    if (!ok) {
        return false;
    }
    BYTE admin[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admin);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &size)) {
        return false;
    }
    return SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                 admin, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
}

bool applyProtectedDacl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kProtectedDirSddl, SDDL_REVISION_1, &descriptor,
                                                              nullptr)) {
        return false;
    }
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    const bool ok = GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl, &daclDefaulted) && daclPresent &&
                    SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                          nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
    LocalFree(descriptor);
    return ok;
}

bool isReparsePoint(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// Owner repair plus DACL reset for one existing file or directory.
bool secureExistingEntry(const std::wstring& path, std::string& error) {
    if (isReparsePoint(path)) {
        error = "reparse point inside the protected data folder: " + narrow(path);
        return false;
    }
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr,
                              nullptr, &descriptor) != ERROR_SUCCESS) {
        error = "cannot read the owner of " + narrow(path);
        return false;
    }
    const bool ownerOk = isTrustedOwner(owner);
    LocalFree(descriptor);
    if (!ownerOk && !setTrustedOwner(path)) {
        error = "untrusted owner cannot be repaired on " + narrow(path);
        return false;
    }
    if (!applyProtectedDacl(path)) {
        error = "the protected DACL cannot be applied to " + narrow(path);
        return false;
    }
    return true;
}

}  // namespace

bool ensureDataDirectory(std::wstring& out, std::string& error) {
    out.clear();
    error.clear();

    wchar_t base[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, base) != S_OK) {
        error = "the ProgramData known folder could not be resolved";
        return false;
    }
    const std::wstring root = base;
    const std::wstring directory = root + L"\\9NS";

    const protected_paths::PolicyResult shape = protected_paths::validateRuntimeDataPath(directory, root);
    if (!shape.ok) {
        error = shape.error;
        return false;
    }
    if (isReparsePoint(root)) {
        error = "the ProgramData location is a reparse point: " + narrow(root);
        return false;
    }

    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(directory.c_str(), nullptr)) {
            error = "cannot create the data folder " + narrow(directory) + " (error " +
                    std::to_string(GetLastError()) + ")";
            return false;
        }
    } else if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        error = "the data folder is a reparse point: " + narrow(directory);
        return false;
    } else if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        error = "the data folder path is not a directory: " + narrow(directory);
        return false;
    }

    if (!secureExistingEntry(directory, error)) {
        return false;
    }

    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((directory + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        error = "cannot enumerate the data folder " + narrow(directory);
        return false;
    }
    bool childrenOk = true;
    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        if (!secureExistingEntry(directory + L"\\" + findData.cFileName, error)) {
            childrenOk = false;
            break;
        }
    } while (FindNextFileW(find, &findData));
    FindClose(find);
    if (!childrenOk) {
        return false;
    }

    out = directory;
    return true;
}

}  // namespace protected_runtime
