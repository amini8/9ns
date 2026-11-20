#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <aclapi.h>
#include <commctrl.h>
#include <sddl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <setupapi.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <VersionHelpers.h>

#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <memory>
#include <new>

#include "../core/ProtectedDirectory.h"
#include "../core/Text.h"
#include "../core/WindowsService.h"
#include "SetupOptions.h"
#include "SetupSecurity.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")

namespace {

constexpr int kWndWidth = 700;
constexpr int kWndHeight = 560;
constexpr UINT kStatusMessage = WM_APP + 1;
constexpr UINT kCompleteMessage = WM_APP + 2;
constexpr wchar_t kUninstallKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\9NS";
enum class Page { Welcome, License, Mode, Destination, Components, Review, Progress, Finish };
Page g_page = Page::Welcome;
std::vector<HWND> g_pages[8];
setup::Options g_options;
std::wstring g_registeredDir;
std::wstring g_logPath;
HANDLE g_log = INVALID_HANDLE_VALUE;
bool g_logFailed = false;
UINT g_dpi = 96;
bool g_custom = false;
int g_exitCode = ERROR_INSTALL_USEREXIT;
struct StatusUpdate { int progress; std::wstring text; };
struct Completion { int code; std::wstring text; };
void consoleOutput(const std::wstring& text);
bool createUninstallFiles(const std::wstring& destDir, protected_paths::InstallManifest& manifest,
                          std::wstring& errorOut);

HWND g_hWnd = nullptr;
HWND g_hEditDest = nullptr;
HWND g_hChkDesktop = nullptr;
HWND g_hChkStartMenu = nullptr;
HWND g_hChkService = nullptr;
HWND g_hChkDriver = nullptr;
HWND g_hChkLaunch = nullptr;
HWND g_hProgress = nullptr;
HWND g_hStatus = nullptr;
HWND g_hBtnInstall = nullptr;
HWND g_hBtnCancel = nullptr;
HWND g_hBtnBack = nullptr;
HWND g_hTitle = nullptr;
HWND g_hSubtitle = nullptr;
HWND g_hAccept = nullptr;
HWND g_hTypical = nullptr;
HWND g_hCustom = nullptr;
HWND g_hReview = nullptr;
HWND g_hDetails = nullptr;
HWND g_hFinish = nullptr;
HFONT g_hFontNormal = nullptr;
HFONT g_hFontTitle = nullptr;

bool g_installing = false;

// Creates a Windows shell shortcut (.lnk)
bool createShortcut(const std::wstring& targetExe, const std::wstring& linkPath, const std::wstring& description, const std::wstring& workingDir) {
    IShellLinkW* psl = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, reinterpret_cast<void**>(&psl));
    if (SUCCEEDED(hr)) {
        psl->SetPath(targetExe.c_str());
        psl->SetDescription(description.c_str());
        psl->SetWorkingDirectory(workingDir.c_str());

        IPersistFile* ppf = nullptr;
        hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf));
        if (SUCCEEDED(hr)) {
            hr = ppf->Save(linkPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    return SUCCEEDED(hr);
}

// Executes a hidden process by its absolute path and waits for completion. The
// application path never goes through the shell search order and arguments are
// passed as command-line data, never as interpreter source.
bool runHidden(const std::wstring& application, const std::wstring& arguments) {
    const std::wstring cmd =
        protected_paths::quoteCommandLineArgument(application) + (arguments.empty() ? L"" : L" " + arguments);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');
    if (!CreateProcessW(application.c_str(), buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &pi)) {
        return false;
    }
    const DWORD wait = WaitForSingleObject(pi.hProcess, 60000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return wait == WAIT_OBJECT_0 && exitCode == 0;
}

// Absolute path of a System32 helper (tar.exe, cmd.exe); empty on failure.
std::wstring systemHelperPath(const wchar_t* name) {
    wchar_t systemDir[MAX_PATH] = {};
    const UINT length = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }
    return std::wstring(systemDir) + L"\\" + name;
}

// Cryptographic randomness for staging names.
bool randomHex(std::string& out, size_t byteCount) {
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    std::vector<BYTE> buffer(byteCount);
    const BOOL ok = CryptGenRandom(provider, static_cast<DWORD>(buffer.size()), buffer.data());
    CryptReleaseContext(provider, 0);
    if (!ok) {
        return false;
    }
    static const char kHex[] = "0123456789abcdef";
    out.clear();
    out.reserve(byteCount * 2);
    for (const BYTE b : buffer) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return true;
}

bool isReparsePoint(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

// Applies a protected DACL (PROTECTED, no inherited ACEs) from an SDDL string.
bool applyProtectedDacl(const std::wstring& path, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
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

bool securePayloadPath(const std::wstring& path, bool directory, std::wstring& error) {
#ifdef NS9_INSTALLER_TEST
    // File-placement regressions run as an ordinary user with temporary roots;
    // actual administrative ACL mutation is reserved for elevated VM tests.
    (void)path; (void)directory; (void)error;
    return true;
#else
    const wchar_t* sddl = directory ? L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
                                   : L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)";
    if (applyProtectedDacl(path, sddl)) return true;
    error = L"Cannot secure the installed entry: " + path;
    return false;
#endif
}

// Reject mutable ancestors for well-known weak principals. Drive-root child
// creation alone is harmless; deleting existing children or rewriting its DACL
// is not. This is conservative screening, not an effective-access calculation.
bool parentChainIsProtected(const std::wstring& destDir, std::wstring& errorOut) {
    std::wstring current = destDir;
    for (;;) {
        const size_t slash = current.find_last_of(L'\\');
        if (slash == std::wstring::npos || slash < 2) {
            break;  // reached the drive root
        }
        const bool driveRoot = slash == 2;
        current = current.substr(0, driveRoot ? 3 : slash);
        if (isReparsePoint(current)) {
            errorOut = L"The parent folder is a reparse point: " + current;
            return false;
        }
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        PACL dacl = nullptr;
        if (GetNamedSecurityInfoW(current.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                  &dacl, nullptr, &descriptor) != ERROR_SUCCESS) {
            errorOut = L"The ACL of the parent folder cannot be read: " + current;
            return false;
        }
        bool weakWrite = dacl == nullptr;  // NULL DACL grants unrestricted access.
        if (dacl) {
            for (DWORD i = 0; i < dacl->AceCount && !weakWrite; ++i) {
                ACE_HEADER* aceHeader = nullptr;
                if (!GetAce(dacl, i, reinterpret_cast<void**>(&aceHeader))) {
                    weakWrite = true;
                    break;
                }
                if (aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                    continue;
                }
                const ACCESS_ALLOWED_ACE* ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(aceHeader);
                if (!setup::ancestorAceAllowsMutation(ace->Mask, aceHeader->AceFlags, driveRoot)) {
                    continue;
                }
                const PSID sid = const_cast<PSID>(reinterpret_cast<const void*>(&ace->SidStart));
                for (const WELL_KNOWN_SID_TYPE weak : {WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid,
                                                       WinInteractiveSid, WinAnonymousSid, WinNetworkSid}) {
                    BYTE buffer[SECURITY_MAX_SID_SIZE];
                    DWORD size = sizeof(buffer);
                    if (CreateWellKnownSid(weak, nullptr, buffer, &size) && EqualSid(sid, buffer)) {
                        weakWrite = true;
                        break;
                    }
                }
            }
        }
        LocalFree(descriptor);
        if (weakWrite) {
            errorOut = L"A parent folder is writable by non-administrators: " + current;
            return false;
        }
        if (driveRoot) break;
    }
    return true;
}

// Writes every byte and flushes; partial writes are a failure.
bool writeAllBytes(HANDLE file, const void* data, DWORD size) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    DWORD total = 0;
    while (total < size) {
        DWORD written = 0;
        if (!WriteFile(file, bytes + total, size - total, &written, nullptr) || written == 0) {
            return false;
        }
        total += written;
    }
    return FlushFileBuffers(file) != 0;
}

// Returns the NineNsFlt service state: 0 = absent, 1 = running, 2 = present but not running
int driverServiceState() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return 0;
    }
    int state = 0;
    SC_HANDLE svc = OpenServiceW(scm, L"NineNsFlt", SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        state = 2;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
            state = (ssp.dwCurrentState == SERVICE_RUNNING) ? 1 : 2;
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return state;
}

// No file-queue UI, including in /silent mode. Missing media/copy errors must
// fail back to setup's log instead of opening a hidden or modal system dialog.
UINT CALLBACK driverFileQueue(PVOID, UINT notification, UINT_PTR, UINT_PTR) {
    switch (notification) {
        case SPFILENOTIFY_COPYERROR:
        case SPFILENOTIFY_RENAMEERROR:
        case SPFILENOTIFY_DELETEERROR:
        case SPFILENOTIFY_NEEDMEDIA: return FILEOP_ABORT;
        case SPFILENOTIFY_TARGETNEWER: return FALSE;
        default: return TRUE;
    }
}

// Installs the NineNsFlt driver package via its INF DefaultInstall section
// (copies the .sys to System32\Drivers and creates the service).
bool installDriverPackage(const std::wstring& driverDir, std::wstring& errorOut) {
    struct NonInteractiveSetup {
        BOOL previous = SetupSetNonInteractiveMode(TRUE);
        ~NonInteractiveSetup() { SetupSetNonInteractiveMode(previous); }
    } nonInteractive;
    std::wstring infPath = driverDir + L"\\NineNsFlt.inf";
    if (!PathFileExistsW(infPath.c_str())) {
        errorOut = L"Driver package files missing from the install folder.";
        return false;
    }

    // Register the INF and catalog in the system INF store.
    if (!SetupCopyOEMInfW(infPath.c_str(), nullptr, SPOST_PATH, 0, nullptr, 0, nullptr, nullptr)) {
        errorOut = L"The driver package could not be registered (Windows error " +
                   std::to_wstring(GetLastError()) + L"). Check the driver signature and catalog.";
        return false;
    }

    HINF hInf = SetupOpenInfFileW(infPath.c_str(), nullptr, INF_STYLE_WIN4, nullptr);
    if (hInf == INVALID_HANDLE_VALUE) {
        errorOut = L"Driver INF could not be opened.";
        return false;
    }

    wchar_t section[LINE_LEN] = {};
    if (!SetupDiGetActualSectionToInstallW(hInf, L"DefaultInstall", section, LINE_LEN, nullptr, nullptr)) {
        SetupCloseInfFile(hInf);
        errorOut = L"The driver INF has no compatible installation section.";
        return false;
    }
    // Resolve the architecture-decorated section used by the packaged INF.
    BOOL ok = SetupInstallFromInfSectionW(nullptr, hInf, section, SPINST_FILES,
                                          nullptr, driverDir.c_str(), SP_COPY_NEWER,
                                          driverFileQueue, nullptr, nullptr, nullptr);

    // AddService/StartService live in the section's .Services subsection.
    if (ok) {
        const std::wstring services = std::wstring(section) + L".Services";
        ok = SetupInstallServicesFromInfSectionW(hInf, services.c_str(), 0);
    }
    const DWORD code = GetLastError();
    SetupCloseInfFile(hInf);
    if (!ok) {
        errorOut = L"Driver service installation failed (Windows error " + std::to_wstring(code) + L").";
        return false;
    }
    return true;
}

// Recursively removes a tree this installer created in its private staging area.
// Never used on the install tree: uninstall there is manifest-driven.
void removeTreeRecursive(const std::wstring& path) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((path + L"\\*").c_str(), &findData);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
                continue;
            }
            const std::wstring child = path + L"\\" + findData.cFileName;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                removeTreeRecursive(child);
            } else {
                DeleteFileW(child.c_str());
            }
        } while (FindNextFileW(find, &findData));
        FindClose(find);
    }
    RemoveDirectoryW(path.c_str());
}

// The payload archive inside a fresh private staging directory. The write
// handle stays open across extraction (FILE_SHARE_READ), so the archive cannot
// be replaced or modified between verification and extraction.
struct StagedArchive {
    std::wstring directory;
    std::wstring archivePath;
    HANDLE handle = INVALID_HANDLE_VALUE;

    StagedArchive() = default;
    ~StagedArchive() {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
        if (!directory.empty()) {
            removeTreeRecursive(directory);
        }
    }
    StagedArchive(const StagedArchive&) = delete;
    StagedArchive& operator=(const StagedArchive&) = delete;
};

// Creates the staging directory (random name, administrator/SYSTEM-only DACL,
// no reparse points) and writes the embedded payload into it. The written bytes
// are read back and compared against the embedded resource before extraction.
bool createStagedArchive(StagedArchive& staged, const void* data, DWORD size, std::wstring& errorOut) {
    wchar_t tempPath[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        errorOut = L"The temporary directory could not be resolved.";
        return false;
    }
    const std::wstring tempRoot = std::wstring(tempPath).substr(0, wcslen(tempPath) - 1);  // drop trailing backslash
    if (isReparsePoint(tempRoot)) {
        errorOut = L"The temporary directory is a reparse point: " + tempRoot;
        return false;
    }

    std::string hex;
    if (!randomHex(hex, 16)) {
        errorOut = L"Randomness for the staging directory name is unavailable.";
        return false;
    }
    const std::wstring name = protected_paths::makeStagingName(hex);
    if (!protected_paths::validateStagingName(name).ok) {
        errorOut = L"The staging directory name is invalid.";
        return false;
    }

    staged.directory = tempRoot + L"\\" + name;
    // Administrator/SYSTEM only: nothing else can see or write the archive.
    const wchar_t* stagingSddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(stagingSddl, SDDL_REVISION_1, &descriptor,
                                                              nullptr)) {
        errorOut = L"The staging directory ACL could not be prepared.";
        return false;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    const bool created = CreateDirectoryW(staged.directory.c_str(), &attributes) != 0;
    LocalFree(descriptor);
    if (!created) {
        errorOut = L"The private staging directory could not be created: " + staged.directory;
        return false;
    }
    if (isReparsePoint(staged.directory)) {
        errorOut = L"The staging directory is a reparse point: " + staged.directory;
        return false;
    }

    staged.archivePath = staged.directory + L"\\payload.zip";
    staged.handle = CreateFileW(staged.archivePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (staged.handle == INVALID_HANDLE_VALUE) {
        errorOut = L"The staging archive could not be created: " + staged.archivePath;
        return false;
    }
    if (!writeAllBytes(staged.handle, data, size)) {
        errorOut = L"The staging archive could not be written completely.";
        return false;
    }

    // Verify the staged bytes against the embedded resource before extraction.
    if (SetFilePointer(staged.handle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        errorOut = L"The staging archive could not be re-read.";
        return false;
    }
    std::vector<BYTE> readBack(size);
    DWORD total = 0;
    while (total < size) {
        DWORD got = 0;
        if (!ReadFile(staged.handle, readBack.data() + total, size - total, &got, nullptr) || got == 0) {
            errorOut = L"The staging archive could not be re-read.";
            return false;
        }
        total += got;
    }
    if (std::memcmp(readBack.data(), data, size) != 0) {
        errorOut = L"The staging archive does not match the embedded payload.";
        return false;
    }
    return true;
}

// Extracts with the inbox tar.exe by absolute System32 path. Every path goes to
// the command line as quoted data; no PowerShell or cmd fallback remains.
bool extractWithTar(const std::wstring& archivePath, const std::wstring& destDir, std::wstring& errorOut) {
    const std::wstring tar = systemHelperPath(L"tar.exe");
    if (tar.empty()) {
        errorOut = L"The System32 tar.exe path could not be resolved.";
        return false;
    }
    const std::wstring arguments = L"-xf " + protected_paths::quoteCommandLineArgument(archivePath) + L" -C " +
                                   protected_paths::quoteCommandLineArgument(destDir);
    if (!runHidden(tar, arguments)) {
        errorOut = L"The distribution archive could not be extracted.";
        return false;
    }
    return true;
}

// Post-extraction containment: every entry must live under root and no reparse
// points may appear in the extracted tree.
bool validateExtractedTree(const std::wstring& root, std::wstring& errorOut) {
    WIN32_FIND_DATAW findData{};
    HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &findData);
    if (find == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_FILE_NOT_FOUND;  // empty tree: nothing to check
    }
    bool ok = true;
    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        const std::wstring child = root + L"\\" + findData.cFileName;
        if (!protected_paths::isContainedPath(root, child)) {
            errorOut = L"An extracted entry escapes the install root: " + child;
            ok = false;
            break;
        }
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            errorOut = L"An extracted entry is a reparse point: " + child;
            ok = false;
            break;
        }
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!validateExtractedTree(child, errorOut)) {
                ok = false;
                break;
            }
        }
    } while (FindNextFileW(find, &findData));
    FindClose(find);
    return ok;
}

// Moves only preplanned staged entries. Recovery ownership has already been
// committed before the first payload file is replaced.
bool moveTreeInto(const std::wstring& src, const std::wstring& relative, const std::wstring& destDir,
                  std::wstring& errorOut) {
    const std::wstring dest = relative.empty() ? destDir : destDir + L"\\" + relative;
    if (isReparsePoint(dest)) {
        errorOut = L"An existing destination entry is a reparse point: " + dest;
        return false;
    }
    const DWORD attributes = GetFileAttributesW(src.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        errorOut = L"A staged entry is missing: " + src;
        return false;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!relative.empty()) {
            if (!CreateDirectoryW(dest.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
                errorOut = L"The install directory could not be created: " + dest;
                return false;
            }
            if (!securePayloadPath(dest, true, errorOut)) return false;
        }
        WIN32_FIND_DATAW findData{};
        HANDLE find = FindFirstFileW((src + L"\\*").c_str(), &findData);
        bool ok = true;
        if (find == INVALID_HANDLE_VALUE) {
            ok = GetLastError() == ERROR_FILE_NOT_FOUND;  // empty directory
        } else {
            do {
                if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
                    continue;
                }
                const std::wstring childRelative =
                    relative.empty() ? std::wstring(findData.cFileName) : relative + L"\\" + findData.cFileName;
                if (!moveTreeInto(src + L"\\" + findData.cFileName, childRelative, destDir, errorOut)) {
                    ok = false;
                    break;
                }
            } while (FindNextFileW(find, &findData));
            FindClose(find);
        }
        if (!ok) {
            return false;
        }
        RemoveDirectoryW(src.c_str());
        return true;
    }
    if (setup::preserveExistingFile(relative) && PathFileExistsW(dest.c_str())) {
        DeleteFileW(src.c_str());  // This staged copy belongs to setup, not the user.
        return true;  // User configuration is never owned by the new uninstaller.
    }
    if (!MoveFileExW(src.c_str(), dest.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        errorOut = L"A staged file could not be moved into the install directory: " + dest;
        return false;
    }
    // Same-volume moves retain the private staging ACL. Restore product RX
    // access for standard users rather than shipping administrator-only files.
    return securePayloadPath(dest, false, errorOut);
}

// Plan ownership and collisions in the private staging tree before replacing
// files. Unknown existing files may not become owned by a newer payload.
bool planStagedTree(const std::wstring& src, const std::wstring& relative, const std::wstring& dest,
                    const protected_paths::InstallManifest& previous,
                    protected_paths::InstallManifest& planned, std::wstring& error) {
    const DWORD attributes = GetFileAttributesW(src.c_str());
    const auto entry = protected_paths::validateManifestEntry(relative);
    if (!entry.ok || attributes == INVALID_FILE_ATTRIBUTES) {
        error = L"Invalid staged package entry: " + relative;
        return false;
    }
    if (_wcsicmp(relative.c_str(), L"install-manifest.txt") == 0 ||
        _wcsicmp(relative.c_str(), L"uninstall.bat") == 0) {
        error = L"The package contains a reserved setup file: " + relative;
        return false;
    }
    const DWORD existing = GetFileAttributesW((dest + L"\\" + relative).c_str());
    if (existing != INVALID_FILE_ATTRIBUTES &&
        ((existing & FILE_ATTRIBUTE_REPARSE_POINT) ||
         bool(existing & FILE_ATTRIBUTE_DIRECTORY) != bool(attributes & FILE_ATTRIBUTE_DIRECTORY))) {
        error = L"The package conflicts with an existing destination entry: " + relative;
        return false;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        planned.directories.push_back(relative);
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW((src + L"\\*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) return true;
            error = L"Cannot enumerate the staged directory: " + relative;
            return false;
        }
        bool ok = true;
        do {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
            if (!planStagedTree(src + L"\\" + data.cFileName, relative + L"\\" + data.cFileName,
                                dest, previous, planned, error)) { ok = false; break; }
        } while (FindNextFileW(find, &data));
        const DWORD code = GetLastError();
        FindClose(find);
        if (ok && code != ERROR_NO_MORE_FILES) { error = L"Staged directory enumeration failed: " + relative; return false; }
        return ok;
    }
    if (setup::preserveExistingFile(relative)) return true;
    const bool owned = std::any_of(previous.files.begin(), previous.files.end(), [&](const std::wstring& name) {
        return protected_paths::normalizePath(name) == protected_paths::normalizePath(relative);
    });
    if (existing != INVALID_FILE_ATTRIBUTES && !owned) {
        error = L"A new package file would overwrite an unowned file: " + dest + L"\\" + relative +
                L". Move or rename it before retrying setup.";
        return false;
    }
    planned.files.push_back(relative);
    return true;
}

// Private randomized staging, verified embedded bytes, contained extraction,
// and an atomically written recovery manifest before payload placement. On an
// interrupted first install, the manifest identifies the folder for a retry.
bool installPayload(const std::wstring& destDir, const protected_paths::InstallManifest& previous,
                    protected_paths::InstallManifest& manifest, std::wstring& errorOut) {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(100), RT_RCDATA);
    HGLOBAL data = resource ? LoadResource(nullptr, resource) : nullptr;
    const DWORD size = data ? SizeofResource(nullptr, resource) : 0;
    const void* bytes = data ? LockResource(data) : nullptr;
    if (!bytes || !size) { errorOut = L"The embedded distribution archive is missing or empty."; return false; }
    StagedArchive staged;
    if (!createStagedArchive(staged, bytes, size, errorOut)) return false;
    const std::wstring extractDir = staged.directory + L"\\extracted";
    if (!CreateDirectoryW(extractDir.c_str(), nullptr)) { errorOut = L"Cannot create the staging extraction directory."; return false; }
    if (!extractWithTar(staged.archivePath, extractDir, errorOut) || !validateExtractedTree(extractDir, errorOut)) return false;
    const std::wstring root = extractDir + L"\\9ns-windows-x64";
    if (!PathIsDirectoryW(root.c_str()) || !PathFileExistsW((root + L"\\9ns.exe").c_str())) {
        errorOut = L"The archive does not contain the expected 9ns-windows-x64 package and executable.";
        return false;
    }
    WIN32_FIND_DATAW dataEntry{};
    HANDLE find = FindFirstFileW((extractDir + L"\\*").c_str(), &dataEntry);
    if (find == INVALID_HANDLE_VALUE) { errorOut = L"Cannot enumerate the extracted package."; return false; }
    bool layout = true;
    do {
        if (wcscmp(dataEntry.cFileName, L".") != 0 && wcscmp(dataEntry.cFileName, L"..") != 0 &&
            _wcsicmp(dataEntry.cFileName, L"9ns-windows-x64") != 0) layout = false;
    } while (FindNextFileW(find, &dataEntry));
    const DWORD layoutCode = GetLastError();
    FindClose(find);
    if (!layout || layoutCode != ERROR_NO_MORE_FILES) { errorOut = L"Unexpected entries outside the package folder."; return false; }
    std::vector<std::wstring> entries;
    find = FindFirstFileW((root + L"\\*").c_str(), &dataEntry);
    if (find == INVALID_HANDLE_VALUE) { errorOut = L"Cannot enumerate the package contents."; return false; }
    do {
        if (wcscmp(dataEntry.cFileName, L".") != 0 && wcscmp(dataEntry.cFileName, L"..") != 0) entries.emplace_back(dataEntry.cFileName);
    } while (FindNextFileW(find, &dataEntry));
    const DWORD entryCode = GetLastError();
    FindClose(find);
    if (entryCode != ERROR_NO_MORE_FILES) { errorOut = L"Package enumeration failed."; return false; }
    for (const auto& entry : entries)
        if (!planStagedTree(root + L"\\" + entry, entry, destDir, previous, manifest, errorOut)) return false;
    setup::mergePreviousManifest(previous, manifest);
    if (!createUninstallFiles(destDir, manifest, errorOut)) return false;
    for (const auto& entry : entries)
        if (!moveTreeInto(root + L"\\" + entry, entry, destDir, errorOut)) return false;
    return true;
}

bool registerUninstaller(const std::wstring& destDir) {
    const wchar_t* subkey = kUninstallKey;
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        std::wstring name = L"9NS";
        std::wstring ver = L"1.0.0";
        std::wstring pub = L"9NS Team";
        std::wstring icon = destDir + L"\\9ns.exe,0";
        // Absolute cmd.exe from System32; the script path is data, not source.
        const std::wstring cmdExe = systemHelperPath(L"cmd.exe");
        std::wstring uninstCmd = protected_paths::buildUninstallString(cmdExe, destDir + L"\\uninstall.bat");

        bool ok = true;
        auto setString = [&](const wchar_t* key, const std::wstring& value) {
            if (RegSetValueExW(hKey, key, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                              static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) ok = false;
        };
        setString(L"DisplayName", name);
        setString(L"DisplayVersion", ver);
        setString(L"Publisher", pub);
        setString(L"DisplayIcon", icon);
        setString(L"InstallLocation", destDir);
        setString(L"UninstallString", uninstCmd);

        DWORD sizeKb = 120 * 1024;
        if (RegSetValueExW(hKey, L"EstimatedSize", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&sizeKb), sizeof(sizeKb)) != ERROR_SUCCESS) ok = false;
        const DWORD noModify = 1;
        if (RegSetValueExW(hKey, L"NoModify", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&noModify), sizeof(noModify)) != ERROR_SUCCESS) ok = false;
        if (RegSetValueExW(hKey, L"NoRepair", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&noModify), sizeof(noModify)) != ERROR_SUCCESS) ok = false;

        RegCloseKey(hKey);
        return ok;
    }
    return false;
}

// Writes install-manifest.txt and the manifest-driven uninstall script. The
// script deletes only product-owned entries (explicit del lines and plain rd),
// so unknown files in the tree survive an uninstall. The manifest is validated
// against the install root before anything is written.
bool createUninstallFiles(const std::wstring& destDir, protected_paths::InstallManifest& manifest,
                          std::wstring& errorOut) {
    if (std::none_of(manifest.files.begin(), manifest.files.end(), [](const std::wstring& file) {
            return _wcsicmp(file.c_str(), L"install-manifest.txt") == 0;
        })) manifest.files.push_back(L"install-manifest.txt");
    protected_paths::DeletionPlan plan;
    const protected_paths::PolicyResult check = protected_paths::planManifestDeletions(manifest, destDir, plan);
    if (!check.ok) {
        errorOut = widen(check.error);
        return false;
    }
    const std::string manifestText = protected_paths::buildManifestFileContent(manifest);
    const std::wstring script = protected_paths::buildUninstallScript(manifest);
    if (script.empty()) {
        errorOut = L"The uninstall script could not be planned from the manifest.";
        return false;
    }
    std::string random;
    if (!randomHex(random, 16)) { errorOut = L"Cannot create atomic recovery filenames."; return false; }
    const std::wstring tempManifest = destDir + L"\\manifest-" + widen(random) + L".tmp";
    const std::wstring tempScript = destDir + L"\\uninstall-" + widen(random) + L".tmp";
    auto stageFile = [&](const std::wstring& path, const std::string& bytes) {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        const bool ok = writeAllBytes(file, bytes.data(), static_cast<DWORD>(bytes.size()));
        CloseHandle(file);
        if (!ok) DeleteFileW(path.c_str());
        return ok;
    };
    // Manifest entries are ASCII, so the batch file needs no UTF-16 BOM.
    const std::string scriptBytes(script.begin(), script.end());
    if (!stageFile(tempManifest, manifestText)) { errorOut = L"Cannot stage the recovery manifest."; return false; }
    if (!stageFile(tempScript, scriptBytes)) {
        DeleteFileW(tempManifest.c_str()); errorOut = L"Cannot stage the uninstall script."; return false;
    }
    const bool manifestWritten = MoveFileExW(tempManifest.c_str(), (destDir + L"\\install-manifest.txt").c_str(),
                                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    const bool scriptWritten = manifestWritten && MoveFileExW(tempScript.c_str(), (destDir + L"\\uninstall.bat").c_str(),
                                                              MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    DeleteFileW(tempManifest.c_str());
    DeleteFileW(tempScript.c_str());
    if (!scriptWritten) { errorOut = L"Cannot commit the recovery manifest and uninstaller. No payload files were replaced."; return false; }
    return true;
}

// Only the worker writes the log; UI updates are posted and applied on the UI thread.
void logLine(const std::wstring& text) {
    if (g_log == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t time[40] = {};
    swprintf(time, 40, L"[%04u-%02u-%02u %02u:%02u:%02u] ", now.wYear, now.wMonth,
             now.wDay, now.wHour, now.wMinute, now.wSecond);
    const std::string bytes = narrow(std::wstring(time) + text + L"\r\n");
    if (!writeAllBytes(g_log, bytes.data(), static_cast<DWORD>(bytes.size()))) g_logFailed = true;
}

void report(int progress, const std::wstring& text) {
    logLine(text);
    if (!g_options.silent) {
        auto* update = new StatusUpdate{progress, text};
        if (!PostMessageW(g_hWnd, kStatusMessage, 0, reinterpret_cast<LPARAM>(update))) delete update;
    }
}

bool openLog(std::wstring& error) {
    g_logPath = g_options.logPath;
    if (g_logPath.empty()) {
        wchar_t temp[MAX_PATH] = {};
        const DWORD length = GetTempPathW(MAX_PATH, temp);
        std::string random;
        if (!length || length >= MAX_PATH || !randomHex(random, 16)) {
            error = L"Cannot create a setup log in the temporary folder.";
            return false;
        }
        g_logPath = std::wstring(temp) + L"9NS-Setup-" + widen(random) + L".log";
    }
    const auto check = protected_paths::validateLocalPath(g_logPath);
    if (!check.ok) { error = widen(check.error); return false; }
    // Never overwrite an existing file (including links), even with /log.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) {
        error = L"The setup log permissions could not be prepared.";
        return false;
    }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    g_log = CreateFileW(g_logPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const DWORD code = GetLastError();
    LocalFree(descriptor);
    if (g_log == INVALID_HANDLE_VALUE) {
        error = L"Cannot create log: " + g_logPath + L" (Windows error " + std::to_wstring(code) +
                L"). Choose a new filename in an existing folder.";
        return false;
    }
    logLine(L"9NS Setup 1.0.0; destination: " + g_options.destination);
    return true;
}

std::wstring registeredLocation() {
    wchar_t path[MAX_PATH] = {};
    DWORD size = sizeof(path);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kUninstallKey, L"InstallLocation",
                     RRF_RT_REG_SZ, nullptr, path, &size) != ERROR_SUCCESS) return {};
    return path;
}

bool readPreviousManifest(const std::wstring& dest, protected_paths::InstallManifest& manifest,
                          std::wstring& error) {
    HANDLE file = CreateFileW((dest + L"\\install-manifest.txt").c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"The existing installation manifest cannot be read. Use its original installer to recover it.";
        return false;
    }
    LARGE_INTEGER length{};
    const bool validSize = GetFileSizeEx(file, &length) && length.QuadPart > 0 && length.QuadPart <= 1024 * 1024;
    std::string text(validSize ? static_cast<size_t>(length.QuadPart) : 0, '\0');
    DWORD read = 0;
    const bool ok = validSize && ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) &&
                    read == text.size();
    CloseHandle(file);
    if (!ok) { error = L"The existing installation manifest is unreadable or exceeds 1 MiB."; return false; }
    if (!setup::parsePreviousManifest(text, manifest, error)) return false;
    if (std::none_of(manifest.files.begin(), manifest.files.end(), [](const std::wstring& entry) {
            return _wcsicmp(entry.c_str(), L"9ns.exe") == 0;
        })) { error = L"The manifest does not identify a recoverable 9NS installation."; return false; }
    protected_paths::DeletionPlan plan;
    const auto check = protected_paths::planManifestDeletions(manifest, dest, plan);
    if (!check.ok) { error = widen(check.error); return false; }
    return true;
}

bool serviceIsStopped(const wchar_t* name, std::wstring& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { error = L"Cannot query Windows services."; return false; }
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    const DWORD code = GetLastError();
    CloseServiceHandle(scm);
    if (!svc) {
        if (code == ERROR_SERVICE_DOES_NOT_EXIST) return true;
        error = L"Cannot inspect service " + std::wstring(name) + L" (Windows error " + std::to_wstring(code) + L").";
        return false;
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    const bool ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status),
                                         sizeof(status), &needed) != 0;
    CloseServiceHandle(svc);
    if (!ok || status.dwCurrentState != SERVICE_STOPPED) {
        error = L"Stop service " + std::wstring(name) + L" before continuing, then retry setup. "
                L"Stop 9NS normally so it can restore adapter DNS. Setup will not force-stop it.";
        return false;
    }
    return true;
}

bool preflight(protected_paths::InstallManifest& previous, std::wstring& error) {
    if (!IsWindows10OrGreater()) { error = L"9NS requires Windows 10 or Windows 11."; return false; }
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        error = L"This package requires an x64 Windows system (including the x64 kernel driver).";
        return false;
    }
    if (!IsUserAnAdmin()) { error = L"Run setup as Administrator."; return false; }
    if (!PathFileExistsW(systemHelperPath(L"tar.exe").c_str())) {
        error = L"Windows System32 tar.exe is required. Update Windows before installing.";
        return false;
    }
    HRSRC payload = FindResourceW(nullptr, MAKEINTRESOURCEW(100), RT_RCDATA);
    if (!payload || !SizeofResource(nullptr, payload)) { error = L"The installer payload is missing."; return false; }
    HRSRC license = FindResourceW(nullptr, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!license || !SizeofResource(nullptr, license)) { error = L"The installer license is missing."; return false; }
    const auto check = protected_paths::validateInstallDestination(g_options.destination);
    if (!check.ok) { error = widen(check.error); return false; }
    if (!g_registeredDir.empty() && protected_paths::normalizePath(g_registeredDir) !=
                                     protected_paths::normalizePath(g_options.destination)) {
        error = L"9NS is already registered in " + g_registeredDir +
                L". Upgrade that location, or uninstall it before choosing another folder.";
        return false;
    }
    if (!parentChainIsProtected(g_options.destination, error)) return false;
    const DWORD attributes = GetFileAttributesW(g_options.destination.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || isReparsePoint(g_options.destination)) {
            error = L"The destination must be a normal, dedicated installation directory."; return false;
        }
        if (!validateExtractedTree(g_options.destination, error)) return false;
        if (!PathIsDirectoryEmptyW(g_options.destination.c_str())) {
            if (!PathFileExistsW((g_options.destination + L"\\install-manifest.txt").c_str())) {
                error = L"Choose an empty folder or an existing 9NS installation with a valid recovery manifest.";
                return false;
            }
            if (!readPreviousManifest(g_options.destination, previous, error)) return false;
        }
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
        error = L"The destination cannot be inspected."; return false;
    }
    if (!serviceIsStopped(service::kServiceName, error)) return false;
    if (g_options.driver && !serviceIsStopped(L"NineNsFlt", error)) return false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = L"Cannot check for running 9NS processes."; return false; }
    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);
    bool running = false;
    if (!Process32FirstW(snapshot, &process)) {
        CloseHandle(snapshot); error = L"Cannot enumerate running processes."; return false;
    }
    do {
        if (_wcsicmp(process.szExeFile, L"9ns.exe") == 0) { running = true; break; }
    } while (Process32NextW(snapshot, &process));
    CloseHandle(snapshot);
    if (running) {
        error = L"Exit 9NS from its tray menu (not just the window), and wait for its DNS watchdog to exit. "
                L"Setup will not terminate DNS protection or change adapter settings.";
        return false;
    }
    const std::wstring parent = g_options.destination.substr(0, g_options.destination.find_last_of(L'\\'));
    ULARGE_INTEGER free{};
    const ULONGLONG required = std::max<ULONGLONG>(512ULL * 1024 * 1024, 4ULL * SizeofResource(nullptr, payload));
    if (!GetDiskFreeSpaceExW(parent.c_str(), &free, nullptr, nullptr) || free.QuadPart < required) {
        error = L"The destination drive needs at least " + std::to_wstring(required / (1024 * 1024)) + L" MiB free.";
        return false;
    }
    return true;
}

// Register directly: the application's --install-service command displays a
// modal message box and is unsuitable for unattended setup.
bool configureService(const std::wstring& exe, std::wstring& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) { error = L"Cannot open Service Control Manager."; return false; }
    const std::wstring command = protected_paths::quoteCommandLineArgument(exe) + L" --service";
    SC_HANDLE svc = CreateServiceW(scm, service::kServiceName, service::kServiceDisplayName,
                                   SERVICE_CHANGE_CONFIG, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                   SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    bool ok = svc != nullptr;
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS) {
        svc = OpenServiceW(scm, service::kServiceName, SERVICE_CHANGE_CONFIG);
        // Preserve account, startup policy, dependencies and recovery settings on upgrade.
        ok = svc && ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                         command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    }
    if (ok) {
        SERVICE_DESCRIPTIONW description{const_cast<wchar_t*>(service::kServiceDescription)};
        ok = ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &description) != 0;
    }
    const DWORD code = GetLastError();
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!ok) error = L"Windows service registration failed (Windows error " + std::to_wstring(code) + L").";
    return ok;
}

Completion performInstall() {
    std::wstring error;
    if (!openLog(error)) return {1, error};
    report(5, L"Checking Windows, destination, free space and running instances...");
    protected_paths::InstallManifest previous;
    if (!preflight(previous, error)) { report(0, L"Pre-install check failed: " + error); return {3, error}; }
    const std::wstring& dest = g_options.destination;
    report(10, L"Preparing the protected installation directory...");
    if (!CreateDirectoryW(dest.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        error = L"The installation directory could not be created: " + dest;
        report(10, error); return {1, error};
    }
    if (!applyProtectedDacl(dest, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")) {
        error = L"The installation directory could not be secured: " + dest;
        report(10, error); return {1, error};
    }
    report(20, L"Extracting and verifying the embedded distribution...");
    protected_paths::InstallManifest manifest;
    if (!installPayload(dest, previous, manifest, error)) { report(20, error); return {1, error}; }
    std::wstring warnings;
    auto warn = [&](const std::wstring& message) { warnings += message + L"\r\n"; report(65, L"Warning: " + message); };
    if (g_options.driver) {
        report(50, L"Installing the optional DNS guard driver...");
        if (!installDriverPackage(dest + L"\\driver", error)) warn(error);
        else if (driverServiceState() != 1)
            warn(L"The DNS guard driver is not running. Check driver signing requirements and Windows event logs; "
                 L"setup has not changed test-signing or Secure Boot settings.");
    }
    report(70, L"Configuring shortcuts and Windows integration...");
    const std::wstring exe = dest + L"\\9ns.exe";
    for (const auto& shortcut : {std::pair<bool, int>{g_options.desktop, CSIDL_COMMON_DESKTOPDIRECTORY},
                                 std::pair<bool, int>{g_options.startMenu, CSIDL_COMMON_PROGRAMS}}) {
        if (!shortcut.first) continue;
        wchar_t folder[MAX_PATH] = {};
        if (SHGetFolderPathW(nullptr, shortcut.second, nullptr, 0, folder) != S_OK ||
            !createShortcut(exe, std::wstring(folder) + L"\\9NS.lnk", L"9NS - Advanced System DNS Client", dest))
            warn(shortcut.second == CSIDL_COMMON_PROGRAMS ? L"Start Menu shortcut creation failed." : L"Desktop shortcut creation failed.");
    }
    if (g_options.service && !configureService(exe, error)) warn(error);
    if (!registerUninstaller(dest)) warn(L"Add/Remove Programs registration failed. The uninstall.bat in the install folder is still available.");
    if (!warnings.empty()) {
        report(100, L"Core files installed; some optional integration steps need attention.");
        return {4, L"Core files were installed, but setup reported:\r\n\r\n" + warnings};
    }
    report(100, L"Installation completed successfully. Existing configuration was preserved.");
    return {0, L"9NS is installed and ready.\r\n\r\nExisting configuration in %ProgramData%\\9NS is unchanged. "
               L"Any existing service or driver not selected in setup was left installed. "
               L"A newly registered background service starts on the next Windows boot; setup does not start it now."};
}

DWORD WINAPI installThread(LPVOID) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    Completion result;
    try { result = performInstall(); }
    catch (const std::exception& e) { result = {1, L"Setup stopped: " + widen(e.what())}; logLine(result.text); }
    if (g_logFailed && (result.code == 0 || result.code == 4)) {
        result.code = 4;
        result.text += L"\r\nSetup could not write the complete log. Check available disk space and permissions.";
    }
    if (g_log != INVALID_HANDLE_VALUE) { CloseHandle(g_log); g_log = INVALID_HANDLE_VALUE; }
    CoUninitialize();
    if (!g_options.silent) {
        auto* completion = new Completion(std::move(result));
        if (!PostMessageW(g_hWnd, kCompleteMessage, 0, reinterpret_cast<LPARAM>(completion))) delete completion;
        return 0;
    }
    // Preserve the actionable error even if the log itself could not be opened.
    consoleOutput(result.text + L"\r\n");
    return static_cast<DWORD>(result.code);
}

HWND addControl(Page page, const wchar_t* type, const wchar_t* text, DWORD style,
                int x, int y, int width, int height, int id = 0, DWORD extended = 0) {
    HWND control = CreateWindowExW(extended, type, text, WS_CHILD | style, x, y, width, height,
                                   g_hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontNormal), TRUE);
    g_pages[static_cast<int>(page)].push_back(control);
    return control;
}

bool checked(HWND control) { return SendMessageW(control, BM_GETCHECK, 0, 0) == BST_CHECKED; }
void check(HWND control, bool value) { SendMessageW(control, BM_SETCHECK, value ? BST_CHECKED : BST_UNCHECKED, 0); }

std::wstring summary() {
    auto yes = [](bool value) { return value ? L"Yes" : L"No"; };
    return std::wstring(g_registeredDir.empty() ? L"Install" : L"Upgrade / reinstall") + L" 9NS 1.0.0\r\n\r\nFolder: " +
           g_options.destination + L"\r\nDesktop shortcut: " + yes(g_options.desktop) +
           L"\r\nStart Menu shortcut: " + yes(g_options.startMenu) + L"\r\nRegister background service: " + yes(g_options.service) +
           L"\r\nInstall kernel DNS guard: " + yes(g_options.driver) + L"\r\nLaunch on Finish: " + yes(g_options.launch) +
           L"\r\n\r\nRuntime configuration and DNS backups in %ProgramData%\\9NS are not modified. "
           L"Existing service/driver integrations are not removed when unchecked.\r\n\r\n"
           L"Setup checks that 9NS is stopped before replacing files. No automatic reboot or DNS redirection. "
           L"The driver requires a Windows-trusted signature (or an already configured test-signing system); "
           L"setup never changes test-signing or Secure Boot.\r\n\r\nA timestamped UTF-8 setup log is saved in %TEMP% "
           L"unless /log= specifies a new file.";
}

void showPage(Page page) {
    g_page = page;
    for (int i = 0; i < 8; ++i)
        for (HWND control : g_pages[i]) ShowWindow(control, i == static_cast<int>(page) ? SW_SHOW : SW_HIDE);
    const wchar_t* titles[] = {L"Welcome to 9NS Setup", L"License agreement", L"Choose setup type",
                               L"Installation folder", L"Components and shortcuts", L"Ready to install",
                               L"Installing 9NS", L"Setup complete"};
    SetWindowTextW(g_hTitle, titles[static_cast<int>(page)]);
    const std::wstring step = L"9NS 1.0.0  |  " + std::to_wstring(static_cast<int>(page) + 1) + L" of 8";
    SetWindowTextW(g_hSubtitle, step.c_str());
    ShowWindow(g_hBtnBack, page == Page::Welcome || page == Page::Progress || page == Page::Finish ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hBtnCancel, page == Page::Finish ? SW_HIDE : SW_SHOW);
    EnableWindow(g_hBtnCancel, page != Page::Progress);
    EnableWindow(g_hBtnInstall, page != Page::Progress && (page != Page::License || checked(g_hAccept)));
    SetWindowTextW(g_hBtnInstall, page == Page::Review ? L"Install" : page == Page::Finish ? L"Finish" : L"Next >");
    if (page == Page::Review) SetWindowTextW(g_hReview, summary().c_str());
    SetFocus(page == Page::License && !checked(g_hAccept) ? g_hAccept : g_hBtnInstall);
}

std::wstring licenseText() {
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(101), RT_RCDATA);
    HGLOBAL data = resource ? LoadResource(nullptr, resource) : nullptr;
    const char* bytes = data ? static_cast<const char*>(LockResource(data)) : nullptr;
    if (!bytes) return {};
    std::wstring text = widen(std::string(bytes, SizeofResource(nullptr, resource)));
    std::wstring crlf;
    for (wchar_t ch : text) { if (ch == L'\n' && (crlf.empty() || crlf.back() != L'\r')) crlf += L'\r'; crlf += ch; }
    return crlf;
}

void createPages() {
    addControl(Page::Welcome, L"STATIC", L"Encrypted DNS. System-wide protection. Your choice of integration.", 0, 28, 100, 620, 40);
    const std::wstring welcome = g_registeredDir.empty()
        ? L"This wizard installs 9NS for all users on this computer. Administrator privileges are required."
        : L"An existing 9NS installation was found in:\r\n" + g_registeredDir + L"\r\n\r\nSetup will upgrade or reinstall it in place.";
    addControl(Page::Welcome, L"STATIC", welcome.c_str(), 0, 28, 155, 620, 110);
    addControl(Page::Welcome, L"STATIC", L"Before installing, exit 9NS from its tray menu and stop its background service if running. "
               L"This lets 9NS restore adapter DNS normally.\r\n\r\nExisting settings are preserved. The kernel driver is optional and is not selected by default.",
               0, 28, 290, 620, 130);
    const std::wstring license = licenseText();
    addControl(Page::License, L"EDIT", license.c_str(), ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
               28, 100, 620, 285, 0, WS_EX_CLIENTEDGE);
    g_hAccept = addControl(Page::License, L"BUTTON", L"I accept the GNU Affero General Public License v3.0", BS_AUTOCHECKBOX | WS_TABSTOP,
                           28, 400, 620, 26, 110);
    check(g_hAccept, g_options.acceptLicense);
    if (license.empty()) EnableWindow(g_hAccept, FALSE);
    g_hTypical = addControl(Page::Mode, L"BUTTON", L"Typical", BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 28, 110, 620, 26, 111);
    addControl(Page::Mode, L"STATIC", L"Use the current folder and integration defaults. Review all choices before installing. "
               L"On a fresh install, only desktop and Start Menu shortcuts are selected; the service and driver are optional.", 0, 52, 147, 585, 80);
    g_hCustom = addControl(Page::Mode, L"BUTTON", L"Custom", BS_AUTORADIOBUTTON | WS_TABSTOP, 28, 255, 620, 26, 112);
    addControl(Page::Mode, L"STATIC", L"Choose the installation folder, shortcuts, background service and optional kernel DNS guard.", 0, 52, 292, 585, 65);
    check(g_hTypical, true);
    addControl(Page::Destination, L"STATIC", L"Choose a dedicated folder under a protected local directory, such as Program Files. "
               L"Upgrades use the existing registered location. Network shares and reparse points are not supported.", 0, 28, 100, 620, 75);
    g_hEditDest = addControl(Page::Destination, L"EDIT", g_options.destination.c_str(), ES_AUTOHSCROLL | WS_TABSTOP,
                             28, 200, 500, 28, 0, WS_EX_CLIENTEDGE);
    SendMessageW(g_hEditDest, EM_SETLIMITTEXT, MAX_PATH - 1, 0);
    addControl(Page::Destination, L"BUTTON", L"Browse...", WS_TABSTOP, 540, 198, 108, 30, 101);
    addControl(Page::Destination, L"STATIC", L"Configuration and runtime logs stay in %ProgramData%\\9NS. "
               L"Setup never replaces that configuration or changes adapter DNS settings.", 0, 28, 265, 620, 80);
    g_hChkDesktop = addControl(Page::Components, L"BUTTON", L"Create a Desktop shortcut", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 105, 620, 26);
    g_hChkStartMenu = addControl(Page::Components, L"BUTTON", L"Create a Start Menu shortcut", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 145, 620, 26);
    g_hChkService = addControl(Page::Components, L"BUTTON", L"Register background Windows service (auto-start on next boot)", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 185, 620, 26);
    g_hChkDriver = addControl(Page::Components, L"BUTTON", L"Install DNS guard driver (kernel; blocks non-loopback DNS)", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 225, 620, 26);
    g_hChkLaunch = addControl(Page::Components, L"BUTTON", L"Launch 9NS when I click Finish", BS_AUTOCHECKBOX | WS_TABSTOP, 28, 265, 620, 26);
    check(g_hChkDesktop, g_options.desktop); check(g_hChkStartMenu, g_options.startMenu);
    check(g_hChkService, g_options.service); check(g_hChkDriver, g_options.driver); check(g_hChkLaunch, g_options.launch);
    addControl(Page::Components, L"STATIC", L"Driver installation is optional and may fail if its signature is not trusted by Windows. "
               L"Setup does not enable test-signing or disable Secure Boot.\r\n\r\nUnchecking an option does not remove an existing shortcut, service or driver.",
               0, 28, 315, 620, 105);
    g_hReview = addControl(Page::Review, L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
                           28, 100, 620, 330, 0, WS_EX_CLIENTEDGE);
    g_hProgress = addControl(Page::Progress, PROGRESS_CLASSW, L"", PBS_SMOOTH, 28, 110, 620, 22);
    SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    g_hStatus = addControl(Page::Progress, L"STATIC", L"Preparing...", 0, 28, 150, 620, 60);
    g_hDetails = addControl(Page::Progress, L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
                            28, 220, 620, 200, 0, WS_EX_CLIENTEDGE);
    SendMessageW(g_hDetails, EM_SETLIMITTEXT, 128000, 0);
    g_hFinish = addControl(Page::Finish, L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
                           28, 100, 620, 330, 0, WS_EX_CLIENTEDGE);
}

void nextPage() {
    switch (g_page) {
        case Page::Welcome: showPage(Page::License); break;
        case Page::License:
            if (checked(g_hAccept)) { g_options.acceptLicense = true; showPage(Page::Mode); }
            break;
        case Page::Mode:
            g_custom = checked(g_hCustom);
            showPage(g_custom ? Page::Destination : Page::Review); break;
        case Page::Destination: {
            wchar_t path[MAX_PATH] = {};
            GetWindowTextW(g_hEditDest, path, MAX_PATH);
            std::wstring dest = path;
            for (auto& ch : dest) if (ch == L'/') ch = L'\\';
            while (dest.size() > 3 && dest.back() == L'\\') dest.pop_back();
            const auto check = protected_paths::validateInstallDestination(dest);
            if (!check.ok) { MessageBoxW(g_hWnd, widen(check.error).c_str(), L"Installation folder", MB_OK | MB_ICONWARNING); break; }
            g_options.destination = std::move(dest);
            showPage(Page::Components); break;
        }
        case Page::Components:
            g_options.desktop = checked(g_hChkDesktop); g_options.startMenu = checked(g_hChkStartMenu);
            g_options.service = checked(g_hChkService); g_options.driver = checked(g_hChkDriver);
            g_options.launch = checked(g_hChkLaunch);
            showPage(Page::Review); break;
        case Page::Review: {
            g_installing = true;
            showPage(Page::Progress);
            HANDLE thread = CreateThread(nullptr, 0, installThread, nullptr, 0, nullptr);
            if (!thread) {
                auto* failure = new Completion{1, L"The installation worker could not be started."};
                PostMessageW(g_hWnd, kCompleteMessage, 0, reinterpret_cast<LPARAM>(failure));
            } else CloseHandle(thread);
            break;
        }
        case Page::Finish:
            if (g_options.launch && (g_exitCode == 0 || g_exitCode == 4)) {
                const std::wstring exe = g_options.destination + L"\\9ns.exe";
                if (reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", exe.c_str(), nullptr,
                                                           g_options.destination.c_str(), SW_SHOW)) <= 32)
                    MessageBoxW(g_hWnd, L"9NS could not be launched. Open it from the Start Menu or installation folder.",
                                L"9NS Setup", MB_OK | MB_ICONWARNING);
            }
            DestroyWindow(g_hWnd); break;
        default: break;
    }
}

UINT windowDpi(HWND window) {
    // Older Windows 10 builds may not export the newer DPI APIs. Resolve them
    // dynamically so preflight can still show a useful compatibility error.
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (window) {
        using GetWindowDpi = UINT (WINAPI*)(HWND);
        const FARPROC function = GetProcAddress(user32, "GetDpiForWindow");
        GetWindowDpi getDpi = nullptr;
        static_assert(sizeof(getDpi) == sizeof(function), "Windows function pointer sizes must match");
        std::memcpy(&getDpi, &function, sizeof(getDpi));
        if (getDpi) return getDpi(window);
    } else {
        using GetSystemDpi = UINT (WINAPI*)();
        const FARPROC function = GetProcAddress(user32, "GetDpiForSystem");
        GetSystemDpi getDpi = nullptr;
        static_assert(sizeof(getDpi) == sizeof(function), "Windows function pointer sizes must match");
        std::memcpy(&getDpi, &function, sizeof(getDpi));
        if (getDpi) return getDpi();
    }
    HDC context = GetDC(window);
    const int dpi = context ? GetDeviceCaps(context, LOGPIXELSX) : 96;
    if (context) ReleaseDC(window, context);
    return dpi > 0 ? static_cast<UINT>(dpi) : 96;
}

void scaleControls(UINT dpi) {
    if (!dpi) return;
    const HFONT previousNormal = g_hFontNormal;
    const HFONT previousTitle = g_hFontTitle;
    g_hFontNormal = CreateFontW(-MulDiv(16, dpi, 96), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_hFontTitle = CreateFontW(-MulDiv(24, dpi, 96), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    for (HWND child = GetWindow(g_hWnd, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        RECT rect{};
        GetWindowRect(child, &rect);
        MapWindowPoints(nullptr, g_hWnd, reinterpret_cast<POINT*>(&rect), 2);
        SetWindowPos(child, nullptr, MulDiv(rect.left, dpi, g_dpi), MulDiv(rect.top, dpi, g_dpi),
                     MulDiv(rect.right - rect.left, dpi, g_dpi), MulDiv(rect.bottom - rect.top, dpi, g_dpi),
                     SWP_NOZORDER | SWP_NOACTIVATE);
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(child == g_hTitle ? g_hFontTitle : g_hFontNormal), TRUE);
    }
    g_dpi = dpi;
    if (previousNormal) DeleteObject(previousNormal);
    if (previousTitle) DeleteObject(previousTitle);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hWnd = hWnd;
            g_hFontNormal = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_hFontTitle = CreateFontW(-24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_hTitle = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 28, 20, 620, 34, hWnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hTitle, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontTitle), TRUE);
            g_hSubtitle = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 28, 60, 620, 25, hWnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hSubtitle, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontNormal), TRUE);
            createPages();
            auto button = [&](const wchar_t* text, int x, int id) {
                HWND control = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                               x, 465, 108, 32, hWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
                SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFontNormal), TRUE); return control;
            };
            g_hBtnBack = button(L"< Back", 300, 103);
            g_hBtnInstall = button(L"Next >", 420, IDOK);
            g_hBtnCancel = button(L"Cancel", 540, IDCANCEL);
            SendMessageW(g_hBtnInstall, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);
            scaleControls(windowDpi(hWnd));
            showPage(Page::Welcome); break;
        }
        case WM_DPICHANGED: {
            scaleControls(HIWORD(wParam));
            const RECT* rect = reinterpret_cast<const RECT*>(lParam);
            SetWindowPos(hWnd, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            break;
        }
        case WM_COMMAND: {
            const int id = LOWORD(wParam);
            if (id == 110) EnableWindow(g_hBtnInstall, checked(g_hAccept));
            else if (id == 101 && !g_installing) {
                BROWSEINFOW bi{}; bi.hwndOwner = hWnd; bi.lpszTitle = L"Select a dedicated 9NS installation folder";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
                if (pidl) {
                    wchar_t path[MAX_PATH] = {};
                    if (SHGetPathFromIDListW(pidl, path)) SetWindowTextW(g_hEditDest, path);
                    CoTaskMemFree(pidl);
                }
            } else if (id == IDOK && !g_installing) nextPage();
            else if (id == 103 && !g_installing) {
                if (g_page == Page::Review) showPage(g_custom ? Page::Components : Page::Mode);
                else showPage(static_cast<Page>(static_cast<int>(g_page) - 1));
            } else if (id == IDCANCEL && !g_installing) DestroyWindow(hWnd);
            break;
        }
        case kStatusMessage: {
            std::unique_ptr<StatusUpdate> update(reinterpret_cast<StatusUpdate*>(lParam));
            SendMessageW(g_hProgress, PBM_SETPOS, update->progress, 0);
            SetWindowTextW(g_hStatus, update->text.c_str());
            const int length = GetWindowTextLengthW(g_hDetails);
            SendMessageW(g_hDetails, EM_SETSEL, length, length);
            const std::wstring line = update->text + L"\r\n";
            SendMessageW(g_hDetails, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
            break;
        }
        case kCompleteMessage: {
            std::unique_ptr<Completion> result(reinterpret_cast<Completion*>(lParam));
            g_installing = false; g_exitCode = result->code;
            std::wstring text = result->text;
            if (result->code == 1) text += L"\r\n\r\nSetup stopped. Some files may already have been updated; "
                                          L"there is no automatic rollback. Resolve the error and rerun setup.";
            text += L"\r\n\r\nSetup log: " + g_logPath;
            SetWindowTextW(g_hFinish, text.c_str());
            showPage(Page::Finish);
            SetWindowTextW(g_hTitle, result->code == 0 ? L"Installation complete" : result->code == 4 ? L"Installed with warnings" : L"Setup stopped");
            break;
        }
        case WM_CLOSE: if (!g_installing) DestroyWindow(hWnd); break;
        case WM_DESTROY:
            if (g_hFontNormal) DeleteObject(g_hFontNormal);
            if (g_hFontTitle) DeleteObject(g_hFontTitle);
            PostQuitMessage(g_exitCode); break;
        default: return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

void consoleOutput(const std::wstring& text) {
    AttachConsole(ATTACH_PARENT_PROCESS);
    HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0, mode = 0;
    if (GetConsoleMode(output, &mode)) WriteConsoleW(output, text.c_str(), static_cast<DWORD>(text.size()), &written, nullptr);
    else { const std::string bytes = narrow(text); WriteFile(output, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr); }
}

}  // namespace

#ifdef NS9_INSTALLER_TEST
// Narrow offline seams: tests supply QTemporaryDir roots and never enter the
// installer, preflight, SCM, registry or adapter paths.
namespace setup_test {
bool plan(const std::wstring& src, const std::wstring& relative, const std::wstring& dest,
          const protected_paths::InstallManifest& previous, protected_paths::InstallManifest& manifest,
          std::wstring& error) { return planStagedTree(src, relative, dest, previous, manifest, error); }
bool place(const std::wstring& src, const std::wstring& relative, const std::wstring& dest,
           std::wstring& error) { return moveTreeInto(src, relative, dest, error); }
bool writeRecovery(const std::wstring& dest, protected_paths::InstallManifest& manifest,
                   std::wstring& error) { return createUninstallFiles(dest, manifest, error); }
bool readRecovery(const std::wstring& dest, protected_paths::InstallManifest& manifest,
                  std::wstring& error) { return readPreviousManifest(dest, manifest, error); }
}  // namespace setup_test
#else
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    int count = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!argv) return 2;
    std::vector<std::wstring> arguments;
    bool silentRequested = false;
    for (int i = 1; i < count; ++i) {
        arguments.emplace_back(argv[i]);
        if (_wcsicmp(argv[i], L"/silent") == 0) silentRequested = true;
    }
    LocalFree(argv);
    g_registeredDir = registeredLocation();
    wchar_t programFiles[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, programFiles) != S_OK) return 1;
    g_options.destination = g_registeredDir.empty() ? std::wstring(programFiles) + L"\\9NS" : g_registeredDir;
    std::wstring error;
    if (!setup::parseOptions(arguments, g_options, error)) {
        consoleOutput(error + L"\r\nUse /help for setup options.\r\n");
        if (!silentRequested) MessageBoxW(nullptr, error.c_str(), L"9NS Setup options", MB_OK | MB_ICONERROR);
        return 2;
    }
    if (g_options.help) {
        const std::wstring help = L"9NS Setup 1.0.0\r\n\r\n/silent /acceptlicense   Unattended install (no app launch)\r\n"
            L"/dir=<absolute folder>  Install location; existing registration is reused\r\n"
            L"/log=<absolute file>    New UTF-8 log file; parent folder must exist\r\n"
            L"/desktop=yes|no /startmenu=yes|no /service=yes|no /driver=yes|no /launch=yes|no\r\n"
            L"/help or /?             Show this help\r\n\r\n"
            L"Defaults: shortcuts yes; service and driver no; launch yes (never in silent mode).\r\n"
            L"Exit codes: 0 success; 1 installation/log failure; 2 invalid options; 3 preflight failure; "
            L"4 installed with integration warnings; 1602 cancelled.\r\n"
            L"Setup requests elevation; /silent does not bypass UAC. Existing integrations are not removed.\r\n";
        consoleOutput(help);
        if (!silentRequested) MessageBoxW(nullptr, help.c_str(), L"9NS Setup help", MB_OK | MB_ICONINFORMATION);
        return 0;
    }
    for (auto& ch : g_options.destination) if (ch == L'/') ch = L'\\';
    while (g_options.destination.size() > 3 && g_options.destination.back() == L'\\') g_options.destination.pop_back();
    // One installer at a time across all Windows sessions, including silent setup.
    HANDLE lock = CreateMutexW(nullptr, FALSE, L"Global\\9NSSetup");
    const bool busy = GetLastError() == ERROR_ALREADY_EXISTS;
    if (!lock || busy) {
        error = L"Another 9NS installer is running, or the setup lock is unavailable.";
        consoleOutput(error + L"\r\n");
        if (!g_options.silent) MessageBoxW(nullptr, error.c_str(), L"9NS Setup", MB_OK | MB_ICONERROR);
        if (lock) CloseHandle(lock);
        return 3;
    }
    if (g_options.silent) {
        const int code = static_cast<int>(installThread(nullptr));
        consoleOutput(L"9NS Setup exit code: " + std::to_wstring(code) + L"\r\nLog: " + g_logPath + L"\r\n");
        CloseHandle(lock);
        return code;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc; wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1); wc.lpszClassName = L"9NSSetupClass";
    RegisterClassExW(&wc);
    const UINT dpi = windowDpi(nullptr);
    const int width = MulDiv(kWndWidth, dpi, 96), height = MulDiv(kWndHeight, dpi, 96);
    g_hWnd = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_CONTROLPARENT, wc.lpszClassName, L"9NS Setup (v1.0.0)",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             (GetSystemMetrics(SM_CXSCREEN) - width) / 2,
                             (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
                             width, height, nullptr, nullptr, instance, nullptr);
    if (!g_hWnd) { CoUninitialize(); CloseHandle(lock); return 1; }
    ShowWindow(g_hWnd, show); UpdateWindow(g_hWnd);
    MSG msg{};
    int status = 0;
    while ((status = GetMessageW(&msg, nullptr, 0, 0)) > 0) {
        if (!IsDialogMessageW(g_hWnd, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    CoUninitialize(); CloseHandle(lock);
    return status == -1 ? 1 : static_cast<int>(msg.wParam);
}
#endif
