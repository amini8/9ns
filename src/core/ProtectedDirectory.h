#pragma once

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

// Safe-path and trusted-directory policy shared by the application, the Windows
// service and the elevated installer.
//
// Everything in protected_paths is pure: it validates strings and plans
// operations and never touches the filesystem, the registry or a process, so it
// can be tested offline without Win32 side effects. protected_runtime holds the
// fail-closed runtime-directory initializer (ProtectedDirectory.cpp); call it
// before any log, config or DNS-backup access.
namespace protected_paths {

// Verdict of a policy check. On failure error names the offending value.
struct PolicyResult {
    bool ok = true;
    std::string error;
};

inline PolicyResult policyPass() {
    return {};
}

inline PolicyResult policyFail(std::string message) {
    return {false, std::move(message)};
}

// Files and directories the installer placed inside the install root. Uninstall
// removes exactly these; anything else in the tree is preserved.
struct InstallManifest {
    std::vector<std::wstring> files;
    std::vector<std::wstring> directories;
};

// Absolute paths to remove. Directories are ordered deepest-first so a plain
// non-recursive removal works in order.
struct DeletionPlan {
    std::vector<std::wstring> files;
    std::vector<std::wstring> directories;
};

// Policy errors must name wide values; entries are ASCII-only once validated,
// so a byte copy is enough here and keeps this layer Win32-free.
inline std::string narrowForError(const std::wstring& text) {
    std::string out;
    out.reserve(text.size());
    for (const wchar_t ch : text) {
        out.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
    }
    return out;
}

// --- path shape ---

// True for "C:\..." absolute local paths. UNC (\\server\share), device
// (\\.\ and \\?\) and drive-relative ("C:foo") forms are not local-absolute.
inline bool isLocalAbsolutePath(const std::wstring& path) {
    return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
           path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

// True for drive roots ("C:\" and "C:/").
inline bool isDriveRoot(const std::wstring& path) {
    return isLocalAbsolutePath(path) && path.size() == 3;
}

inline bool isReservedDeviceName(const std::wstring& name) {
    std::wstring base;
    for (const wchar_t ch : name) {
        if (ch == L'.') {
            break;
        }
        base.push_back(static_cast<wchar_t>(towupper(ch)));
    }
    if (base == L"CON" || base == L"PRN" || base == L"AUX" || base == L"NUL" || base == L"CONIN$" ||
        base == L"CONOUT$") {
        return true;
    }
    if (base.size() == 4 && (base.compare(0, 3, L"COM") == 0 || base.compare(0, 3, L"LPT") == 0) &&
        base[3] >= L'1' && base[3] <= L'9') {
        return true;
    }
    return false;
}

// One path segment: non-empty, no traversal, no reserved device name, no
// characters that are invalid in a Windows path, no trailing dot or space.
inline PolicyResult validateSegment(const std::wstring& name) {
    if (name.empty()) {
        return policyFail("path segment is empty");
    }
    if (name == L"." || name == L"..") {
        return policyFail("traversal path segment '" + narrowForError(name) + "'");
    }
    for (const wchar_t ch : name) {
        if (ch < 0x20 || ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' || ch == L'/' || ch == L'\\' ||
            ch == L'|' || ch == L'?' || ch == L'*') {
            return policyFail("illegal character in path segment '" + narrowForError(name) + "'");
        }
    }
    const wchar_t last = name.back();
    if (last == L'.' || last == L' ') {
        return policyFail("path segment ends with a dot or space: '" + narrowForError(name) + "'");
    }
    if (isReservedDeviceName(name)) {
        return policyFail("reserved device name in path segment '" + narrowForError(name) + "'");
    }
    return policyPass();
}

// Lowercases, unifies separators, strips the trailing separator of a
// non-root path and lexically resolves "." and ".." segments, so containment
// and equality checks cannot be escaped by traversal segments.
inline std::wstring normalizePath(const std::wstring& path) {
    std::wstring out;
    out.reserve(path.size());
    for (const wchar_t ch : path) {
        out.push_back(ch == L'/' ? L'\\' : static_cast<wchar_t>(towlower(ch)));
    }
    const size_t rootLength = isLocalAbsolutePath(out) ? 3 : 0;
    std::wstring resolved = out.substr(0, rootLength);
    std::vector<std::wstring> stack;
    size_t i = rootLength;
    while (i < out.size()) {
        size_t next = out.find(L'\\', i);
        if (next == std::wstring::npos) {
            next = out.size();
        }
        const std::wstring segment = out.substr(i, next - i);
        i = next + 1;
        if (segment.empty() || segment == L".") {
            continue;
        }
        if (segment == L"..") {
            if (!stack.empty()) {
                stack.pop_back();
            }
            continue;
        }
        stack.push_back(segment);
    }
    for (const std::wstring& segment : stack) {
        if (!resolved.empty() && resolved.back() != L'\\') {
            resolved += L'\\';
        }
        resolved += segment;
    }
    return resolved;
}

inline std::vector<std::wstring> splitSegments(const std::wstring& path) {
    std::vector<std::wstring> segments;
    const size_t start = isLocalAbsolutePath(path) ? 3 : 0;
    std::wstring current;
    for (size_t i = start; i < path.size(); ++i) {
        if (path[i] == L'\\' || path[i] == L'/') {
            segments.push_back(current);
            current.clear();
        } else {
            current.push_back(path[i]);
        }
    }
    segments.push_back(current);
    return segments;
}

// Structural validation of a full path: absolute and local, every segment safe.
inline PolicyResult validateLocalPath(const std::wstring& path) {
    if (!isLocalAbsolutePath(path)) {
        return policyFail("path is not an absolute local path: '" + narrowForError(path) + "'");
    }
    for (const std::wstring& segment : splitSegments(path)) {
        const PolicyResult result = validateSegment(segment);
        if (!result.ok) {
            return result;
        }
    }
    return policyPass();
}

// A dedicated install root: absolute local, at least two segments below the
// drive (so neither a drive root nor a shallow shared folder), and not one of
// the well-known shared or system roots. Parent-chain writability is checked
// separately against real ACLs by the installer.
inline PolicyResult validateInstallDestination(const std::wstring& path) {
    const PolicyResult shape = validateLocalPath(path);
    if (!shape.ok) {
        return shape;
    }
    const std::vector<std::wstring> segments = splitSegments(path);
    if (segments.size() < 2) {
        return policyFail("install destination must be at least two levels below the drive root: '" +
                          narrowForError(path) + "'");
    }
    const std::wstring normalized = normalizePath(path);
    const std::wstring withoutDrive = normalized.substr(2);  // strip "c:"
    for (const wchar_t* shared : {L"\\users", L"\\users\\public", L"\\programdata", L"\\windows",
                                  L"\\program files", L"\\program files (x86)", L"\\temp"}) {
        if (withoutDrive == shared) {
            return policyFail("install destination is a shared or system root: '" + narrowForError(path) + "'");
        }
    }
    return policyPass();
}

// The runtime data folder must be exactly one safe segment below trustedRoot
// (for example %ProgramData%\9NS).
inline PolicyResult validateRuntimeDataPath(const std::wstring& path, const std::wstring& trustedRoot) {
    const PolicyResult shape = validateLocalPath(path);
    if (!shape.ok) {
        return shape;
    }
    if (!isLocalAbsolutePath(trustedRoot)) {
        return policyFail("trusted root is not an absolute local path: '" + narrowForError(trustedRoot) + "'");
    }
    const std::wstring normalizedPath = normalizePath(path);
    const std::wstring prefix = normalizePath(trustedRoot);
    if (normalizedPath.size() <= prefix.size() + 1 || normalizedPath.compare(0, prefix.size(), prefix) != 0 ||
        normalizedPath[prefix.size()] != L'\\') {
        return policyFail("runtime data folder '" + narrowForError(path) + "' is not directly inside '" +
                          narrowForError(trustedRoot) + "'");
    }
    if (normalizedPath.find(L'\\', prefix.size() + 1) != std::wstring::npos) {
        return policyFail("runtime data folder must be exactly one level below the trusted root: '" +
                          narrowForError(path) + "'");
    }
    return policyPass();
}

// True when candidate equals root or lies below it after normalization.
// C:\a\bc is not inside C:\a\b.
inline bool isContainedPath(const std::wstring& root, const std::wstring& candidate) {
    const std::wstring normalizedRoot = normalizePath(root);
    const std::wstring normalizedCandidate = normalizePath(candidate);
    if (normalizedCandidate == normalizedRoot) {
        return true;
    }
    return normalizedCandidate.size() > normalizedRoot.size() + 1 &&
           normalizedCandidate.compare(0, normalizedRoot.size(), normalizedRoot) == 0 &&
           normalizedCandidate[normalizedRoot.size()] == L'\\';
}

// --- manifest and uninstall planning ---

// One manifest entry: a relative path of safe ASCII segments. '%' and '!' are
// refused because the generated uninstall script is a batch file.
inline PolicyResult validateManifestEntry(const std::wstring& relative) {
    if (relative.empty()) {
        return policyFail("manifest entry is empty");
    }
    if (isLocalAbsolutePath(relative) || relative[0] == L'\\' || relative[0] == L'/') {
        return policyFail("manifest entry must be a relative path: '" + narrowForError(relative) + "'");
    }
    for (const wchar_t ch : relative) {
        if (ch >= 0x80 || ch == L'%' || ch == L'!') {
            return policyFail("manifest entry has a character unsafe in a batch file: '" + narrowForError(relative) +
                              "'");
        }
    }
    for (const std::wstring& segment : splitSegments(relative)) {
        const PolicyResult result = validateSegment(segment);
        if (!result.ok) {
            return result;
        }
    }
    return policyPass();
}

inline size_t segmentCount(const std::wstring& relative) {
    size_t count = 1;
    for (const wchar_t ch : relative) {
        if (ch == L'\\' || ch == L'/') {
            ++count;
        }
    }
    return count;
}

// Deepest-first so plain non-recursive rd removes children before parents.
inline void sortDirectoriesDeepestFirst(std::vector<std::wstring>& directories) {
    std::sort(directories.begin(), directories.end(), [](const std::wstring& a, const std::wstring& b) {
        const size_t depthA = segmentCount(a);
        const size_t depthB = segmentCount(b);
        if (depthA != depthB) {
            return depthA > depthB;
        }
        return a < b;
    });
}

// Validates every entry and produces the deletion plan. Refuses the whole plan
// (empty result) when any entry is malformed or would escape root.
inline PolicyResult planManifestDeletions(const InstallManifest& manifest, const std::wstring& root,
                                          DeletionPlan& out) {
    out = {};
    if (!isLocalAbsolutePath(root) || isDriveRoot(root)) {
        return policyFail("manifest deletion root is not a usable absolute local path: '" + narrowForError(root) +
                          "'");
    }
    const std::wstring normalizedRoot = normalizePath(root);
    for (const std::wstring& entry : manifest.files) {
        const PolicyResult result = validateManifestEntry(entry);
        if (!result.ok) {
            out = {};
            return result;
        }
        const std::wstring absolute = normalizedRoot + L"\\" + normalizePath(entry);
        if (!isContainedPath(normalizedRoot, absolute)) {
            out = {};
            return policyFail("manifest file escapes the install root: '" + narrowForError(entry) + "'");
        }
        out.files.push_back(absolute);
    }
    for (const std::wstring& entry : manifest.directories) {
        const PolicyResult result = validateManifestEntry(entry);
        if (!result.ok) {
            out = {};
            return result;
        }
        const std::wstring absolute = normalizedRoot + L"\\" + normalizePath(entry);
        if (!isContainedPath(normalizedRoot, absolute)) {
            out = {};
            return policyFail("manifest directory escapes the install root: '" + narrowForError(entry) + "'");
        }
        out.directories.push_back(absolute);
    }
    sortDirectoriesDeepestFirst(out.directories);
    return policyPass();
}

inline PolicyResult planTeardown(const InstallManifest& manifest, const std::wstring& root, DeletionPlan& out) {
    out = {};
    const auto check = validateInstallDestination(root);
    if (!check.ok) return check;
    DeletionPlan planned;
    const auto result = planManifestDeletions(manifest, root, planned);
    if (!result.ok) return result;
    std::vector<std::wstring> seen;
    for (const auto* entries : {&planned.files, &planned.directories}) {
        for (const auto& entry : *entries) {
            if (std::find(seen.begin(), seen.end(), entry) != seen.end())
                return policyFail("duplicate teardown entry: '" + narrowForError(entry) + "'");
            seen.push_back(entry);
        }
    }
    for (const auto& file : planned.files) {
        for (const auto& entry : seen) {
            if (entry != file && isContainedPath(file, entry))
                return policyFail("file used as a manifest directory: '" + narrowForError(file) + "'");
        }
    }
    const auto config = normalizePath(root) + L"\\config.json";
    planned.files.erase(std::remove(planned.files.begin(), planned.files.end(), config), planned.files.end());
    planned.directories.erase(std::remove(planned.directories.begin(), planned.directories.end(), config), planned.directories.end());
    out = std::move(planned);
    return policyPass();
}

inline bool isKnownRuntimeFile(const std::wstring& name) {
    if (!validateSegment(name).ok) return false;
    const auto normalized = normalizePath(name);
    for (const auto* file : {L"config.json", L"config.json.tmp", L"system-dns-backup.json",
                             L"system-dns-backup.json.tmp", L"9ns.log", L"service.log"})
        if (normalized == file) return true;
    for (const auto* base : {L"9ns.log.", L"service.log."}) {
        const std::wstring prefix(base);
        if (normalized.compare(0, prefix.size(), prefix) != 0) continue;
        const auto suffix = normalized.substr(prefix.size());
        if (!suffix.empty() && suffix.size() <= 9 && suffix[0] >= L'1' && suffix[0] <= L'9' &&
            std::all_of(suffix.begin(), suffix.end(), [](wchar_t ch) { return ch >= L'0' && ch <= L'9'; })) return true;
    }
    return false;
}

inline PolicyResult planDataPurge(const std::wstring& root, const std::wstring& programData,
                                  const std::vector<std::wstring>& enumeratedFiles, DeletionPlan& out) {
    out = {};
    const auto check = validateRuntimeDataPath(root, programData);
    if (!check.ok) return check;
    if (normalizePath(root) != normalizePath(programData) + L"\\9ns")
        return policyFail("purge root is not the 9NS data directory");
    for (const auto& file : enumeratedFiles) {
        if (!validateSegment(file).ok) { out = {}; return policyFail("unsafe enumerated runtime filename"); }
        if (isKnownRuntimeFile(file)) out.files.push_back(normalizePath(root) + L"\\" + file);
    }
    return policyPass();
}

// UTF-8 text of install-manifest.txt written at install time.
inline std::string buildManifestFileContent(const InstallManifest& manifest) {
    std::string text =
        "# 9NS installation manifest.\r\n"
        "# Uninstall removes only the entries listed here; unknown files are preserved.\r\n"
        "[files]\r\n";
    for (const std::wstring& entry : manifest.files) {
        text += narrowForError(entry);
        text += "\r\n";
    }
    text += "[directories]\r\n";
    for (const std::wstring& entry : manifest.directories) {
        text += narrowForError(entry);
        text += "\r\n";
    }
    return text;
}

// The uninstall script body (CRLF). It deletes only manifest files with
// explicit del lines, then removes product directories with a plain rd
// (deepest first) and finally deletes itself. It never runs rd /s, so unknown
// files survive an uninstall. Returns an empty string when the manifest is
// invalid.
inline std::wstring buildUninstallScript(const InstallManifest& manifest) {
    std::vector<std::wstring> directories;
    for (const std::wstring& entry : manifest.files) {
        if (!validateManifestEntry(entry).ok) {
            return {};
        }
    }
    for (const std::wstring& entry : manifest.directories) {
        if (!validateManifestEntry(entry).ok) {
            return {};
        }
        directories.push_back(entry);
    }
    sortDirectoriesDeepestFirst(directories);

    std::wstring script =
        L"@echo off\r\n"
        L"setlocal\r\n"
        L"echo Uninstalling 9NS...\r\n"
        L"\"%~dp09ns.exe\" --uninstall-service >nul 2>&1\r\n"
        L"%SystemRoot%\\System32\\sc.exe stop NineNsFlt >nul 2>&1\r\n"
        L"%SystemRoot%\\System32\\sc.exe delete NineNsFlt >nul 2>&1\r\n"
        L"del /f /q \"%SystemRoot%\\System32\\drivers\\NineNsFlt.sys\" >nul 2>&1\r\n"
        L"reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\9NS\" /f >nul 2>&1\r\n"
        L"del /f /q \"%PUBLIC%\\Desktop\\9NS.lnk\" >nul 2>&1\r\n"
        L"del /f /q \"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\9NS.lnk\" >nul 2>&1\r\n"
        L"echo Removing installed files...\r\n";
    for (const std::wstring& entry : manifest.files) {
        script += L"del /f /q \"%~dp0" + entry + L"\" >nul 2>&1\r\n";
    }
    for (const std::wstring& entry : directories) {
        script += L"rd \"%~dp0" + entry + L"\" >nul 2>&1\r\n";
    }
    script +=
        L"echo 9NS shortcuts and registry entries removed.\r\n"
        // Delete only this script and then the root with a plain rd: an unknown
        // file keeps the directory, so user data inside the tree survives.
        L"start /b \"\" \"%SystemRoot%\\System32\\cmd.exe\" /c ping -n 3 127.0.0.1 ^>nul ^& del /f /q "
        L"\"%~dp0uninstall.bat\" ^& rd \"%~dp0\" 2^>nul\r\n";
    return script;
}

// --- staging design ---

// Staging name from installer randomness: "9ns-staging-" + 32 hex characters.
inline std::wstring makeStagingName(const std::string& randomHex) {
    return L"9ns-staging-" + std::wstring(randomHex.begin(), randomHex.end());
}

inline PolicyResult validateStagingName(const std::wstring& name) {
    const std::wstring prefix = L"9ns-staging-";
    if (name.size() != prefix.size() + 32) {
        return policyFail("staging name has the wrong length: '" + narrowForError(name) + "'");
    }
    if (name.compare(0, prefix.size(), prefix) != 0) {
        return policyFail("staging name has the wrong prefix: '" + narrowForError(name) + "'");
    }
    for (size_t i = prefix.size(); i < name.size(); ++i) {
        const wchar_t ch = name[i];
        const bool hex = (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F');
        if (!hex) {
            return policyFail("staging name is not hex: '" + narrowForError(name) + "'");
        }
    }
    return policyPass();
}

// --- command construction ---

// Quotes one Windows command-line argument (CommandLineToArgvW rules) so
// callers never concatenate raw paths into a command line. Validated paths
// never contain quotes; trailing backslashes before the closing quote are
// doubled so they cannot escape it.
inline std::wstring quoteCommandLineArgument(const std::wstring& argument) {
    if (argument.empty()) {
        return L"\"\"";
    }
    bool needsQuotes = false;
    for (const wchar_t ch : argument) {
        if (ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\v' || ch == L'"') {
            needsQuotes = true;
            break;
        }
    }
    if (!needsQuotes) {
        return argument;
    }
    std::wstring result;
    result += L'"';
    size_t i = 0;
    while (i < argument.size()) {
        size_t slashes = 0;
        while (i < argument.size() && argument[i] == L'\\') {
            ++slashes;
            ++i;
        }
        if (i == argument.size()) {
            result.append(slashes * 2, L'\\');
        } else if (argument[i] == L'"') {
            result.append(slashes * 2 + 1, L'\\');
            result += L'"';
            ++i;
        } else {
            result.append(slashes, L'\\');
            result += argument[i];
            ++i;
        }
    }
    result += L'"';
    return result;
}

// ARP uninstall command: absolute cmd.exe plus the script path as data. The
// doubled quotes keep the whole path one token for cmd /c even with spaces.
inline std::wstring buildUninstallString(const std::wstring& cmdExePath, const std::wstring& uninstallScriptPath) {
    return quoteCommandLineArgument(cmdExePath) + L" /c \"\"" + uninstallScriptPath + L"\"\"";
}

inline std::wstring buildNativeUninstallString(const std::wstring& executable, bool quiet = false) {
    if (!validateLocalPath(executable).ok) return {};
    return L"\"" + executable + L"\" /uninstall" + (quiet ? L" /silent /keepdata=yes" : L"");
}

inline std::wstring buildNativeRepairString(const std::wstring& executable) {
    if (!validateLocalPath(executable).ok) return {};
    return L"\"" + executable + L"\" /repair";
}

// Values interpolated into netsh's own name="..." syntax: netsh parses that
// syntax itself, so quotes and control characters would break out of it.
inline bool isSafeNetshValue(const std::wstring& value) {
    if (value.empty() || value.size() > 256) {
        return false;
    }
    for (const wchar_t ch : value) {
        if (ch < 0x20 || ch == L'"') {
            return false;
        }
    }
    return true;
}

// Address tokens handed to netsh as server addresses: only hex digits, dots
// and colons (the textual IPv4/IPv6 alphabet).
inline bool isSafeAddressToken(const std::wstring& token) {
    if (token.empty() || token.size() > 46) {
        return false;
    }
    for (const wchar_t ch : token) {
        const bool hex = (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F');
        if (!hex && ch != L'.' && ch != L':') {
            return false;
        }
    }
    return true;
}

}  // namespace protected_paths

// Fail-closed runtime-directory trust for %ProgramData%\9NS. Implemented in
// ProtectedDirectory.cpp; call it from the GUI startup, the service main and
// the watchdog before any log, config or DNS-backup access.
namespace protected_runtime {

constexpr wchar_t kConfigFileName[] = L"config.json";
constexpr wchar_t kBackupFileName[] = L"system-dns-backup.json";
constexpr wchar_t kServiceLogFileName[] = L"service.log";

// The protected DACL: SYSTEM and Administrators have full control, standard
// users may only read. The config file and the DNS backup live in this folder.
constexpr wchar_t kProtectedDirSddl[] = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

// Resolves %ProgramData%\9NS through the ProgramData known folder and makes the
// tree trustworthy in one fail-closed step: creates the folder with the
// protected DACL when missing, refuses reparse points and untrusted owners
// (repairing ownership of files this product created), resets the DACL and
// secures existing child files. Returns false and fills error, naming the
// offending value, when anything is untrusted; the caller must then refuse to
// read config, logs or DNS backups.
bool ensureDataDirectory(std::wstring& out, std::string& error);

}  // namespace protected_runtime
