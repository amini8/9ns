#include "core/SystemDns.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/ProtectedDirectory.h"
#include "core/Text.h"

namespace {

using json = nlohmann::json;

constexpr wchar_t kLoopback[] = L"127.0.0.1";
constexpr DWORD kAdapterFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

struct Adapter {
    std::string guid;
    std::wstring name;
};

enum class Presence { Present, Missing, Unknown };

// Returns the adapter list for one address family, or an empty buffer if the query failed.
std::vector<uint8_t> queryAdapters(ULONG family) {
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buffer;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.assign(size, 0);
        rc = GetAdaptersAddresses(family, kAdapterFlags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (rc != NO_ERROR) {
        buffer.clear();
    }
    return buffer;
}

// Tells whether an adapter with this GUID exists. Unknown means the adapter list could not be read.
Presence adapterPresence(const std::string& guid) {
    const std::vector<uint8_t> buffer = queryAdapters(AF_UNSPEC);
    if (buffer.empty()) {
        return Presence::Unknown;
    }
    for (const IP_ADAPTER_ADDRESSES* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a;
         a = a->Next) {
        if (a->AdapterName && _stricmp(a->AdapterName, guid.c_str()) == 0) {
            return Presence::Present;
        }
    }
    return Presence::Missing;
}

bool parseGuid(const std::string& text, GUID& guid) {
    const std::wstring wide = widen(text);
    return CLSIDFromString(wide.c_str(), &guid) == S_OK;
}

// Accepts an empty string, or comma-separated IPv4 or IPv6 addresses. Anything else is rejected.
bool validNameServers(const std::string& text) {
    if (text.empty()) {
        return true;
    }
    std::string item;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == ',') {
            IN_ADDR v4{};
            IN6_ADDR v6{};
            if (inet_pton(AF_INET, item.c_str(), &v4) != 1 && inet_pton(AF_INET6, item.c_str(), &v6) != 1) {
                return false;
            }
            item.clear();
        } else {
            item.push_back(text[i]);
        }
    }
    return true;
}

// The per-interface DNS settings API (Windows 10 2004 and later) is missing from the MinGW-w64
// headers and import libraries. This declares the layout from windns.h and resolves the three
// functions from dnsapi.dll at run time, so the code builds with MSVC and MinGW alike and
// fails cleanly on a Windows version that lacks the API.
struct InterfaceDnsSettings {
    ULONG Version;
    ULONG64 Flags;
    PWSTR Domain;
    PWSTR NameServer;
    PWSTR SearchList;
    ULONG RegistrationEnabled;
    ULONG RegisterAdapterName;
    ULONG EnableLLMNR;
    ULONG QueryAdapterName;
    PWSTR ProfileNameServer;
};

constexpr ULONG kSettingsVersion1 = 1;
constexpr ULONG64 kSettingNameServer = 0x0002;

using GetSettingsFn = DWORD(WINAPI*)(GUID, InterfaceDnsSettings*);
using SetSettingsFn = DWORD(WINAPI*)(GUID, const InterfaceDnsSettings*);
using FreeSettingsFn = void(WINAPI*)(InterfaceDnsSettings*);

struct DnsSettingsApi {
    GetSettingsFn get = nullptr;
    SetSettingsFn set = nullptr;
    FreeSettingsFn release = nullptr;
};

const DnsSettingsApi& dnsSettingsApi() {
    static const DnsSettingsApi api = [] {
        DnsSettingsApi result;
        HMODULE module = LoadLibraryW(L"dnsapi.dll");
        if (!module) {
            return result;
        }
        auto get = reinterpret_cast<GetSettingsFn>(
            reinterpret_cast<void*>(GetProcAddress(module, "GetInterfaceDnsSettings")));
        auto set = reinterpret_cast<SetSettingsFn>(
            reinterpret_cast<void*>(GetProcAddress(module, "SetInterfaceDnsSettings")));
        auto release = reinterpret_cast<FreeSettingsFn>(
            reinterpret_cast<void*>(GetProcAddress(module, "FreeInterfaceDnsSettings")));
        if (get && set && release) {
            result.get = get;
            result.set = set;
            result.release = release;
            // Deliberate process-lifetime retention: the resolved function pointers
            // stay valid while callers use them, so the module reference is kept.
        } else {
            FreeLibrary(module);  // incomplete exports; release the reference
        }
        return result;
    }();
    return api;
}

bool executeNetsh(const std::wstring& args) {
    wchar_t systemDir[MAX_PATH] = {};
    const UINT length = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    // netsh runs by its absolute System32 path so no searched-for helper can be
    // substituted; the argument tail is data, never interpreter source.
    const std::wstring application = std::wstring(systemDir) + L"\\netsh.exe";
    const std::wstring cmd =
        protected_paths::quoteCommandLineArgument(application) + L" " + args;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');
    if (!CreateProcessW(application.c_str(), cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 3500);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

std::wstring adapterFriendlyName(const std::string& guid) {
    const std::vector<uint8_t> buffer = queryAdapters(AF_UNSPEC);
    if (buffer.empty()) {
        return {};
    }
    for (const IP_ADAPTER_ADDRESSES* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (a->AdapterName && _stricmp(a->AdapterName, guid.c_str()) == 0) {
            return a->FriendlyName ? a->FriendlyName : L"";
        }
    }
    return {};
}

bool readNameServer(const GUID& guid, std::wstring& out) {
    const DnsSettingsApi& api = dnsSettingsApi();
    if (api.get) {
        InterfaceDnsSettings settings{};
        settings.Version = kSettingsVersion1;
        if (api.get(guid, &settings) == NO_ERROR) {
            out = settings.NameServer ? settings.NameServer : L"";
            api.release(&settings);
            return true;
        }
    }
    // Fallback: Read from Windows Registry
    wchar_t guidStr[42] = {};
    if (StringFromGUID2(guid, guidStr, 42) > 0) {
        std::wstring subkey = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + std::wstring(guidStr);
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t val[512] = {};
            DWORD size = sizeof(val);
            if (RegQueryValueExW(hKey, L"NameServer", nullptr, nullptr, reinterpret_cast<BYTE*>(val), &size) == ERROR_SUCCESS && val[0]) {
                out = val;
                RegCloseKey(hKey);
                return true;
            }
            size = sizeof(val);
            if (RegQueryValueExW(hKey, L"DhcpNameServer", nullptr, nullptr, reinterpret_cast<BYTE*>(val), &size) == ERROR_SUCCESS) {
                out = val;
                RegCloseKey(hKey);
                return true;
            }
            RegCloseKey(hKey);
        }
    }
    out = L"";
    return true;
}

// An empty string is written to return an adapter to automatic DNS.
bool writeNameServer(const GUID& guid, const std::wstring& adapterName, const std::wstring& servers) {
    const DnsSettingsApi& api = dnsSettingsApi();
    if (api.set) {
        InterfaceDnsSettings settings{};
        settings.Version = kSettingsVersion1;
        settings.Flags = kSettingNameServer;
        settings.NameServer = const_cast<PWSTR>(servers.c_str());
        if (api.set(guid, &settings) == NO_ERROR) {
            return true;
        }
    }
    // Fallback: Netsh command execution. Adapter name and address tokens are
    // interpolated into netsh's own name="..." syntax, so refuse values that
    // could escape those quotes before they reach the command line.
    if (!adapterName.empty()) {
        if (!protected_paths::isSafeNetshValue(adapterName)) {
            return false;
        }
        if (servers.empty()) {
            executeNetsh(L"interface ipv4 set dnsservers name=\"" + adapterName + L"\" source=dhcp");
            executeNetsh(L"interface ipv6 set dnsservers name=\"" + adapterName + L"\" source=dhcp");
            return true;
        }
        bool ok = false;
        bool hasV4 = false;
        bool hasV6 = false;
        std::wstring item;
        for (size_t i = 0; i <= servers.size(); ++i) {
            if (i == servers.size() || servers[i] == L',') {
                if (!item.empty()) {
                    if (protected_paths::isSafeAddressToken(item)) {
                        if (item.find(L':') != std::wstring::npos) {
                            if (!hasV6) {
                                if (executeNetsh(L"interface ipv6 set dnsservers name=\"" + adapterName + L"\" static " + item + L" primary")) {
                                    ok = true;
                                }
                                hasV6 = true;
                            } else {
                                executeNetsh(L"interface ipv6 add dnsservers name=\"" + adapterName + L"\" " + item);
                            }
                        } else if (item.find(L'.') != std::wstring::npos) {
                            if (!hasV4) {
                                if (executeNetsh(L"interface ipv4 set dnsservers name=\"" + adapterName + L"\" static " + item + L" primary")) {
                                    ok = true;
                                }
                                hasV4 = true;
                            } else {
                                executeNetsh(L"interface ipv4 add dnsservers name=\"" + adapterName + L"\" " + item);
                            }
                        }
                    }
                    item.clear();
                }
            } else if (!iswspace(servers[i])) {
                item.push_back(servers[i]);
            }
        }
        return ok;
    }
    return false;
}

// Writes to a temporary file, flushes it to disk, then replaces the target in one step.
// A crash leaves either the old file or the new one, never a partial file.
bool writeFileDurably(const std::filesystem::path& target, const std::string& data) {
    const std::wstring temp = target.wstring() + L".tmp";
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const bool ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
                    written == data.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok) {
        DeleteFileW(temp.c_str());
        return false;
    }
    return MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

// Creation time of a process in 100 ns ticks. Together with the PID, this identifies one process.
bool creationTimeOf(HANDLE process, uint64_t& out) {
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        return false;
    }
    out = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return true;
}

std::vector<Adapter> eligibleAdapters() {
    std::vector<Adapter> result;
    const std::vector<uint8_t> buffer = queryAdapters(AF_UNSPEC);
    if (buffer.empty()) {
        return result;  // the query failed; the cleared buffer must not be walked
    }
    for (const IP_ADAPTER_ADDRESSES* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a;
         a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        if (a->OperStatus == IfOperStatusDown) {
            continue;
        }
        if (!a->FirstUnicastAddress || !a->AdapterName) {
            continue;
        }
        result.push_back({a->AdapterName, a->FriendlyName ? a->FriendlyName : L""});
    }
    return result;
}

// Full path of this executable, or an empty string on failure.
std::wstring currentExecutable() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD copied = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (copied == 0) {
            return {};
        }
        if (copied < path.size()) {
            path.resize(copied);
            return path;
        }
        if (path.size() > 32768) {
            return {};
        }
        path.resize(path.size() * 2);
    }
}

void setSmartMultiHomedResolution(bool disable) {
    HKEY hKey = nullptr;
    const wchar_t* subkey = L"Software\\Policies\\Microsoft\\Windows NT\\DNSClient";
    if (disable) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExW(hKey, L"DisableSmartNameResolution", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
            RegCloseKey(hKey);
        }
    } else {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"DisableSmartNameResolution");
            RegCloseKey(hKey);
        }
    }
}

}  // namespace

std::vector<InterfaceInfo> SystemDns::listInterfaces() {
    std::vector<InterfaceInfo> list;
    const std::vector<uint8_t> buffer = queryAdapters(AF_UNSPEC);
    if (buffer.empty()) {
        return list;
    }
    for (const auto* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (!a->AdapterName) {
            continue;
        }
        InterfaceInfo info;
        info.guid = a->AdapterName;
        if (a->FriendlyName) {
            info.name = narrow(a->FriendlyName);
        } else {
            info.name = info.guid;
        }
        std::string description;
        if (a->Description) {
            description = narrow(a->Description);
        }
        info.isVpn = (a->IfType == IF_TYPE_PPP || a->IfType == IF_TYPE_TUNNEL ||
                      info.name.find("VPN") != std::string::npos ||
                      description.find("VPN") != std::string::npos);
        list.push_back(info);
    }
    return list;
}

SystemDns::SystemDns(std::filesystem::path backupPath, Logger& logger)
    : backupPath_(std::move(backupPath)), logger_(logger) {}

SystemDns::~SystemDns() {
    restore();
}

// Starts a second copy of this program that waits for the current process to exit.
// Runs once per SystemDns object. The watchdog inherits this process's elevation.
// The command line carries only the PID and start time. The watchdog finds the backup file itself,
// in the protected data folder, so a caller cannot point it at another file.
bool SystemDns::launchWatchdog() {
    if (watchdogStarted_) {
        return true;
    }
    const std::wstring exe = currentExecutable();
    uint64_t started = 0;
    if (exe.empty() || !creationTimeOf(GetCurrentProcess(), started)) {
        return false;
    }

    const std::wstring commandLine = L"\"" + exe + L"\" --dns-watchdog " +
                                     std::to_wstring(GetCurrentProcessId()) + L" " + std::to_wstring(started);
    std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
    buffer.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe.c_str(), buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    watchdogStarted_ = true;
    return true;
}

bool SystemDns::apply(bool preventLeaks, bool ipv6) {
    if (active_) {
        return true;
    }

    const wchar_t* targetLoopback = (ipv6 && preventLeaks) ? L"127.0.0.1,::1" : L"127.0.0.1";

    // If a leftover backup exists from an earlier run, restore it first so original values are not lost.
    std::error_code ec;
    if (std::filesystem::exists(backupPath_, ec)) {
        logger_.log(Logger::Level::Info,
                    "Found DNS backup from a previous run; restoring adapter settings first...");
        restoreLeftover();
    }

    const std::vector<Adapter> adapters = eligibleAdapters();
    size_t alreadyLoopback = 0;
    std::vector<Saved> saved;
    std::vector<GUID> guids;
    std::vector<std::wstring> names;
    for (const Adapter& adapter : adapters) {
        GUID guid{};
        std::wstring current;
        if (!parseGuid(adapter.guid, guid) || !readNameServer(guid, current)) {
            logger_.log(Logger::Level::Error, "Cannot read the DNS settings of adapter " + narrow(adapter.name));
            continue;
        }
        if (current == targetLoopback || current == L"127.0.0.1" || current == L"127.0.0.1,::1" || current.find(L"127.0.0.1") != std::wstring::npos) {
            ++alreadyLoopback;  // already pointing here
            continue;
        }
        saved.push_back({adapter.guid, narrow(current)});
        guids.push_back(guid);
        names.push_back(adapter.name);
    }

    if (saved.empty()) {
        if (alreadyLoopback > 0) {
            logger_.log(Logger::Level::Info,
                        "Active adapters already point to loopback; adapter DNS left as it is");
            if (preventLeaks) {
                setSmartMultiHomedResolution(true);
            }
            active_ = true;
            return true;
        }
        if (adapters.empty()) {
            logger_.log(Logger::Level::Error, "No active network adapter found for system DNS");
        } else {
            logger_.log(Logger::Level::Error,
                        "The DNS settings of the active adapters could not be read; adapter DNS was not changed");
        }
        return false;
    }

    if (!launchWatchdog()) {
        logger_.log(Logger::Level::Error, "Cannot start the DNS watchdog; adapter DNS was not changed");
        return false;
    }
    if (!writeBackup(saved)) {
        logger_.log(Logger::Level::Error,
                    "Cannot write " + narrow(backupPath_.wstring()) + "; adapter DNS was not changed");
        return false;
    }

    size_t changed = 0;
    for (size_t i = 0; i < guids.size(); ++i) {
        if (writeNameServer(guids[i], names[i], targetLoopback)) {
            ++changed;
            logger_.log(Logger::Level::Info, "System DNS set to " + narrow(targetLoopback) + " on " + narrow(names[i]));
        } else {
            logger_.log(Logger::Level::Error, "Cannot change the DNS of adapter " + narrow(names[i]));
        }
    }
    if (changed == 0) {
        removeBackup();
        return false;
    }

    if (preventLeaks) {
        setSmartMultiHomedResolution(true);
    }

    saved_ = std::move(saved);
    active_ = true;
    return true;
}

void SystemDns::restore() {
    if (!active_) {
        return;
    }
    setSmartMultiHomedResolution(false);
    restoreFrom(saved_);
    saved_.clear();
    active_ = false;
}

void SystemDns::restoreLeftover() {
    std::vector<Saved> saved;
    if (!readBackup(saved)) {
        logger_.log(Logger::Level::Error,
                    "The DNS backup " + narrow(backupPath_.wstring()) +
                        " cannot be read. It was kept so the saved values are not lost. "
                        "Adapters may still use 127.0.0.1.");
        return;
    }
    if (saved.empty()) {
        removeBackup();
        return;
    }
    logger_.log(Logger::Level::Info, "Restoring adapter DNS settings left by a previous run");
    restoreFrom(saved);
}

// Restores each entry. Entries that could not be restored are written back to the backup file,
// so the next startup retries them. Returns true if nothing is left.
bool SystemDns::restoreFrom(const std::vector<Saved>& saved) {
    std::vector<Saved> unresolved;
    for (const Saved& entry : saved) {
        GUID guid{};
        if (!parseGuid(entry.guid, guid)) {
            logger_.log(Logger::Level::Error,
                        "Skipping a malformed adapter GUID in the DNS backup: " + entry.guid);
            continue;
        }

        const Presence presence = adapterPresence(entry.guid);
        if (presence == Presence::Missing) {
            logger_.log(Logger::Level::Info, "Adapter " + entry.guid + " no longer exists; dropping its saved DNS");
            continue;
        }

        std::wstring current;
        if (presence == Presence::Unknown || !readNameServer(guid, current)) {
            logger_.log(Logger::Level::Error,
                        "Cannot read the DNS of adapter " + entry.guid + "; the saved value is kept for the next attempt");
            unresolved.push_back(entry);
            continue;
        }
        if (current != kLoopback && current != L"127.0.0.1,::1" && current.find(L"127.0.0.1") == std::wstring::npos) {
            continue;  // someone else changed it; do not overwrite
        }

        std::string value = entry.nameServer;
        if (!validNameServers(value)) {
            logger_.log(Logger::Level::Error,
                        "The saved DNS of adapter " + entry.guid +
                            " is not a valid address list; setting automatic DNS");
            value.clear();
        }
        const std::wstring adapterName = adapterFriendlyName(entry.guid);
        if (writeNameServer(guid, adapterName, widen(value))) {
            logger_.log(Logger::Level::Info, "Restored DNS of adapter " + (adapterName.empty() ? entry.guid : narrow(adapterName)));
        } else {
            logger_.log(Logger::Level::Error, "Cannot restore the DNS of adapter " + (adapterName.empty() ? entry.guid : narrow(adapterName)));
            unresolved.push_back(entry);
        }
    }

    if (unresolved.empty()) {
        removeBackup();
        return true;
    }
    writeBackup(unresolved);
    return false;
}

bool SystemDns::writeBackup(const std::vector<Saved>& saved) const {
    try {
        json array = json::array();
        for (const Saved& entry : saved) {
            json item = json::object();
            item["guid"] = entry.guid;
            item["name_server"] = entry.nameServer;
            array.push_back(item);
        }
        return writeFileDurably(backupPath_, array.dump(2) + "\n");
    } catch (const std::exception&) {
        return false;
    }
}

// Returns false if the file exists but cannot be read or parsed. A missing file gives an empty list and true.
bool SystemDns::readBackup(std::vector<Saved>& out) const {
    out.clear();
    std::error_code ec;
    if (!std::filesystem::exists(backupPath_, ec)) {
        return !ec;
    }
    std::ifstream in(backupPath_, std::ios::binary);
    if (!in) {
        return false;
    }
    try {
        const json array = json::parse(in);
        if (!array.is_array()) {
            return false;
        }
        for (const auto& item : array) {
            out.push_back({item.at("guid").get<std::string>(), item.at("name_server").get<std::string>()});
        }
    } catch (const std::exception&) {
        out.clear();
        return false;
    }
    return true;
}

void SystemDns::removeBackup() const {
    std::error_code ec;
    std::filesystem::remove(backupPath_, ec);
}

int runDnsWatchdog(uint32_t parentPid, uint64_t parentStarted, const std::filesystem::path& backupPath) {
    if (HANDLE parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid)) {
        uint64_t started = 0;
        if (!creationTimeOf(parent, started)) {
            CloseHandle(parent);
            return 1;  // unknown state; leave DNS alone
        }
        // A different creation time means the PID was reused, so the original parent has already exited.
        if (started == parentStarted) {
            WaitForSingleObject(parent, INFINITE);
        }
        CloseHandle(parent);
    } else if (GetLastError() != ERROR_INVALID_PARAMETER) {
        return 1;  // the parent may still run; leave DNS alone
    }

    Logger logger;
    SystemDns dns(backupPath, logger);
    dns.restoreLeftover();
    return 0;
}
