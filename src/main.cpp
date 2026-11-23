#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>

#include <QApplication>
#include <QAbstractNativeEventFilter>
#include <vector>

#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <string>

#include "core/Engine.h"
#include "core/Logger.h"
#include "ui/MainWindow.h"
#include "ui/Theme.h"
#include "core/ProtectedDirectory.h"
#include "core/SystemDns.h"
#include "core/Text.h"
#include "core/WindowsService.h"

namespace {

constexpr wchar_t kAppTitle[] = L"9NS";

class MaintenanceShutdownFilter : public QAbstractNativeEventFilter {
public:
    bool nativeEventFilter(const QByteArray&, void* message, qintptr* result) override {
        const auto* event = static_cast<MSG*>(message);
        if (messageId_ && event->message == messageId_) {
            QApplication::quit();
            *result = 0;
            return true;
        }
        return false;
    }
private:
    const UINT messageId_ = RegisterWindowMessageW(L"9NS.MaintenanceShutdown");
};

std::wstring executableDirectory() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD copied = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (copied == 0) {
            return L".";
        }
        if (copied < path.size()) {
            path.resize(copied);
            break;
        }
        path.resize(path.size() * 2);  // the path was truncated; try a larger buffer
    }
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring(L".") : path.substr(0, slash);
}

// Reads an unsigned decimal number after optional spaces. A sign, a missing number, or an
// overflow is rejected.
bool readNumber(const wchar_t*& cursor, unsigned long long& value) {
    while (*cursor == L' ') {
        ++cursor;
    }
    if (*cursor < L'0' || *cursor > L'9') {
        return false;
    }
    errno = 0;
    wchar_t* end = nullptr;
    value = std::wcstoull(cursor, &end, 10);
    if (errno == ERANGE) {
        return false;
    }
    cursor = end;
    return true;
}

// Parses "--dns-watchdog <pid> <start time>". Returns false for any other command line, including
// one with extra arguments. The backup path is deliberately not an argument.
bool parseWatchdogArgs(const std::wstring& args, unsigned long& pid, unsigned long long& started) {
    const std::wstring prefix = L"--dns-watchdog ";
    if (args.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const wchar_t* cursor = args.c_str() + prefix.size();

    unsigned long long parsedPid = 0;
    if (!readNumber(cursor, parsedPid) || parsedPid == 0 || parsedPid > 0xFFFFFFFFull) {
        return false;
    }
    if (!readNumber(cursor, started) || started == 0) {
        return false;
    }
    while (*cursor == L' ') {
        ++cursor;
    }
    if (*cursor != L'\0') {
        return false;
    }
    pid = static_cast<unsigned long>(parsedPid);
    return true;
}

}  // namespace

int main(int argc, char* argv[]) {
    // The watchdog runs as this same executable. It must not create a Qt application or a window.
    std::wstring args;
    std::vector<std::wstring> tokens;
    int wideCount = 0;
    LPWSTR* wideArgs = CommandLineToArgvW(GetCommandLineW(), &wideCount);
    if (wideArgs) {
        for (int i = 1; i < wideCount; ++i) {
            if (i > 1) {
                args += L' ';
            }
            args += wideArgs[i];
            tokens.emplace_back(wideArgs[i]);
        }
        LocalFree(wideArgs);
    }

    unsigned long watchdogPid = 0;
    unsigned long long watchdogStarted = 0;
    if (parseWatchdogArgs(args, watchdogPid, watchdogStarted)) {
        // Fail closed before touching the backup: the runtime directory must pass
        // the shared trust checks (owner, DACL, reparse points) first.
        std::wstring watchdogDir;
        std::string dirError;
        if (!protected_runtime::ensureDataDirectory(watchdogDir, dirError)) {
            return 1;  // cannot trust the backup location; leave DNS alone
        }
        return runDnsWatchdog(static_cast<uint32_t>(watchdogPid), watchdogStarted,
                              std::filesystem::path(watchdogDir + L"\\" + protected_runtime::kBackupFileName));
    }

    if (args == L"--service") {
        return service::runService();
    }
    bool quiet = false;
    std::wstring action;
    for (const auto& token : tokens) {
        if (token == L"--quiet" && !quiet) quiet = true;
        else if ((token == L"--install-service" || token == L"--uninstall-service" || token == L"--restore-dns") && action.empty()) action = token;
        else if (!action.empty() || quiet || token.compare(0, 2, L"--") == 0) return ERROR_INVALID_PARAMETER;
    }
    if (!action.empty()) {
        std::string error;
        bool ok = false;
        if (action == L"--restore-dns") {
            std::wstring directory;
            if (!protected_runtime::ensureDataDirectory(directory, error)) return 1;
            WSADATA wsa{};
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
            try {
                Logger logger;
                logger.open(std::filesystem::path(directory + L"\\" + protected_runtime::kServiceLogFileName), Logger::Level::Info);
                SystemDns dns(std::filesystem::path(directory + L"\\" + protected_runtime::kBackupFileName), logger);
                const bool restored = dns.restoreLeftover();
                const bool cleared = SystemDns::clearLeakPreventionPolicy();
                ok = restored && cleared;
                if (!ok) logger.log(Logger::Level::Error, "DNS restoration or leak-prevention policy cleanup failed");
            } catch (const std::exception&) { ok = false; }
            WSACleanup();
            return ok ? 0 : 1;
        }
        ok = action == L"--install-service" ? service::installService(error) : service::uninstallService(error);
        if (!quiet) MessageBoxW(nullptr, ok ? L"9NS service action completed." : widen(error).c_str(),
                                kAppTitle, MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
        return ok ? 0 : 1;
    }
    if (quiet) return ERROR_INVALID_PARAMETER;

    // Two instances would fight over port 53 and over the adapter DNS backup.
    HANDLE instanceLock = CreateMutexW(nullptr, FALSE, L"Local\\9NSSingleInstance");
    if (instanceLock && GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"9NS is already running.", kAppTitle, MB_OK | MB_ICONINFORMATION);
        CloseHandle(instanceLock);
        return 0;
    }

    // Fail closed: config, logs and the DNS backup may only be read from the
    // protected runtime directory created or validated by the shared initializer.
    std::wstring dataDir;
    std::string dirError;
    if (!protected_runtime::ensureDataDirectory(dataDir, dirError)) {
        MessageBoxW(nullptr,
                    widen("The data folder %ProgramData%\\9NS could not be created or secured: " + dirError)
                        .c_str(),
                    kAppTitle, MB_OK | MB_ICONERROR);
        if (instanceLock) {
            CloseHandle(instanceLock);
        }
        return 1;
    }

    // Elevated launches can start in another directory; keep relative paths next to the executable.
    SetCurrentDirectoryW(executableDirectory().c_str());

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(nullptr, L"Winsock could not be initialized.", kAppTitle, MB_OK | MB_ICONERROR);
        if (instanceLock) {
            CloseHandle(instanceLock);
        }
        return 1;
    }

    int exitCode = 0;
    {
        // Destruction runs in reverse: window, then engine (restores adapter DNS), then logger, then app.
        QApplication app(argc, argv);
        MaintenanceShutdownFilter maintenanceShutdown;
        app.installNativeEventFilter(&maintenanceShutdown);
        QApplication::setApplicationName(QStringLiteral("9NS"));
        Theme::apply(app);

        Logger logger;
        Engine engine(logger, narrow(dataDir + L"\\" + protected_runtime::kBackupFileName));
        engine.recoverSystemDns();
        MainWindow window(logger, engine, std::filesystem::path(dataDir + L"\\" + protected_runtime::kConfigFileName));
        window.show();
        exitCode = app.exec();
    }

    WSACleanup();
    if (instanceLock) {
        CloseHandle(instanceLock);
    }
    return exitCode;
}
