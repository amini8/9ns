#include "core/WindowsService.h"

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>

#include "core/Config.h"
#include "core/Engine.h"
#include "core/Logger.h"
#include "core/ProtectedDirectory.h"
#include "core/Text.h"

namespace service {
namespace {

SERVICE_STATUS g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = nullptr;

std::wstring getModulePath() {
    std::wstring path(MAX_PATH, L'\0');
    const DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(len);
    return path;
}

DWORD WINAPI serviceHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_statusHandle, &g_serviceStatus);
            if (g_stopEvent) {
                SetEvent(g_stopEvent);
            }
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

VOID WINAPI serviceMain(DWORD argc, LPWSTR* argv) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, serviceHandler, nullptr);
    if (!g_statusHandle) {
        return;
    }

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        return;
    }

    // Fail closed before any log, config or DNS-backup access: the runtime
    // directory must pass the shared trust checks (owner, DACL, reparse points)
    // exactly like the GUI and the watchdog do.
    std::wstring dataDir;
    std::string dirError;
    if (!protected_runtime::ensureDataDirectory(dataDir, dirError)) {
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        CloseHandle(g_stopEvent);
        return;
    }

    Logger logger;
    Engine engine(logger, narrow(dataDir + L"\\" + protected_runtime::kBackupFileName));

    try {
        logger.open(narrow(dataDir + L"\\" + protected_runtime::kServiceLogFileName), Logger::Level::Info);
        engine.recoverSystemDns();
        const Config config = loadConfig(dataDir + L"\\" + protected_runtime::kConfigFileName);
        engine.start(config);
    } catch (const std::exception& e) {
        logger.log(Logger::Level::Error, std::string("Service failed to start engine: ") + e.what());
        WSACleanup();
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
        CloseHandle(g_stopEvent);
        return;
    }

    g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);

    WaitForSingleObject(g_stopEvent, INFINITE);

    g_serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);

    engine.stop();
    WSACleanup();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

}  // namespace

int runService() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), serviceMain },
        { nullptr, nullptr }
    };
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
}

bool installService(std::string& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        error = "cannot open Service Control Manager (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    const std::wstring binPath = L"\"" + getModulePath() + L"\" --service";
    SC_HANDLE svc = CreateServiceW(scm, kServiceName, kServiceDisplayName,
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        error = "cannot create service (error " + std::to_string(GetLastError()) + ")";
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = const_cast<LPWSTR>(kServiceDescription);
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool uninstallService(std::string& error) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        error = "cannot open Service Control Manager (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, kServiceName, DELETE);
    if (!svc) {
        error = "cannot open service (error " + std::to_string(GetLastError()) + ")";
        CloseServiceHandle(scm);
        return false;
    }

    const bool ok = DeleteService(svc) != FALSE;
    if (!ok) {
        error = "cannot delete service (error " + std::to_string(GetLastError()) + ")";
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

}  // namespace service
