#pragma once

#include <string>

// Manages execution, installation, and uninstallation of 9ns as a background Windows Service.
namespace service {

constexpr wchar_t kServiceName[] = L"9NSService";
constexpr wchar_t kServiceDisplayName[] = L"9NS Proxy Service";
constexpr wchar_t kServiceDescription[] = L"System-level secure DNS proxy with DoH, DoT, DNSCrypt, and rule routing.";

// Runs the service under Service Control Manager (SCM). Call when exe is launched with --service.
int runService();

// Installs the service in SCM. Requires administrator elevation.
bool installService(std::string& error);

// Uninstalls the service from SCM. Requires administrator elevation.
bool uninstallService(std::string& error);

}  // namespace service
