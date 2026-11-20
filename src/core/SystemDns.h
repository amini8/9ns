#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "core/Logger.h"

// Points the DNS server of every active Ethernet and Wi-Fi adapter at 127.0.0.1 and restores the
// original values later. The original values go to a backup file before anything is changed. A
// watchdog process, started first, restores them if this process exits without doing so.
//
struct InterfaceInfo {
    std::string guid;
    std::string name;
    bool isVpn = false;
};

// Points the DNS server of active network adapters at loopback (127.0.0.1 and ::1)
// and restores the original values later.
class SystemDns {
public:
    SystemDns(std::filesystem::path backupPath, Logger& logger);
    ~SystemDns();

    SystemDns(const SystemDns&) = delete;
    SystemDns& operator=(const SystemDns&) = delete;

    // Returns true if at least one adapter now uses loopback.
    bool apply(bool preventLeaks = true, bool ipv6 = true);

    // Restores the saved values.
    void restore();

    // Restores adapters from a backup file left by a run that did not exit cleanly.
    void restoreLeftover();

    bool active() const { return active_; }

    static std::vector<InterfaceInfo> listInterfaces();

private:
    struct Saved {
        std::string guid;        // adapter GUID in "{...}" form
        std::string nameServer;  // comma-separated IPv4/IPv6 addresses; empty means automatic DNS
    };

    bool launchWatchdog();
    bool writeBackup(const std::vector<Saved>& saved) const;
    bool readBackup(std::vector<Saved>& out) const;
    void removeBackup() const;
    bool restoreFrom(const std::vector<Saved>& saved);

    std::filesystem::path backupPath_;
    Logger& logger_;
    std::vector<Saved> saved_;
    bool active_ = false;
    bool watchdogStarted_ = false;
};

// Entry point of the watchdog, started as: <exe> --dns-watchdog <pid> <start time>.
// <start time> is the parent's process creation time, so a reused PID is not mistaken for the parent.
// The caller derives backupPath from the protected data folder. It is never taken from the command line.
// Waits while the parent process runs, then restores DNS listed in the backup file.
int runDnsWatchdog(uint32_t parentPid, uint64_t parentStarted, const std::filesystem::path& backupPath);
