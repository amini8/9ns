#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// One upstream DNS server. Type is "plain", "doh", "dot", "dnscrypt", "odoh" or "doq".
struct UpstreamConfig {
    std::string name;
    std::string type;
    std::string address;
    std::string stamp;  // optional sdns:// stamp. When set, it replaces type and address.
    uint16_t port = 0;  // 0 uses default for the protocol
    std::vector<std::string> bootstrapIps;
    std::string sni;
    bool tlsVerify = true;
    std::string proxy;  // "odoh": optional relay URL the ODoH query is sent through
};

// A server pool grouping multiple upstreams with a load balancing or redundancy strategy.
struct PoolConfig {
    std::string name;
    std::string strategy = "failover";  // "failover", "round_robin", "fastest", "random"
    std::vector<std::string> servers;
};

// One rule controlling routing based on hostname masks and actions.
struct RuleConfig {
    std::string name;
    std::vector<std::string> hostnames;  // masks like "*.example.com", "*", or domain names
    std::string pattern;                 // legacy single pattern support
    std::string action = "process";      // "process", "block", "bypass", "local"
    std::string blockMode = "nxdomain";  // "nxdomain", "null_ip", "refused", "drop"
    std::string target;                  // target upstream or pool name (for "process")
    std::string upstream;                // legacy field mapping to target
    std::string localIp;                 // static IP for "local" action
    std::string interfaceGuid;           // adapter binding; rejected by validateConfig (unsupported)
    std::string queryType;               // optional filter e.g. "A", "AAAA", "PTR"
    std::string dnssecMode = "default";  // "default", "force", "ignore"
    std::string hostsFile;               // path to local hosts file or blocklist
};

struct Config {
    uint16_t listenPort = 53;
    std::size_t cacheEntries = 4096;  // 0 turns the reply cache off
    uint32_t minTtl = 0;              // 0 keeps upstream TTL
    uint32_t maxTtl = 86400;          // cap upstream TTL to at most 1 day
    uint32_t negativeTtl = 60;        // TTL for negative/NXDOMAIN caching
    bool systemDns = false;
    bool ipv6Loopback = true;
    bool preventDnsLeaks = true;
    bool dnssecValidation = true;
    bool autostart = false;
    bool closeToTray = true;
    std::string defaultTarget;         // default upstream or pool name
    std::string defaultUpstream;       // legacy field mapping to defaultTarget
    std::vector<UpstreamConfig> upstreams;
    std::vector<PoolConfig> pools;
    std::vector<RuleConfig> rules;     // first match wins
    std::string logFile;               // file name inside the data folder; empty means no log file
    std::string logLevel = "info";     // "error", "info" or "debug"
};

// Returns standard public DNS provider presets (Cloudflare, Google, Quad9, AdGuard).
std::vector<UpstreamConfig> publicDnsPresets();

// The settings used when no config file exists yet.
Config defaultConfig();

// Reads config.json. A missing file yields defaultConfig(). Throws std::runtime_error if the file
// is not valid JSON or the values fail validateConfig().
Config loadConfig(const std::filesystem::path& path);

// Checks the values the engine depends on. Throws std::runtime_error naming the first problem.
void validateConfig(const Config& config);

// Rewrites every alias of `oldName` (default target, pool membership, rule
// targets) to `newName` in one step. Used so a server or pool rename cannot
// leave dangling references. Does not check collisions.
void renameTargetReferences(Config& config, const std::string& oldName, const std::string& newName);

// Validates, then writes the file through a temporary file so a failed write keeps the old config.
// Throws std::runtime_error on failure.
void saveConfig(const std::filesystem::path& path, const Config& config);
