#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "core/Cache.h"
#include "core/Config.h"
#include "core/DnsMessage.h"
#include "core/DnsSec.h"
#include "core/Logger.h"
#include "core/Pool.h"
#include "core/Rules.h"
#include "transports/Upstream.h"

// Structured event emitted for each query resolution.
struct ResolveEvent {
    std::string clientIp;
    std::string queryName;
    uint16_t queryType = 0;
    std::string action;       // "Resolved", "Cached", "Blocked", "Local", "Error", "Bogus"
    std::string target;       // target name (Server or Pool)
    std::string usedServer;   // specific server name that replied
    uint8_t rcode = 0;
    uint32_t latencyMs = 0;
    DnsSecStatus dnssec = DnsSecStatus::Indeterminate;  // upstream-validation status
    dns::Bytes query;
    dns::Bytes response;
};

// Answers one DNS query. Coordinates Rules, Pools, Upstreams, Reply Cache, and DNSSEC Validation.
class Resolver {
public:
    using EventSink = std::function<void(const ResolveEvent&)>;

    Resolver(const Config& config, Logger& logger);
    ~Resolver();

    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // Resolves a query and emits a structured event.
    dns::Bytes resolve(const dns::Bytes& query, const dns::Query& parsed, const std::string& clientIp = "127.0.0.1");

    void setEventSink(EventSink sink);
    Cache& cache() { return cache_; }

private:
    Logger& logger_;
    Config config_;
    Rules rules_;
    Cache cache_;
    DnsSec dnssec_;
    std::unordered_map<std::string, std::unique_ptr<Upstream>> upstreams_;
    std::unordered_map<std::string, std::unique_ptr<Pool>> pools_;
    std::string defaultTarget_;

    std::mutex sinkMutex_;
    EventSink eventSink_;
};
