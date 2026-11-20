#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/DnsMessage.h"
#include "transports/Upstream.h"

// A DNS Server Pool that balances or fails over queries among a group of upstreams.
class Pool {
public:
    Pool(std::string name, std::string strategy, std::vector<Upstream*> upstreams);
    ~Pool();

    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;

    // Dispatches query according to strategy. usedUpstream receives the name of the server that answered.
    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream);

private:
    bool exchangeFailover(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream);
    bool exchangeRoundRobin(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream);
    bool exchangeFastest(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream);
    bool exchangeRandom(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream);

    void refreshLatencies();

    std::string allServersFailedError(const std::string& lastError) const;

    std::string name_;
    std::string strategy_;
    std::vector<Upstream*> upstreams_;

    std::atomic<size_t> counter_{0};

    std::mutex latencyMutex_;
    std::unordered_map<std::string, uint32_t> latencies_;
    std::chrono::steady_clock::time_point lastLatencyCheck_{};
};
