#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "core/DnsMessage.h"
#include "core/DnsSec.h"

// Validation provenance of a cached reply.
struct CacheProvenance {
    // Trust of the upstream channel that produced the reply (as recorded at put()).
    bool authenticatedTransport = false;
    // put(): the status computed for the fresh reply. get(): the status re-evaluated
    // at retrieval, because a cached RRSIG may expire while the entry is still cached.
    DnsSecStatus status = DnsSecStatus::Indeterminate;
};

// Builds the reply-cache key: target, name/type/class and the query context (CD/DO
// flags, EDNS payload size and option hash), so replies never cross request contexts.
std::string cacheKey(const std::string& target, const dns::Query& parsed,
                     const dns::QueryContext& context);

// Reply cache keyed by cacheKey(). Keeps NOERROR and NXDOMAIN replies together with
// their validation provenance. Enforces minimum and maximum TTL overrides, and
// negative caching.
class Cache {
public:
    explicit Cache(size_t maxEntries, uint32_t minTtl = 0, uint32_t maxTtl = 86400, uint32_t negativeTtl = 60);

    // On a fresh hit, fills reply with the stored bytes, sets the id, reduces TTLs by
    // the age and reports the provenance. The status is re-evaluated from the stored
    // reply because signatures may expire while the entry is cached.
    bool get(const std::string& key, uint16_t id, dns::Bytes& reply, CacheProvenance& provenance);

    // Stores a NOERROR or NXDOMAIN reply that echoes the query's question.
    // Bogus replies are never stored.
    void put(const std::string& key, const dns::Bytes& query, const dns::Bytes& response,
             const CacheProvenance& provenance);

    // Clears all cached entries.
    void flush();

    size_t size();
    uint64_t hits() const { return hits_.load(); }
    uint64_t misses() const { return misses_.load(); }

private:
    bool enabled() const { return maxEntries_ > 0; }

    using Clock = std::chrono::steady_clock;

    struct Entry {
        dns::Bytes response;
        CacheProvenance provenance;
        Clock::time_point storedAt;
        Clock::time_point expiresAt;
    };

    void evictIfFull(Clock::time_point now);

    size_t maxEntries_;
    uint32_t minTtl_;
    uint32_t maxTtl_;
    uint32_t negativeTtl_;
    DnsSec dnssec_;

    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};
