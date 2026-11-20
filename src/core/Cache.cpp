#include "core/Cache.h"

#include <algorithm>
#include <sstream>
#include <vector>

std::string cacheKey(const std::string& target, const dns::Query& parsed,
                     const dns::QueryContext& context) {
    std::string key = target + " " + parsed.name + "/" + std::to_string(parsed.type) + "/" +
                      std::to_string(parsed.qclass);
    key += "/cd=" + std::string(context.cd ? "1" : "0");
    key += "/do=" + std::string(context.doBit ? "1" : "0");
    if (context.hasOpt) {
        std::ostringstream ss;
        ss << "/edns=" << context.ednsPayloadSize << "-" << std::hex << context.ednsOptionsHash;
        key += ss.str();
    } else {
        key += "/edns=none";
    }
    return key;
}

Cache::Cache(size_t maxEntries, uint32_t minTtl, uint32_t maxTtl, uint32_t negativeTtl)
    : maxEntries_(maxEntries), minTtl_(minTtl), maxTtl_(maxTtl), negativeTtl_(negativeTtl) {}

bool Cache::get(const std::string& key, uint16_t id, dns::Bytes& reply, CacheProvenance& provenance) {
    if (!enabled()) {
        misses_++;
        return false;
    }
    const Clock::time_point now = Clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    const auto found = entries_.find(key);
    if (found == entries_.end()) {
        misses_++;
        return false;
    }
    if (now >= found->second.expiresAt) {
        entries_.erase(found);
        misses_++;
        return false;
    }

    const Entry& entry = found->second;
    const uint32_t age = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - entry.storedAt).count());
    reply = entry.response;
    dns::setId(reply, id);

    std::vector<dns::TtlField> fields;
    if (!dns::collectTtls(reply, fields)) {
        entries_.erase(found);
        misses_++;
        return false;
    }
    for (const dns::TtlField& field : fields) {
        if (field.type == dns::kTypeOpt) {
            continue;
        }
        const uint32_t ttl = field.ttl > age ? field.ttl - age : 0;
        dns::setTtl(reply, field.offset, ttl);
    }

    provenance = entry.provenance;
    // Re-evaluate at retrieval: a signature that was valid when the reply was
    // stored may be outside its validity window now.
    provenance.status = dnssec_.validate(entry.response, entry.provenance.authenticatedTransport);
    hits_++;
    return true;
}

void Cache::put(const std::string& key, const dns::Bytes& query, const dns::Bytes& response,
                const CacheProvenance& provenance) {
    if (!enabled()) {
        return;
    }
    if (provenance.status == DnsSecStatus::Bogus) {
        return;
    }
    if (response.size() < dns::kHeaderSize || (response[2] & 0x02) != 0 || (response[2] & 0x80) == 0) {
        return;
    }
    if (!dns::isResponseFor(response, query)) {
        return;
    }
    uint8_t rcode = 0;
    if (!dns::responseCode(response, rcode) ||
        (rcode != dns::kRcodeNoError && rcode != dns::kRcodeNxDomain)) {
        return;
    }

    std::vector<dns::TtlField> fields;
    if (!dns::collectTtls(response, fields)) {
        return;
    }

    bool haveTtl = false;
    uint32_t recordTtl = 0;
    for (const dns::TtlField& field : fields) {
        if (field.type == dns::kTypeOpt) {
            continue;
        }
        recordTtl = haveTtl ? (std::min)(recordTtl, field.ttl) : field.ttl;
        haveTtl = true;
    }

    uint32_t effectiveTtl = 0;
    if (rcode == dns::kRcodeNxDomain || !haveTtl) {
        effectiveTtl = negativeTtl_;
    } else {
        effectiveTtl = recordTtl;
        if (minTtl_ > 0) {
            effectiveTtl = (std::max)(effectiveTtl, minTtl_);
        }
        if (maxTtl_ > 0) {
            effectiveTtl = (std::min)(effectiveTtl, maxTtl_);
        }
    }

    if (effectiveTtl == 0) {
        return;
    }

    const Clock::time_point now = Clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.find(key) == entries_.end() && entries_.size() >= maxEntries_) {
        evictIfFull(now);
    }
    Entry& entry = entries_[key];
    entry.response = response;
    entry.provenance = provenance;
    entry.storedAt = now;
    entry.expiresAt = now + std::chrono::seconds(effectiveTtl);
}

void Cache::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

size_t Cache::size() {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

void Cache::evictIfFull(Clock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now >= it->second.expiresAt) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    while (!entries_.empty() && entries_.size() >= maxEntries_) {
        entries_.erase(entries_.begin());
    }
}
