#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hpke.h>

#include "transports/Upstream.h"

// Immutable ODoH key configuration. A refresh builds a whole new snapshot and
// swaps it in; an exchange keeps exactly one snapshot for its entire HPKE
// exchange, so a concurrent key rotation can never change suite or key state
// mid-exchange. Published snapshots are never mutated.
struct OdohConfigSnapshot {
    OSSL_HPKE_SUITE suite{};
    std::vector<uint8_t> targetKey;
    std::vector<uint8_t> keyId;
    const EVP_CIPHER* cipher = nullptr;
    size_t keyLen = 0;
};

// Holds the published configuration snapshot and when it was fetched. The
// mutex covers only the lookup and the swap; callers hold their captured
// shared_ptr outside it and never observe a partially updated configuration.
class OdohConfigSlot {
public:
    // Returns the snapshot published within maxAge, or null when none is that
    // fresh. The returned snapshot never changes afterwards.
    std::shared_ptr<const OdohConfigSnapshot> fresh(std::chrono::milliseconds maxAge) const;
    // Swaps in a snapshot built by a refresh and stamps it as published now.
    // Publishing null forgets the configuration, as a failed refresh does.
    void publish(std::shared_ptr<const OdohConfigSnapshot> snapshot);

private:
    mutable std::mutex mutex_;
    std::shared_ptr<const OdohConfigSnapshot> snapshot_;
    std::chrono::steady_clock::time_point published_{};
};

// Oblivious DNS over HTTPS (RFC 9230). Each query is HPKE-encrypted to the target's
// public key and sent to the target directly or through an ODoH relay (proxy).
class OdohUpstream : public Upstream {
public:
    // targetUrl is the https://host/path of the ODoH target. proxyUrl is an optional
    // relay URL; queries are sent through it with the targethost/targetpath parameters.
    OdohUpstream(std::string name, const std::string& targetUrl, const std::string& proxyUrl,
                 std::vector<std::string> bootstrapIps = {});
    ~OdohUpstream() override;

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
