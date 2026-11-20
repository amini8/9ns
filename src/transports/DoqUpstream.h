#pragma once

#include <string>
#include <vector>

#include "transports/Upstream.h"

// DNS over QUIC (RFC 9250). One bidirectional QUIC stream per query with two-byte
// length-prefixed DNS messages, like DoT but over QUIC with ALPN "doq".
class DoqUpstream : public Upstream {
public:
    explicit DoqUpstream(const UpstreamConfig& config);
    ~DoqUpstream() override;

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override;

private:
    std::string host_;
    std::string sni_;
    uint16_t port_ = 853;
    std::vector<std::string> bootstrapIps_;
    bool tlsVerify_ = true;
};
