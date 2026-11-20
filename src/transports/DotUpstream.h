#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/Config.h"
#include "transports/Upstream.h"

// DNS over TLS (RFC 7858) upstream communicating over TCP port 853 with TLS encryption.
class DotUpstream : public Upstream {
public:
    DotUpstream(std::string name, const UpstreamConfig& config);
    ~DotUpstream() override;

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override;

private:
    std::string host_;
    uint16_t port_ = 853;
    std::string sni_;
    std::vector<std::string> bootstrapIps_;
    bool tlsVerify_ = true;
};
