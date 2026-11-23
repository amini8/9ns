#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "core/DnsMessage.h"
#include "transports/Stamp.h"
#include "transports/Upstream.h"

// DNSCrypt v2 upstream. Queries go over UDP and fall back to TCP. Stamps must carry an IP address.
class DnsCryptUpstream : public Upstream {
public:
    DnsCryptUpstream(std::string name, const DnsStamp& stamp);

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override;

private:
    using ReplyFilter = std::function<bool(const dns::Bytes&)>;

    bool roundTripUdp(const dns::Bytes& packet, const ReplyFilter& accept, dns::Bytes& reply,
                      std::string& error) const;
    bool roundTripTcp(const dns::Bytes& packet, dns::Bytes& reply, std::string& error) const;
    bool fetchCertificate(std::string& error);
    bool acceptCertificate(const dns::Bytes& cert, std::string& error);

    // Numeric server endpoint text, for tunnelling the TCP leg through an upstream proxy.
    std::string numericServerHost() const;
    uint16_t numericServerPort() const;

    DnsStamp stamp_;
    sockaddr_storage server_{};
    int serverLength_ = 0;

    // The certificate is fetched on first use and again after it expires. Guarded by mutex_.
    std::mutex mutex_;
    bool haveCertificate_ = false;
    std::array<uint8_t, 32> resolverPk_{};
    std::array<uint8_t, 8> clientMagic_{};
    uint16_t esVersion_ = 0;
    uint64_t certificateEnd_ = 0;
};
