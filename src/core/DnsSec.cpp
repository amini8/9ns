#include "core/DnsSec.h"

#include <chrono>
#include <cstdint>

namespace {

uint32_t readU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint64_t currentUnixTime() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

} // namespace

std::string dnsSecStatusToString(DnsSecStatus status) {
    switch (status) {
        case DnsSecStatus::Secure: return "Secure";
        case DnsSecStatus::Insecure: return "Insecure";
        case DnsSecStatus::Bogus: return "Bogus";
        case DnsSecStatus::Indeterminate: return "Indeterminate";
        default: return "Unknown";
    }
}

DnsSec::DnsSec() = default;
DnsSec::~DnsSec() = default;

DnsSecStatus DnsSec::validate(const dns::Bytes& response, bool authenticatedUpstream) const {
    if (response.size() < dns::kHeaderSize) {
        return DnsSecStatus::Indeterminate;
    }

    uint8_t rcode = 0;
    if (dns::responseCode(response, rcode) && rcode == dns::kRcodeServFail) {
        // SERVFAIL returned by upstream on DNSSEC failure
        return DnsSecStatus::Bogus;
    }

    dns::ParsedMessage msg;
    if (!dns::parseMessage(response, msg)) {
        return dns::hasAdBit(response) && authenticatedUpstream ? DnsSecStatus::Secure
                                                                : DnsSecStatus::Indeterminate;
    }

    // Signature timestamps are the only local evidence inspected. A signature
    // outside its validity window is Bogus; mere presence proves nothing and
    // never yields Secure (no chain or signature verification is performed).
    bool hasRrsig = false;
    bool outsideWindow = false;
    const uint64_t now = currentUnixTime();

    auto scanSignatures = [&](const std::vector<dns::Record>& records) {
        for (const dns::Record& r : records) {
            if (r.type != dns::kTypeRrsig || r.rdata.size() < 18) {
                continue;
            }
            hasRrsig = true;
            const uint32_t expiration = readU32(r.rdata.data() + 8);
            const uint32_t inception = readU32(r.rdata.data() + 12);
            if (now > expiration || now < inception) {
                outsideWindow = true;
            }
        }
    };
    scanSignatures(msg.answers);
    scanSignatures(msg.authorities);
    if (outsideWindow) {
        return DnsSecStatus::Bogus;
    }

    if (msg.ad) {
        // Authenticated upstream validation: the AD bit counts as Secure only
        // when the channel authenticates the upstream that set it.
        return authenticatedUpstream ? DnsSecStatus::Secure : DnsSecStatus::Indeterminate;
    }

    return hasRrsig ? DnsSecStatus::Indeterminate : DnsSecStatus::Insecure;
}
