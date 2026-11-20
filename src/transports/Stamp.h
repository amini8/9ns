#pragma once

#include <array>
#include <cstdint>
#include <string>

// A parsed DNS stamp (sdns://...). Supported protocols: DNSCrypt (0x01), DoH (0x02),
// DoQ (0x04), ODoH (0x05), Anonymized Relay (0x81) and ODoH Relay (0x85).
struct DnsStamp {
    enum class Protocol { DnsCrypt, DoH, DoQ, Odoh, AnonymizedRelay, OdohRelay };

    Protocol protocol = Protocol::DnsCrypt;
    std::string address;                  // DNSCrypt / Relay / DoQ: host name, "ip", "ip:port", "[ipv6]" or "[ipv6]:port"; may be empty
    std::array<uint8_t, 32> publicKey{};  // DNSCrypt: the provider's Ed25519 public key
    std::string providerName;             // DNSCrypt: name that serves the certificate
    std::string url;                      // DoH / ODoH / ODoH Relay: https://host[:port]/path
    uint16_t port = 0;                    // DoQ: server port (0 means the protocol default)
};

// Parses an sdns:// stamp. Returns false and sets error for malformed input or an unsupported protocol.
bool parseStamp(const std::string& text, DnsStamp& out, std::string& error);
