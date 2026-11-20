#include "transports/Stamp.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

constexpr char kPrefix[] = "sdns://";
constexpr uint8_t kProtocolDnsCrypt = 0x01;
constexpr uint8_t kProtocolDoH = 0x02;
constexpr uint8_t kProtocolDoQ = 0x04;
constexpr uint8_t kProtocolOdoh = 0x05;
constexpr uint8_t kProtocolAnonymizedRelay = 0x81;
constexpr uint8_t kProtocolOdohRelay = 0x85;
constexpr size_t kPropsBytes = 8;

// Decodes base64url with or without padding. Returns false for characters outside the alphabet
// or for a length that cannot come from valid base64.
bool decodeBase64Url(const std::string& text, std::vector<uint8_t>& out) {
    out.clear();
    size_t end = text.size();
    while (end > 0 && text[end - 1] == '=') {
        --end;
    }
    if (end % 4 == 1) {
        return false;
    }

    uint32_t bits = 0;
    unsigned bitCount = 0;
    for (size_t i = 0; i < end; ++i) {
        const char c = text[i];
        uint32_t value = 0;
        if (c >= 'A' && c <= 'Z') {
            value = static_cast<uint32_t>(c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            value = static_cast<uint32_t>(c - 'a' + 26);
        } else if (c >= '0' && c <= '9') {
            value = static_cast<uint32_t>(c - '0' + 52);
        } else if (c == '-') {
            value = 62;
        } else if (c == '_') {
            value = 63;
        } else {
            return false;
        }
        bits = (bits << 6) | value;
        bitCount += 6;
        if (bitCount >= 8) {
            bitCount -= 8;
            out.push_back(static_cast<uint8_t>(bits >> bitCount));
            bits &= (1u << bitCount) - 1;
        }
    }
    return true;
}

// Reads the fields of a stamp in order. Every read checks the remaining length first.
class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& data) : data_(data) {}

    bool skip(size_t count) {
        if (count > data_.size() - pos_) {
            return false;
        }
        pos_ += count;
        return true;
    }

    bool byte(uint8_t& out) {
        if (pos_ >= data_.size()) {
            return false;
        }
        out = data_[pos_++];
        return true;
    }

    // One length byte, then that many bytes.
    bool lengthPrefixed(std::string& out) {
        uint8_t length = 0;
        if (!byte(length) || length > data_.size() - pos_) {
            return false;
        }
        out.assign(reinterpret_cast<const char*>(data_.data() + pos_), length);
        pos_ += length;
        return true;
    }

    // Two bytes, big-endian.
    bool u16(uint16_t& out) {
        if (data_.size() - pos_ < 2) {
            return false;
        }
        out = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }

    // Hashes: each entry starts with a length byte. Bit 0x80 means another entry follows.
    bool skipHashes() {
        uint8_t length = 0;
        do {
            if (!byte(length) || !skip(static_cast<size_t>(length & 0x7F))) {
                return false;
            }
        } while ((length & 0x80) != 0);
        return true;
    }

private:
    const std::vector<uint8_t>& data_;
    size_t pos_ = 0;
};

// True if the text has no spaces, control characters or DEL.
bool printable(const std::string& text) {
    for (const char c : text) {
        const auto b = static_cast<unsigned char>(c);
        if (b <= 0x20 || b == 0x7F) {
            return false;
        }
    }
    return true;
}

// Host names and IP literals only. Rejects characters that would change the meaning of the URL.
bool validHost(const std::string& host) {
    if (host.empty()) {
        return false;
    }
    for (const char c : host) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                        c == '-' || c == ':' || c == '[' || c == ']';
        if (!ok) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool parseStamp(const std::string& text, DnsStamp& out, std::string& error) {
    const std::string prefix = kPrefix;
    if (text.size() <= prefix.size() || text.compare(0, prefix.size(), prefix) != 0) {
        error = "stamp must start with sdns://";
        return false;
    }

    std::vector<uint8_t> data;
    if (!decodeBase64Url(text.substr(prefix.size()), data) || data.empty()) {
        error = "stamp is not valid base64url";
        return false;
    }

    Reader reader(data);
    uint8_t protocol = 0;
    if (!reader.byte(protocol)) {
        error = "stamp is truncated";
        return false;
    }

    if (protocol == kProtocolAnonymizedRelay) {
        DnsStamp candidate;
        candidate.protocol = DnsStamp::Protocol::AnonymizedRelay;
        if (!reader.lengthPrefixed(candidate.address)) {
            error = "Relay stamp is truncated";
            return false;
        }
        out = candidate;
        return true;
    }

    if (!reader.skip(kPropsBytes)) {
        error = "stamp is truncated";
        return false;
    }

    if (protocol == kProtocolDnsCrypt) {
        DnsStamp candidate;
        candidate.protocol = DnsStamp::Protocol::DnsCrypt;
        std::string key;
        if (!reader.lengthPrefixed(candidate.address) || !reader.lengthPrefixed(key) ||
            !reader.lengthPrefixed(candidate.providerName)) {
            error = "DNSCrypt stamp is truncated";
            return false;
        }
        if (key.size() != candidate.publicKey.size()) {
            error = "DNSCrypt stamp public key must be 32 bytes";
            return false;
        }
        if (candidate.providerName.empty() || !printable(candidate.providerName)) {
            error = "DNSCrypt stamp has no valid provider name";
            return false;
        }
        std::memcpy(candidate.publicKey.data(), key.data(), key.size());
        out = candidate;
        return true;
    }

    if (protocol == kProtocolDoH) {
        // The address hint is ignored. The host name is used like any other DoH URL.
        std::string addressHint;
        std::string host;
        std::string path;
        if (!reader.lengthPrefixed(addressHint) || !reader.skipHashes() || !reader.lengthPrefixed(host) ||
            !reader.lengthPrefixed(path)) {
            error = "DoH stamp is truncated";
            return false;
        }
        if (!validHost(host) || path.empty() || path[0] != '/' || !printable(path)) {
            error = "DoH stamp has an invalid host name or path";
            return false;
        }
        DnsStamp candidate;
        candidate.protocol = DnsStamp::Protocol::DoH;
        candidate.url = "https://" + host + path;
        out = candidate;
        return true;
    }

    if (protocol == kProtocolDoQ) {
        // Same shape as DoH but with a port and no path.
        std::string addressHint;
        std::string host;
        DnsStamp candidate;
        candidate.protocol = DnsStamp::Protocol::DoQ;
        if (!reader.lengthPrefixed(addressHint) || !reader.skipHashes() || !reader.lengthPrefixed(host) ||
            !reader.u16(candidate.port)) {
            error = "DoQ stamp is truncated";
            return false;
        }
        if (!validHost(host)) {
            error = "DoQ stamp has an invalid host name";
            return false;
        }
        candidate.address = host;
        out = candidate;
        return true;
    }

    if (protocol == kProtocolOdoh || protocol == kProtocolOdohRelay) {
        // Host name and path only; the stamp carries no key material.
        std::string host;
        std::string path;
        if (!reader.lengthPrefixed(host) || !reader.lengthPrefixed(path)) {
            error = "ODoH stamp is truncated";
            return false;
        }
        if (!validHost(host) || path.empty() || path[0] != '/' || !printable(path)) {
            error = "ODoH stamp has an invalid host name or path";
            return false;
        }
        DnsStamp candidate;
        candidate.protocol = (protocol == kProtocolOdoh) ? DnsStamp::Protocol::Odoh : DnsStamp::Protocol::OdohRelay;
        candidate.address = host;
        candidate.url = "https://" + host + path;
        out = candidate;
        return true;
    }

    error = "stamp protocol is not supported (DNSCrypt, DoH, DoQ, ODoH or relays)";
    return false;
}
