#include "transports/DnsCryptUpstream.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sodium.h>

#include "core/Net.h"

namespace {

constexpr uint16_t kDefaultPort = 443;
constexpr size_t kMinQueryPadded = 256;   // padded queries are at least this long
constexpr size_t kMaxUdpReply = 4096;
constexpr size_t kCertBytes = 124;        // magic 4, es-version 2, minor 2, signature 64, signed part 52
constexpr size_t kSignedOffset = 72;      // the signature covers bytes 72 to the end of the certificate
constexpr size_t kReplyHeaderBytes = 8 + crypto_box_NONCEBYTES;  // resolver magic + nonce
constexpr std::array<uint8_t, 8> kResolverMagic = {0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38};  // "r6fnvWj8"
constexpr uint16_t kTypeTxt = 16;

uint16_t readU16(const dns::Bytes& p, size_t off) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[off]) << 8) | p[off + 1]);
}

uint32_t readU32(const dns::Bytes& p, size_t off) {
    return (static_cast<uint32_t>(p[off]) << 24) | (static_cast<uint32_t>(p[off + 1]) << 16) |
           (static_cast<uint32_t>(p[off + 2]) << 8) | static_cast<uint32_t>(p[off + 3]);
}

uint64_t unixNow() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// ISO/IEC 7816-4 padding: a 0x80 byte, then zeros up to a multiple of 64 bytes (at least kMinQueryPadded).
void padQuery(dns::Bytes& packet) {
    packet.push_back(0x80);
    size_t target = (packet.size() + 63) / 64 * 64;
    target = (std::max)(target, kMinQueryPadded);
    packet.resize(target, 0);
}

// Removes the padding added by padQuery. Returns false if the padding is missing.
bool unpad(dns::Bytes& packet) {
    size_t end = packet.size();
    while (end > 0 && packet[end - 1] == 0) {
        --end;
    }
    if (end == 0 || packet[end - 1] != 0x80) {
        return false;
    }
    packet.resize(end - 1);
    return true;
}

// Skips a (possibly compressed) domain name at pos. Returns false if the name runs past the packet.
bool skipName(const dns::Bytes& p, size_t& pos) {
    for (;;) {
        if (pos >= p.size()) {
            return false;
        }
        const uint8_t len = p[pos];
        if (len == 0) {
            pos += 1;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 2 > p.size()) {
                return false;
            }
            pos += 2;
            return true;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        pos += 1 + static_cast<size_t>(len);
    }
}

// Builds a recursive TXT query for name.
dns::Bytes buildTxtQuery(const std::string& name, uint16_t id) {
    dns::Bytes packet = {static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id), 0x01, 0x00, 0x00, 0x01,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) {
            dot = name.size();
        }
        const size_t length = dot - start;
        if (length == 0 || length > 63) {
            throw std::runtime_error("invalid DNS name '" + name + "'");
        }
        packet.push_back(static_cast<uint8_t>(length));
        const std::string label = name.substr(start, length);
        packet.insert(packet.end(), label.begin(), label.end());
        start = dot + 1;
    }
    packet.push_back(0);
    packet.insert(packet.end(), {0x00, 0x10, 0x00, 0x01});  // TXT, class IN
    return packet;
}

// Finds the first TXT string in a reply that starts with the "DNSC" certificate magic.
bool findTxtCertificate(const dns::Bytes& reply, uint16_t id, dns::Bytes& cert) {
    if (reply.size() < dns::kHeaderSize || !dns::isResponseFor(reply, id)) {
        return false;
    }
    uint8_t rcode = 0;
    if (!dns::responseCode(reply, rcode) || rcode != dns::kRcodeNoError) {
        return false;
    }
    const size_t questions = readU16(reply, 4);
    const size_t answers = readU16(reply, 6);
    size_t pos = dns::kHeaderSize;
    for (size_t i = 0; i < questions; ++i) {
        if (!skipName(reply, pos) || pos + 4 > reply.size()) {
            return false;
        }
        pos += 4;
    }
    for (size_t i = 0; i < answers; ++i) {
        if (!skipName(reply, pos) || pos + 10 > reply.size()) {
            return false;
        }
        const uint16_t type = readU16(reply, pos);
        const size_t length = readU16(reply, pos + 8);
        pos += 10;
        if (pos + length > reply.size()) {
            return false;
        }
        if (type == kTypeTxt) {
            size_t offset = pos;
            const size_t end = pos + length;
            while (offset < end) {
                const size_t textLength = reply[offset];
                if (offset + 1 + textLength > end) {
                    break;
                }
                if (textLength >= kCertBytes && std::memcmp(&reply[offset + 1], "DNSC", 4) == 0) {
                    cert.assign(reply.begin() + static_cast<std::ptrdiff_t>(offset + 1),
                                reply.begin() + static_cast<std::ptrdiff_t>(offset + 1 + textLength));
                    return true;
                }
                offset += 1 + textLength;
            }
        }
        pos += length;
    }
    return false;
}

}  // namespace

DnsCryptUpstream::DnsCryptUpstream(std::string name, const DnsStamp& stamp)
    : Upstream(std::move(name), "dnscrypt"), stamp_(stamp) {
    if (stamp_.address.empty()) {
        throw std::runtime_error("upstream '" + this->name() + "': DNSCrypt stamps without an address are not supported");
    }
    if (stamp_.providerName.empty()) {
        throw std::runtime_error("upstream '" + this->name() + "': DNSCrypt stamp has no provider name");
    }
    buildTxtQuery(stamp_.providerName, 0);  // throws if the provider name is not a valid DNS name
    parseEndpoint(stamp_.address, kDefaultPort, server_, serverLength_);
}

bool DnsCryptUpstream::exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) {
    if (query.size() < dns::kHeaderSize) {
        error = "query is too short";
        return false;
    }
    if (sodium_init() < 0) {
        error = "libsodium failed to initialize";
        return false;
    }
    const uint16_t id = readU16(query, 0);

    std::array<uint8_t, 32> resolverPk{};
    std::array<uint8_t, 8> clientMagic{};
    uint16_t esVersion = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!haveCertificate_ || unixNow() > certificateEnd_) {
            haveCertificate_ = false;
            if (!fetchCertificate(error)) {
                return false;
            }
        }
        resolverPk = resolverPk_;
        clientMagic = clientMagic_;
        esVersion = esVersion_;
    }

    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> clientPk{};
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> clientSk{};
    crypto_box_keypair(clientPk.data(), clientSk.data());

    std::array<uint8_t, 12> clientNonce{};
    randombytes_buf(clientNonce.data(), clientNonce.size());
    std::array<uint8_t, crypto_box_NONCEBYTES> nonce{};  // the 12 client bytes followed by zeros
    std::copy(clientNonce.begin(), clientNonce.end(), nonce.begin());

    std::array<uint8_t, crypto_box_BEFORENMBYTES> key{};
    dns::Bytes padded = query;
    padQuery(padded);
    dns::Bytes cipher(padded.size() + crypto_box_MACBYTES);
    int rc = 0;
    if (esVersion == 2) {
        rc = crypto_box_curve25519xchacha20poly1305_beforenm(key.data(), resolverPk.data(), clientSk.data());
        if (rc == 0) {
            rc = crypto_box_curve25519xchacha20poly1305_easy_afternm(cipher.data(), padded.data(), padded.size(),
                                                                     nonce.data(), key.data());
        }
    } else {
        rc = crypto_box_beforenm(key.data(), resolverPk.data(), clientSk.data());
        if (rc == 0) {
            rc = crypto_box_easy_afternm(cipher.data(), padded.data(), padded.size(), nonce.data(), key.data());
        }
    }
    if (rc != 0) {
        error = "cannot encrypt the DNSCrypt query";
        return false;
    }

    dns::Bytes packet;
    packet.reserve(clientMagic.size() + clientPk.size() + clientNonce.size() + cipher.size());
    packet.insert(packet.end(), clientMagic.begin(), clientMagic.end());
    packet.insert(packet.end(), clientPk.begin(), clientPk.end());
    packet.insert(packet.end(), clientNonce.begin(), clientNonce.end());
    packet.insert(packet.end(), cipher.begin(), cipher.end());

    const auto looksLikeReply = [&clientNonce](const dns::Bytes& p) {
        return p.size() >= kReplyHeaderBytes + crypto_box_MACBYTES &&
               std::equal(kResolverMagic.begin(), kResolverMagic.end(), p.begin()) &&
               std::equal(clientNonce.begin(), clientNonce.end(), p.begin() + 8);
    };

    // Opens a reply and checks its padding. Only the reply nonce and ciphertext are used.
    const auto openReply = [&](const dns::Bytes& reply, dns::Bytes& plain, std::string& why) -> bool {
        if (!looksLikeReply(reply)) {
            why = "DNSCrypt reply does not match the query";
            return false;
        }
        std::array<uint8_t, crypto_box_NONCEBYTES> replyNonce{};
        std::copy(reply.begin() + 8, reply.begin() + static_cast<std::ptrdiff_t>(kReplyHeaderBytes),
                  replyNonce.begin());
        const size_t cipherLength = reply.size() - kReplyHeaderBytes;
        dns::Bytes opened(cipherLength - crypto_box_MACBYTES);
        const unsigned char* ciphertext = reply.data() + kReplyHeaderBytes;
        int status = 0;
        if (esVersion == 2) {
            status = crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
                opened.data(), ciphertext, cipherLength, replyNonce.data(), key.data());
        } else {
            status = crypto_box_open_easy_afternm(opened.data(), ciphertext, cipherLength, replyNonce.data(),
                                                  key.data());
        }
        if (status != 0) {
            why = "cannot decrypt the DNSCrypt reply";
            return false;
        }
        if (!unpad(opened)) {
            why = "DNSCrypt reply has bad padding";
            return false;
        }
        plain = std::move(opened);
        return true;
    };

    dns::Bytes reply;
    dns::Bytes plain;
    bool overTcp = false;
    if (!roundTripUdp(packet, looksLikeReply, reply, error)) {
        overTcp = true;
        if (!roundTripTcp(packet, reply, error)) {
            return false;
        }
    }
    if (!openReply(reply, plain, error)) {
        return false;
    }
    // A truncated UDP answer is asked again over TCP, as with plain DNS.
    if (!overTcp && plain.size() >= dns::kHeaderSize && (plain[2] & 0x02) != 0) {
        if (!roundTripTcp(packet, reply, error) || !openReply(reply, plain, error)) {
            return false;
        }
    }

    if (plain.size() < dns::kHeaderSize || !dns::isResponseFor(plain, id)) {
        error = "DNSCrypt reply does not match the query id";
        return false;
    }
    response = std::move(plain);
    return true;
}

bool DnsCryptUpstream::roundTripUdp(const dns::Bytes& packet, const ReplyFilter& accept, dns::Bytes& reply,
                                    std::string& error) const {
    Socket udp = openConnected(server_, serverLength_, SOCK_DGRAM, IPPROTO_UDP, error);
    if (!udp.valid()) {
        return false;
    }
    const int size = static_cast<int>(packet.size());
    if (::send(udp.get(), reinterpret_cast<const char*>(packet.data()), size, 0) != size) {
        error = "cannot send to DNSCrypt server (error " + std::to_string(WSAGetLastError()) + ")";
        return false;
    }

    // Packets that fail the filter are dropped, and reading continues until the deadline.
    const NetClock::time_point deadline = NetClock::now() + kNetTimeout;
    std::vector<char> buffer(kMaxUdpReply);
    for (;;) {
        if (NetClock::now() >= deadline) {
            error = "no valid reply from DNSCrypt server before the timeout";
            return false;
        }
        setReceiveDeadline(udp.get(), deadline);
        const int received = ::recv(udp.get(), buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received <= 0) {
            error = "no reply from DNSCrypt server (error " + std::to_string(WSAGetLastError()) + ")";
            return false;
        }
        reply.assign(buffer.begin(), buffer.begin() + received);
        if (accept(reply)) {
            return true;
        }
    }
}

bool DnsCryptUpstream::roundTripTcp(const dns::Bytes& packet, dns::Bytes& reply, std::string& error) const {
    if (packet.size() > 0xFFFF) {
        error = "message is too large for TCP";
        return false;
    }
    Socket tcp = openConnected(server_, serverLength_, SOCK_STREAM, IPPROTO_TCP, error);
    if (!tcp.valid()) {
        return false;
    }
    dns::Bytes framed = {static_cast<uint8_t>(packet.size() >> 8), static_cast<uint8_t>(packet.size())};
    framed.insert(framed.end(), packet.begin(), packet.end());
    if (!sendAll(tcp.get(), framed.data(), framed.size())) {
        error = "cannot send to DNSCrypt server over TCP";
        return false;
    }

    uint8_t prefix[2] = {};
    if (!recvAll(tcp.get(), prefix, sizeof(prefix))) {
        error = "no reply from DNSCrypt server over TCP";
        return false;
    }
    const size_t length = (static_cast<size_t>(prefix[0]) << 8) | prefix[1];
    if (length == 0) {
        error = "empty reply from DNSCrypt server over TCP";
        return false;
    }
    reply.resize(length);
    if (!recvAll(tcp.get(), reply.data(), length)) {
        error = "incomplete reply from DNSCrypt server over TCP";
        return false;
    }
    return true;
}

// Caller must hold mutex_.
bool DnsCryptUpstream::fetchCertificate(std::string& error) {
    uint16_t id = 0;
    randombytes_buf(&id, sizeof(id));
    const dns::Bytes query = buildTxtQuery(stamp_.providerName, id);
    const auto matchesId = [id](const dns::Bytes& p) { return dns::isResponseFor(p, id); };

    for (const bool overTcp : {false, true}) {
        dns::Bytes reply;
        dns::Bytes cert;
        std::string why;
        const bool received = overTcp ? roundTripTcp(query, reply, why)
                                      : roundTripUdp(query, matchesId, reply, why);
        if (!received) {
            error = why;
            continue;
        }
        if (!findTxtCertificate(reply, id, cert)) {
            error = "no DNSCrypt certificate in the reply from the server";
            continue;
        }
        if (acceptCertificate(cert, error)) {
            return true;
        }
    }
    return false;
}

// Caller must hold mutex_. Verifies the certificate signature and validity window, then stores its keys.
bool DnsCryptUpstream::acceptCertificate(const dns::Bytes& cert, std::string& error) {
    if (cert.size() < kCertBytes || std::memcmp(cert.data(), "DNSC", 4) != 0) {
        error = "malformed DNSCrypt certificate";
        return false;
    }
    const uint16_t esVersion = readU16(cert, 4);
    if (esVersion != 1 && esVersion != 2) {
        error = "unsupported DNSCrypt encryption version";
        return false;
    }
    if (crypto_sign_verify_detached(cert.data() + 8, cert.data() + kSignedOffset, kCertBytes - kSignedOffset,
                                    stamp_.publicKey.data()) != 0) {
        error = "DNSCrypt certificate signature is invalid";
        return false;
    }
    const uint64_t start = readU32(cert, 116);
    const uint64_t end = readU32(cert, 120);
    const uint64_t now = unixNow();
    if (now < start || now > end) {
        error = "DNSCrypt certificate is not valid at this time";
        return false;
    }

    std::copy(cert.begin() + 72, cert.begin() + 104, resolverPk_.begin());
    std::copy(cert.begin() + 104, cert.begin() + 112, clientMagic_.begin());
    esVersion_ = esVersion;
    certificateEnd_ = end;
    haveCertificate_ = true;
    return true;
}
