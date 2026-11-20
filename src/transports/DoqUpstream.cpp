#include "transports/DoqUpstream.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#include <openssl/err.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

#include "core/DnsMessage.h"
#include "core/Net.h"
#include "core/Text.h"
#include "transports/DoqFraming.h"

namespace {

constexpr size_t kAlpnDoq = 3;

void loadWindowsRootCerts(SSL_CTX* ctx) {
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
    if (!hStore) {
        return;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        CertCloseStore(hStore, 0);
        return;
    }

    PCCERT_CONTEXT pContext = nullptr;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != nullptr) {
        const unsigned char* encoded = pContext->pbCertEncoded;
        X509* x509 = d2i_X509(nullptr, &encoded, static_cast<long>(pContext->cbCertEncoded));
        if (x509) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }
    CertCloseStore(hStore, 0);
}

std::string getOpenSslError() {
    char buf[256] = {};
    const unsigned long err = ERR_get_error();
    if (err == 0) {
        return "unknown TLS error";
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

// Parses host and optional port from "host", "host:port", "[ipv6]", "[ipv6]:port"
void parseHostPort(const std::string& address, uint16_t defaultPort, std::string& outHost, uint16_t& outPort) {
    outPort = defaultPort;
    std::string text = address;
    if (text.rfind("quic://", 0) == 0) {
        text = text.substr(7);
    }
    if (!text.empty() && text.front() == '[') {
        const size_t close = text.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("invalid address: missing ']'");
        }
        outHost = text.substr(1, close - 1);
        if (close + 1 < text.size() && text[close + 1] == ':') {
            outPort = static_cast<uint16_t>(std::stoi(text.substr(close + 2)));
        }
    } else {
        const size_t colon = text.rfind(':');
        if (colon != std::string::npos && text.find(':') == colon) { // single colon
            outHost = text.substr(0, colon);
            outPort = static_cast<uint16_t>(std::stoi(text.substr(colon + 1)));
        } else {
            outHost = text;
        }
    }
}

// Resolves the server: a bootstrap IP when given, otherwise the host name.
bool resolveEndpoint(const std::string& host, uint16_t port, const std::vector<std::string>& bootstrapIps,
                     sockaddr_storage& out, int& outLen, std::string& error) {
    if (!bootstrapIps.empty()) {
        try {
            parseEndpoint(bootstrapIps.front() + ":" + std::to_string(port), port, out, outLen);
        } catch (const std::exception& e) {
            error = std::string("cannot parse bootstrap IP: ") + e.what();
            return false;
        }
        return true;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* result = nullptr;
    const std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0 || result == nullptr) {
        error = "cannot resolve '" + host + "'";
        return false;
    }
    std::memcpy(&out, result->ai_addr, result->ai_addrlen);
    outLen = static_cast<int>(result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

}  // namespace

DoqUpstream::DoqUpstream(const UpstreamConfig& config)
    : Upstream(config.name, "doq"),
      sni_(config.sni),
      bootstrapIps_(config.bootstrapIps),
      tlsVerify_(config.tlsVerify) {
    parseHostPort(config.address, config.port != 0 ? config.port : 853, host_, port_);
    if (sni_.empty()) {
        sni_ = host_;
    }
}

DoqUpstream::~DoqUpstream() = default;

bool DoqUpstream::exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) {
    if (query.size() < dns::kHeaderSize || query.size() > 0xFFFF) {
        error = "invalid query size for DoQ";
        return false;
    }

    sockaddr_storage serverAddr{};
    int addrLen = 0;
    if (!resolveEndpoint(host_, port_, bootstrapIps_, serverAddr, addrLen, error)) {
        return false;
    }
    Socket sock = openConnected(serverAddr, addrLen, SOCK_DGRAM, IPPROTO_UDP, error);
    if (!sock.valid()) {
        return false;
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
        SSL_CTX_new(OSSL_QUIC_client_thread_method()), SSL_CTX_free);
    if (!ctx) {
        error = "cannot create QUIC context: " + getOpenSslError();
        return false;
    }
    if (tlsVerify_) {
        loadWindowsRootCerts(ctx.get());
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }

    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
    if (!ssl) {
        error = "cannot create QUIC connection: " + getOpenSslError();
        return false;
    }

    BIO* bio = BIO_new_dgram(sock.get(), BIO_NOCLOSE);
    if (!bio) {
        error = "cannot create DoQ datagram BIO: " + getOpenSslError();
        return false;
    }
    SSL_set_bio(ssl.get(), bio, bio);
    SSL_set_blocking_mode(ssl.get(), 1);

    SSL_set_tlsext_host_name(ssl.get(), sni_.c_str());
    if (tlsVerify_) {
        SSL_set1_host(ssl.get(), sni_.c_str());
    }
    // ALPN "doq" in wire format (RFC 9250, section 4.1.1).
    const unsigned char alpn[] = {static_cast<unsigned char>(kAlpnDoq), 'd', 'o', 'q'};
    SSL_set_alpn_protos(ssl.get(), alpn, sizeof(alpn));

    if (SSL_connect(ssl.get()) != 1) {
        error = "DoQ handshake failed: " + getOpenSslError();
        return false;
    }

    std::unique_ptr<SSL, decltype(&SSL_free)> stream(SSL_new_stream(ssl.get(), 0), SSL_free);
    if (!stream) {
        error = "cannot open a DoQ stream: " + getOpenSslError();
        return false;
    }

    const bool ok = doq::exchangeFrame(query, response, error,
        [&stream](const uint8_t* data, size_t length, size_t& written) {
            return SSL_write_ex2(stream.get(), data, length, SSL_WRITE_FLAG_CONCLUDE, &written) == 1;
        },
        [&stream](uint8_t* data, size_t length, size_t& got) {
            return SSL_read_ex(stream.get(), data, length, &got) == 1;
        });
    stream.reset();
    if (ok) {
        SSL_shutdown(ssl.get());
    }
    return ok;
}
