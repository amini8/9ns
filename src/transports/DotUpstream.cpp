#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

#include "transports/DotUpstream.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

#include "core/DnsMessage.h"
#include "core/Net.h"
#include "core/Text.h"

namespace {

constexpr size_t kMaxDotReply = 65535;

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
    if (text.rfind("tls://", 0) == 0) {
        text = text.substr(6);
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

} // namespace

DotUpstream::DotUpstream(std::string name, const UpstreamConfig& config)
    : Upstream(std::move(name), "dot"),
      sni_(config.sni),
      bootstrapIps_(config.bootstrapIps),
      tlsVerify_(config.tlsVerify) {
    parseHostPort(config.address, config.port != 0 ? config.port : 853, host_, port_);
    if (sni_.empty()) {
        sni_ = host_;
    }
}

DotUpstream::~DotUpstream() = default;

bool DotUpstream::exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) {
    if (query.size() < dns::kHeaderSize || query.size() > 0xFFFF) {
        error = "invalid query size for DoT";
        return false;
    }
    const uint16_t id = static_cast<uint16_t>((query[0] << 8) | query[1]);

    // Choose target endpoint (bootstrap IP if provided, otherwise host)
    std::string connectTarget = host_;
    if (!bootstrapIps_.empty()) {
        connectTarget = bootstrapIps_.front();
    }

    sockaddr_storage serverAddr{};
    int addrLen = 0;
    try {
        parseEndpoint(connectTarget + ":" + std::to_string(port_), port_, serverAddr, addrLen);
    } catch (const std::exception& e) {
        error = std::string("cannot parse endpoint: ") + e.what();
        return false;
    }

    Socket sock = openConnected(serverAddr, addrLen, SOCK_STREAM, IPPROTO_TCP, error);
    if (!sock.valid()) {
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        error = "cannot create SSL_CTX: " + getOpenSslError();
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (tlsVerify_) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        loadWindowsRootCerts(ctx);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        error = "cannot create SSL instance: " + getOpenSslError();
        return false;
    }

    SSL_set_fd(ssl, static_cast<int>(sock.get()));
    if (!sni_.empty()) {
        SSL_set_tlsext_host_name(ssl, sni_.c_str());
        if (tlsVerify_) {
            SSL_set1_host(ssl, sni_.c_str());
        }
    }

    if (SSL_connect(ssl) <= 0) {
        error = "TLS handshake failed: " + getOpenSslError();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    // Framing: 2-byte length prefix
    const uint16_t lenPrefix = htons(static_cast<uint16_t>(query.size()));
    dns::Bytes framed(2 + query.size());
    std::memcpy(framed.data(), &lenPrefix, 2);
    std::memcpy(framed.data() + 2, query.data(), query.size());

    int written = 0;
    while (written < static_cast<int>(framed.size())) {
        const int n = SSL_write(ssl, framed.data() + written, static_cast<int>(framed.size()) - written);
        if (n <= 0) {
            error = "cannot write query over TLS: " + getOpenSslError();
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return false;
        }
        written += n;
    }

    // Read 2-byte reply length
    uint8_t lenBuf[2] = {};
    int readLen = 0;
    while (readLen < 2) {
        const int n = SSL_read(ssl, lenBuf + readLen, 2 - readLen);
        if (n <= 0) {
            error = "cannot read reply length over TLS: " + getOpenSslError();
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return false;
        }
        readLen += n;
    }

    const size_t replySize = (static_cast<size_t>(lenBuf[0]) << 8) | lenBuf[1];
    if (replySize < dns::kHeaderSize || replySize > kMaxDotReply) {
        error = "invalid reply length from DoT server";
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    response.resize(replySize);
    size_t totalRead = 0;
    while (totalRead < replySize) {
        const int n = SSL_read(ssl, response.data() + totalRead, static_cast<int>(replySize - totalRead));
        if (n <= 0) {
            error = "cannot read reply payload over TLS: " + getOpenSslError();
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return false;
        }
        totalRead += static_cast<size_t>(n);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    if (!dns::isResponseFor(response, id)) {
        error = "DoT reply transaction ID mismatch";
        return false;
    }

    return true;
}
