#include "core/Net.h"

#include <winhttp.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "transports/DnsCryptUpstream.h"
#include "core/DnsMessage.h"
#include "transports/DoqUpstream.h"
#include "transports/DotUpstream.h"
#include "transports/OdohUpstream.h"
#include "transports/ProxyTunnel.h"
#include "transports/Stamp.h"
#include "core/Text.h"
#include "transports/Upstream.h"

#pragma comment(lib, "winhttp.lib")

namespace {

constexpr uint16_t kPlainPort = 53;
constexpr size_t kMaxUdpReply = 4096;
constexpr size_t kMaxDohReply = 65535;
constexpr int kDohTimeoutMs = 3000;

#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 133
#define WINHTTP_PROTOCOL_FLAG_HTTP2 0x1
#endif

#ifndef WINHTTP_OPTION_RESOLUTION_HOSTNAME
#define WINHTTP_OPTION_RESOLUTION_HOSTNAME 165
#endif

// Closes a WinHTTP handle on destruction.
class WinHttpHandle {
public:
    explicit WinHttpHandle(HINTERNET handle) : handle_(handle) {}
    WinHttpHandle(WinHttpHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                WinHttpCloseHandle(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }
    ~WinHttpHandle() {
        if (handle_) {
            WinHttpCloseHandle(handle_);
        }
    }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    HINTERNET get() const { return handle_; }

private:
    HINTERNET handle_;
};

// Plain DNS. Queries go over UDP. A truncated reply is asked again over TCP.
class PlainUpstream : public Upstream {
public:
    PlainUpstream(std::string name, const std::string& address)
        : Upstream(std::move(name), "plain") {
        parseEndpoint(address, kPlainPort, server_, length_);
    }

    // The numeric address text and port, for tunnelling through an upstream proxy.
    std::string numericHost() const {
        char host[NI_MAXHOST] = {};
        return getnameinfo(reinterpret_cast<const sockaddr*>(&server_), length_, host, sizeof(host), nullptr, 0,
                           NI_NUMERICHOST) == 0
                   ? std::string(host)
                   : std::string();
    }
    uint16_t serverPort() const {
        char service[16] = {};
        if (getnameinfo(reinterpret_cast<const sockaddr*>(&server_), length_, nullptr, 0, service,
                        sizeof(service), NI_NUMERICSERV) != 0)
            return kPlainPort;
        return static_cast<uint16_t>(std::atoi(service));
    }

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override {
        if (query.size() < dns::kHeaderSize) {
            error = "query is too short";
            return false;
        }
        if (!udpExchange(query, response, error)) {
            return false;
        }
        if ((response[2] & 0x02) != 0) {
            return tcpExchange(query, response, error);
        }
        return true;
    }

private:
    bool udpExchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) const {
        Socket sock = openConnected(server_, length_, SOCK_DGRAM, IPPROTO_UDP, error);
        if (!sock.valid()) {
            return false;
        }
        const int size = static_cast<int>(query.size());
        if (::send(sock.get(), reinterpret_cast<const char*>(query.data()), size, 0) != size) {
            error = "cannot send query over UDP (error " + std::to_string(WSAGetLastError()) + ")";
            return false;
        }

        const NetClock::time_point deadline = NetClock::now() + kNetTimeout;
        std::vector<char> buffer(kMaxUdpReply);
        for (;;) {
            if (NetClock::now() >= deadline) {
                error = "no reply before the timeout";
                return false;
            }
            setReceiveDeadline(sock.get(), deadline);
            const int received = ::recv(sock.get(), buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received <= 0) {
                error = "no reply (error " + std::to_string(WSAGetLastError()) + ")";
                return false;
            }
            response.assign(buffer.begin(), buffer.begin() + received);
            // Packets that do not echo the query are stray and skipped.
            if (dns::isResponseFor(response, query)) {
                return true;
            }
        }
    }

    bool tcpExchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) const {
        if (query.size() > 0xFFFF) {
            error = "query is too large for TCP";
            return false;
        }
        // A configured upstream proxy is applied here and never bypassed: falling back to a
        // direct connection would leak the query around the corporate proxy.
        Socket sock = upstreamProxy().enabled
            ? openProxyTunnel(upstreamProxy(), numericHost(), serverPort(), error)
            : openConnected(server_, length_, SOCK_STREAM, IPPROTO_TCP, error);
        if (!sock.valid()) {
            return false;
        }
        dns::Bytes framed = {static_cast<uint8_t>(query.size() >> 8), static_cast<uint8_t>(query.size())};
        framed.insert(framed.end(), query.begin(), query.end());
        if (!sendAll(sock.get(), framed.data(), framed.size())) {
            error = "cannot send query over TCP";
            return false;
        }

        uint8_t prefix[2] = {};
        if (!recvAll(sock.get(), prefix, sizeof(prefix))) {
            error = "no reply over TCP";
            return false;
        }
        const size_t length = (static_cast<size_t>(prefix[0]) << 8) | prefix[1];
        if (length < dns::kHeaderSize) {
            error = "TCP reply is too short";
            return false;
        }
        response.resize(length);
        if (!recvAll(sock.get(), response.data(), length)) {
            error = "TCP reply is incomplete";
            return false;
        }
        if (!dns::isResponseFor(response, query)) {
            error = "TCP reply does not match the query";
            return false;
        }
        return true;
    }

    sockaddr_storage server_{};
    int length_ = 0;
};

// DNS over HTTPS (RFC 8484) with POST. Supports bootstrap IPs and HTTP/2.
class DohUpstream : public Upstream {
public:
    DohUpstream(std::string name, const std::string& url, std::vector<std::string> bootstrapIps = {})
        : Upstream(std::move(name), "doh"), bootstrapIps_(std::move(bootstrapIps)) {
        parseUrl(url);
    }

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override {
        std::wstring proxyName;
        const bool proxied = winHttpProxyName(upstreamProxy(), 8080, proxyName, error);
        // A configured proxy that WinHTTP cannot use must fail, never fall back to direct.
        if (upstreamProxy().enabled && !proxied) return false;
        WinHttpHandle session(WinHttpOpen(L"9NS/1.0",
                                          proxied ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_NO_PROXY,
                                          proxied ? proxyName.c_str() : WINHTTP_NO_PROXY_NAME,
                                          WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session.get()) {
            error = "cannot open HTTP session (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        WinHttpSetTimeouts(session.get(), kDohTimeoutMs, kDohTimeoutMs, kDohTimeoutMs, kDohTimeoutMs);

        WinHttpHandle conn(WinHttpConnect(session.get(), host_.c_str(), port_, 0));
        if (!conn.get()) {
            error = "cannot connect to DoH server (error " + std::to_string(GetLastError()) + ")";
            return false;
        }

        WinHttpHandle request(WinHttpOpenRequest(conn.get(), L"POST", path_.c_str(), nullptr,
                                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                 WINHTTP_FLAG_SECURE));
        if (!request.get()) {
            error = "cannot open DoH request (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        if (proxied) applyWinHttpCredentials(request.get(), upstreamProxy());
        // Behind a proxy WinHTTP resolves the proxy, not the DoH host, so bootstrap pinning
        // would conflict with the tunnel and is skipped.
        if (!bootstrapIps_.empty() && !proxied) {
            const std::wstring bootstrap = widen(bootstrapIps_.front());
            // Resolve the bootstrap IP while TLS identity stays host_: SNI and
            // certificate verification name the URL host, not the address literal.
            const bool resolutionOverridden =
                WinHttpSetOption(request.get(), WINHTTP_OPTION_RESOLUTION_HOSTNAME,
                                 const_cast<wchar_t*>(bootstrap.c_str()),
                                 static_cast<DWORD>((bootstrap.size() + 1) * sizeof(wchar_t))) != FALSE;
            if (!resolutionOverridden) {
                // WINHTTP_OPTION_RESOLUTION_HOSTNAME needs Windows 10 21H1+. On older
                // systems fall back to connecting to the IP literal: TLS verification
                // then names the address and fails closed unless its certificate
                // covers it. Certificate verification is never disabled.
                WinHttpHandle ipConn(WinHttpConnect(session.get(), bootstrap.c_str(), port_, 0));
                if (!ipConn.get()) {
                    error = "cannot connect to DoH server (error " + std::to_string(GetLastError()) + ")";
                    return false;
                }
                WinHttpHandle ipRequest(WinHttpOpenRequest(ipConn.get(), L"POST", path_.c_str(), nullptr,
                                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                           WINHTTP_FLAG_SECURE));
                if (!ipRequest.get()) {
                    error = "cannot open DoH request (error " + std::to_string(GetLastError()) + ")";
                    return false;
                }
                conn = std::move(ipConn);
                request = std::move(ipRequest);
            }
        }

        DWORD http2Flag = WINHTTP_PROTOCOL_FLAG_HTTP2;
        WinHttpSetOption(request.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http2Flag, sizeof(http2Flag));

        std::wstring headers = L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\nHost: " + host_ + L"\r\n";
        const DWORD size = static_cast<DWORD>(query.size());
        if (!WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(-1L),
                                const_cast<uint8_t*>(query.data()), size, size, 0)) {
            error = "cannot send DoH request (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        if (!WinHttpReceiveResponse(request.get(), nullptr)) {
            error = "no DoH reply (error " + std::to_string(GetLastError()) + ")";
            return false;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX) ||
            status != 200) {
            error = "DoH server replied with HTTP status " + std::to_string(status);
            return false;
        }

        response.clear();
        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request.get(), &available)) {
                error = "cannot read DoH reply (error " + std::to_string(GetLastError()) + ")";
                return false;
            }
            if (available == 0) {
                break;
            }
            if (response.size() + available > kMaxDohReply) {
                error = "DoH reply is too large";
                return false;
            }
            const size_t offset = response.size();
            response.resize(offset + available);
            DWORD read = 0;
            if (!WinHttpReadData(request.get(), response.data() + offset, available, &read)) {
                error = "cannot read DoH reply data (error " + std::to_string(GetLastError()) + ")";
                return false;
            }
            response.resize(offset + read);
        }

        if (response.size() < dns::kHeaderSize) {
            error = "DoH reply is too short";
            return false;
        }
        if (!dns::isResponseFor(response, query)) {
            error = "DoH reply does not match the query";
            return false;
        }
        return true;
    }

private:
    void parseUrl(const std::string& url) {
        const std::wstring wide = widen(url);
        URL_COMPONENTS parts{};
        parts.dwStructSize = sizeof(parts);
        parts.dwSchemeLength = static_cast<DWORD>(-1);
        parts.dwHostNameLength = static_cast<DWORD>(-1);
        parts.dwUrlPathLength = static_cast<DWORD>(-1);
        parts.dwExtraInfoLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts)) {
            throw std::runtime_error("DoH address '" + url + "' is not a valid URL");
        }
        if (parts.nScheme != INTERNET_SCHEME_HTTPS) {
            throw std::runtime_error("DoH address '" + url + "' must use https");
        }
        host_.assign(parts.lpszHostName, parts.dwHostNameLength);
        port_ = parts.nPort;
        if (parts.dwUrlPathLength > 0) {
            path_.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
        }
        if (parts.dwExtraInfoLength > 0) {
            path_.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
        }
        if (path_.empty()) {
            path_ = L"/";
        }
    }

    std::wstring host_;
    std::wstring path_;
    INTERNET_PORT port_ = 443;
    std::vector<std::string> bootstrapIps_;
};

}  // namespace

bool Upstream::ping(uint32_t& rttMs, std::string& error) {
    // DNS query for "example.com" A record (IN class)
    dns::Bytes probe = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    dns::Bytes reply;
    const auto start = std::chrono::steady_clock::now();
    if (!exchange(probe, reply, error)) {
        return false;
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    rttMs = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    return true;
}

namespace {

std::unique_ptr<Upstream> makeUpstream(const UpstreamConfig& config) {
    // The NextDNS protocol was removed. Reject it before stamp expansion so a
    // stamp cannot silently resurrect the removed provider.
    if (config.type == "nextdns") {
        throw std::runtime_error("upstream '" + config.name +
                                 "': the NextDNS protocol was removed from 9NS; choose and "
                                 "configure a supported replacement upstream (plain, doh, dot, "
                                 "dnscrypt, odoh or doq)");
    }
    if (!config.stamp.empty()) {
        DnsStamp stamp;
        std::string error;
        if (!parseStamp(config.stamp, stamp, error)) {
            throw std::runtime_error("upstream '" + config.name + "': " + error);
        }
        if (stamp.protocol == DnsStamp::Protocol::DoH) {
            UpstreamConfig resolved = config;
            resolved.type = "doh";
            resolved.address = stamp.url;
            resolved.stamp.clear();
            return makeUpstream(resolved);
        }
        if (stamp.protocol == DnsStamp::Protocol::Odoh) {
            UpstreamConfig resolved = config;
            resolved.type = "odoh";
            resolved.address = stamp.url;
            resolved.stamp.clear();
            return makeUpstream(resolved);
        }
        if (stamp.protocol == DnsStamp::Protocol::OdohRelay) {
            throw std::runtime_error("upstream '" + config.name +
                                     "': an ODoH relay stamp goes into the proxy field of an odoh upstream");
        }
        if (stamp.protocol == DnsStamp::Protocol::DoQ) {
            UpstreamConfig resolved = config;
            resolved.type = "doq";
            resolved.address = stamp.address;
            resolved.port = stamp.port;
            resolved.stamp.clear();
            return makeUpstream(resolved);
        }
        return std::make_unique<DnsCryptUpstream>(config.name, stamp);
    }
    if (config.type == "dot") {
        return std::make_unique<DotUpstream>(config.name, config);
    }
    if (config.type == "plain") {
        return std::make_unique<PlainUpstream>(config.name, config.address);
    }
    if (config.type == "doh") {
        return std::make_unique<DohUpstream>(config.name, config.address, config.bootstrapIps);
    }
    if (config.type == "odoh") {
        return std::make_unique<OdohUpstream>(config.name, config.address, config.proxy, config.bootstrapIps);
    }
    if (config.type == "doq") {
        return std::make_unique<DoqUpstream>(config);
    }
    throw std::runtime_error("upstream '" + config.name + "': unknown type '" + config.type + "'");
}

}  // namespace

std::unique_ptr<Upstream> Upstream::create(const UpstreamConfig& config,
                                           const UpstreamProxyConfig& proxy) {
    std::unique_ptr<Upstream> upstream = makeUpstream(config);
    upstream->setUpstreamProxy(proxy);
    // Channel trust is a property of the resolved transport plus its tls_verify
    // setting; encryption alone never authenticates an upstream.
    upstream->setAuthenticated(isAuthenticatedChannel(upstream->type(), config.tlsVerify));
    return upstream;
}
