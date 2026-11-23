#include "transports/ProxyTunnel.h"

#include <algorithm>
#include <array>
#include <vector>

#include <winhttp.h>

#include "core/ProxyProtocol.h"
#include "core/Text.h"

namespace {

// Reads until the parser reports Done, Malformed, or the deadline passes.
template <typename T, typename Parser>
proxyproto::Stage negotiate(SOCKET socket, proxyproto::Bytes& buffer, T& output, Parser parser) {
    const auto deadline = NetClock::now() + kNetTimeout;
    while (NetClock::now() < deadline) {
        size_t consumed = 0;
        const auto stage = parser(buffer, output, consumed);
        if (stage == proxyproto::Stage::Done) {
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
            return stage;
        }
        if (stage == proxyproto::Stage::Malformed) return stage;
        if (buffer.size() >= proxyproto::kMaxHandshakeSize) return proxyproto::Stage::Malformed;
        std::array<uint8_t, 1024> chunk{};
        setReceiveDeadline(socket, deadline);
        const int count = recv(socket, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
        if (count <= 0) return proxyproto::Stage::Malformed;
        buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + count);
    }
    return proxyproto::Stage::NeedMore;
}

bool sendBytes(SOCKET socket, const proxyproto::Bytes& bytes) {
    setReceiveDeadline(socket, NetClock::now() + kNetTimeout);
    return sendAll(socket, bytes.data(), bytes.size());
}

bool socks5Tunnel(SOCKET socket, const UpstreamProxyConfig& proxy, const proxyproto::Target& target) {
    const bool authenticating = !proxy.username.empty();
    proxyproto::Bytes buffer = proxyproto::makeSocks5Greeting(authenticating ? proxyproto::Bytes{0, 2}
                                                                           : proxyproto::Bytes{0});
    if (!sendBytes(socket, buffer)) return false;

    buffer.clear();
    uint8_t method = 0xFF;
    if (negotiate(socket, buffer, method, proxyproto::parseSocks5MethodChoice) != proxyproto::Stage::Done)
        return false;
    if (authenticating) {
        if (method != 2) return false;
        const proxyproto::Socks5Auth credentials{proxy.username, proxy.password};
        if (!sendBytes(socket, proxyproto::makeSocks5Auth(credentials))) return false;
        buffer.clear();
        uint8_t status = 0;
        if (negotiate(socket, buffer, status, proxyproto::parseSocks5AuthReply) != proxyproto::Stage::Done ||
            status != 0)
            return false;
    } else if (method != 0) {
        return false;
    }

    proxyproto::Socks5Request request;
    request.command = proxyproto::Socks5Command::Connect;
    request.target = target;
    if (!sendBytes(socket, proxyproto::makeSocks5Request(request))) return false;
    buffer.clear();
    proxyproto::Socks5Reply reply;
    return negotiate(socket, buffer, reply, proxyproto::parseSocks5Reply) == proxyproto::Stage::Done &&
           reply.code == 0;
}

bool httpTunnel(SOCKET socket, const UpstreamProxyConfig& proxy, const proxyproto::Target& target) {
    proxyproto::HttpConnectRequest request;
    request.target = target;
    request.method = "CONNECT";
    request.isConnect = true;
    request.hasCredentials = !proxy.username.empty();
    request.username = proxy.username;
    request.password = proxy.password;
    if (!sendBytes(socket, proxyproto::makeHttpConnectRequest(request))) return false;
    proxyproto::Bytes buffer;
    proxyproto::HttpResponse response;
    return negotiate(socket, buffer, response, proxyproto::parseHttpResponse) == proxyproto::Stage::Done &&
           response.statusCode >= 200 && response.statusCode < 300;
}

}  // namespace

void parseTunnelEndpoint(const std::string& address, uint16_t defaultPort, std::string& host, uint16_t& port) {    host = address;
    port = defaultPort;
    std::string service;
    if (!host.empty() && host.front() == '[') {
        const auto close = host.find(']');
        if (close == std::string::npos) throw std::runtime_error("endpoint is missing ']'");
        if (close + 1 < host.size()) {
            if (host[close + 1] != ':') throw std::runtime_error("invalid endpoint suffix");
            service = host.substr(close + 2);
            if (service.empty()) throw std::runtime_error("endpoint port is empty");
        }
        host = host.substr(1, close - 1);
    } else if (std::count(host.begin(), host.end(), ':') == 1) {
        const auto colon = host.find(':');
        service = host.substr(colon + 1);
        host.resize(colon);
        if (service.empty()) throw std::runtime_error("endpoint port is empty");
    }
    if (!service.empty()) {
        unsigned value = 0;
        for (const char c : service) {
            if (c < '0' || c > '9' || value > 6553) throw std::runtime_error("invalid endpoint port");
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value == 0 || value > 65535) throw std::runtime_error("endpoint port must be between 1 and 65535");
        port = static_cast<uint16_t>(value);
    }
    if (host.empty() || host.size() > 253 || port == 0) throw std::runtime_error("invalid TCP endpoint");
    const bool literal = host.find(':') != std::string::npos || host.find_first_not_of("0123456789.") == std::string::npos;
    if (!literal) {
        for (const unsigned char c : host) {
            if (c <= 32 || c >= 127 || c == '/' || c == '\\' || c == '[' || c == ']' || c == '@') {
                throw std::runtime_error("invalid TCP endpoint hostname");
            }
        }
    }
}

Socket openProxyTunnel(const UpstreamProxyConfig& proxy, const std::string& host, uint16_t port, std::string& error) {
    error.clear();
    std::string validatedHost = host;
    uint16_t validatedPort = port;
    try {
        parseTunnelEndpoint(host.find(':') == std::string::npos ? host : "[" + host + "]", port, validatedHost,
                            validatedPort);
    } catch (const std::exception& exception) {
        error = exception.what();
        return Socket(INVALID_SOCKET);
    }
    proxyproto::Target target;
    target.host = validatedHost;
    target.port = validatedPort;
    target.hostIsNumeric = false;

    // An enabled proxy never falls back to a direct connection: that would leak the query.
    const bool tunnelling = proxy.enabled;
    sockaddr_storage address{};
    int length = 0;
    try {
        if (tunnelling) {
            std::string proxyHost = proxy.address;
            if (proxyHost.size() > 2 && proxyHost.front() == '[' && proxyHost.back() == ']')
                proxyHost = proxyHost.substr(1, proxyHost.size() - 2);
            parseEndpoint(proxyHost, proxy.port, address, length);
        } else {
            parseEndpoint(target.host, target.port, address, length);
        }
    } catch (const std::exception& exception) {
        error = exception.what();
        return Socket(INVALID_SOCKET);
    }

    Socket socket = openConnected(address, length, SOCK_STREAM, IPPROTO_TCP, error);
    if (!socket.valid()) return socket;
    if (!tunnelling) return socket;

    const bool ok = proxy.type == "socks5" ? socks5Tunnel(socket.get(), proxy, target)
                                           : httpTunnel(socket.get(), proxy, target);
    if (!ok) {
        error = "upstream proxy tunnel negotiation failed or timed out";
        return Socket(INVALID_SOCKET);
    }
    // The tunnel is open; hand back a blocking socket with the usual network timeouts.
    const DWORD timeout = static_cast<DWORD>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kNetTimeout).count());
    setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    return socket;
}

bool winHttpProxyName(const UpstreamProxyConfig& proxy, uint16_t defaultPort, std::wstring& out,
                      std::string& error) {
    if (!proxy.enabled) return false;
    if (proxy.type != "http") {
        error = "upstream_proxy type '" + proxy.type + "' cannot carry this transport; use \"http\"";
        return false;
    }
    if (proxy.address.empty()) {
        error = "upstream_proxy requires an address";
        return false;
    }
    const uint16_t port = proxy.port != 0 ? proxy.port : defaultPort;
    std::string host = proxy.address;
    if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    out = widen(host) + L":" + std::to_wstring(port);
    return true;
}

void applyWinHttpCredentials(void* request, const UpstreamProxyConfig& proxy) {
    if (!request || proxy.username.empty()) return;
    const std::wstring user = widen(proxy.username);
    const std::wstring password = widen(proxy.password);
    WinHttpSetCredentials(static_cast<HINTERNET>(request), WINHTTP_AUTH_TARGET_PROXY,
                          WINHTTP_AUTH_SCHEME_BASIC, user.c_str(), password.c_str(), nullptr);
}

