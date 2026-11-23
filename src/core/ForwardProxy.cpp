#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/ForwardProxy.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "core/Logger.h"
#include "core/ProxyProtocol.h"
#include "core/Resolver.h"

namespace {
using Clock = std::chrono::steady_clock;
using proxyproto::Bytes;
constexpr uintptr_t kInvalidSocket = static_cast<uintptr_t>(INVALID_SOCKET);
constexpr size_t kMaxClients = 128;

bool nonblocking(SOCKET socket) {
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0;
}

std::string sanitized(const std::string& text) {
    std::string result;
    for (unsigned char c : text.substr(0, 253)) {
        result += (c >= 33 && c <= 126 && c != '\\' && c != '"') ? static_cast<char>(c) : '_';
    }
    return result.empty() ? "-" : result;
}

bool waitSocket(SOCKET socket, bool writing, Clock::time_point deadline,
                const std::atomic<bool>& stopping) {
    while (!stopping && Clock::now() < deadline) {
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(socket, &ready);
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - Clock::now()).count();
        if (left <= 0) return false;
        timeval timeout{0, static_cast<long>((std::min)(left, 200000LL))};
        const int count = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr,
                                 nullptr, &timeout);
        if (count > 0) return !stopping;
        if (count < 0) return false;
    }
    return false;
}

bool sendBytes(SOCKET socket, const uint8_t* data, size_t size, Clock::time_point deadline,
               const std::atomic<bool>& stopping) {
    deadline = (std::min)(deadline, Clock::now() + std::chrono::seconds(2));
    while (size != 0 && waitSocket(socket, true, deadline, stopping)) {
        const int sent = send(socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0);
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<size_t>(sent);
    }
    return size == 0;
}

bool numericEndpoint(const std::string& ip, uint16_t port, sockaddr_storage& address, int& length) {
    auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
    if (inet_pton(AF_INET, ip.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        length = sizeof(*v4);
        return true;
    }
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
    if (inet_pton(AF_INET6, ip.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        length = sizeof(*v6);
        return true;
    }
    return false;
}

bool loopbackOrUnspecified(const sockaddr_storage& address) {
    if (address.ss_family == AF_INET) {
        const auto value = ntohl(reinterpret_cast<const sockaddr_in*>(&address)->sin_addr.s_addr);
        return value == 0 || (value >> 24) == 127;
    }
    const auto& ip = reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr;
    if (IN6_IS_ADDR_LOOPBACK(&ip) || IN6_IS_ADDR_UNSPECIFIED(&ip)) return true;
    if (IN6_IS_ADDR_V4MAPPED(&ip)) return ip.s6_addr[12] == 127 ||
        (ip.s6_addr[12] == 0 && ip.s6_addr[13] == 0 && ip.s6_addr[14] == 0 && ip.s6_addr[15] == 0);
    return false;
}
} // namespace

struct ForwardProxy::State {
    struct Client {
        std::mutex mutex;
        uintptr_t socket = kInvalidSocket;
        uintptr_t upstream = kInvalidSocket;
        std::thread thread;
        std::atomic<bool> done{false};
        std::string ip;

        void shutdownSockets() {
            std::lock_guard<std::mutex> lock(mutex);
            if (socket != kInvalidSocket) shutdown(socket, SD_BOTH);
            if (upstream != kInvalidSocket) shutdown(upstream, SD_BOTH);
        }
        void closeUpstream() {
            std::lock_guard<std::mutex> lock(mutex);
            if (upstream != kInvalidSocket) closesocket(upstream);
            upstream = kInvalidSocket;
        }
        void closeSockets() {
            std::lock_guard<std::mutex> lock(mutex);
            if (socket != kInvalidSocket) closesocket(socket);
            if (upstream != kInvalidSocket) closesocket(upstream);
            socket = upstream = kInvalidSocket;
        }
    };

    Resolver& resolver;
    Logger& logger;
    ForwardProxyConfig config;
    uint16_t dnsPort;
    std::atomic<bool> stopping{true};
    std::atomic<bool> active{false};
    std::array<uintptr_t, 2> listeners{kInvalidSocket, kInvalidSocket};
    std::thread listener;
    std::mutex clientsMutex;
    std::vector<std::shared_ptr<Client>> clients;

    State(Resolver& resolver, Logger& logger, const ForwardProxyConfig& config, uint16_t dnsPort)
        : resolver(resolver), logger(logger), config(config), dnsPort(dnsPort) {}

    uintptr_t bindListener(int family) {
        const SOCKET socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (socket == INVALID_SOCKET) return kInvalidSocket;
        const BOOL exclusive = TRUE;
        bool ok = setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                             reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0;
        if (family == AF_INET6) {
            const DWORD only = 1;
            ok = ok && setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
                                  reinterpret_cast<const char*>(&only), sizeof(only)) == 0;
        }
        sockaddr_storage address{};
        int length = 0;
        ok = ok && numericEndpoint(family == AF_INET ? "127.0.0.1" : "::1", config.port, address, length);
        ok = ok && bind(socket, reinterpret_cast<const sockaddr*>(&address), length) == 0;
        ok = ok && listen(socket, SOMAXCONN) == 0 && nonblocking(socket);
        if (!ok) {
            closesocket(socket);
            return kInvalidSocket;
        }
        return socket;
    }

    bool receive(Client& client, Bytes& buffer, Clock::time_point deadline) {
        if (buffer.size() >= proxyproto::kMaxHandshakeSize) return false;
        const auto receiveDeadline = (std::min)(deadline, Clock::now() + std::chrono::seconds(2));
        while (waitSocket(client.socket, false, receiveDeadline, stopping)) {
            std::array<uint8_t, 8192> bytes{};
            const int count = recv(client.socket, reinterpret_cast<char*>(bytes.data()),
                                   static_cast<int>(bytes.size() - buffer.size()), 0);
            if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            if (count <= 0) return false;
            buffer.insert(buffer.end(), bytes.begin(), bytes.begin() + count);
            return true;
        }
        return false;
    }

    template <typename T, typename Parser>
    bool parse(Client& client, Bytes& buffer, T& output, Parser parser, Clock::time_point deadline) {
        while (!stopping && Clock::now() < deadline) {
            size_t consumed = 0;
            const auto stage = parser(buffer, output, consumed);
            if (stage == proxyproto::Stage::Done) {
                buffer.erase(buffer.begin(), buffer.begin() + consumed);
                return true;
            }
            if (stage == proxyproto::Stage::Malformed || !receive(client, buffer, deadline)) return false;
        }
        return false;
    }

    bool reply(Client& client, const Bytes& bytes, Clock::time_point deadline) {
        return sendBytes(client.socket, bytes.data(), bytes.size(), deadline, stopping);
    }

    void refuse(Client& client, proxyproto::Protocol protocol, proxyproto::Refusal reason,
                Clock::time_point deadline) {
        const auto codes = proxyproto::refusalFor(reason);
        if (protocol == proxyproto::Protocol::Socks5) reply(client, proxyproto::makeSocks5Reply(codes.socks5), deadline);
        else if (protocol == proxyproto::Protocol::Socks4) reply(client, proxyproto::makeSocks4Reply(codes.socks4), deadline);
        else if (protocol == proxyproto::Protocol::HttpConnect) reply(client, proxyproto::makeHttpResponse(codes.http), deadline);
    }

    bool handshake(Client& client, Bytes& buffer, proxyproto::Protocol& protocol,
                   proxyproto::Target& target, std::string& verdict) {
        const auto deadline = Clock::now() + std::chrono::seconds(5);
        if (!receive(client, buffer, deadline)) return false;
        protocol = proxyproto::detectProtocol(buffer);
        const bool auth = !config.username.empty() || !config.password.empty();
        if (protocol == proxyproto::Protocol::Socks5) {
            proxyproto::Socks5Greeting greeting;
            if (!parse(client, buffer, greeting, proxyproto::parseSocks5Greeting, deadline)) return false;
            const uint8_t method = auth ? 2 : 0;
            if (std::find(greeting.methods.begin(), greeting.methods.end(), method) == greeting.methods.end()) {
                verdict = "authentication-refused";
                reply(client, proxyproto::makeSocks5MethodChoice(255), deadline);
                return false;
            }
            if (!reply(client, proxyproto::makeSocks5MethodChoice(method), deadline)) return false;
            if (auth) {
                proxyproto::Socks5Auth credentials;
                if (!parse(client, buffer, credentials, proxyproto::parseSocks5Auth, deadline)) return false;
                const bool valid = credentials.username == config.username && credentials.password == config.password;
                if (!reply(client, proxyproto::makeSocks5AuthReply(valid ? 0 : 1), deadline) || !valid) {
                    verdict = "authentication-refused";
                    return false;
                }
            }
            proxyproto::Socks5Request request;
            if (!parse(client, buffer, request, proxyproto::parseSocks5Request, deadline)) return false;
            target = request.target;
            if (request.command != proxyproto::Socks5Command::Connect) {
                verdict = "unsupported-command";
                refuse(client, protocol, proxyproto::Refusal::UnsupportedCommand, deadline);
                return false;
            }
        } else if (protocol == proxyproto::Protocol::Socks4) {
            proxyproto::Socks4Request request;
            if (!parse(client, buffer, request, proxyproto::parseSocks4Request, deadline)) return false;
            target = request.target;
            if (auth || request.command != 1) {
                verdict = auth ? "authentication-refused" : "unsupported-command";
                refuse(client, protocol, auth ? proxyproto::Refusal::Authentication : proxyproto::Refusal::UnsupportedCommand, deadline);
                return false;
            }
        } else if (protocol == proxyproto::Protocol::HttpConnect) {
            proxyproto::HttpConnectRequest request;
            if (!parse(client, buffer, request, proxyproto::parseHttpConnect, deadline)) return false;
            target = request.target;
            if (auth && (!request.hasCredentials || request.username != config.username || request.password != config.password)) {
                verdict = "authentication-refused";
                refuse(client, protocol, proxyproto::Refusal::Authentication, deadline);
                return false;
            }
            if (!request.isConnect) {
                verdict = "unsupported-command";
                refuse(client, protocol, proxyproto::Refusal::UnsupportedCommand, deadline);
                return false;
            }
        } else return false;
        return !stopping;
    }

    bool connectTarget(Client& client, const std::vector<std::string>& addresses, uint16_t port) {
        const auto deadline = Clock::now() + std::chrono::seconds(5);
        for (const auto& ip : addresses) {
            if (stopping || Clock::now() >= deadline) return false;
            sockaddr_storage address{};
            int length = 0;
            if (!numericEndpoint(ip, port, address, length)) continue;
            if (loopbackOrUnspecified(address) && (port == config.port || port == dnsPort || port == 53)) continue;
            const SOCKET socket = ::socket(address.ss_family, SOCK_STREAM, IPPROTO_TCP);
            if (socket == INVALID_SOCKET) continue;
            {
                std::lock_guard<std::mutex> lock(client.mutex);
                if (stopping) {
                    closesocket(socket);
                    return false;
                }
                client.upstream = socket;
            }
            bool connected = false;
            if (nonblocking(socket)) {
                const int result = connect(socket, reinterpret_cast<const sockaddr*>(&address), length);
                connected = result == 0;
                if (!connected && WSAGetLastError() == WSAEWOULDBLOCK && waitSocket(socket, true, deadline, stopping)) {
                    int error = 0;
                    int size = sizeof(error);
                    connected = getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == 0 && error == 0;
                }
            }
            if (connected && !stopping) return true;
            client.closeUpstream();
        }
        return false;
    }

    void relay(Client& client, const Bytes& pending) {
        if (!sendBytes(client.upstream, pending.data(), pending.size(), Clock::now() + std::chrono::seconds(2), stopping)) return;
        const std::array<SOCKET, 2> sockets{client.socket, client.upstream};
        std::array<bool, 2> reading{true, true};
        auto lastActivity = Clock::now();
        while (!stopping && (reading[0] || reading[1]) && Clock::now() - lastActivity < std::chrono::seconds(120)) {
            fd_set reads;
            FD_ZERO(&reads);
            for (size_t i = 0; i < 2; ++i) if (reading[i]) FD_SET(sockets[i], &reads);
            timeval timeout{1, 0};
            const int ready = select(0, &reads, nullptr, nullptr, &timeout);
            if (ready < 0) return;
            if (ready == 0) continue;
            for (size_t i = 0; i < 2 && !stopping; ++i) {
                if (!reading[i] || !FD_ISSET(sockets[i], &reads)) continue;
                std::array<uint8_t, 8192> bytes{};
                const int count = recv(sockets[i], reinterpret_cast<char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
                if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
                if (count < 0) return;
                if (count == 0) {
                    reading[i] = false;
                    shutdown(sockets[1 - i], SD_SEND);
                } else {
                    if (!sendBytes(sockets[1 - i], bytes.data(), static_cast<size_t>(count),
                                   Clock::now() + std::chrono::seconds(2), stopping)) return;
                    lastActivity = Clock::now();
                }
            }
        }
    }

    void serve(Client& client) {
        proxyproto::Protocol protocol = proxyproto::Protocol::Unknown;
        proxyproto::Target target;
        std::string verdict = "malformed-or-timeout";
        try {
            Bytes pending;
            if (handshake(client, pending, protocol, target, verdict)) {
                std::vector<std::string> addresses;
                const auto result = resolver.resolveAddresses(target.host, client.ip, addresses);
                if (result != LookupVerdict::Allowed) {
                    const auto reason = result == LookupVerdict::Blocked ? proxyproto::Refusal::Blocked :
                        result == LookupVerdict::NotFound ? proxyproto::Refusal::NotFound : proxyproto::Refusal::Failed;
                    verdict = result == LookupVerdict::Blocked ? "blocked" : result == LookupVerdict::NotFound ? "not-found" : "resolution-failed";
                    refuse(client, protocol, reason, Clock::now() + std::chrono::seconds(2));
                } else if (!connectTarget(client, addresses, target.port)) {
                    verdict = stopping ? "cancelled" : "connect-failed";
                    refuse(client, protocol, proxyproto::Refusal::Failed, Clock::now() + std::chrono::seconds(2));
                } else {
                    verdict = "allowed";
                    const auto response = protocol == proxyproto::Protocol::Socks5 ? proxyproto::makeSocks5Reply(0) :
                        protocol == proxyproto::Protocol::Socks4 ? proxyproto::makeSocks4Reply(90) : proxyproto::makeHttpResponse(200);
                    if (reply(client, response, Clock::now() + std::chrono::seconds(2))) relay(client, pending);
                }
            }
        } catch (...) {
            verdict = "failed";
        }
        client.closeSockets();
        logger.log(Logger::Level::Info, "Forward proxy client=" + sanitized(client.ip) +
            " target=" + sanitized(target.host) + ":" + std::to_string(target.port) + " verdict=" + verdict);
        client.done = true;
    }

    void acceptLoop() {
        while (!stopping) {
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                clients.erase(std::remove_if(clients.begin(), clients.end(), [](const auto& client) {
                    if (!client->done) return false;
                    client->thread.join();
                    return true;
                }), clients.end());
            }
            fd_set reads;
            FD_ZERO(&reads);
            for (const auto socket : listeners) if (socket != kInvalidSocket) FD_SET(socket, &reads);
            timeval timeout{0, 200000};
            const int ready = select(0, &reads, nullptr, nullptr, &timeout);
            if (ready < 0) break;
            if (ready == 0) continue;
            for (const auto socket : listeners) {
                if (stopping || socket == kInvalidSocket || !FD_ISSET(socket, &reads)) continue;
                sockaddr_storage address{};
                int length = sizeof(address);
                const SOCKET accepted = accept(socket, reinterpret_cast<sockaddr*>(&address), &length);
                if (accepted == INVALID_SOCKET) continue;
                std::lock_guard<std::mutex> lock(clientsMutex);
                if (stopping || clients.size() >= kMaxClients || !nonblocking(accepted)) {
                    closesocket(accepted);
                    logger.log(Logger::Level::Info, "Forward proxy client=loopback target=- verdict=capacity-or-cancelled");
                    continue;
                }
                auto client = std::make_shared<Client>();
                client->socket = accepted;
                client->ip = address.ss_family == AF_INET ? "127.0.0.1" : "::1";
                try {
                    clients.push_back(client);
                    client->thread = std::thread([this, client] { serve(*client); });
                } catch (...) {
                    client->closeSockets();
                    if (!clients.empty() && clients.back() == client) clients.pop_back();
                    logger.log(Logger::Level::Error, "Forward proxy client=loopback target=- verdict=worker-failed");
                }
            }
        }
        active = false;
    }
};

ForwardProxy::ForwardProxy(Resolver& resolver, Logger& logger, const ForwardProxyConfig& config, uint16_t dnsPort)
    : state_(std::make_unique<State>(resolver, logger, config, dnsPort)) {}

ForwardProxy::~ForwardProxy() { stop(); }

void ForwardProxy::start() {
    stop();
    auto& state = *state_;
    state.listeners[0] = state.bindListener(AF_INET);
    if (state.listeners[0] == kInvalidSocket) throw std::runtime_error("cannot bind forward proxy to 127.0.0.1:" + std::to_string(state.config.port));
    state.listeners[1] = state.bindListener(AF_INET6);
    if (state.listeners[1] == kInvalidSocket) state.logger.log(Logger::Level::Info, "Forward proxy IPv6 loopback unavailable; IPv4 remains active");
    state.stopping = false;
    state.active = true;
    try {
        state.listener = std::thread([&state] { state.acceptLoop(); });
    } catch (...) {
        stop();
        throw;
    }
}

void ForwardProxy::stop() {
    auto& state = *state_;
    state.stopping = true;
    {
        std::lock_guard<std::mutex> lock(state.clientsMutex);
        for (const auto& client : state.clients) client->shutdownSockets();
    }
    // Listener handles remain owned until the select loop has exited.
    if (state.listener.joinable()) state.listener.join();
    for (auto& socket : state.listeners) {
        if (socket != kInvalidSocket) closesocket(socket);
        socket = kInvalidSocket;
    }
    for (const auto& client : state.clients) if (client->thread.joinable()) client->thread.join();
    state.clients.clear();
    state.active = false;
}

bool ForwardProxy::running() const { return state_->active; }
