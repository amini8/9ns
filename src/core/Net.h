#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

// Winsock helpers shared by the plain and DNSCrypt upstreams.
// WSAStartup must have run before any of these are called.

using NetClock = std::chrono::steady_clock;
constexpr auto kNetTimeout = std::chrono::seconds(3);

// Owns a SOCKET and closes it on destruction.
class Socket {
public:
    explicit Socket(SOCKET s) : s_(s) {}
    ~Socket() {
        if (valid()) {
            closesocket(s_);
        }
    }
    Socket(Socket&& other) noexcept : s_(std::exchange(other.s_, INVALID_SOCKET)) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    bool valid() const { return s_ != INVALID_SOCKET; }
    SOCKET get() const { return s_; }

private:
    SOCKET s_;
};

// Parses "ip", "ip:port", "[ipv6]" or "[ipv6]:port". Throws std::runtime_error if the text is not a numeric address.
inline void parseEndpoint(const std::string& text, uint16_t defaultPort, sockaddr_storage& out, int& length) {
    std::string host = text;
    std::string port = std::to_string(defaultPort);
    if (!host.empty() && host.front() == '[') {
        const size_t close = host.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("address '" + text + "' is missing ']'");
        }
        const std::string rest = host.substr(close + 1);
        host = host.substr(1, close - 1);
        if (!rest.empty()) {
            if (rest.front() != ':') {
                throw std::runtime_error("address '" + text + "' is malformed");
            }
            port = rest.substr(1);
        }
    } else if (std::count(host.begin(), host.end(), ':') == 1) {
        // A single colon means "host:port". Bare IPv6 addresses always contain several colons.
        const size_t colon = host.find(':');
        port = host.substr(colon + 1);
        host.resize(colon);
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0 || result == nullptr) {
        throw std::runtime_error("address '" + text + "' must be an IP address with an optional port");
    }
    std::memcpy(&out, result->ai_addr, result->ai_addrlen);
    length = static_cast<int>(result->ai_addrlen);
    freeaddrinfo(result);
}

// Creates a socket and connects it to addr. UDP sockets then accept datagrams from addr only.
// Returns an invalid Socket and sets error on failure.
inline Socket openConnected(const sockaddr_storage& addr, int length, int type, int protocol, std::string& error) {
    Socket sock(::socket(static_cast<int>(addr.ss_family), type, protocol));
    if (!sock.valid()) {
        error = "cannot create socket (error " + std::to_string(WSAGetLastError()) + ")";
        return sock;
    }
    const DWORD timeoutMs = static_cast<DWORD>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kNetTimeout).count());
    setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    setsockopt(sock.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), length) == SOCKET_ERROR) {
        error = "cannot connect (error " + std::to_string(WSAGetLastError()) + ")";
        return Socket(INVALID_SOCKET);
    }
    return sock;
}

// Sets SO_RCVTIMEO so the next recv() gives up at deadline. At least 1 ms, because 0 means no timeout.
inline void setReceiveDeadline(SOCKET s, NetClock::time_point deadline) {
    const long long left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - NetClock::now()).count();
    const DWORD ms = static_cast<DWORD>((std::max)(1LL, left));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}

// Sends or receives exactly size bytes. Returns false on error, timeout or early close.
inline bool sendAll(SOCKET s, const uint8_t* data, size_t size) {
    while (size > 0) {
        const int chunk = static_cast<int>((std::min)(size, static_cast<size_t>(65536)));
        const int sent = ::send(s, reinterpret_cast<const char*>(data), chunk, 0);
        if (sent <= 0) {
            return false;
        }
        data += sent;
        size -= static_cast<size_t>(sent);
    }
    return true;
}

inline bool recvAll(SOCKET s, uint8_t* data, size_t size) {
    while (size > 0) {
        const int chunk = static_cast<int>((std::min)(size, static_cast<size_t>(65536)));
        const int got = ::recv(s, reinterpret_cast<char*>(data), chunk, 0);
        if (got <= 0) {
            return false;
        }
        data += got;
        size -= static_cast<size_t>(got);
    }
    return true;
}
