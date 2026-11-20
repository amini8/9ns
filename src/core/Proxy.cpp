#include <winsock2.h>
#include <ws2tcpip.h>
#include "core/Proxy.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/DnsMessage.h"

namespace {

constexpr size_t kMaxPacket = 4096;        // largest query accepted, and the largest EDNS0 UDP size we honor
constexpr size_t kMinUdpPayload = 512;     // limit for a client without an OPT record, and the floor for EDNS0 sizes
constexpr size_t kMaxUdpPayload = 4096;    // never send more than this over UDP
constexpr size_t kMaxTcpMessage = 65535;   // the 2-byte TCP length prefix cannot express more
constexpr long kPollMicroseconds = 200000; // wake up this often to notice stop()
constexpr DWORD kErrorBackoffMs = 200;     // pause after a select() or accept() failure, so the loop does not spin
constexpr DWORD kTcpTimeoutMs = 2000;      // limit for one send() or recv() on a TCP connection
constexpr ULONGLONG kTcpDeadlineMs = 5000; // limit for reading one whole query from a TCP client
constexpr unsigned kWorkerCount = 4;       // threads that run upstream lookups in parallel
constexpr size_t kMaxQueued = 256;         // queries beyond this are dropped; clients retry

static_assert(sizeof(sockaddr_storage) <= 128, "Proxy::Job stores the client address in 128 bytes");

// The largest UDP reply this client accepts. Without an OPT record that is 512 bytes. With one, it is
// the payload size the client advertised, kept between 512 and 4096.
size_t udpLimitFor(const dns::Bytes& query) {
    std::vector<dns::TtlField> fields;
    if (!dns::collectTtls(query, fields)) {
        return kMinUdpPayload;
    }
    for (const dns::TtlField& field : fields) {
        if (field.type == dns::kTypeOpt) {
            // In an OPT record the CLASS field, which sits just before the TTL, holds the
            // requestor's UDP payload size. collectTtls has already checked the bounds.
            const size_t advertised =
                (static_cast<size_t>(query[field.offset - 2]) << 8) | static_cast<size_t>(query[field.offset - 1]);
            return std::clamp(advertised, kMinUdpPayload, kMaxUdpPayload);
        }
    }
    return kMinUdpPayload;
}

// Returns the query's header and question with the TC bit set, so the client retries over TCP.
dns::Bytes truncatedReply(const dns::Bytes& query, const dns::Query& parsed, const dns::Bytes& full) {
    uint8_t rcode = 0;
    if (!dns::responseCode(full, rcode)) {
        return full;
    }
    dns::Bytes reply = dns::makeErrorResponse(query, parsed, rcode);
    reply[2] = static_cast<uint8_t>(reply[2] | 0x02);  // TC is 0x0200 in the flags word; this is its high byte
    return reply;
}

// Creates a socket bound to the IPv4 or IPv6 loopback address on the given port. A TCP socket also
// starts listening. Loopback only: the proxy must not answer queries from other machines on the
// network. IPv6 sockets are V6-only so binding ::1 never captures IPv4 traffic.
SOCKET openLoopbackSocket(int family, int type, int protocol, uint16_t port) {
    const std::string kind = type == SOCK_DGRAM ? "UDP" : "TCP";
    const SOCKET s = socket(family, type, protocol);
    if (s == INVALID_SOCKET) {
        throw std::runtime_error("cannot create " + kind + " socket (error " +
                                 std::to_string(WSAGetLastError()) + ")");
    }
    if (family == AF_INET6) {
        const DWORD v6Only = 1;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6Only), sizeof(v6Only)) ==
            SOCKET_ERROR) {
            const int error = WSAGetLastError();
            closesocket(s);
            throw std::runtime_error("cannot restrict " + kind + " socket to IPv6 (error " +
                                     std::to_string(error) + ")");
        }
    }

    if (family == AF_INET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            closesocket(s);
            throw std::runtime_error("cannot bind " + kind + " 127.0.0.1:" + std::to_string(port) + " (error " +
                                     std::to_string(error) + "). Another program may be using the port.");
        }
    } else {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = in6addr_loopback;
        if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            closesocket(s);
            throw std::runtime_error("cannot bind " + kind + " [::1]:" + std::to_string(port) + " (error " +
                                     std::to_string(error) + "). Another program may be using the port.");
        }
    }
    if (type == SOCK_STREAM && listen(s, SOMAXCONN) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(s);
        throw std::runtime_error("cannot listen on TCP loopback:" + std::to_string(port) + " (error " +
                                 std::to_string(error) + ")");
    }
    return s;
}

void setTcpTimeouts(SOCKET s) {
    const DWORD timeout = kTcpTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
}

// Reads exactly count bytes. Returns false on error, on close by the peer, or after the deadline.
bool receiveExactly(SOCKET s, uint8_t* out, size_t count, ULONGLONG deadline) {
    size_t done = 0;
    while (done < count) {
        if (GetTickCount64() > deadline) {
            return false;
        }
        const int got = recv(s, reinterpret_cast<char*>(out + done), static_cast<int>(count - done), 0);
        if (got <= 0) {
            return false;
        }
        done += static_cast<size_t>(got);
    }
    return true;
}

bool sendAll(SOCKET s, const uint8_t* data, size_t count) {
    size_t done = 0;
    while (done < count) {
        const int sent = send(s, reinterpret_cast<const char*>(data + done), static_cast<int>(count - done), 0);
        if (sent <= 0) {
            return false;
        }
        done += static_cast<size_t>(sent);
    }
    return true;
}

}  // namespace

Proxy::Proxy(Resolver& resolver, Logger& logger, uint16_t port)
    : resolver_(resolver), logger_(logger), port_(port) {}

Proxy::~Proxy() {
    stop();
}

void Proxy::start() {
    if (running_) {
        return;
    }

    const SOCKET udp4 = openLoopbackSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, port_);
    SOCKET tcp4 = INVALID_SOCKET;
    try {
        tcp4 = openLoopbackSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, port_);
    } catch (...) {
        closesocket(udp4);
        throw;
    }

    // IPv6 loopback is optional: on hosts without ::1 the v4 listeners still serve DNS. When it is
    // available, both UDP and TCP must bind so advertised ::1 is fully usable.
    SOCKET udp6 = INVALID_SOCKET;
    SOCKET tcp6 = INVALID_SOCKET;
    try {
        udp6 = openLoopbackSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, port_);
        tcp6 = openLoopbackSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, port_);
    } catch (const std::exception& e) {
        if (udp6 != INVALID_SOCKET) {
            closesocket(udp6);
        }
        if (tcp6 != INVALID_SOCKET) {
            closesocket(tcp6);
        }
        udp6 = INVALID_SOCKET;
        tcp6 = INVALID_SOCKET;
        logger_.log(Logger::Level::Info,
                    std::string("IPv6 loopback listeners unavailable; ::1 will not be advertised: ") + e.what());
    }

    udp4Socket_ = static_cast<std::uintptr_t>(udp4);
    tcp4Socket_ = static_cast<std::uintptr_t>(tcp4);
    udp6Socket_ = static_cast<std::uintptr_t>(udp6);
    tcp6Socket_ = static_cast<std::uintptr_t>(tcp6);
    ipv6Listeners_ = (udp6 != INVALID_SOCKET && tcp6 != INVALID_SOCKET);

    running_ = true;
    for (unsigned i = 0; i < kWorkerCount; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
    listener_ = std::thread([this] { receiveLoop(); });
    logger_.log(Logger::Level::Info,
                ipv6Listeners_ ? "Listening for DNS on 127.0.0.1 and [::1]:" + std::to_string(port_) +
                                     " (UDP and TCP)"
                               : "Listening for DNS on 127.0.0.1:" + std::to_string(port_) + " (UDP and TCP)");
}

void Proxy::stop() {
    running_ = false;
    if (listener_.joinable()) {
        listener_.join();  // the listener checks running_ at least every kPollMicroseconds
    }
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        for (Job& job : queue_) {
            release(job);  // a queued TCP connection owns an open socket
        }
        queue_.clear();
    }
    queueReady_.notify_all();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();  // a query in progress finishes before the sockets close
        }
    }
    workers_.clear();

    auto closeHandle = [](std::uintptr_t& handle) {
        if (handle != kNoSocket) {
            closesocket(static_cast<SOCKET>(handle));
            handle = kNoSocket;
        }
    };
    closeHandle(udp4Socket_);
    closeHandle(tcp4Socket_);
    closeHandle(udp6Socket_);
    closeHandle(tcp6Socket_);
    ipv6Listeners_ = false;
}

void Proxy::receiveLoop() {
    std::vector<char> buffer(kMaxPacket);

    while (running_) {
        fd_set readable;
        FD_ZERO(&readable);
        bool any = false;
        auto addSocket = [&](std::uintptr_t handle) {
            if (handle != kNoSocket) {
                FD_SET(static_cast<SOCKET>(handle), &readable);
                any = true;
            }
        };
        addSocket(udp4Socket_);
        addSocket(tcp4Socket_);
        addSocket(udp6Socket_);
        addSocket(tcp6Socket_);
        if (!any) {
            return;
        }
        timeval wait{};
        wait.tv_sec = 0;
        wait.tv_usec = kPollMicroseconds;

        const int ready = select(0, &readable, nullptr, nullptr, &wait);
        if (ready == SOCKET_ERROR) {
            if (running_) {
                logger_.log(Logger::Level::Error,
                            "select failed (error " + std::to_string(WSAGetLastError()) + ")");
                Sleep(kErrorBackoffMs);
            }
            continue;
        }
        if (ready == 0) {
            continue;
        }
        auto handleReady = [&](std::uintptr_t udpHandle, std::uintptr_t tcpHandle) {
            if (tcpHandle != kNoSocket && FD_ISSET(static_cast<SOCKET>(tcpHandle), &readable)) {
                acceptConnection(tcpHandle);
            }
            if (udpHandle != kNoSocket && FD_ISSET(static_cast<SOCKET>(udpHandle), &readable)) {
                receiveDatagram(udpHandle, buffer);
            }
        };
        handleReady(udp4Socket_, tcp4Socket_);
        handleReady(udp6Socket_, tcp6Socket_);
    }
}

void Proxy::receiveDatagram(std::uintptr_t udpSocket, std::vector<char>& buffer) {
    sockaddr_storage client{};
    int clientLength = sizeof(client);
    const int received = recvfrom(static_cast<SOCKET>(udpSocket), buffer.data(), static_cast<int>(buffer.size()), 0,
                                  reinterpret_cast<sockaddr*>(&client), &clientLength);
    if (received <= 0) {
        // On Windows, WSAECONNRESET here only reports an ICMP error for an earlier reply. Not fatal.
        return;
    }

    dns::Bytes query(buffer.begin(), buffer.begin() + received);
    Job job;
    if (!dns::parseQuery(query, job.parsed)) {
        return;  // malformed or unsupported packet: no reply
    }
    std::memcpy(job.client.data(), &client, sizeof(client));
    job.clientLength = clientLength;
    job.replySocket = udpSocket;
    job.query = std::move(query);
    enqueue(std::move(job));
}

void Proxy::acceptConnection(std::uintptr_t tcpSocket) {
    const SOCKET connection = accept(static_cast<SOCKET>(tcpSocket), nullptr, nullptr);
    if (connection == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        if (error != WSAECONNRESET && running_) {  // a client that left before accept() is not worth a log line
            logger_.log(Logger::Level::Error, "accept failed (error " + std::to_string(error) + ")");
            Sleep(kErrorBackoffMs);
        }
        return;
    }
    Job job;
    job.connection = static_cast<std::uintptr_t>(connection);
    enqueue(std::move(job));  // the worker reads the query, so a slow client does not block this thread
}

void Proxy::enqueue(Job job) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (queue_.size() >= kMaxQueued) {
            logger_.log(Logger::Level::Debug, "query queue full; dropping a query");
            release(job);
            return;
        }
        queue_.push_back(std::move(job));
    }
    queueReady_.notify_one();
}

void Proxy::workerLoop() {
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueReady_.wait(lock, [this] { return !queue_.empty() || !running_; });
            if (queue_.empty()) {
                return;  // stopped
            }
            job = std::move(queue_.front());
            queue_.pop_front();
        }
        if (job.connection != kNoSocket) {
            answerTcp(job);
            release(job);
        } else {
            answerUdp(job);
        }
    }
}

std::string Proxy::formatClientIp(const Job& job) const {
    std::string clientIp = "127.0.0.1";
    if (job.clientLength >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* sa = reinterpret_cast<const sockaddr*>(job.client.data());
        char ipBuf[INET6_ADDRSTRLEN] = {};
        if (sa->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
            if (inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf))) {
                clientIp = ipBuf;
            }
        } else if (sa->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, ipBuf, sizeof(ipBuf))) {
                clientIp = ipBuf;
            }
        }
    }
    return clientIp;
}

void Proxy::answerUdp(const Job& job) {
    try {
        const std::string clientIp = formatClientIp(job);
        dns::Bytes reply = resolver_.resolve(job.query, job.parsed, clientIp);
        if (reply.empty()) {
            return; // Dropped by rule
        }
        if (reply.size() > udpLimitFor(job.query)) {
            reply = truncatedReply(job.query, job.parsed, reply);
        }

        const SOCKET s = static_cast<SOCKET>(job.replySocket);
        if (s == INVALID_SOCKET) {
            return;
        }
        sendto(s, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(job.client.data()), job.clientLength);
    } catch (const std::exception& e) {
        logger_.log(Logger::Level::Error, std::string("query failed: ") + e.what());
    }
}

// Reads one length-prefixed query, writes one length-prefixed reply, and returns. The caller closes
// the connection. Malformed or slow clients get no reply.
void Proxy::answerTcp(const Job& job) {
    const SOCKET s = static_cast<SOCKET>(job.connection);
    try {
        setTcpTimeouts(s);
        const ULONGLONG deadline = GetTickCount64() + kTcpDeadlineMs;

        uint8_t prefix[2] = {0, 0};
        if (!receiveExactly(s, prefix, sizeof(prefix), deadline)) {
            return;
        }
        const size_t length = (static_cast<size_t>(prefix[0]) << 8) | static_cast<size_t>(prefix[1]);
        if (length < dns::kHeaderSize || length > kMaxPacket) {
            return;
        }
        dns::Bytes query(length);
        if (!receiveExactly(s, query.data(), query.size(), deadline)) {
            return;
        }
        dns::Query parsed;
        if (!dns::parseQuery(query, parsed)) {
            return;
        }

        const std::string clientIp = formatClientIp(job);
        dns::Bytes reply = resolver_.resolve(query, parsed, clientIp);
        if (reply.empty()) {
            return; // Dropped by rule
        }
        if (reply.size() > kMaxTcpMessage) {
            reply = dns::makeErrorResponse(query, parsed, dns::kRcodeServFail);
        }

        dns::Bytes framed;
        framed.reserve(reply.size() + 2);
        framed.push_back(static_cast<uint8_t>(reply.size() >> 8));
        framed.push_back(static_cast<uint8_t>(reply.size() & 0xFF));
        framed.insert(framed.end(), reply.begin(), reply.end());
        if (sendAll(s, framed.data(), framed.size())) {
            shutdown(s, SD_SEND);
        }
    } catch (const std::exception& e) {
        logger_.log(Logger::Level::Error, std::string("TCP query failed: ") + e.what());
    }
}

void Proxy::release(Job& job) {
    if (job.connection != kNoSocket) {
        closesocket(static_cast<SOCKET>(job.connection));
        job.connection = kNoSocket;
    }
}
