#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include "core/DnsMessage.h"
#include "core/Logger.h"
#include "core/Resolver.h"

// DNS listener bound to 127.0.0.1 (and ::1 when IPv6 loopback is available), on UDP and TCP of the
// same port. One thread receives UDP queries and
// accepts TCP connections, and queues them. A fixed set of worker threads answers them through the
// Resolver, so one slow upstream does not delay other clients.
// UDP replies larger than the client's limit (512 bytes, or the size from its EDNS0 OPT record, at most
// 4096) are sent as a truncated reply with the TC bit, and the client retries over TCP.
// A TCP connection carries one query and one reply, then it is closed.
// Winsock must be initialized before start().
class Proxy {
public:
    Proxy(Resolver& resolver, Logger& logger, uint16_t port);
    ~Proxy();

    Proxy(const Proxy&) = delete;
    Proxy& operator=(const Proxy&) = delete;

    // Binds the UDP and TCP sockets and starts the threads. Throws std::runtime_error if either
    // socket cannot be bound.
    void start();

    // Stops the listener and the workers and closes the sockets. Waits for queries in progress.
    // Safe to call twice.
    void stop();

    // True when both IPv6 loopback listeners are bound. The caller must not advertise ::1
    // unless this is true.
    bool hasIpv6Listeners() const { return ipv6Listeners_; }

private:
    // Value of a socket that is not open. The sockets are kept as integers so this header does not
    // need winsock2.h, which conflicts with windows.h when both are included earlier.
    static constexpr std::uintptr_t kNoSocket = ~std::uintptr_t{0};

    // A received query waiting for a worker. The client address is kept as raw sockaddr_in bytes,
    // so this header does not need winsock2.h.
    // For a UDP job, query and parsed are filled. For a TCP job, only connection is set, and the
    // worker reads the query from that connection.
    struct Job {
        std::array<unsigned char, 128> client{};
        int clientLength = 0;
        dns::Bytes query;
        dns::Query parsed;
        std::uintptr_t connection = kNoSocket;
        std::uintptr_t replySocket = kNoSocket;  // UDP listener that received the query
    };

    void receiveLoop();
    void receiveDatagram(std::uintptr_t udpSocket, std::vector<char>& buffer);
    void acceptConnection(std::uintptr_t tcpSocket);
    void workerLoop();
    void enqueue(Job job);
    std::string formatClientIp(const Job& job) const;
    void answerUdp(const Job& job);
    void answerTcp(const Job& job);
    static void release(Job& job);

    Resolver& resolver_;
    Logger& logger_;
    uint16_t port_;

    std::atomic<bool> running_{false};
    std::thread listener_;
    std::vector<std::thread> workers_;

    std::mutex queueMutex_;
    std::condition_variable queueReady_;
    std::deque<Job> queue_;

    std::uintptr_t udp4Socket_ = kNoSocket;
    std::uintptr_t tcp4Socket_ = kNoSocket;
    std::uintptr_t udp6Socket_ = kNoSocket;
    std::uintptr_t tcp6Socket_ = kNoSocket;
    bool ipv6Listeners_ = false;
};
