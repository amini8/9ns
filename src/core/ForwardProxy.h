#pragma once

#include <cstdint>
#include <memory>

#include "core/Config.h"

class Logger;
class Resolver;

// start()/stop() are owner-thread operations; Winsock must already be initialized.
// The resolver must outlive this listener and all its clients.
class ForwardProxy {
public:
    ForwardProxy(Resolver& resolver, Logger& logger, const ForwardProxyConfig& config,
                 uint16_t dnsPort);
    ~ForwardProxy();
    ForwardProxy(const ForwardProxy&) = delete;
    ForwardProxy& operator=(const ForwardProxy&) = delete;

    void start();
    void stop();
    bool running() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};
