#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "core/Config.h"
#include "core/Logger.h"
#include "core/Proxy.h"
#include "core/Resolver.h"
#include "core/SystemDns.h"

// Owns the running resolver, listener and adapter DNS switching. Use it from the UI thread only.
// Winsock must be initialized before start().
class Engine {
public:
    Engine(Logger& logger, const std::string& backupPath);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Repairs adapter DNS left over from a crashed run. Call once at startup.
    void recoverSystemDns();

    // Stops a running instance first. Throws std::runtime_error on failure and leaves the engine stopped.
    // Adapter DNS is switched when config.systemDns is set.
    void start(const Config& config);

    // Restores adapter DNS first, then stops the listener.
    void stop();

    bool running() const { return proxy_ != nullptr; }
    uint16_t port() const { return port_; }
    bool systemDnsActive() const { return systemDns_.active(); }
    Resolver* resolver() { return resolver_.get(); }

private:
    // Points adapter DNS at this engine. Returns false when it could not be done;
    // enabling needs a running engine on port 53.
    bool applySystemDns();

    Logger& logger_;
    SystemDns systemDns_;
    Config config_;
    std::unique_ptr<Resolver> resolver_;  // declared before proxy_, so it is destroyed after it
    std::unique_ptr<Proxy> proxy_;
    uint16_t port_ = 0;
};
