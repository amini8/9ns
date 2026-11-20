#include "core/Engine.h"

#include <ws2tcpip.h>

#include <stdexcept>
#include <utility>

#include "core/Text.h"

namespace {

// With system DNS on, a host name in a DoH URL is resolved through this proxy, which needs that
// same upstream. Only an IP literal avoids the loop.
void warnAboutHostNames(const Config& config, Logger& logger) {
    for (const auto& up : config.upstreams) {
        if (up.type != "doh" || up.address.size() <= 8) {
            continue;
        }
        const std::string rest = up.address.substr(8);  // validated to start with "https://"
        if (!rest.empty() && rest[0] == '[') {
            continue;  // a bracketed host is an IPv6 literal, which needs no name lookup
        }
        const std::string host = rest.substr(0, rest.find_first_of("/:?"));
        in_addr addr{};
        if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
            logger.log(Logger::Level::Error,
                       "DoH upstream '" + up.name + "' uses a host name. With system DNS on, resolving it "
                       "goes through this proxy and can fail. Use an IP address in the URL.");
        }
    }
}

}  // namespace

Engine::Engine(Logger& logger, const std::string& backupPath)
    : logger_(logger), systemDns_(widen(backupPath), logger) {}

Engine::~Engine() {
    stop();
}

void Engine::recoverSystemDns() {
    systemDns_.restoreLeftover();
}

void Engine::start(const Config& config) {
    stop();
    config_ = config;

    auto resolver = std::make_unique<Resolver>(config, logger_);
    auto proxy = std::make_unique<Proxy>(*resolver, logger_, config.listenPort);
    proxy->start();
    resolver_ = std::move(resolver);
    proxy_ = std::move(proxy);
    port_ = config.listenPort;

    if (config.systemDns) {
        warnAboutHostNames(config, logger_);
        if (!applySystemDns()) {
            logger_.log(Logger::Level::Error,
                "System DNS could not be automatically configured on network adapters. "
                "The DNS proxy is active and listening on port 53. "
                "Ensure 9NS is run as Administrator or configure adapter DNS to 127.0.0.1 manually.");
        }
    }
}

void Engine::stop() {
    systemDns_.restore();
    proxy_.reset();
    resolver_.reset();
}

bool Engine::applySystemDns() {
    if (!running()) {
        return false;
    }
    if (port_ != 53) {
        logger_.log(Logger::Level::Error, "System DNS needs listen_port 53");
        return false;
    }
    // Only advertise ::1 when an IPv6 loopback listener actually accepted the bind; otherwise
    // clients would be pointed at an address nothing serves.
    const bool advertiseIpv6 = config_.ipv6Loopback && proxy_ && proxy_->hasIpv6Listeners();
    return systemDns_.apply(config_.preventDnsLeaks, advertiseIpv6);
}
