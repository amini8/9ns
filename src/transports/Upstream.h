#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "core/Config.h"
#include "core/DnsMessage.h"

// One DNS server the proxy forwards to. Implementations are Plain, DoH, DoT, DNSCrypt, ODoH and DoQ.
class Upstream {
public:
    virtual ~Upstream() = default;

    // Builds the upstream for a config entry. Throws std::runtime_error if the address is unusable.
    // The optional upstream proxy is applied to every transport that can traverse it; DoQ and
    // DNSCrypt-over-UDP cannot and validateConfig rejects that combination up front.
    static std::unique_ptr<Upstream> create(const UpstreamConfig& config,
                                            const UpstreamProxyConfig& proxy = {});

    // Sends the raw query and fills response with the raw reply. Returns false and sets error on
    // failure. Each call blocks for at most a few seconds.
    virtual bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) = 0;

    // Tests reachability and measures round-trip time in milliseconds.
    virtual bool ping(uint32_t& rttMs, std::string& error);

    const std::string& name() const { return name_; }
    const std::string& type() const { return type_; }

    // True when this channel authenticates the upstream server. Encryption alone
    // does not count: a tls_verify=false transport is not authenticated.
    bool isAuthenticated() const { return authenticated_; }

    // Channel-trust decision for a transport type and its tls_verify setting.
    // Only verified TLS-family transports (doh, dot, doq) and DNSCrypt authenticate
    // their server; plain DNS, unverified TLS and ODoH relaying do not.
    static bool isAuthenticatedChannel(const std::string& type, bool tlsVerify) {
        if (type == "dnscrypt") {
            return true;
        }
        if (type == "doh" || type == "dot" || type == "doq") {
            return tlsVerify;
        }
        return false;
    }

protected:
    Upstream(std::string name, std::string type)
        : name_(std::move(name)), type_(std::move(type)) {}

    // Declares this channel's trust provenance. create() sets it from the resolved
    // transport and tls_verify; test fakes may set it directly.
    void setAuthenticated(bool authenticated) { authenticated_ = authenticated; }

    // The upstream proxy every outbound connection of this transport is tunnelled through.
    // Set by create() before the transport is first used. Disabled means a direct connection.
    const UpstreamProxyConfig& upstreamProxy() const { return upstreamProxy_; }

private:
    // create() applies the proxy before handing the transport out, so no transport sees a
    // half-configured upstream proxy.
    void setUpstreamProxy(const UpstreamProxyConfig& proxy) {
        upstreamProxy_ = proxy;
        onUpstreamProxyChanged();
    }

    std::string name_;
    std::string type_;
    bool authenticated_ = false;
    UpstreamProxyConfig upstreamProxy_;

protected:
    // Transports that keep their proxy state in a helper object override this to copy it.
    virtual void onUpstreamProxyChanged() {}
};
