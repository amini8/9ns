#include "core/Resolver.h"

#include <chrono>
#include <utility>

Resolver::Resolver(const Config& config, Logger& logger)
    : logger_(logger),
      config_(config),
      rules_(config.rules),
      cache_(config.cacheEntries, config.minTtl, config.maxTtl, config.negativeTtl),
      defaultTarget_(!config.defaultTarget.empty() ? config.defaultTarget : config.defaultUpstream) {

    // Instantiate upstreams
    for (const UpstreamConfig& item : config.upstreams) {
        upstreams_[item.name] = Upstream::create(item);
    }

    // Instantiate pools
    for (const PoolConfig& item : config.pools) {
        std::vector<Upstream*> members;
        for (const std::string& serverName : item.servers) {
            auto it = upstreams_.find(serverName);
            if (it != upstreams_.end()) {
                members.push_back(it->second.get());
            }
        }
        if (!members.empty()) {
            pools_[item.name] = std::make_unique<Pool>(item.name, item.strategy, std::move(members));
        }
    }
}

Resolver::~Resolver() = default;

void Resolver::setEventSink(EventSink sink) {
    std::lock_guard<std::mutex> lock(sinkMutex_);
    eventSink_ = std::move(sink);
}

dns::Bytes Resolver::resolve(const dns::Bytes& query, const dns::Query& parsed, const std::string& clientIp) {
    const auto startTime = std::chrono::steady_clock::now();
    ResolveEvent event;
    event.clientIp = clientIp;
    event.queryName = parsed.name;
    event.queryType = parsed.type;
    event.query = query;

    auto emitEvent = [this, &event, startTime](const dns::Bytes& reply) {
        const auto elapsed = std::chrono::steady_clock::now() - startTime;
        event.latencyMs = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        event.response = reply;
        if (!reply.empty()) {
            dns::responseCode(reply, event.rcode);
        }

        std::lock_guard<std::mutex> lock(sinkMutex_);
        if (eventSink_) {
            eventSink_(event);
        }
    };

    // 1. Rules lookup
    std::string target = defaultTarget_;
    const RuleConfig* rule = rules_.find(parsed.name, parsed.type);
    if (rule) {
        if (rule->action == "block") {
            event.action = "Blocked";
            event.target = "Block";
            dns::Bytes reply;
            if (rule->blockMode == "null_ip") {
                reply = dns::makeNullIpResponse(query, parsed);
            } else if (rule->blockMode == "refused") {
                reply = dns::makeErrorResponse(query, parsed, dns::kRcodeRefused);
            } else if (rule->blockMode == "drop") {
                emitEvent(reply);
                return reply; // Empty drops query
            } else {
                reply = dns::makeErrorResponse(query, parsed, dns::kRcodeNxDomain);
            }
            logger_.log(Logger::Level::Debug, "blocked " + parsed.name + " (" + rule->blockMode + ")");
            emitEvent(reply);
            return reply;
        }

        if (rule->action == "local" && !rule->localIp.empty()) {
            event.action = "Local";
            event.target = "Local IP";
            dns::Bytes reply = dns::makeLocalIpResponse(query, parsed, rule->localIp);
            logger_.log(Logger::Level::Debug, "local record for " + parsed.name + " -> " + rule->localIp);
            emitEvent(reply);
            return reply;
        }

        if (!rule->target.empty()) {
            target = rule->target;
        } else if (!rule->upstream.empty()) {
            target = rule->upstream;
        }
    }

    event.target = target;

    // Rejects a response whose DNSSEC status is Bogus unless the rule opts out.
    // Applies to cache hits and fresh replies alike.
    auto enforceDnssec = [this, &event, &emitEvent, &query, &parsed, rule](DnsSecStatus status) -> dns::Bytes {
        if (config_.dnssecValidation && status == DnsSecStatus::Bogus &&
            (!rule || rule->dnssecMode != "ignore")) {
            logger_.log(Logger::Level::Error, "DNSSEC validation failed (Bogus) for " + parsed.name);
            event.action = "Bogus";
            return dns::makeErrorResponse(query, parsed, dns::kRcodeServFail);
        }
        return {};
    };

    // 2. Reply Cache lookup
    dns::QueryContext queryCtx;
    dns::queryContext(query, parsed, queryCtx);
    const std::string key = cacheKey(target, parsed, queryCtx);
    dns::Bytes cachedReply;
    CacheProvenance cachedProvenance;
    if (cache_.get(key, parsed.id, cachedReply, cachedProvenance)) {
        event.action = "Cached";
        event.usedServer = "Cache";
        event.dnssec = cachedProvenance.status;
        dns::Bytes rejected = enforceDnssec(cachedProvenance.status);
        if (!rejected.empty()) {
            emitEvent(rejected);
            return rejected;
        }
        emitEvent(cachedReply);
        return cachedReply;
    }

    // 3. Upstream or Pool resolution
    dns::Bytes response;
    std::string error;
    std::string usedServer = target;
    bool success = false;
    bool authenticated = false;

    auto poolIt = pools_.find(target);
    if (poolIt != pools_.end()) {
        success = poolIt->second->exchange(query, response, error, usedServer);
        // Channel trust follows the pool member that actually answered.
        auto memberIt = upstreams_.find(usedServer);
        authenticated = success && memberIt != upstreams_.end() && memberIt->second->isAuthenticated();
    } else {
        auto upIt = upstreams_.find(target);
        if (upIt != upstreams_.end()) {
            authenticated = upIt->second->isAuthenticated();
            success = upIt->second->exchange(query, response, error);
            usedServer = upIt->second->name();
        } else {
            error = "no upstream or pool named '" + target + "'";
        }
    }

    event.usedServer = usedServer;

    if (!success || !dns::isResponseFor(response, query)) {
        event.action = "Error";
        logger_.log(Logger::Level::Error, "target '" + target + "' failed for " + parsed.name + ": " +
                                              (error.empty() ? std::string("bad reply") : error));
        dns::Bytes failReply = dns::makeErrorResponse(query, parsed, dns::kRcodeServFail);
        emitEvent(failReply);
        return failReply;
    }

    // 4. DNSSEC Validation
    const DnsSecStatus secStatus = dnssec_.validate(response, authenticated);
    event.dnssec = secStatus;

    dns::Bytes rejected = enforceDnssec(secStatus);
    if (!rejected.empty()) {
        emitEvent(rejected);
        return rejected;
    }

    // 5. Store in cache & return
    CacheProvenance provenance;
    provenance.authenticatedTransport = authenticated;
    provenance.status = secStatus;
    cache_.put(key, query, response, provenance);
    event.action = "Resolved";
    emitEvent(response);
    return response;
}
