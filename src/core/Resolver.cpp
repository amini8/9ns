#include "core/Resolver.h"

#include <chrono>
#include <cstring>
#include <utility>

#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

// Builds a one-question standard query. Kept file-local: the forwarding proxy is the
// only production caller that needs to synthesise a query from a host name.
dns::Bytes makeQuery(uint16_t id, const std::string& name, uint16_t type) {
    dns::Bytes query(dns::kHeaderSize, 0);
    const auto writeU16 = [&query](size_t offset, uint16_t value) {
        query[offset] = static_cast<uint8_t>(value >> 8);
        query[offset + 1] = static_cast<uint8_t>(value & 0xFF);
    };
    writeU16(0, id);
    writeU16(2, 0x0100);  // RD, no error
    writeU16(4, 1);       // one question
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        const auto length = dot - start;
        if (length == 0 || length > 63) return {};
        query.push_back(static_cast<uint8_t>(length));
        query.insert(query.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                     name.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
    }
    query.push_back(0);  // root label
    query.push_back(static_cast<uint8_t>(type >> 8));
    query.push_back(static_cast<uint8_t>(type & 0xFF));
    query.push_back(0);
    query.push_back(1);  // class IN
    return query;
}

// Renders the A/AAAA rdata of a reply. Returns false when any rdata has the wrong length.
bool collectAddresses(const dns::Bytes& reply, uint16_t type, std::vector<std::string>& out) {
    dns::ParsedMessage message;
    if (!dns::parseMessage(reply, message)) return false;
    for (const dns::Record& record : message.answers) {
        if (record.type != type || record.rclass != 1) continue;
        if (type == dns::kTypeA && record.rdata.size() != 4) return false;
        if (type == dns::kTypeAaaa && record.rdata.size() != 16) return false;
        char text[64] = {};
        if (!inet_ntop(type == dns::kTypeA ? AF_INET : AF_INET6, record.rdata.data(), text, sizeof(text)))
            return false;
        out.emplace_back(text);
    }
    return true;
}

// True when every address is the all-zero unspecified address, which is what a
// null_ip block rule synthesises.
bool allUnspecified(const std::vector<std::string>& addresses) {
    if (addresses.empty()) return false;
    for (const std::string& address : addresses) {
        if (address == "0.0.0.0" || address == "::") continue;
        return false;
    }
    return true;
}

// Query ids are only used to match a reply to its request, never for caching, so a
// process-wide counter is enough. resolve() overwrites the id for every reply.
uint16_t nextQueryId() {
    static std::atomic<uint16_t> counter{0};
    return ++counter;
}

}  // namespace

Resolver::Resolver(const Config& config, Logger& logger)
    : logger_(logger),
      config_(config),
      rules_(config.rules),
      cache_(config.cacheEntries, config.minTtl, config.maxTtl, config.negativeTtl),
      defaultTarget_(!config.defaultTarget.empty() ? config.defaultTarget : config.defaultUpstream) {

    // Instantiate upstreams
    for (const UpstreamConfig& item : config.upstreams) {
        upstreams_[item.name] = Upstream::create(item, config.upstreamProxy);
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

LookupVerdict Resolver::resolveAddresses(const std::string& name, const std::string& clientIp,
                                        std::vector<std::string>& addresses) {
    addresses.clear();
    // A block rule is honoured without an upstream query, so a blocked name is never
    // contacted. Without this check the null_ip/nxdomain replies would look resolvable.
    const RuleConfig* rule = rules_.find(name, dns::kTypeA);
    if (rule && rule->action == "block") {
        logger_.log(Logger::Level::Debug, "forward proxy refused blocked name " + name + " (" + rule->blockMode + ")");
        return LookupVerdict::Blocked;
    }

    // A "bypass" rule has no meaning for a CONNECT target, so it resolves normally.
    // A "local" rule needs no special case: resolve() already synthesises the static IP.
    for (const uint16_t type : {dns::kTypeA, dns::kTypeAaaa}) {
        const dns::Bytes query = makeQuery(nextQueryId(), name, type);
        if (query.empty()) return LookupVerdict::Failed;
        dns::Query parsed;
        if (!dns::parseQuery(query, parsed)) return LookupVerdict::Failed;
        const dns::Bytes reply = resolve(query, parsed, clientIp);
        if (reply.empty()) return LookupVerdict::Blocked;  // block_mode "drop"
        uint8_t rcode = dns::kRcodeNoError;
        if (!dns::responseCode(reply, rcode)) return LookupVerdict::Failed;
        if (rcode == dns::kRcodeNxDomain || rcode == dns::kRcodeRefused) {
            if (addresses.empty()) return LookupVerdict::NotFound;
            break;
        }
        if (rcode != dns::kRcodeNoError) return LookupVerdict::Failed;
        std::vector<std::string> found;
        if (!collectAddresses(reply, type, found)) return LookupVerdict::Failed;
        if (allUnspecified(found)) return LookupVerdict::Blocked;  // block_mode "null_ip"
        addresses.insert(addresses.end(), found.begin(), found.end());
    }
    return addresses.empty() ? LookupVerdict::NotFound : LookupVerdict::Allowed;
}
