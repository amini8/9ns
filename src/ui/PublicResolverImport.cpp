#include "ui/PublicResolverImport.h"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <utility>

#include <QString>

namespace resolvers {

bool resolverCandidate(const PublicDnsItem& item, UpstreamConfig& upstream, std::string& error) {
    error.clear();
    DnsStamp stamp;
    if (!parseStamp(item.stamp, stamp, error)) {
        error = "Resolver '" + item.name + "': " + error;
        return false;
    }
    const char* type = upstreamType(stamp.protocol);
    if (!type) {
        error = "'" + item.name + "' is a relay, not a standalone resolver. Copy its stamp to configure a relay separately.";
        return false;
    }
    const std::string name = QString::fromStdString(item.name).trimmed().toStdString();
    if (name.empty()) {
        error = "Every selected resolver needs a name";
        return false;
    }
    UpstreamConfig result;
    result.name = name;
    result.stamp = item.stamp;
    result.type = type;
    upstream = std::move(result);
    return true;
}

bool importCandidate(const Config& original, const std::vector<PublicDnsItem>& selection,
                     const std::optional<std::string>& poolName, Config& candidate, std::string& error) {
    error.clear();
    if (selection.empty()) {
        error = "Select at least one resolver";
        return false;
    }
    Config result = original;
    std::set<std::string> names;
    for (const auto& upstream : result.upstreams) names.insert(upstream.name);
    for (const auto& pool : result.pools) names.insert(pool.name);
    std::string newPoolName;
    if (poolName) {
        newPoolName = QString::fromStdString(*poolName).trimmed().toStdString();
        if (newPoolName.empty() || !names.insert(newPoolName).second) {
            error = "Pool name '" + newPoolName + "' is empty or already used by a server or pool";
            return false;
        }
    }
    std::set<std::string> stamps;
    std::vector<std::string> members;
    for (const auto& item : selection) {
        UpstreamConfig upstream;
        if (!resolverCandidate(item, upstream, error)) return false;
        if (!stamps.insert(item.stamp).second) continue;
        const auto existing = std::find_if(result.upstreams.begin(), result.upstreams.end(),
                                           [&](const auto& entry) { return entry.stamp == item.stamp; });
        if (existing != result.upstreams.end()) {
            members.push_back(existing->name);
            continue;
        }
        const std::string base = upstream.name;
        int suffix = 1;
        while (!names.insert(upstream.name).second) upstream.name = base + "-" + std::to_string(++suffix);
        members.push_back(upstream.name);
        result.upstreams.push_back(std::move(upstream));
    }
    if (poolName) {
        const std::set<std::string> uniqueMembers(members.begin(), members.end());
        if (uniqueMembers.size() < 2) {
            error = "A pool requires at least two distinct resolvers";
            return false;
        }
        PoolConfig pool;
        pool.name = newPoolName;
        pool.strategy = "fastest";
        pool.servers = std::move(members);
        result.pools.push_back(std::move(pool));
    }
    try {
        validateConfig(result);
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
    candidate = std::move(result);
    return true;
}

}  // namespace resolvers
