#include "core/Config.h"
#include "transports/Stamp.h"

#include <cstdint>
#include <fstream>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

const std::set<std::string> kUpstreamTypes = {"plain", "doh", "dot", "dnscrypt", "odoh", "doq"};
const std::set<std::string> kActions = {"block", "forward", "process", "bypass", "local"};
const std::set<std::string> kBlockModes = {"nxdomain", "null_ip", "refused", "drop"};
const std::set<std::string> kPoolStrategies = {"failover", "round_robin", "fastest", "random"};
const std::set<std::string> kLogLevels = {"error", "info", "debug"};

constexpr std::size_t kMaxCacheEntries = 1000000;

// Diagnostic reused whenever a config still refers to the removed NextDNS support.
const char* kNextDnsRemoved =
    "the NextDNS protocol was removed from 9NS; choose and configure a supported "
    "replacement upstream (plain, doh, dot, dnscrypt, odoh or doq)";

std::string upstreamLabel(const json& item) {
    if (item.contains("name") && item["name"].is_string()) {
        return item["name"].get<std::string>();
    }
    return "(unnamed)";
}

std::string ruleLabel(const RuleConfig& rule) {
    if (!rule.name.empty()) {
        return rule.name;
    }
    if (!rule.pattern.empty()) {
        return rule.pattern;
    }
    if (!rule.hostnames.empty()) {
        return rule.hostnames.front();
    }
    return "(unnamed)";
}

UpstreamConfig parseUpstream(const json& item) {
    if (!item.is_object()) {
        throw std::runtime_error("each upstream must be a JSON object");
    }
    if (item.contains("nextdns_id") || item.contains("nextdns_device")) {
        throw std::runtime_error("upstream '" + upstreamLabel(item) + "': " + kNextDnsRemoved +
                                 " (remove the nextdns_id/nextdns_device keys)");
    }
    UpstreamConfig up;
    up.name = item.at("name").get<std::string>();
    up.type = item.value("type", std::string());
    up.address = item.value("address", std::string());
    up.stamp = item.value("stamp", std::string());
    up.proxy = item.value("proxy", std::string());
    up.port = static_cast<uint16_t>(item.value("port", 0));
    up.sni = item.value("sni", std::string());
    up.tlsVerify = item.value("tls_verify", true);
    if (up.type == "nextdns") {
        throw std::runtime_error("upstream '" + up.name + "': " + kNextDnsRemoved);
    }

    if (item.contains("bootstrap_ips") && item["bootstrap_ips"].is_array()) {
        for (const auto& ip : item["bootstrap_ips"]) {
            if (ip.is_string() && !ip.get<std::string>().empty()) {
                up.bootstrapIps.push_back(ip.get<std::string>());
            }
        }
    }
    return up;
}

PoolConfig parsePool(const json& item) {
    if (!item.is_object()) {
        throw std::runtime_error("each pool must be a JSON object");
    }
    PoolConfig pool;
    pool.name = item.at("name").get<std::string>();
    pool.strategy = item.value("strategy", "failover");
    if (item.contains("servers") && item["servers"].is_array()) {
        for (const auto& s : item["servers"]) {
            if (s.is_string()) {
                pool.servers.push_back(s.get<std::string>());
            }
        }
    }
    return pool;
}

RuleConfig parseRule(const json& item) {
    if (!item.is_object()) {
        throw std::runtime_error("each rule must be a JSON object");
    }
    RuleConfig rule;
    rule.name = item.value("name", std::string());
    rule.action = item.value("action", "process");
    rule.blockMode = item.value("block_mode", "nxdomain");
    rule.target = item.value("target", std::string());
    rule.upstream = item.value("upstream", std::string());
    if (rule.target.empty() && !rule.upstream.empty()) {
        rule.target = rule.upstream;
    }
    rule.localIp = item.value("local_ip", std::string());
    rule.interfaceGuid = item.value("interface_guid", std::string());
    rule.queryType = item.value("query_type", std::string());
    rule.dnssecMode = item.value("dnssec_mode", "default");
    rule.hostsFile = item.value("hosts_file", std::string());

    if (item.contains("hostnames") && item["hostnames"].is_array()) {
        for (const auto& h : item["hostnames"]) {
            if (h.is_string() && !h.get<std::string>().empty()) {
                rule.hostnames.push_back(h.get<std::string>());
            }
        }
    }
    rule.pattern = item.value("pattern", std::string());
    if (rule.hostnames.empty() && !rule.pattern.empty()) {
        rule.hostnames.push_back(rule.pattern);
    }
    if (rule.name.empty()) {
        rule.name = !rule.hostnames.empty() ? rule.hostnames.front() : "Rule";
    }
    return rule;
}

void checkProxyObject(const json& item, const std::string& name, const std::set<std::string>& keys) {
    if (!item.is_object()) {
        throw std::runtime_error(name + " must be a JSON object");
    }
    for (auto it = item.begin(); it != item.end(); ++it) {
        if (keys.count(it.key()) == 0) {
            throw std::runtime_error(name + ": unknown option '" + it.key() + "'");
        }
    }
}

uint16_t proxyPort(const json& item, uint16_t fallback, const std::string& name) {
    if (!item.contains("port")) {
        return fallback;
    }
    const auto& value = item.at("port");
    if (!value.is_number_integer() || (value.is_number_unsigned() && value.get<uint64_t>() > 65535)) {
        throw std::runtime_error(name + ".port must be an integer between 0 and 65535");
    }
    const auto port = value.get<int64_t>();
    if (port < 0 || port > 65535) {
        throw std::runtime_error(name + ".port must be between 0 and 65535");
    }
    return static_cast<uint16_t>(port);
}

void validateCredentials(const std::string& username, const std::string& password, const std::string& name) {
    if (username.empty() != password.empty() || username.size() > 255 || password.size() > 255) {
        throw std::runtime_error(name + ": username and password must be paired and at most 255 bytes each");
    }
    if (username.find('\0') != std::string::npos || password.find('\0') != std::string::npos) {
        throw std::runtime_error(name + ": credentials must not contain NUL");
    }
}

Config fromJson(const json& root) {
    if (!root.is_object()) {
        throw std::runtime_error("the config must be a JSON object");
    }
    const Config defaults = defaultConfig();
    Config config;

    const long long port = root.value("listen_port", static_cast<long long>(defaults.listenPort));
    if (port < 1 || port > 65535) {
        throw std::runtime_error("listen_port must be between 1 and 65535");
    }
    config.listenPort = static_cast<uint16_t>(port);

    const long long cache = root.value("cache_entries", static_cast<long long>(defaults.cacheEntries));
    if (cache < 0) {
        throw std::runtime_error("cache_entries must not be negative");
    }
    config.cacheEntries = static_cast<std::size_t>(cache);

    config.minTtl = static_cast<uint32_t>(root.value("min_ttl", defaults.minTtl));
    config.maxTtl = static_cast<uint32_t>(root.value("max_ttl", defaults.maxTtl));
    config.negativeTtl = static_cast<uint32_t>(root.value("negative_ttl", defaults.negativeTtl));
    config.systemDns = root.value("system_dns", defaults.systemDns);
    config.ipv6Loopback = root.value("ipv6_loopback", defaults.ipv6Loopback);
    config.preventDnsLeaks = root.value("prevent_dns_leaks", defaults.preventDnsLeaks);
    config.dnssecValidation = root.value("dnssec_validation", defaults.dnssecValidation);
    config.autostart = root.value("autostart", defaults.autostart);
    config.closeToTray = root.value("close_to_tray", defaults.closeToTray);
    if (root.contains("forward_proxy")) {
        const auto& item = root.at("forward_proxy");
        checkProxyObject(item, "forward_proxy", {"enabled", "port", "username", "password"});
        config.forwardProxy.enabled = item.value("enabled", false);
        config.forwardProxy.port = proxyPort(item, 1080, "forward_proxy");
        config.forwardProxy.username = item.value("username", std::string());
        config.forwardProxy.password = item.value("password", std::string());
    }
    if (root.contains("upstream_proxy")) {
        const auto& item = root.at("upstream_proxy");
        checkProxyObject(item, "upstream_proxy", {"enabled", "type", "address", "port", "username", "password"});
        config.upstreamProxy.enabled = item.value("enabled", false);
        config.upstreamProxy.type = item.value("type", std::string("socks5"));
        config.upstreamProxy.address = item.value("address", std::string());
        config.upstreamProxy.port = proxyPort(item, 0, "upstream_proxy");
        config.upstreamProxy.username = item.value("username", std::string());
        config.upstreamProxy.password = item.value("password", std::string());
    }

    config.defaultTarget = root.value("default_target", root.value("default_upstream", defaults.defaultTarget));
    config.defaultUpstream = config.defaultTarget;
    config.logFile = root.value("log_file", defaults.logFile);
    config.logLevel = root.value("log_level", defaults.logLevel);

    const json upstreams = root.value("upstreams", json::array());
    if (!upstreams.is_array()) {
        throw std::runtime_error("upstreams must be an array");
    }
    for (const json& item : upstreams) {
        config.upstreams.push_back(parseUpstream(item));
    }

    const json pools = root.value("pools", json::array());
    if (pools.is_array()) {
        for (const json& item : pools) {
            config.pools.push_back(parsePool(item));
        }
    }

    const json rules = root.value("rules", json::array());
    if (!rules.is_array()) {
        throw std::runtime_error("rules must be an array");
    }
    for (const json& item : rules) {
        config.rules.push_back(parseRule(item));
    }
    return config;
}

json toJson(const Config& config) {
    json upstreams = json::array();
    for (const UpstreamConfig& up : config.upstreams) {
        json item = {{"name", up.name}, {"type", up.type}, {"address", up.address}};
        if (!up.stamp.empty()) {
            item["stamp"] = up.stamp;
        }
        if (!up.proxy.empty()) {
            item["proxy"] = up.proxy;
        }
        if (up.port != 0) {
            item["port"] = up.port;
        }
        if (!up.bootstrapIps.empty()) {
            item["bootstrap_ips"] = up.bootstrapIps;
        }
        if (!up.sni.empty()) {
            item["sni"] = up.sni;
        }
        if (!up.tlsVerify) {
            item["tls_verify"] = false;
        }
        upstreams.push_back(item);
    }

    json pools = json::array();
    for (const PoolConfig& pool : config.pools) {
        pools.push_back({
            {"name", pool.name},
            {"strategy", pool.strategy},
            {"servers", pool.servers}
        });
    }

    json rules = json::array();
    for (const RuleConfig& rule : config.rules) {
        json item = {
            {"name", rule.name},
            {"action", rule.action},
            {"block_mode", rule.blockMode}
        };
        if (!rule.hostnames.empty()) {
            item["hostnames"] = rule.hostnames;
            item["pattern"] = rule.hostnames.front();
        } else if (!rule.pattern.empty()) {
            item["pattern"] = rule.pattern;
            item["hostnames"] = {rule.pattern};
        }
        if (!rule.target.empty()) {
            item["target"] = rule.target;
            item["upstream"] = rule.target;
        }
        if (!rule.localIp.empty()) {
            item["local_ip"] = rule.localIp;
        }
        if (!rule.interfaceGuid.empty()) {
            item["interface_guid"] = rule.interfaceGuid;
        }
        if (!rule.queryType.empty()) {
            item["query_type"] = rule.queryType;
        }
        if (rule.dnssecMode != "default") {
            item["dnssec_mode"] = rule.dnssecMode;
        }
        if (!rule.hostsFile.empty()) {
            item["hosts_file"] = rule.hostsFile;
        }
        rules.push_back(item);
    }

    json result = {
        {"listen_port", config.listenPort},
        {"cache_entries", config.cacheEntries},
        {"min_ttl", config.minTtl},
        {"max_ttl", config.maxTtl},
        {"negative_ttl", config.negativeTtl},
        {"system_dns", config.systemDns},
        {"ipv6_loopback", config.ipv6Loopback},
        {"prevent_dns_leaks", config.preventDnsLeaks},
        {"dnssec_validation", config.dnssecValidation},
        {"autostart", config.autostart},
        {"close_to_tray", config.closeToTray},
        {"default_target", config.defaultTarget},
        {"default_upstream", config.defaultTarget},
        {"upstreams", upstreams},
        {"pools", pools},
        {"rules", rules},
        {"log_file", config.logFile},
        {"log_level", config.logLevel},
    };
    json forward = json::object();
    if (config.forwardProxy.enabled) forward["enabled"] = true;
    if (config.forwardProxy.port != 1080) forward["port"] = config.forwardProxy.port;
    if (!config.forwardProxy.username.empty()) forward["username"] = config.forwardProxy.username;
    if (!config.forwardProxy.password.empty()) forward["password"] = config.forwardProxy.password;
    if (!forward.empty()) result["forward_proxy"] = std::move(forward);
    json upstream = json::object();
    if (config.upstreamProxy.enabled) upstream["enabled"] = true;
    if (config.upstreamProxy.type != "socks5") upstream["type"] = config.upstreamProxy.type;
    if (!config.upstreamProxy.address.empty()) upstream["address"] = config.upstreamProxy.address;
    if (config.upstreamProxy.port != 0) upstream["port"] = config.upstreamProxy.port;
    if (!config.upstreamProxy.username.empty()) upstream["username"] = config.upstreamProxy.username;
    if (!config.upstreamProxy.password.empty()) upstream["password"] = config.upstreamProxy.password;
    if (!upstream.empty()) result["upstream_proxy"] = std::move(upstream);
    return result;
}

}  // namespace

std::vector<UpstreamConfig> publicDnsPresets() {
    return {
        {"cloudflare-doh", "doh", "https://cloudflare-dns.com/dns-query", "", 443, {"1.1.1.1", "1.0.0.1"}, "cloudflare-dns.com", true},
        {"cloudflare-dot", "dot", "1.1.1.1", "", 853, {"1.1.1.1"}, "cloudflare-dns.com", true},
        {"google-doh", "doh", "https://dns.google/dns-query", "", 443, {"8.8.8.8", "8.8.4.4"}, "dns.google", true},
        {"google-dot", "dot", "8.8.8.8", "", 853, {"8.8.8.8"}, "dns.google", true},
        {"quad9-doh", "doh", "https://dns.quad9.net/dns-query", "", 443, {"9.9.9.9", "149.112.112.112"}, "dns.quad9.net", true},
        {"quad9-dot", "dot", "9.9.9.9", "", 853, {"9.9.9.9"}, "dns.quad9.net", true},
        {"adguard-doh", "doh", "https://dns.adguard-dns.com/dns-query", "", 443, {"94.140.14.14"}, "dns.adguard-dns.com", true}
    };
}

Config defaultConfig() {
    Config config;
    config.upstreams.push_back({"cloudflare-doh", "doh", "https://cloudflare-dns.com/dns-query", "", 443, {"1.1.1.1", "1.0.0.1"}, "cloudflare-dns.com", true});
    config.defaultTarget = "cloudflare-doh";
    config.defaultUpstream = "cloudflare-doh";
    config.logFile = "9ns.log";
    return config;
}

void validateConfig(const Config& config) {
    if (config.listenPort == 0) {
        throw std::runtime_error("listen_port must be between 1 and 65535");
    }
    if (config.forwardProxy.port == 0 || config.forwardProxy.port == config.listenPort) {
        throw std::runtime_error("forward_proxy.port must be nonzero and distinct from listen_port");
    }
    validateCredentials(config.forwardProxy.username, config.forwardProxy.password, "forward_proxy");
    validateCredentials(config.upstreamProxy.username, config.upstreamProxy.password, "upstream_proxy");
    if (config.upstreamProxy.type != "socks5" && config.upstreamProxy.type != "http") {
        throw std::runtime_error("upstream_proxy.type must be socks5 or http");
    }
    if (config.upstreamProxy.enabled && (config.upstreamProxy.address.empty() || config.upstreamProxy.port == 0)) {
        throw std::runtime_error("upstream_proxy requires a nonempty address and nonzero port when enabled");
    }
    for (const unsigned char c : config.upstreamProxy.address) {
        if (c <= 32 || c >= 127 || c == '/' || c == '\\' || c == ';' || c == '=' || c == '@' || c == '?' || c == '#') {
            throw std::runtime_error("upstream_proxy.address must be a hostname or IP literal, not a URL or proxy list");
        }
    }
    if (config.upstreamProxy.type == "http" && config.upstreamProxy.username.find(':') != std::string::npos) {
        throw std::runtime_error("upstream_proxy.username must not contain ':' for HTTP Basic authentication");
    }
    if (config.cacheEntries > kMaxCacheEntries) {
        throw std::runtime_error("cache_entries must be at most 1000000");
    }
    if (kLogLevels.count(config.logLevel) == 0) {
        throw std::runtime_error("log_level must be error, info or debug");
    }
    if (config.upstreams.empty()) {
        throw std::runtime_error("at least one upstream is required");
    }

    std::set<std::string> upstreamNames;
    for (const UpstreamConfig& up : config.upstreams) {
        if (up.name.empty()) {
            throw std::runtime_error("every upstream needs a name");
        }
        if (!upstreamNames.insert(up.name).second) {
            throw std::runtime_error("duplicate upstream name '" + up.name + "'");
        }
        if (up.type == "nextdns") {
            throw std::runtime_error("upstream '" + up.name + "': " + std::string(kNextDnsRemoved));
        }
        if (config.upstreamProxy.enabled) {
            std::string transport = up.type;
            if (!up.stamp.empty()) {
                DnsStamp stamp;
                std::string error;
                if (!parseStamp(up.stamp, stamp, error)) {
                    throw std::runtime_error("upstream '" + up.name + "': " + error);
                }
                transport = stamp.protocol == DnsStamp::Protocol::DoH ? "doh" :
                            stamp.protocol == DnsStamp::Protocol::Odoh ? "odoh" : "unsupported";
            }
            if (transport != "plain" && transport != "dot" && transport != "doh" && transport != "odoh") {
                throw std::runtime_error("upstream '" + up.name + "': transport is not supported with upstream_proxy (DoQ and DNSCrypt/relays are disabled)");
            }
            if (config.upstreamProxy.type == "socks5" && (transport == "doh" || transport == "odoh")) {
                throw std::runtime_error("upstream '" + up.name + "': DoH/ODoH require an HTTP upstream_proxy, not SOCKS5");
            }
        }
        if (up.stamp.empty()) {
            if (kUpstreamTypes.count(up.type) == 0) {
                throw std::runtime_error("upstream '" + up.name +
                                         "': type must be plain, doh, dot, dnscrypt, odoh or doq");
            }
            if (up.address.empty()) {
                throw std::runtime_error("upstream '" + up.name + "': address is required");
            }
        }
    }

    std::set<std::string> poolNames;
    for (const PoolConfig& pool : config.pools) {
        if (pool.name.empty()) {
            throw std::runtime_error("every pool needs a name");
        }
        if (upstreamNames.count(pool.name) > 0 || !poolNames.insert(pool.name).second) {
            throw std::runtime_error("duplicate pool or collision with upstream name '" + pool.name + "'");
        }
        if (kPoolStrategies.count(pool.strategy) == 0) {
            throw std::runtime_error("pool '" + pool.name + "': strategy must be failover, round_robin, fastest or random");
        }
        if (pool.servers.empty()) {
            throw std::runtime_error("pool '" + pool.name + "' must have at least one server");
        }
        for (const std::string& s : pool.servers) {
            if (upstreamNames.count(s) == 0) {
                throw std::runtime_error("pool '" + pool.name + "' references unknown upstream '" + s + "'");
            }
        }
    }

    const std::string defaultTarget = !config.defaultTarget.empty() ? config.defaultTarget : config.defaultUpstream;
    if (upstreamNames.count(defaultTarget) == 0 && poolNames.count(defaultTarget) == 0) {
        throw std::runtime_error("default target '" + defaultTarget + "' must name one of the upstreams or pools");
    }

    for (const RuleConfig& rule : config.rules) {
        if (!rule.interfaceGuid.empty()) {
            throw std::runtime_error("rule '" + ruleLabel(rule) +
                                     "': interface-bound rules are not supported by the loopback proxy");
        }
        if (rule.hostnames.empty() && rule.pattern.empty() && rule.hostsFile.empty()) {
            throw std::runtime_error("every rule needs at least one hostname, pattern or hosts file");
        }
        if (kActions.count(rule.action) == 0) {
            throw std::runtime_error("rule '" + rule.name + "': action must be process, block, bypass or local");
        }
        if (rule.action == "block" && kBlockModes.count(rule.blockMode) == 0) {
            throw std::runtime_error("rule '" + rule.name + "': block_mode must be nxdomain, null_ip, refused or drop");
        }
        if ((rule.action == "process" || rule.action == "forward")) {
            const std::string target = !rule.target.empty() ? rule.target : rule.upstream;
            if (upstreamNames.count(target) == 0 && poolNames.count(target) == 0) {
                throw std::runtime_error("rule '" + rule.name + "': target needs an existing upstream or pool");
            }
        }
    }
}

void renameTargetReferences(Config& config, const std::string& oldName, const std::string& newName) {
    if (oldName == newName) {
        return;
    }
    if (config.defaultTarget == oldName) {
        config.defaultTarget = newName;
    }
    if (config.defaultUpstream == oldName) {
        config.defaultUpstream = newName;
    }
    for (PoolConfig& pool : config.pools) {
        for (std::string& member : pool.servers) {
            if (member == oldName) {
                member = newName;
            }
        }
    }
    for (RuleConfig& rule : config.rules) {
        if (rule.target == oldName) {
            rule.target = newName;
        }
        if (rule.upstream == oldName) {
            rule.upstream = newName;
        }
    }
}

Config loadConfig(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return defaultConfig();
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open the config file");
    }

    json root;
    try {
        root = json::parse(in);
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("config.json is not valid JSON: ") + e.what());
    }

    try {
        Config config = fromJson(root);
        validateConfig(config);
        return config;
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("config.json: ") + e.what());
    }
}

void saveConfig(const std::filesystem::path& path, const Config& config) {
    validateConfig(config);

    std::string text;
    try {
        text = toJson(config).dump(2);
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("cannot encode the config: ") + e.what());
    }

    std::filesystem::path temp = path;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("cannot write the config file");
        }
        out << text << '\n';
        out.flush();
        if (!out) {
            throw std::runtime_error("cannot write the config file");
        }
    }

    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        throw std::runtime_error("cannot replace the config file: " + ec.message());
    }
}
