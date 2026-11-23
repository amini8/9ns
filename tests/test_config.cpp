// Config parsing, validation, round-trip and legacy NextDNS rejection.
// Offline only: everything happens inside a QTemporaryDir.

#include <QtTest/QtTest>

#include <QTemporaryDir>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "core/Config.h"

namespace {

std::string readFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

void writeFile(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

}  // namespace

class TestConfig : public QObject {
    Q_OBJECT

private slots:
    void defaultConfigIsValidAndRoundTrips();
    void everyRemainingProtocolRoundTrips();
    void poolsAndRulesRoundTrip();
    void proxyBlocksRoundTrip();
    void proxyDefaultsAreOffAndOmitted();
    void proxyValidationRejectsBadValues();
    void upstreamProxyRefusesLeakingTransports();
    void missingFileYieldsDefaults();
    void invalidJsonThrows();
    void nextDnsTypeIsRejectedEvenWithStamp();
    void nextDnsTypeIsRejectedWhenUnused();
    void legacyNextDnsKeysAreRejectedEvenWhenEmptyOrNull();
    void staleTypeListMentionsOdohAndDoq();
    void exampleConfigHasNoNextDns();
    void renameUpdatesAllAliases();
    void renameKeepsUnrelatedReferences();
    void interfaceBoundRulesAreRejectedByName();
    void interfaceBoundRulesBlockLoadAndSave();
};

void TestConfig::defaultConfigIsValidAndRoundTrips() {
    const Config config = defaultConfig();
    QVERIFY(!config.upstreams.empty());
    validateConfig(config);  // must not throw

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";

    saveConfig(path, config);
    const Config loaded = loadConfig(path);
    QCOMPARE(loaded.defaultTarget, config.defaultTarget);
    QCOMPARE(loaded.upstreams.size(), config.upstreams.size());
    QCOMPARE(loaded.upstreams.front().name, config.upstreams.front().name);
    QCOMPARE(loaded.upstreams.front().type, config.upstreams.front().type);
    QCOMPARE(loaded.upstreams.front().address, config.upstreams.front().address);
}

void TestConfig::everyRemainingProtocolRoundTrips() {
    const std::vector<std::string> types = {"plain", "doh", "dot", "dnscrypt", "odoh", "doq"};
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    for (const std::string& type : types) {
        Config config;
        UpstreamConfig up;
        up.name = "up-" + type;
        up.type = type;
        up.address = (type == "plain") ? "8.8.8.8" : (type == "dot") ? "8.8.8.8" : "https://example.test/dns-query";
        if (type == "dnscrypt") {
            up.stamp = "sdns://AQAAAAAAAAAAAAAAAAAAAAA";  // placeholder, validate does not parse stamps
        }
        config.upstreams.push_back(up);
        config.defaultTarget = up.name;
        config.defaultUpstream = up.name;
        validateConfig(config);

        const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / (type + ".json");
        saveConfig(path, config);
        const Config loaded = loadConfig(path);
        QCOMPARE(loaded.upstreams.size(), size_t(1));
        QCOMPARE(loaded.upstreams.front().type, type);
    }
}

void TestConfig::proxyBlocksRoundTrip() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "proxy.json";

    Config config = defaultConfig();
    config.forwardProxy.enabled = true;
    config.forwardProxy.port = 1081;
    config.forwardProxy.username = "user";
    config.forwardProxy.password = "secret";
    config.upstreamProxy.enabled = true;
    config.upstreamProxy.type = "http";
    config.upstreamProxy.address = "proxy.corp.test";
    config.upstreamProxy.port = 8080;
    config.upstreamProxy.username = "user";
    config.upstreamProxy.password = "secret";
    validateConfig(config);
    saveConfig(path, config);

    const Config loaded = loadConfig(path);
    QVERIFY(loaded.forwardProxy.enabled);
    QCOMPARE(loaded.forwardProxy.port, uint16_t(1081));
    QCOMPARE(loaded.forwardProxy.username, std::string("user"));
    QCOMPARE(loaded.forwardProxy.password, std::string("secret"));
    QVERIFY(loaded.upstreamProxy.enabled);
    QCOMPARE(loaded.upstreamProxy.type, std::string("http"));
    QCOMPARE(loaded.upstreamProxy.address, std::string("proxy.corp.test"));
    QCOMPARE(loaded.upstreamProxy.port, uint16_t(8080));
}

void TestConfig::proxyDefaultsAreOffAndOmitted() {
    // A default config must not gain proxy keys, so existing installs are unaffected.
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "default.json";
    Config config = defaultConfig();
    validateConfig(config);
    saveConfig(path, config);
    const std::string text = readFile(path);
    QVERIFY(text.find("forward_proxy") == std::string::npos);
    QVERIFY(text.find("upstream_proxy") == std::string::npos);
    QVERIFY(!loadConfig(path).forwardProxy.enabled);
    QVERIFY(!loadConfig(path).upstreamProxy.enabled);
}

void TestConfig::proxyValidationRejectsBadValues() {
    // The proxy port must not collide with the DNS listener.
    Config collision = defaultConfig();
    collision.forwardProxy.enabled = true;
    collision.forwardProxy.port = collision.listenPort;
    QVERIFY_EXCEPTION_THROWN(validateConfig(collision), std::runtime_error);

    // Half-set credentials are a configuration error, not a silent downgrade to no auth.
    Config halfCredentials = defaultConfig();
    halfCredentials.forwardProxy.username = "user";
    QVERIFY_EXCEPTION_THROWN(validateConfig(halfCredentials), std::runtime_error);

    Config halfUpstream = defaultConfig();
    halfUpstream.upstreamProxy.password = "secret";
    QVERIFY_EXCEPTION_THROWN(validateConfig(halfUpstream), std::runtime_error);

    Config badType = defaultConfig();
    badType.upstreamProxy.type = "socks4";
    QVERIFY_EXCEPTION_THROWN(validateConfig(badType), std::runtime_error);

    Config emptyAddress = defaultConfig();
    emptyAddress.upstreamProxy.enabled = true;
    emptyAddress.upstreamProxy.type = "socks5";
    QVERIFY_EXCEPTION_THROWN(validateConfig(emptyAddress), std::runtime_error);

    Config zeroPort = defaultConfig();
    zeroPort.forwardProxy.enabled = true;
    zeroPort.forwardProxy.port = 0;
    QVERIFY_EXCEPTION_THROWN(validateConfig(zeroPort), std::runtime_error);
}

void TestConfig::upstreamProxyRefusesLeakingTransports() {
    // Fail closed: a transport that would bypass the corporate proxy is a leak, not a warning.
    Config config = defaultConfig();
    config.upstreams.clear();
    UpstreamConfig doq;
    doq.name = "leaky";
    doq.type = "doq";
    doq.address = "quic.example.test";
    config.upstreams.push_back(doq);
    config.defaultTarget = doq.name;
    config.defaultUpstream = doq.name;
    config.upstreamProxy.enabled = true;
    config.upstreamProxy.type = "socks5";
    config.upstreamProxy.address = "proxy.corp.test";
    config.upstreamProxy.port = 1080;
    QVERIFY_EXCEPTION_THROWN(validateConfig(config), std::runtime_error);

    // DoH needs an HTTP proxy: WinHTTP has no SOCKS support.
    Config socksDoh = defaultConfig();
    socksDoh.upstreams.clear();
    UpstreamConfig doh;
    doh.name = "doh";
    doh.type = "doh";
    doh.address = "https://example.test/dns-query";
    socksDoh.upstreams.push_back(doh);
    socksDoh.defaultTarget = doh.name;
    socksDoh.defaultUpstream = doh.name;
    socksDoh.upstreamProxy.enabled = true;
    socksDoh.upstreamProxy.type = "socks5";
    socksDoh.upstreamProxy.address = "proxy.corp.test";
    socksDoh.upstreamProxy.port = 1080;
    QVERIFY_EXCEPTION_THROWN(validateConfig(socksDoh), std::runtime_error);

    // The same DoH upstream is accepted once the proxy is HTTP.
    socksDoh.upstreamProxy.type = "http";
    validateConfig(socksDoh);
}

void TestConfig::poolsAndRulesRoundTrip() {    Config config = defaultConfig();

    PoolConfig pool;
    pool.name = "fast-pool";
    pool.strategy = "failover";
    pool.servers = {config.upstreams.front().name};
    config.pools.push_back(pool);
    config.defaultTarget = pool.name;
    config.defaultUpstream = pool.name;

    RuleConfig rule;
    rule.name = "block-ads";
    rule.hostnames = {"ads.example.com", "*.doubleclick.net"};
    rule.action = "block";
    rule.blockMode = "null_ip";
    config.rules.push_back(rule);

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";
    saveConfig(path, config);

    const Config loaded = loadConfig(path);
    QCOMPARE(loaded.pools.size(), size_t(1));
    QCOMPARE(loaded.pools.front().name, pool.name);
    QCOMPARE(loaded.pools.front().servers, pool.servers);
    QCOMPARE(loaded.rules.size(), size_t(1));
    QCOMPARE(loaded.rules.front().action, rule.action);
    QCOMPARE(loaded.rules.front().blockMode, rule.blockMode);
    QCOMPARE(loaded.rules.front().hostnames, rule.hostnames);
}

void TestConfig::missingFileYieldsDefaults() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "absent.json";
    const Config loaded = loadConfig(path);
    QCOMPARE(loaded.defaultTarget, defaultConfig().defaultTarget);
}

void TestConfig::invalidJsonThrows() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";
    writeFile(path, "{not json");
    QVERIFY_EXCEPTION_THROWN(loadConfig(path), std::runtime_error);
}

void TestConfig::nextDnsTypeIsRejectedEvenWithStamp() {
    Config config;
    UpstreamConfig up;
    up.name = "legacy-nextdns";
    up.type = "nextdns";
    up.stamp = "sdns://AQAAAAAAAAAAAAAAAAAAAAA";  // stamp must not rescue a removed protocol
    config.upstreams.push_back(up);
    config.defaultTarget = up.name;
    config.defaultUpstream = up.name;

    try {
        validateConfig(config);
        QFAIL("validateConfig accepted a nextdns upstream");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("legacy-nextdns") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("NextDNS") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("removed") != std::string::npos, msg.c_str());
    }
}

void TestConfig::nextDnsTypeIsRejectedWhenUnused() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";
    // nextdns is present as an upstream but not the default target and not referenced by rules.
    writeFile(path, R"({
        "default_target": "ok",
        "upstreams": [
            {"name": "ok", "type": "plain", "address": "8.8.8.8"},
            {"name": "unused-nextdns", "type": "nextdns", "address": "https://dns.nextdns.io"}
        ]
    })");
    try {
        loadConfig(path);
        QFAIL("loadConfig accepted an unused nextdns upstream");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("unused-nextdns") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("NextDNS") != std::string::npos, msg.c_str());
    }
}

void TestConfig::legacyNextDnsKeysAreRejectedEvenWhenEmptyOrNull() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";

    const char* variants[] = {
        R"("nextdns_id": "abc", "nextdns_device": "pc")",
        R"("nextdns_id": "", "nextdns_device": "")",
        R"("nextdns_id": null, "nextdns_device": null)",
        R"("nextdns_id": "abc")",
        R"("nextdns_device": "pc")",
    };
    for (const char* legacy : variants) {
        std::string text = R"({"default_target": "ok", "upstreams": [{"name": "ok", "type": "plain", "address": "8.8.8.8", )";
        text += legacy;
        text += R"(}]})";
        writeFile(path, text);
        try {
            loadConfig(path);
            QFAIL("loadConfig accepted legacy nextdns keys");
        } catch (const std::runtime_error& e) {
            const std::string msg = e.what();
            QVERIFY2(msg.find("nextdns") != std::string::npos, msg.c_str());
            QVERIFY2(msg.find("removed") != std::string::npos, msg.c_str());
        }
    }
}

void TestConfig::staleTypeListMentionsOdohAndDoq() {
    Config config;
    UpstreamConfig up;
    up.name = "broken";
    up.type = "bogus";
    config.upstreams.push_back(up);
    config.defaultTarget = up.name;
    config.defaultUpstream = up.name;
    try {
        validateConfig(config);
        QFAIL("validateConfig accepted a bogus type");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("odoh") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("doq") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("nextdns") == std::string::npos, msg.c_str());
    }
}

void TestConfig::exampleConfigHasNoNextDns() {
    const std::string text = readFile(NS9_SOURCE_DIR "/src/config/config.example.json");
    QVERIFY2(text.find("nextdns") == std::string::npos,
             "config.example.json must not advertise the removed NextDNS protocol");
    // The example must still parse and validate.
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";
    writeFile(path, text);
    const Config loaded = loadConfig(path);
    validateConfig(loaded);
}

void TestConfig::renameUpdatesAllAliases() {
    Config config;
    UpstreamConfig up;
    up.name = "old-name";
    up.type = "plain";
    up.address = "8.8.8.8";
    config.upstreams.push_back(up);
    config.defaultTarget = "old-name";
    config.defaultUpstream = "old-name";

    PoolConfig pool;
    pool.name = "pool";
    pool.strategy = "failover";
    pool.servers = {"old-name"};
    config.pools.push_back(pool);

    RuleConfig rule;
    rule.name = "r";
    rule.hostnames = {"x.example"};
    rule.action = "process";
    rule.target = "old-name";
    config.rules.push_back(rule);

    renameTargetReferences(config, "old-name", "new-name");

    QCOMPARE(config.defaultTarget, std::string("new-name"));
    QCOMPARE(config.defaultUpstream, std::string("new-name"));
    QCOMPARE(config.pools.front().servers.front(), std::string("new-name"));
    QCOMPARE(config.rules.front().target, std::string("new-name"));
    config.upstreams.front().name = "new-name";
    validateConfig(config);  // the rewritten config must still be valid
}

void TestConfig::renameKeepsUnrelatedReferences() {
    Config config;
    UpstreamConfig a;
    a.name = "a";
    a.type = "plain";
    a.address = "8.8.8.8";
    UpstreamConfig b;
    b.name = "b";
    b.type = "plain";
    b.address = "9.9.9.9";
    config.upstreams = {a, b};
    config.defaultTarget = "b";
    config.defaultUpstream = "b";

    RuleConfig rule;
    rule.name = "r";
    rule.hostnames = {"x.example"};
    rule.action = "process";
    rule.target = "b";
    config.rules.push_back(rule);

    renameTargetReferences(config, "a", "a-renamed");

    QCOMPARE(config.defaultTarget, std::string("b"));
    QCOMPARE(config.rules.front().target, std::string("b"));
}

void TestConfig::interfaceBoundRulesAreRejectedByName() {
    Config config = defaultConfig();
    RuleConfig rule;
    rule.name = "scoped-rule";
    rule.hostnames = {"example.com"};
    rule.interfaceGuid = "{some-guid}";
    config.rules.push_back(rule);

    try {
        validateConfig(config);
        QFAIL("validateConfig accepted an interface-bound rule");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("scoped-rule") != std::string::npos, msg.c_str());
        QVERIFY2(msg.find("interface-bound rules are not supported") != std::string::npos, msg.c_str());
    }

    // An unnamed rule is identified by its pattern.
    Config unnamed = defaultConfig();
    RuleConfig anonymous;
    anonymous.pattern = "*.example.org";
    anonymous.interfaceGuid = "{some-guid}";
    unnamed.rules.push_back(anonymous);
    try {
        validateConfig(unnamed);
        QFAIL("validateConfig accepted an unnamed interface-bound rule");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("*.example.org") != std::string::npos, msg.c_str());
    }
}

void TestConfig::interfaceBoundRulesBlockLoadAndSave() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = std::filesystem::path(dir.path().toStdString()) / "config.json";

    // Loading a config with an interface binding is rejected.
    writeFile(path, R"({
        "default_target": "ok",
        "upstreams": [{"name": "ok", "type": "plain", "address": "8.8.8.8"}],
        "rules": [{"name": "scoped", "hostnames": ["example.com"], "interface_guid": "{g}"}]
    })");
    try {
        loadConfig(path);
        QFAIL("loadConfig accepted an interface-bound rule");
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        QVERIFY2(msg.find("scoped") != std::string::npos, msg.c_str());
    }

    // Saving is rejected the same way, so the binding cannot persist.
    Config config = defaultConfig();
    RuleConfig rule;
    rule.name = "scoped";
    rule.hostnames = {"example.com"};
    rule.interfaceGuid = "{g}";
    config.rules.push_back(rule);
    QVERIFY_EXCEPTION_THROWN(saveConfig(path, config), std::runtime_error);
}

QTEST_GUILESS_MAIN(TestConfig)
#include "test_config.moc"
