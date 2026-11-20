// Dialog ordering and candidate-validation invariants: pool member priority on
// round-trip, rule ordering, and field-to-config round-trip for upstreams.
// Offline only: no widgets, no network, no ProgramData.

#include <QtTest/QtTest>

#include <QTemporaryDir>

#include <filesystem>
#include <string>
#include <vector>

#include "core/Config.h"
#include "ui/PoolDialog.h"
#include "ui/ServerDialog.h"

namespace {

Config makeConfigWithUpstreams(const std::vector<std::string>& names) {
    Config config;
    for (size_t i = 0; i < names.size(); ++i) {
        UpstreamConfig up;
        up.name = names[i];
        up.type = "plain";
        up.address = "10.0.0." + std::to_string(i + 1);
        config.upstreams.push_back(up);
    }
    config.defaultTarget = config.upstreams.front().name;
    return config;
}

std::filesystem::path configPathIn(const QTemporaryDir& dir) {
    return std::filesystem::path(dir.path().toStdString()) / "config.json";
}

}  // namespace

class TestDialogs : public QObject {
    Q_OBJECT

private slots:
    void poolMemberOrderIsPreservedOnRoundTrip();
    void ruleOrderIsPreservedOnRoundTrip();
    void upstreamFieldsSurviveRoundTrip();
};

void TestDialogs::poolMemberOrderIsPreservedOnRoundTrip() {
    Config config = makeConfigWithUpstreams({"alpha", "beta", "gamma"});
    PoolConfig pool;
    pool.name = "failover-pool";
    pool.strategy = "failover";
    // Deliberately not the upstream declaration order: beta has priority 1.
    pool.servers = {"beta", "alpha", "gamma"};
    config.pools.push_back(pool);

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = configPathIn(dir);

    saveConfig(path, config);
    const Config loaded = loadConfig(path);
    QCOMPARE(loaded.pools.size(), size_t(1));
    QCOMPARE(loaded.pools.front().servers, pool.servers);

    // The dialog save path collects checked members in list order and the list
    // starts in saved priority order, so a no-op save cannot reorder the pool.
    std::vector<std::string> upstreamNames;
    for (const auto& u : config.upstreams) {
        upstreamNames.push_back(u.name);
    }
    QCOMPARE(poolMemberListOrder(pool.servers, upstreamNames), pool.servers);

    // New candidates (and members whose upstream is missing) append/keep their
    // slot without disturbing the existing priority.
    PoolConfig partial;
    partial.servers = {"beta", "ghost", "alpha"};
    QCOMPARE(poolMemberListOrder(partial.servers, upstreamNames),
             (std::vector<std::string>{"beta", "ghost", "alpha", "gamma"}));
}

void TestDialogs::ruleOrderIsPreservedOnRoundTrip() {
    Config config = makeConfigWithUpstreams({"alpha", "beta"});

    RuleConfig block;
    block.name = "block-ads";
    block.hostnames = {"*.ads.example"};
    block.action = "block";
    block.blockMode = "nxdomain";

    RuleConfig route;
    route.name = "route-work";
    route.hostnames = {"*.corp.example"};
    route.action = "process";
    route.target = "alpha";

    RuleConfig local;
    local.name = "local-lan";
    local.hostnames = {"*.lan"};
    local.action = "local";
    local.localIp = "10.0.0.9";

    config.rules = {block, route, local};

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const std::filesystem::path path = configPathIn(dir);

    saveConfig(path, config);
    const Config loaded = loadConfig(path);
    QCOMPARE(loaded.rules.size(), size_t(3));
    // First match wins, so the saved order is semantic and must round-trip.
    QCOMPARE(loaded.rules.at(0).name, std::string("block-ads"));
    QCOMPARE(loaded.rules.at(1).name, std::string("route-work"));
    QCOMPARE(loaded.rules.at(2).name, std::string("local-lan"));
}

void TestDialogs::upstreamFieldsSurviveRoundTrip() {
    UpstreamConfig u;
    u.name = "example";
    u.type = "dot";
    u.address = "dot.example.com";
    u.stamp = "sdns://test-stamp";
    u.port = 8530;
    u.bootstrapIps = {"1.1.1.1", "9.9.9.9"};
    u.sni = "sni.example.com";
    u.proxy = "https://relay.example.net/oh";
    u.tlsVerify = false;

    // A no-op edit through the dialog fields must reproduce the config.
    const ServerFields fields = serverFieldsFromUpstream(u);
    const UpstreamConfig out = upstreamFromServerFields(u, fields);
    QCOMPARE(out.name, u.name);
    QCOMPARE(out.type, u.type);
    QCOMPARE(out.address, u.address);
    QCOMPARE(out.stamp, u.stamp);
    QCOMPARE(out.port, u.port);
    QCOMPARE(out.bootstrapIps, u.bootstrapIps);
    QCOMPARE(out.sni, u.sni);
    QCOMPARE(out.proxy, u.proxy);
    QCOMPARE(out.tlsVerify, u.tlsVerify);

    // Editing a form field keeps the fields the form does not expose (the
    // stamp): the old round-trip silently dropped it.
    ServerFields edited = fields;
    edited.address = "other.example.com";
    const UpstreamConfig overlay = upstreamFromServerFields(u, edited);
    QCOMPARE(overlay.address, std::string("other.example.com"));
    QCOMPARE(overlay.stamp, u.stamp);
    QCOMPARE(overlay.sni, u.sni);
}

QTEST_GUILESS_MAIN(TestDialogs)
#include "test_dialogs.moc"
