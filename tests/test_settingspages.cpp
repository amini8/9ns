#include <QtTest/QtTest>

#include <QComboBox>
#include <QImage>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalSpy>
#include <QTableWidget>

#include <tuple>

#include "core/Config.h"
#include "ui/Theme.h"
#include "ui/pages/OverviewPage.h"
#include "ui/pages/RulesPage.h"
#include "ui/pages/ServersPoolsPage.h"
#include "ui/pages/SettingsPage.h"
#include "ui/pages/SystemLogPage.h"

namespace {

template <typename T>
T* accessibleChild(QWidget& parent, const QString& name) {
    for (auto* child : parent.findChildren<T*>()) {
        if (child->accessibleName() == name) return child;
    }
    return nullptr;
}

QPushButton* button(QWidget& parent, const QString& text) {
    for (auto* child : parent.findChildren<QPushButton*>()) {
        if (child->text() == text) return child;
    }
    return nullptr;
}

Config routingConfig() {
    Config config;
    UpstreamConfig upstream;
    upstream.name = "offline";
    upstream.type = "dot";
    upstream.address = "resolver.example";
    upstream.port = 8853;
    upstream.stamp = "opaque-stamp";
    upstream.bootstrapIps = {"192.0.2.1", "2001:db8::1"};
    upstream.sni = "tls.example";
    upstream.tlsVerify = false;
    upstream.proxy = "opaque-relay";
    config.upstreams = {upstream};
    PoolConfig pool;
    pool.name = "priority";
    pool.strategy = "failover";
    pool.servers = {"offline"};
    config.pools = {pool};
    RuleConfig rule;
    rule.name = "route";
    rule.hostnames = {"*.example", "*.invalid"};
    rule.pattern = "legacy.example";
    rule.target = "priority";
    rule.upstream = "offline";
    rule.localIp = "192.0.2.2";
    rule.interfaceGuid = "offline-interface";
    rule.queryType = "AAAA";
    rule.dnssecMode = "ignore";
    rule.hostsFile = "offline-hosts";
    config.rules = {rule, rule, rule};
    config.rules[1].name = "second";
    config.rules[2].name = "third";
    config.defaultTarget = "priority";
    config.defaultUpstream = "offline";
    return config;
}

auto upstreamFields(const UpstreamConfig& u) {
    return std::tie(u.name, u.type, u.address, u.stamp, u.port, u.bootstrapIps,
                    u.sni, u.tlsVerify, u.proxy);
}

auto ruleFields(const RuleConfig& r) {
    return std::tie(r.name, r.hostnames, r.pattern, r.action, r.blockMode, r.target,
                    r.upstream, r.localIp, r.interfaceGuid, r.queryType, r.dnssecMode, r.hostsFile);
}

} // namespace

class TestSettingsPages : public QObject {
    Q_OBJECT

private slots:
    void pagesRenderAtSmallSizesAndSettingsScroll();
    void settingsRoundTripPreservesRouting();
    void settingsActionsAreIndependentSignals();
    void rulesSelectionAndMoveSignals();
    void defaultTargetPopulationIsSilent();
    void serverAndPoolSelectionActions();
    void overviewLatencyTransitions();
    void systemLogAppendAndClear();
};

void TestSettingsPages::pagesRenderAtSmallSizesAndSettingsScroll() {
    OverviewPage overview;
    SettingsPage settings;
    RulesPage rules;
    ServersPoolsPage servers;
    SystemLogPage log;
    const Config config = routingConfig();
    overview.setProtectionSummary(QStringLiteral("<b>9NS stopped</b> — offline preview"));
    overview.setMetrics(123, 7, 2.5, 42.5);
    overview.setUpstreamCount(1);
    overview.setUpstreamRow(0, "offline", "dot", "resolver.example");
    settings.setValues(config);
    rules.setRules(config.rules);
    servers.setUpstreams(config.upstreams);
    servers.setPools(config.pools);
    log.appendLine(QStringLiteral("Offline diagnostics"));

    for (QWidget* page : {static_cast<QWidget*>(&overview), static_cast<QWidget*>(&settings),
                          static_cast<QWidget*>(&rules), static_cast<QWidget*>(&servers),
                          static_cast<QWidget*>(&log)}) {
        for (const QSize size : {QSize(480, 320), QSize(640, 480)}) {
            page->resize(size);
            page->show();
            QCoreApplication::processEvents();
            QImage image(page->size(), QImage::Format_ARGB32_Premultiplied);
            image.fill(Qt::transparent);
            const QImage blank = image.copy();
            page->render(&image);
            QVERIFY(!image.isNull());
            QVERIFY(image != blank);
            page->hide();
        }
    }

    auto* scroll = settings.findChild<QScrollArea*>();
    QVERIFY(scroll);
    QVERIFY(scroll->widgetResizable());
    QVERIFY(scroll->widget());
    settings.resize(480, 240);
    settings.show();
    QCoreApplication::processEvents();
    QVERIFY(scroll->verticalScrollBar()->maximum() > 0);
    scroll->verticalScrollBar()->setValue(scroll->verticalScrollBar()->maximum());
    QCOMPARE(scroll->verticalScrollBar()->value(), scroll->verticalScrollBar()->maximum());
}

void TestSettingsPages::settingsRoundTripPreservesRouting() {
    SettingsPage page;
    QSignalSpy save(&page, &SettingsPage::saveRequested);
    QVERIFY(save.isValid());
    const Config original = routingConfig();
    const std::string levels[] = {"error", "info", "debug"};
    for (int i = 0; i < 3; ++i) {
        Config input;
        input.listenPort = i == 0 ? 1 : (i == 1 ? 5353 : 65535);
        input.cacheEntries = i == 0 ? 0 : (i == 1 ? 12345 : 1000000);
        input.minTtl = i == 0 ? 0 : 17;
        input.maxTtl = i == 0 ? 0 : 86400;
        input.negativeTtl = i == 0 ? 0 : 123;
        input.systemDns = i != 0;
        input.ipv6Loopback = i == 0;
        input.preventDnsLeaks = i != 0;
        input.dnssecValidation = i == 0;
        input.autostart = i != 0;
        input.closeToTray = i == 0;
        input.logLevel = levels[i];
        input.logFile = i == 0 ? "" : "offline-log.txt";
        page.setValues(input);
        Config output = original;
        page.applyTo(output);
        QCOMPARE(output.listenPort, input.listenPort);
        QCOMPARE(output.cacheEntries, input.cacheEntries);
        QCOMPARE(output.minTtl, input.minTtl);
        QCOMPARE(output.maxTtl, input.maxTtl);
        QCOMPARE(output.negativeTtl, input.negativeTtl);
        QCOMPARE(output.systemDns, input.systemDns);
        QCOMPARE(output.ipv6Loopback, input.ipv6Loopback);
        QCOMPARE(output.preventDnsLeaks, input.preventDnsLeaks);
        QCOMPARE(output.dnssecValidation, input.dnssecValidation);
        QCOMPARE(output.autostart, input.autostart);
        QCOMPARE(output.closeToTray, input.closeToTray);
        QCOMPARE(output.logLevel, input.logLevel);
        QCOMPARE(output.logFile, input.logFile);
        QCOMPARE(output.defaultTarget, original.defaultTarget);
        QCOMPARE(output.defaultUpstream, original.defaultUpstream);
        QCOMPARE(output.upstreams.size(), original.upstreams.size());
        for (size_t row = 0; row < output.upstreams.size(); ++row)
            QVERIFY(upstreamFields(output.upstreams[row]) == upstreamFields(original.upstreams[row]));
        QCOMPARE(output.pools.size(), original.pools.size());
        for (size_t row = 0; row < output.pools.size(); ++row) {
            QCOMPARE(output.pools[row].name, original.pools[row].name);
            QCOMPARE(output.pools[row].strategy, original.pools[row].strategy);
            QCOMPARE(output.pools[row].servers, original.pools[row].servers);
        }
        QCOMPARE(output.rules.size(), original.rules.size());
        for (size_t row = 0; row < output.rules.size(); ++row)
            QVERIFY(ruleFields(output.rules[row]) == ruleFields(original.rules[row]));
    }
    QCOMPARE(save.count(), 0);
}

void TestSettingsPages::settingsActionsAreIndependentSignals() {
    SettingsPage page;
    QSignalSpy save(&page, &SettingsPage::saveRequested);
    QSignalSpy reload(&page, &SettingsPage::reloadRequested);
    QSignalSpy install(&page, &SettingsPage::installServiceRequested);
    QSignalSpy uninstall(&page, &SettingsPage::uninstallServiceRequested);
    QSignalSpy folder(&page, &SettingsPage::openDataFolderRequested);
    QVERIFY(save.isValid() && reload.isValid() && install.isValid()
            && uninstall.isValid() && folder.isValid());
    auto* installButton = button(page, "Install Windows Service");
    auto* uninstallButton = button(page, "Uninstall Windows Service");
    auto* saveButton = button(page, "Save Changes");
    auto* reloadButton = button(page, "Reload from Disk");
    auto* folderButton = button(page, "Open Data Folder");
    QVERIFY(installButton && uninstallButton && saveButton && reloadButton && folderButton);
    installButton->click();
    QCOMPARE(install.count(), 1);
    QCOMPARE(uninstall.count(), 0);
    QCOMPARE(save.count(), 0);
    uninstallButton->click();
    QCOMPARE(uninstall.count(), 1);
    QCOMPARE(install.count(), 1);
    QCOMPARE(save.count(), 0);
    reloadButton->click();
    folderButton->click();
    QCOMPARE(reload.count(), 1);
    QCOMPARE(folder.count(), 1);
    QCOMPARE(save.count(), 0);
    saveButton->click();
    QCOMPARE(save.count(), 1);
    QCOMPARE(install.count(), 1);
    QCOMPARE(uninstall.count(), 1);
}

void TestSettingsPages::rulesSelectionAndMoveSignals() {
    RulesPage page;
    auto* edit = button(page, QString::fromUtf8("Edit…"));
    auto* remove = button(page, "Delete");
    auto* up = button(page, "Move Up");
    auto* down = button(page, "Move Down");
    QVERIFY(edit && remove && up && down);
    QVERIFY(!edit->isEnabled() && !remove->isEnabled() && !up->isEnabled() && !down->isEnabled());
    page.setRules(routingConfig().rules);
    QCOMPARE(page.selectedRow(), -1);
    QVERIFY(!edit->isEnabled() && !remove->isEnabled());
    QSignalSpy moves(&page, &RulesPage::moveRequested);
    QSignalSpy edits(&page, &RulesPage::editRequested);
    QSignalSpy deletes(&page, &RulesPage::deleteRequested);
    QVERIFY(moves.isValid() && edits.isValid() && deletes.isValid());
    page.selectRow(0);
    QVERIFY(edit->isEnabled() && remove->isEnabled());
    QVERIFY(!up->isEnabled() && down->isEnabled());
    up->click();
    QCOMPARE(moves.count(), 0);
    page.selectRow(1);
    QVERIFY(up->isEnabled() && down->isEnabled());
    up->click();
    down->click();
    QCOMPARE(moves.count(), 2);
    QCOMPARE(moves.at(0).at(0).toInt(), 1);
    QCOMPARE(moves.at(0).at(1).toInt(), -1);
    QCOMPARE(moves.at(1).at(0).toInt(), 1);
    QCOMPARE(moves.at(1).at(1).toInt(), 1);
    QCOMPARE(page.selectedRow(), 1);
    page.selectRow(2);
    QVERIFY(up->isEnabled() && !down->isEnabled());
    edit->click();
    remove->click();
    QCOMPARE(edits.count(), 1);
    QCOMPARE(edits.at(0).at(0).toInt(), 2);
    QCOMPARE(deletes.count(), 1);
    QCOMPARE(deletes.at(0).at(0).toInt(), 2);
    page.setRules({});
    QCOMPARE(page.selectedRow(), -1);
    QVERIFY(!edit->isEnabled() && !remove->isEnabled() && !up->isEnabled() && !down->isEnabled());
}

void TestSettingsPages::defaultTargetPopulationIsSilent() {
    ServersPoolsPage page;
    auto* combo = accessibleChild<QComboBox>(page, "Default upstream or pool");
    QVERIFY(combo);
    QSignalSpy changed(&page, &ServersPoolsPage::defaultTargetChanged);
    QVERIFY(changed.isValid());
    const QList<QPair<QString, QString>> targets = {
        {"Server: Offline", "offline"}, {"Pool: Priority", "priority"}};
    page.setDefaultTargets(targets, "priority");
    QCOMPARE(combo->count(), 2);
    QCOMPARE(page.defaultTarget(), std::string("priority"));
    QCOMPARE(changed.count(), 0);
    page.setDefaultTargets(targets, "offline");
    QCOMPARE(page.defaultTarget(), std::string("offline"));
    QCOMPARE(changed.count(), 0);
    page.show();
    combo->setFocus();
    QTest::keyClick(combo, Qt::Key_Down);
    QCOMPARE(changed.count(), 1);
    QCOMPARE(changed.at(0).at(0).toString(), QStringLiteral("priority"));
    QCOMPARE(page.defaultTarget(), std::string("priority"));
    page.setDefaultTargets({}, "");
    QCOMPARE(combo->count(), 0);
    QVERIFY(page.defaultTarget().empty());
    QCOMPARE(changed.count(), 1);
}

void TestSettingsPages::serverAndPoolSelectionActions() {
    ServersPoolsPage page;
    auto* upstreams = accessibleChild<QTableWidget>(page, "Upstream servers");
    auto* pools = accessibleChild<QTableWidget>(page, "Server pools");
    QVERIFY(upstreams && pools);
    auto* editUpstream = button(*upstreams->parentWidget(), QString::fromUtf8("Edit…"));
    auto* deleteUpstream = button(*upstreams->parentWidget(), "Delete");
    auto* test = button(*upstreams->parentWidget(), "Test");
    auto* editPool = button(*pools->parentWidget(), QString::fromUtf8("Edit…"));
    auto* deletePool = button(*pools->parentWidget(), "Delete");
    QVERIFY(editUpstream && deleteUpstream && test && editPool && deletePool);
    QVERIFY(!editUpstream->isEnabled() && !deleteUpstream->isEnabled() && !test->isEnabled());
    QVERIFY(!editPool->isEnabled() && !deletePool->isEnabled());
    const Config config = routingConfig();
    page.setUpstreams(config.upstreams);
    page.setPools(config.pools);
    QCOMPARE(page.selectedUpstreamRow(), -1);
    QCOMPARE(page.selectedPoolRow(), -1);
    QVERIFY(!editUpstream->isEnabled() && !editPool->isEnabled());
    QSignalSpy edits(&page, &ServersPoolsPage::editUpstreamRequested);
    QSignalSpy deletes(&page, &ServersPoolsPage::deleteUpstreamRequested);
    QSignalSpy tests(&page, &ServersPoolsPage::testUpstreamRequested);
    QSignalSpy poolEdits(&page, &ServersPoolsPage::editPoolRequested);
    QSignalSpy poolDeletes(&page, &ServersPoolsPage::deletePoolRequested);
    QVERIFY(edits.isValid() && deletes.isValid() && tests.isValid()
            && poolEdits.isValid() && poolDeletes.isValid());
    page.selectUpstreamRow(0);
    QVERIFY(editUpstream->isEnabled() && deleteUpstream->isEnabled() && test->isEnabled());
    QVERIFY(!editPool->isEnabled() && !deletePool->isEnabled());
    editUpstream->click();
    deleteUpstream->click();
    test->click();
    pools->selectRow(0);
    QCOMPARE(page.selectedPoolRow(), 0);
    QVERIFY(editPool->isEnabled() && deletePool->isEnabled());
    editPool->click();
    deletePool->click();
    for (const auto* spy : {&edits, &deletes, &tests, &poolEdits, &poolDeletes}) {
        QCOMPARE(spy->count(), 1);
        QCOMPARE(spy->at(0).at(0).toInt(), 0);
    }
    QCOMPARE(upstreams->rowCount(), 1);
    QCOMPARE(pools->rowCount(), 1);
    page.setUpstreams({});
    page.setPools({});
    QVERIFY(!editUpstream->isEnabled() && !deleteUpstream->isEnabled() && !test->isEnabled());
    QVERIFY(!editPool->isEnabled() && !deletePool->isEnabled());
}

void TestSettingsPages::overviewLatencyTransitions() {
    OverviewPage page;
    auto* table = accessibleChild<QTableWidget>(page, "Upstream latency table");
    QVERIFY(table);
    page.setUpstreamCount(2);
    page.setUpstreamRow(0, "offline", "dot", "resolver.example");
    page.setUpstreamRow(1, "backup", "plain", "192.0.2.2");
    QCOMPARE(table->item(0, 3)->text(), QStringLiteral("Not tested"));
    page.setLatency(0, OverviewPage::LatencyState::Testing, {});
    QCOMPARE(table->item(0, 3)->text(), QString::fromUtf8("Testing…"));
    QCOMPARE(table->item(0, 3)->foreground().color(), Theme::warning());
    page.setLatency(0, OverviewPage::LatencyState::Success, "12 ms");
    QCOMPARE(table->item(0, 3)->text(), QString::fromUtf8("Success — 12 ms"));
    QCOMPARE(table->item(0, 3)->foreground().color(), Theme::success());
    page.setLatency(0, OverviewPage::LatencyState::Failure, "timeout");
    QCOMPARE(table->item(0, 3)->text(), QString::fromUtf8("Failure — timeout"));
    QCOMPARE(table->item(0, 3)->foreground().color(), Theme::danger());
    page.setLatency(0, OverviewPage::LatencyState::Success, {});
    QCOMPARE(table->item(0, 3)->text(), QStringLiteral("Success"));
    page.setLatency(1, OverviewPage::LatencyState::Failure, {});
    QCOMPARE(table->item(1, 3)->text(), QStringLiteral("Failure"));
    page.clearLatency();
    for (int row = 0; row < table->rowCount(); ++row) {
        QCOMPARE(table->item(row, 3)->text(), QStringLiteral("Not tested"));
        QCOMPARE(table->item(row, 3)->foreground().color(), Theme::textMuted());
    }
    QCOMPARE(table->item(0, 0)->text(), QStringLiteral("offline"));
    QCOMPARE(table->item(1, 2)->text(), QStringLiteral("192.0.2.2"));
    QSignalSpy start(&page, &OverviewPage::startStopRequested);
    QSignalSpy save(&page, &OverviewPage::saveRequested);
    QSignalSpy flush(&page, &OverviewPage::flushCacheRequested);
    QVERIFY(start.isValid() && save.isValid() && flush.isValid());
    for (const QString& text : {QStringLiteral("Start / Stop"), QStringLiteral("Save Changes"),
                                 QStringLiteral("Flush Cache")}) {
        auto* action = button(page, text);
        QVERIFY(action);
        action->click();
    }
    QCOMPARE(start.count(), 1);
    QCOMPARE(save.count(), 1);
    QCOMPARE(flush.count(), 1);
}

void TestSettingsPages::systemLogAppendAndClear() {
    SystemLogPage page;
    auto* log = accessibleChild<QPlainTextEdit>(page, "System diagnostics log");
    QVERIFY(log);
    QVERIFY(log->isReadOnly());
    QVERIFY(log->toPlainText().isEmpty());
    page.appendLine(QStringLiteral("first <literal>"));
    page.appendLine(QString::fromUtf8("second — diagnostics"));
    QCOMPARE(log->toPlainText(), QString::fromUtf8("first <literal>\nsecond — diagnostics"));
    auto* clear = button(page, "Clear Log");
    auto* folder = button(page, "Open Data Folder");
    QVERIFY(clear && folder);
    QSignalSpy open(&page, &SystemLogPage::openDataFolderRequested);
    QVERIFY(open.isValid());
    clear->click();
    QVERIFY(log->toPlainText().isEmpty());
    QCOMPARE(open.count(), 0);
    page.appendLine(QStringLiteral("after clear"));
    QCOMPARE(log->toPlainText(), QStringLiteral("after clear"));
    page.clear();
    QVERIFY(log->toPlainText().isEmpty());
    folder->click();
    QCOMPARE(open.count(), 1);
}

QTEST_MAIN(TestSettingsPages)
#include "test_settingspages.moc"
