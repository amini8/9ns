#include <QtTest/QtTest>

#include <QComboBox>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>

#include "core/SystemDns.h"
#include "ui/RuleDialog.h"

namespace {

RuleConfig makeRule() {
    RuleConfig rule;
    rule.name = "Restricted";
    rule.hostnames = {"*.example"};
    rule.pattern = "*.example";
    rule.action = "block";
    rule.interfaceGuid = "{unavailable-guid}";
    rule.queryType = "HTTPS";
    return rule;
}

const std::vector<UpstreamConfig> kUpstreams;
const std::vector<PoolConfig> kPools;
const std::vector<InterfaceInfo> kInterfaces = {
    {"{ethernet-guid}", "Ethernet", false},
    {"{vpn-guid}", "Private tunnel", true}
};

}  // namespace

class TestRuleDialog : public QObject {
    Q_OBJECT

private slots:
    void unchangedSavePreservesRestrictions_data();
    void unchangedSavePreservesRestrictions();
    void availableInterfaceAndCommonTypeRoundTrip();
    void intentionalSelectionChanges_data();
    void intentionalSelectionChanges();
    void cancelDoesNotMutateRule();
};

void TestRuleDialog::unchangedSavePreservesRestrictions_data() {
    QTest::addColumn<QString>("type");
    QTest::addColumn<bool>("emptyInterfaces");
    QTest::newRow("HTTPS-with-fixtures") << QStringLiteral("HTTPS") << false;
    QTest::newRow("SOA-without-adapters") << QStringLiteral("SOA") << true;
    QTest::newRow("private-type") << QStringLiteral("TYPE65400") << false;
    QTest::newRow("lowercase") << QStringLiteral("mx") << true;
}

void TestRuleDialog::unchangedSavePreservesRestrictions() {
    QFETCH(QString, type);
    QFETCH(bool, emptyInterfaces);
    auto rule = makeRule();
    rule.queryType = type.toStdString();
    const std::vector<InterfaceInfo> interfaces = emptyInterfaces ? std::vector<InterfaceInfo>{} : kInterfaces;
    RuleDialog dialog(rule, kUpstreams, kPools, interfaces);
    dialog.show();
    auto* iface = dialog.findChild<QComboBox*>(QStringLiteral("interfaceCombo"));
    auto* qtype = dialog.findChild<QComboBox*>(QStringLiteral("queryTypeCombo"));
    auto* buttons = dialog.findChild<QDialogButtonBox*>();
    QVERIFY(iface);
    QVERIFY(qtype);
    QVERIFY(buttons);
    QCOMPARE(iface->currentData().toString(), QStringLiteral("{unavailable-guid}"));
    QVERIFY(iface->currentText().contains(QStringLiteral("{unavailable-guid}")));
    QVERIFY(iface->currentText().contains(QStringLiteral("unavailable")));
    QCOMPARE(qtype->currentData().toString(), type);
    QVERIFY(qtype->currentText().contains(QStringLiteral("current")));
    QTest::mouseClick(buttons->button(QDialogButtonBox::Save), Qt::LeftButton);
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(QString::fromStdString(rule.interfaceGuid), QStringLiteral("{unavailable-guid}"));
    QCOMPARE(QString::fromStdString(rule.queryType), type);
}

void TestRuleDialog::availableInterfaceAndCommonTypeRoundTrip() {
    auto rule = makeRule();
    rule.interfaceGuid = "{vpn-guid}";
    rule.queryType = "AAAA";
    RuleDialog dialog(rule, kUpstreams, kPools, kInterfaces);
    dialog.show();
    auto* iface = dialog.findChild<QComboBox*>(QStringLiteral("interfaceCombo"));
    auto* qtype = dialog.findChild<QComboBox*>(QStringLiteral("queryTypeCombo"));
    auto* buttons = dialog.findChild<QDialogButtonBox*>();
    QVERIFY(iface);
    QVERIFY(qtype);
    QVERIFY(buttons);
    QCOMPARE(iface->count(), 3);
    QCOMPARE(iface->currentText(), QStringLiteral("Private tunnel (VPN)"));
    QCOMPARE(qtype->count(), 8);
    QCOMPARE(qtype->currentText(), QStringLiteral("AAAA"));
    QTest::mouseClick(buttons->button(QDialogButtonBox::Save), Qt::LeftButton);
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(QString::fromStdString(rule.interfaceGuid), QStringLiteral("{vpn-guid}"));
    QCOMPARE(QString::fromStdString(rule.queryType), QStringLiteral("AAAA"));
}

void TestRuleDialog::intentionalSelectionChanges_data() {
    QTest::addColumn<QString>("guid");
    QTest::addColumn<QString>("type");
    QTest::newRow("clear-restrictions") << QString() << QStringLiteral("ANY");
    QTest::newRow("choose-available") << QStringLiteral("{ethernet-guid}") << QStringLiteral("A");
}

void TestRuleDialog::intentionalSelectionChanges() {
    QFETCH(QString, guid);
    QFETCH(QString, type);
    auto rule = makeRule();
    RuleDialog dialog(rule, kUpstreams, kPools, kInterfaces);
    dialog.show();
    auto* iface = dialog.findChild<QComboBox*>(QStringLiteral("interfaceCombo"));
    auto* qtype = dialog.findChild<QComboBox*>(QStringLiteral("queryTypeCombo"));
    auto* buttons = dialog.findChild<QDialogButtonBox*>();
    QVERIFY(iface);
    QVERIFY(qtype);
    QVERIFY(buttons);
    const int ifaceIdx = iface->findData(guid);
    const int typeIdx = qtype->findData(type);
    QVERIFY(ifaceIdx >= 0);
    QVERIFY(typeIdx >= 0);
    iface->setCurrentIndex(ifaceIdx);
    qtype->setCurrentIndex(typeIdx);
    QCOMPARE(QString::fromStdString(rule.interfaceGuid), QStringLiteral("{unavailable-guid}"));
    QCOMPARE(QString::fromStdString(rule.queryType), QStringLiteral("HTTPS"));
    QTest::mouseClick(buttons->button(QDialogButtonBox::Save), Qt::LeftButton);
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(QString::fromStdString(rule.interfaceGuid), guid);
    QCOMPARE(QString::fromStdString(rule.queryType), type);
}

void TestRuleDialog::cancelDoesNotMutateRule() {
    auto rule = makeRule();
    const auto original = rule;
    RuleDialog dialog(rule, kUpstreams, kPools, kInterfaces);
    dialog.show();
    auto* iface = dialog.findChild<QComboBox*>(QStringLiteral("interfaceCombo"));
    auto* qtype = dialog.findChild<QComboBox*>(QStringLiteral("queryTypeCombo"));
    auto* masks = dialog.findChild<QPlainTextEdit*>();
    auto* buttons = dialog.findChild<QDialogButtonBox*>();
    QVERIFY(iface);
    QVERIFY(qtype);
    QVERIFY(masks);
    QVERIFY(buttons);
    iface->setCurrentIndex(0);
    qtype->setCurrentIndex(0);
    masks->setPlainText(QStringLiteral("changed.example"));
    for (auto* edit : dialog.findChildren<QLineEdit*>()) edit->setText(QStringLiteral("changed"));
    QTest::mouseClick(buttons->button(QDialogButtonBox::Cancel), Qt::LeftButton);
    QCOMPARE(dialog.result(), int(QDialog::Rejected));
    QVERIFY(rule.name == original.name);
    QVERIFY(rule.hostnames == original.hostnames);
    QVERIFY(rule.pattern == original.pattern);
    QVERIFY(rule.action == original.action);
    QVERIFY(rule.blockMode == original.blockMode);
    QVERIFY(rule.target == original.target);
    QVERIFY(rule.upstream == original.upstream);
    QVERIFY(rule.localIp == original.localIp);
    QVERIFY(rule.interfaceGuid == original.interfaceGuid);
    QVERIFY(rule.queryType == original.queryType);
    QVERIFY(rule.dnssecMode == original.dnssecMode);
    QVERIFY(rule.hostsFile == original.hostsFile);
}

QTEST_MAIN(TestRuleDialog)
#include "test_ruledialog.moc"
