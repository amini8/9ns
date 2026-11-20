#include <QtTest/QtTest>

#include <QClipboard>
#include <QComboBox>
#include <QGuiApplication>
#include <QProgressBar>
#include <QSignalSpy>
#include <QTableWidget>

#include <atomic>

#include "PublicResolverFixtures.h"
#include "ui/PublicResolversDialog.h"

using namespace publicResolverFixtures;

namespace {

PublicResolversDialog::Services services(const std::vector<PublicDnsItem>& entries,
                                         std::atomic<int>& probes, QStringList& warnings,
                                         const QString& poolName = QStringLiteral("public-pool")) {
    PublicResolversDialog::Services result;
    result.load = [entries](bool, std::string&) { return entries; };
    result.probe = [&probes](const UpstreamConfig&, uint32_t& rtt, std::string&) {
        ++probes;
        rtt = 7;
        return true;
    };
    result.notice = [&warnings](const QString&, const QString& text, bool warning) {
        if (warning) warnings.push_back(text);
    };
    result.poolName = [poolName](QString& out) { out = poolName; return true; };
    return result;
}

void selectRows(QTableWidget* table, int first, int last) {
    table->clearSelection();
    table->setRangeSelected(QTableWidgetSelectionRange(first, 0, last, table->columnCount() - 1), true);
}

}  // namespace

class TestPublicResolversDialog : public QObject {
    Q_OBJECT

private slots:
    void mixedSelectionDoesNotMutateAndRelayCanBeCopied() {
        Config current = config();
        std::atomic<int> probes{0};
        QStringList warnings;
        auto relay = item(0x85, "relay");
        PublicResolversDialog dialog(current, services({item(0x02), relay}, probes, warnings));
        QSignalSpy modified(&dialog, &PublicResolversDialog::configurationModified);
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        QVERIFY(table);
        QTRY_COMPARE(table->rowCount(), 2);
        selectRows(table, 0, 1);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onAddSelectedToServers", Qt::DirectConnection));
        QCOMPARE(current.upstreams.size(), size_t(1));
        QCOMPARE(modified.count(), 0);
        QCOMPARE(warnings.size(), 1);
        QVERIFY(warnings.back().contains(QStringLiteral("relay")));
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onCreatePoolFromSelected", Qt::DirectConnection));
        QVERIFY(current.pools.empty());
        QCOMPARE(current.upstreams.size(), size_t(1));
        QCOMPARE(modified.count(), 0);
        selectRows(table, 1, 1);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onCopyStamp", Qt::DirectConnection));
        QCOMPARE(QGuiApplication::clipboard()->text(), QString::fromStdString(relay.stamp));
    }

    void poolAndServerImportsUseStampTypes() {
        Config current = config();
        std::atomic<int> probes{0};
        QStringList warnings;
        PublicResolversDialog dialog(current, services({item(0x04, "same"), item(0x05, "same")}, probes, warnings));
        QSignalSpy modified(&dialog, &PublicResolversDialog::configurationModified);
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        QTRY_COMPARE(table->rowCount(), 2);
        selectRows(table, 0, 1);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onCreatePoolFromSelected", Qt::DirectConnection));
        QCOMPARE(current.pools.size(), size_t(1));
        QCOMPARE(current.pools[0].servers.size(), size_t(2));
        QCOMPARE(current.upstreams[1].type, std::string("doq"));
        QCOMPARE(current.upstreams[2].type, std::string("odoh"));
        QCOMPARE(current.upstreams[1].name, std::string("same"));
        QCOMPARE(current.upstreams[2].name, std::string("same-2"));
        QCOMPARE(modified.count(), 1);
        QVERIFY(warnings.empty());
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onAddSelectedToServers", Qt::DirectConnection));
        QCOMPARE(current.upstreams.size(), size_t(3));
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onCreatePoolFromSelected", Qt::DirectConnection));
        QCOMPARE(current.pools.size(), size_t(1));
        QCOMPARE(warnings.size(), 1);
    }

    void protocolFiltersAndProbeGuards() {
        Config current = config();
        std::atomic<int> probes{0};
        QStringList warnings;
        std::vector<PublicDnsItem> entries;
        for (unsigned char protocol : {0x01, 0x02, 0x04, 0x05, 0x81, 0x85}) {
            entries.push_back(item(protocol, "entry-" + std::to_string(protocol)));
        }
        auto invalid = item(0x02, "invalid");
        invalid.stamp = "broken";
        entries.push_back(invalid);
        PublicResolversDialog dialog(current, services(entries, probes, warnings));
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        auto* filter = dialog.findChild<QComboBox*>(QStringLiteral("protocolFilter"));
        QVERIFY(table && filter);
        QTRY_COMPARE(table->rowCount(), 7);
        QCOMPARE(filter->count(), 7);
        for (int index = 1; index < filter->count(); ++index) {
            filter->setCurrentIndex(index);
            QCOMPARE(table->rowCount(), 1);
            QCOMPARE(table->item(0, 1)->text(), filter->currentData().toString());
        }
        filter->setCurrentIndex(0);
        selectRows(table, 0, 6);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onPingSelected", Qt::DirectConnection));
        QTRY_COMPARE(probes.load(), 4);
        QTRY_COMPARE(table->item(0, 5)->text(), QStringLiteral("7 ms"));
        QTRY_COMPARE(table->item(3, 5)->text(), QStringLiteral("7 ms"));
        for (int row : {4, 5, 6}) QCOMPARE(table->item(row, 5)->text(), QStringLiteral("Not a resolver"));
        QCOMPARE(current.upstreams.size(), size_t(1));
    }

    void duplicateMemberPoolIsRejected() {
        Config current = config();
        std::atomic<int> probes{0};
        QStringList warnings;
        const auto entry = item(0x02);
        PublicResolversDialog dialog(current, services({entry, entry}, probes, warnings));
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        QTRY_COMPARE(table->rowCount(), 2);
        selectRows(table, 0, 1);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onCreatePoolFromSelected", Qt::DirectConnection));
        QCOMPARE(current.upstreams.size(), size_t(1));
        QVERIFY(current.pools.empty());
        QCOMPARE(warnings.size(), 1);
        QVERIFY(warnings[0].contains(QStringLiteral("distinct")));
    }
};

QTEST_MAIN(TestPublicResolversDialog)
#include "test_publicresolversdialog.moc"
