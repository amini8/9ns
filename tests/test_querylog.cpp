// QueryLogModel: stable timestamps, bounded history with correct notifications,
// combined domain/status filtering and optional row snapshots. Offline only.

#include <QtTest/QtTest>

#include <QCoreApplication>
#include <QDateTime>
#include <QSignalSpy>
#include <QSortFilterProxyModel>
#include <QAbstractItemModelTester>

#include <chrono>
#include <thread>

#include "core/Resolver.h"
#include "ui/QueryLogFilterProxyModel.h"
#include "ui/QueryLogModel.h"

namespace {

ResolveEvent makeEvent(const std::string& name, const std::string& action = "Resolved",
                       uint32_t latencyMs = 5) {
    ResolveEvent ev;
    ev.queryName = name;
    ev.action = action;
    ev.latencyMs = latencyMs;
    ev.clientIp = "127.0.0.1";
    ev.queryType = 1;
    ev.rcode = 0;
    return ev;
}

}  // namespace

class TestQueryLog : public QObject {
    Q_OBJECT

private slots:
    void addInsertsRowAtTop();
    void timestampsAreStableAndNotPaintTime();
    void evictionEmitsRemoveNotifications();
    void smallCapEvictsImmediately();
    void zeroCapKeepsNoRows();
    void clearResetsRows();
    void domainFilterIsCaseInsensitive();
    void statusFilterIsExact();
    void domainAndStatusCombineWithAnd();
    void changingAndClearingFiltersUpdatesExistingRows();
    void filterMatchesAllActionValues();
    void snapshotsAreIndependentOfRowIndex();
    void sortingByLatencyIsNumeric();
    void sortingByTimestampIsChronological();
    void filterWhileDataArrives();
    void filterDuringEviction();
};

void TestQueryLog::addInsertsRowAtTop() {
    QueryLogModel model;
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);

    model.addEvent(makeEvent("first.example"));
    QCOMPARE(model.rowCount(), 1);
    model.addEvent(makeEvent("second.example"));
    QCOMPARE(model.rowCount(), 2);
    // Newest first.
    QCOMPARE(model.data(model.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("second.example"));
    QCOMPARE(model.data(model.index(1, QueryLogModel::ColDomain)).toString(), QStringLiteral("first.example"));
}

void TestQueryLog::timestampsAreStableAndNotPaintTime() {
    QueryLogModel model;
    model.addEvent(makeEvent("early.example"));
    const QString first = model.data(model.index(0, QueryLogModel::ColTime)).toString();

    // A later read must not drift with wall-clock paint time.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    const QString second = model.data(model.index(0, QueryLogModel::ColTime)).toString();
    QCOMPARE(first, second);
}

void TestQueryLog::evictionEmitsRemoveNotifications() {
    QueryLogModel model(nullptr, 3);
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);

    for (int i = 0; i < 3; ++i) {
        model.addEvent(makeEvent("host" + std::to_string(i) + ".example"));
    }
    QCOMPARE(model.rowCount(), 3);

    QSignalSpy rowsRemoved(&model, &QAbstractItemModel::rowsRemoved);
    model.addEvent(makeEvent("overflow.example"));
    QCOMPARE(model.rowCount(), 3);
    QVERIFY2(rowsRemoved.count() >= 1, "evicting the oldest row must emit rowsRemoved");
}

void TestQueryLog::smallCapEvictsImmediately() {
    QueryLogModel model(nullptr, 1);
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);

    model.addEvent(makeEvent("one.example"));
    model.addEvent(makeEvent("two.example"));
    QCOMPARE(model.rowCount(), 1);
    QCOMPARE(model.data(model.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("two.example"));
}

void TestQueryLog::zeroCapKeepsNoRows() {
    QueryLogModel model(nullptr, 0);
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);

    model.addEvent(makeEvent("dropped.example"));
    QCOMPARE(model.rowCount(), 0);
    QVERIFY(!model.snapshot(0).has_value());
}

void TestQueryLog::clearResetsRows() {
    QueryLogModel model;
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);
    model.addEvent(makeEvent("a.example"));
    model.addEvent(makeEvent("b.example"));
    model.clear();
    QCOMPARE(model.rowCount(), 0);
}

void TestQueryLog::domainFilterIsCaseInsensitive() {
    QueryLogModel model;
    model.addEvent(makeEvent("WikiPedia.org"));
    model.addEvent(makeEvent("example.com"));

    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setDomainFilter(QStringLiteral("wikipedia"));
    QCOMPARE(proxy.rowCount(), 1);
}

void TestQueryLog::statusFilterIsExact() {
    QueryLogModel model;
    model.addEvent(makeEvent("ads.example", "Blocked"));
    model.addEvent(makeEvent("ok.example", "Resolved"));

    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setStatusFilter(QStringLiteral("Blocked"));
    QCOMPARE(proxy.rowCount(), 1);
    QCOMPARE(proxy.data(proxy.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("ads.example"));
}

void TestQueryLog::domainAndStatusCombineWithAnd() {
    QueryLogModel model;
    model.addEvent(makeEvent("ads.example", "Blocked"));
    model.addEvent(makeEvent("ads.cdn.example", "Resolved"));
    model.addEvent(makeEvent("ok.example", "Blocked"));

    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setDomainFilter(QStringLiteral("ads"));
    proxy.setStatusFilter(QStringLiteral("Blocked"));
    QCOMPARE(proxy.rowCount(), 1);
    QCOMPARE(proxy.data(proxy.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("ads.example"));
}

void TestQueryLog::filterMatchesAllActionValues() {
    QueryLogModel model;
    const char* actions[] = {"Blocked", "Cached", "Resolved", "Local", "Error", "Bogus"};
    for (const char* action : actions) {
        model.addEvent(makeEvent(std::string("h-") + action + ".example", action));
    }
    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    for (const char* action : actions) {
        proxy.setStatusFilter(QString::fromLatin1(action));
        QVERIFY2(proxy.rowCount() == 1, action);
    }
    proxy.setStatusFilter(QString());
    QCOMPARE(proxy.rowCount(), 6);
}

void TestQueryLog::changingAndClearingFiltersUpdatesExistingRows() {
    QueryLogModel model;
    model.addEvent(makeEvent("Ads.Example", "Blocked"));
    model.addEvent(makeEvent("ads.other", "Resolved"));
    model.addEvent(makeEvent("ok.example", "Resolved"));
    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    QAbstractItemModelTester tester(&proxy, QAbstractItemModelTester::FailureReportingMode::Fatal);
    QCOMPARE(proxy.rowCount(), 3);

    proxy.setDomainFilter(QStringLiteral("  ADS  "));
    QCOMPARE(proxy.rowCount(), 2);
    proxy.setStatusFilter(QStringLiteral("Blocked"));
    QCOMPARE(proxy.rowCount(), 1);
    proxy.setDomainFilter(QStringLiteral("  example  "));
    QCOMPARE(proxy.rowCount(), 1);
    proxy.setStatusFilter(QStringLiteral("Resolved"));
    QCOMPARE(proxy.rowCount(), 1);
    QCOMPARE(proxy.index(0, QueryLogModel::ColDomain).data().toString(), QStringLiteral("ok.example"));

    proxy.setDomainFilter(QStringLiteral(" 	 "));
    QCOMPARE(proxy.rowCount(), 2);
    proxy.setStatusFilter(QStringLiteral("resolved"));
    QCOMPARE(proxy.rowCount(), 0);
    proxy.setStatusFilter(QString());
    QCOMPARE(proxy.rowCount(), 3);
}

void TestQueryLog::snapshotsAreIndependentOfRowIndex() {
    QueryLogModel model(nullptr, 4);
    model.addEvent(makeEvent("keep.example", "Resolved", 7));
    auto snap = model.snapshot(0);
    QVERIFY(snap.has_value());
    QCOMPARE(QString::fromStdString(snap->queryName), QStringLiteral("keep.example"));

    // Push the row down the deque and force an eviction later; the snapshot
    // must still describe the entry it was taken for.
    model.addEvent(makeEvent("newer-1.example"));
    model.addEvent(makeEvent("newer-2.example"));
    QVERIFY(snap.has_value());
    QCOMPARE(QString::fromStdString(snap->queryName), QStringLiteral("keep.example"));
    QCOMPARE(snap->latencyMs, uint32_t(7));
}

void TestQueryLog::sortingByLatencyIsNumeric() {
    QueryLogModel model;
    model.addEvent(makeEvent("slow.example", "Resolved", 250));
    model.addEvent(makeEvent("fast.example", "Resolved", 3));

    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setSortRole(QueryLogModel::SortLatency);
    proxy.sort(0, Qt::AscendingOrder);
    QCOMPARE(proxy.data(proxy.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("fast.example"));
    QCOMPARE(proxy.data(proxy.index(1, QueryLogModel::ColDomain)).toString(), QStringLiteral("slow.example"));
}

void TestQueryLog::sortingByTimestampIsChronological() {
    QueryLogModel model;
    model.addEvent(makeEvent("older.example"));
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    model.addEvent(makeEvent("newer.example"));

    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setSortRole(QueryLogModel::SortTimestamp);
    proxy.sort(0, Qt::AscendingOrder);
    QCOMPARE(proxy.data(proxy.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("older.example"));
    QCOMPARE(proxy.data(proxy.index(1, QueryLogModel::ColDomain)).toString(), QStringLiteral("newer.example"));

    proxy.sort(0, Qt::DescendingOrder);
    QCOMPARE(proxy.data(proxy.index(0, QueryLogModel::ColDomain)).toString(), QStringLiteral("newer.example"));
    QCOMPARE(proxy.data(proxy.index(1, QueryLogModel::ColDomain)).toString(), QStringLiteral("older.example"));
}

void TestQueryLog::filterWhileDataArrives() {
    QueryLogModel model(nullptr, 50);
    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    QAbstractItemModelTester tester(&proxy, QAbstractItemModelTester::FailureReportingMode::Fatal);

    proxy.setDomainFilter(QStringLiteral("keep"));
    for (int i = 0; i < 20; ++i) {
        model.addEvent(makeEvent(i % 2 == 0 ? "keep.example" : "drop.example"));
    }
    QCOMPARE(proxy.rowCount(), 10);
}

void TestQueryLog::filterDuringEviction() {
    QueryLogModel model(nullptr, 4);
    QueryLogFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    QAbstractItemModelTester tester(&proxy, QAbstractItemModelTester::FailureReportingMode::Fatal);

    proxy.setDomainFilter(QStringLiteral("keep"));
    for (int i = 0; i < 10; ++i) {
        model.addEvent(makeEvent(i % 2 == 0 ? "keep.example" : "drop.example"));
    }
    // The four newest rows are two keep/drop alternations.
    QCOMPARE(model.rowCount(), 4);
    QCOMPARE(proxy.rowCount(), 2);
}

QTEST_GUILESS_MAIN(TestQueryLog)
#include "test_querylog.moc"
