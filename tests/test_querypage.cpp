#include <QtTest/QtTest>

#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QTableView>
#include <QTimer>

#include "ui/QueryLogFilterProxyModel.h"
#include "ui/QueryLogModel.h"
#include "ui/pages/QueryLogPage.h"

namespace {

ResolveEvent makeEvent(const char* domain, const char* action = "Resolved", uint32_t latency = 5) {
    ResolveEvent result;
    result.queryName = domain;
    result.action = action;
    result.latencyMs = latency;
    result.queryType = 1;
    return result;
}

QLabel* emptyLabel(QueryLogPage& page) {
    for (auto* label : page.findChildren<QLabel*>()) {
        if (label->text().startsWith(QStringLiteral("No queries"))) return label;
    }
    return nullptr;
}

void wireFilters(QueryLogPage& page, QueryLogFilterProxyModel& proxy) {
    QObject::connect(&page, &QueryLogPage::searchChanged, &proxy, &QueryLogFilterProxyModel::setDomainFilter);
    QObject::connect(&page, &QueryLogPage::statusFilterChanged, &proxy, &QueryLogFilterProxyModel::setStatusFilter);
}

}  // namespace

class TestQueryPage : public QObject {
    Q_OBJECT

private slots:
    void constructsBeforeModelIsAttached();
    void arrivingRowsReplaceEmptyState();
    void filtersAndClearUpdateEmptyState();
    void statusOnlyNoResultsHasAccurateMessage();
    void sortingUsesClickedColumn();
    void searchFocusAndClearAreSignalsOnly();
    void contextInspectionKeepsEvictedSnapshot();
    void doubleClickInspectsClickedRow();
    void rebindingDisconnectsPreviousModel();
    void filteredFirstArrivalUpdatesEmptyMessage();
    void proxyWithoutSourceRemainsEmpty();
};

void TestQueryPage::constructsBeforeModelIsAttached() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    page.setModels(&model, &proxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    QCOMPARE(table->model(), &proxy);
    QCOMPARE(table->horizontalHeader()->count(), int(QueryLogModel::ColCount));
    QCOMPARE(table->horizontalHeader()->sectionResizeMode(QueryLogModel::ColDomain), QHeaderView::Stretch);
}

void TestQueryPage::arrivingRowsReplaceEmptyState() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    page.setModels(&model, &proxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    QVERIFY(table->isHidden());
    model.addEvent(makeEvent("new.example"));
    QCoreApplication::processEvents();
    QVERIFY(!table->isHidden());
    QCOMPARE(table->model()->rowCount(), 1);
}

void TestQueryPage::filtersAndClearUpdateEmptyState() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    wireFilters(page, proxy);
    model.addEvent(makeEvent("local.example", "Local"));
    model.addEvent(makeEvent("other.example", "Blocked"));
    page.setModels(&model, &proxy);
    auto* table = page.findChild<QTableView*>();
    auto* search = page.findChild<QLineEdit*>();
    auto* status = page.findChild<QComboBox*>();
    QVERIFY(table && search && status);
    search->setText(QStringLiteral("local"));
    status->setCurrentIndex(status->findData(QStringLiteral("Local")));
    QCOMPARE(proxy.rowCount(), 1);
    QVERIFY(!table->isHidden());
    search->setText(QStringLiteral("missing"));
    QCOMPARE(proxy.rowCount(), 0);
    QVERIFY(table->isHidden());
    search->clear();
    QVERIFY(!table->isHidden());
    model.clear();
    QVERIFY(table->isHidden());
    QVERIFY(emptyLabel(page));
    QCOMPARE(emptyLabel(page)->text(), QStringLiteral("No queries recorded yet."));
}

void TestQueryPage::statusOnlyNoResultsHasAccurateMessage() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    wireFilters(page, proxy);
    model.addEvent(makeEvent("ok.example"));
    page.setModels(&model, &proxy);
    auto* status = page.findChild<QComboBox*>();
    QVERIFY(status);
    status->setCurrentIndex(status->findData(QStringLiteral("Blocked")));
    QVERIFY(emptyLabel(page));
    QCOMPARE(emptyLabel(page)->text(), QStringLiteral("No queries match the current filters."));
}

void TestQueryPage::sortingUsesClickedColumn() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    model.addEvent(makeEvent("z-fast.example", "Resolved", 3));
    model.addEvent(makeEvent("a-slow.example", "Resolved", 250));
    page.setModels(&model, &proxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    QVERIFY(table->isSortingEnabled());
    table->sortByColumn(QueryLogModel::ColLatency, Qt::AscendingOrder);
    QCOMPARE(proxy.index(0, QueryLogModel::ColDomain).data().toString(), QStringLiteral("z-fast.example"));
    table->sortByColumn(QueryLogModel::ColDomain, Qt::DescendingOrder);
    QCOMPARE(proxy.index(0, QueryLogModel::ColDomain).data().toString(), QStringLiteral("z-fast.example"));
}

void TestQueryPage::searchFocusAndClearAreSignalsOnly() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    page.setModels(&model, &proxy);
    QSignalSpy searchChanges(&page, &QueryLogPage::searchChanged);
    QSignalSpy clearRequests(&page, &QueryLogPage::clearRequested);
    auto* search = page.findChild<QLineEdit*>();
    auto* clear = page.findChild<QPushButton*>();
    QVERIFY(search && clear);
    search->setText(QStringLiteral("example"));
    page.focusSearch();
    QCOMPARE(search->selectedText(), QStringLiteral("example"));
    QCOMPARE(searchChanges.count(), 1);
    clear->click();
    QCOMPARE(clearRequests.count(), 1);
}

void TestQueryPage::contextInspectionKeepsEvictedSnapshot() {
    QueryLogModel model(nullptr, 1);
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    model.addEvent(makeEvent("original.example"));
    page.setModels(&model, &proxy);
    page.resize(900, 400);
    page.show();
    QCoreApplication::processEvents();
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    const QPoint pos = table->visualRect(proxy.index(0, QueryLogModel::ColDomain)).center();
    QVERIFY(table->indexAt(pos).isValid());
    QString inspected;
    connect(&page, &QueryLogPage::inspectRequested, this, [&inspected](const ResolveEvent& entry) {
        inspected = QString::fromStdString(entry.queryName);
    });
    bool foundMenu = false;
    QTimer::singleShot(0, &page, [&] {
        auto* menu = page.findChild<QMenu*>();
        if (!menu) return;
        foundMenu = true;
        // A received query evicts the row while the menu's nested event loop runs.
        model.addEvent(makeEvent("replacement.example"));
        menu->actions().first()->trigger();
        menu->close();
    });
    table->customContextMenuRequested(pos);
    QVERIFY(foundMenu);
    QCOMPARE(inspected, QStringLiteral("original.example"));
    QCOMPARE(QString::fromStdString(model.snapshot(0)->queryName), QStringLiteral("replacement.example"));
}

void TestQueryPage::doubleClickInspectsClickedRow() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    model.addEvent(makeEvent("first.example"));
    model.addEvent(makeEvent("second.example"));
    page.setModels(&model, &proxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    QString inspected;
    connect(&page, &QueryLogPage::inspectRequested, this, [&inspected](const ResolveEvent& entry) {
        inspected = QString::fromStdString(entry.queryName);
    });
    table->selectRow(0);
    table->doubleClicked(proxy.index(1, QueryLogModel::ColDomain));
    QCOMPARE(inspected, proxy.index(1, QueryLogModel::ColDomain).data().toString());
}

void TestQueryPage::rebindingDisconnectsPreviousModel() {
    QueryLogModel first;
    QueryLogModel second;
    QueryLogFilterProxyModel firstProxy;
    QueryLogFilterProxyModel secondProxy;
    QueryLogPage page;
    page.setModels(&first, &firstProxy);
    page.setModels(&second, &secondProxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    first.addEvent(makeEvent("old.example"));
    QVERIFY(table->isHidden());
    second.addEvent(makeEvent("current.example"));
    QVERIFY(!table->isHidden());
    QCOMPARE(table->model(), &secondProxy);
    page.setModels(nullptr, nullptr);
    QVERIFY(!table->model());
    QVERIFY(table->isHidden());
    QCOMPARE(page.selectedSourceRow(), -1);
    second.addEvent(makeEvent("disconnected.example"));
    QVERIFY(table->isHidden());
}

void TestQueryPage::filteredFirstArrivalUpdatesEmptyMessage() {
    QueryLogModel model;
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    wireFilters(page, proxy);
    page.setModels(&model, &proxy);
    auto* status = page.findChild<QComboBox*>();
    QVERIFY(status);
    status->setCurrentIndex(status->findData(QStringLiteral("Blocked")));
    model.addEvent(makeEvent("resolved.example"));
    QCOMPARE(proxy.rowCount(), 0);
    QVERIFY(emptyLabel(page));
    QCOMPARE(emptyLabel(page)->text(), QStringLiteral("No queries match the current filters."));
    model.clear();
    QCOMPARE(emptyLabel(page)->text(), QStringLiteral("No queries recorded yet."));
}

void TestQueryPage::proxyWithoutSourceRemainsEmpty() {
    QueryLogFilterProxyModel proxy;
    QueryLogPage page;
    page.setModels(nullptr, &proxy);
    auto* table = page.findChild<QTableView*>();
    QVERIFY(table);
    QCOMPARE(table->horizontalHeader()->count(), 0);
    QVERIFY(!table->isSortingEnabled());
    QVERIFY(table->isHidden());
    QCOMPARE(page.selectedSourceRow(), -1);
}

QTEST_MAIN(TestQueryPage)
#include "test_querypage.moc"
