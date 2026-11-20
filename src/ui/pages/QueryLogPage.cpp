#include "ui/pages/QueryLogPage.h"

#include <QAbstractItemModel>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStackedLayout>
#include <QTableView>
#include <QVBoxLayout>

#include "ui/QueryLogModel.h"
#include "ui/Theme.h"

QueryLogPage::QueryLogPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    auto* filters = new QHBoxLayout();
    auto* searchLabel = new QLabel(tr("&Domain:"), this);
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText(tr("Filter by domain substring"));
    searchEdit_->setClearButtonEnabled(true);
    searchEdit_->setAccessibleName(tr("Domain search"));
    searchLabel->setBuddy(searchEdit_);
    connect(searchEdit_, &QLineEdit::textChanged, this, [this](const QString& pattern) {
        emit searchChanged(pattern);
        updateEmptyState();
    });

    auto* statusLabel = new QLabel(tr("&Status:"), this);
    statusFilter_ = new QComboBox(this);
    statusFilter_->setAccessibleName(tr("Status filter"));
    statusFilter_->addItem(tr("All"), QString());
    for (const QString& status : {QStringLiteral("Resolved"), QStringLiteral("Cached"), QStringLiteral("Blocked"),
                                  QStringLiteral("Local"), QStringLiteral("Error"), QStringLiteral("Bogus")}) {
        statusFilter_->addItem(status, status);
    }
    statusLabel->setBuddy(statusFilter_);
    connect(statusFilter_, &QComboBox::currentIndexChanged, this, [this] {
        emit statusFilterChanged(statusFilter_->currentData().toString());
        updateEmptyState();
    });

    clearButton_ = new QPushButton(tr("Clear Log"), this);
    connect(clearButton_, &QPushButton::clicked, this, &QueryLogPage::clearRequested);

    filters->addWidget(searchLabel);
    filters->addWidget(searchEdit_, 1);
    filters->addWidget(statusLabel);
    filters->addWidget(statusFilter_);
    filters->addSpacing(Theme::spacingLarge());
    filters->addWidget(clearButton_);
    root->addLayout(filters);

    tableView_ = new QTableView(this);
    tableView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView_->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableView_->setAlternatingRowColors(true);
    tableView_->setWordWrap(false);
    tableView_->setAccessibleName(tr("Query log"));
    tableView_->horizontalHeader()->setStretchLastSection(false);
    connect(tableView_, &QTableView::doubleClicked, this, &QueryLogPage::inspectIndex);

    // Context actions operate on the snapshot taken when the menu opens, so
    // incoming rows or eviction cannot retarget them.
    tableView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tableView_, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
        const QModelIndex proxyIndex = tableView_->indexAt(pos);
        if (!proxyIndex.isValid() || !proxy_) {
            return;
        }
        const QModelIndex srcIndex = proxy_->mapToSource(proxyIndex);
        const auto* source = qobject_cast<QueryLogModel*>(proxy_->sourceModel());
        const auto snapshot = source ? source->snapshot(srcIndex.row()) : std::nullopt;
        if (!snapshot) return;
        const ResolveEvent entry = *snapshot;
        const QString domain = QString::fromStdString(entry.queryName);

        QMenu menu(this);
        menu.addAction(tr("Inspect Query Details…"), this, [this, entry] {
            emit inspectRequested(entry);
        });
        menu.addSeparator();
        menu.addAction(tr("Block Domain (*.%1)").arg(domain), this, [this, domain] {
            emit blockDomainRequested(domain);
        });
        menu.addAction(tr("Bypass Domain (*.%1)").arg(domain), this, [this, domain] {
            emit bypassDomainRequested(domain);
        });
        menu.addSeparator();
        menu.addAction(tr("Copy Domain Name"), this, [domain] {
            QGuiApplication::clipboard()->setText(domain);
        });
        menu.exec(tableView_->viewport()->mapToGlobal(pos));
    });

    emptyLabel_ = new QLabel(tr("No queries recorded yet."), this);
    emptyLabel_->setAlignment(Qt::AlignCenter);
    emptyLabel_->setStyleSheet(QStringLiteral("color: #64748B; font-size: 14px;"));

    contentStack_ = new QStackedLayout();
    contentStack_->addWidget(emptyLabel_);
    contentStack_->addWidget(tableView_);
    contentStack_->setCurrentWidget(emptyLabel_);
    root->addLayout(contentStack_, 1);
}

void QueryLogPage::setModels(QAbstractItemModel* source, QSortFilterProxyModel* proxy) {
    if (proxy_) disconnect(proxy_, nullptr, this, nullptr);
    if (source_) disconnect(source_, nullptr, this, nullptr);
    source_ = source;
    proxy_ = proxy;
    if (proxy_) {
        proxy_->setSourceModel(source);
        // The proxy chooses typed time/latency comparisons by column. A single
        // metric sort role would incorrectly sort every clicked column by time.
        proxy_->setSortRole(Qt::DisplayRole);
        connect(proxy_, &QAbstractItemModel::rowsInserted, this, &QueryLogPage::updateEmptyState);
        connect(proxy_, &QAbstractItemModel::rowsRemoved, this, &QueryLogPage::updateEmptyState);
        connect(proxy_, &QAbstractItemModel::modelReset, this, &QueryLogPage::updateEmptyState);
        connect(proxy_, &QAbstractItemModel::layoutChanged, this, &QueryLogPage::updateEmptyState);
    }
    tableView_->setModel(proxy_);
    if (source_) {
        // A filtered-out arrival changes history without inserting a proxy row.
        connect(source_, &QAbstractItemModel::rowsInserted, this, &QueryLogPage::updateEmptyState);
        connect(source_, &QAbstractItemModel::rowsRemoved, this, &QueryLogPage::updateEmptyState);
        connect(source_, &QAbstractItemModel::modelReset, this, &QueryLogPage::updateEmptyState);
    }
    const bool hasColumns = proxy_ && proxy_->columnCount() >= QueryLogModel::ColCount;
    tableView_->setSortingEnabled(hasColumns);
    if (hasColumns) {
        // Per-column modes only take effect once the header has model sections.
        tableView_->horizontalHeader()->setSectionResizeMode(QueryLogModel::ColDomain, QHeaderView::Stretch);
        tableView_->horizontalHeader()->setSectionResizeMode(QueryLogModel::ColTime, QHeaderView::ResizeToContents);
        tableView_->horizontalHeader()->setSectionResizeMode(QueryLogModel::ColLatency, QHeaderView::ResizeToContents);
        tableView_->sortByColumn(QueryLogModel::ColTime, Qt::DescendingOrder);
    }
    updateEmptyState();
}

void QueryLogPage::inspectIndex(const QModelIndex& index) {
    if (!proxy_ || !index.isValid()) return;
    const auto* source = qobject_cast<QueryLogModel*>(proxy_->sourceModel());
    const auto snapshot = source ? source->snapshot(proxy_->mapToSource(index).row()) : std::nullopt;
    if (snapshot) emit inspectRequested(*snapshot);
}

void QueryLogPage::updateEmptyState() {
    showNoResults(!proxy_ || proxy_->rowCount() == 0);
}

void QueryLogPage::focusSearch() {
    searchEdit_->setFocus();
    searchEdit_->selectAll();
}

int QueryLogPage::selectedSourceRow() const {
    if (!proxy_) {
        return -1;
    }
    const QModelIndexList selected = tableView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) {
        return -1;
    }
    return proxy_->mapToSource(selected.first()).row();
}

void QueryLogPage::showNoResults(bool noResults) {
    if (noResults) {
        const bool noHistory = !proxy_ || !proxy_->sourceModel() || proxy_->sourceModel()->rowCount() == 0;
        emptyLabel_->setText(noHistory
                                 ? tr("No queries recorded yet.")
                                 : tr("No queries match the current filters."));
        contentStack_->setCurrentWidget(emptyLabel_);
    } else {
        contentStack_->setCurrentWidget(tableView_);
    }
}
