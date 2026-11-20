#include "ui/QueryLogFilterProxyModel.h"

#include "ui/QueryLogModel.h"

QueryLogFilterProxyModel::QueryLogFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent) {
    setDynamicSortFilter(true);
}

void QueryLogFilterProxyModel::setDomainFilter(const QString& pattern) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif
    domainPattern_ = pattern.trimmed();
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(Direction::Rows);
#else
    invalidateFilter();
#endif
}

void QueryLogFilterProxyModel::setStatusFilter(const QString& status) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
#endif
    status_ = status;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    endFilterChange(Direction::Rows);
#else
    invalidateFilter();
#endif
}

bool QueryLogFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const {
    if (!status_.isEmpty()) {
        const QModelIndex actionIdx = sourceModel()->index(sourceRow, QueryLogModel::ColAction, sourceParent);
        if (sourceModel()->data(actionIdx, Qt::DisplayRole).toString() != status_) {
            return false;
        }
    }
    if (!domainPattern_.isEmpty()) {
        const QModelIndex domainIdx = sourceModel()->index(sourceRow, QueryLogModel::ColDomain, sourceParent);
        const QString domain = sourceModel()->data(domainIdx, Qt::DisplayRole).toString();
        if (!domain.contains(domainPattern_, Qt::CaseInsensitive)) {
            return false;
        }
    }
    return true;
}

bool QueryLogFilterProxyModel::lessThan(const QModelIndex& left, const QModelIndex& right) const {
    // Typed roles pick the metric explicitly; the natural columns stay typed
    // too so header-driven sorting is never lexicographic for time or latency.
    int role = 0;
    if (sortRole() == QueryLogModel::SortLatency) {
        role = QueryLogModel::SortLatency;
    } else if (sortRole() == QueryLogModel::SortTimestamp) {
        role = QueryLogModel::SortTimestamp;
    } else if (left.column() == QueryLogModel::ColLatency) {
        role = QueryLogModel::SortLatency;
    } else if (left.column() == QueryLogModel::ColTime) {
        role = QueryLogModel::SortTimestamp;
    }
    if (role == 0) {
        return QSortFilterProxyModel::lessThan(left, right);
    }
    return left.data(role).toLongLong() < right.data(role).toLongLong();
}
