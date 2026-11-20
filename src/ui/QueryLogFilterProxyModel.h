#pragma once

#include <QSortFilterProxyModel>
#include <QString>

// Combines a case-insensitive domain substring filter with an exact action
// filter (AND semantics) over QueryLogModel. Pass an empty status string to
// accept every action value. Sorting honors QueryLogModel::SortTimestamp and
// QueryLogModel::SortLatency, and the Time/Latency columns sort typed even
// without an explicit sort role.
class QueryLogFilterProxyModel : public QSortFilterProxyModel {
    Q_OBJECT

public:
    explicit QueryLogFilterProxyModel(QObject* parent = nullptr);

    void setDomainFilter(const QString& pattern);
    void setStatusFilter(const QString& status);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
    bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;

private:
    QString domainPattern_;
    QString status_;
};
