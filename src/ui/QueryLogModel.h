#pragma once

#include <deque>
#include <optional>

#include <QAbstractTableModel>
#include <QDateTime>
#include <QString>

#include "core/Resolver.h"

// Table model storing real-time DNS resolution events with bounded history.
// Use it from the GUI thread only; resolver threads must deliver events through
// queued connections. Each entry keeps the immutable time it was received.
class QueryLogModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColTime = 0,
        ColClient,
        ColDomain,
        ColType,
        ColTarget,
        ColAction,
        ColRcode,
        ColLatency,
        ColDnsSec,
        ColCount
    };

    // Typed sorting values: chronological receipt time and numeric latency.
    // For any column these return the entry's metric so proxies sort by the
    // metric rather than the formatted display string.
    enum SortRole {
        SortTimestamp = Qt::UserRole + 1,
        SortLatency,
    };

    explicit QueryLogModel(QObject* parent = nullptr, size_t maxEntries = 5000);
    ~QueryLogModel() override = default;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    void addEvent(const ResolveEvent& event);
    void clear();

    // Copies the entry at row, immune to later insertion or eviction. Use this
    // instead of touching rows by pointer before nested menus or dialogs run.
    std::optional<ResolveEvent> snapshot(int row) const;

private:
    struct Entry {
        ResolveEvent event;
        QDateTime receivedAt;
    };

    size_t maxEntries_;
    std::deque<Entry> events_;
};
