#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

// Protection summary, live metrics and per-upstream latency. Display only: it
// never touches the Engine or the configuration; MainWindow feeds it values.
class OverviewPage : public QWidget {
    Q_OBJECT

public:
    // Latency cell states for the upstream table.
    enum class LatencyState { NotTested, Testing, Success, Failure };

    explicit OverviewPage(QWidget* parent = nullptr);

    void setProtectionSummary(const QString& html);
    void setMetrics(quint64 totalQueries, quint64 blockedQueries, double qps, double hitRatePercent);
    void setUpstreamCount(int count);
    void setUpstreamRow(int row, const QString& name, const QString& type, const QString& address);
    void setLatency(int row, LatencyState state, const QString& detail);
    void clearLatency();

signals:
    void startStopRequested();
    void saveRequested();
    void flushCacheRequested();
    void testUpstreamRequested(int row);

private:
    QLabel* summaryLabel_ = nullptr;
    QLabel* totalQueriesLabel_ = nullptr;
    QLabel* blockedLabel_ = nullptr;
    QLabel* qpsLabel_ = nullptr;
    QLabel* hitRateLabel_ = nullptr;
    QTableWidget* upstreamTable_ = nullptr;
};
