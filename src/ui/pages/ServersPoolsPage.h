#pragma once

#include <QWidget>

#include <string>
#include <vector>

#include "core/Config.h"

class QComboBox;
class QPushButton;
class QTableWidget;

// Upstream and pool tables with selection-aware actions and a clear default
// target. Display only: edits go out as signals and MainWindow owns the draft.
class ServersPoolsPage : public QWidget {
    Q_OBJECT

public:
    explicit ServersPoolsPage(QWidget* parent = nullptr);

    void setUpstreams(const std::vector<UpstreamConfig>& upstreams);
    void setPools(const std::vector<PoolConfig>& pools);
    // Options must be provided as display label + stable name pairs.
    void setDefaultTargets(const QList<QPair<QString, QString>>& targets, const std::string& current);
    std::string defaultTarget() const;

    int selectedUpstreamRow() const;
    int selectedPoolRow() const;
    void selectUpstreamRow(int row);

    // Inline test feedback on the upstream table's latency column.
    void setUpstreamStatus(int row, const QString& text, bool isFailure);

signals:
    void addUpstreamRequested();
    void editUpstreamRequested(int row);
    void deleteUpstreamRequested(int row);
    void testUpstreamRequested(int row);
    void addPoolRequested();
    void editPoolRequested(int row);
    void deletePoolRequested(int row);
    void defaultTargetChanged(const QString& name);
    void openPublicResolversRequested();

private:
    void updateActionState();

    QTableWidget* upstreamTable_ = nullptr;
    QTableWidget* poolTable_ = nullptr;
    QComboBox* defaultTargetCombo_ = nullptr;
    QPushButton* editUpstreamButton_ = nullptr;
    QPushButton* deleteUpstreamButton_ = nullptr;
    QPushButton* testUpstreamButton_ = nullptr;
    QPushButton* editPoolButton_ = nullptr;
    QPushButton* deletePoolButton_ = nullptr;
};
