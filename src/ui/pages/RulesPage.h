#pragma once

#include <QWidget>

#include <string>
#include <vector>

#include "core/Config.h"

class QPushButton;
class QTableWidget;

// First-match rule list with explicit ordering and selection-aware actions.
// Display only: edits go out as signals and MainWindow updates the draft.
class RulesPage : public QWidget {
    Q_OBJECT

public:
    explicit RulesPage(QWidget* parent = nullptr);

    void setRules(const std::vector<RuleConfig>& rules);
    int selectedRow() const;
    void selectRow(int row);

signals:
    void addRequested();
    void editRequested(int row);
    void deleteRequested(int row);
    void moveRequested(int row, int delta);

private:
    QTableWidget* ruleTable_ = nullptr;
    QPushButton* editButton_ = nullptr;
    QPushButton* deleteButton_ = nullptr;
    QPushButton* upButton_ = nullptr;
    QPushButton* downButton_ = nullptr;

    void updateActionState();
};
