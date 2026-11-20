#pragma once

#include <algorithm>
#include <string>
#include <vector>

#include "core/Config.h"

// Display order for the pool member editor: current members first in their
// saved priority order (including members whose upstream is currently missing),
// then the remaining upstreams. Save collects checked items in list order, so
// the priority round-trips. Inline so the offline dialog tests can use it.
inline std::vector<std::string> poolMemberListOrder(const std::vector<std::string>& poolServers,
                                                    const std::vector<std::string>& upstreamNames) {
    std::vector<std::string> order = poolServers;
    for (const std::string& name : upstreamNames) {
        if (std::find(order.begin(), order.end(), name) == order.end()) {
            order.push_back(name);
        }
    }
    return order;
}

// The dialog itself needs Qt Widgets. Offline tests link only Qt Test and
// include this header for the ordering helper above, so keep the widgets
// behind __has_include (see ServerDialog.h).
#if __has_include(<QDialog>)

#include <QDialog>

class QComboBox;
class QLineEdit;
class QListWidget;
class QPushButton;

// Dialog to add or edit a DNS Server Pool and configure load balancing or failover strategies.
class PoolDialog : public QDialog {
    Q_OBJECT

public:
    explicit PoolDialog(PoolConfig& pool, const std::vector<UpstreamConfig>& availableUpstreams, QWidget* parent = nullptr);
    ~PoolDialog() override = default;

private slots:
    void onSaveClicked();
    void onMoveUp();
    void onMoveDown();

private:
    void buildUi();

    PoolConfig& pool_;
    const std::vector<UpstreamConfig>& upstreams_;

    QLineEdit* nameEdit_ = nullptr;
    QComboBox* strategyCombo_ = nullptr;
    QListWidget* serverList_ = nullptr;
    QPushButton* moveUpBtn_ = nullptr;
    QPushButton* moveDownBtn_ = nullptr;
};

#endif  // __has_include(<QDialog>)
