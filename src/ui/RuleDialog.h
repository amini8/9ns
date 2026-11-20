#pragma once

#include <QDialog>
#include <vector>

#include "core/Config.h"

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
struct InterfaceInfo;

// Dialog to add or edit routing rules with wildcards, hosts files, actions, and interface filters.
class RuleDialog : public QDialog {
    Q_OBJECT

public:
    explicit RuleDialog(RuleConfig& rule,
                        const std::vector<UpstreamConfig>& availableUpstreams,
                        const std::vector<PoolConfig>& availablePools,
                        const std::vector<InterfaceInfo>& interfaces,
                        QWidget* parent = nullptr);
    ~RuleDialog() override = default;

private slots:
    void onActionChanged(const QString& action);
    void onBrowseHostsFile();
    void onSaveClicked();

private:
    void buildUi(const std::vector<InterfaceInfo>& interfaces);

    RuleConfig& rule_;
    const std::vector<UpstreamConfig>& upstreams_;
    const std::vector<PoolConfig>& pools_;

    QLineEdit* nameEdit_ = nullptr;
    QPlainTextEdit* hostnamesEdit_ = nullptr;
    QLineEdit* hostsFileEdit_ = nullptr;
    QPushButton* browseHostsBtn_ = nullptr;

    QComboBox* actionCombo_ = nullptr;
    QComboBox* targetCombo_ = nullptr;
    QComboBox* blockModeCombo_ = nullptr;
    QLineEdit* localIpEdit_ = nullptr;

    QComboBox* interfaceCombo_ = nullptr;
    QComboBox* queryTypeCombo_ = nullptr;
    QComboBox* dnssecCombo_ = nullptr;
};
