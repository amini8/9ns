#pragma once

#include <QWidget>

#include "core/Config.h"

class QCheckBox;
class QComboBox;
class QLineEdit;
class QSpinBox;

// Scrollable grouped settings form. Display only: values are read and written
// through setValues()/values(); the page never persists anything itself.
class SettingsPage : public QWidget {
    Q_OBJECT

public:
    explicit SettingsPage(QWidget* parent = nullptr);

    void setValues(const Config& config);
    // Fills only the settings fields into an existing config, leaving upstreams,
    // pools and rules untouched.
    void applyTo(Config& config) const;

signals:
    void saveRequested();
    void reloadRequested();
    void installServiceRequested();
    void uninstallServiceRequested();
    void openDataFolderRequested();

private:
    QSpinBox* portSpin_ = nullptr;
    QSpinBox* cacheSpin_ = nullptr;
    QSpinBox* minTtlSpin_ = nullptr;
    QSpinBox* maxTtlSpin_ = nullptr;
    QSpinBox* negativeTtlSpin_ = nullptr;
    QCheckBox* systemDnsCheck_ = nullptr;
    QCheckBox* ipv6Check_ = nullptr;
    QCheckBox* leakPreventCheck_ = nullptr;
    QCheckBox* dnssecCheck_ = nullptr;
    QCheckBox* autostartCheck_ = nullptr;
    QCheckBox* closeToTrayCheck_ = nullptr;
    QComboBox* logLevelCombo_ = nullptr;
    QLineEdit* logFileEdit_ = nullptr;
};
