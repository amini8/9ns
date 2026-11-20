#pragma once

#include <QDialog>

#include "core/Config.h"

class QCheckBox;
class QComboBox;
class QLineEdit;
class QRadioButton;

// Guided wizard for initial setup (Public Encrypted DNS presets or Custom Server).
class WizardDialog : public QDialog {
    Q_OBJECT

public:
    explicit WizardDialog(QWidget* parent = nullptr);
    ~WizardDialog() override = default;

    Config resultConfig() const;

private slots:
    void onSelectionChanged();

private:
    void buildUi();

    QRadioButton* presetRadio_ = nullptr;
    QComboBox* presetCombo_ = nullptr;

    QRadioButton* customRadio_ = nullptr;
    QComboBox* customTypeCombo_ = nullptr;
    QLineEdit* customAddressEdit_ = nullptr;

    QCheckBox* systemDnsCheck_ = nullptr;
    QCheckBox* leakPreventCheck_ = nullptr;
    QCheckBox* dnssecCheck_ = nullptr;
};
