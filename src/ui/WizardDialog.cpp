#include "ui/WizardDialog.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

WizardDialog::WizardDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("First Start Wizard - 9NS"));
    resize(520, 480);
    buildUi();
    onSelectionChanged();
}

void WizardDialog::buildUi() {
    setWindowIcon(QIcon(QStringLiteral(":/icons/9ns-mark.svg")));
    auto* root = new QVBoxLayout(this);

    auto* bannerRow = new QHBoxLayout();
    auto* logoLabel = new QLabel(this);
    logoLabel->setPixmap(QIcon(QStringLiteral(":/icons/9ns-mark.svg")).pixmap(48, 48));
    logoLabel->setFixedSize(48, 48);

    auto* banner = new QLabel(tr("<h3>Welcome to 9NS!</h3>"
                                 "<p>Select how you would like to route and encrypt your Windows DNS queries.</p>"), this);
    banner->setWordWrap(true);
    bannerRow->addWidget(logoLabel);
    bannerRow->addWidget(banner, 1);
    root->addLayout(bannerRow);

    auto* buttonGroup = new QButtonGroup(this);

    // Option 1: Presets
    auto* presetBox = new QGroupBox(tr("Public Encrypted DNS Providers"), this);
    auto* presetLayout = new QFormLayout(presetBox);
    presetRadio_ = new QRadioButton(tr("Use a popular secure DNS provider"), presetBox);
    buttonGroup->addButton(presetRadio_);
    presetCombo_ = new QComboBox(presetBox);
    const auto presets = publicDnsPresets();
    for (const auto& p : presets) {
        presetCombo_->addItem(QString::fromStdString(p.name) + " (" + QString::fromStdString(p.type) + ")",
                              QString::fromStdString(p.name));
    }
    presetLayout->addRow(presetRadio_);
    presetLayout->addRow(tr("Provider:"), presetCombo_);
    root->addWidget(presetBox);

    // Option 2: Custom
    auto* customBox = new QGroupBox(tr("Custom Upstream Server"), this);
    auto* customLayout = new QFormLayout(customBox);
    customRadio_ = new QRadioButton(tr("Manually configure a DNS server"), customBox);
    buttonGroup->addButton(customRadio_);
    customTypeCombo_ = new QComboBox(customBox);
    customTypeCombo_->addItems(QStringList{QStringLiteral("doh"), QStringLiteral("dot"), QStringLiteral("plain"), QStringLiteral("dnscrypt"), QStringLiteral("odoh"), QStringLiteral("doq")});
    customAddressEdit_ = new QLineEdit(customBox);
    customAddressEdit_->setPlaceholderText(tr("e.g. https://1.1.1.1/dns-query or 8.8.8.8"));

    customLayout->addRow(customRadio_);
    customLayout->addRow(tr("Protocol:"), customTypeCombo_);
    customLayout->addRow(tr("Address / URL:"), customAddressEdit_);
    root->addWidget(customBox);

    // Options Group
    auto* optionsBox = new QGroupBox(tr("System Security & Privacy Settings"), this);
    auto* optLayout = new QVBoxLayout(optionsBox);
    systemDnsCheck_ = new QCheckBox(tr("Automatically set 9NS as Windows System DNS"), optionsBox);
    systemDnsCheck_->setChecked(true);
    leakPreventCheck_ = new QCheckBox(tr("Prevent DNS leaks (Disable Smart Multi-Homed Resolution)"), optionsBox);
    leakPreventCheck_->setChecked(true);
    dnssecCheck_ = new QCheckBox(tr("Enable DNSSEC validation (trust AD from authenticated resolvers)"), optionsBox);
    dnssecCheck_->setChecked(true);
    optLayout->addWidget(systemDnsCheck_);
    optLayout->addWidget(leakPreventCheck_);
    optLayout->addWidget(dnssecCheck_);
    forwardProxyCheck_ = new QCheckBox(tr("Enable local SOCKS / HTTP CONNECT proxy (port 1080)"), optionsBox);
    forwardProxyCheck_->setObjectName(QStringLiteral("forwardProxyEnabled"));
    forwardProxyCheck_->setChecked(false);
    forwardProxyCheck_->setToolTip(tr("Optional loopback-only proxy. SOCKS5, SOCKS4a and HTTP CONNECT share one port. Configure authentication and the port in Settings."));
    optLayout->addWidget(forwardProxyCheck_);
    root->addWidget(optionsBox);

    presetRadio_->setChecked(true);

    connect(presetRadio_, &QRadioButton::toggled, this, &WizardDialog::onSelectionChanged);
    connect(customRadio_, &QRadioButton::toggled, this, &WizardDialog::onSelectionChanged);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Apply & Start"));
    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttonBox);
}

void WizardDialog::onSelectionChanged() {
    presetCombo_->setEnabled(presetRadio_->isChecked());
    customTypeCombo_->setEnabled(customRadio_->isChecked());
    customAddressEdit_->setEnabled(customRadio_->isChecked());
}

Config WizardDialog::resultConfig() const {
    Config config = defaultConfig();
    config.systemDns = systemDnsCheck_->isChecked();
    config.preventDnsLeaks = leakPreventCheck_->isChecked();
    config.dnssecValidation = dnssecCheck_->isChecked();
    config.forwardProxy.enabled = forwardProxyCheck_->isChecked();
    config.upstreams.clear();

    if (presetRadio_->isChecked()) {
        const std::string selected = presetCombo_->currentData().toString().toStdString();
        const auto presets = publicDnsPresets();
        for (const auto& p : presets) {
            if (p.name == selected) {
                config.upstreams.push_back(p);
                config.defaultTarget = p.name;
                config.defaultUpstream = p.name;
                break;
            }
        }
    } else if (customRadio_->isChecked()) {
        UpstreamConfig up;
        up.name = "custom";
        up.type = customTypeCombo_->currentText().toStdString();
        up.address = customAddressEdit_->text().trimmed().toStdString();
        if (up.address.empty()) {
            up.address = "https://1.1.1.1/dns-query";
            up.type = "doh";
        }
        config.upstreams.push_back(up);
        config.defaultTarget = "custom";
        config.defaultUpstream = "custom";
    }

    if (config.upstreams.empty()) {
        config = defaultConfig();
    }
    return config;
}
