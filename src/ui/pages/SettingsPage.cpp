#include "ui/pages/SettingsPage.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QVBoxLayout>

#include "ui/Theme.h"

SettingsPage::SettingsPage(QWidget* parent) : QWidget(parent) {
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* body = new QWidget(scroll);
    auto* root = new QVBoxLayout(body);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    // Listener & cache
    auto* listenerBox = new QGroupBox(tr("Listener & Cache"), body);
    auto* listenerForm = new QFormLayout(listenerBox);
    portSpin_ = new QSpinBox(listenerBox);
    portSpin_->setRange(1, 65535);
    portSpin_->setToolTip(tr("UDP/TCP port 9NS listens on (53 for system DNS)"));
    listenerForm->addRow(tr("Listen &port:"), portSpin_);
    cacheSpin_ = new QSpinBox(listenerBox);
    cacheSpin_->setRange(0, 1000000);
    cacheSpin_->setToolTip(tr("Maximum cached replies (0 turns the cache off)"));
    listenerForm->addRow(tr("&Cache entries:"), cacheSpin_);
    minTtlSpin_ = new QSpinBox(listenerBox);
    minTtlSpin_->setRange(0, 86400);
    minTtlSpin_->setToolTip(tr("Minimum TTL applied to upstream replies (0 keeps upstream TTL)"));
    listenerForm->addRow(tr("Minimum &TTL (s):"), minTtlSpin_);
    maxTtlSpin_ = new QSpinBox(listenerBox);
    maxTtlSpin_->setRange(0, 86400);
    maxTtlSpin_->setToolTip(tr("Maximum TTL applied to upstream replies"));
    listenerForm->addRow(tr("Ma&ximum TTL (s):"), maxTtlSpin_);
    negativeTtlSpin_ = new QSpinBox(listenerBox);
    negativeTtlSpin_->setRange(0, 86400);
    negativeTtlSpin_->setToolTip(tr("TTL for negative (NXDOMAIN) replies"));
    listenerForm->addRow(tr("&Negative TTL (s):"), negativeTtlSpin_);
    root->addWidget(listenerBox);

    // Security
    auto* securityBox = new QGroupBox(tr("Security & Privacy"), body);
    auto* securityLayout = new QVBoxLayout(securityBox);
    systemDnsCheck_ = new QCheckBox(tr("Set 9NS as the Windows system DNS"), securityBox);
    ipv6Check_ = new QCheckBox(tr("Redirect IPv6 loopback (::1) as well as 127.0.0.1"), securityBox);
    leakPreventCheck_ = new QCheckBox(tr("Prevent DNS leaks (disable Smart Multi-Homed Resolution)"), securityBox);
    dnssecCheck_ = new QCheckBox(tr("DNSSEC validation (trust AD from authenticated resolvers)"), securityBox);
    securityLayout->addWidget(systemDnsCheck_);
    securityLayout->addWidget(ipv6Check_);
    securityLayout->addWidget(leakPreventCheck_);
    securityLayout->addWidget(dnssecCheck_);
    root->addWidget(securityBox);

    // Application
    auto* appBox = new QGroupBox(tr("Application & Background Operation"), body);
    auto* appLayout = new QVBoxLayout(appBox);
    autostartCheck_ = new QCheckBox(tr("Start 9NS when I sign in"), appBox);
    closeToTrayCheck_ = new QCheckBox(tr("Closing the window keeps 9NS in the tray"), appBox);
    appLayout->addWidget(autostartCheck_);
    appLayout->addWidget(closeToTrayCheck_);

    auto* serviceRow = new QHBoxLayout();
    auto* installBtn = new QPushButton(tr("Install Windows Service"), appBox);
    connect(installBtn, &QPushButton::clicked, this, &SettingsPage::installServiceRequested);
    auto* uninstallBtn = new QPushButton(tr("Uninstall Windows Service"), appBox);
    connect(uninstallBtn, &QPushButton::clicked, this, &SettingsPage::uninstallServiceRequested);
    serviceRow->addWidget(installBtn);
    serviceRow->addWidget(uninstallBtn);
    serviceRow->addStretch(1);
    appLayout->addLayout(serviceRow);
    appLayout->addWidget(new QLabel(tr("Service management is independent of saving the configuration."), appBox));
    root->addWidget(appBox);

    // Logging
    auto* logBox = new QGroupBox(tr("Logging"), body);
    auto* logForm = new QFormLayout(logBox);
    logLevelCombo_ = new QComboBox(logBox);
    logLevelCombo_->addItems({QStringLiteral("error"), QStringLiteral("info"), QStringLiteral("debug")});
    logForm->addRow(tr("Log &level:"), logLevelCombo_);
    logFileEdit_ = new QLineEdit(logBox);
    logFileEdit_->setToolTip(tr("Log file name inside the data folder (empty disables the log file)"));
    logForm->addRow(tr("Log &file:"), logFileEdit_);
    root->addWidget(logBox);

    root->addStretch(1);
    scroll->setWidget(body);
    outer->addWidget(scroll, 1);

    auto* actions = new QHBoxLayout();
    auto* saveBtn = new QPushButton(tr("Save Changes"), this);
    saveBtn->setDefault(true);
    connect(saveBtn, &QPushButton::clicked, this, &SettingsPage::saveRequested);
    auto* reloadBtn = new QPushButton(tr("Reload from Disk"), this);
    connect(reloadBtn, &QPushButton::clicked, this, &SettingsPage::reloadRequested);
    auto* openFolderBtn = new QPushButton(tr("Open Data Folder"), this);
    connect(openFolderBtn, &QPushButton::clicked, this, &SettingsPage::openDataFolderRequested);
    actions->addWidget(saveBtn);
    actions->addWidget(reloadBtn);
    actions->addWidget(openFolderBtn);
    actions->addStretch(1);
    outer->addLayout(actions);
}

void SettingsPage::setValues(const Config& config) {
    portSpin_->setValue(config.listenPort);
    cacheSpin_->setValue(static_cast<int>(config.cacheEntries));
    minTtlSpin_->setValue(static_cast<int>(config.minTtl));
    maxTtlSpin_->setValue(static_cast<int>(config.maxTtl));
    negativeTtlSpin_->setValue(static_cast<int>(config.negativeTtl));
    systemDnsCheck_->setChecked(config.systemDns);
    ipv6Check_->setChecked(config.ipv6Loopback);
    leakPreventCheck_->setChecked(config.preventDnsLeaks);
    dnssecCheck_->setChecked(config.dnssecValidation);
    autostartCheck_->setChecked(config.autostart);
    closeToTrayCheck_->setChecked(config.closeToTray);
    logLevelCombo_->setCurrentText(QString::fromStdString(config.logLevel));
    logFileEdit_->setText(QString::fromStdString(config.logFile));
}

void SettingsPage::applyTo(Config& config) const {
    config.listenPort = static_cast<uint16_t>(portSpin_->value());
    config.cacheEntries = static_cast<std::size_t>(cacheSpin_->value());
    config.minTtl = static_cast<uint32_t>(minTtlSpin_->value());
    config.maxTtl = static_cast<uint32_t>(maxTtlSpin_->value());
    config.negativeTtl = static_cast<uint32_t>(negativeTtlSpin_->value());
    config.systemDns = systemDnsCheck_->isChecked();
    config.ipv6Loopback = ipv6Check_->isChecked();
    config.preventDnsLeaks = leakPreventCheck_->isChecked();
    config.dnssecValidation = dnssecCheck_->isChecked();
    config.autostart = autostartCheck_->isChecked();
    config.closeToTray = closeToTrayCheck_->isChecked();
    config.logLevel = logLevelCombo_->currentText().toStdString();
    config.logFile = logFileEdit_->text().trimmed().toStdString();
}
