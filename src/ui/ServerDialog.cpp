#include "ui/ServerDialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStringList>
#include <QVBoxLayout>

#include "transports/Upstream.h"
#include "ui/ResolverJobs.h"

namespace {

ResolverJobs::Probe pingProbe() {
    return [](const UpstreamConfig& config, uint32_t& rttMs, std::string& error) {
        auto upstream = Upstream::create(config);
        return upstream->ping(rttMs, error);
    };
}

}  // namespace

ServerDialog::ServerDialog(UpstreamConfig& server, QWidget* parent)
    : QDialog(parent), server_(server) {
    setWindowTitle(server_.name.empty() ? tr("Add DNS Server") : tr("Edit DNS Server"));
    resize(480, 420);
    jobs_ = new ResolverJobs(pingProbe(), this);
    connect(jobs_, &ResolverJobs::pingFinished, this, &ServerDialog::onPingFinished);
    buildUi();
    onTypeChanged(typeCombo_->currentText());
}

void ServerDialog::buildUi() {
    auto* root = new QVBoxLayout(this);
    form_ = new QFormLayout();

    nameEdit_ = new QLineEdit(this);
    nameEdit_->setText(QString::fromStdString(server_.name));

    typeCombo_ = new QComboBox(this);
    typeCombo_->addItems(QStringList{QStringLiteral("doh"), QStringLiteral("dot"), QStringLiteral("plain"), QStringLiteral("dnscrypt"), QStringLiteral("odoh"), QStringLiteral("doq")});
    if (!server_.type.empty()) {
        // Keep types the combo does not list (e.g. "relay") selectable so
        // saving without touching the protocol cannot rewrite them.
        if (typeCombo_->findText(QString::fromStdString(server_.type)) < 0) {
            typeCombo_->addItem(QString::fromStdString(server_.type));
        }
        typeCombo_->setCurrentText(QString::fromStdString(server_.type));
    }

    addressEdit_ = new QLineEdit(this);
    addressEdit_->setText(QString::fromStdString(server_.address));

    portSpin_ = new QSpinBox(this);
    portSpin_->setRange(0, 65535);
    portSpin_->setSpecialValueText(tr("Default"));
    portSpin_->setValue(server_.port);

    bootstrapEdit_ = new QLineEdit(this);
    QStringList bootstraps;
    for (const auto& ip : server_.bootstrapIps) {
        bootstraps << QString::fromStdString(ip);
    }
    bootstrapEdit_->setText(bootstraps.join(QStringLiteral(", ")));
    bootstrapEdit_->setPlaceholderText(tr("Comma-separated IP addresses"));

    sniEdit_ = new QLineEdit(this);
    sniEdit_->setText(QString::fromStdString(server_.sni));

    proxyEdit_ = new QLineEdit(this);
    proxyEdit_->setText(QString::fromStdString(server_.proxy));
    proxyEdit_->setPlaceholderText(tr("https://relay-host/path (optional ODoH relay)"));

    tlsVerifyCheck_ = new QCheckBox(tr("Verify TLS certificates"), this);
    tlsVerifyCheck_->setChecked(server_.tlsVerify);

    form_->addRow(tr("Server Name:"), nameEdit_);
    form_->addRow(tr("Protocol:"), typeCombo_);
    form_->addRow(tr("Address / URL:"), addressEdit_);
    form_->addRow(tr("Port:"), portSpin_);
    form_->addRow(tr("Bootstrap IPs:"), bootstrapEdit_);
    form_->addRow(tr("SNI Hostname:"), sniEdit_);
    form_->addRow(tr("ODoH Relay URL:"), proxyEdit_);
    form_->addRow(tlsVerifyCheck_);

    root->addLayout(form_);

    // Test Box
    auto* testBox = new QGroupBox(tr("Reachability & Health Check"), this);
    auto* testLayout = new QHBoxLayout(testBox);
    testButton_ = new QPushButton(tr("Test Server"), testBox);
    testResultLabel_ = new QLabel(tr("Click 'Test Server' to check response time."), testBox);
    testLayout->addWidget(testButton_);
    testLayout->addWidget(testResultLabel_, 1);
    root->addWidget(testBox);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &ServerDialog::onSaveClicked);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttonBox);

    connect(typeCombo_, &QComboBox::currentTextChanged, this, &ServerDialog::onTypeChanged);
    connect(testButton_, &QPushButton::clicked, this, &ServerDialog::onTestClicked);
}

void ServerDialog::onTypeChanged(const QString& type) {
    const bool isTls = (type == "doh" || type == "dot" || type == "odoh" || type == "doq");
    const bool isDot = (type == "dot");
    const bool isDoq = (type == "doq");
    const bool isOdoh = (type == "odoh");

    // Only the rows the protocol uses are shown; the rest are hidden instead
    // of sitting there disabled.
    form_->setRowVisible(bootstrapEdit_, isTls);
    form_->setRowVisible(sniEdit_, isDot || isDoq);
    form_->setRowVisible(proxyEdit_, isOdoh);
    form_->setRowVisible(tlsVerifyCheck_, isTls);
}

ServerFields ServerDialog::fieldsFromWidgets() const {
    ServerFields fields;
    fields.name = nameEdit_->text().trimmed().toStdString();
    fields.type = typeCombo_->currentText().toStdString();
    fields.address = addressEdit_->text().trimmed().toStdString();
    fields.port = static_cast<uint16_t>(portSpin_->value());
    fields.sni = sniEdit_->text().trimmed().toStdString();
    fields.proxy = proxyEdit_->text().trimmed().toStdString();
    fields.tlsVerify = tlsVerifyCheck_->isChecked();
    const QStringList ips = bootstrapEdit_->text().split(',', Qt::SkipEmptyParts);
    for (const QString& ip : ips) {
        fields.bootstrapIps.push_back(ip.trimmed().toStdString());
    }
    return fields;
}

void ServerDialog::onTestClicked() {
    if (testInFlight_) {
        return;
    }
    // The probe config is exactly what Save would store, so the test result
    // describes the config the user is about to commit.
    const UpstreamConfig config = upstreamFromServerFields(server_, fieldsFromWidgets());

    ++testGeneration_;
    testInFlight_ = true;
    testButton_->setEnabled(false);
    testResultLabel_->setStyleSheet(QString());
    testResultLabel_->setText(tr("Pinging server..."));
    jobs_->startPing(config, testGeneration_);
}

void ServerDialog::onPingFinished(const PingResult& result) {
    if (result.generation != testGeneration_ || !testInFlight_) {
        return;
    }
    testInFlight_ = false;
    testButton_->setEnabled(true);
    if (result.ok) {
        testResultLabel_->setStyleSheet(QStringLiteral("color: green; font-weight: bold;"));
        testResultLabel_->setText(tr("Operational - Latency: %1 ms").arg(result.rttMs));
    } else {
        testResultLabel_->setStyleSheet(QStringLiteral("color: red; font-weight: bold;"));
        testResultLabel_->setText(tr("Failed: ") + result.error);
    }
}

void ServerDialog::onSaveClicked() {
    const ServerFields fields = fieldsFromWidgets();
    if (fields.name.empty()) {
        QMessageBox::warning(this, tr("Invalid Name"), tr("Please provide a name for this upstream."));
        return;
    }
    server_ = upstreamFromServerFields(server_, fields);
    accept();
}

void ServerDialog::done(int result) {
    // Drop queued probes and invalidate in-flight results before teardown.
    ++testGeneration_;
    testInFlight_ = false;
    jobs_->cancelAll();
    QDialog::done(result);
}
