#include "ui/RuleDialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

#include "core/SystemDns.h"

RuleDialog::RuleDialog(RuleConfig& rule,
                       const std::vector<UpstreamConfig>& availableUpstreams,
                       const std::vector<PoolConfig>& availablePools,
                       const std::vector<InterfaceInfo>& interfaces,
                       QWidget* parent)
    : QDialog(parent), rule_(rule), upstreams_(availableUpstreams), pools_(availablePools) {
    setWindowTitle(rule_.name.empty() ? tr("Add Routing Rule") : tr("Edit Routing Rule"));
    resize(520, 560);
    buildUi(interfaces);
    onActionChanged(actionCombo_->currentData().toString());
}

void RuleDialog::buildUi(const std::vector<InterfaceInfo>& interfaces) {
    auto* root = new QVBoxLayout(this);
    auto* form = new QFormLayout();

    nameEdit_ = new QLineEdit(this);
    nameEdit_->setText(QString::fromStdString(rule_.name));

    hostnamesEdit_ = new QPlainTextEdit(this);
    hostnamesEdit_->setPlaceholderText(tr("Enter domain names or wildcard masks, one per line or separated by semicolon.\n"
                                          "Examples: *.example.com, *.corp.lan, tracker.*, *"));
    QStringList hostList;
    for (const auto& h : rule_.hostnames) {
        hostList << QString::fromStdString(h);
    }
    if (hostList.isEmpty() && !rule_.pattern.empty()) {
        hostList << QString::fromStdString(rule_.pattern);
    }
    hostnamesEdit_->setPlainText(hostList.join(QStringLiteral("\n")));
    hostnamesEdit_->setMaximumHeight(100);

    // Hosts file row
    auto* hostsLayout = new QHBoxLayout();
    hostsFileEdit_ = new QLineEdit(this);
    hostsFileEdit_->setText(QString::fromStdString(rule_.hostsFile));
    hostsFileEdit_->setPlaceholderText(tr("Optional path to /etc/hosts format blocklist"));
    browseHostsBtn_ = new QPushButton(tr("Browse..."), this);
    connect(browseHostsBtn_, &QPushButton::clicked, this, &RuleDialog::onBrowseHostsFile);
    hostsLayout->addWidget(hostsFileEdit_, 1);
    hostsLayout->addWidget(browseHostsBtn_);

    // Action
    actionCombo_ = new QComboBox(this);
    actionCombo_->addItem(tr("Process (Forward to Server/Pool)"), QStringLiteral("process"));
    actionCombo_->addItem(tr("Block Query"), QStringLiteral("block"));
    actionCombo_->addItem(tr("Bypass Proxy (Direct to System DNS)"), QStringLiteral("bypass"));
    actionCombo_->addItem(tr("Local Static IP"), QStringLiteral("local"));

    const std::string initialAction = (rule_.action == "forward") ? "process" : rule_.action;
    int actionIdx = actionCombo_->findData(QString::fromStdString(initialAction));
    if (actionIdx >= 0) actionCombo_->setCurrentIndex(actionIdx);

    // Target (Server or Pool)
    targetCombo_ = new QComboBox(this);
    for (const auto& p : pools_) {
        targetCombo_->addItem(QStringLiteral("[Pool] ") + QString::fromStdString(p.name), QString::fromStdString(p.name));
    }
    for (const auto& u : upstreams_) {
        targetCombo_->addItem(QStringLiteral("[Server] ") + QString::fromStdString(u.name), QString::fromStdString(u.name));
    }
    const std::string initialTarget = !rule_.target.empty() ? rule_.target : rule_.upstream;
    int targetIdx = targetCombo_->findData(QString::fromStdString(initialTarget));
    if (targetIdx >= 0) targetCombo_->setCurrentIndex(targetIdx);

    // Block Mode
    blockModeCombo_ = new QComboBox(this);
    blockModeCombo_->addItem(tr("NXDOMAIN (Domain not found)"), QStringLiteral("nxdomain"));
    blockModeCombo_->addItem(tr("Null IP (0.0.0.0 / ::)"), QStringLiteral("null_ip"));
    blockModeCombo_->addItem(tr("REFUSED (Refused error)"), QStringLiteral("refused"));
    blockModeCombo_->addItem(tr("DROP (Silent drop, no response)"), QStringLiteral("drop"));
    int blockIdx = blockModeCombo_->findData(QString::fromStdString(rule_.blockMode));
    if (blockIdx >= 0) blockModeCombo_->setCurrentIndex(blockIdx);

    // Local IP
    localIpEdit_ = new QLineEdit(this);
    localIpEdit_->setText(QString::fromStdString(rule_.localIp));
    localIpEdit_->setPlaceholderText(tr("e.g. 192.168.1.100 or ::1"));

    // Network Interface
    interfaceCombo_ = new QComboBox(this);
    interfaceCombo_->setObjectName(QStringLiteral("interfaceCombo"));
    interfaceCombo_->addItem(tr("Any Active Interface"), QString());
    for (const auto& iface : interfaces) {
        QString label = QString::fromStdString(iface.name);
        if (iface.isVpn) label += tr(" (VPN)");
        interfaceCombo_->addItem(label, QString::fromStdString(iface.guid));
    }
    int ifaceIdx = interfaceCombo_->findData(QString::fromStdString(rule_.interfaceGuid));
    if (ifaceIdx < 0) {
        interfaceCombo_->addItem(tr("%1 (unavailable, current)").arg(QString::fromStdString(rule_.interfaceGuid)),
                                 QString::fromStdString(rule_.interfaceGuid));
        ifaceIdx = interfaceCombo_->count() - 1;
    }
    interfaceCombo_->setCurrentIndex(ifaceIdx);

    // Query Type
    queryTypeCombo_ = new QComboBox(this);
    queryTypeCombo_->setObjectName(QStringLiteral("queryTypeCombo"));
    for (const auto& type : QStringList{QStringLiteral("ANY"), QStringLiteral("A"), QStringLiteral("AAAA"),
                                       QStringLiteral("PTR"), QStringLiteral("CNAME"), QStringLiteral("MX"),
                                       QStringLiteral("TXT"), QStringLiteral("SRV")}) {
        queryTypeCombo_->addItem(type, type);
    }
    if (!rule_.queryType.empty()) {
        const QString type = QString::fromStdString(rule_.queryType);
        int typeIdx = queryTypeCombo_->findData(type);
        if (typeIdx < 0) {
            queryTypeCombo_->addItem(tr("%1 (current)").arg(type), type);
            typeIdx = queryTypeCombo_->count() - 1;
        }
        queryTypeCombo_->setCurrentIndex(typeIdx);
    }

    // DNSSEC Policy
    dnssecCombo_ = new QComboBox(this);
    dnssecCombo_->addItem(tr("Default (Inherit global setting)"), QStringLiteral("default"));
    dnssecCombo_->addItem(tr("Force DNSSEC Validation"), QStringLiteral("force"));
    dnssecCombo_->addItem(tr("Ignore / Bypass DNSSEC"), QStringLiteral("ignore"));
    int secIdx = dnssecCombo_->findData(QString::fromStdString(rule_.dnssecMode));
    if (secIdx >= 0) dnssecCombo_->setCurrentIndex(secIdx);

    form->addRow(tr("Rule Name:"), nameEdit_);
    form->addRow(tr("Hostname Masks:"), hostnamesEdit_);
    form->addRow(tr("Hosts / Blocklist File:"), hostsLayout);
    form->addRow(tr("Action:"), actionCombo_);
    form->addRow(tr("Target (Server/Pool):"), targetCombo_);
    form->addRow(tr("Block Mode:"), blockModeCombo_);
    form->addRow(tr("Static IP:"), localIpEdit_);
    form->addRow(tr("Network Interface:"), interfaceCombo_);
    form->addRow(tr("Query Type:"), queryTypeCombo_);
    form->addRow(tr("DNSSEC Policy:"), dnssecCombo_);

    root->addLayout(form);

    connect(actionCombo_, &QComboBox::currentTextChanged, [this] {
        onActionChanged(actionCombo_->currentData().toString());
    });

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &RuleDialog::onSaveClicked);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttonBox);
}

void RuleDialog::onActionChanged(const QString& action) {
    targetCombo_->setEnabled(action == "process");
    blockModeCombo_->setEnabled(action == "block");
    localIpEdit_->setEnabled(action == "local");
}

void RuleDialog::onBrowseHostsFile() {
    QString path = QFileDialog::getOpenFileName(this, tr("Select Hosts or Blocklist File"),
                                                QString(), tr("Hosts Files (*.txt *hosts*);;All Files (*.*)"));
    if (!path.isEmpty()) {
        hostsFileEdit_->setText(path);
    }
}

void RuleDialog::onSaveClicked() {
    const QString name = nameEdit_->text().trimmed();
    const QString hostnamesText = hostnamesEdit_->toPlainText();
    const QString hostsFile = hostsFileEdit_->text().trimmed();

    QStringList hostList;
    const QStringList lines = hostnamesText.split(QRegularExpression(QStringLiteral("[\r\n;]+")), Qt::SkipEmptyParts);
    for (const QString& line : lines) {
        const QString item = line.trimmed();
        if (!item.isEmpty()) {
            hostList << item;
        }
    }

    if (hostList.isEmpty() && hostsFile.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid Rule"), tr("Please provide at least one hostname mask or select a hosts file."));
        return;
    }

    rule_.name = !name.isEmpty() ? name.toStdString() : (!hostList.isEmpty() ? hostList.front().toStdString() : "Rule");
    rule_.hostnames.clear();
    for (const QString& h : hostList) {
        rule_.hostnames.push_back(h.toStdString());
    }
    rule_.pattern = !rule_.hostnames.empty() ? rule_.hostnames.front() : "";
    rule_.hostsFile = hostsFile.toStdString();
    rule_.action = actionCombo_->currentData().toString().toStdString();
    rule_.target = targetCombo_->currentData().toString().toStdString();
    rule_.upstream = rule_.target;
    rule_.blockMode = blockModeCombo_->currentData().toString().toStdString();
    rule_.localIp = localIpEdit_->text().trimmed().toStdString();
    rule_.interfaceGuid = interfaceCombo_->currentData().toString().toStdString();
    rule_.queryType = queryTypeCombo_->currentData().toString().toStdString();
    rule_.dnssecMode = dnssecCombo_->currentData().toString().toStdString();

    accept();
}
