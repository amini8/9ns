#include "ui/PublicResolversDialog.h"

#include <algorithm>
#include <functional>
#include <string>
#include <stdexcept>
#include <utility>
#include <vector>

#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QProgressBar>
#include <QPushButton>
#include <QRunnable>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextDocument>
#include <QVBoxLayout>

#include "ui/PublicResolverImport.h"
#include "ui/ResolverJobs.h"

namespace {

QString qstr(const std::string& s) {
    return QString::fromStdString(s);
}

// Wraps untrusted text so a tooltip shows it literally: convertFromPlainText
// escapes the content and the <qt> wrapper forces rich-text rendering of that
// escaped form (an unwrapped escape would show entities when Qt classifies the
// tooltip as plain text).
QString literalToolTip(const QString& text) {
    return QStringLiteral("<qt>%1</qt>").arg(Qt::convertFromPlainText(text));
}

// Runs one unit of background work on a pool thread. The work posts its result
// through a queued, context-bound call; the dialog's pool drains in its
// destructor, so that call is never made against a destroyed receiver.
class WorkRunnable : public QRunnable {
public:
    explicit WorkRunnable(std::function<void()> work) : work_(std::move(work)) {}

    void run() override { work_(); }

private:
    std::function<void()> work_;
};

}  // namespace

PublicResolversDialog::PublicResolversDialog(Config& config, Services services, QWidget* parent)
    : QDialog(parent), config_(config), services_(std::move(services)) {
    if (!services_.load || !services_.probe) throw std::invalid_argument("PublicResolversDialog requires a loader and probe");
    if (!services_.notice) services_.notice = [this](const QString& title, const QString& message, bool warning) {
        // Resolver names and parse errors in the message are untrusted; show
        // them literally instead of letting Qt interpret rich text.
        QMessageBox box(warning ? QMessageBox::Warning : QMessageBox::Information,
                        title, message, QMessageBox::Ok, this);
        box.setTextFormat(Qt::PlainText);
        box.exec();
    };
    if (!services_.poolName) services_.poolName = [this](QString& name) {
        bool ok = false;
        name = QInputDialog::getText(this, tr("Create DNS Server Pool"), tr("Enter a name for the new pool:"),
                                     QLineEdit::Normal, QStringLiteral("Fast-Public-Pool"), &ok);
        return ok;
    };
    loadPool_.setMaxThreadCount(1);
    jobs_ = new ResolverJobs(services_.probe, this);
    connect(jobs_, &ResolverJobs::pingFinished, this, &PublicResolversDialog::onPingFinished);
    buildUi();
    loadData(false);
}

PublicResolversDialog::~PublicResolversDialog() = default;

void PublicResolversDialog::done(int result) {
    // Invalidate every outstanding request and drop queued deliveries. In-flight
    // network calls are not interrupted; their late results fail the guards.
    ++loadGeneration_;
    ++pingGeneration_;
    jobs_->cancelAll();
    loadPool_.clear();
    unsetCursor();
    refreshBtn_->setEnabled(true);
    QDialog::done(result);
}

void PublicResolversDialog::buildUi() {
    setWindowTitle(tr("Public Resolvers & Relays Browser"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/9ns-mark.svg")));
    resize(980, 640);

    auto* mainLayout = new QVBoxLayout(this);

    // Top Header Banner with SVG Logo
    auto* bannerCard = new QWidget(this);
    bannerCard->setStyleSheet(QStringLiteral("background: #f0f4f8; border-radius: 6px; padding: 4px;"));
    auto* bannerLayout = new QHBoxLayout(bannerCard);

    auto* logoLabel = new QLabel(bannerCard);
    logoLabel->setPixmap(QIcon(QStringLiteral(":/icons/9ns-mark.svg")).pixmap(44, 44));
    logoLabel->setFixedSize(44, 44);

    auto* banner = new QLabel(
        tr("<b>Public DNS Resolvers & Anonymized Relays</b><br>"
           "<span style='color: #555;'>Loaded directly from official repositories: "
           "<code>public-resolvers.md</code> &amp; <code>relays.md</code>. "
           "Select items to benchmark latency, import to your server list, or create multi-server pools.</span>"),
        bannerCard);
    banner->setWordWrap(true);
    bannerLayout->addWidget(logoLabel);
    bannerLayout->addWidget(banner, 1);
    mainLayout->addWidget(bannerCard);

    // Filter Bar
    auto* filterRow = new QHBoxLayout();

    filterRow->addWidget(new QLabel(tr("Search:"), this));
    searchEdit_ = new QLineEdit(this);
    searchEdit_->setPlaceholderText(tr("Search by name, location or description..."));
    searchEdit_->setClearButtonEnabled(true);
    connect(searchEdit_, &QLineEdit::textChanged, this, &PublicResolversDialog::onFilterChanged);
    filterRow->addWidget(searchEdit_, 2);

    filterRow->addWidget(new QLabel(tr("Protocol:"), this));
    protocolCombo_ = new QComboBox(this);
    protocolCombo_->setObjectName(QStringLiteral("protocolFilter"));
    protocolCombo_->addItem(tr("All Protocols"), QString());
    for (const auto protocol : {DnsStamp::Protocol::DoH, DnsStamp::Protocol::DnsCrypt,
                               DnsStamp::Protocol::AnonymizedRelay, DnsStamp::Protocol::DoQ,
                               DnsStamp::Protocol::Odoh, DnsStamp::Protocol::OdohRelay}) {
        const QString label = QString::fromLatin1(resolvers::protocolName(protocol));
        protocolCombo_->addItem(label, label);
    }
    connect(protocolCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &PublicResolversDialog::onFilterChanged);
    filterRow->addWidget(protocolCombo_, 1);

    dnssecCheck_ = new QCheckBox(tr("DNSSEC"), this);
    connect(dnssecCheck_, &QCheckBox::toggled, this, &PublicResolversDialog::onFilterChanged);
    filterRow->addWidget(dnssecCheck_);

    noLogCheck_ = new QCheckBox(tr("No Logs"), this);
    connect(noLogCheck_, &QCheckBox::toggled, this, &PublicResolversDialog::onFilterChanged);
    filterRow->addWidget(noLogCheck_);

    noFilterCheck_ = new QCheckBox(tr("No Filter"), this);
    connect(noFilterCheck_, &QCheckBox::toggled, this, &PublicResolversDialog::onFilterChanged);
    filterRow->addWidget(noFilterCheck_);

    refreshBtn_ = new QPushButton(tr("Refresh from Web"), this);
    connect(refreshBtn_, &QPushButton::clicked, this, &PublicResolversDialog::onRefreshFromWeb);
    filterRow->addWidget(refreshBtn_);

    mainLayout->addLayout(filterRow);

    // Table
    table_ = new QTableWidget(this);
    table_->setObjectName(QStringLiteral("resolversTable"));
    table_->setColumnCount(7);
    table_->setHorizontalHeaderLabels({
        tr("Name"), tr("Protocol"), tr("DNSSEC"), tr("No Logs"), tr("No Filter"), tr("Latency"), tr("Description")
    });
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(false);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &PublicResolversDialog::onSelectionChanged);
    mainLayout->addWidget(table_);

    // Progress Bar (hidden by default)
    progressBar_ = new QProgressBar(this);
    progressBar_->setVisible(false);
    progressBar_->setTextVisible(true);
    mainLayout->addWidget(progressBar_);

    // Bottom Bar (Status & Action buttons)
    auto* bottomRow = new QHBoxLayout();
    statusLabel_ = new QLabel(this);
    statusLabel_->setStyleSheet(QStringLiteral("color: #666; font-size: 12px;"));
    bottomRow->addWidget(statusLabel_, 1);

    pingBtn_ = new QPushButton(tr("Test Latency (Ping)"), this);
    pingBtn_->setEnabled(false);
    connect(pingBtn_, &QPushButton::clicked, this, &PublicResolversDialog::onPingSelected);
    bottomRow->addWidget(pingBtn_);

    copyStampBtn_ = new QPushButton(tr("Copy Stamp"), this);
    copyStampBtn_->setEnabled(false);
    connect(copyStampBtn_, &QPushButton::clicked, this, &PublicResolversDialog::onCopyStamp);
    bottomRow->addWidget(copyStampBtn_);

    addServersBtn_ = new QPushButton(tr("Add to My Servers"), this);
    addServersBtn_->setEnabled(false);
    addServersBtn_->setStyleSheet(QStringLiteral("font-weight: bold;"));
    connect(addServersBtn_, &QPushButton::clicked, this, &PublicResolversDialog::onAddSelectedToServers);
    bottomRow->addWidget(addServersBtn_);

    createPoolBtn_ = new QPushButton(tr("Create Pool from Selection..."), this);
    createPoolBtn_->setEnabled(false);
    connect(createPoolBtn_, &QPushButton::clicked, this, &PublicResolversDialog::onCreatePoolFromSelected);
    bottomRow->addWidget(createPoolBtn_);

    auto* closeBtn = new QPushButton(tr("Close"), this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    bottomRow->addWidget(closeBtn);

    mainLayout->addLayout(bottomRow);
}

void PublicResolversDialog::loadData(bool forceRefresh) {
    statusLabel_->setText(tr("Downloading & parsing resolvers from GitHub..."));
    refreshBtn_->setEnabled(false);
    // Widget-local cursor: it disappears with this dialog and cannot leak into
    // the rest of the application like an override cursor can.
    setCursor(Qt::WaitCursor);
    const quint64 generation = ++loadGeneration_;

    loadPool_.start(new WorkRunnable([this, forceRefresh, generation]() {
        std::string err;
        auto items = services_.load(forceRefresh, err);
        QMetaObject::invokeMethod(
            this,
            [this, generation, items = std::move(items), err]() mutable {
                onLoadFinished(generation, std::move(items), err);
            },
            Qt::QueuedConnection);
    }));
}

void PublicResolversDialog::onLoadFinished(quint64 generation, std::vector<PublicDnsItem> items, const std::string& error) {
    if (generation != loadGeneration_) {
        return;  // superseded by a newer load
    }
    unsetCursor();
    refreshBtn_->setEnabled(true);
    if (items.empty()) {
        services_.notice(tr("Download Error"), tr("Failed to load public resolvers:\n%1").arg(qstr(error)), true);
        statusLabel_->setText(tr("Error loading public resolvers"));
        return;
    }
    // New data invalidates the identity of every pinged item.
    ++pingGeneration_;
    jobs_->cancelAll();
    progressTotal_ = 0;
    progressDone_ = 0;
    progressBar_->setVisible(false);
    for (auto& item : items) {
        DnsStamp stamp;
        std::string parseError;
        item.protocol = parseStamp(item.stamp, stamp, parseError) ? resolvers::protocolName(stamp.protocol) : "Invalid";
    }
    allItems_ = std::move(items);
    onFilterChanged();
}

void PublicResolversDialog::onRefreshFromWeb() {
    loadData(true);
}

void PublicResolversDialog::onFilterChanged() {
    filteredIndices_.clear();
    const QString query = searchEdit_->text().trimmed().toLower();
    const QString protocol = protocolCombo_->currentData().toString();
    const bool reqDnssec = dnssecCheck_->isChecked();
    const bool reqNoLog = noLogCheck_->isChecked();
    const bool reqNoFilter = noFilterCheck_->isChecked();

    for (size_t i = 0; i < allItems_.size(); ++i) {
        const auto& item = allItems_[i];

        // Protocol filter
        if (!protocol.isEmpty() && qstr(item.protocol) != protocol) continue;

        // Capabilities
        if (reqDnssec && !item.dnssec) continue;
        if (reqNoLog && !item.noLog) continue;
        if (reqNoFilter && !item.noFilter) continue;

        // Search text
        if (!query.isEmpty()) {
            const QString name = qstr(item.name).toLower();
            const QString desc = qstr(item.description).toLower();
            const QString proto = qstr(item.protocol).toLower();
            if (!name.contains(query) && !desc.contains(query) && !proto.contains(query)) {
                continue;
            }
        }

        filteredIndices_.push_back(static_cast<int>(i));
    }

    populateTable();
}

void PublicResolversDialog::populateTable() {
    table_->setSortingEnabled(false);
    table_->setRowCount(static_cast<int>(filteredIndices_.size()));

    for (int row = 0; row < static_cast<int>(filteredIndices_.size()); ++row) {
        const int itemIdx = filteredIndices_[row];
        const auto& item = allItems_[itemIdx];

        auto* nameItem = new QTableWidgetItem(qstr(item.name));
        nameItem->setData(Qt::UserRole, itemIdx);
        QFont f = nameItem->font();
        f.setBold(true);
        nameItem->setFont(f);
        table_->setItem(row, 0, nameItem);

        auto* protoItem = new QTableWidgetItem(qstr(item.protocol));
        if (item.protocol == "DoH") {
            protoItem->setForeground(QColor(0, 102, 204));
        } else if (item.protocol == "DNSCrypt") {
            protoItem->setForeground(QColor(0, 153, 76));
        } else {
            protoItem->setForeground(QColor(153, 51, 204));
        }
        table_->setItem(row, 1, protoItem);

        table_->setItem(row, 2, new QTableWidgetItem(item.dnssec ? tr("Yes") : QStringLiteral("-")));
        table_->setItem(row, 3, new QTableWidgetItem(item.noLog ? tr("Yes") : QStringLiteral("-")));
        table_->setItem(row, 4, new QTableWidgetItem(item.noFilter ? tr("Yes") : QStringLiteral("-")));

        auto* latencyItem = new QTableWidgetItem(QStringLiteral("-"));
        latencyItem->setTextAlignment(Qt::AlignCenter);
        table_->setItem(row, 5, latencyItem);

        auto* descItem = new QTableWidgetItem(qstr(item.description));
        descItem->setToolTip(literalToolTip(qstr(item.stamp)));
        table_->setItem(row, 6, descItem);
    }

    statusLabel_->setText(
        tr("Showing %1 of %2 items (Total: %3 public resolvers, %4 relays)")
            .arg(filteredIndices_.size())
            .arg(allItems_.size())
            .arg(std::count_if(allItems_.begin(), allItems_.end(), [](const auto& it){ return it.protocol != "Relay" && it.protocol != "ODoH Relay" && it.protocol != "Invalid"; }))
            .arg(std::count_if(allItems_.begin(), allItems_.end(), [](const auto& it){ return it.protocol == "Relay" || it.protocol == "ODoH Relay"; })));

    onSelectionChanged();
}

std::vector<int> PublicResolversDialog::selectedItemIndices() const {
    std::vector<int> result;
    const auto selectedRanges = table_->selectedRanges();
    for (const auto& range : selectedRanges) {
        for (int r = range.topRow(); r <= range.bottomRow(); ++r) {
            if (auto* item = table_->item(r, 0)) {
                result.push_back(item->data(Qt::UserRole).toInt());
            }
        }
    }
    return result;
}

int PublicResolversDialog::rowForItem(const QString& stamp, const QString& name) const {
    int nameMatch = -1;
    for (int row = 0; row < table_->rowCount(); ++row) {
        const auto* nameItem = table_->item(row, 0);
        if (!nameItem) {
            continue;
        }
        const int idx = nameItem->data(Qt::UserRole).toInt();
        if (idx < 0 || idx >= static_cast<int>(allItems_.size())) {
            continue;
        }
        const auto& item = allItems_[idx];
        if (!stamp.isEmpty() && qstr(item.stamp) == stamp) {
            return row;
        }
        if (nameMatch < 0 && qstr(item.name) == name) {
            nameMatch = row;
        }
    }
    return nameMatch;
}

void PublicResolversDialog::onSelectionChanged() {
    const auto indices = selectedItemIndices();
    const bool hasSel = !indices.empty();
    pingBtn_->setEnabled(hasSel);
    copyStampBtn_->setEnabled(indices.size() == 1);
    addServersBtn_->setEnabled(hasSel);
    createPoolBtn_->setEnabled(indices.size() >= 2);
}

void PublicResolversDialog::onCopyStamp() {
    const auto indices = selectedItemIndices();
    if (indices.size() == 1 && indices[0] < static_cast<int>(allItems_.size())) {
        QGuiApplication::clipboard()->setText(qstr(allItems_[indices[0]].stamp));
    }
}

void PublicResolversDialog::onPingSelected() {
    const auto indices = selectedItemIndices();
    if (indices.empty()) {
        return;
    }

    // A new run supersedes any previous one.
    ++pingGeneration_;
    jobs_->cancelAll();

    progressTotal_ = static_cast<int>(indices.size());
    progressDone_ = 0;
    progressBar_->setVisible(true);
    progressBar_->setRange(0, progressTotal_);
    progressBar_->setValue(0);
    pingBtn_->setEnabled(false);

    for (int idx : indices) {
        if (idx < 0 || idx >= static_cast<int>(allItems_.size())) {
            continue;
        }
        const auto& item = allItems_[idx];
        UpstreamConfig cfg;
        std::string error;
        if (!resolvers::resolverCandidate(item, cfg, error)) {
            // Relays are never queried directly; they get no latency number.
            const int row = rowForItem(qstr(item.stamp), qstr(item.name));
            if (row >= 0) {
                auto* latItem = table_->item(row, 5);
                if (!latItem) {
                    latItem = new QTableWidgetItem();
                    table_->setItem(row, 5, latItem);
                }
                latItem->setText(tr("Not a resolver"));
                latItem->setToolTip(literalToolTip(qstr(error)));
                latItem->setForeground(Qt::gray);
            }
            ++progressDone_;
        } else {
            jobs_->startPing(cfg, pingGeneration_);
        }
    }

    progressBar_->setValue(progressDone_);
    if (progressDone_ >= progressTotal_) {
        progressBar_->setVisible(false);
        pingBtn_->setEnabled(true);
    }
}

void PublicResolversDialog::onPingFinished(const PingResult& result) {
    if (result.generation != pingGeneration_) {
        return;  // refreshed, superseded or closed since the ping was issued
    }

    // Resolve the row at delivery time by stable identity: rows move when the
    // user filters or refreshes while results are still arriving.
    const int row = rowForItem(result.stamp, result.name);
    if (row >= 0) {
        auto* latItem = table_->item(row, 5);
        if (!latItem) {
            latItem = new QTableWidgetItem();
            table_->setItem(row, 5, latItem);
        }
        if (result.ok) {
            QColor textColor = Qt::black;
            if (result.rttMs < 50) textColor = QColor(0, 153, 0);
            else if (result.rttMs < 150) textColor = QColor(204, 153, 0);
            else textColor = QColor(204, 0, 0);
            latItem->setText(QStringLiteral("%1 ms").arg(result.rttMs));
            latItem->setForeground(textColor);
        } else {
            latItem->setText(result.error.isEmpty() ? tr("Timeout") : result.error);
            latItem->setForeground(Qt::red);
        }
    }

    if (progressTotal_ > 0) {
        ++progressDone_;
        progressBar_->setValue(progressDone_);
        if (progressDone_ >= progressTotal_) {
            progressBar_->setVisible(false);
            pingBtn_->setEnabled(true);
        }
    }
}

void PublicResolversDialog::onAddSelectedToServers() {
    std::vector<PublicDnsItem> selection;
    for (int index : selectedItemIndices()) selection.push_back(allItems_[index]);
    if (selection.empty()) return;
    Config candidate;
    std::string error;
    if (!resolvers::importCandidate(config_, selection, std::nullopt, candidate, error)) {
        services_.notice(tr("Cannot Add Servers"), qstr(error), true);
        return;
    }
    const auto added = candidate.upstreams.size() - config_.upstreams.size();
    config_ = std::move(candidate);
    emit configurationModified();
    services_.notice(tr("Servers Added"), tr("Added %1 public server(s).").arg(added), false);
}

void PublicResolversDialog::onCreatePoolFromSelected() {
    std::vector<PublicDnsItem> selection;
    for (int index : selectedItemIndices()) selection.push_back(allItems_[index]);
    if (selection.size() < 2) {
        services_.notice(tr("Create Pool"), tr("Please select at least 2 distinct resolvers to create a pool."), true);
        return;
    }
    QString poolName;
    if (!services_.poolName(poolName)) return;
    Config candidate;
    std::string error;
    if (!resolvers::importCandidate(config_, selection, poolName.toStdString(), candidate, error)) {
        services_.notice(tr("Cannot Create Pool"), qstr(error), true);
        return;
    }
    const auto members = candidate.pools.back().servers.size();
    config_ = std::move(candidate);
    emit configurationModified();
    services_.notice(tr("Pool Created"), tr("Pool '%1' created with %2 servers and 'fastest' strategy.")
                         .arg(poolName.trimmed()).arg(members), false);
}
