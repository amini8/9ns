#include "ui/pages/OverviewPage.h"

#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "ui/Theme.h"

namespace {

QLabel* metricTile(QGroupBox* parent, const QString& caption) {
    auto* tile = new QWidget(parent);
    auto* layout = new QVBoxLayout(tile);
    layout->setContentsMargins(Theme::spacingNormal(), Theme::spacingSmall(), Theme::spacingNormal(), Theme::spacingSmall());
    layout->setSpacing(0);
    auto* value = new QLabel(QStringLiteral("0"), tile);
    value->setFont(Theme::titleFont());
    value->setStyleSheet(QStringLiteral("font-size: 20px; color: #0F172A;"));
    value->setAlignment(Qt::AlignCenter);
    auto* cap = new QLabel(caption, tile);
    cap->setStyleSheet(QStringLiteral("color: #64748B; font-size: 11px;"));
    cap->setAlignment(Qt::AlignCenter);
    cap->setWordWrap(true);
    layout->addWidget(value);
    layout->addWidget(cap);
    return value;
}

}  // namespace

OverviewPage::OverviewPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    auto* summaryBox = new QGroupBox(tr("Protection"), this);
    auto* summaryLayout = new QVBoxLayout(summaryBox);
    summaryLabel_ = new QLabel(summaryBox);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextFormat(Qt::RichText);
    summaryLayout->addWidget(summaryLabel_);

    auto* actions = new QHBoxLayout();
    auto* startStopBtn = new QPushButton(tr("Start / Stop"), summaryBox);
    connect(startStopBtn, &QPushButton::clicked, this, &OverviewPage::startStopRequested);
    auto* saveBtn = new QPushButton(tr("Save Changes"), summaryBox);
    connect(saveBtn, &QPushButton::clicked, this, &OverviewPage::saveRequested);
    auto* flushBtn = new QPushButton(tr("Flush Cache"), summaryBox);
    connect(flushBtn, &QPushButton::clicked, this, &OverviewPage::flushCacheRequested);
    actions->addWidget(startStopBtn);
    actions->addWidget(saveBtn);
    actions->addWidget(flushBtn);
    actions->addStretch(1);
    summaryLayout->addLayout(actions);
    root->addWidget(summaryBox);

    auto* metricsBox = new QGroupBox(tr("Current Metrics"), this);
    auto* grid = new QGridLayout(metricsBox);
    grid->setHorizontalSpacing(Theme::spacingLarge());
    totalQueriesLabel_ = metricTile(metricsBox, tr("Total Queries"));
    blockedLabel_ = metricTile(metricsBox, tr("Blocked"));
    qpsLabel_ = metricTile(metricsBox, tr("Queries / s"));
    hitRateLabel_ = metricTile(metricsBox, tr("Cache Hit Rate"));
    grid->addWidget(totalQueriesLabel_->parentWidget(), 0, 0);
    grid->addWidget(blockedLabel_->parentWidget(), 0, 1);
    grid->addWidget(qpsLabel_->parentWidget(), 0, 2);
    grid->addWidget(hitRateLabel_->parentWidget(), 0, 3);
    root->addWidget(metricsBox);

    auto* latencyBox = new QGroupBox(tr("Upstream Latency (last tested)"), this);
    auto* latencyLayout = new QVBoxLayout(latencyBox);
    upstreamTable_ = new QTableWidget(0, 4, latencyBox);
    upstreamTable_->setHorizontalHeaderLabels({tr("Server"), tr("Protocol"), tr("Address"), tr("Latency")});
    upstreamTable_->horizontalHeader()->setStretchLastSection(true);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    upstreamTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    upstreamTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    upstreamTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    upstreamTable_->setAccessibleName(tr("Upstream latency table"));
    connect(upstreamTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit testUpstreamRequested(row);
    });
    latencyLayout->addWidget(upstreamTable_);
    root->addWidget(latencyBox, 1);
}

void OverviewPage::setProtectionSummary(const QString& html) {
    summaryLabel_->setText(html);
}

void OverviewPage::setMetrics(quint64 totalQueries, quint64 blockedQueries, double qps, double hitRatePercent) {
    totalQueriesLabel_->setText(QString::number(totalQueries));
    blockedLabel_->setText(QString::number(blockedQueries));
    qpsLabel_->setText(QString::number(qps));
    hitRateLabel_->setText(QString::number(hitRatePercent, 'f', 1) + QStringLiteral("%"));
}

void OverviewPage::setUpstreamCount(int count) {
    upstreamTable_->setRowCount(count);
}

void OverviewPage::setUpstreamRow(int row, const QString& name, const QString& type, const QString& address) {
    upstreamTable_->setItem(row, 0, new QTableWidgetItem(name));
    upstreamTable_->setItem(row, 1, new QTableWidgetItem(type));
    upstreamTable_->setItem(row, 2, new QTableWidgetItem(address));
    if (!upstreamTable_->item(row, 3)) {
        upstreamTable_->setItem(row, 3, new QTableWidgetItem(tr("Not tested")));
    }
}

void OverviewPage::setLatency(int row, LatencyState state, const QString& detail) {
    QString text;
    QColor color;
    switch (state) {
        case LatencyState::NotTested:
            text = tr("Not tested");
            color = Theme::textMuted();
            break;
        case LatencyState::Testing:
            text = tr("Testing…");
            color = Theme::warning();
            break;
        case LatencyState::Success:
            text = detail.isEmpty() ? tr("Success") : tr("Success — %1").arg(detail);
            color = Theme::success();
            break;
        case LatencyState::Failure:
            text = detail.isEmpty() ? tr("Failure") : tr("Failure — %1").arg(detail);
            color = Theme::danger();
            break;
    }
    auto* item = new QTableWidgetItem(text);
    item->setForeground(color);
    upstreamTable_->setItem(row, 3, item);
}

void OverviewPage::clearLatency() {
    for (int row = 0; row < upstreamTable_->rowCount(); ++row) {
        setLatency(row, LatencyState::NotTested, QString());
    }
}
