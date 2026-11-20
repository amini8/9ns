#include "ui/pages/ServersPoolsPage.h"

#include <QComboBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "ui/Theme.h"

ServersPoolsPage::ServersPoolsPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    // Default target
    auto* targetRow = new QHBoxLayout();
    auto* targetLabel = new QLabel(tr("Default &target:"), this);
    defaultTargetCombo_ = new QComboBox(this);
    defaultTargetCombo_->setAccessibleName(tr("Default upstream or pool"));
    targetLabel->setBuddy(defaultTargetCombo_);
    connect(defaultTargetCombo_, &QComboBox::currentIndexChanged, this, [this] {
        emit defaultTargetChanged(defaultTargetCombo_->currentData().toString());
    });
    targetRow->addWidget(targetLabel);
    targetRow->addWidget(defaultTargetCombo_, 1);
    targetRow->addStretch(2);
    root->addLayout(targetRow);

    // Upstreams
    auto* upstreamBox = new QGroupBox(tr("Upstream Servers"), this);
    auto* upstreamLayout = new QVBoxLayout(upstreamBox);
    upstreamTable_ = new QTableWidget(0, 5, upstreamBox);
    upstreamTable_->setHorizontalHeaderLabels({tr("Name"), tr("Protocol"), tr("Address"), tr("Port"), tr("Status")});
    upstreamTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    upstreamTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    upstreamTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    upstreamTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    upstreamTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    upstreamTable_->setAccessibleName(tr("Upstream servers"));
    connect(upstreamTable_, &QTableWidget::itemSelectionChanged, this, &ServersPoolsPage::updateActionState);
    connect(upstreamTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit editUpstreamRequested(row);
    });
    upstreamLayout->addWidget(upstreamTable_);

    auto* upstreamActions = new QHBoxLayout();
    auto* addUpstreamButton = new QPushButton(tr("Add Server…"), upstreamBox);
    connect(addUpstreamButton, &QPushButton::clicked, this, &ServersPoolsPage::addUpstreamRequested);
    editUpstreamButton_ = new QPushButton(tr("Edit…"), upstreamBox);
    connect(editUpstreamButton_, &QPushButton::clicked, this, [this] {
        emit editUpstreamRequested(selectedUpstreamRow());
    });
    deleteUpstreamButton_ = new QPushButton(tr("Delete"), upstreamBox);
    connect(deleteUpstreamButton_, &QPushButton::clicked, this, [this] {
        emit deleteUpstreamRequested(selectedUpstreamRow());
    });
    testUpstreamButton_ = new QPushButton(tr("Test"), upstreamBox);
    connect(testUpstreamButton_, &QPushButton::clicked, this, [this] {
        emit testUpstreamRequested(selectedUpstreamRow());
    });
    auto* resolversButton = new QPushButton(tr("Public Resolvers…"), upstreamBox);
    connect(resolversButton, &QPushButton::clicked, this, &ServersPoolsPage::openPublicResolversRequested);
    upstreamActions->addWidget(addUpstreamButton);
    upstreamActions->addWidget(editUpstreamButton_);
    upstreamActions->addWidget(deleteUpstreamButton_);
    upstreamActions->addSpacing(Theme::spacingLarge());
    upstreamActions->addWidget(testUpstreamButton_);
    upstreamActions->addStretch(1);
    upstreamActions->addWidget(resolversButton);
    upstreamLayout->addLayout(upstreamActions);
    root->addWidget(upstreamBox, 3);

    // Pools
    auto* poolBox = new QGroupBox(tr("Server Pools"), this);
    auto* poolLayout = new QVBoxLayout(poolBox);
    poolTable_ = new QTableWidget(0, 3, poolBox);
    poolTable_->setHorizontalHeaderLabels({tr("Name"), tr("Strategy"), tr("Members")});
    poolTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    poolTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    poolTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    poolTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    poolTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    poolTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    poolTable_->setAccessibleName(tr("Server pools"));
    connect(poolTable_, &QTableWidget::itemSelectionChanged, this, &ServersPoolsPage::updateActionState);
    connect(poolTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit editPoolRequested(row);
    });
    poolLayout->addWidget(poolTable_);

    auto* poolActions = new QHBoxLayout();
    auto* addPoolButton = new QPushButton(tr("Add Pool…"), poolBox);
    connect(addPoolButton, &QPushButton::clicked, this, &ServersPoolsPage::addPoolRequested);
    editPoolButton_ = new QPushButton(tr("Edit…"), poolBox);
    connect(editPoolButton_, &QPushButton::clicked, this, [this] {
        emit editPoolRequested(selectedPoolRow());
    });
    deletePoolButton_ = new QPushButton(tr("Delete"), poolBox);
    connect(deletePoolButton_, &QPushButton::clicked, this, [this] {
        emit deletePoolRequested(selectedPoolRow());
    });
    poolActions->addWidget(addPoolButton);
    poolActions->addWidget(editPoolButton_);
    poolActions->addWidget(deletePoolButton_);
    poolActions->addStretch(1);
    poolLayout->addLayout(poolActions);
    root->addWidget(poolBox, 2);

    updateActionState();
}

void ServersPoolsPage::setUpstreams(const std::vector<UpstreamConfig>& upstreams) {
    const int selected = selectedUpstreamRow();
    upstreamTable_->setRowCount(static_cast<int>(upstreams.size()));
    for (int i = 0; i < static_cast<int>(upstreams.size()); ++i) {
        const UpstreamConfig& up = upstreams[static_cast<size_t>(i)];
        upstreamTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(up.name)));
        upstreamTable_->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(up.type)));
        upstreamTable_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(up.address)));
        upstreamTable_->setItem(i, 3, new QTableWidgetItem(up.port != 0 ? QString::number(up.port) : tr("Default")));
        if (!upstreamTable_->item(i, 4)) {
            upstreamTable_->setItem(i, 4, new QTableWidgetItem(tr("Ready")));
        }
    }
    if (selected >= 0 && selected < upstreamTable_->rowCount()) {
        upstreamTable_->selectRow(selected);
    }
    updateActionState();
}

void ServersPoolsPage::setPools(const std::vector<PoolConfig>& pools) {
    const int selected = selectedPoolRow();
    poolTable_->setRowCount(static_cast<int>(pools.size()));
    for (int i = 0; i < static_cast<int>(pools.size()); ++i) {
        const PoolConfig& p = pools[static_cast<size_t>(i)];
        poolTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(p.name)));
        poolTable_->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(p.strategy)));
        QStringList members;
        for (const auto& s : p.servers) members << QString::fromStdString(s);
        poolTable_->setItem(i, 2, new QTableWidgetItem(members.join(QStringLiteral(", "))));
    }
    if (selected >= 0 && selected < poolTable_->rowCount()) {
        poolTable_->selectRow(selected);
    }
    updateActionState();
}

void ServersPoolsPage::setDefaultTargets(const QList<QPair<QString, QString>>& targets, const std::string& current) {
    const QSignalBlocker blocker(defaultTargetCombo_);
    defaultTargetCombo_->clear();
    for (const auto& target : targets) {
        defaultTargetCombo_->addItem(target.first, target.second);
    }
    const int index = defaultTargetCombo_->findData(QString::fromStdString(current));
    if (index >= 0) {
        defaultTargetCombo_->setCurrentIndex(index);
    }
}

std::string ServersPoolsPage::defaultTarget() const {
    return defaultTargetCombo_->currentData().toString().toStdString();
}

int ServersPoolsPage::selectedUpstreamRow() const {
    return upstreamTable_->currentRow();
}

int ServersPoolsPage::selectedPoolRow() const {
    return poolTable_->currentRow();
}

void ServersPoolsPage::selectUpstreamRow(int row) {
    if (row >= 0 && row < upstreamTable_->rowCount()) {
        upstreamTable_->selectRow(row);
    }
}

void ServersPoolsPage::setUpstreamStatus(int row, const QString& text, bool isFailure) {
    auto* item = new QTableWidgetItem(text);
    item->setForeground(isFailure ? Theme::danger() : Theme::success());
    upstreamTable_->setItem(row, 4, item);
}

void ServersPoolsPage::updateActionState() {
    const int upRow = selectedUpstreamRow();
    const bool hasUpstream = upRow >= 0;
    editUpstreamButton_->setEnabled(hasUpstream);
    deleteUpstreamButton_->setEnabled(hasUpstream);
    testUpstreamButton_->setEnabled(hasUpstream);

    const int poolRow = selectedPoolRow();
    const bool hasPool = poolRow >= 0;
    editPoolButton_->setEnabled(hasPool);
    deletePoolButton_->setEnabled(hasPool);
}
