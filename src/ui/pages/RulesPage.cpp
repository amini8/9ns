#include "ui/pages/RulesPage.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "ui/Theme.h"

RulesPage::RulesPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    auto* hint = new QLabel(
        tr("Rules are evaluated top to bottom; the first match wins. Use Move Up / Move Down "
           "(or Alt+Up / Alt+Down) to change the order."), this);
    hint->setWordWrap(true);
    hint->setStyleSheet(QStringLiteral("color: #64748B;"));
    root->addWidget(hint);

    ruleTable_ = new QTableWidget(0, 4, this);
    ruleTable_->setHorizontalHeaderLabels({tr("Name"), tr("Hostnames"), tr("Action"), tr("Details")});
    ruleTable_->horizontalHeader()->setStretchLastSection(true);
    ruleTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ruleTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ruleTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ruleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ruleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    ruleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ruleTable_->setAccessibleName(tr("Rule list (first match wins)"));
    connect(ruleTable_, &QTableWidget::itemSelectionChanged, this, &RulesPage::updateActionState);
    connect(ruleTable_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        emit editRequested(row);
    });
    root->addWidget(ruleTable_, 1);

    auto* actions = new QHBoxLayout();
    auto* addButton = new QPushButton(tr("Add Rule…"), this);
    connect(addButton, &QPushButton::clicked, this, &RulesPage::addRequested);
    editButton_ = new QPushButton(tr("Edit…"), this);
    connect(editButton_, &QPushButton::clicked, this, [this] {
        emit editRequested(selectedRow());
    });
    deleteButton_ = new QPushButton(tr("Delete"), this);
    connect(deleteButton_, &QPushButton::clicked, this, [this] {
        emit deleteRequested(selectedRow());
    });
    upButton_ = new QPushButton(tr("Move Up"), this);
    upButton_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Up));
    connect(upButton_, &QPushButton::clicked, this, [this] {
        emit moveRequested(selectedRow(), -1);
    });
    downButton_ = new QPushButton(tr("Move Down"), this);
    downButton_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Down));
    connect(downButton_, &QPushButton::clicked, this, [this] {
        emit moveRequested(selectedRow(), 1);
    });
    actions->addWidget(addButton);
    actions->addWidget(editButton_);
    actions->addWidget(deleteButton_);
    actions->addSpacing(Theme::spacingLarge());
    actions->addWidget(upButton_);
    actions->addWidget(downButton_);
    actions->addStretch(1);
    root->addLayout(actions);

    updateActionState();
}

void RulesPage::setRules(const std::vector<RuleConfig>& rules) {
    const int selected = selectedRow();
    ruleTable_->setRowCount(static_cast<int>(rules.size()));
    for (int i = 0; i < static_cast<int>(rules.size()); ++i) {
        const RuleConfig& r = rules[static_cast<size_t>(i)];
        ruleTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(r.name)));
        QStringList hosts;
        for (const auto& h : r.hostnames) hosts << QString::fromStdString(h);
        if (hosts.isEmpty() && !r.pattern.empty()) hosts << QString::fromStdString(r.pattern);
        if (!r.hostsFile.empty()) hosts << tr("[Hosts File]");
        ruleTable_->setItem(i, 1, new QTableWidgetItem(hosts.join(QStringLiteral(", "))));
        ruleTable_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(r.action)));
        QString details = QString::fromStdString(!r.target.empty() ? r.target : r.upstream);
        if (r.action == "block") details = QString::fromStdString(r.blockMode);
        if (r.action == "local") details = QString::fromStdString(r.localIp);
        ruleTable_->setItem(i, 3, new QTableWidgetItem(details));
    }
    if (selected >= 0 && selected < ruleTable_->rowCount()) {
        ruleTable_->selectRow(selected);
    }
    updateActionState();
}

int RulesPage::selectedRow() const {
    return ruleTable_->currentRow();
}

void RulesPage::selectRow(int row) {
    if (row >= 0 && row < ruleTable_->rowCount()) {
        ruleTable_->selectRow(row);
    }
}

void RulesPage::updateActionState() {
    const int row = selectedRow();
    const bool hasSelection = row >= 0;
    editButton_->setEnabled(hasSelection);
    deleteButton_->setEnabled(hasSelection);
    upButton_->setEnabled(hasSelection && row > 0);
    downButton_->setEnabled(hasSelection && row + 1 < ruleTable_->rowCount());
}
