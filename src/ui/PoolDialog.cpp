#include "ui/PoolDialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

PoolDialog::PoolDialog(PoolConfig& pool, const std::vector<UpstreamConfig>& availableUpstreams, QWidget* parent)
    : QDialog(parent), pool_(pool), upstreams_(availableUpstreams) {
    setWindowTitle(pool_.name.empty() ? tr("Add DNS Server Pool") : tr("Edit DNS Server Pool"));
    resize(420, 380);
    buildUi();
}

void PoolDialog::buildUi() {
    auto* root = new QVBoxLayout(this);
    auto* form = new QFormLayout();

    nameEdit_ = new QLineEdit(this);
    nameEdit_->setText(QString::fromStdString(pool_.name));

    strategyCombo_ = new QComboBox(this);
    strategyCombo_->addItem(tr("Failover (Priority order)"), QStringLiteral("failover"));
    strategyCombo_->addItem(tr("Round Robin (Balanced load)"), QStringLiteral("round_robin"));
    strategyCombo_->addItem(tr("Fastest (Lowest latency)"), QStringLiteral("fastest"));
    strategyCombo_->addItem(tr("Random"), QStringLiteral("random"));

    int strategyIndex = strategyCombo_->findData(QString::fromStdString(pool_.strategy));
    if (strategyIndex >= 0) {
        strategyCombo_->setCurrentIndex(strategyIndex);
    }

    form->addRow(tr("Pool Name:"), nameEdit_);
    form->addRow(tr("Strategy:"), strategyCombo_);
    root->addLayout(form);

    root->addWidget(new QLabel(tr("Select member servers in this pool (top = highest priority):"), this));

    auto* listRow = new QHBoxLayout();
    serverList_ = new QListWidget(this);

    // Members keep their saved priority order at the top of the list so that
    // saving without touching anything cannot reorder the pool. Members whose
    // upstream is missing are still listed and kept, not silently dropped.
    std::vector<std::string> upstreamNames;
    upstreamNames.reserve(upstreams_.size());
    for (const auto& u : upstreams_) {
        upstreamNames.push_back(u.name);
    }
    for (const auto& name : poolMemberListOrder(pool_.servers, upstreamNames)) {
        const auto up = std::find_if(upstreams_.begin(), upstreams_.end(),
                                     [&](const UpstreamConfig& u) { return u.name == name; });
        auto* item = new QListWidgetItem(serverList_);
        item->setData(Qt::UserRole, QString::fromStdString(name));
        if (up != upstreams_.end()) {
            item->setText(QString::fromStdString(name) + " (" + QString::fromStdString(up->type) + ")");
        } else {
            item->setText(QString::fromStdString(name) + tr(" (missing)"));
        }
        item->setCheckState(std::find(pool_.servers.begin(), pool_.servers.end(), name) != pool_.servers.end()
                                ? Qt::Checked
                                : Qt::Unchecked);
    }
    listRow->addWidget(serverList_, 1);

    auto* moveCol = new QVBoxLayout();
    moveUpBtn_ = new QPushButton(tr("Move Up"), this);
    moveUpBtn_->setToolTip(tr("Raise the selected member's priority"));
    moveUpBtn_->setAccessibleName(tr("Move selected pool member up"));
    connect(moveUpBtn_, &QPushButton::clicked, this, &PoolDialog::onMoveUp);
    moveCol->addWidget(moveUpBtn_);
    moveDownBtn_ = new QPushButton(tr("Move Down"), this);
    moveDownBtn_->setToolTip(tr("Lower the selected member's priority"));
    moveDownBtn_->setAccessibleName(tr("Move selected pool member down"));
    connect(moveDownBtn_, &QPushButton::clicked, this, &PoolDialog::onMoveDown);
    moveCol->addWidget(moveDownBtn_);
    moveCol->addStretch(1);
    listRow->addLayout(moveCol);
    root->addLayout(listRow);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &PoolDialog::onSaveClicked);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttonBox);
}

void PoolDialog::onMoveUp() {
    const int row = serverList_->currentRow();
    if (row <= 0) {
        return;
    }
    auto* item = serverList_->takeItem(row);
    serverList_->insertItem(row - 1, item);
    serverList_->setCurrentItem(item);
}

void PoolDialog::onMoveDown() {
    const int row = serverList_->currentRow();
    if (row < 0 || row >= serverList_->count() - 1) {
        return;
    }
    auto* item = serverList_->takeItem(row);
    serverList_->insertItem(row + 1, item);
    serverList_->setCurrentItem(item);
}

void PoolDialog::onSaveClicked() {
    const QString name = nameEdit_->text().trimmed();
    if (name.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid Name"), tr("Please provide a name for this pool."));
        return;
    }

    // Checked items are collected in list order: top of the list is highest
    // priority for failover.
    std::vector<std::string> chosen;
    for (int i = 0; i < serverList_->count(); ++i) {
        auto* item = serverList_->item(i);
        if (item->checkState() == Qt::Checked) {
            chosen.push_back(item->data(Qt::UserRole).toString().toStdString());
        }
    }
    if (chosen.empty()) {
        QMessageBox::warning(this, tr("Empty Pool"), tr("Please check at least one server to include in this pool."));
        return;
    }

    pool_.name = name.toStdString();
    pool_.strategy = strategyCombo_->currentData().toString().toStdString();
    pool_.servers = std::move(chosen);
    accept();
}
