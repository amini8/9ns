#include "ui/pages/SystemLogPage.h"

#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/Theme.h"

SystemLogPage::SystemLogPage(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal(), Theme::spacingNormal());
    root->setSpacing(Theme::spacingNormal());

    logView_ = new QPlainTextEdit(this);
    logView_->setReadOnly(true);
    logView_->setMaximumBlockCount(5000);
    logView_->setAccessibleName(tr("System diagnostics log"));
    logView_->setFont(Theme::monoFont());
    root->addWidget(logView_, 1);

    auto* actions = new QHBoxLayout();
    auto* clearBtn = new QPushButton(tr("Clear Log"), this);
    connect(clearBtn, &QPushButton::clicked, this, &SystemLogPage::clear);
    auto* openFolderBtn = new QPushButton(tr("Open Data Folder"), this);
    connect(openFolderBtn, &QPushButton::clicked, this, &SystemLogPage::openDataFolderRequested);
    actions->addWidget(clearBtn);
    actions->addWidget(openFolderBtn);
    actions->addStretch(1);
    root->addLayout(actions);
}

void SystemLogPage::appendLine(const QString& line) {
    logView_->appendPlainText(line);
}

void SystemLogPage::clear() {
    logView_->clear();
}
