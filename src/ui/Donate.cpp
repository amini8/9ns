#include "ui/Donate.h"

#include <QClipboard>
#include <QDialog>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QObject>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>

namespace Donate {

void showDialog(QWidget* parent) {
    QDialog dlg(parent);
    dlg.setWindowTitle(QObject::tr("Donate to 9NS"));
    dlg.setWindowIcon(QIcon(QStringLiteral(":/icons/9ns-mark.svg")));

    auto* layout = new QVBoxLayout(&dlg);
    layout->addWidget(new QLabel(QObject::tr("<h3>Support 9NS</h3>"), &dlg));

    auto* blurb = new QLabel(
        QObject::tr("9NS is free, open-source software licensed under the GNU AGPL v3. "
                    "If it has earned a place on your machine, a Bitcoin donation keeps it maintained."),
        &dlg);
    blurb->setWordWrap(true);
    layout->addWidget(blurb);

    const QString address = QString::fromLatin1(kBtcAddress);

    auto* addressLabel = new QLabel(address, &dlg);
    addressLabel->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    addressLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    addressLabel->setStyleSheet(QStringLiteral("padding: 8px; border: 1px solid #CBD5E1; border-radius: 6px;"));
    layout->addWidget(addressLabel);

    auto* statusLabel = new QLabel(&dlg);
    statusLabel->setStyleSheet(QStringLiteral("color: #64748B; font-size: 12px;"));
    layout->addWidget(statusLabel);

    auto* buttons = new QHBoxLayout();
    auto* copyBtn = new QPushButton(QObject::tr("Copy Address"), &dlg);
    copyBtn->setDefault(true);
    QObject::connect(copyBtn, &QPushButton::clicked, &dlg, [address, statusLabel] {
        QGuiApplication::clipboard()->setText(address);
        statusLabel->setText(QObject::tr("Address copied to clipboard."));
    });
    buttons->addWidget(copyBtn);

    auto* closeBtn = new QPushButton(QObject::tr("Close"), &dlg);
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    buttons->addWidget(closeBtn);

    layout->addLayout(buttons);
    dlg.exec();
}

}  // namespace Donate
