#include "ui/QueryDetailsDialog.h"

#include <cctype>
#include <iomanip>
#include <sstream>

#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QHeaderView>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

QueryDetailsDialog::QueryDetailsDialog(const ResolveEvent& event, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("DNS Query Inspector - ") + QString::fromStdString(event.queryName));
    resize(750, 550);

    auto* layout = new QVBoxLayout(this);
    auto* tabs = new QTabWidget(this);

    // Tab 1: Structured Sections
    treeWidget_ = new QTreeWidget(tabs);
    treeWidget_->setHeaderLabels(QStringList{tr("Field / Section"), tr("Value")});
    treeWidget_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tabs->addTab(treeWidget_, tr("Decoded Sections"));

    // Tab 2: Raw Hex Dump
    hexView_ = new QPlainTextEdit(tabs);
    hexView_->setReadOnly(true);
    hexView_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    tabs->addTab(hexView_, tr("Hex Packet Dump"));

    layout->addWidget(tabs);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    populate(event);
}

void QueryDetailsDialog::populate(const ResolveEvent& event) {
    // Top summary
    auto* summaryItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("Event Summary"), QString()});
    new QTreeWidgetItem(summaryItem, QStringList{tr("Client IP"), QString::fromStdString(event.clientIp)});
    new QTreeWidgetItem(summaryItem, QStringList{tr("Target"), QString::fromStdString(event.target)});
    new QTreeWidgetItem(summaryItem, QStringList{tr("Server Used"), QString::fromStdString(event.usedServer)});
    new QTreeWidgetItem(summaryItem, QStringList{tr("Action"), QString::fromStdString(event.action)});
    new QTreeWidgetItem(summaryItem, QStringList{tr("Latency"), QString::number(event.latencyMs) + tr(" ms")});
    new QTreeWidgetItem(summaryItem, QStringList{tr("DNSSEC Status"), QString::fromStdString(dnsSecStatusToString(event.dnssec))});
    summaryItem->setExpanded(true);

    const dns::Bytes& packet = !event.response.empty() ? event.response : event.query;
    dns::ParsedMessage msg;
    if (dns::parseMessage(packet, msg)) {
        // Header
        auto* headerItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("DNS Header"), QString()});
        new QTreeWidgetItem(headerItem, QStringList{tr("Transaction ID"), QString("0x%1").arg(msg.id, 4, 16, QChar('0'))});
        new QTreeWidgetItem(headerItem, QStringList{tr("Response (QR)"), msg.isResponse ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Authoritative (AA)"), msg.aa ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Truncated (TC)"), msg.tc ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Recursion Desired (RD)"), msg.rd ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Recursion Available (RA)"), msg.ra ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Authenticated Data (AD)"), msg.ad ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Checking Disabled (CD)"), msg.cd ? tr("True") : tr("False")});
        new QTreeWidgetItem(headerItem, QStringList{tr("Response Code"), QString::fromStdString(dns::rcodeName(msg.rcode))});
        headerItem->setExpanded(true);

        // Questions
        auto* qItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("Questions (%1)").arg(msg.questions.size()), QString()});
        for (const auto& q : msg.questions) {
            new QTreeWidgetItem(qItem, QStringList{QString::fromStdString(q.name),
                                                   QString("%1 (Class %2)").arg(QString::fromStdString(dns::typeName(q.type))).arg(q.qclass)});
        }
        qItem->setExpanded(true);

        // Answers
        auto* anItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("Answers (%1)").arg(msg.answers.size()), QString()});
        for (const auto& a : msg.answers) {
            new QTreeWidgetItem(anItem, QStringList{QString::fromStdString(a.name) + " [" + QString::fromStdString(dns::typeName(a.type)) + "]",
                                                    QString("TTL %1s | %2").arg(a.ttl).arg(QString::fromStdString(a.dataFormatted))});
        }
        anItem->setExpanded(!msg.answers.empty());

        // Authorities
        auto* nsItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("Authority (%1)").arg(msg.authorities.size()), QString()});
        for (const auto& a : msg.authorities) {
            new QTreeWidgetItem(nsItem, QStringList{QString::fromStdString(a.name) + " [" + QString::fromStdString(dns::typeName(a.type)) + "]",
                                                    QString("TTL %1s | %2").arg(a.ttl).arg(QString::fromStdString(a.dataFormatted))});
        }
        nsItem->setExpanded(!msg.authorities.empty());

        // Additional
        auto* arItem = new QTreeWidgetItem(treeWidget_, QStringList{tr("Additional (%1)").arg(msg.additionals.size()), QString()});
        for (const auto& a : msg.additionals) {
            new QTreeWidgetItem(arItem, QStringList{QString::fromStdString(a.name) + " [" + QString::fromStdString(dns::typeName(a.type)) + "]",
                                                    QString("TTL %1s | %2").arg(a.ttl).arg(QString::fromStdString(a.dataFormatted))});
        }
        arItem->setExpanded(!msg.additionals.empty());
    }

    hexView_->setPlainText(formatHexDump(packet));
}

QString QueryDetailsDialog::formatHexDump(const dns::Bytes& data) {
    if (data.empty()) {
        return tr("(empty packet)");
    }
    QString out;
    for (size_t i = 0; i < data.size(); i += 16) {
        out += QString("%1  ").arg(i, 4, 16, QChar('0'));
        QString ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                const uint8_t byte = data[i + j];
                out += QString("%1 ").arg(byte, 2, 16, QChar('0'));
                ascii += (byte >= 32 && byte < 127) ? QChar(byte) : QChar('.');
            } else {
                out += "   ";
            }
            if (j == 7) {
                out += " ";
            }
        }
        out += " |" + ascii + "|\n";
    }
    return out;
}
