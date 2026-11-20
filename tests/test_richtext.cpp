#include <QtTest/QtTest>

#include <QTableWidget>
#include <QTextDocument>

#include "PublicResolverFixtures.h"
#include "ui/PublicResolversDialog.h"

using namespace publicResolverFixtures;

namespace {

PublicResolversDialog::Services services(const std::vector<PublicDnsItem>& entries) {
    PublicResolversDialog::Services result;
    result.load = [entries](bool, std::string&) { return entries; };
    result.probe = [](const UpstreamConfig&, uint32_t& rtt, std::string&) {
        rtt = 7;
        return true;
    };
    result.notice = [](const QString&, const QString&, bool) {};
    result.poolName = [](QString& out) {
        out = QStringLiteral("p");
        return true;
    };
    return result;
}

void selectRows(QTableWidget* table, int first, int last) {
    table->clearSelection();
    table->setRangeSelected(QTableWidgetSelectionRange(first, 0, last, table->columnCount() - 1), true);
}

// The tooltip must render the original characters literally: wrapped so Qt
// treats it as rich text, with every tag from the input escaped away (SEC-12).
bool rendersLiterally(const QString& toolTip, const QString& original) {
    if (!toolTip.startsWith(QStringLiteral("<qt>")) || !toolTip.endsWith(QStringLiteral("</qt>"))) {
        return false;
    }
    if (toolTip.contains(QStringLiteral("<b>")) || toolTip.contains(QStringLiteral("</b>"))) {
        return false;
    }
    QTextDocument document;
    document.setHtml(toolTip);
    return document.toPlainText().contains(original);
}

}  // namespace

class TestRichTextEscape : public QObject {
    Q_OBJECT

private slots:
    void stampToolTipRendersStampLiterally() {
        Config current = config();
        auto entry = item(0x02, "plain");
        entry.stamp = "<b>STAMP</b>";
        PublicResolversDialog dialog(current, services({entry}));
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        QVERIFY(table);
        QTRY_COMPARE(table->rowCount(), 1);
        const QString toolTip = table->item(0, 6)->toolTip();
        QVERIFY2(rendersLiterally(toolTip, QStringLiteral("<b>STAMP</b>")), qPrintable(toolTip));
    }

    void relayErrorToolTipRendersNameLiterally() {
        Config current = config();
        auto relay = item(0x85, "<b>INJECT</b>");
        PublicResolversDialog dialog(current, services({relay}));
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>(QStringLiteral("resolversTable"));
        QVERIFY(table);
        QTRY_COMPARE(table->rowCount(), 1);
        selectRows(table, 0, 0);
        QVERIFY(QMetaObject::invokeMethod(&dialog, "onPingSelected", Qt::DirectConnection));
        auto* latItem = table->item(0, 5);
        QVERIFY(latItem);
        QCOMPARE(latItem->text(), QStringLiteral("Not a resolver"));
        const QString toolTip = latItem->toolTip();
        QVERIFY2(rendersLiterally(toolTip, QStringLiteral("<b>INJECT</b>")), qPrintable(toolTip));
    }
};

QTEST_MAIN(TestRichTextEscape)
#include "test_richtext.moc"
