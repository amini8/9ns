#include "ui/Theme.h"

#include <windows.h>

#include <QApplication>
#include <QFont>
#include <QGuiApplication>
#include <QPalette>

namespace Theme {

namespace {

// Teal/slate brand scale. Used only when the platform is not in high contrast.
const QColor kTextMuted(100, 116, 139);   // slate 500
const QColor kSuccess(22, 163, 74);
const QColor kWarning(217, 119, 6);
const QColor kDanger(220, 38, 38);

QColor paletteColor(QPalette::ColorRole role) {
    return QGuiApplication::palette().color(role);
}

}  // namespace

QFont uiFont() {
    QFont font(QStringLiteral("Segoe UI"));
    font.setPointSize(9);
    return font;
}

QFont titleFont() {
    QFont font = uiFont();
    font.setBold(true);
    return font;
}

QFont monoFont() {
    QFont font(QStringLiteral("Consolas"));
    font.setPointSize(9);
    return font;
}

int spacingSmall() { return 4; }
int spacingNormal() { return 8; }
int spacingLarge() { return 16; }
int sidebarWidth() { return 200; }

QColor textMuted() { return isHighContrast() ? paletteColor(QPalette::PlaceholderText) : kTextMuted; }
QColor success() { return kSuccess; }
QColor warning() { return kWarning; }
QColor danger() { return kDanger; }

bool isHighContrast() {
    HIGHCONTRASTW hc{};
    hc.cbSize = sizeof(hc);
    if (!SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0)) {
        return false;
    }
    return (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
}

QString applicationStyleSheet() {
    if (isHighContrast()) {
        // Let the platform style paint everything so keyboard focus and
        // disabled states stay exactly as the user configured them.
        return QString();
    }
    return QStringLiteral(R"(
        QMainWindow {
            background-color: #F8FAFC;
            font-family: "Segoe UI", system-ui, sans-serif;
            font-size: 13px;
            color: #1E293B;
        }
        QMenuBar {
            background-color: #FFFFFF;
            border-bottom: 1px solid #E2E8F0;
            padding: 4px 6px;
            font-size: 13px;
            color: #334155;
        }
        QMenuBar::item:selected { background-color: #F1F5F9; color: #0F172A; }
        QMenu {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            padding: 4px;
            color: #1E293B;
        }
        QMenu::item { padding: 6px 20px; border-radius: 4px; }
        QMenu::item:selected { background-color: #F0FDFA; color: #0F766E; }
        QGroupBox {
            font-weight: bold;
            font-size: 13px;
            color: #1E293B;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            margin-top: 12px;
            padding: 14px;
            background-color: #FFFFFF;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            background-color: #FFFFFF;
        }
        QPushButton {
            border-radius: 6px;
            border: 1px solid #CBD5E1;
            background-color: #FFFFFF;
            padding: 6px 14px;
            font-weight: 500;
            font-size: 13px;
            color: #334155;
        }
        QPushButton:hover { background-color: #F8FAFC; border-color: #94A3B8; color: #0F172A; }
        QPushButton:pressed { background-color: #F1F5F9; }
        QPushButton:disabled {
            background-color: #F1F5F9;
            color: #94A3B8;
            border-color: #E2E8F0;
        }
        QLineEdit, QComboBox, QSpinBox {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 13px;
            background-color: #FFFFFF;
            color: #1E293B;
            selection-background-color: #0D9488;
        }
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #0D9488; }
        QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {
            background-color: #F1F5F9;
            color: #94A3B8;
        }
        QCheckBox, QRadioButton { color: #334155; font-size: 13px; spacing: 8px; }
        QTableView {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            gridline-color: #F1F5F9;
            selection-background-color: #CCFBF1;
            selection-color: #134E4A;
            font-size: 12px;
        }
        QTableView::item { padding: 4px 8px; }
        QHeaderView::section {
            background-color: #F8FAFC;
            color: #475569;
            border: none;
            border-bottom: 2px solid #0D9488;
            padding: 6px 8px;
            font-weight: bold;
            font-size: 12px;
        }
        QPlainTextEdit, QTextEdit {
            background-color: #0F172A;
            color: #E2E8F0;
            border: 1px solid #1E293B;
            border-radius: 8px;
            font-family: "Consolas", monospace;
            font-size: 12px;
        }
        QTabWidget::pane { border: none; background-color: transparent; }
        QTabBar { display: none; }
        QListWidget {
            background-color: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            outline: none;
        }
        QListWidget::item { padding: 10px 12px; border-radius: 6px; color: #334155; }
        QListWidget::item:hover { background-color: #F1F5F9; }
        QListWidget::item:selected { background-color: #0D9488; color: #FFFFFF; }
        QScrollBar:vertical {
            background: transparent;
            width: 10px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #CBD5E1;
            border-radius: 5px;
            min-height: 30px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar:horizontal {
            background: transparent;
            height: 10px;
            margin: 0;
        }
        QScrollBar::handle:horizontal {
            background: #CBD5E1;
            border-radius: 5px;
            min-width: 30px;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
        QToolTip {
            background-color: #0F172A;
            color: #F8FAFC;
            border: 1px solid #1E293B;
            padding: 4px 8px;
        }
    )");
}

void apply(QApplication& app) {
    app.setFont(uiFont());
    app.setStyleSheet(applicationStyleSheet());
}

}  // namespace Theme
