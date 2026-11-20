#pragma once

#include <QColor>
#include <QFont>
#include <QString>

class QApplication;

// Small application-level theme: shared spacing, typography and semantic colors
// for the sidebar shell, pages and owned dialogs.
//
// Colors are palette-aware: the branded teal/slate scheme is only applied when
// the platform is not in high-contrast mode. In high-contrast mode the
// stylesheet is empty so native keyboard focus and disabled states are
// preserved exactly as the user configured them.
namespace Theme {

// Standard Windows UI font at the application's base size.
QFont uiFont();
QFont titleFont();
QFont monoFont();

// Scalable metrics (grow with the font, not with hard-coded pixels).
int spacingSmall();
int spacingNormal();
int spacingLarge();
int sidebarWidth();

// Semantic colors. Meaning is stable even when the exact hue is not.
QColor textMuted();
QColor success();
QColor warning();
QColor danger();

// True when the platform runs in high-contrast mode: brand styling is skipped.
bool isHighContrast();

// The application stylesheet. Empty in high-contrast mode.
QString applicationStyleSheet();

// Applies font and stylesheet to the application. Call once after QApplication
// construction and after the service/watchdog dispatch paths have returned.
void apply(QApplication& app);

}  // namespace Theme
