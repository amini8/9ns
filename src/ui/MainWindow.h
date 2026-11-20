#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <QCloseEvent>
#include <QMainWindow>
#include <QString>

#include "core/Config.h"
#include "core/Engine.h"
#include "core/Logger.h"
#include "ui/ConfigSession.h"
#include "ui/QueryLogModel.h"
#include "ui/ResolverJobs.h"

class QLabel;
class QListWidget;
class QPushButton;
class QueryLogFilterProxyModel;
class QStackedWidget;
class QSystemTrayIcon;
class QTimer;
class QVBoxLayout;

class OverviewPage;
class QueryLogPage;
class RulesPage;
class ServersPoolsPage;
class SettingsPage;
class SystemLogPage;

// Main window: sidebar shell (Overview, Query Log, Servers & Pools, Rules,
// Settings, System Log), system tray integration, and configuration lifecycle
// (ConfigSession draft/saved/running coordination).
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(Logger& logger, Engine& engine, std::filesystem::path configPath, QWidget* parent = nullptr);
    ~MainWindow() override;

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

signals:
    void logReceived(const QString& line);
    void eventReceived(const ResolveEvent& ev);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onToggleEngine();
    void onSaveConfig();
    void onReloadConfig();
    void onFlushCache();
    void onClearLog();
    void onTrayActivated(int reason);
    void appendLog(const QString& line);
    void onEventHandled(const ResolveEvent& ev);
    void onSessionChanged();

    // Servers & Pools
    void addUpstream();
    void editUpstream();
    void deleteUpstream();
    void testSelectedUpstream();

    void addPool();
    void editPool();
    void deletePool();

    // Rules
    void addRule();
    void editRule();
    void deleteRule();
    void moveRule(int delta);

    // Wizard & Service
    void runFirstStartWizard();
    void installWindowsService();
    void uninstallWindowsService();

    // Query Details & Actions
    void blockDomainFromLog(const QString& domain);
    void bypassDomainFromLog(const QString& domain);
    void updateDashboardMetrics();

    // Public Resolvers Browser
    void openPublicResolversBrowser();

    // Menu Actions
    void onImportConfig();
    void onExportConfig();
    void onOpenLogFolder();
    void onAbout();
    void quitApp();

private:
    void buildMenuBar();
    void buildUi();
    void buildHeaderCard(QVBoxLayout* mainLayout);
    void wirePages();
    void setupTrayIcon();

    void loadConfigFile();
    void populate();
    void refreshUpstreams();
    void refreshPools();
    void refreshDefaultTargetCombo();
    void refreshRules();
    Config settingsFromUi() const;
    // Opens the log file for the draft's logging settings. Returns false and
    // records the reason in logError_ on failure.
    bool openLog();
    QString logError_;
    void updateState();
    void showError(const QString& message);
    // Renders untrusted interpolated text literally (plain text, never rich text).
    void showPlainInfo(const QString& title, const QString& message);
    void showStatus(const QString& message);

    // Returns false and explains why when a failed load blocks every write path.
    bool guardWrites();
    // Save / Discard / Cancel. Returns true when it is safe to lose the draft.
    bool confirmDiscardDraft(const QString& reason);
    // Explicit replacement confirmation, asked even when the draft is clean.
    bool confirmReplacement(const QString& reason);
    void applyRuntimeConfig(const Config& config);
    void rebuildErrorBanner();

    // Commits a dialog result into the draft. Validates the candidate first and,
    // when the name changed, rewrites every alias (default target, pool members,
    // rule targets) in the same mutation. Returns false and explains why on a
    // rejected candidate or a name collision.
    bool commitEditedUpstream(const UpstreamConfig& server, int row);
    bool commitEditedPool(const PoolConfig& pool, int row);

    // The editable working copy. Never persist it without going through session_.
    Config& draft() { return session_.draft(); }
    const Config& draft() const { return session_.draft(); }

    Logger& logger_;
    Engine& engine_;
    std::filesystem::path configPath_;
    ConfigSession session_;
    // The configuration the running engine was started with. Kept separate from
    // the draft: edits take effect on the next start only.
    Config runtimeConfig_;

    // Navigation: named sidebar entries mapped 1:1 onto the page stack.
    QListWidget* sidebar_ = nullptr;
    QStackedWidget* stack_ = nullptr;

    // Header Card Controls
    QLabel* headerStatusBadge_ = nullptr;
    QLabel* headerDirtyLabel_ = nullptr;
    QPushButton* toggleEngineBtn_ = nullptr;
    QPushButton* flushCacheBtn_ = nullptr;
    QPushButton* publicResolversBtn_ = nullptr;

    // Persistent load-error banner (shown only while session state is Failed)
    QWidget* errorBanner_ = nullptr;
    QLabel* errorBannerLabel_ = nullptr;

    // Set when the user chose File/Tray Exit, so closeEvent does not hide to tray.
    bool quitting_ = false;

    // Tray
    QSystemTrayIcon* trayIcon_ = nullptr;

    // Pages. They are display-only: MainWindow owns the Engine, the draft and
    // all persistence.
    OverviewPage* overviewPage_ = nullptr;
    QueryLogPage* queryLogPage_ = nullptr;
    ServersPoolsPage* serversPoolsPage_ = nullptr;
    RulesPage* rulesPage_ = nullptr;
    SettingsPage* settingsPage_ = nullptr;
    SystemLogPage* systemLogPage_ = nullptr;

    // Query Log model (owned here so the Engine sink outlives the page)
    QueryLogModel* queryLogModel_ = nullptr;
    QueryLogFilterProxyModel* queryFilterProxy_ = nullptr;

    // Background reachability tests for the Servers & Pools page.
    ResolverJobs* resolverJobs_ = nullptr;
    PingRequestTracker pingRequests_;

    QTimer* metricsTimer_ = nullptr;
    uint64_t totalQueries_ = 0;
    uint64_t blockedQueries_ = 0;
    uint64_t lastSecondQueries_ = 0;
};
