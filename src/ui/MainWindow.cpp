#include <winsock2.h>
#include <windows.h>

#include "ui/MainWindow.h"

#include <algorithm>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QKeySequence>
#include <QLabel>
#include <QListWidget>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStringList>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QVBoxLayout>

#include "ui/Donate.h"
#include "ui/PoolDialog.h"
#include "ui/PublicResolversDialog.h"
#include "ui/QueryDetailsDialog.h"
#include "ui/QueryLogFilterProxyModel.h"
#include "ui/ResolverJobs.h"
#include "ui/RuleDialog.h"
#include "ui/ServerDialog.h"
#include "ui/Theme.h"
#include "ui/pages/OverviewPage.h"
#include "ui/pages/QueryLogPage.h"
#include "ui/pages/RulesPage.h"
#include "ui/pages/ServersPoolsPage.h"
#include "ui/pages/SettingsPage.h"
#include "ui/pages/SystemLogPage.h"
#include "core/Text.h"
#include "core/SystemDns.h"
#include "core/WindowsService.h"
#include "ui/WizardDialog.h"

namespace {

QString qstr(const std::string& text) {
    return QString::fromStdString(text);
}

std::filesystem::path resolveLogPath(const std::filesystem::path& dataDir, const std::wstring& name) {
    if (name.empty()) {
        return {};
    }
    const std::filesystem::path relative = std::filesystem::path(name).lexically_normal();
    if (relative.is_absolute() || relative.has_root_name() || relative.has_root_directory()) {
        throw std::runtime_error("log_file must be a file name inside the data folder");
    }
    for (const auto& part : relative) {
        if (part.native() == L"..") {
            throw std::runtime_error("log_file must not leave the data folder");
        }
    }
    return (dataDir / relative).lexically_normal();
}

QIcon createStatusIcon(const QColor& color) {
    QIcon baseIcon(QStringLiteral(":/icons/9ns-mark.svg"));
    QPixmap pixmap = baseIcon.pixmap(32, 32);
    if (pixmap.isNull()) {
        pixmap = QPixmap(32, 32);
        pixmap.fill(Qt::transparent);
    }
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setBrush(color);
    painter.setPen(QPen(Qt::white, 1.5));
    painter.drawEllipse(18, 18, 12, 12);
    return QIcon(pixmap);
}

// Returns false and fills error when the Run-key write fails.
bool setAutostartRegistry(bool enable, QString& error) {
    HKEY hKey = nullptr;
    const wchar_t* subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        error = QObject::tr("cannot open the Run registry key (error %1)").arg(GetLastError());
        return false;
    }
    bool ok = true;
    if (enable) {
        std::wstring path(MAX_PATH, L'\0');
        const DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        path.resize(len);
        const std::wstring cmd = L"\"" + path + L"\"";
        ok = RegSetValueExW(hKey, L"9NS", 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(cmd.c_str()),
                            static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    } else {
        const LSTATUS status = RegDeleteValueW(hKey, L"9NS");
        // Deleting a value that is not there is not a failure.
        ok = (status == ERROR_SUCCESS) || (status == ERROR_FILE_NOT_FOUND);
    }
    RegCloseKey(hKey);
    if (!ok) {
        error = QObject::tr("cannot update the Run registry key (error %1)").arg(GetLastError());
    }
    return ok;
}

}  // namespace

MainWindow::MainWindow(Logger& logger, Engine& engine, std::filesystem::path configPath, QWidget* parent)
    : QMainWindow(parent), logger_(logger), engine_(engine), configPath_(std::move(configPath)),
      session_(configPath_) {
    buildUi();

    connect(this, &MainWindow::logReceived, this, &MainWindow::appendLog, Qt::QueuedConnection);
    connect(this, &MainWindow::eventReceived, this, &MainWindow::onEventHandled, Qt::QueuedConnection);
    connect(&session_, &ConfigSession::changed, this, &MainWindow::onSessionChanged);

    logger_.setSink([this](const std::string& line) { emit logReceived(qstr(line)); });

    loadConfigFile();
    populate();
    if (!openLog()) {
        showError(tr("Cannot open log file: %1").arg(logError_));
    }
    setupTrayIcon();

    // Stats timer
    metricsTimer_ = new QTimer(this);
    connect(metricsTimer_, &QTimer::timeout, this, &MainWindow::updateDashboardMetrics);
    metricsTimer_->start(1000);

    updateState();

    // Onboarding is only for a genuinely absent configuration file, not for a
    // valid config that happens to be minimal.
    if (session_.state() == ConfigSession::State::Missing) {
        QTimer::singleShot(200, this, [this] {
            runFirstStartWizard();
        });
    }
}

MainWindow::~MainWindow() {
    logger_.setSink(nullptr);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (!quitting_ && draft().closeToTray && trayIcon_ && trayIcon_->isVisible()) {
        // Hiding to the tray keeps the draft; only a true Exit prompts.
        hide();
        trayIcon_->showMessage(tr("9NS Running"),
                               tr("9NS is running in the system tray."),
                               QSystemTrayIcon::Information, 2000);
        event->ignore();
        return;
    }
    if (!confirmDiscardDraft(tr("Exiting 9NS discards your unsaved changes."))) {
        event->ignore();
        return;
    }
    event->accept();
}

void MainWindow::quitApp() {
    if (!confirmDiscardDraft(tr("Exiting 9NS discards your unsaved changes."))) {
        return;
    }
    quitting_ = true;
    close();
    qApp->quit();
}

void MainWindow::onSessionChanged() {
    rebuildErrorBanner();
    if (headerDirtyLabel_) {
        if (session_.writesBlocked()) {
            headerDirtyLabel_->setText(tr("Configuration blocked"));
            headerDirtyLabel_->setStyleSheet(QStringLiteral("color: #B91C1C; font-size: 11px; font-weight: bold;"));
        } else if (session_.isDirty()) {
            headerDirtyLabel_->setText(tr("Unsaved changes — takes effect on next start"));
            headerDirtyLabel_->setStyleSheet(QStringLiteral("color: #B45309; font-size: 11px; font-weight: bold;"));
        } else {
            headerDirtyLabel_->setText(tr("Saved"));
            headerDirtyLabel_->setStyleSheet(QStringLiteral("color: #64748B; font-size: 11px;"));
        }
    }
    updateState();
}

void MainWindow::buildMenuBar() {
    auto* bar = menuBar();

    // File
    auto* fileMenu = bar->addMenu(tr("&File"));
    fileMenu->addAction(QIcon(QStringLiteral(":/icons/save.svg")), tr("&Save Settings"), QKeySequence::Save, this, &MainWindow::onSaveConfig);
    fileMenu->addAction(QIcon(QStringLiteral(":/icons/folder.svg")), tr("&Import Configuration..."), QKeySequence::Open, this, &MainWindow::onImportConfig);
    fileMenu->addAction(tr("&Export Configuration..."), this, &MainWindow::onExportConfig);
    fileMenu->addSeparator();
    fileMenu->addAction(QIcon(QStringLiteral(":/icons/9ns-mark.svg")), tr("&About 9NS..."), this, &MainWindow::onAbout);
    fileMenu->addSeparator();
    fileMenu->addAction(QIcon(QStringLiteral(":/icons/folder.svg")), tr("&Reload Configuration"), this, &MainWindow::onReloadConfig);
    fileMenu->addAction(QIcon(QStringLiteral(":/icons/stop.svg")), tr("E&xit"), QKeySequence::Quit, this, &MainWindow::quitApp);

    // Configuration
    auto* cfgMenu = bar->addMenu(tr("&Configuration"));
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/flush.svg")), tr("&Flush DNS Cache"), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_F), this, &MainWindow::onFlushCache);
    cfgMenu->addSeparator();
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/globe.svg")), tr("&Public Resolvers & Relays (Web Import)..."), QKeySequence(Qt::CTRL | Qt::Key_R), this, &MainWindow::openPublicResolversBrowser);
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/wizard.svg")), tr("&First-Start Setup Wizard..."), this, &MainWindow::runFirstStartWizard);
    cfgMenu->addSeparator();
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/add.svg")), tr("Add DNS &Server..."), this, &MainWindow::addUpstream);
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/add.svg")), tr("Add Server &Pool..."), this, &MainWindow::addPool);
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/add.svg")), tr("Add DNS &Rule..."), this, &MainWindow::addRule);
    cfgMenu->addSeparator();

    // Logs submenu under Configuration
    auto* logsMenu = cfgMenu->addMenu(QIcon(QStringLiteral(":/icons/system-log.svg")), tr("&Logs"));
    logsMenu->addAction(QIcon(QStringLiteral(":/icons/query-log.svg")), tr("View &Live Query Log"), QKeySequence(Qt::CTRL | Qt::Key_2), this, [this] {
        sidebar_->setCurrentRow(1);
    });
    logsMenu->addAction(QIcon(QStringLiteral(":/icons/system-log.svg")), tr("View &System Diagnostics Log"), QKeySequence(Qt::CTRL | Qt::Key_6), this, [this] {
        sidebar_->setCurrentRow(5);
    });
    logsMenu->addSeparator();
    logsMenu->addAction(QIcon(QStringLiteral(":/icons/clear.svg")), tr("&Clear Live Query Log"), this, &MainWindow::onClearLog);
    logsMenu->addAction(QIcon(QStringLiteral(":/icons/folder.svg")), tr("&Open Logs & Data Folder..."), this, &MainWindow::onOpenLogFolder);
    cfgMenu->addSeparator();

    // Service actions under Configuration
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/start.svg")), tr("&Install Windows Service"), this, &MainWindow::installWindowsService);
    cfgMenu->addAction(QIcon(QStringLiteral(":/icons/stop.svg")), tr("&Uninstall Windows Service"), this, &MainWindow::uninstallWindowsService);
    cfgMenu->addSeparator();

    // Minimize to System Tray under Configuration
    cfgMenu->addAction(tr("&Minimize to System Tray"), this, [this] {
        if (trayIcon_ && trayIcon_->isVisible()) hide();
    });
}

void MainWindow::buildHeaderCard(QVBoxLayout* mainLayout) {
    auto* headerCard = new QWidget(this);
    headerCard->setObjectName(QStringLiteral("headerCard"));
    headerCard->setStyleSheet(QStringLiteral(
        "#headerCard {"
        "  background-color: #FFFFFF;"
        "  border: 1px solid #E2E8F0;"
        "  border-radius: 8px;"
        "  padding: 6px 14px;"
        "}"
    ));
    auto* layout = new QHBoxLayout(headerCard);
    layout->setContentsMargins(10, 6, 10, 6);
    layout->setSpacing(12);

    auto* logoLabel = new QLabel(headerCard);
    logoLabel->setPixmap(QIcon(QStringLiteral(":/icons/9ns-mark.svg")).pixmap(32, 32));
    logoLabel->setFixedSize(32, 32);

    auto* titleCol = new QVBoxLayout();
    titleCol->setSpacing(0);
    auto* titleLabel = new QLabel(QStringLiteral("<b style='font-size: 15px; color: #0F172A;'>9NS</b> <span style='font-size: 11px; color: #64748B;'>v1.1.0</span>"), headerCard);
    auto* subLabel = new QLabel(tr("Encrypted DNS Client & System Protection"), headerCard);
    subLabel->setStyleSheet(QStringLiteral("color: #64748B; font-size: 11px;"));
    titleCol->addWidget(titleLabel);
    titleCol->addWidget(subLabel);

    headerStatusBadge_ = new QLabel(headerCard);
    headerStatusBadge_->setAlignment(Qt::AlignCenter);

    headerDirtyLabel_ = new QLabel(headerCard);
    headerDirtyLabel_->setAlignment(Qt::AlignCenter);
    headerDirtyLabel_->setStyleSheet(QStringLiteral("color: #64748B; font-size: 11px;"));

    layout->addWidget(logoLabel);
    layout->addLayout(titleCol);
    layout->addSpacing(8);
    layout->addWidget(headerStatusBadge_);
    layout->addWidget(headerDirtyLabel_);
    layout->addStretch(1);

    auto* saveBtn = new QPushButton(QIcon(QStringLiteral(":/icons/save.svg")), tr("Save Changes"), headerCard);
    saveBtn->setToolTip(tr("Save the configuration to disk (Ctrl+S)"));
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveConfig);
    layout->addWidget(saveBtn);

    toggleEngineBtn_ = new QPushButton(headerCard);
    toggleEngineBtn_->setCursor(Qt::PointingHandCursor);
    connect(toggleEngineBtn_, &QPushButton::clicked, this, &MainWindow::onToggleEngine);
    layout->addWidget(toggleEngineBtn_);

    flushCacheBtn_ = new QPushButton(QIcon(QStringLiteral(":/icons/flush.svg")), tr("Flush Cache"), headerCard);
    flushCacheBtn_->setToolTip(tr("Flush DNS Reply Cache"));
    connect(flushCacheBtn_, &QPushButton::clicked, this, &MainWindow::onFlushCache);
    layout->addWidget(flushCacheBtn_);

    publicResolversBtn_ = new QPushButton(QIcon(QStringLiteral(":/icons/globe.svg")), tr("Public Resolvers"), headerCard);
    publicResolversBtn_->setToolTip(tr("Browse & Benchmark Public DNS Resolvers (Ctrl+R)"));
    connect(publicResolversBtn_, &QPushButton::clicked, this, &MainWindow::openPublicResolversBrowser);
    layout->addWidget(publicResolversBtn_);

    mainLayout->addWidget(headerCard);
}

void MainWindow::buildUi() {
    setWindowTitle(tr("9NS - Advanced System DNS Client"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/9ns-mark.svg")));
    resize(1120, 760);

    buildMenuBar();

    auto* central = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(10, 8, 10, 10);
    mainLayout->setSpacing(8);

    buildHeaderCard(mainLayout);

    // Persistent error banner for a failed configuration load.
    errorBanner_ = new QWidget(central);
    errorBanner_->setObjectName(QStringLiteral("errorBanner"));
    errorBanner_->setStyleSheet(QStringLiteral(
        "#errorBanner {"
        "  background-color: #FEF2F2;"
        "  border: 1px solid #FECACA;"
        "  border-radius: 8px;"
        "  padding: 10px 12px;"
        "}"));
    auto* errorLayout = new QHBoxLayout(errorBanner_);
    errorLayout->setContentsMargins(12, 8, 12, 8);
    errorBannerLabel_ = new QLabel(errorBanner_);
    errorBannerLabel_->setWordWrap(true);
    errorBannerLabel_->setStyleSheet(QStringLiteral("color: #991B1B;"));
    errorLayout->addWidget(errorBannerLabel_, 1);

    auto* errorButtons = new QHBoxLayout();
    auto* openDataBtn = new QPushButton(tr("Open Data Folder"), errorBanner_);
    connect(openDataBtn, &QPushButton::clicked, this, &MainWindow::onOpenLogFolder);
    auto* reloadBtn = new QPushButton(tr("Reload"), errorBanner_);
    connect(reloadBtn, &QPushButton::clicked, this, &MainWindow::onReloadConfig);
    auto* importBtn = new QPushButton(tr("Import Replacement..."), errorBanner_);
    connect(importBtn, &QPushButton::clicked, this, &MainWindow::onImportConfig);
    errorButtons->addWidget(openDataBtn);
    errorButtons->addWidget(reloadBtn);
    errorButtons->addWidget(importBtn);
    errorLayout->addLayout(errorButtons);
    errorBanner_->setVisible(false);
    mainLayout->addWidget(errorBanner_);

    // Sidebar + page stack. Page order matches the sidebar order exactly.
    auto* body = new QHBoxLayout();
    body->setSpacing(Theme::spacingNormal());

    sidebar_ = new QListWidget(central);
    sidebar_->setObjectName(QStringLiteral("sidebar"));
    sidebar_->setFixedWidth(Theme::sidebarWidth());
    sidebar_->setMovement(QListView::Static);
    sidebar_->setSpacing(2);
    sidebar_->setAccessibleName(tr("Primary navigation"));
    sidebar_->setStyleSheet(QStringLiteral(
        "#sidebar {"
        "  background-color: #FFFFFF;"
        "  border: 1px solid #E2E8F0;"
        "  border-radius: 8px;"
        "  padding: 6px;"
        "  outline: none;"
        "}"
        "#sidebar::item {"
        "  padding: 10px 12px;"
        "  border-radius: 6px;"
        "  color: #334155;"
        "  margin: 1px 2px;"
        "}"
        "#sidebar::item:hover { background-color: #F1F5F9; }"
        "#sidebar::item:selected {"
        "  background-color: #0D9488;"
        "  color: #FFFFFF;"
        "  font-weight: bold;"
        "}"));

    auto addSidebarEntry = [this](const QString& label, const QIcon& icon, const QString& key) {
        auto* item = new QListWidgetItem(icon, label, sidebar_);
        item->setData(Qt::UserRole, key);
        item->setToolTip(label);
    };
    addSidebarEntry(tr("Overview"), QIcon(QStringLiteral(":/icons/dashboard.svg")), QStringLiteral("overview"));
    addSidebarEntry(tr("Query Log"), QIcon(QStringLiteral(":/icons/query-log.svg")), QStringLiteral("query-log"));
    addSidebarEntry(tr("Servers & Pools"), QIcon(QStringLiteral(":/icons/servers.svg")), QStringLiteral("servers-pools"));
    addSidebarEntry(tr("Rules"), QIcon(QStringLiteral(":/icons/rules.svg")), QStringLiteral("rules"));
    addSidebarEntry(tr("Settings"), QIcon(QStringLiteral(":/icons/settings.svg")), QStringLiteral("settings"));
    addSidebarEntry(tr("System Log"), QIcon(QStringLiteral(":/icons/system-log.svg")), QStringLiteral("system-log"));

    stack_ = new QStackedWidget(central);
    overviewPage_ = new OverviewPage(stack_);
    queryLogPage_ = new QueryLogPage(stack_);
    serversPoolsPage_ = new ServersPoolsPage(stack_);
    rulesPage_ = new RulesPage(stack_);
    settingsPage_ = new SettingsPage(stack_);
    systemLogPage_ = new SystemLogPage(stack_);

    // Stack index == sidebar row, so navigation is a single mapping.
    stack_->addWidget(overviewPage_);
    stack_->addWidget(queryLogPage_);
    stack_->addWidget(serversPoolsPage_);
    stack_->addWidget(rulesPage_);
    stack_->addWidget(settingsPage_);
    stack_->addWidget(systemLogPage_);

    connect(sidebar_, &QListWidget::currentRowChanged, stack_, &QStackedWidget::setCurrentIndex);

    body->addWidget(sidebar_);
    body->addWidget(stack_, 1);
    mainLayout->addLayout(body, 1);

    setCentralWidget(central);

    // Model ownership stays here so the Engine sink outlives the pages.
    queryLogModel_ = new QueryLogModel(this);
    queryFilterProxy_ = new QueryLogFilterProxyModel(this);
    queryFilterProxy_->setSourceModel(queryLogModel_);
    queryLogPage_->setModels(queryLogModel_, queryFilterProxy_);

    // Background reachability tests. The probe is the real transport; results
    // come back on this thread and are matched by stable upstream identity.
    resolverJobs_ = new ResolverJobs(
        [](const UpstreamConfig& config, uint32_t& rttMs, std::string& error) {
            auto upstream = Upstream::create(config);
            return upstream->ping(rttMs, error);
        },
        this);
    connect(resolverJobs_, &ResolverJobs::pingFinished, this, [this](const PingResult& result) {
        if (!pingRequests_.accept(result, draft().upstreams)) {
            return;  // superseded request or changed endpoint
        }
        int row = -1;
        for (int i = 0; i < static_cast<int>(draft().upstreams.size()); ++i) {
            const auto& up = draft().upstreams[static_cast<size_t>(i)];
            if (up.name == result.config.name) {
                row = i;
                break;
            }
        }
        if (row < 0) {
            return;  // the upstream was edited, renamed or deleted while testing
        }
        if (result.ok) {
            serversPoolsPage_->setUpstreamStatus(row, tr("%1 ms").arg(result.rttMs), false);
            overviewPage_->setLatency(row, OverviewPage::LatencyState::Success,
                                      tr("%1 ms").arg(result.rttMs));
        } else {
            serversPoolsPage_->setUpstreamStatus(row, tr("Failed"), true);
            overviewPage_->setLatency(row, OverviewPage::LatencyState::Failure, result.error);
        }
    });

    wirePages();

    // Named page routing for the menu and keyboard shortcuts (Ctrl+1..6).
    auto addPageAction = [this](const QString& title, const QKeySequence& shortcut, int row) {
        QAction* action = new QAction(title, this);
        action->setShortcut(shortcut);
        connect(action, &QAction::triggered, this, [this, row] {
            sidebar_->setCurrentRow(row);
        });
        addAction(action);
    };
    addPageAction(tr("Overview"), QKeySequence(Qt::CTRL | Qt::Key_1), 0);
    addPageAction(tr("Query Log"), QKeySequence(Qt::CTRL | Qt::Key_2), 1);
    addPageAction(tr("Servers && Pools"), QKeySequence(Qt::CTRL | Qt::Key_3), 2);
    addPageAction(tr("Rules"), QKeySequence(Qt::CTRL | Qt::Key_4), 3);
    addPageAction(tr("Settings"), QKeySequence(Qt::CTRL | Qt::Key_5), 4);
    addPageAction(tr("System Log"), QKeySequence(Qt::CTRL | Qt::Key_6), 5);

    QAction* findAction = new QAction(tr("Find in Query Log"), this);
    findAction->setShortcut(QKeySequence::Find);
    connect(findAction, &QAction::triggered, this, [this] {
        sidebar_->setCurrentRow(1);
        queryLogPage_->focusSearch();
    });
    addAction(findAction);

    sidebar_->setCurrentRow(0);
}

void MainWindow::wirePages() {
    // Overview
    connect(overviewPage_, &OverviewPage::startStopRequested, this, &MainWindow::onToggleEngine);
    connect(overviewPage_, &OverviewPage::saveRequested, this, &MainWindow::onSaveConfig);
    connect(overviewPage_, &OverviewPage::flushCacheRequested, this, &MainWindow::onFlushCache);
    connect(overviewPage_, &OverviewPage::testUpstreamRequested, this, [this](int row) {
        sidebar_->setCurrentRow(2);
        serversPoolsPage_->selectUpstreamRow(row);
        testSelectedUpstream();
    });

    // Query Log
    connect(queryLogPage_, &QueryLogPage::searchChanged, queryFilterProxy_, &QueryLogFilterProxyModel::setDomainFilter);
    connect(queryLogPage_, &QueryLogPage::statusFilterChanged, queryFilterProxy_, &QueryLogFilterProxyModel::setStatusFilter);
    connect(queryLogPage_, &QueryLogPage::inspectRequested, this, [this](const ResolveEvent& event) {
        QueryDetailsDialog dlg(event, this);
        dlg.exec();
    });
    connect(queryLogPage_, &QueryLogPage::blockDomainRequested, this, &MainWindow::blockDomainFromLog);
    connect(queryLogPage_, &QueryLogPage::bypassDomainRequested, this, &MainWindow::bypassDomainFromLog);
    connect(queryLogPage_, &QueryLogPage::clearRequested, this, &MainWindow::onClearLog);

    // Servers & Pools
    connect(serversPoolsPage_, &ServersPoolsPage::addUpstreamRequested, this, &MainWindow::addUpstream);
    connect(serversPoolsPage_, &ServersPoolsPage::editUpstreamRequested, this, &MainWindow::editUpstream);
    connect(serversPoolsPage_, &ServersPoolsPage::deleteUpstreamRequested, this, &MainWindow::deleteUpstream);
    connect(serversPoolsPage_, &ServersPoolsPage::testUpstreamRequested, this, &MainWindow::testSelectedUpstream);
    connect(serversPoolsPage_, &ServersPoolsPage::addPoolRequested, this, &MainWindow::addPool);
    connect(serversPoolsPage_, &ServersPoolsPage::editPoolRequested, this, &MainWindow::editPool);
    connect(serversPoolsPage_, &ServersPoolsPage::deletePoolRequested, this, &MainWindow::deletePool);
    connect(serversPoolsPage_, &ServersPoolsPage::openPublicResolversRequested, this, &MainWindow::openPublicResolversBrowser);
    connect(serversPoolsPage_, &ServersPoolsPage::defaultTargetChanged, this, [this](const QString& name) {
        session_.mutateDraft([&name](Config& c) {
            c.defaultTarget = name.toStdString();
            c.defaultUpstream = c.defaultTarget;
        });
    });

    // Rules
    connect(rulesPage_, &RulesPage::addRequested, this, &MainWindow::addRule);
    connect(rulesPage_, &RulesPage::editRequested, this, &MainWindow::editRule);
    connect(rulesPage_, &RulesPage::deleteRequested, this, &MainWindow::deleteRule);
    connect(rulesPage_, &RulesPage::moveRequested, this, &MainWindow::moveRule);

    // Settings
    connect(settingsPage_, &SettingsPage::saveRequested, this, &MainWindow::onSaveConfig);
    connect(settingsPage_, &SettingsPage::reloadRequested, this, &MainWindow::onReloadConfig);
    connect(settingsPage_, &SettingsPage::installServiceRequested, this, &MainWindow::installWindowsService);
    connect(settingsPage_, &SettingsPage::uninstallServiceRequested, this, &MainWindow::uninstallWindowsService);
    connect(settingsPage_, &SettingsPage::openDataFolderRequested, this, &MainWindow::onOpenLogFolder);

    // System Log
    connect(systemLogPage_, &SystemLogPage::openDataFolderRequested, this, &MainWindow::onOpenLogFolder);
}
void MainWindow::setupTrayIcon() {
    trayIcon_ = new QSystemTrayIcon(createStatusIcon(Qt::gray), this);
    trayIcon_->setToolTip(tr("9NS - Stopped"));

    auto* trayMenu = new QMenu(this);
    trayMenu->addAction(tr("Open Window"), this, &MainWindow::showNormal);
    trayMenu->addAction(tr("Toggle Engine"), this, &MainWindow::onToggleEngine);
    trayMenu->addAction(tr("Flush Cache"), this, &MainWindow::onFlushCache);
    trayMenu->addSeparator();
    trayMenu->addAction(tr("Exit"), this, &MainWindow::quitApp);

    trayIcon_->setContextMenu(trayMenu);
    connect(trayIcon_, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
    trayIcon_->show();
}

void MainWindow::onTrayActivated(int reason) {
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
        if (isVisible()) {
            hide();
        } else {
            showNormal();
            activateWindow();
        }
    }
}

void MainWindow::loadConfigFile() {
    QString error;
    if (!session_.reload(error)) {
        // The session keeps the failure armed; the banner explains it and every
        // write path is blocked until the file is repaired or replaced.
        rebuildErrorBanner();
        showError(tr("Error loading config: ") + error);
        return;
    }
    rebuildErrorBanner();
}

bool MainWindow::guardWrites() {
    if (session_.writesBlocked()) {
        showError(tr("The configuration file could not be loaded (%1), so changes are disabled.\n"
                     "Repair the file in the data folder or import a replacement configuration.")
                      .arg(session_.loadError()));
        return false;
    }
    return true;
}

bool MainWindow::confirmDiscardDraft(const QString& reason) {
    if (!session_.isDirty()) {
        return true;
    }
    const QMessageBox::StandardButton choice = QMessageBox::question(
        this, tr("Unsaved Changes"),
        tr("%1\n\nYou have unsaved configuration changes. Save them before continuing?").arg(reason),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);
    if (choice == QMessageBox::Cancel) {
        return false;
    }
    if (choice == QMessageBox::Save) {
        QString error;
        if (!session_.save(error)) {
            showError(tr("Could not save the configuration: %1").arg(error));
            return false;
        }
    }
    return true;
}

void MainWindow::applyRuntimeConfig(const Config& config) {
    runtimeConfig_ = config;
}

bool MainWindow::confirmReplacement(const QString& reason) {
    return QMessageBox::question(this, tr("Replace Configuration"),
                                 tr("%1\n\nReplace the current configuration?").arg(reason),
                                 QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes;
}

bool MainWindow::commitEditedUpstream(const UpstreamConfig& server, int row) {
    if (server.name.empty()) {
        showError(tr("Every upstream needs a name."));
        return false;
    }
    const std::string oldName = draft().upstreams[static_cast<size_t>(row)].name;
    const bool renamed = (oldName != server.name);
    if (renamed) {
        for (const auto& other : draft().upstreams) {
            if (other.name == server.name) {
                showError(tr("An upstream named '%1' already exists.").arg(QString::fromStdString(server.name)));
                return false;
            }
        }
        for (const auto& pool : draft().pools) {
            if (pool.name == server.name) {
                showError(tr("A pool named '%1' already exists.").arg(QString::fromStdString(server.name)));
                return false;
            }
        }
    }

    // Validate the candidate before the draft is touched.
    Config candidate = draft();
    candidate.upstreams[static_cast<size_t>(row)] = server;
    if (renamed) {
        renameTargetReferences(candidate, oldName, server.name);
    }
    try {
        validateConfig(candidate);
    } catch (const std::exception& e) {
        showError(tr("The edited server is not usable: %1").arg(QString::fromUtf8(e.what())));
        return false;
    }

    session_.setDraft(std::move(candidate));
    return true;
}

bool MainWindow::commitEditedPool(const PoolConfig& pool, int row) {
    if (pool.name.empty()) {
        showError(tr("Every pool needs a name."));
        return false;
    }
    const std::string oldName = draft().pools[static_cast<size_t>(row)].name;
    const bool renamed = (oldName != pool.name);
    if (renamed) {
        for (const auto& other : draft().pools) {
            if (other.name == pool.name) {
                showError(tr("A pool named '%1' already exists.").arg(QString::fromStdString(pool.name)));
                return false;
            }
        }
        for (const auto& upstream : draft().upstreams) {
            if (upstream.name == pool.name) {
                showError(tr("An upstream named '%1' already exists.").arg(QString::fromStdString(pool.name)));
                return false;
            }
        }
    }

    Config candidate = draft();
    candidate.pools[static_cast<size_t>(row)] = pool;
    if (renamed) {
        renameTargetReferences(candidate, oldName, pool.name);
    }
    try {
        validateConfig(candidate);
    } catch (const std::exception& e) {
        showError(tr("The edited pool is not usable: %1").arg(QString::fromUtf8(e.what())));
        return false;
    }

    session_.setDraft(std::move(candidate));
    return true;
}

void MainWindow::rebuildErrorBanner() {
    if (!errorBanner_) {
        return;
    }
    const bool failed = session_.state() == ConfigSession::State::Failed;
    errorBanner_->setVisible(failed);
    if (!failed) {
        return;
    }
    errorBannerLabel_->setText(
        tr("<b>Configuration could not be loaded:</b> %1<br>"
           "Changes, saving and the setup wizard are disabled until this is resolved.")
            .arg(session_.loadError().toHtmlEscaped()));
}

void MainWindow::populate() {
    settingsPage_->setValues(draft());
    refreshUpstreams();
    refreshPools();
    refreshDefaultTargetCombo();
    refreshRules();
}

void MainWindow::refreshUpstreams() {
    // Refresh rebuilds rows and clears their Testing state. Invalidate all
    // pending results, including a deleted/re-added server with the same name.
    pingRequests_.clear();
    if (resolverJobs_) {
        resolverJobs_->cancelAll();
    }
    serversPoolsPage_->setUpstreams(draft().upstreams);
    overviewPage_->setUpstreamCount(static_cast<int>(draft().upstreams.size()));
    for (int i = 0; i < static_cast<int>(draft().upstreams.size()); ++i) {
        const auto& up = draft().upstreams[static_cast<size_t>(i)];
        overviewPage_->setUpstreamRow(i, QString::fromStdString(up.name),
                                      QString::fromStdString(up.type),
                                      QString::fromStdString(up.address));
    }
    overviewPage_->clearLatency();
}

void MainWindow::refreshPools() {
    serversPoolsPage_->setPools(draft().pools);
}

void MainWindow::refreshDefaultTargetCombo() {
    QList<QPair<QString, QString>> targets;
    for (const auto& p : draft().pools) {
        targets.append({QStringLiteral("[Pool] ") + QString::fromStdString(p.name),
                        QString::fromStdString(p.name)});
    }
    for (const auto& u : draft().upstreams) {
        targets.append({QStringLiteral("[Server] ") + QString::fromStdString(u.name),
                        QString::fromStdString(u.name)});
    }
    const std::string cur = !draft().defaultTarget.empty() ? draft().defaultTarget : draft().defaultUpstream;
    serversPoolsPage_->setDefaultTargets(targets, cur);
}

void MainWindow::refreshRules() {
    rulesPage_->setRules(draft().rules);
}

Config MainWindow::settingsFromUi() const {
    Config cfg = draft();
    settingsPage_->applyTo(cfg);
    cfg.defaultTarget = serversPoolsPage_->defaultTarget();
    cfg.defaultUpstream = cfg.defaultTarget;
    return cfg;
}

void MainWindow::onSaveConfig() {
    if (!guardWrites()) return;
    session_.setDraft(settingsFromUi());
    QString error;
    if (!session_.save(error)) {
        showError(tr("Error saving settings: %1").arg(error));
        return;
    }
    // Application-only side effects are reported separately; a failure here
    // must not be presented as "everything succeeded".
    QStringList sideEffects;
    QString sideEffectError;
    if (!setAutostartRegistry(session_.draft().autostart, sideEffectError)) {
        sideEffects << tr("autostart: %1").arg(sideEffectError);
    }
    if (!openLog()) {
        sideEffects << tr("log file: %1").arg(logError_);
    }
    if (sideEffects.isEmpty()) {
        showStatus(tr("Settings saved successfully."));
    } else {
        // A side-effect failure is actionable, so it stays a deliberate dialog.
        QMessageBox::warning(this, tr("Saved with problems"),
                             tr("The configuration was saved, but some actions failed:\n%1")
                                 .arg(sideEffects.join(QStringLiteral("\n"))));
    }
}

void MainWindow::onReloadConfig() {
    if (!confirmDiscardDraft(tr("Reloading discards your unsaved changes."))) {
        return;
    }
    QString error;
    if (!session_.reload(error)) {
        rebuildErrorBanner();
        showError(tr("Could not reload the configuration: %1").arg(error));
        return;
    }
    rebuildErrorBanner();
    populate();
    updateState();
}

void MainWindow::onFlushCache() {
    if (engine_.resolver()) {
        engine_.resolver()->cache().flush();
        logger_.log(Logger::Level::Info, "DNS cache flushed by user");
        showStatus(tr("The reply cache has been cleared."));
    }
}

void MainWindow::onClearLog() {
    queryLogModel_->clear();
}

void MainWindow::onToggleEngine() {
    if (engine_.running()) {
        // Stopping is always available, even when the draft is invalid.
        engine_.stop();
        updateState();
        return;
    }
    if (!guardWrites()) return;
    Config candidate = settingsFromUi();
    try {
        validateConfig(candidate);
    } catch (const std::exception& e) {
        showError(tr("Cannot start engine: %1").arg(QString::fromUtf8(e.what())));
        return;
    }
    QString error;
    session_.setDraft(candidate);
    if (!session_.save(error)) {
        showError(tr("Cannot start engine: the configuration was not saved (%1)").arg(error));
        return;
    }
    try {
        engine_.start(candidate);
        applyRuntimeConfig(candidate);
        if (engine_.resolver()) {
            engine_.resolver()->setEventSink([this](const ResolveEvent& ev) {
                emit eventReceived(ev);
            });
        }
    } catch (const std::exception& e) {
        showError(tr("Cannot start engine: %1").arg(QString::fromUtf8(e.what())));
    }
    updateState();
}

void MainWindow::updateState() {
    const bool running = engine_.running();

    if (running) {
        if (toggleEngineBtn_) {
            toggleEngineBtn_->setText(tr("Stop Engine"));
            toggleEngineBtn_->setIcon(QIcon(QStringLiteral(":/icons/stop.svg")));
            toggleEngineBtn_->setStyleSheet(QStringLiteral(
                "QPushButton {"
                "  background-color: #FEF2F2;"
                "  color: #991B1B;"
                "  border: 1px solid #FECACA;"
                "  border-radius: 6px;"
                "  padding: 6px 14px;"
                "  font-weight: bold;"
                "}"
                "QPushButton:hover {"
                "  background-color: #FEE2E2;"
                "}"
            ));
        }

        if (headerStatusBadge_) {
            if (engine_.systemDnsActive()) {
                headerStatusBadge_->setText(tr("● Active — Port %1 | System DNS").arg(engine_.port()));
                headerStatusBadge_->setStyleSheet(QStringLiteral(
                    "background-color: #ECFDF5; color: #065F46; border: 1px solid #A7F3D0; border-radius: 12px; padding: 4px 12px; font-weight: bold; font-size: 12px;"
                ));
            } else if (runtimeConfig_.systemDns) {
                headerStatusBadge_->setText(tr("● Active — Port %1 | Manual DNS").arg(engine_.port()));
                headerStatusBadge_->setStyleSheet(QStringLiteral(
                    "background-color: #FFFBEB; color: #92400E; border: 1px solid #FDE68A; border-radius: 12px; padding: 4px 12px; font-weight: bold; font-size: 12px;"
                ));
            } else {
                headerStatusBadge_->setText(tr("● Active — Port %1").arg(engine_.port()));
                headerStatusBadge_->setStyleSheet(QStringLiteral(
                    "background-color: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; border-radius: 12px; padding: 4px 12px; font-weight: bold; font-size: 12px;"
                ));
            }
        }

        QString statusText = tr("<font color='green'>● Running</font> on port %1").arg(engine_.port());
        if (engine_.systemDnsActive()) {
            statusText += tr(" | <b>System DNS Active</b>");
            // Leak prevention is applied together with the system DNS redirection,
            // so it is only claimed when that redirection is actually active.
            if (runtimeConfig_.preventDnsLeaks) statusText += tr(" | <b>Leak Protection On</b>");
        } else if (runtimeConfig_.systemDns) {
            statusText += tr(" | <font color='#e67e22'><b>System DNS Inactive (Run as Administrator)</b></font>");
        }
        if (engine_.forwardProxyEnabled()) {
            const QString forwardStatus = engine_.forwardProxyRunning()
                ? tr("Forward proxy: loopback port %1").arg(engine_.forwardProxyPort())
                : tr("Forward proxy: failed (see System Log)");
            statusText += QStringLiteral(" | ") + forwardStatus;
            if (headerStatusBadge_) headerStatusBadge_->setText(headerStatusBadge_->text() + QStringLiteral(" | ") + forwardStatus);
        }
        if (overviewPage_) {
            overviewPage_->setProtectionSummary(statusText);
        }
        if (trayIcon_) {
            trayIcon_->setIcon(createStatusIcon(QColor(34, 139, 34)));
            trayIcon_->setToolTip(tr("9NS - Running (Port %1)").arg(engine_.port()));
        }
    } else {
        if (toggleEngineBtn_) {
            toggleEngineBtn_->setText(tr("Start Engine"));
            toggleEngineBtn_->setIcon(QIcon(QStringLiteral(":/icons/start.svg")));
            toggleEngineBtn_->setStyleSheet(QStringLiteral(
                "QPushButton {"
                "  background-color: #0D9488;"
                "  color: #FFFFFF;"
                "  border: none;"
                "  border-radius: 6px;"
                "  padding: 6px 14px;"
                "  font-weight: bold;"
                "}"
                "QPushButton:hover {"
                "  background-color: #0F766E;"
                "}"
            ));
        }

        if (headerStatusBadge_) {
            headerStatusBadge_->setText(tr("○ Protection Stopped"));
            headerStatusBadge_->setStyleSheet(QStringLiteral(
                "background-color: #F1F5F9; color: #64748B; border: 1px solid #E2E8F0; border-radius: 12px; padding: 4px 12px; font-weight: bold; font-size: 12px;"
            ));
        }

        if (overviewPage_) {
            overviewPage_->setProtectionSummary(tr("<font color='gray'>○ Protection Stopped</font>"));
        }
        if (trayIcon_) {
            trayIcon_->setIcon(createStatusIcon(Qt::gray));
            trayIcon_->setToolTip(tr("9NS - Stopped"));
        }
        // Running-only metrics must not survive a stop and look like live data.
        totalQueries_ = 0;
        blockedQueries_ = 0;
        lastSecondQueries_ = 0;
        overviewPage_->setMetrics(0, 0, 0, 0);
    }
}

void MainWindow::onEventHandled(const ResolveEvent& ev) {
    queryLogModel_->addEvent(ev);
    totalQueries_++;
    if (ev.action == "Blocked") {
        blockedQueries_++;
    }
}

void MainWindow::updateDashboardMetrics() {
    double hitRate = -1.0;
    if (engine_.resolver()) {
        const uint64_t hits = engine_.resolver()->cache().hits();
        const uint64_t misses = engine_.resolver()->cache().misses();
        const uint64_t total = hits + misses;
        hitRate = (total > 0) ? (static_cast<double>(hits) / total * 100.0) : 0.0;
    }
    const uint64_t qps = totalQueries_ >= lastSecondQueries_ ? (totalQueries_ - lastSecondQueries_) : 0;
    lastSecondQueries_ = totalQueries_;
    overviewPage_->setMetrics(totalQueries_, blockedQueries_, static_cast<double>(qps),
                              hitRate < 0 ? 0.0 : hitRate);
}

void MainWindow::addUpstream() {
    if (!guardWrites()) return;
    UpstreamConfig server;
    ServerDialog dlg(server, this);
    if (dlg.exec() == QDialog::Accepted) {
        if (server.name.empty()) {
            showError(tr("Every upstream needs a name."));
            return;
        }
        for (const auto& other : draft().upstreams) {
            if (other.name == server.name) {
                showError(tr("An upstream named '%1' already exists.").arg(QString::fromStdString(server.name)));
                return;
            }
        }
        for (const auto& pool : draft().pools) {
            if (pool.name == server.name) {
                showError(tr("A pool named '%1' already exists.").arg(QString::fromStdString(server.name)));
                return;
            }
        }
        Config candidate = draft();
        candidate.upstreams.push_back(server);
        try {
            validateConfig(candidate);
        } catch (const std::exception& e) {
            showError(tr("The new server is not usable: %1").arg(QString::fromUtf8(e.what())));
            return;
        }
        session_.setDraft(std::move(candidate));
        refreshUpstreams();
        refreshDefaultTargetCombo();
    }
}

void MainWindow::editUpstream() {
    if (!guardWrites()) return;
    int row = serversPoolsPage_->selectedUpstreamRow();
    if (row < 0 || row >= static_cast<int>(draft().upstreams.size())) return;
    UpstreamConfig server = draft().upstreams[static_cast<size_t>(row)];
    ServerDialog dlg(server, this);
    if (dlg.exec() == QDialog::Accepted) {
        commitEditedUpstream(server, row);
        refreshUpstreams();
        refreshDefaultTargetCombo();
        refreshPools();
        refreshRules();
    }
}

void MainWindow::deleteUpstream() {
    if (!guardWrites()) return;
    int row = serversPoolsPage_->selectedUpstreamRow();
    if (row < 0 || row >= static_cast<int>(draft().upstreams.size())) return;
    if (draft().upstreams.size() <= 1) {
        showError(tr("At least one upstream server is required."));
        return;
    }
    const std::string name = draft().upstreams[static_cast<size_t>(row)].name;
    // Never silently retarget: identify the dependents and let the user decide.
    QStringList dependents;
    if (draft().defaultTarget == name) dependents << tr("the default target");
    for (const auto& p : draft().pools) {
        for (const auto& s : p.servers) {
            if (s == name) dependents << tr("pool '%1'").arg(QString::fromStdString(p.name));
        }
    }
    for (const auto& r : draft().rules) {
        const std::string target = !r.target.empty() ? r.target : r.upstream;
        if (target == name) dependents << tr("rule '%1'").arg(QString::fromStdString(r.name));
    }
    if (!dependents.isEmpty()) {
        showError(tr("Cannot delete upstream '%1' because it is used by %2.")
                      .arg(QString::fromStdString(name), dependents.join(QStringLiteral(", "))));
        return;
    }
    session_.mutateDraft([row](Config& c) { c.upstreams.erase(c.upstreams.begin() + row); });
    refreshUpstreams();
    refreshDefaultTargetCombo();
}

void MainWindow::testSelectedUpstream() {
    int row = serversPoolsPage_->selectedUpstreamRow();
    if (row < 0 || row >= static_cast<int>(draft().upstreams.size())) return;
    const UpstreamConfig up = draft().upstreams[static_cast<size_t>(row)];
    serversPoolsPage_->setUpstreamStatus(row, tr("Testing…"), false);
    overviewPage_->setLatency(row, OverviewPage::LatencyState::Testing, QString());
    resolverJobs_->startPing(up, pingRequests_.begin(up));
}

void MainWindow::addPool() {
    if (!guardWrites()) return;
    PoolConfig pool;
    PoolDialog dlg(pool, draft().upstreams, this);
    if (dlg.exec() == QDialog::Accepted) {
        session_.mutateDraft([&pool](Config& c) { c.pools.push_back(pool); });
        refreshPools();
        refreshDefaultTargetCombo();
    }
}

void MainWindow::editPool() {
    if (!guardWrites()) return;
    int row = serversPoolsPage_->selectedPoolRow();
    if (row < 0 || row >= static_cast<int>(draft().pools.size())) return;
    PoolConfig pool = draft().pools[static_cast<size_t>(row)];
    PoolDialog dlg(pool, draft().upstreams, this);
    if (dlg.exec() == QDialog::Accepted) {
        commitEditedPool(pool, row);
        refreshPools();
        refreshDefaultTargetCombo();
        refreshRules();
    }
}

void MainWindow::deletePool() {
    if (!guardWrites()) return;
    int row = serversPoolsPage_->selectedPoolRow();
    if (row < 0 || row >= static_cast<int>(draft().pools.size())) return;
    const std::string name = draft().pools[static_cast<size_t>(row)].name;
    QStringList dependents;
    if (draft().defaultTarget == name) dependents << tr("the default target");
    for (const auto& r : draft().rules) {
        const std::string target = !r.target.empty() ? r.target : r.upstream;
        if (target == name) dependents << tr("rule '%1'").arg(QString::fromStdString(r.name));
    }
    if (!dependents.isEmpty()) {
        showError(tr("Cannot delete pool '%1' because it is used by %2.")
                      .arg(QString::fromStdString(name), dependents.join(QStringLiteral(", "))));
        return;
    }
    session_.mutateDraft([row](Config& c) { c.pools.erase(c.pools.begin() + row); });
    refreshPools();
    refreshDefaultTargetCombo();
}

void MainWindow::addRule() {
    if (!guardWrites()) return;
    RuleConfig rule;
    RuleDialog dlg(rule, draft().upstreams, draft().pools, SystemDns::listInterfaces(), this);
    if (dlg.exec() == QDialog::Accepted) {
        session_.mutateDraft([&rule](Config& c) { c.rules.push_back(rule); });
        refreshRules();
    }
}

void MainWindow::editRule() {
    if (!guardWrites()) return;
    int row = rulesPage_->selectedRow();
    if (row < 0 || row >= static_cast<int>(draft().rules.size())) return;
    RuleConfig rule = draft().rules[static_cast<size_t>(row)];
    RuleDialog dlg(rule, draft().upstreams, draft().pools, SystemDns::listInterfaces(), this);
    if (dlg.exec() == QDialog::Accepted) {
        session_.mutateDraft([&rule, row](Config& c) { c.rules[static_cast<size_t>(row)] = rule; });
        refreshRules();
    }
}

void MainWindow::deleteRule() {
    if (!guardWrites()) return;
    int row = rulesPage_->selectedRow();
    if (row < 0 || row >= static_cast<int>(draft().rules.size())) return;
    session_.mutateDraft([row](Config& c) { c.rules.erase(c.rules.begin() + row); });
    refreshRules();
}

void MainWindow::moveRule(int delta) {
    if (!guardWrites()) return;
    int row = rulesPage_->selectedRow();
    if (row < 0) return;
    int target = row + delta;
    if (target < 0 || target >= static_cast<int>(draft().rules.size())) return;
    session_.mutateDraft([row, target](Config& c) { std::swap(c.rules[row], c.rules[target]); });
    refreshRules();
    rulesPage_->selectRow(target);
}

void MainWindow::runFirstStartWizard() {
    if (!guardWrites()) return;
    if (!confirmReplacement(tr("The setup wizard replaces your current configuration."))) {
        return;
    }
    if (!confirmDiscardDraft(tr("The setup wizard replaces your current configuration."))) {
        return;
    }
    WizardDialog wizard(this);
    if (wizard.exec() != QDialog::Accepted) {
        return;
    }
    // The wizard produces a validated candidate; it never starts or stops the
    // engine by itself.
    Config candidate = wizard.resultConfig();
    try {
        validateConfig(candidate);
    } catch (const std::exception& e) {
        showError(tr("The wizard produced an invalid configuration: %1").arg(QString::fromUtf8(e.what())));
        return;
    }
    session_.setDraft(candidate);
    populate();
    QString error;
    if (!session_.save(error)) {
        showError(tr("Could not save the configuration: %1").arg(error));
        return;
    }
    // Save & Start is only offered when the engine is not already running; an
    // already-running engine is never stopped by the wizard.
    if (!engine_.running()) {
        const QMessageBox::StandardButton start = QMessageBox::question(
            this, tr("Start Engine"),
            tr("The configuration was saved. Start the engine now?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (start == QMessageBox::Yes) {
            onToggleEngine();
        }
    } else {
        QMessageBox::information(this, tr("Saved"),
                                 tr("The configuration was saved. It will be used the next time the engine starts."));
    }
}

void MainWindow::installWindowsService() {
    std::string err;
    if (service::installService(err)) {
        QMessageBox::information(this, tr("Service Installed"), tr("9NS background service installed successfully."));
    } else {
        showError(tr("Failed to install service: ") + QString::fromStdString(err));
    }
}

void MainWindow::uninstallWindowsService() {
    std::string err;
    if (service::uninstallService(err)) {
        QMessageBox::information(this, tr("Service Uninstalled"), tr("9NS background service removed."));
    } else {
        showError(tr("Failed to uninstall service: ") + QString::fromStdString(err));
    }
}

void MainWindow::appendLog(const QString& line) {
    systemLogPage_->appendLine(line);
}

bool MainWindow::openLog() {
    try {
        const std::filesystem::path path = resolveLogPath(configPath_.parent_path(), widen(draft().logFile));
        Logger::Level level = Logger::Level::Info;
        if (draft().logLevel == "error") level = Logger::Level::Error;
        if (draft().logLevel == "debug") level = Logger::Level::Debug;
        logger_.open(narrow(path.wstring()), level);
        return true;
    } catch (const std::exception& e) {
        logError_ = QString::fromUtf8(e.what());
        return false;
    }
}

void MainWindow::showError(const QString& message) {
    // Messages embed untrusted config text (load errors, names, paths); show
    // them literally instead of letting Qt interpret rich text.
    QMessageBox box(QMessageBox::Critical, tr("Error"), message, QMessageBox::Ok, this);
    box.setTextFormat(Qt::PlainText);
    box.exec();
}

// Information box that renders `message` literally: it may embed untrusted
// query-derived text (domains, paths) that must not become rich text.
void MainWindow::showPlainInfo(const QString& title, const QString& message) {
    QMessageBox box(QMessageBox::Information, title, message, QMessageBox::Ok, this);
    box.setTextFormat(Qt::PlainText);
    box.exec();
}

void MainWindow::showStatus(const QString& message) {
    // Non-modal feedback: the user can keep working while the note is up.
    if (statusBar()) {
        statusBar()->showMessage(message, 5000);
    }
}

void MainWindow::blockDomainFromLog(const QString& domain) {
    if (!guardWrites()) return;
    RuleConfig rule;
    rule.name = "Block " + domain.toStdString();
    rule.hostnames = {"*." + domain.toStdString(), domain.toStdString()};
    rule.action = "block";
    rule.blockMode = "nxdomain";
    // Query-derived rules join the same draft workflow as manual edits; nothing
    // is written to disk until the user saves.
    session_.mutateDraft([&rule](Config& c) { c.rules.push_back(rule); });
    refreshRules();
    showPlainInfo(tr("Rule Added"),
                  tr("Rule created to block '%1' (mode: NXDOMAIN). It is part of your "
                     "unsaved changes; use Save to persist it.").arg(domain));
}

void MainWindow::bypassDomainFromLog(const QString& domain) {
    if (!guardWrites()) return;
    RuleConfig rule;
    rule.name = "Bypass " + domain.toStdString();
    rule.hostnames = {"*." + domain.toStdString(), domain.toStdString()};
    rule.action = "bypass";
    session_.mutateDraft([&rule](Config& c) { c.rules.push_back(rule); });
    refreshRules();
    showPlainInfo(tr("Rule Added"),
                  tr("Rule created to bypass '%1' through system default adapter. It is "
                     "part of your unsaved changes; use Save to persist it.").arg(domain));
}

void MainWindow::openPublicResolversBrowser() {
    if (!guardWrites()) return;
    PublicResolversDialog dlg(draft(), this);
    connect(&dlg, &PublicResolversDialog::configurationModified, this, [this] {
        // The dialog edits the draft through the reference it was given; only
        // the dirty flag and the views need updating. Persistence stays an
        // explicit Save action.
        session_.markDirty();
        refreshUpstreams();
        refreshPools();
        refreshDefaultTargetCombo();
    });
    dlg.exec();
}

void MainWindow::onImportConfig() {
    if (!confirmReplacement(tr("Importing a configuration replaces your current one."))) {
        return;
    }
    if (!confirmDiscardDraft(tr("Importing a configuration replaces your current one."))) {
        return;
    }
    QString file = QFileDialog::getOpenFileName(this, tr("Import Configuration"),
                                                QString::fromStdString(configPath_.parent_path().string()),
                                                tr("JSON Configuration (*.json)"));
    if (file.isEmpty()) return;

    // Explicit replacement: the session validates the candidate, backs up the
    // rejected original and aborts cleanly if anything fails.
    QString error;
    if (!session_.replaceFromFile(std::filesystem::path(file.toStdWString()), error)) {
        rebuildErrorBanner();
        showError(tr("Failed to import configuration: %1").arg(error));
        return;
    }
    rebuildErrorBanner();
    populate();
    updateState();
    QMessageBox::information(this, tr("Configuration Imported"), tr("Configuration successfully loaded."));
}

void MainWindow::onExportConfig() {
    QString file = QFileDialog::getSaveFileName(this, tr("Export Configuration"),
                                                QString::fromStdString((configPath_.parent_path() / "config.backup.json").string()),
                                                tr("JSON Configuration (*.json)"));
    if (file.isEmpty()) return;

    try {
        // Export what the user sees: the current draft plus any unsaved control edits.
        saveConfig(std::filesystem::path(file.toStdWString()), settingsFromUi());
        showPlainInfo(tr("Configuration Exported"), tr("Configuration saved to:\n%1").arg(file));
    } catch (const std::exception& e) {
        showError(tr("Failed to export configuration: ") + QString::fromStdString(e.what()));
    }
}

void MainWindow::onOpenLogFolder() {
    const std::filesystem::path folder = configPath_.parent_path();
    ShellExecuteW(nullptr, L"open", folder.wstring().c_str(), nullptr, nullptr, SW_SHOW);
}

void MainWindow::onAbout() {
    QMessageBox msg(this);
    msg.setWindowTitle(tr("About 9NS"));
    msg.setIconPixmap(QIcon(QStringLiteral(":/icons/9ns-mark.svg")).pixmap(64, 64));
    msg.setText(tr("<h3>9NS v1.1.0</h3>"
                   "<p>Modern Encrypted System DNS Client & Proxy.</p>"
                   "<ul>"
                   "<li><b>Protocols:</b> Plain DNS, DNS over HTTPS (DoH / HTTP/2), DNS over TLS (DoT), DNS over QUIC (DoQ), Oblivious DoH (ODoH), DNSCrypt v2, Anonymized Relays.</li>"
                   "<li><b>Routing:</b> Flexible wildcard rules, hosts files, custom actions (Process, Block, Bypass, Local IP).</li>"
                   "<li><b>Pools:</b> Failover, Round Robin, Fastest (Lowest Latency), Random strategies.</li>"
                   "<li><b>Security:</b> Full DNSSEC AD validation & signature checks, DNS Leak Protection (multi-homed resolution suppression), System DNS dual-stack redirection.</li>"
                   "<li><b>Public Resolvers:</b> Live repository browser supporting 1,000+ public resolvers and relays.</li>"
                   "<li><b>Service:</b> Windows background service support.</li>"
                   "</ul>"
                   "<p><b>Donate (BTC):</b> <a href=\"bitcoin:%1\">%1</a></p>")
                    .arg(QString::fromLatin1(Donate::kBtcAddress)));
    msg.setTextInteractionFlags(Qt::TextBrowserInteraction);
    msg.exec();
}
