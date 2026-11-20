#pragma once

#include <string>
#include <vector>
#include <functional>

#include <QDialog>
#include <QString>
#include <QThreadPool>

#include "core/Config.h"
#include "ui/ResolverJobs.h"
#include "web/PublicResolversLoader.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QTableWidget;

// Interactive public DNS resolver & relay browser.
// Loads and parses DNSCrypt & DoH public resolvers and anonymized relays from GitHub,
// allowing search, protocol filtering, latency ping benchmarking, and one-click import.
class PublicResolversDialog : public QDialog {
    Q_OBJECT

public:
    struct Services {
        std::function<std::vector<PublicDnsItem>(bool, std::string&)> load;
        ResolverJobs::Probe probe;
        std::function<void(const QString&, const QString&, bool warning)> notice;
        std::function<bool(QString&)> poolName;
    };

    PublicResolversDialog(Config& config, QWidget* parent = nullptr);
    // Explicit loader and probe keep this constructor independent of production I/O.
    PublicResolversDialog(Config& config, Services services, QWidget* parent = nullptr);
    ~PublicResolversDialog() override;

    // Cancels outstanding work on every close path so late results cannot
    // reach a half-destroyed dialog. Consumers drop without waiting on I/O;
    // in-flight probes finish within their transport timeouts and drain.
    void done(int result) override;

signals:
    void configurationModified();

private slots:
    void onFilterChanged();
    void onRefreshFromWeb();
    void onPingSelected();
    void onAddSelectedToServers();
    void onCreatePoolFromSelected();
    void onCopyStamp();
    void onSelectionChanged();
    void onPingFinished(const PingResult& result);

private:
    void buildUi();
    void loadData(bool forceRefresh);
    void onLoadFinished(quint64 generation, std::vector<PublicDnsItem> items, const std::string& error);
    void populateTable();
    std::vector<int> selectedItemIndices() const;
    // Resolves a ping result to a visible row by stable item identity. Returns
    // -1 when the item was refreshed away or is not shown in the current filter.
    int rowForItem(const QString& stamp, const QString& name) const;

    Config& config_;
    Services services_;
    std::vector<PublicDnsItem> allItems_;
    std::vector<int> filteredIndices_;

    // Background work: list downloads run on a small local pool that drains in
    // the destructor, pings go through the ResolverJobs dispatcher. Both
    // deliver through queued connections bound to this dialog, so a closed
    // dialog drops the delivery instead of touching dead widgets.
    QThreadPool loadPool_;
    ResolverJobs* jobs_ = nullptr;
    quint64 loadGeneration_ = 0;
    quint64 pingGeneration_ = 0;
    int progressTotal_ = 0;
    int progressDone_ = 0;

    // Filter controls
    QLineEdit* searchEdit_ = nullptr;
    QComboBox* protocolCombo_ = nullptr;
    QCheckBox* dnssecCheck_ = nullptr;
    QCheckBox* noLogCheck_ = nullptr;
    QCheckBox* noFilterCheck_ = nullptr;

    // Table & Status
    QTableWidget* table_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QProgressBar* progressBar_ = nullptr;

    // Buttons
    QPushButton* refreshBtn_ = nullptr;
    QPushButton* pingBtn_ = nullptr;
    QPushButton* addServersBtn_ = nullptr;
    QPushButton* createPoolBtn_ = nullptr;
    QPushButton* copyStampBtn_ = nullptr;
};
