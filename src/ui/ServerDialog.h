#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/Config.h"

// Editable fields of ServerDialog, decoupled from widgets so Test and Save
// share one mapping and tests can exercise it without a GUI.
struct ServerFields {
    std::string name;
    std::string type;
    std::string address;
    uint16_t port = 0;
    std::vector<std::string> bootstrapIps;
    std::string sni;
    std::string proxy;
    bool tlsVerify = true;
};

// Inline so the offline dialog tests can use the mapping without linking the
// dialog translation unit (and with it Qt Widgets).
inline ServerFields serverFieldsFromUpstream(const UpstreamConfig& upstream) {
    ServerFields fields;
    fields.name = upstream.name;
    fields.type = upstream.type;
    fields.address = upstream.address;
    fields.port = upstream.port;
    fields.bootstrapIps = upstream.bootstrapIps;
    fields.sni = upstream.sni;
    fields.proxy = upstream.proxy;
    fields.tlsVerify = upstream.tlsVerify;
    return fields;
}

// Overlays form fields onto a base config so fields the form does not expose
// (notably the sdns:// stamp) survive the round-trip.
inline UpstreamConfig upstreamFromServerFields(const UpstreamConfig& base, const ServerFields& fields) {
    UpstreamConfig out = base;
    out.name = fields.name;
    out.type = fields.type;
    out.address = fields.address;
    out.port = fields.port;
    out.bootstrapIps = fields.bootstrapIps;
    out.sni = fields.sni;
    out.proxy = fields.proxy;
    out.tlsVerify = fields.tlsVerify;
    return out;
}

// The dialog itself needs Qt Widgets. Offline tests link only Qt Test and
// include this header for the mapping above, so keep the widgets behind
// __has_include: the class is absent exactly where Widgets cannot be found.
#if __has_include(<QDialog>)

#include <QDialog>

#include "ui/ResolverJobs.h"

class QCheckBox;
class QComboBox;
class QFormLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

// Dialog to add or edit an upstream DNS server, with reachability and latency testing.
class ServerDialog : public QDialog {
    Q_OBJECT

public:
    explicit ServerDialog(UpstreamConfig& server, QWidget* parent = nullptr);
    ~ServerDialog() override = default;

    // Cancels outstanding probes on every close path (Save, Cancel, window X)
    // so late results cannot reach a half-destroyed dialog.
    void done(int result) override;

private slots:
    void onTypeChanged(const QString& type);
    void onTestClicked();
    void onSaveClicked();
    void onPingFinished(const PingResult& result);

private:
    void buildUi();
    ServerFields fieldsFromWidgets() const;

    UpstreamConfig& server_;

    // Reachability probes run off the GUI thread; results come back via
    // pingFinished() with a generation echo. Child of this dialog.
    ResolverJobs* jobs_ = nullptr;
    quint64 testGeneration_ = 0;
    bool testInFlight_ = false;

    QFormLayout* form_ = nullptr;
    QLineEdit* nameEdit_ = nullptr;
    QComboBox* typeCombo_ = nullptr;
    QLineEdit* addressEdit_ = nullptr;
    QSpinBox* portSpin_ = nullptr;
    QLineEdit* bootstrapEdit_ = nullptr;
    QLineEdit* sniEdit_ = nullptr;
    QLineEdit* proxyEdit_ = nullptr;
    QCheckBox* tlsVerifyCheck_ = nullptr;

    QPushButton* testButton_ = nullptr;
    QLabel* testResultLabel_ = nullptr;
};

#endif  // __has_include(<QDialog>)
