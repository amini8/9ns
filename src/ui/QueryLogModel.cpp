#include "ui/QueryLogModel.h"

#include <QBrush>
#include <QColor>
#include <QThread>

namespace {

// Self-contained display names mirroring dns::typeName / dns::rcodeName /
// dnsSecStatusToString: the query-log tests link this translation unit without
// the wire-format and DNSSEC .cpp files that own the canonical helpers.
std::string formatTypeName(uint16_t type) {
    switch (type) {
        case dns::kTypeA: return "A";
        case dns::kTypeNs: return "NS";
        case dns::kTypeCname: return "CNAME";
        case dns::kTypeSoa: return "SOA";
        case dns::kTypePtr: return "PTR";
        case dns::kTypeMx: return "MX";
        case dns::kTypeTxt: return "TXT";
        case dns::kTypeAaaa: return "AAAA";
        case dns::kTypeSrv: return "SRV";
        case dns::kTypeOpt: return "OPT";
        case dns::kTypeDs: return "DS";
        case dns::kTypeRrsig: return "RRSIG";
        case dns::kTypeNsec: return "NSEC";
        case dns::kTypeDnskey: return "DNSKEY";
        case dns::kTypeNsec3: return "NSEC3";
        case dns::kTypeAny: return "ANY";
        default: return std::to_string(type);
    }
}

std::string formatRcodeName(uint8_t rcode) {
    switch (rcode) {
        case dns::kRcodeNoError: return "NOERROR";
        case dns::kRcodeFormErr: return "FORMERR";
        case dns::kRcodeServFail: return "SERVFAIL";
        case dns::kRcodeNxDomain: return "NXDOMAIN";
        case dns::kRcodeNotImp: return "NOTIMP";
        case dns::kRcodeRefused: return "REFUSED";
        default: return "RCODE(" + std::to_string(rcode) + ")";
    }
}

std::string formatDnsSecName(DnsSecStatus status) {
    switch (status) {
        case DnsSecStatus::Secure: return "Secure";
        case DnsSecStatus::Insecure: return "Insecure";
        case DnsSecStatus::Bogus: return "Bogus";
        case DnsSecStatus::Indeterminate: return "Indeterminate";
        default: return "Unknown";
    }
}

}  // namespace

QueryLogModel::QueryLogModel(QObject* parent, size_t maxEntries)
    : QAbstractTableModel(parent), maxEntries_(maxEntries) {}

int QueryLogModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }
    return static_cast<int>(events_.size());
}

int QueryLogModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }
    return ColCount;
}

QVariant QueryLogModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) {
        return {};
    }
    if (index.row() < 0 || static_cast<size_t>(index.row()) >= events_.size()) {
        return {};
    }

    const Entry& entry = events_[index.row()];
    const ResolveEvent& ev = entry.event;

    if (role == SortTimestamp) {
        return entry.receivedAt.toMSecsSinceEpoch();
    }
    if (role == SortLatency) {
        return static_cast<qlonglong>(ev.latencyMs);
    }

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case ColTime:
                return entry.receivedAt.toString(QStringLiteral("HH:mm:ss"));
            case ColClient:
                return QString::fromStdString(ev.clientIp);
            case ColDomain:
                return QString::fromStdString(ev.queryName.empty() ? "." : ev.queryName);
            case ColType:
                return QString::fromStdString(formatTypeName(ev.queryType));
            case ColTarget:
                return QString::fromStdString(!ev.usedServer.empty() ? ev.usedServer : ev.target);
            case ColAction:
                return QString::fromStdString(ev.action);
            case ColRcode:
                return QString::fromStdString(formatRcodeName(ev.rcode));
            case ColLatency:
                return QString::number(ev.latencyMs) + QStringLiteral(" ms");
            case ColDnsSec:
                return QString::fromStdString(formatDnsSecName(ev.dnssec));
            default:
                return {};
        }
    }

    if (role == Qt::ForegroundRole) {
        if (index.column() == ColAction) {
            if (ev.action == "Blocked") return QBrush(QColor(220, 20, 60));
            if (ev.action == "Cached") return QBrush(QColor(30, 144, 255));
            if (ev.action == "Resolved") return QBrush(QColor(34, 139, 34));
            if (ev.action == "Error" || ev.action == "Bogus") return QBrush(QColor(255, 69, 0));
        }
        if (index.column() == ColDnsSec) {
            if (ev.dnssec == DnsSecStatus::Secure) return QBrush(QColor(34, 139, 34));
            if (ev.dnssec == DnsSecStatus::Bogus) return QBrush(QColor(220, 20, 60));
            if (ev.dnssec == DnsSecStatus::Insecure) return QBrush(QColor(128, 128, 128));
        }
    }

    return {};
}

QVariant QueryLogModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        switch (section) {
            case ColTime: return tr("Time");
            case ColClient: return tr("Client IP");
            case ColDomain: return tr("Domain");
            case ColType: return tr("Type");
            case ColTarget: return tr("Target / Server");
            case ColAction: return tr("Action");
            case ColRcode: return tr("Result");
            case ColLatency: return tr("Latency");
            case ColDnsSec: return tr("DNSSEC");
            default: return {};
        }
    }
    return {};
}

void QueryLogModel::addEvent(const ResolveEvent& event) {
    Q_ASSERT(QThread::currentThread() == thread());

    // A zero cap means "keep no history": never expose rows we must drop again.
    if (maxEntries_ == 0) {
        return;
    }

    // Evict before inserting so the bounded size holds at every observable
    // point; both changes carry their own row notifications.
    if (events_.size() >= maxEntries_) {
        const int lastRow = static_cast<int>(events_.size()) - 1;
        beginRemoveRows(QModelIndex(), lastRow, lastRow);
        events_.pop_back();
        endRemoveRows();
    }

    beginInsertRows(QModelIndex(), 0, 0);
    events_.push_front(Entry{event, QDateTime::currentDateTime()});
    endInsertRows();
}

void QueryLogModel::clear() {
    Q_ASSERT(QThread::currentThread() == thread());

    beginResetModel();
    events_.clear();
    endResetModel();
}

std::optional<ResolveEvent> QueryLogModel::snapshot(int row) const {
    if (row < 0 || static_cast<size_t>(row) >= events_.size()) {
        return std::nullopt;
    }
    return events_[row].event;
}
