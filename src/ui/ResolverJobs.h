#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <map>
#include <string>
#include <vector>

#include <QObject>
#include <QString>
#include <QThreadPool>

#include "core/Config.h"

// Cancellation flag polled by a queued worker. Workers bail out before
// publishing a result once this is set. Safe to touch from any thread.
class CancelToken {
public:
    void cancel() { cancelled_.store(true, std::memory_order_release); }
    bool isCancelled() const { return cancelled_.load(std::memory_order_acquire); }

private:
    std::atomic<bool> cancelled_{false};
};

// One reachability test result routed back to the GUI thread. The full input
// snapshot distinguishes endpoint edits, not just a name/stamp or view row.
struct PingResult {
    QString name;
    QString stamp;
    UpstreamConfig config;
    quint64 generation = 0;
    bool ok = false;
    uint32_t rttMs = 0;
    QString error;
};

// GUI-thread request correlation, separate from widgets and network work.
// Each server has its own latest request. clear() invalidates every pending
// request without reusing generations, including deletion/re-add of a name.
class PingRequestTracker {
public:
    quint64 begin(const UpstreamConfig& config);
    bool accept(const PingResult& result, const std::vector<UpstreamConfig>& current);
    void clear() { pending_.clear(); }

private:
    struct Request {
        UpstreamConfig config;
        quint64 generation = 0;
    };
    quint64 nextGeneration_ = 0;
    std::map<std::string, Request> pending_;
};

// Application-owned GUI-thread dispatcher for background resolver work.
//
// Threading contract: startPing()/cancelAll() are called from the GUI thread.
// Workers run on a dedicated QThreadPool and only touch copied immutable input;
// they never access widgets, Engine or the mutable draft. Results are delivered
// through queued connections whose context object is this dispatcher, so a
// destroyed dispatcher drops the delivery instead of touching dead state. The
// destructor cancels and drains outstanding work before returning.
class ResolverJobs : public QObject {
    Q_OBJECT

public:
    // Reachability probe. Returns false and fills error on failure. The caller
    // supplies it so this dispatcher stays transport-agnostic and tests can
    // inject a fake to stay offline.
    using Probe = std::function<bool(const UpstreamConfig& config, uint32_t& rttMs, std::string& error)>;

    explicit ResolverJobs(Probe probe, QObject* parent = nullptr);
    ~ResolverJobs() override;

    ResolverJobs(const ResolverJobs&) = delete;
    ResolverJobs& operator=(const ResolverJobs&) = delete;

    // Queues a reachability test for a copied upstream config. The result is
    // delivered via pingFinished(). The caller supplies the generation the job
    // is issued under; stale results for older generations must be ignored.
    void startPing(UpstreamConfig config, quint64 generation);

    // Cancels queued and not-yet-started work. In-flight blocking network calls
    // are not interrupted; their late results are dropped by the cancellation
    // and generation guards.
    void cancelAll();

signals:
    void pingFinished(const PingResult& result);

private:
    friend class TestJobs;  // Offline tests inspect bounded token bookkeeping.
    QThreadPool pool_;
    std::vector<std::weak_ptr<CancelToken>> tokens_;
    Probe probe_;
};
