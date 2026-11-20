#include "ui/ResolverJobs.h"

#include <algorithm>
#include <utility>

#include <QMetaObject>
#include <QObject>
#include <QRunnable>

namespace {

bool sameUpstream(const UpstreamConfig& a, const UpstreamConfig& b) {
    return a.name == b.name && a.type == b.type && a.address == b.address &&
           a.stamp == b.stamp && a.port == b.port && a.bootstrapIps == b.bootstrapIps &&
           a.sni == b.sni && a.tlsVerify == b.tlsVerify && a.proxy == b.proxy;
}

// Immutable worker input. It owns its transport through the config copy and
// never references widgets, Engine or the mutable draft.
struct PingTask {
    UpstreamConfig config;
    std::shared_ptr<CancelToken> token;
    quint64 generation = 0;
    ResolverJobs::Probe probe;
};

// Runs one reachability test on a pool thread, then posts the result to the
// GUI thread. `receiver` is only used as the queued-call context object; the
// dispatcher's destructor drains the pool while the object is still alive, so
// the pointer stays valid for every invokeMethod call.
class PingRunnable : public QRunnable {
public:
    PingRunnable(std::shared_ptr<PingTask> task, QObject* receiver) : task_(std::move(task)), receiver_(receiver) {}

    void run() override {
        PingResult result;
        result.name = QString::fromStdString(task_->config.name);
        result.stamp = QString::fromStdString(task_->config.stamp);
        result.config = task_->config;
        result.generation = task_->generation;

        if (task_->token->isCancelled()) {
            return;
        }

        try {
            std::string error;
            uint32_t rttMs = 0;
            if (task_->probe(task_->config, rttMs, error)) {
                result.ok = true;
                result.rttMs = rttMs;
            } else {
                result.error = QString::fromStdString(error);
            }
        } catch (const std::exception& e) {
            result.error = QString::fromUtf8(e.what());
        }

        if (task_->token->isCancelled()) {
            return;
        }
        // Queued delivery: runs later on the receiver's thread. If the receiver
        // has been destroyed by then, Qt drops the call.
        QMetaObject::invokeMethod(
            receiver_,
            [receiver = receiver_, token = task_->token, result] {
                ResolverJobs* jobs = qobject_cast<ResolverJobs*>(receiver);
                if (jobs && !token->isCancelled()) {
                    emit jobs->pingFinished(result);
                }
            },
            Qt::QueuedConnection);
    }

private:
    std::shared_ptr<PingTask> task_;
    QObject* receiver_;
};

}  // namespace

quint64 PingRequestTracker::begin(const UpstreamConfig& config) {
    const quint64 generation = ++nextGeneration_;
    pending_.insert_or_assign(config.name, Request{config, generation});
    return generation;
}

bool PingRequestTracker::accept(const PingResult& result, const std::vector<UpstreamConfig>& current) {
    auto it = pending_.find(result.config.name);
    if (it == pending_.end() || it->second.generation != result.generation) {
        return false;
    }
    const bool matchesRequest = sameUpstream(it->second.config, result.config);
    pending_.erase(it);
    return matchesRequest && std::any_of(current.begin(), current.end(), [&](const UpstreamConfig& config) {
        return sameUpstream(config, result.config);
    });
}

ResolverJobs::ResolverJobs(Probe probe, QObject* parent)
    : QObject(parent), probe_(std::move(probe)) {
    // The pool only ever runs our short network probes; keep it small.
    pool_.setMaxThreadCount(4);
}

ResolverJobs::~ResolverJobs() {
    cancelAll();
    // Drain while this object is still alive so every pending invokeMethod has
    // a valid context pointer. Pending deliveries are dropped after destruction.
    pool_.waitForDone();
}

void ResolverJobs::startPing(UpstreamConfig config, quint64 generation) {
    auto task = std::make_shared<PingTask>();
    task->config = std::move(config);
    task->token = std::make_shared<CancelToken>();
    task->generation = generation;
    task->probe = probe_;
    tokens_.erase(std::remove_if(tokens_.begin(), tokens_.end(), [](const auto& token) {
        return token.expired();
    }), tokens_.end());
    tokens_.push_back(task->token);

    auto* runnable = new PingRunnable(std::move(task), this);
    runnable->setAutoDelete(true);
    pool_.start(runnable);
}

void ResolverJobs::cancelAll() {
    for (const auto& token : tokens_) {
        if (auto active = token.lock()) {
            active->cancel();
        }
    }
    tokens_.clear();
}
