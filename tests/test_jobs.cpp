// ResolverJobs dispatcher: lifetime safety, cancellation, generation guards,
// exception propagation and shutdown drain. A fake probe keeps every case
// offline and lets us simulate slow and failing work.

#include <QtTest/QtTest>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QSignalSpy>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>

#include "core/Config.h"
#include "ui/ResolverJobs.h"

namespace {

UpstreamConfig makeUpstream(const std::string& name, const std::string& stamp = std::string()) {
    UpstreamConfig up;
    up.name = name;
    up.type = "plain";
    up.address = "127.0.0.1";
    up.stamp = stamp;
    return up;
}

// Processes queued signal deliveries for a bounded time.
void drainEvents(int ms = 400) {
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

}  // namespace

class TestJobs : public QObject {
    Q_OBJECT

private slots:
    void successResultDelivered();
    void failureResultDelivered();
    void exceptionIsConvertedToErrorResult();
    void generationIsEchoedOnResult();
    void destroyedDispatcherDropsDelivery();
    void cancelAllDropsResults();
    void slowWorkDoesNotBlockGuiThread();
    void destructorDrainsOutstandingWork();
    void independentServersAndLatestRequest();
    void changedEndpointRejectsResult();
    void deletedOrReplacedServerRejectsResult();
    void cancellationDropsAlreadyQueuedDelivery();
    void completedTokenBookkeepingIsPruned();
};

void TestJobs::successResultDelivered() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
        rttMs = 42;
        return true;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);

    jobs.startPing(makeUpstream("ok", "sdns://ok"), 1);
    drainEvents();

    QCOMPARE(spy.count(), 1);
    const PingResult r = spy.takeFirst().at(0).value<PingResult>();
    QCOMPARE(r.name, QStringLiteral("ok"));
    QCOMPARE(r.stamp, QStringLiteral("sdns://ok"));
    QCOMPARE(r.generation, quint64(1));
    QCOMPARE(r.config.address, std::string("127.0.0.1"));
    QVERIFY(r.ok);
    QCOMPARE(r.rttMs, uint32_t(42));
    QVERIFY(r.error.isEmpty());
}

void TestJobs::failureResultDelivered() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t&, std::string& error) {
        error = "probe refused";
        return false;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);

    jobs.startPing(makeUpstream("bad"), 2);
    drainEvents();

    QCOMPARE(spy.count(), 1);
    const PingResult r = spy.takeFirst().at(0).value<PingResult>();
    QVERIFY(!r.ok);
    QCOMPARE(r.error, QStringLiteral("probe refused"));
    QCOMPARE(r.generation, quint64(2));
}

void TestJobs::exceptionIsConvertedToErrorResult() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t&, std::string&) -> bool {
        throw std::runtime_error("boom");
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);

    jobs.startPing(makeUpstream("thrower"), 3);
    drainEvents();

    QCOMPARE(spy.count(), 1);
    const PingResult r = spy.takeFirst().at(0).value<PingResult>();
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("boom")));
}

void TestJobs::generationIsEchoedOnResult() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
        rttMs = 1;
        return true;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);

    jobs.startPing(makeUpstream("a"), 10);
    jobs.startPing(makeUpstream("b"), 11);
    drainEvents();

    QCOMPARE(spy.count(), 2);
    QSet<quint64> generations;
    for (int i = 0; i < spy.count(); ++i) {
        generations.insert(spy.at(i).at(0).value<PingResult>().generation);
    }
    QVERIFY(generations.contains(quint64(10)));
    QVERIFY(generations.contains(quint64(11)));
}

void TestJobs::destroyedDispatcherDropsDelivery() {
    int delivered = 0;
    auto* jobs = new ResolverJobs([](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        rttMs = 1;
        return true;
    });
    connect(jobs, &ResolverJobs::pingFinished, this, [&delivered](const PingResult&) { ++delivered; });

    jobs->startPing(makeUpstream("slow"), 1);
    // Destroy while the worker is still probing. The destructor must drain
    // without crashing and the late delivery must not reach a dead object.
    delete jobs;
    drainEvents();
    QCOMPARE(delivered, 0);
}

void TestJobs::cancelAllDropsResults() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        rttMs = 1;
        return true;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);

    jobs.startPing(makeUpstream("cancelled"), 1);
    jobs.cancelAll();
    drainEvents();
    QCOMPARE(spy.count(), 0);
}

void TestJobs::slowWorkDoesNotBlockGuiThread() {
    ResolverJobs jobs([](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        rttMs = 1;
        return true;
    });

    QElapsedTimer timer;
    timer.start();
    jobs.startPing(makeUpstream("slow"), 1);
    const qint64 elapsed = timer.elapsed();
    // Queueing the work must return immediately, not wait for the probe.
    QVERIFY2(elapsed < 100, qPrintable(QStringLiteral("startPing blocked for %1 ms").arg(elapsed)));
    drainEvents();
}

void TestJobs::destructorDrainsOutstandingWork() {
    std::atomic<int> inFlight{0};
    {
        ResolverJobs jobs([&inFlight](const UpstreamConfig&, uint32_t& rttMs, std::string&) {
            inFlight.fetch_add(1);
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
            inFlight.fetch_sub(1);
            rttMs = 1;
            return true;
        });
        jobs.startPing(makeUpstream("a"), 1);
        jobs.startPing(makeUpstream("b"), 2);
        // Leaving the scope runs the destructor, which must wait for the
        // workers so nothing touches Winsock/Qt after teardown.
    }
    QCOMPARE(inFlight.load(), 0);
}

void TestJobs::independentServersAndLatestRequest() {
    PingRequestTracker tracker;
    const auto a = makeUpstream("a");
    const auto b = makeUpstream("b");
    PingResult oldA;
    oldA.config = a;
    oldA.generation = tracker.begin(a);
    PingResult resultB;
    resultB.config = b;
    resultB.generation = tracker.begin(b);
    PingResult newA;
    newA.config = a;
    newA.generation = tracker.begin(a);
    const std::vector<UpstreamConfig> current{a, b};
    QVERIFY(!tracker.accept(oldA, current));
    QVERIFY(tracker.accept(resultB, current));
    QVERIFY(tracker.accept(newA, current));
    QVERIFY(!tracker.accept(newA, current));
}

void TestJobs::changedEndpointRejectsResult() {
    const std::vector<std::function<void(UpstreamConfig&)>> edits{
        [](auto& c) { c.name = "renamed"; },
        [](auto& c) { c.address = "192.0.2.1"; },
        [](auto& c) { c.type = "dot"; },
        [](auto& c) { c.stamp = "changed stamp"; },
        [](auto& c) { c.port = 5353; },
        [](auto& c) { c.bootstrapIps = {"192.0.2.2"}; },
        [](auto& c) { c.sni = "new.example"; },
        [](auto& c) { c.tlsVerify = false; },
        [](auto& c) { c.proxy = "https://relay.example"; }
    };
    for (const auto& edit : edits) {
        PingRequestTracker tracker;
        auto config = makeUpstream("a");
        PingResult result;
        result.config = config;
        result.generation = tracker.begin(config);
        edit(config);
        QVERIFY(!tracker.accept(result, {config}));
    }
}

void TestJobs::deletedOrReplacedServerRejectsResult() {
    PingRequestTracker tracker;
    const auto config = makeUpstream("a");
    PingResult old;
    old.config = config;
    old.generation = tracker.begin(config);
    QVERIFY(!tracker.accept(old, {}));
    old.generation = tracker.begin(config);
    tracker.clear();
    PingResult replacement;
    replacement.config = config;
    replacement.generation = tracker.begin(config);
    QVERIFY(!tracker.accept(old, {config}));
    QVERIFY(tracker.accept(replacement, {config}));
}

void TestJobs::cancellationDropsAlreadyQueuedDelivery() {
    ResolverJobs jobs([](const auto&, uint32_t& rtt, std::string&) {
        rtt = 1;
        return true;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);
    jobs.startPing(makeUpstream("queued"), 1);
    // Waiting without pumping the GUI guarantees the result is queued, not
    // delivered. Cancellation must still suppress it at delivery time.
    QVERIFY(jobs.pool_.waitForDone(5000));
    jobs.cancelAll();
    QCoreApplication::processEvents();
    QCOMPARE(spy.count(), 0);
}

void TestJobs::completedTokenBookkeepingIsPruned() {
    ResolverJobs jobs([](const auto&, uint32_t& rtt, std::string&) {
        rtt = 1;
        return true;
    });
    QSignalSpy spy(&jobs, &ResolverJobs::pingFinished);
    for (quint64 generation = 1; generation <= 20; ++generation) {
        jobs.startPing(makeUpstream("repeated"), generation);
        QVERIFY(jobs.pool_.waitForDone(5000));
        QTRY_COMPARE(spy.count(), int(generation));
        QTRY_VERIFY(std::all_of(jobs.tokens_.begin(), jobs.tokens_.end(), [](const auto& token) {
            return token.expired();
        }));
        QVERIFY(jobs.tokens_.size() <= 1);
    }
}

QTEST_GUILESS_MAIN(TestJobs)
#include "test_jobs.moc"
