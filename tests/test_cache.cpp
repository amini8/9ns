// Reply-cache context separation and validation provenance. Offline only.

#include <QtTest/QtTest>

#include "core/Cache.h"
#include "core/DnsMessage.h"
#include "core/DnsSec.h"
#include "DnsFixtures.h"

class TestCache : public QObject {
    Q_OBJECT

private slots:
    void transportTrustRoundTrips();
    void retrievalReassessesStatus();
    void expiredRrsigYieldsBogusOnCacheHit();
    void bogusRepliesAreNeverStored();
    void keySeparatesCdDoAndEdnsContext();
    void distinctContextsDoNotShareEntries();
    void mismatchedQuestionIsNotCached();
};

void TestCache::transportTrustRoundTrips() {
    Cache cache(16);
    const dns::Bytes query = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response = dns::makeNullIpResponse(query, parsed);

    CacheProvenance stored;
    stored.authenticatedTransport = true;
    stored.status = DnsSecStatus::Secure;
    cache.put("key", query, response, stored);
    QCOMPARE(cache.size(), size_t(1));

    dns::Bytes reply;
    CacheProvenance hit;
    QVERIFY(cache.get("key", 99, reply, hit));
    QVERIFY(hit.authenticatedTransport);
    QCOMPARE(reply.size(), response.size());
}

void TestCache::retrievalReassessesStatus() {
    Cache cache(16);
    const dns::Bytes query = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response = dns::makeNullIpResponse(query, parsed);

    // A cached reply without evidence is Insecure at retrieval even if the
    // stored status said otherwise: the store-time status is not replayed.
    CacheProvenance stored;
    stored.authenticatedTransport = true;
    stored.status = DnsSecStatus::Secure;
    cache.put("key", query, response, stored);

    dns::Bytes reply;
    CacheProvenance hit;
    QVERIFY(cache.get("key", 1, reply, hit));
    QCOMPARE(hit.status, DnsSecStatus::Insecure);
    QVERIFY(hit.authenticatedTransport);
}

void TestCache::expiredRrsigYieldsBogusOnCacheHit() {
    Cache cache(16);
    const dns::Bytes query = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    // Signature outside its validity window. Stored as Secure to model a reply
    // whose assurance decayed while it sat in the cache.
    const uint32_t now = testdns::nowUnix();
    const dns::Bytes expired = testdns::makeAnswerResponse(
        query, parsed, dns::kTypeRrsig,
        testdns::makeRrsigRdata(now - 60, now - 3600), true);

    CacheProvenance stored;
    stored.authenticatedTransport = true;
    stored.status = DnsSecStatus::Secure;
    cache.put("key", query, expired, stored);
    QCOMPARE(cache.size(), size_t(1));

    dns::Bytes reply;
    CacheProvenance hit;
    QVERIFY(cache.get("key", 1, reply, hit));
    QVERIFY(hit.authenticatedTransport);
    QCOMPARE(hit.status, DnsSecStatus::Bogus);  // the value cache-hit enforcement uses

    // A signature still inside its window keeps the Secure assessment.
    const dns::Bytes valid = testdns::makeAnswerResponse(
        query, parsed, dns::kTypeRrsig,
        testdns::makeRrsigRdata(now + 3600, now - 60), true);
    cache.put("key2", query, valid, stored);
    QVERIFY(cache.get("key2", 1, reply, hit));
    QCOMPARE(hit.status, DnsSecStatus::Secure);
}

void TestCache::bogusRepliesAreNeverStored() {
    Cache cache(16);
    const dns::Bytes query = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response = dns::makeNullIpResponse(query, parsed);

    CacheProvenance stored;
    stored.status = DnsSecStatus::Bogus;
    cache.put("key", query, response, stored);
    QCOMPARE(cache.size(), size_t(0));

    dns::Bytes reply;
    CacheProvenance hit;
    QVERIFY(!cache.get("key", 1, reply, hit));
}

void TestCache::keySeparatesCdDoAndEdnsContext() {
    const std::string target = "server";
    const dns::Bytes ecsA = testdns::makeEcsOption(0, {192, 0, 2, 0});
    const dns::Bytes ecsB = testdns::makeEcsOption(24, {198, 51, 100, 0});

    const dns::Bytes base = testdns::makeQuery(1, "a.example", dns::kTypeA);
    const dns::Bytes withCd = testdns::makeQuery(2, "a.example", dns::kTypeA, 1, true);
    const dns::Bytes withDo = testdns::makeQuery(3, "a.example", dns::kTypeA, 1, false, true,
                                                 1232, true, {});
    const dns::Bytes bigPayload = testdns::makeQuery(4, "a.example", dns::kTypeA, 1, false, true,
                                                     4096, false, {});
    const dns::Bytes ecsOne = testdns::makeQuery(5, "a.example", dns::kTypeA, 1, false, true,
                                                 1232, false, ecsA);
    const dns::Bytes ecsTwo = testdns::makeQuery(6, "a.example", dns::kTypeA, 1, false, true,
                                                 1232, false, ecsB);

    auto keyOf = [&target](const dns::Bytes& packet) {
        dns::Query parsed;
        if (!dns::parseQuery(packet, parsed)) {
            return std::string();
        }
        dns::QueryContext ctx;
        dns::queryContext(packet, parsed, ctx);
        return cacheKey(target, parsed, ctx);
    };

    const std::string baseKey = keyOf(base);
    QVERIFY(!baseKey.empty());
    QCOMPARE(keyOf(base), baseKey);
    QVERIFY(keyOf(withCd) != baseKey);
    QVERIFY(keyOf(withDo) != baseKey);
    QVERIFY(keyOf(bigPayload) != keyOf(withDo));
    QVERIFY(keyOf(ecsOne) != baseKey);
    QVERIFY(keyOf(ecsTwo) != keyOf(ecsOne));
    QCOMPARE(keyOf(testdns::makeQuery(7, "a.example", dns::kTypeA)), baseKey);
}

void TestCache::distinctContextsDoNotShareEntries() {
    Cache cache(16);
    const dns::Bytes query = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response = dns::makeNullIpResponse(query, parsed);

    dns::QueryContext ctx;
    QVERIFY(dns::queryContext(query, parsed, ctx));
    const std::string baseKey = cacheKey("server", parsed, ctx);

    const dns::Bytes cdQuery = testdns::makeQuery(2, "a.example", dns::kTypeA, 1, true);
    dns::Query cdParsed;
    QVERIFY(dns::parseQuery(cdQuery, cdParsed));
    dns::QueryContext cdCtx;
    QVERIFY(dns::queryContext(cdQuery, cdParsed, cdCtx));
    const std::string cdKey = cacheKey("server", cdParsed, cdCtx);

    cache.put(baseKey, query, response, CacheProvenance{});

    dns::Bytes reply;
    CacheProvenance hit;
    QVERIFY(cache.get(baseKey, 1, reply, hit));
    QVERIFY(!cache.get(cdKey, 1, reply, hit));
}

void TestCache::mismatchedQuestionIsNotCached() {
    Cache cache(16);
    const dns::Bytes queryA = testdns::makeQuery(1, "a.example", dns::kTypeA);
    dns::Query parsedA;
    QVERIFY(dns::parseQuery(queryA, parsedA));
    const dns::Bytes queryB = testdns::makeQuery(1, "b.example", dns::kTypeA);
    dns::Query parsedB;
    QVERIFY(dns::parseQuery(queryB, parsedB));
    const dns::Bytes responseB = dns::makeNullIpResponse(queryB, parsedB);

    cache.put("key", queryA, responseB, CacheProvenance{});
    QCOMPARE(cache.size(), size_t(0));

    // The echo of the right question is accepted.
    const dns::Bytes responseA = dns::makeNullIpResponse(queryA, parsedA);
    cache.put("key", queryA, responseA, CacheProvenance{});
    QCOMPARE(cache.size(), size_t(1));
}

QTEST_GUILESS_MAIN(TestCache)
#include "test_cache.moc"
