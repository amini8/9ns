// Upstream-validation DNSSEC semantics and per-upstream channel trust. Offline
// only: fake upstreams, no sockets.

#include <QtTest/QtTest>

#include <memory>
#include <string>
#include <vector>

#include "core/DnsMessage.h"
#include "core/DnsSec.h"
#include "core/Pool.h"
#include "transports/Upstream.h"
#include "DnsFixtures.h"

namespace {

// Upstream fake answering with a canned response. Trust is declared through the
// same decision the production factory uses.
class FakeUpstream : public Upstream {
public:
    FakeUpstream(std::string name, std::string type, bool tlsVerify, bool ok, dns::Bytes response)
        : Upstream(std::move(name), type),
          ok_(ok),
          response_(std::move(response)) {
        setAuthenticated(isAuthenticatedChannel(this->type(), tlsVerify));
    }

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) override {
        (void)query;
        if (!ok_) {
            error = "fake upstream failure";
            return false;
        }
        response = response_;
        return true;
    }

private:
    bool ok_;
    dns::Bytes response_;
};

}  // namespace

// Test-local definition of Upstream::ping so this test links without the real
// transport translation unit (Upstream.cpp pulls in every transport and their
// crypto dependencies). The key-function definition also emits Upstream's vtable.
bool Upstream::ping(uint32_t& rttMs, std::string& error) {
    rttMs = 0;
    error = "ping is not available in tests";
    return false;
}

class TestDnsTrust : public QObject {
    Q_OBJECT

private slots:
    void channelTrustFollowsTransportAndVerification();
    void adOverAuthenticatedChannelIsSecure();
    void adOverUnauthenticatedChannelIsNotSecure();
    void forgedRrsigIsNotSecure();
    void rrsigAloneIsNeverSecure();
    void expiredRrsigIsBogus();
    void servFailIsBogus();
    void noEvidenceIsInsecure();
    void plainPoolMemberAdIsNotSecure();
    void authenticatedPoolMemberAdIsSecure();
};

void TestDnsTrust::channelTrustFollowsTransportAndVerification() {
    // tls_verify=false is never authenticated, even when encrypted.
    QVERIFY(Upstream::isAuthenticatedChannel("doh", true));
    QVERIFY(!Upstream::isAuthenticatedChannel("doh", false));
    QVERIFY(Upstream::isAuthenticatedChannel("dot", true));
    QVERIFY(!Upstream::isAuthenticatedChannel("dot", false));
    QVERIFY(Upstream::isAuthenticatedChannel("doq", true));
    QVERIFY(!Upstream::isAuthenticatedChannel("doq", false));

    // Plain DNS and ODoH relaying are not authenticated channels.
    QVERIFY(!Upstream::isAuthenticatedChannel("plain", true));
    QVERIFY(!Upstream::isAuthenticatedChannel("plain", false));
    QVERIFY(!Upstream::isAuthenticatedChannel("odoh", true));

    // DNSCrypt authenticates through its own provider keys.
    QVERIFY(Upstream::isAuthenticatedChannel("dnscrypt", true));
    QVERIFY(Upstream::isAuthenticatedChannel("dnscrypt", false));

    QVERIFY(!Upstream::isAuthenticatedChannel("unknown", true));
}

void TestDnsTrust::adOverAuthenticatedChannelIsSecure() {
    const dns::Bytes query = testdns::makeQuery(1, "secure.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response =
        testdns::makeAnswerResponse(query, parsed, dns::kTypeA, {192, 0, 2, 1}, true);

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, true), DnsSecStatus::Secure);
}

void TestDnsTrust::adOverUnauthenticatedChannelIsNotSecure() {
    const dns::Bytes query = testdns::makeQuery(1, "plain.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response =
        testdns::makeAnswerResponse(query, parsed, dns::kTypeA, {192, 0, 2, 1}, true);

    DnsSec dnssec;
    QVERIFY(dnssec.validate(response, false) != DnsSecStatus::Secure);
    QCOMPARE(dnssec.validate(response, false), DnsSecStatus::Indeterminate);
}

void TestDnsTrust::forgedRrsigIsNotSecure() {
    const dns::Bytes query = testdns::makeQuery(1, "forged.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const uint32_t now = testdns::nowUnix();
    const dns::Bytes rrsig = testdns::makeRrsigRdata(now + 3600, now - 60);
    const dns::Bytes withAd = testdns::makeAnswerResponse(query, parsed, dns::kTypeRrsig, rrsig, true);
    const dns::Bytes withoutAd = testdns::makeAnswerResponse(query, parsed, dns::kTypeRrsig, rrsig, false);

    DnsSec dnssec;
    // A timestamp-valid RRSIG proves nothing on its own.
    QVERIFY(dnssec.validate(withAd, false) != DnsSecStatus::Secure);
    QVERIFY(dnssec.validate(withoutAd, true) != DnsSecStatus::Secure);
    QVERIFY(dnssec.validate(withoutAd, false) != DnsSecStatus::Secure);
    QCOMPARE(dnssec.validate(withoutAd, true), DnsSecStatus::Indeterminate);
}

void TestDnsTrust::rrsigAloneIsNeverSecure() {
    const dns::Bytes query = testdns::makeQuery(1, "signed.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const uint32_t now = testdns::nowUnix();
    const dns::Bytes response = testdns::makeAnswerResponse(
        query, parsed, dns::kTypeRrsig, testdns::makeRrsigRdata(now + 3600, now - 60), false);

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, true), DnsSecStatus::Indeterminate);
    QCOMPARE(dnssec.validate(response, false), DnsSecStatus::Indeterminate);
}

void TestDnsTrust::expiredRrsigIsBogus() {
    const dns::Bytes query = testdns::makeQuery(1, "expired.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const uint32_t now = testdns::nowUnix();
    const dns::Bytes response = testdns::makeAnswerResponse(
        query, parsed, dns::kTypeRrsig, testdns::makeRrsigRdata(now - 60, now - 3600), true);

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, true), DnsSecStatus::Bogus);
    QCOMPARE(dnssec.validate(response, false), DnsSecStatus::Bogus);
}

void TestDnsTrust::servFailIsBogus() {
    const dns::Bytes query = testdns::makeQuery(1, "fail.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response = dns::makeErrorResponse(query, parsed, dns::kRcodeServFail);

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, true), DnsSecStatus::Bogus);
    QCOMPARE(dnssec.validate(response, false), DnsSecStatus::Bogus);
}

void TestDnsTrust::noEvidenceIsInsecure() {
    const dns::Bytes query = testdns::makeQuery(1, "unsigned.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes response =
        testdns::makeAnswerResponse(query, parsed, dns::kTypeA, {192, 0, 2, 1}, false);

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, true), DnsSecStatus::Insecure);
    QCOMPARE(dnssec.validate(response, false), DnsSecStatus::Insecure);
}

void TestDnsTrust::plainPoolMemberAdIsNotSecure() {
    const dns::Bytes query = testdns::makeQuery(0x1111, "pool.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes adResponse =
        testdns::makeAnswerResponse(query, parsed, dns::kTypeA, {192, 0, 2, 1}, true);

    FakeUpstream plain("plain-member", "plain", true, true, adResponse);
    FakeUpstream dot("dot-member", "dot", true, true, adResponse);
    QVERIFY(!plain.isAuthenticated());
    QVERIFY(dot.isAuthenticated());

    Pool pool("p", "failover", {&plain, &dot});
    dns::Bytes response;
    std::string error;
    std::string used;
    QVERIFY(pool.exchange(query, response, error, used));

    // The pool reports the member that answered; its trust decides the outcome.
    QCOMPARE(used, plain.name());
    DnsSec dnssec;
    QVERIFY(dnssec.validate(response, plain.isAuthenticated()) != DnsSecStatus::Secure);
    QCOMPARE(dnssec.validate(response, plain.isAuthenticated()), DnsSecStatus::Indeterminate);
}

void TestDnsTrust::authenticatedPoolMemberAdIsSecure() {
    const dns::Bytes query = testdns::makeQuery(0x2222, "pool.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    const dns::Bytes adResponse =
        testdns::makeAnswerResponse(query, parsed, dns::kTypeA, {192, 0, 2, 1}, true);

    FakeUpstream plain("plain-member", "plain", true, false, {});
    FakeUpstream dot("dot-member", "dot", true, true, adResponse);
    Pool pool("p", "failover", {&plain, &dot});

    dns::Bytes response;
    std::string error;
    std::string used;
    QVERIFY(pool.exchange(query, response, error, used));
    QCOMPARE(used, dot.name());

    DnsSec dnssec;
    QCOMPARE(dnssec.validate(response, dot.isAuthenticated()), DnsSecStatus::Secure);
}

QTEST_GUILESS_MAIN(TestDnsTrust)
#include "test_dnstrust.moc"
