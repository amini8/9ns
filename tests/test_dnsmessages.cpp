// Synthetic DNS answer sizing and response validation. Offline only: pure wire
// helpers and hand-built packets.

#include <QtTest/QtTest>

#include "core/DnsMessage.h"
#include "DnsFixtures.h"

class TestDnsMessages : public QObject {
    Q_OBJECT

private slots:
    void nullIpAAnswerIsWellFormed();
    void nullIpAaaaAnswerIsWellFormed();
    void nullIpForOtherTypesFallsBackToEmptyNoError();
    void localIpv4AnswerIsWellFormed();
    void localIpv6AnswerIsWellFormed();
    void localIpTypeMismatchFallsBackToEmptyNoError();
    void queryContextReadsFlagsAndOpt();
    void queryContextHashSeparatesEcs();
    void questionEchoIsValidated();
    void idOnlyMatchIsRetainedForWirePaths();
};

namespace {

// Offset of the single answer record in a synthetic reply: header, question and
// the 2-byte compression pointer to the question name.
size_t answerOffset(const dns::Query& parsed) {
    return parsed.questionEnd + 2;
}

uint16_t readU16At(const dns::Bytes& packet, size_t off) {
    return static_cast<uint16_t>((packet[off] << 8) | packet[off + 1]);
}

}  // namespace

void TestDnsMessages::nullIpAAnswerIsWellFormed() {
    const dns::Bytes query = testdns::makeQuery(0x1234, "test.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const dns::Bytes reply = dns::makeNullIpResponse(query, parsed);
    const size_t anStart = answerOffset(parsed);
    // RR fixed fields are 10 bytes (type/class/ttl/rdlength) before the 4-byte RDATA.
    QCOMPARE(reply.size(), anStart + 10 + 4);
    QCOMPARE(readU16At(reply, anStart + 8), uint16_t(4));  // RDLENGTH field

    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(1));
    QCOMPARE(msg.answers[0].type, dns::kTypeA);
    QCOMPARE(msg.answers[0].rclass, uint16_t(1));
    QCOMPARE(msg.answers[0].ttl, uint32_t(300));
    QCOMPARE(msg.answers[0].rdata.size(), size_t(4));
    QCOMPARE(msg.answers[0].rdata, dns::Bytes(4, 0));
    QCOMPARE(msg.questions.size(), size_t(1));
    QCOMPARE(msg.questions[0].name, parsed.name);
}

void TestDnsMessages::nullIpAaaaAnswerIsWellFormed() {
    const dns::Bytes query = testdns::makeQuery(0x1234, "test.example", dns::kTypeAaaa);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const dns::Bytes reply = dns::makeNullIpResponse(query, parsed);
    const size_t anStart = answerOffset(parsed);
    QCOMPARE(reply.size(), anStart + 10 + 16);
    QCOMPARE(readU16At(reply, anStart + 8), uint16_t(16));

    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(1));
    QCOMPARE(msg.answers[0].type, dns::kTypeAaaa);
    QCOMPARE(msg.answers[0].rdata.size(), size_t(16));
    QCOMPARE(msg.answers[0].rdata, dns::Bytes(16, 0));
}

void TestDnsMessages::nullIpForOtherTypesFallsBackToEmptyNoError() {
    const dns::Bytes query = testdns::makeQuery(0x1234, "test.example", dns::kTypeMx);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const dns::Bytes reply = dns::makeNullIpResponse(query, parsed);
    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(0));
    QCOMPARE(msg.rcode, dns::kRcodeNoError);
}

void TestDnsMessages::localIpv4AnswerIsWellFormed() {
    const dns::Bytes query = testdns::makeQuery(0xABCD, "host.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const dns::Bytes reply = dns::makeLocalIpResponse(query, parsed, "192.0.2.7");
    const size_t anStart = answerOffset(parsed);
    // Fixed fields (10 bytes) plus a 4-byte address; the write must stay in bounds.
    QCOMPARE(reply.size(), anStart + 10 + 4);
    QCOMPARE(readU16At(reply, anStart + 8), uint16_t(4));

    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(1));
    QCOMPARE(msg.answers[0].type, dns::kTypeA);
    QCOMPARE(msg.answers[0].rdata, dns::Bytes({192, 0, 2, 7}));
}

void TestDnsMessages::localIpv6AnswerIsWellFormed() {
    const dns::Bytes query = testdns::makeQuery(0xABCD, "host.example", dns::kTypeAaaa);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    const dns::Bytes reply = dns::makeLocalIpResponse(query, parsed, "2001:db8::1");
    const size_t anStart = answerOffset(parsed);
    QCOMPARE(reply.size(), anStart + 10 + 16);
    QCOMPARE(readU16At(reply, anStart + 8), uint16_t(16));

    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(1));
    QCOMPARE(msg.answers[0].type, dns::kTypeAaaa);
    QCOMPARE(msg.answers[0].rdata,
             dns::Bytes({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}));
}

void TestDnsMessages::localIpTypeMismatchFallsBackToEmptyNoError() {
    const dns::Bytes query = testdns::makeQuery(0xABCD, "host.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));

    // IPv6 literal for an A query cannot produce an answer.
    const dns::Bytes reply = dns::makeLocalIpResponse(query, parsed, "2001:db8::1");
    dns::ParsedMessage msg;
    QVERIFY(dns::parseMessage(reply, msg));
    QCOMPARE(msg.answers.size(), size_t(0));
    QCOMPARE(msg.rcode, dns::kRcodeNoError);
}

void TestDnsMessages::queryContextReadsFlagsAndOpt() {
    dns::Query parsed;
    dns::QueryContext ctx;

    const dns::Bytes plain = testdns::makeQuery(1, "a.example", dns::kTypeA);
    QVERIFY(dns::parseQuery(plain, parsed));
    QVERIFY(dns::queryContext(plain, parsed, ctx));
    QVERIFY(!ctx.cd);
    QVERIFY(!ctx.hasOpt);
    QCOMPARE(ctx.ednsPayloadSize, uint16_t(0));
    QCOMPARE(ctx.ednsOptionsHash, uint64_t(0));

    const dns::Bytes ecs = testdns::makeEcsOption(0, {192, 0, 2, 0});
    const dns::Bytes withOpt = testdns::makeQuery(2, "a.example", dns::kTypeA, 1, true, true,
                                                  1232, true, ecs);
    QVERIFY(dns::parseQuery(withOpt, parsed));
    QVERIFY(dns::queryContext(withOpt, parsed, ctx));
    QVERIFY(ctx.cd);
    QVERIFY(ctx.hasOpt);
    QVERIFY(ctx.doBit);
    QCOMPARE(ctx.ednsPayloadSize, uint16_t(1232));
    QVERIFY(ctx.ednsOptionsHash != 0);

    const dns::Bytes noDo = testdns::makeQuery(3, "a.example", dns::kTypeA, 1, false, true,
                                               4096, false, {});
    QVERIFY(dns::parseQuery(noDo, parsed));
    QVERIFY(dns::queryContext(noDo, parsed, ctx));
    QVERIFY(!ctx.cd);
    QVERIFY(!ctx.doBit);
    QCOMPARE(ctx.ednsPayloadSize, uint16_t(4096));
}

void TestDnsMessages::queryContextHashSeparatesEcs() {
    dns::Query parsed;
    dns::QueryContext first;
    dns::QueryContext second;

    const dns::Bytes ecsA = testdns::makeEcsOption(0, {192, 0, 2, 0});
    const dns::Bytes ecsB = testdns::makeEcsOption(24, {198, 51, 100, 0});
    const dns::Bytes queryA = testdns::makeQuery(1, "a.example", dns::kTypeA, 1, false, true,
                                                 1232, false, ecsA);
    const dns::Bytes queryB = testdns::makeQuery(2, "a.example", dns::kTypeA, 1, false, true,
                                                 1232, false, ecsB);
    QVERIFY(dns::parseQuery(queryA, parsed));
    QVERIFY(dns::queryContext(queryA, parsed, first));
    QVERIFY(dns::parseQuery(queryB, parsed));
    QVERIFY(dns::queryContext(queryB, parsed, second));
    QVERIFY(first.ednsOptionsHash != second.ednsOptionsHash);

    // Identical options hash identically.
    const dns::Bytes queryAAgain = testdns::makeQuery(3, "a.example", dns::kTypeA, 1, false, true,
                                                      1232, false, ecsA);
    QVERIFY(dns::parseQuery(queryAAgain, parsed));
    dns::QueryContext again;
    QVERIFY(dns::queryContext(queryAAgain, parsed, again));
    QCOMPARE(again.ednsOptionsHash, first.ednsOptionsHash);
}

void TestDnsMessages::questionEchoIsValidated() {
    const dns::Bytes queryA = testdns::makeQuery(0x4242, "alpha.example", dns::kTypeA);
    dns::Query parsedA;
    QVERIFY(dns::parseQuery(queryA, parsedA));
    const dns::Bytes responseA = dns::makeNullIpResponse(queryA, parsedA);

    QVERIFY(dns::isResponseFor(responseA, queryA));
    QVERIFY(dns::isResponseFor(responseA, parsedA.id));

    // Different QNAME.
    const dns::Bytes queryB = testdns::makeQuery(0x4242, "beta.example", dns::kTypeA);
    QVERIFY(!dns::isResponseFor(responseA, queryB));

    // Same name, different QTYPE.
    const dns::Bytes queryC = testdns::makeQuery(0x4242, "alpha.example", dns::kTypeAaaa);
    QVERIFY(!dns::isResponseFor(responseA, queryC));

    // Same name and type, different QCLASS.
    const dns::Bytes queryD = testdns::makeQuery(0x4242, "alpha.example", dns::kTypeA, 3);
    QVERIFY(!dns::isResponseFor(responseA, queryD));

    // Matching question but a different id.
    const dns::Bytes queryE = testdns::makeQuery(0x4343, "alpha.example", dns::kTypeA);
    QVERIFY(!dns::isResponseFor(responseA, queryE));

    // Case-insensitive name echo still matches (DNS names compare case-insensitively).
    const dns::Bytes queryUpper = testdns::makeQuery(0x4242, "Alpha.Example", dns::kTypeA);
    QVERIFY(dns::isResponseFor(responseA, queryUpper));
}

void TestDnsMessages::idOnlyMatchIsRetainedForWirePaths() {
    // DoQ validates the zero-id wire form before restoring the real id; the
    // id-only overload must keep matching purely on id and QR.
    const dns::Bytes query = testdns::makeQuery(0x4242, "alpha.example", dns::kTypeA);
    dns::Query parsed;
    QVERIFY(dns::parseQuery(query, parsed));
    dns::Bytes response = dns::makeNullIpResponse(query, parsed);
    dns::setId(response, 0);

    QVERIFY(dns::isResponseFor(response, 0));
    QVERIFY(!dns::isResponseFor(response, query));
}

QTEST_GUILESS_MAIN(TestDnsMessages)
#include "test_dnsmessages.moc"
