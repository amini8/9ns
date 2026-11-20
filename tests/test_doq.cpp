#include <QtTest/QtTest>

#include <algorithm>
#include <cstring>
#include <limits>

#include "transports/DoqFraming.h"

namespace {

struct FakeStream {
    dns::Bytes incoming;
    dns::Bytes sent;
    size_t offset = 0;
    size_t chunk = 1;
    size_t failAt = std::numeric_limits<size_t>::max();
    bool zeroProgress = false;
    bool writeOk = true;
    size_t writeLimit = std::numeric_limits<size_t>::max();
    size_t reads = 0;

    bool exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) {
        return doq::exchangeFrame(query, response, error,
            [this](const uint8_t* data, size_t size, size_t& written) {
                written = std::min(size, writeLimit);
                sent.assign(data, data + written);
                return writeOk;
            },
            [this](uint8_t* data, size_t size, size_t& got) {
                ++reads;
                got = 0;
                if (offset >= failAt || offset == incoming.size()) {
                    return zeroProgress;
                }
                got = std::min({size, chunk, incoming.size() - offset, failAt - offset});
                std::memcpy(data, incoming.data() + offset, got);
                offset += got;
                return true;
            });
    }
};

dns::Bytes queryWithId(uint16_t id, size_t size = dns::kHeaderSize) {
    dns::Bytes query(size, 0);
    dns::setId(query, id);
    query[2] = 1;
    return query;
}

dns::Bytes replyFrame(size_t size = dns::kHeaderSize) {
    dns::Bytes frame(size + 2, 0);
    frame[0] = static_cast<uint8_t>(size >> 8);
    frame[1] = static_cast<uint8_t>(size);
    frame[4] = 0x81;
    return frame;
}

} // namespace

class TestDoq : public QObject {
    Q_OBJECT

private slots:
    void restoresIdsAndReadsFragments() {
        for (const uint16_t id : {uint16_t(0), uint16_t(1), uint16_t(65535)}) {
            for (const size_t chunk : {size_t(1), size_t(3), size_t(65537)}) {
                const dns::Bytes query = queryWithId(id, 300);
                const dns::Bytes original = query;
                FakeStream stream;
                stream.incoming = replyFrame(300);
                stream.chunk = chunk;
                dns::Bytes response;
                std::string error = "stale";
                QVERIFY(stream.exchange(query, response, error));
                QVERIFY(error.empty());
                QCOMPARE(query, original);
                QVERIFY(dns::isResponseFor(response, id));
                QCOMPARE(response.size(), size_t(300));
                dns::Bytes expected = {1, 44};
                expected.insert(expected.end(), query.begin(), query.end());
                expected[2] = expected[3] = 0;
                QCOMPARE(stream.sent, expected);
                dns::Bytes expectedResponse(stream.incoming.begin() + 2, stream.incoming.end());
                dns::setId(expectedResponse, id);
                QCOMPARE(response, expectedResponse);
            }
        }
    }

    void rejectsTruncatedRepliesAndReadFailures() {
        const dns::Bytes complete = replyFrame();
        for (size_t cut = 0; cut < complete.size(); ++cut) {
            for (const bool zeroProgress : {false, true}) {
                FakeStream stream;
                stream.incoming.assign(complete.begin(), complete.begin() + cut);
                stream.zeroProgress = zeroProgress;
                dns::Bytes response = {9, 8, 7};
                const dns::Bytes original = response;
                std::string error;
                QVERIFY(!stream.exchange(queryWithId(1), response, error));
                QVERIFY(!error.empty());
                QCOMPARE(response, original);
            }
            FakeStream stream;
            stream.incoming = complete;
            stream.failAt = cut;
            dns::Bytes response = {5};
            std::string error;
            QVERIFY(!stream.exchange(queryWithId(1), response, error));
            QCOMPARE(response, dns::Bytes{5});
        }
    }

    void rejectsMalformedReplies() {
        std::vector<dns::Bytes> invalid;
        for (uint8_t size = 0; size < dns::kHeaderSize; ++size) {
            invalid.push_back({0, size});
        }
        dns::Bytes wrongId = replyFrame();
        wrongId[3] = 1;
        invalid.push_back(wrongId);
        wrongId[2] = wrongId[3] = 255;
        invalid.push_back(wrongId);
        dns::Bytes notResponse = replyFrame();
        notResponse[4] &= 0x7F;
        invalid.push_back(notResponse);
        for (const auto& frame : invalid) {
            FakeStream stream;
            stream.incoming = frame;
            dns::Bytes response = {7};
            std::string error;
            QVERIFY(!stream.exchange(queryWithId(1), response, error));
            QVERIFY(!error.empty());
            QCOMPARE(response, dns::Bytes{7});
        }
    }

    void rejectsShortAndFailedWrites() {
        const dns::Bytes query = queryWithId(65535);
        for (size_t count = 0; count <= query.size() + 2; ++count) {
            for (const bool ok : {false, true}) {
                if (ok && count == query.size() + 2) {
                    continue;
                }
                FakeStream stream;
                stream.incoming = replyFrame();
                stream.writeLimit = count;
                stream.writeOk = ok;
                dns::Bytes response = {6};
                std::string error;
                QVERIFY(!stream.exchange(query, response, error));
                QVERIFY(!error.empty());
                QCOMPARE(stream.reads, size_t(0));
                QCOMPARE(response, dns::Bytes{6});
            }
        }
    }

    void enforcesQuerySizeAndSupportsMaximumFrame() {
        for (const size_t size : {size_t(0), size_t(11), size_t(65536)}) {
            FakeStream stream;
            dns::Bytes response = {4};
            std::string error;
            QVERIFY(!stream.exchange(dns::Bytes(size), response, error));
            QVERIFY(stream.sent.empty());
            QCOMPARE(stream.reads, size_t(0));
            QCOMPARE(response, dns::Bytes{4});
        }
        FakeStream stream;
        stream.incoming = replyFrame(65535);
        stream.chunk = 1024;
        dns::Bytes response;
        std::string error;
        QVERIFY(stream.exchange(queryWithId(65535, 65535), response, error));
        QCOMPARE(response.size(), size_t(65535));
        QVERIFY(dns::isResponseFor(response, 65535));
        QCOMPARE(stream.sent.size(), size_t(65537));
        QCOMPARE(stream.sent[0], uint8_t(255));
        QCOMPARE(stream.sent[1], uint8_t(255));
    }
};

QTEST_GUILESS_MAIN(TestDoq)
#include "test_doq.moc"
