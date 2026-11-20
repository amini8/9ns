#include <QtTest/QtTest>

#include <QFile>
#include <QTemporaryDir>

#include "PublicResolverFixtures.h"
#include "ui/PublicResolverImport.h"

using namespace publicResolverFixtures;

namespace {

std::filesystem::path cachePath(const QTemporaryDir& dir) {
    return std::filesystem::path(dir.path().toStdWString()) / "resolvers.md";
}

QByteArray bytesAt(const std::filesystem::path& path) {
    QFile file(QString::fromStdWString(path.wstring()));
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}

resolvers::ListIo fetched(const std::string& text) {
    resolvers::ListIo io;
    io.fetch = [text](const std::string&, std::string& out, std::string&) { out = text; return true; };
    return io;
}

}  // namespace

class TestPublicResolvers : public QObject {
    Q_OBJECT

private slots:
    void parsedProtocols_data() {
        QTest::addColumn<int>("protocol");
        QTest::addColumn<QString>("label");
        QTest::addColumn<QString>("type");
        QTest::newRow("dnscrypt") << 0x01 << QStringLiteral("DNSCrypt") << QStringLiteral("dnscrypt");
        QTest::newRow("doh") << 0x02 << QStringLiteral("DoH") << QStringLiteral("doh");
        QTest::newRow("doq") << 0x04 << QStringLiteral("DoQ") << QStringLiteral("doq");
        QTest::newRow("odoh") << 0x05 << QStringLiteral("ODoH") << QStringLiteral("odoh");
        QTest::newRow("relay") << 0x81 << QStringLiteral("Relay") << QStringLiteral("");
        QTest::newRow("odoh-relay") << 0x85 << QStringLiteral("ODoH Relay") << QStringLiteral("");
    }

    void parsedProtocols() {
        QFETCH(int, protocol);
        QFETCH(QString, label);
        QFETCH(QString, type);
        const auto entry = item(static_cast<unsigned char>(protocol));
        const auto parsed = resolvers::parseMarkdown(markdown(entry));
        QCOMPARE(parsed.size(), size_t(1));
        QCOMPARE(QString::fromStdString(parsed[0].protocol), label);
        QVERIFY(parsed[0].dnssec && parsed[0].noLog && parsed[0].noFilter);
        UpstreamConfig upstream;
        std::string error;
        QCOMPARE(resolvers::resolverCandidate(entry, upstream, error), !type.isEmpty());
        if (!type.isEmpty()) QCOMPARE(QString::fromStdString(upstream.type), type);
        else QVERIFY(error.find("relay") != std::string::npos);
    }

    void malformedDoesNotBecomeDnscrypt() {
        auto entry = item(0x02);
        entry.stamp = "sdns://!";
        const auto parsed = resolvers::parseMarkdown(markdown(entry));
        QCOMPARE(parsed.size(), size_t(1));
        QCOMPARE(parsed[0].protocol, std::string("Invalid"));
        UpstreamConfig upstream;
        std::string error;
        QVERIFY(!resolvers::resolverCandidate(entry, upstream, error));
    }

    void mixedSelectionIsAtomic() {
        const Config original = config();
        for (unsigned char protocol : {0x81, 0x85, 0xff}) {
            auto invalid = item(protocol);
            if (protocol == 0xff) invalid.stamp = "broken";
            for (const auto& pool : {std::optional<std::string>{}, std::optional<std::string>{"pool"}}) {
                Config candidate = original;
                std::string error;
                QVERIFY(!resolvers::importCandidate(original, {item(0x02), invalid}, pool, candidate, error));
                QCOMPARE(candidate.upstreams.size(), original.upstreams.size());
                QVERIFY(candidate.pools.empty());
                QVERIFY(!error.empty());
            }
        }
    }

    void namesMembersAndValidation() {
        Config original = config();
        Config candidate;
        std::string error;
        const auto first = item(0x02, "existing");
        const auto second = item(0x04, "existing");
        QVERIFY(resolvers::importCandidate(original, {first, second}, std::string(" pool "), candidate, error));
        QCOMPARE(candidate.upstreams[1].name, std::string("existing-2"));
        QCOMPARE(candidate.upstreams[2].name, std::string("existing-3"));
        QCOMPARE(candidate.pools[0].name, std::string("pool"));
        QCOMPARE(candidate.pools[0].servers.size(), size_t(2));
        QCOMPARE(candidate.upstreams[2].type, std::string("doq"));
        Config reused;
        QVERIFY(resolvers::importCandidate(candidate, {first, first, second}, std::string("another"), reused, error));
        QCOMPARE(reused.upstreams.size(), candidate.upstreams.size());
        QCOMPARE(reused.pools.back().servers.size(), size_t(2));
        for (const std::string name : {"", " ", "existing", "pool"}) {
            Config untouched = original;
            QVERIFY(!resolvers::importCandidate(candidate, {first, second}, name, untouched, error));
            QCOMPARE(untouched.upstreams.size(), original.upstreams.size());
        }
        QVERIFY(!resolvers::importCandidate(original, {first, first}, std::string("pool"), candidate, error));
        original.defaultTarget = "missing";
        QVERIFY(!resolvers::importCandidate(original, {first}, std::nullopt, candidate, error));
        QVERIFY(error.find("default target") != std::string::npos);
    }

    void boundedReadCompletion() {
        std::string content = "unchanged";
        std::string error;
        int calls = 0;
        QVERIFY(!resolvers::readBounded([&](std::string& chunk, bool&, std::string& err) {
            if (++calls == 1) { chunk = markdown(item(0x02)); return true; }
            err = "injected read failure";
            return false;
        }, content, error));
        QCOMPARE(content, std::string("unchanged"));
        QCOMPARE(error, std::string("injected read failure"));
        QVERIFY(!resolvers::readBounded([](std::string&, bool&, std::string&) { return true; }, content, error));
        QVERIFY(error.find("no progress") != std::string::npos);
        QVERIFY(!resolvers::readBounded([](std::string&, bool& eof, std::string&) { eof = true; return true; }, content, error));
        QVERIFY(!resolvers::readBounded([](std::string& chunk, bool& eof, std::string&) {
            chunk.assign(resolvers::kMaxListBytes + 1, 'x'); eof = true; return true;
        }, content, error));
        calls = 0;
        QVERIFY(resolvers::readBounded([&](std::string& chunk, bool& eof, std::string&) {
            chunk = ++calls == 1 ? "abc" : "def"; eof = calls == 2; return true;
        }, content, error));
        QCOMPARE(content, std::string("abcdef"));
        QVERIFY(error.empty());
    }

    void cacheRefreshAndFailurePreservation() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto path = cachePath(dir);
        const auto oldText = markdown(item(0x02, "old"));
        const auto freshText = markdown(item(0x04, "fresh"));
        std::string out;
        std::string error;
        QVERIFY(resolvers::loadList("fixture", path, true, out, error, fetched(oldText)));
        QCOMPARE(bytesAt(path).toStdString(), oldText);
        for (const auto& bad : {std::string{}, std::string("not a list"), std::string(resolvers::kMaxListBytes + 1, 'x'),
                                std::string("## invalid\nsdns://!\n")}) {
            out = "unchanged";
            QVERIFY(!resolvers::loadList("fixture", path, true, out, error, fetched(bad)));
            QCOMPARE(out, std::string("unchanged"));
            QCOMPARE(bytesAt(path).toStdString(), oldText);
            QVERIFY(!error.empty());
        }
        auto io = fetched(freshText);
        io.fetch = [](const std::string&, std::string& text, std::string& err) {
            text = markdown(item(0x02)); err = "partial fetch failed"; return false;
        };
        QVERIFY(!resolvers::loadList("fixture", path, true, out, error, io));
        QCOMPARE(bytesAt(path).toStdString(), oldText);
        io = fetched(freshText);
        io.write = [](const auto&, const auto&, std::string& err) { err = "replacement failed"; return false; };
        QVERIFY(!resolvers::loadList("fixture", path, true, out, error, io));
        QCOMPARE(bytesAt(path).toStdString(), oldText);
        QVERIFY(resolvers::loadList("fixture", path, true, out, error, fetched(freshText)));
        QCOMPARE(bytesAt(path).toStdString(), freshText);
        QVERIFY(error.empty());
        io.fetch = [](const auto&, auto&, auto&) { QTest::qFail("cache must avoid fetch", __FILE__, __LINE__); return false; };
        QVERIFY(resolvers::loadList("fixture", path, false, out, error, io));
        QCOMPARE(out, freshText);
    }

    void cacheReadErrorsAndInvalidData() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto path = cachePath(dir);
        const auto valid = markdown(item(0x02));
        std::string out, error;
        QVERIFY(resolvers::loadList("fixture", path, true, out, error, fetched(valid)));
        auto io = fetched(valid);
        io.fetch = [](const auto&, auto&, std::string& err) { err = "fetch failed"; return false; };
        io.read = [](const auto&, std::string& text, std::string& err) { text = "partial"; err = "read failed"; return false; };
        out = "unchanged";
        QVERIFY(!resolvers::loadList("fixture", path, false, out, error, io));
        QCOMPARE(out, std::string("unchanged"));
        QCOMPARE(bytesAt(path).toStdString(), valid);
        io.read = [](const auto&, std::string& text, std::string&) { text = "not markdown"; return true; };
        QVERIFY(!resolvers::loadList("fixture", path, false, out, error, io));
        QCOMPARE(error, std::string("fetch failed"));
        QFile bad(QString::fromStdWString(path.wstring()));
        QVERIFY(bad.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(bad.write("bad"), qint64(3));
        bad.close();
        QVERIFY(resolvers::loadList("fixture", path, false, out, error, fetched(valid)));
        QCOMPARE(out, valid);
        QCOMPARE(bytesAt(path).toStdString(), valid);
        QVERIFY(error.empty());
        QVERIFY(bad.open(QIODevice::WriteOnly | QIODevice::Truncate));
        bad.close();
        out = "unchanged";
        QVERIFY(!resolvers::loadList("fixture", path, false, out, error, io));
        QCOMPARE(out, std::string("unchanged"));
        QVERIFY(bytesAt(path).isEmpty());
        QVERIFY(resolvers::loadList("fixture", path, false, out, error, fetched(valid)));
        QCOMPARE(bytesAt(path).toStdString(), valid);
        io = fetched(valid);
        io.read = [](const auto&, auto&, std::string& err) { err = "unreadable"; return false; };
        QVERIFY(resolvers::loadList("fixture", path, false, out, error, io));
        QVERIFY(error.empty());
    }

    void actualReplacementFailure() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto path = cachePath(dir);
        QVERIFY(std::filesystem::create_directory(path));
        const auto sentinel = path / "keep";
        QFile file(QString::fromStdWString(sentinel.wstring()));
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("old"), qint64(3));
        file.close();
        std::string out = "unchanged", error;
        QVERIFY(!resolvers::loadList("fixture", path, true, out, error, fetched(markdown(item(0x02)))));
        QCOMPARE(bytesAt(sentinel), QByteArray("old"));
        QCOMPARE(out, std::string("unchanged"));
    }

    void multiListPartialSuccess() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        resolvers::ListIo io;
        io.fetch = [](const std::string& url, std::string& text, std::string& error) {
            if (url == resolvers::kPublicResolversUrl) { text = markdown(item(0x02)); return true; }
            error = "unavailable"; return false;
        };
        std::string error = "stale";
        auto entries = resolvers::loadAll(true, error, cachePath(dir).parent_path(), io);
        QCOMPARE(entries.size(), size_t(1));
        QVERIFY(error.empty());
        io.fetch = [](const auto&, auto&, std::string& err) { err = "all failed"; return false; };
        entries = resolvers::loadAll(true, error, cachePath(dir).parent_path(), io);
        QVERIFY(entries.empty());
        QVERIFY(error.find("all failed") != std::string::npos);
    }
};

QTEST_GUILESS_MAIN(TestPublicResolvers)
#include "test_publicresolvers.moc"
