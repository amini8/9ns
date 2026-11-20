// Draft/saved/running semantics of ConfigSession: load states, dirty tracking,
// failed persistence and recovery import. Offline only: QTemporaryDir + files.

#include <QtTest/QtTest>

#include <QTemporaryDir>

#include <filesystem>
#include <fstream>
#include <string>

#include "ui/ConfigSession.h"

namespace {

std::filesystem::path writeConfig(const std::filesystem::path& dir, const std::string& name,
                                  const std::string& text) {
    const std::filesystem::path path = dir / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    return path;
}

const char* kValidOne =
    R"({"default_target": "a", "upstreams": [{"name": "a", "type": "plain", "address": "8.8.8.8"}]})";

const char* kValidTwo =
    R"({"default_target": "b", "upstreams": [{"name": "b", "type": "plain", "address": "9.9.9.9"}]})";

const char* kBrokenNextDns =
    R"({"default_target": "legacy", "upstreams": [{"name": "legacy", "type": "nextdns", "address": "https://dns.nextdns.io"}]})";

}  // namespace

class TestConfigSession : public QObject {
    Q_OBJECT

private slots:
    void missingFileIsCleanSlate();
    void validFileLoadsWithoutDirty();
    void failedLoadBlocksWritesAndKeepsDraftUsable();
    void failedLoadSurvivesSaveAttempts();
    void mutateDraftMarksDirty();
    void markDirtyAfterInPlaceEdit();
    void saveCommitsSavedState();
    void failedSaveKeepsDraftAndDirty();
    void reloadReplacesDraftOnSuccess();
    void reloadKeepsDraftOnFailure();
    void replaceFromFileBacksUpAndCommits();
    void replaceFromFileWithInvalidSourceChangesNothing();
    void replaceFromFileBacksUpFailedOriginal();
    void missingFileReloadDoesNotReportError();
    void metadataErrorKeepsDraftAndBlocksWrites();
    void metadataErrorAbortsReplacementBeforeBackup();
    void successfulOperationsClearOldErrors();
};

void TestConfigSession::missingFileIsCleanSlate() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    ConfigSession session(std::filesystem::path(dir.path().toStdString()) / "config.json");
    QCOMPARE(session.state(), ConfigSession::State::Missing);
    QVERIFY(!session.writesBlocked());
    QVERIFY(!session.isDirty());
    QVERIFY(session.loadError().isEmpty());
    QCOMPARE(session.draft().defaultTarget, defaultConfig().defaultTarget);
}

void TestConfigSession::validFileLoadsWithoutDirty() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);

    ConfigSession session(path);
    QCOMPARE(session.state(), ConfigSession::State::Loaded);
    QVERIFY(!session.isDirty());
    QVERIFY(!session.writesBlocked());
    QCOMPARE(session.draft().upstreams.size(), size_t(1));
    QCOMPARE(session.draft().upstreams.front().name, std::string("a"));
    QCOMPARE(session.saved().upstreams.front().name, std::string("a"));
}

void TestConfigSession::failedLoadBlocksWritesAndKeepsDraftUsable() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kBrokenNextDns);

    ConfigSession session(path);
    QCOMPARE(session.state(), ConfigSession::State::Failed);
    QVERIFY(session.writesBlocked());
    QVERIFY(!session.loadError().isEmpty());
    // The failure is armed: no write path may run until the file is repaired or
    // replaced, even though the draft itself is left untouched.
    QString error;
    QVERIFY(!session.save(error));
}

void TestConfigSession::failedLoadSurvivesSaveAttempts() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kBrokenNextDns);

    ConfigSession session(path);
    QVERIFY(session.writesBlocked());

    QString error;
    QVERIFY(!session.save(error));
    QVERIFY(!error.isEmpty());
    QCOMPARE(session.state(), ConfigSession::State::Failed);

    // The rejected file must be left exactly as it was.
    std::ifstream in(path, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    QVERIFY(text.find("nextdns") != std::string::npos);
}

void TestConfigSession::markDirtyAfterInPlaceEdit() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);

    ConfigSession session(path);
    QVERIFY(!session.isDirty());

    // A dialog holding a reference mutates the draft in place, then flags it.
    QSignalSpy spy(&session, &ConfigSession::changed);
    session.draft().listenPort = 5353;
    session.markDirty();
    QVERIFY(session.isDirty());
    QCOMPARE(spy.count(), 1);
    QCOMPARE(session.draft().listenPort, uint16_t(5353));
    QCOMPARE(session.saved().listenPort, defaultConfig().listenPort);
}

void TestConfigSession::mutateDraftMarksDirty() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);

    ConfigSession session(path);
    QVERIFY(!session.isDirty());

    QSignalSpy spy(&session, &ConfigSession::changed);
    session.mutateDraft([](Config& c) {
        UpstreamConfig up;
        up.name = "extra";
        up.type = "plain";
        up.address = "1.1.1.1";
        c.upstreams.push_back(up);
        c.defaultTarget = "extra";
        c.defaultUpstream = "extra";
    });
    QVERIFY(session.isDirty());
    QCOMPARE(spy.count(), 1);
    QCOMPARE(session.draft().upstreams.size(), size_t(2));
    // The saved snapshot must not move with the draft.
    QCOMPARE(session.saved().upstreams.size(), size_t(1));
}

void TestConfigSession::saveCommitsSavedState() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);

    ConfigSession session(path);
    session.mutateDraft([](Config& c) { c.defaultTarget = "a"; c.defaultUpstream = "a"; });

    QString error;
    QVERIFY2(session.save(error), qPrintable(error));
    QVERIFY(!session.isDirty());
    QCOMPARE(session.state(), ConfigSession::State::Loaded);

    // A fresh session over the same path must agree with the committed saved state.
    ConfigSession reread(path);
    QCOMPARE(reread.state(), ConfigSession::State::Loaded);
    QCOMPARE(reread.draft().upstreams.size(), size_t(1));
}

void TestConfigSession::failedSaveKeepsDraftAndDirty() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);

    ConfigSession session(path);
    // An invalid draft (no upstreams) must make save() fail validation without
    // discarding the edit or claiming success.
    session.mutateDraft([](Config& c) {
        c.upstreams.clear();
        c.listenPort = 5353;
    });

    QString error;
    QVERIFY(!session.save(error));
    QVERIFY(!error.isEmpty());
    QVERIFY(session.isDirty());
    QCOMPARE(session.draft().listenPort, uint16_t(5353));
    QVERIFY(session.draft().upstreams.empty());
    // The saved snapshot still describes the last successful write.
    QCOMPARE(session.saved().upstreams.size(), size_t(1));
}

void TestConfigSession::reloadReplacesDraftOnSuccess() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto dirPath = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(dirPath, "config.json", kValidOne);

    ConfigSession session(path);
    session.mutateDraft([](Config& c) { c.listenPort = 1234; });
    QVERIFY(session.isDirty());

    writeConfig(dirPath, "config.json", kValidTwo);
    QString error;
    QVERIFY2(session.reload(error), qPrintable(error));
    QVERIFY(!session.isDirty());
    QCOMPARE(session.draft().upstreams.front().name, std::string("b"));
    QCOMPARE(session.saved().upstreams.front().name, std::string("b"));
}

void TestConfigSession::reloadKeepsDraftOnFailure() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto dirPath = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(dirPath, "config.json", kValidOne);

    ConfigSession session(path);
    session.mutateDraft([](Config& c) { c.listenPort = 1234; });

    writeConfig(dirPath, "config.json", kBrokenNextDns);
    QString error;
    QVERIFY(!session.reload(error));
    QCOMPARE(session.state(), ConfigSession::State::Failed);
    // The pending draft is not discarded by the failed reload.
    QCOMPARE(session.draft().listenPort, uint16_t(1234));
    QVERIFY(session.isDirty());
}

void TestConfigSession::replaceFromFileBacksUpAndCommits() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto dirPath = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(dirPath, "config.json", kBrokenNextDns);
    const auto replacement = writeConfig(dirPath, "replacement.json", kValidOne);

    ConfigSession session(path);
    QCOMPARE(session.state(), ConfigSession::State::Failed);

    QString error;
    QVERIFY2(session.replaceFromFile(replacement, error), qPrintable(error));
    QCOMPARE(session.state(), ConfigSession::State::Loaded);
    QVERIFY(!session.isDirty());
    QVERIFY(!session.writesBlocked());

    const std::filesystem::path backup = std::filesystem::path(path.string() + ".replaced.bak");
    QVERIFY(std::filesystem::exists(backup));
    std::ifstream in(backup, std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    QVERIFY(text.find("nextdns") != std::string::npos);
}

void TestConfigSession::replaceFromFileWithInvalidSourceChangesNothing() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto dirPath = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(dirPath, "config.json", kValidOne);
    const auto bad = writeConfig(dirPath, "bad.json", kBrokenNextDns);

    ConfigSession session(path);
    QCOMPARE(session.state(), ConfigSession::State::Loaded);
    session.mutateDraft([](Config& c) { c.listenPort = 1234; });

    QString error;
    QVERIFY(!session.replaceFromFile(bad, error));
    QVERIFY(!error.isEmpty());
    // Disk and the in-memory draft stay exactly as they were.
    QCOMPARE(session.state(), ConfigSession::State::Loaded);
    QCOMPARE(session.draft().listenPort, uint16_t(1234));
    QVERIFY(session.isDirty());
    QVERIFY(!std::filesystem::exists(std::filesystem::path(path.string() + ".replaced.bak")));
}

void TestConfigSession::replaceFromFileBacksUpFailedOriginal() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto dirPath = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(dirPath, "config.json", "{not json");
    const auto replacement = writeConfig(dirPath, "replacement.json", kValidTwo);

    ConfigSession session(path);
    QCOMPARE(session.state(), ConfigSession::State::Failed);

    QString error;
    QVERIFY2(session.replaceFromFile(replacement, error), qPrintable(error));
    QVERIFY(std::filesystem::exists(std::filesystem::path(path.string() + ".replaced.bak")));
    QCOMPARE(session.draft().upstreams.front().name, std::string("b"));
}

void TestConfigSession::missingFileReloadDoesNotReportError() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = std::filesystem::path(dir.path().toStdString()) / "config.json";

    ConfigSession session(path);
    QString error;
    QVERIFY2(session.reload(error), qPrintable(error));
    QVERIFY(error.isEmpty());
    QCOMPARE(session.state(), ConfigSession::State::Missing);
}

void TestConfigSession::metadataErrorKeepsDraftAndBlocksWrites() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = writeConfig(std::filesystem::path(dir.path().toStdString()), "config.json", kValidOne);
    bool deny = false;
    ConfigSession session(path, nullptr, [&deny](const auto& p, std::error_code& ec) {
        if (deny) {
            ec = std::make_error_code(std::errc::permission_denied);
            return false;
        }
        return std::filesystem::exists(p, ec);
    });
    session.mutateDraft([](Config& c) { c.listenPort = 5353; });
    QSignalSpy spy(&session, &ConfigSession::changed);
    deny = true;
    QString error;
    QVERIFY(!session.reload(error));
    QVERIFY(error.contains(QStringLiteral("config.json")));
    QCOMPARE(session.state(), ConfigSession::State::Failed);
    QCOMPARE(session.loadError(), error);
    QCOMPARE(spy.count(), 1);
    QVERIFY(session.isDirty());
    QCOMPARE(session.draft().listenPort, uint16_t(5353));
    QCOMPARE(session.saved().listenPort, defaultConfig().listenPort);
    QVERIFY(!session.save(error));
    QCOMPARE(loadConfig(path).listenPort, defaultConfig().listenPort);
    deny = false;
    QVERIFY(session.reload(error));
    QVERIFY(error.isEmpty());
    QVERIFY(!session.writesBlocked());
}

void TestConfigSession::metadataErrorAbortsReplacementBeforeBackup() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto root = std::filesystem::path(dir.path().toStdString());
    const auto path = writeConfig(root, "config.json", kValidOne);
    const auto replacement = writeConfig(root, "replacement.json", kValidTwo);
    bool deny = false;
    ConfigSession session(path, nullptr, [&deny](const auto& p, std::error_code& ec) {
        if (deny) {
            ec = std::make_error_code(std::errc::io_error);
            return false;
        }
        return std::filesystem::exists(p, ec);
    });
    session.mutateDraft([](Config& c) { c.listenPort = 5353; });
    QSignalSpy spy(&session, &ConfigSession::changed);
    deny = true;
    QString error;
    QVERIFY(!session.replaceFromFile(replacement, error));
    QVERIFY(!error.isEmpty());
    QCOMPARE(spy.count(), 0);
    QCOMPARE(session.state(), ConfigSession::State::Loaded);
    QVERIFY(session.isDirty());
    QCOMPARE(session.draft().listenPort, uint16_t(5353));
    QCOMPARE(session.saved().upstreams.front().name, std::string("a"));
    QCOMPARE(loadConfig(path).upstreams.front().name, std::string("a"));
    QVERIFY(!std::filesystem::exists(root / "config.json.replaced.bak"));
}

void TestConfigSession::successfulOperationsClearOldErrors() {
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto root = std::filesystem::path(dir.path().toStdString());
    ConfigSession session(root / "config.json");
    QString error = QStringLiteral("old missing-file error");
    QVERIFY(session.reload(error));
    QVERIFY(error.isEmpty());
    error = QStringLiteral("old save error");
    QVERIFY(session.save(error));
    QVERIFY(error.isEmpty());
    const auto replacement = writeConfig(root, "replacement.json", kValidTwo);
    error = QStringLiteral("old import error");
    QVERIFY(session.replaceFromFile(replacement, error));
    QVERIFY(error.isEmpty());
}

QTEST_GUILESS_MAIN(TestConfigSession)
#include "test_configsession.moc"
