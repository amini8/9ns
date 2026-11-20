#include <windows.h>

#include <algorithm>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest/QtTest>

#include "core/ProtectedDirectory.h"

namespace setup_test {
bool plan(const std::wstring& src, const std::wstring& relative, const std::wstring& dest,
          const protected_paths::InstallManifest& previous, protected_paths::InstallManifest& manifest,
          std::wstring& error);
bool place(const std::wstring& src, const std::wstring& relative, const std::wstring& dest, std::wstring& error);
bool writeRecovery(const std::wstring& dest, protected_paths::InstallManifest& manifest, std::wstring& error);
bool readRecovery(const std::wstring& dest, protected_paths::InstallManifest& manifest, std::wstring& error);
}

namespace {
std::wstring nativePath(const QString& path) {
    return QDir::toNativeSeparators(path).toStdWString();
}

bool writeFile(const QString& path, const QByteArray& bytes) {
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size();
}

QByteArray readFile(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}

bool contains(const std::vector<std::wstring>& entries, const std::wstring& entry) {
    return std::find(entries.begin(), entries.end(), entry) != entries.end();
}

class FileLock {
public:
    explicit FileLock(const QString& path)
        : handle_(CreateFileW(nativePath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
    ~FileLock() { close(); }
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    bool isValid() const { return handle_ != INVALID_HANDLE_VALUE; }
    void close() {
        if (isValid()) CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
private:
    HANDLE handle_;
};
}

class TestSetupFiles : public QObject {
    Q_OBJECT
private slots:
    void recoveryCommittedBeforePayloadPlacement() {
        QTemporaryDir staging, destination;
        QVERIFY(staging.isValid());
        QVERIFY(destination.isValid());
        const QString source = staging.filePath("9ns.exe");
        const QString target = destination.filePath("9ns.exe");
        QVERIFY(writeFile(source, "fake executable bytes"));
        protected_paths::InstallManifest manifest;
        std::wstring error;
        const auto dest = nativePath(destination.path());
        QVERIFY(setup_test::plan(nativePath(source), L"9ns.exe", dest, {}, manifest, error));
        QVERIFY(contains(manifest.files, L"9ns.exe"));
        QVERIFY(setup_test::writeRecovery(dest, manifest, error));
        QVERIFY(!QFile::exists(target));
        QCOMPARE(readFile(source), QByteArray("fake executable bytes"));
        QVERIFY(QFile::exists(destination.filePath("uninstall.bat")));
        protected_paths::InstallManifest recovered;
        QVERIFY(setup_test::readRecovery(dest, recovered, error));
        QVERIFY(recovered.files == manifest.files);
        QVERIFY(recovered.directories == manifest.directories);
        protected_paths::InstallManifest retry;
        QVERIFY(setup_test::plan(nativePath(source), L"9ns.exe", dest, recovered, retry, error));
        QVERIFY(contains(retry.files, L"9ns.exe"));
        QVERIFY(setup_test::place(nativePath(source), L"9ns.exe", dest, error));
        QCOMPARE(readFile(target), QByteArray("fake executable bytes"));
        QVERIFY(!QFile::exists(source));
    }

    void lockedPayloadCanBeRetriedWithCommittedManifest() {
        QTemporaryDir staging, destination;
        QVERIFY(staging.isValid());
        QVERIFY(destination.isValid());
        const QString source = staging.filePath("9ns.exe");
        const QString target = destination.filePath("9ns.exe");
        QVERIFY(writeFile(source, "new payload"));
        QVERIFY(writeFile(target, "original payload"));
        const auto dest = nativePath(destination.path());
        protected_paths::InstallManifest previous, manifest;
        previous.files = {L"9ns.exe"};
        std::wstring error;
        QVERIFY(setup_test::plan(nativePath(source), L"9ns.exe", dest, previous, manifest, error));
        QVERIFY(setup_test::writeRecovery(dest, manifest, error));
        const QString manifestPath = destination.filePath("install-manifest.txt");
        const QByteArray committed = readFile(manifestPath);
        QVERIFY(!committed.isEmpty());
        FileLock lock(target);
        QVERIFY(lock.isValid());
        QVERIFY(!setup_test::place(nativePath(source), L"9ns.exe", dest, error));
        QVERIFY(!error.empty());
        QCOMPARE(readFile(target), QByteArray("original payload"));
        QCOMPARE(readFile(source), QByteArray("new payload"));
        QCOMPARE(readFile(manifestPath), committed);
        protected_paths::InstallManifest recovered;
        QVERIFY(setup_test::readRecovery(dest, recovered, error));
        QVERIFY(recovered.files == manifest.files);
        lock.close();
        error.clear();
        QVERIFY(setup_test::place(nativePath(source), L"9ns.exe", dest, error));
        QCOMPARE(readFile(target), QByteArray("new payload"));
        QVERIFY(!QFile::exists(source));
        QCOMPARE(readFile(manifestPath), committed);
        protected_paths::InstallManifest afterRetry;
        QVERIFY(setup_test::readRecovery(dest, afterRetry, error));
        QVERIFY(afterRetry.files == recovered.files);
    }

    void rootConfigurationIsPreservedAndNeverOwned() {
        QTemporaryDir staging, destination;
        QVERIFY(staging.isValid());
        QVERIFY(destination.isValid());
        const QString source = staging.filePath("config.json");
        const QString target = destination.filePath("config.json");
        const QByteArray original = "{\"user\":true}\r\n";
        QVERIFY(writeFile(source, "{\"default\":true}"));
        QVERIFY(writeFile(target, original));
        const auto dest = nativePath(destination.path());
        protected_paths::InstallManifest manifest;
        std::wstring error;
        const QString executable = staging.filePath("9ns.exe");
        QVERIFY(writeFile(executable, "fake executable"));
        QVERIFY(setup_test::plan(nativePath(executable), L"9ns.exe", dest, {}, manifest, error));
        QVERIFY(setup_test::plan(nativePath(source), L"config.json", dest, {}, manifest, error));
        QVERIFY(!contains(manifest.files, L"config.json"));
        QVERIFY(setup_test::writeRecovery(dest, manifest, error));
        QVERIFY(setup_test::place(nativePath(source), L"config.json", dest, error));
        QCOMPARE(readFile(target), original);
        QVERIFY(!QFile::exists(source));
        const QByteArray manifestBytes = readFile(destination.filePath("install-manifest.txt"));
        const QByteArray scriptBytes = readFile(destination.filePath("uninstall.bat"));
        QVERIFY(!manifestBytes.isEmpty());
        QVERIFY(!scriptBytes.isEmpty());
        QVERIFY(!manifestBytes.contains("config.json"));
        QVERIFY(!scriptBytes.contains("config.json"));
        protected_paths::InstallManifest recovered;
        QVERIFY(setup_test::readRecovery(dest, recovered, error));
        QVERIFY(!contains(recovered.files, L"config.json"));
    }

    void unownedCollisionIsRejectedWithoutOverwrite() {
        QTemporaryDir staging, destination;
        QVERIFY(staging.isValid());
        QVERIFY(destination.isValid());
        const QString source = staging.filePath("library.dll");
        const QString target = destination.filePath("library.dll");
        QVERIFY(writeFile(source, "new library"));
        QVERIFY(writeFile(target, "unowned library"));
        protected_paths::InstallManifest manifest;
        std::wstring error;
        QVERIFY(!setup_test::plan(nativePath(source), L"library.dll", nativePath(destination.path()),
                                  {}, manifest, error));
        QVERIFY(QString::fromStdWString(error).contains(QStringLiteral("library.dll")));
        QVERIFY(manifest.files.empty());
        QCOMPARE(readFile(target), QByteArray("unowned library"));
        QCOMPARE(readFile(source), QByteArray("new library"));
        QVERIFY(!QFile::exists(destination.filePath("install-manifest.txt")));
        QVERIFY(!QFile::exists(destination.filePath("uninstall.bat")));
    }

    void lockedManifestReplacementIsAtomicAndCleansTemps() {
        QTemporaryDir destination;
        QVERIFY(destination.isValid());
        const auto dest = nativePath(destination.path());
        protected_paths::InstallManifest original;
        original.files = {L"9ns.exe", L"old.dll"};
        std::wstring error;
        QVERIFY(setup_test::writeRecovery(dest, original, error));
        const QString manifestPath = destination.filePath("install-manifest.txt");
        const QString scriptPath = destination.filePath("uninstall.bat");
        const QByteArray manifestBytes = readFile(manifestPath);
        const QByteArray scriptBytes = readFile(scriptPath);
        QVERIFY(!manifestBytes.isEmpty());
        QVERIFY(!scriptBytes.isEmpty());
        const QStringList entries = QDir(destination.path()).entryList(QDir::Files | QDir::Hidden);
        FileLock lock(manifestPath);
        QVERIFY(lock.isValid());
        protected_paths::InstallManifest replacement;
        replacement.files = {L"9ns.exe", L"new.dll"};
        QVERIFY(!setup_test::writeRecovery(dest, replacement, error));
        QVERIFY(!error.empty());
        QCOMPARE(readFile(manifestPath), manifestBytes);
        QCOMPARE(readFile(scriptPath), scriptBytes);
        QCOMPARE(QDir(destination.path()).entryList(QDir::Files | QDir::Hidden), entries);
        protected_paths::InstallManifest recovered;
        QVERIFY(setup_test::readRecovery(dest, recovered, error));
        QVERIFY(recovered.files == original.files);
        lock.close();
        error.clear();
        QVERIFY(setup_test::writeRecovery(dest, replacement, error));
        QCOMPARE(readFile(manifestPath), QByteArray::fromStdString(protected_paths::buildManifestFileContent(replacement)));
        QVERIFY(readFile(manifestPath) != manifestBytes);
        QVERIFY(readFile(scriptPath) != scriptBytes);
        QCOMPARE(QDir(destination.path()).entryList(QDir::Files | QDir::Hidden), entries);
        protected_paths::InstallManifest afterRetry;
        QVERIFY(setup_test::readRecovery(dest, afterRetry, error));
        QVERIFY(afterRetry.files == replacement.files);
    }
};

QTEST_APPLESS_MAIN(TestSetupFiles)
#include "test_setupfiles.moc"
