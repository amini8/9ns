#include <QtTest/QtTest>

#include <algorithm>

#include "core/ProtectedDirectory.h"

using protected_paths::DeletionPlan;
using protected_paths::InstallManifest;

namespace {

bool contains(const std::vector<std::wstring>& list, const std::wstring& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

}  // namespace

class TestInstallerPolicy : public QObject {
    Q_OBJECT

private slots:
    void manifestEntryValidation() {
        QVERIFY(protected_paths::validateManifestEntry(L"9ns.exe").ok);
        QVERIFY(protected_paths::validateManifestEntry(L"driver\\NineNsFlt.sys").ok);
        QVERIFY(protected_paths::validateManifestEntry(L"platforms\\qwindows.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"..\\evil.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"\\abs.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"C:\\abs.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"sub\\..\\evil.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"bad%var.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"bad!name.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"bad:name.dll").ok);
        QVERIFY(!protected_paths::validateManifestEntry(L"caf\u00e9.dll").ok);  // non-ASCII
    }

    void deletionPlanIsContainedAndOrdered() {
        InstallManifest manifest;
        manifest.files = {L"9ns.exe", L"driver\\NineNsFlt.sys", L"install-manifest.txt"};
        manifest.directories = {L"driver", L"platforms", L"platforms\\imageformats"};
        DeletionPlan plan;
        const auto result = protected_paths::planManifestDeletions(manifest, L"C:\\Program Files\\9NS", plan);
        QVERIFY(result.ok);
        QCOMPARE(plan.files.size(), size_t(3));
        QVERIFY(contains(plan.files, L"c:\\program files\\9ns\\9ns.exe"));
        QVERIFY(contains(plan.files, L"c:\\program files\\9ns\\driver\\ninensflt.sys"));
        QVERIFY(contains(plan.files, L"c:\\program files\\9ns\\install-manifest.txt"));
        // Deepest directory first so plain rd works bottom-up.
        QCOMPARE(plan.directories.size(), size_t(3));
        QCOMPARE(QString::fromStdWString(plan.directories[0]),
                 QStringLiteral("c:\\program files\\9ns\\platforms\\imageformats"));
    }

    void deletionPlanRefusesEscapes() {
        InstallManifest bad;
        bad.files = {L"..\\outside.txt"};
        DeletionPlan plan;
        QVERIFY(!protected_paths::planManifestDeletions(bad, L"C:\\Program Files\\9NS", plan).ok);
        QCOMPARE(plan.files.size(), size_t(0));

        InstallManifest badRoot;
        badRoot.files = {L"9ns.exe"};
        QVERIFY(!protected_paths::planManifestDeletions(badRoot, L"C:\\", plan).ok);
    }

    void uninstallScriptRemovesOnlyManifestEntries() {
        InstallManifest manifest;
        manifest.files = {L"9ns.exe", L"Qt6Core.dll", L"install-manifest.txt"};
        manifest.directories = {L"driver", L"platforms"};
        const std::wstring script = protected_paths::buildUninstallScript(manifest);
        QVERIFY(!script.empty());
        const QString text = QString::fromStdWString(script);

        // Product files are removed by explicit, quoted del lines.
        QVERIFY(text.contains(QStringLiteral("del /f /q \"%~dp09ns.exe\"")));
        QVERIFY(text.contains(QStringLiteral("del /f /q \"%~dp0Qt6Core.dll\"")));
        QVERIFY(text.contains(QStringLiteral("del /f /q \"%~dp0install-manifest.txt\"")));
        // Directories use a plain rd, never a recursive one: unknown files win.
        QVERIFY(text.contains(QStringLiteral("rd \"%~dp0driver\"")));
        QVERIFY(text.contains(QStringLiteral("rd \"%~dp0platforms\"")));
        QVERIFY(!text.contains(QStringLiteral("rd /s")));
        QVERIFY(!text.contains(QStringLiteral("rd /q")));
        QVERIFY(!text.contains(QStringLiteral("powershell")));
        QVERIFY(!text.contains(QStringLiteral("move ")));
        // The script deletes only itself at the end.
        QVERIFY(text.contains(QStringLiteral("del /f /q \"%~dp0uninstall.bat\"")));
        // Service, driver and registry cleanup stays.
        QVERIFY(text.contains(QStringLiteral("--uninstall-service")));
        QVERIFY(text.contains(QStringLiteral("sc.exe delete NineNsFlt")));
        QVERIFY(text.contains(QStringLiteral("reg delete")));
    }

    void uninstallScriptRefusesBadManifest() {
        InstallManifest manifest;
        manifest.files = {L"..\\evil.dll"};
        QVERIFY(protected_paths::buildUninstallScript(manifest).empty());
    }

    void manifestFileContent() {
        InstallManifest manifest;
        manifest.files = {L"9ns.exe"};
        manifest.directories = {L"driver"};
        const std::string content = protected_paths::buildManifestFileContent(manifest);
        QVERIFY(content.find("[files]\r\n9ns.exe\r\n") != std::string::npos);
        QVERIFY(content.find("[directories]\r\ndriver\r\n") != std::string::npos);
    }

    void uninstallStringUsesAbsolutePath() {
        const std::wstring command = protected_paths::buildUninstallString(
            L"C:\\Windows\\System32\\cmd.exe", L"C:\\Program Files\\9NS\\uninstall.bat");
        QCOMPARE(QString::fromStdWString(command),
                 QStringLiteral("C:\\Windows\\System32\\cmd.exe /c \"\"C:\\Program Files\\9NS\\uninstall.bat\"\""));

        const std::wstring quoted = protected_paths::buildUninstallString(
            L"C:\\Program Files\\cmd.exe", L"C:\\Program Files\\9NS\\uninstall.bat");
        QCOMPARE(QString::fromStdWString(quoted),
                 QStringLiteral("\"C:\\Program Files\\cmd.exe\" /c \"\"C:\\Program Files\\9NS\\uninstall.bat\"\""));
    }
};

QTEST_GUILESS_MAIN(TestInstallerPolicy)
#include "test_installerpolicy.moc"
