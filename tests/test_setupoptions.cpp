#include <QtTest/QtTest>

#include "installer/SetupOptions.h"

class TestSetupOptions : public QObject {
    Q_OBJECT

private slots:
    void defaults() {
        setup::Options options;
        options.destination = L"C:\\Default destination";
        options.logPath = L"C:\\Default.log";
        std::wstring error = L"stale error";
        QVERIFY(setup::parseOptions({}, options, error));
        QVERIFY(error.empty());
        QVERIFY(options.destination == L"C:\\Default destination");
        QVERIFY(options.logPath == L"C:\\Default.log");
        QVERIFY(options.desktop && options.startMenu && options.launch);
        QVERIFY(!options.service && !options.driver && !options.silent);
        QVERIFY(!options.acceptLicense && !options.help);
    }

    void caseAndPaths() {
        setup::Options options;
        std::wstring error;
        QVERIFY(setup::parseOptions({L"/DiR=C:\\Program Files\\9NS=Test\\\u00c9",
                                    L"/LoG=C:\\Logs\\Setup Log=A.txt", L"/DESKTOP=nO",
                                    L"/STARTMENU=NO", L"/SERVICE=YeS", L"/DRIVER=YES",
                                    L"/LAUNCH=No", L"/ACCEPTLICENSE"}, options, error));
        QVERIFY(options.destination == L"C:\\Program Files\\9NS=Test\\\u00c9");
        QVERIFY(options.logPath == L"C:\\Logs\\Setup Log=A.txt");
        QVERIFY(!options.desktop && !options.startMenu && !options.launch);
        QVERIFY(options.service && options.driver && options.acceptLicense);
        QVERIFY(setup::parseOptions({L"/desktop=yes", L"/startmenu=yes", L"/service=no",
                                    L"/driver=no", L"/launch=yes"}, options, error));
        QVERIFY(options.desktop && options.startMenu && options.launch);
        QVERIFY(!options.service && !options.driver);
        QVERIFY(options.logPath == L"C:\\Logs\\Setup Log=A.txt");
    }

    void invalidAndAtomic() {
        const std::vector<std::vector<std::wstring>> invalid = {
            {L""}, {L"/unknown"}, {L"--silent"}, {L"destination"},
            {L"/dir"}, {L"/dir="}, {L"/log"}, {L"/log="},
            {L"/silent=yes"}, {L"/acceptlicense=no"}, {L"/help=yes"}, {L"/?=yes"},
            {L"/dir=a", L"/DIR=b"}, {L"/log=a", L"/LOG=a"},
            {L"/silent", L"/SILENT"}, {L"/acceptlicense", L"/ACCEPTLICENSE"},
            {L"/help", L"/?"}, {L"/?", L"/HELP"}, {L"/silent"},
            {L"/help", L"/unknown"}
        };
        for (auto arguments : invalid) {
            setup::Options options;
            options.destination = L"original destination";
            options.logPath = L"original log";
            arguments.insert(arguments.begin(), {L"/desktop=no", L"/startmenu=no",
                                                L"/service=yes", L"/driver=yes", L"/launch=no"});
            std::wstring error;
            QVERIFY(!setup::parseOptions(arguments, options, error));
            QVERIFY(!error.empty());
            QVERIFY(options.destination == L"original destination");
            QVERIFY(options.logPath == L"original log");
            QVERIFY(options.desktop && options.startMenu && options.launch);
            QVERIFY(!options.service && !options.driver && !options.silent);
            QVERIFY(!options.acceptLicense && !options.help);
        }
        for (const auto* flag : {L"/desktop", L"/startmenu", L"/service", L"/driver", L"/launch"}) {
            for (const auto* value : {L"", L"=", L"=true", L"=1", L"=yes=no", L"= yes", L"=no "}) {
                setup::Options options;
                std::wstring error;
                QVERIFY(!setup::parseOptions({std::wstring(flag) + value}, options, error));
                QVERIFY(!error.empty());
            }
            setup::Options options;
            std::wstring error;
            QVERIFY(!setup::parseOptions({std::wstring(flag) + L"=yes",
                                         std::wstring(flag) + L"=no"}, options, error));
            QVERIFY(error.find(L"Duplicate") != std::wstring::npos);
        }
        setup::Options options;
        options.destination = L"original";
        options.logPath = L"original log";
        std::wstring error;
        QVERIFY(!setup::parseOptions({L"/dir=changed", L"/log=changed", L"/unknown"}, options, error));
        QVERIFY(options.destination == L"original" && options.logPath == L"original log");
    }

    void uninstallAndRepairModes() {
        setup::Options options;
        std::wstring error;
        QVERIFY(setup::parseOptions({L"/uninstall"}, options, error));
        QVERIFY(options.mode == setup::Mode::Uninstall);
        QVERIFY(options.keepData);
        // Removal is not licence acceptance, so /silent needs no /acceptlicense here.
        QVERIFY(setup::parseOptions({L"/UNINSTALL", L"/silent", L"/keepdata=no"}, options, error));
        QVERIFY(options.mode == setup::Mode::Uninstall);
        QVERIFY(options.silent);
        QVERIFY(!options.keepData);
        QVERIFY(setup::parseOptions({L"/repair", L"/silent"}, options, error));
        QVERIFY(options.mode == setup::Mode::Repair);
        QVERIFY(setup::parseOptions({L"/uninstall", L"/keepdata=yes"}, options, error));
        QVERIFY(options.keepData);
    }

    void uninstallRejectsInstallOptions() {
        // The two modes cannot be combined.
        setup::Options options;
        std::wstring error;
        QVERIFY(!setup::parseOptions({L"/uninstall", L"/repair"}, options, error));
        QVERIFY(!error.empty());
        // Installation component toggles make no sense when removing.
        for (const auto* flag : {L"/desktop=yes", L"/startmenu=yes", L"/service=yes",
                                 L"/driver=yes", L"/launch=yes"}) {
            setup::Options rejecting;
            std::wstring message;
            QVERIFY(!setup::parseOptions({L"/uninstall", flag}, rejecting, message));
            QVERIFY(!message.empty());
        }
        /* /keepdata only applies to uninstall. */
        setup::Options install;
        std::wstring message;
        QVERIFY(!setup::parseOptions({L"/keepdata=no"}, install, message));
        QVERIFY(!message.empty());
        setup::Options repair;
        QVERIFY(!setup::parseOptions({L"/repair", L"/keepdata=no"}, repair, message));
        QVERIFY(!message.empty());
    }

    void uninstallKeepDataValuesAndDuplicates() {
        for (const auto* value : {L"", L"=", L"=true", L"=1", L"=maybe"}) {
            setup::Options options;
            std::wstring error;
            QVERIFY(!setup::parseOptions({L"/uninstall", std::wstring(L"/keepdata") + value}, options, error));
            QVERIFY(!error.empty());
        }
        setup::Options options;
        std::wstring error;
        QVERIFY(!setup::parseOptions({L"/uninstall", L"/keepdata=yes", L"/KEEPDATA=no"}, options, error));
        QVERIFY(error.find(L"Duplicate") != std::wstring::npos);
    }

    void installStillRequiresLicenseInSilentMode() {
        // The relaxed rule must be scoped to removal modes only.
        setup::Options options;
        std::wstring error;
        QVERIFY(!setup::parseOptions({L"/silent"}, options, error));
        QVERIFY(error.find(L"/acceptlicense") != std::wstring::npos);
        QVERIFY(setup::parseOptions({L"/silent", L"/acceptlicense"}, options, error));
    }

    void licenseAndSilentLaunch() {        const std::vector<std::vector<std::wstring>> valid = {
            {L"/acceptlicense", L"/silent", L"/launch=yes"},
            {L"/launch=yes", L"/silent", L"/acceptlicense"},
            {L"/silent", L"/launch=no", L"/acceptlicense"},
            {L"/silent", L"/help"}, {L"/?", L"/silent"}
        };
        for (const auto& arguments : valid) {
            setup::Options options;
            std::wstring error;
            QVERIFY(setup::parseOptions(arguments, options, error));
            QVERIFY(options.silent);
            QVERIFY(!options.launch);
            QVERIFY(options.acceptLicense || options.help);
        }
        setup::Options options;
        std::wstring error;
        QVERIFY(!setup::parseOptions({L"/silent"}, options, error));
        QVERIFY(error.find(L"/acceptlicense") != std::wstring::npos);
        QVERIFY(!options.silent && options.launch);
        QVERIFY(setup::parseOptions({L"/HeLp"}, options, error));
        QVERIFY(options.help && options.launch);
    }

    void preservation() {
        QVERIFY(setup::preserveExistingFile(L"config.json"));
        QVERIFY(setup::preserveExistingFile(L"CONFIG.JSON"));
        QVERIFY(setup::preserveExistingFile(L"CoNfIg.JsOn"));
        for (const auto* relative : {L"", L"config.example.json", L"sub\\config.json",
                                     L"sub/config.json", L".\\config.json", L"./config.json",
                                     L"config.json.bak", L"config.json ", L" config.json",
                                     L"C:\\config.json", L"/config.json", L"config.json:stream"}) {
            QVERIFY(!setup::preserveExistingFile(relative));
        }
    }

    void previousManifest() {
        protected_paths::InstallManifest manifest;
        std::wstring error = L"stale";
        const protected_paths::InstallManifest original{{L"9ns.exe", L"config.json",
                                                        L"config.example.json", L"plugins\\old.dll"},
                                                       {L"plugins"}};
        QVERIFY(setup::parsePreviousManifest(protected_paths::buildManifestFileContent(original), manifest, error));
        QVERIFY(error.empty());
        QVERIFY(manifest.files == std::vector<std::wstring>({L"9ns.exe", L"config.example.json", L"plugins\\old.dll"}));
        QVERIFY(manifest.directories == original.directories);
        QVERIFY(setup::parsePreviousManifest("[files]\nCONFIG.JSON\n9ns.exe\n[directories]\nplugins", manifest, error));
        QVERIFY(manifest.files == std::vector<std::wstring>({L"9ns.exe"}));
        const std::vector<std::string> invalid = {
            "", "9ns.exe\n[files]\n[directories]\n", "[files]\n", "[Files]\n[directories]\n",
            "[files]\n[files]\n[directories]\n", "[files]\n[directories]\n[directories]\n",
            "[files]\na\nA\n[directories]\n", "[files]\na/b\na\\b\n[directories]\n",
            "[files]\na\n[directories]\nA\n", "[files]\n[unknown]\n[directories]\n",
            "[files]\n../evil\n[directories]\n", "[files]\nC:\\evil\n[directories]\n",
            "[files]\nbad%name\n[directories]\n", "[files]\n\xc3\xa9\n[directories]\n",
            "[files]\n9ns.exe\rjunk\n[directories]\n", "[files]\n\tbad\n[directories]\n"
        };
        for (const auto& text : invalid) {
            manifest = original;
            QVERIFY(!setup::parsePreviousManifest(text, manifest, error));
            QVERIFY(!error.empty());
            QVERIFY(manifest.files == original.files);
            QVERIFY(manifest.directories == original.directories);
        }
    }

    void mergeManifest() {
        protected_paths::InstallManifest current{{L"9ns.exe", L"CONFIG.JSON", L"new.dll"}, {L"Plugins"}};
        const protected_paths::InstallManifest previous{{L"9NS.EXE", L"config.json", L"old.dll", L"OLD.DLL",
                                                        L"config.example.json"}, {L"plugins", L"old"}};
        setup::mergePreviousManifest(previous, current);
        QVERIFY(current.files == std::vector<std::wstring>({L"9ns.exe", L"new.dll", L"old.dll", L"config.example.json"}));
        QVERIFY(current.directories == std::vector<std::wstring>({L"Plugins", L"old"}));
        const auto merged = current;
        setup::mergePreviousManifest(previous, current);
        QVERIFY(current.files == merged.files && current.directories == merged.directories);
    }
};

QTEST_APPLESS_MAIN(TestSetupOptions)
#include "test_setupoptions.moc"
