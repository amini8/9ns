#include <QtTest/QtTest>

#include "core/ProtectedDirectory.h"

using protected_paths::policyFail;
using protected_paths::policyPass;
using protected_paths::PolicyResult;

class TestProtectedPaths : public QObject {
    Q_OBJECT

private slots:
    void absoluteLocalPathShape() {
        QVERIFY(protected_paths::isLocalAbsolutePath(L"C:\\x"));
        QVERIFY(protected_paths::isLocalAbsolutePath(L"d:/x"));
        QVERIFY(!protected_paths::isLocalAbsolutePath(L"C:x"));        // drive-relative
        QVERIFY(!protected_paths::isLocalAbsolutePath(L"\\x"));        // rooted, no drive
        QVERIFY(!protected_paths::isLocalAbsolutePath(L"\\\\server\\x"));  // UNC
        QVERIFY(!protected_paths::isLocalAbsolutePath(L"\\\\?\\C:\\x"));   // device
        QVERIFY(!protected_paths::isLocalAbsolutePath(L"relative\\x"));
        QVERIFY(protected_paths::isDriveRoot(L"C:\\"));
        QVERIFY(!protected_paths::isDriveRoot(L"C:\\x"));
    }

    void segmentValidation() {
        QVERIFY(protected_paths::validateSegment(L"9ns").ok);
        QVERIFY(protected_paths::validateSegment(L"9ns-windows-x64").ok);
        QVERIFY(protected_paths::validateSegment(L"NineNsFlt.inf").ok);
        QVERIFY(!protected_paths::validateSegment(L"").ok);
        QVERIFY(!protected_paths::validateSegment(L"..").ok);
        QVERIFY(!protected_paths::validateSegment(L".").ok);
        QVERIFY(protected_paths::validateSegment(L"a..b").ok);
        QVERIFY(!protected_paths::validateSegment(L"trailing.").ok);
        QVERIFY(!protected_paths::validateSegment(L"trailing ").ok);
        QVERIFY(!protected_paths::validateSegment(L"bad:name").ok);
        QVERIFY(!protected_paths::validateSegment(L"bad\"name").ok);
        QVERIFY(!protected_paths::validateSegment(L"bad*name").ok);
        QVERIFY(!protected_paths::validateSegment(L"bad\tname").ok);
        QVERIFY(!protected_paths::validateSegment(L"CON").ok);
        QVERIFY(!protected_paths::validateSegment(L"nul").ok);
        QVERIFY(!protected_paths::validateSegment(L"COM1").ok);
        QVERIFY(!protected_paths::validateSegment(L"lpt9").ok);
        QVERIFY(!protected_paths::validateSegment(L"nul.txt").ok);
        QVERIFY(protected_paths::validateSegment(L"COM10").ok);
    }

    void installDestinationPolicy() {
        QVERIFY(protected_paths::validateInstallDestination(L"C:\\Program Files\\9NS").ok);
        QVERIFY(protected_paths::validateInstallDestination(L"D:\\Apps\\9NS").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\9NS").ok);  // one level only
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Users").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Users\\Public").ok);  // shared root
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\ProgramData").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Windows").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Program Files").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Temp").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"\\\\server\\share\\9NS").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Tools\\..\\Windows").ok);
        QVERIFY(!protected_paths::validateInstallDestination(L"C:\\Tools\\stream:x").ok);
    }

    void runtimeDataPathPolicy() {
        QVERIFY(protected_paths::validateRuntimeDataPath(L"C:\\ProgramData\\9NS", L"C:\\ProgramData").ok);
        QVERIFY(!protected_paths::validateRuntimeDataPath(L"C:\\ProgramData", L"C:\\ProgramData").ok);
        QVERIFY(!protected_paths::validateRuntimeDataPath(L"C:\\ProgramData\\9NS\\logs", L"C:\\ProgramData").ok);
        QVERIFY(!protected_paths::validateRuntimeDataPath(L"C:\\Other\\9NS", L"C:\\ProgramData").ok);
        QVERIFY(!protected_paths::validateRuntimeDataPath(L"C:\\ProgramData\\..\\9NS", L"C:\\ProgramData").ok);
    }

    void pathContainment() {
        QVERIFY(protected_paths::isContainedPath(L"C:\\a\\b", L"C:\\a\\b"));
        QVERIFY(protected_paths::isContainedPath(L"C:\\a\\b", L"C:\\a\\b\\c"));
        QVERIFY(!protected_paths::isContainedPath(L"C:\\a\\b", L"C:\\a\\bc"));
        QVERIFY(!protected_paths::isContainedPath(L"C:\\a\\b", L"C:\\a"));
        QVERIFY(protected_paths::isContainedPath(L"C:\\A\\B", L"c:\\a\\b\\c"));  // case/separator stable
        QVERIFY(!protected_paths::isContainedPath(L"C:\\a\\b", L"C:\\a\\b\\..\\..\\x"));
    }

    void commandLineQuoting() {
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"")), QStringLiteral("\"\""));
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"simple")), QStringLiteral("simple"));
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"a b")), QStringLiteral("\"a b\""));
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"a\"b")), QStringLiteral("\"a\\\"b\""));
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"C:\\dir with space\\")),
                 QStringLiteral("\"C:\\dir with space\\\\\""));
        QCOMPARE(QString::fromStdWString(protected_paths::quoteCommandLineArgument(L"C:\\Program Files\\9NS")),
                 QStringLiteral("\"C:\\Program Files\\9NS\""));
    }

    void netshValueSafety() {
        QVERIFY(protected_paths::isSafeNetshValue(L"Ethernet 2"));
        QVERIFY(protected_paths::isSafeNetshValue(L"Wi-Fi"));
        QVERIFY(!protected_paths::isSafeNetshValue(L""));
        QVERIFY(!protected_paths::isSafeNetshValue(L"evil\"name"));
        QVERIFY(!protected_paths::isSafeNetshValue(L"evil\nname"));
        QVERIFY(protected_paths::isSafeAddressToken(L"192.0.2.1"));
        QVERIFY(protected_paths::isSafeAddressToken(L"2001:db8::1"));
        QVERIFY(!protected_paths::isSafeAddressToken(L""));
        QVERIFY(!protected_paths::isSafeAddressToken(L"1.2.3.4 & calc"));
        QVERIFY(!protected_paths::isSafeAddressToken(L"..\\evil"));
    }

    void stagingNames() {
        const std::wstring name = protected_paths::makeStagingName("0123456789abcdef0123456789abcdef");
        QCOMPARE(QString::fromStdWString(name),
                 QStringLiteral("9ns-staging-0123456789abcdef0123456789abcdef"));
        QVERIFY(protected_paths::validateStagingName(name).ok);
        QVERIFY(!protected_paths::validateStagingName(L"9ns-staging-").ok);
        QVERIFY(!protected_paths::validateStagingName(L"9ns-staging-zzzz").ok);
        QVERIFY(!protected_paths::validateStagingName(L"other-0123456789abcdef0123456789abcdef").ok);
        QVERIFY(!protected_paths::validateStagingName(L"9ns-staging-0123456789abcdef0123456789abcde").ok);
        QVERIFY(!protected_paths::validateStagingName(L"9ns-staging-0123456789abcdef0123456789abcdeff").ok);
    }
};

QTEST_GUILESS_MAIN(TestProtectedPaths)
#include "test_protectedpaths.moc"
