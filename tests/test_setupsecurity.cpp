#include <windows.h>

#include <QtTest/QtTest>

#include "installer/SetupSecurity.h"

class TestSetupSecurity : public QObject {
    Q_OBJECT

private slots:
    void readExecuteIsNotWrite() {
        for (const bool root : {false, true}) {
            QVERIFY(!setup::ancestorAceAllowsMutation(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, 0, root));
            QVERIFY(!setup::ancestorAceAllowsMutation(READ_CONTROL | SYNCHRONIZE, 0, root));
            QVERIFY(!setup::ancestorAceAllowsMutation(GENERIC_READ | GENERIC_EXECUTE, 0, root));
        }
    }

    void actualMutationIsRejected() {
        for (const DWORD mask : {DWORD(GENERIC_WRITE), DWORD(GENERIC_ALL), DWORD(FILE_GENERIC_WRITE),
                                 DWORD(FILE_ALL_ACCESS), DWORD(DELETE), DWORD(WRITE_DAC), DWORD(WRITE_OWNER),
                                 DWORD(FILE_WRITE_DATA), DWORD(FILE_APPEND_DATA), DWORD(FILE_WRITE_EA),
                                 DWORD(FILE_WRITE_ATTRIBUTES), DWORD(FILE_DELETE_CHILD)}) {
            QVERIFY(setup::ancestorAceAllowsMutation(mask, 0, false));
            QVERIFY(!setup::ancestorAceAllowsMutation(mask, INHERIT_ONLY_ACE, false));
        }
    }

    void driveRootSemantics() {
        QVERIFY(!setup::ancestorAceAllowsMutation(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY, 0, true));
        QVERIFY(!setup::ancestorAceAllowsMutation(FILE_GENERIC_WRITE, 0, true));
        for (const DWORD mask : {DWORD(FILE_DELETE_CHILD), DWORD(WRITE_DAC), DWORD(WRITE_OWNER),
                                 DWORD(GENERIC_ALL), DWORD(FILE_ALL_ACCESS)}) {
            QVERIFY(setup::ancestorAceAllowsMutation(mask, 0, true));
            QVERIFY(!setup::ancestorAceAllowsMutation(mask, INHERIT_ONLY_ACE, true));
        }
        QVERIFY(setup::ancestorAceAllowsMutation(FILE_WRITE_DATA, CONTAINER_INHERIT_ACE, false));
    }
};

QTEST_APPLESS_MAIN(TestSetupSecurity)
#include "test_setupsecurity.moc"
