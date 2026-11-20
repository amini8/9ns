#include <QtTest/QtTest>

#include <QFile>
#include <QTemporaryDir>

#include "core/Rules.h"

class TestRules : public QObject {
    Q_OBJECT

private slots:
    void domainListsAndHostsAliases() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath("hosts.txt");
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        const QByteArray contents =
            "\n \t\r\n# comment.example\n \t# indented.example\n"
            "Ads.Example.COM. # ignored.example\n"
            "\ttracker.example\t\r\n"
            "localhost\n"
            "0.0.0.0 V4.Example. alias4.example # ignored4.example\n"
            "127.0.0.1 loopback.example\n"
            "::1 V6.Example. alias6.example\n"
            "2001:db8::1 global6.example\n"
            "::ffff:192.0.2.1 mapped.example\n"
            "0.0.0.0\n::1\n";
        QCOMPARE(file.write(contents), qint64(contents.size()));
        file.close();
        RuleConfig rule;
        rule.name = "blocklist";
        rule.hostsFile = path.toStdString();
        Rules rules({rule});
        for (const auto* name : {"ads.example.com", "ADS.EXAMPLE.COM.", "tracker.example",
                                 "localhost", "v4.example", "alias4.example", "loopback.example",
                                 "v6.example", "alias6.example", "global6.example", "mapped.example"}) {
            const RuleConfig* found = rules.find(name);
            QVERIFY2(found, name);
            QCOMPARE(found->name, rule.name);
        }
        for (const auto* name : {"comment.example", "indented.example", "ignored.example",
                                 "ignored4.example", "0.0.0.0", "::1", "unlisted.example",
                                 "sub.ads.example.com"}) {
            QVERIFY2(!rules.find(name), name);
        }
    }

    void malformedAddressesAreNotHostsPrefixes() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.filePath("malformed.txt");
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        const QByteArray contents =
            "999.1.2.3 ignored-v4.example\n"
            "2001:db8:::1 ignored-v6.example\n"
            "not-an-ip ignored-text.example\n"
            "domain.example ignored-domain.example\n";
        QCOMPARE(file.write(contents), qint64(contents.size()));
        file.close();
        RuleConfig rule;
        rule.hostsFile = path.toStdString();
        Rules rules({rule});
        for (const auto* name : {"ignored-v4.example", "ignored-v6.example", "ignored-text.example",
                                 "ignored-domain.example"}) {
            QVERIFY2(!rules.find(name), name);
        }
        // Non-address first tokens retain the domain-list interpretation.
        QVERIFY(rules.find("999.1.2.3"));
        QVERIFY(rules.find("not-an-ip"));
        QVERIFY(rules.find("domain.example"));
    }

    void missingFileStillLeavesPatternsUsable() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        RuleConfig rule;
        rule.hostsFile = dir.filePath("missing.txt").toStdString();
        rule.hostnames = {"*.Example.COM."};
        Rules rules({rule});
        QVERIFY(rules.find("example.com"));
        QVERIFY(rules.find("sub.example.com"));
        QVERIFY(!rules.find("other.example"));
    }

    void interfaceBoundRulesFailClosedOnUnknownInterface() {
        RuleConfig bound;
        bound.name = "vpn-only";
        bound.hostnames = {"*.Example.COM."};
        bound.interfaceGuid = "{vpn-guid}";
        Rules rules({bound});

        // An unknown originating interface never matches a bound rule.
        QVERIFY(!rules.find("example.com"));
        QVERIFY(!rules.find("sub.example.com", 0));
        QVERIFY(!rules.find("example.com", 0, ""));
        // A different interface never matches either.
        QVERIFY(!rules.find("example.com", 0, "{other-guid}"));
        // Only the exact bound interface matches.
        QVERIFY(rules.find("example.com", 0, "{vpn-guid}"));
        QVERIFY(rules.find("sub.example.com", 0, "{VPN-GUID}"));
    }

    void unboundRulesMatchRegardlessOfInterface() {
        RuleConfig open;
        open.name = "open";
        open.hostnames = {"example.com"};
        Rules rules({open});
        QVERIFY(rules.find("example.com"));
        QVERIFY(rules.find("example.com", 0, "{any-guid}"));
    }
};

QTEST_GUILESS_MAIN(TestRules)
#include "test_rules.moc"
