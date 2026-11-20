#include <QtTest/QtTest>

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "transports/OdohUpstream.h"

// Test-local definition of Upstream::ping so this test links without the real
// transport translation unit (Upstream.cpp pulls in every transport and their
// crypto dependencies). The key-function definition also emits Upstream's vtable.
bool Upstream::ping(uint32_t& rttMs, std::string& error) {
    rttMs = 0;
    error = "ping is not available in tests";
    return false;
}

namespace {

std::shared_ptr<const OdohConfigSnapshot> snapshot(uint8_t marker) {
    auto config = std::make_shared<OdohConfigSnapshot>();
    config->suite = {OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128};
    config->targetKey.assign(32, marker);
    config->keyId.assign(32, static_cast<uint8_t>(marker + 1));
    config->cipher = EVP_aes_128_gcm();
    config->keyLen = 16;
    return config;
}

}  // namespace

class TestOdohSnapshot : public QObject {
    Q_OBJECT

private slots:
    // A refresh that completes while an exchange still runs must not change
    // the snapshot that exchange captured (SEC-11).
    void refreshDuringExchangeKeepsCapturedSnapshot() {
        OdohConfigSlot slot;
        slot.publish(snapshot(1));
        // Exchange start: the pointer the whole HPKE exchange keeps.
        const auto held = slot.fresh(std::chrono::seconds(300));
        QVERIFY(held);
        // Fake refresh with rotated key material while the exchange holds on.
        slot.publish(snapshot(2));
        // The exchange still reads its captured key state ...
        QCOMPARE(held->suite.kem_id, uint16_t(OSSL_HPKE_KEM_ID_X25519));
        QCOMPARE(held->targetKey, std::vector<uint8_t>(32, 1));
        QCOMPARE(held->keyId, std::vector<uint8_t>(32, 2));
        QCOMPARE(held->keyLen, size_t(16));
        QVERIFY(held->cipher == EVP_aes_128_gcm());
        // ... while later exchanges see the refreshed configuration.
        const auto current = slot.fresh(std::chrono::seconds(300));
        QVERIFY(current);
        QVERIFY(current.get() != held.get());
        QCOMPARE(current->targetKey, std::vector<uint8_t>(32, 2));
        QCOMPARE(current->keyId, std::vector<uint8_t>(32, 3));
    }

    void publishReplacesRatherThanMutates() {
        OdohConfigSlot slot;
        slot.publish(snapshot(1));
        const auto first = slot.fresh(std::chrono::seconds(300));
        slot.publish(snapshot(2));
        const auto second = slot.fresh(std::chrono::seconds(300));
        QVERIFY(first.get() != second.get());
        QCOMPARE(first->targetKey, std::vector<uint8_t>(32, 1));
        QCOMPARE(second->targetKey, std::vector<uint8_t>(32, 2));
    }

    void freshRejectsStaleAndClearedSnapshots() {
        OdohConfigSlot slot;
        QVERIFY(!slot.fresh(std::chrono::seconds(300)));  // nothing published yet
        slot.publish(snapshot(1));
        QVERIFY(slot.fresh(std::chrono::seconds(300)));
        QVERIFY(!slot.fresh(std::chrono::milliseconds(0)));  // zero max age is always stale
        slot.publish(nullptr);  // a failed refresh forgets the configuration
        QVERIFY(!slot.fresh(std::chrono::seconds(300)));
    }
};

QTEST_MAIN(TestOdohSnapshot)
#include "test_odoh.moc"
