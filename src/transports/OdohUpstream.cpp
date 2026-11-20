#include "transports/OdohUpstream.h"

#include <windows.h>
#include <winhttp.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/hpke.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "core/DnsMessage.h"
#include "core/Text.h"

#pragma comment(lib, "winhttp.lib")

namespace {

constexpr int kTimeoutMs = 3000;
constexpr size_t kMaxHttpReply = 65535;
constexpr uint16_t kOdohVersion = 0x0001;
constexpr size_t kKeyIdLen = 32;   // Nh of HKDF-SHA256
constexpr size_t kQueryPadBlock = 128;
constexpr auto kConfigTtl = std::chrono::seconds(300);

const char kMediaType[] = "application/oblivious-dns-message";
const char kConfigPath[] = "/.well-known/odohconfigs";
const char kHpkeInfoQuery[] = "odoh query";
const char kLabelResponse[] = "odoh response";
const char kLabelKeyId[] = "odoh key id";
const char kLabelKey[] = "odoh key";
const char kLabelNonce[] = "odoh nonce";

#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 133
#define WINHTTP_PROTOCOL_FLAG_HTTP2 0x1
#endif
#ifndef WINHTTP_OPTION_RESOLUTION_HOSTNAME
#define WINHTTP_OPTION_RESOLUTION_HOSTNAME 165
#endif

// Closes a WinHTTP handle on destruction.
class WinHttpHandle {
public:
    explicit WinHttpHandle(HINTERNET handle) : handle_(handle) {}
    ~WinHttpHandle() {
        if (handle_) {
            WinHttpCloseHandle(handle_);
        }
    }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    HINTERNET get() const { return handle_; }
    void reset(HINTERNET handle) {
        if (handle_) {
            WinHttpCloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HINTERNET handle_;
};

struct Url {
    std::wstring host;
    std::wstring path;
    std::string host8;
    std::string path8;
    INTERNET_PORT port = 443;
};

// Splits an https URL into host, port and path using WinHTTP.
bool parseUrl(const std::string& url, Url& out, std::string& error) {
    const std::wstring wide = widen(url);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts)) {
        error = "ODoH URL '" + url + "' is not valid";
        return false;
    }
    if (parts.nScheme != INTERNET_SCHEME_HTTPS) {
        error = "ODoH URL '" + url + "' must use https";
        return false;
    }
    out.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    out.host8.assign(url.begin(), url.end());
    out.port = parts.nPort;
    out.path.clear();
    if (parts.dwUrlPathLength > 0) {
        out.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    }
    if (parts.dwExtraInfoLength > 0) {
        out.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    }
    if (out.path.empty()) {
        out.path = L"/";
    }
    out.host8 = std::string(out.host.begin(), out.host.end());
    out.path8 = std::string(out.path.begin(), out.path.end());
    return true;
}

// Percent-encodes a value for use in a query string.
std::string urlEncode(const std::string& value) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
            c == '_' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        }
    }
    return out;
}

// Sends one HTTPS request and reads the reply body.
bool httpRequest(const Url& url, const std::wstring& method, const std::string& contentType,
                 const std::vector<uint8_t>* body, const std::vector<std::string>& bootstrapIps,
                 DWORD& status, std::vector<uint8_t>& reply, std::string& error) {
    WinHttpHandle session(WinHttpOpen(L"9NS/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.get()) {
        error = "cannot open HTTP session (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    WinHttpSetTimeouts(session.get(), kTimeoutMs, kTimeoutMs, kTimeoutMs, kTimeoutMs);

    // The connection always uses the URL hostname so TLS SNI and certificate
    // verification check that identity. Bootstrap mode only redirects name
    // resolution: WINHTTP_OPTION_RESOLUTION_HOSTNAME (request handle, Windows
    // 10 21H1+) resolves the hostname to the bootstrap address. When that
    // option is unavailable the request is reopened against the bootstrap IP
    // literal, the previous behavior, where certificate verification fails
    // closed for hostname certificates. Verification is never relaxed.
    std::wstring bootstrapHost;
    if (!bootstrapIps.empty()) {
        bootstrapHost = widen(bootstrapIps.front());
    }
    WinHttpHandle conn(WinHttpConnect(session.get(), url.host.c_str(), url.port, 0));
    if (!conn.get()) {
        error = "cannot connect to ODoH server (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    WinHttpHandle request(WinHttpOpenRequest(conn.get(), method.c_str(), url.path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE));
    if (!request.get()) {
        error = "cannot open ODoH request (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD http2Flag = WINHTTP_PROTOCOL_FLAG_HTTP2;
    WinHttpSetOption(request.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http2Flag, sizeof(http2Flag));

    if (!bootstrapHost.empty() &&
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_RESOLUTION_HOSTNAME, bootstrapHost.data(),
                          static_cast<DWORD>((bootstrapHost.size() + 1) * sizeof(wchar_t)))) {
        // Option unsupported: fall back to connecting to the bootstrap IP
        // literal as before, which fails certificate verification against the
        // hostname and so fails closed. Do not disable verification here.
        conn.reset(WinHttpConnect(session.get(), bootstrapHost.c_str(), url.port, 0));
        if (!conn.get()) {
            error = "cannot connect to ODoH server (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        request.reset(WinHttpOpenRequest(conn.get(), method.c_str(), url.path.c_str(), nullptr,
                                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE));
        if (!request.get()) {
            error = "cannot open ODoH request (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        WinHttpSetOption(request.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http2Flag, sizeof(http2Flag));
    }

    const std::wstring headers = widen("Content-Type: " + contentType + "\r\nAccept: " + contentType +
                                       "\r\nHost: " + url.host8 + "\r\n");
    const DWORD size = body ? static_cast<DWORD>(body->size()) : 0;
    LPVOID buffer = body ? const_cast<uint8_t*>(body->data()) : nullptr;
    if (!WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(-1L), buffer, size, size, 0)) {
        error = "cannot send ODoH request (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    if (!WinHttpReceiveResponse(request.get(), nullptr)) {
        error = "no ODoH reply (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    DWORD statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        error = "cannot read ODoH reply status (error " + std::to_string(GetLastError()) + ")";
        return false;
    }

    reply.clear();
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available)) {
            error = "cannot read ODoH reply (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        if (available == 0) {
            break;
        }
        if (reply.size() + available > kMaxHttpReply) {
            error = "ODoH reply is too large";
            return false;
        }
        const size_t offset = reply.size();
        reply.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), reply.data() + offset, available, &read)) {
            error = "cannot read ODoH reply data (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        reply.resize(offset + read);
    }
    return true;
}

// Reads bytes of a TLS-style encoding. Every read bounds-checks first.
class Reader {
public:
    explicit Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool u16(uint16_t& out) {
        if (size_ - pos_ < 2) {
            return false;
        }
        out = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }

    bool u8(uint8_t& out) {
        if (pos_ >= size_) {
            return false;
        }
        out = data_[pos_++];
        return true;
    }

    bool bytes(size_t count, const uint8_t*& out) {
        if (count > size_ - pos_) {
            return false;
        }
        out = data_ + pos_;
        pos_ += count;
        return true;
    }

    // A two-byte length prefix followed by that many bytes.
    bool lengthPrefixed(const uint8_t*& out, size_t& length) {
        uint16_t prefix = 0;
        if (!u16(prefix)) {
            return false;
        }
        length = prefix;
        return bytes(length, out);
    }

    size_t remaining() const { return size_ - pos_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
};

void appendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

// HKDF-Extract (RFC 5869) with SHA-256.
void hkdfExtract(const std::vector<uint8_t>& salt, const uint8_t* ikm, size_t ikmLen, uint8_t* prk) {
    unsigned int prkLen = 32;
    const uint8_t zeros[32] = {};
    const uint8_t* key = salt.empty() ? zeros : salt.data();
    const int keyLen = salt.empty() ? 32 : static_cast<int>(salt.size());
    HMAC(EVP_sha256(), key, keyLen, ikm, ikmLen, prk, &prkLen);
}

// HKDF-Expand (RFC 5869) with SHA-256.
bool hkdfExpand(const uint8_t* prk, const std::string& info, uint8_t* out, size_t outLen) {
    if (outLen > 255 * 32) {
        return false;
    }
    std::vector<uint8_t> block;
    uint8_t previous[32];
    size_t previousLen = 0;
    size_t offset = 0;
    uint8_t counter = 1;
    while (offset < outLen) {
        block.assign(previous, previous + previousLen);
        block.insert(block.end(), info.begin(), info.end());
        block.push_back(counter++);
        unsigned int blockLen = 32;
        if (!HMAC(EVP_sha256(), prk, 32, block.data(), block.size(), previous, &blockLen)) {
            return false;
        }
        previousLen = blockLen;
        const size_t take = std::min<size_t>(blockLen, outLen - offset);
        std::memcpy(out + offset, previous, take);
        offset += take;
    }
    return true;
}

// Opens an AEAD ciphertext whose trailing tag is 16 bytes.
bool aeadOpen(const EVP_CIPHER* cipher, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
              const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext,
              std::vector<uint8_t>& out, std::string& error) {
    if (ciphertext.size() < 16) {
        error = "ODoH response is too short";
        return false;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        error = "cannot create cipher context";
        return false;
    }
    out.clear();
    out.resize(ciphertext.size() - 16);
    int written = 0;
    int finalWritten = 0;
    bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx, nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1 &&
              EVP_DecryptUpdate(ctx, out.data(), &written, ciphertext.data(),
                                static_cast<int>(ciphertext.size() - 16)) == 1;
    if (ok) {
        out.resize(written);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                            const_cast<uint8_t*>(ciphertext.data() + ciphertext.size() - 16));
        ok = EVP_DecryptFinal_ex(ctx, out.data() + written, &finalWritten) == 1;
        if (ok) {
            out.resize(written + finalWritten);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        error = "ODoH response failed to decrypt";
        out.clear();
    }
    return ok;
}

}  // namespace

std::shared_ptr<const OdohConfigSnapshot> OdohConfigSlot::fresh(std::chrono::milliseconds maxAge) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (snapshot_ && std::chrono::steady_clock::now() - published_ < maxAge) {
        return snapshot_;
    }
    return nullptr;
}

void OdohConfigSlot::publish(std::shared_ptr<const OdohConfigSnapshot> snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_ = std::move(snapshot);
    if (snapshot_) {
        published_ = std::chrono::steady_clock::now();
    }
}

struct OdohUpstream::Impl {
    Url target;
    Url proxy;
    bool useProxy = false;
    std::vector<std::string> bootstrapIps;

    // Serializes configuration refreshes so only one fetch runs at a time, as
    // before; the slot's own mutex guards only the snapshot swap.
    std::mutex refreshMutex;
    OdohConfigSlot configSlot;

    // Fetches and parses the target's ObliviousDoHConfigs into a new immutable
    // snapshot, picking the first usable suite. Returns null on failure.
    std::shared_ptr<const OdohConfigSnapshot> loadConfig(std::string& error);
    // Returns a fresh snapshot, refreshing the target key configuration first
    // when it is stale; keys rotate regularly.
    std::shared_ptr<const OdohConfigSnapshot> ensureConfig(std::string& error);
};

OdohUpstream::OdohUpstream(std::string name, const std::string& targetUrl, const std::string& proxyUrl,
                           std::vector<std::string> bootstrapIps)
    : Upstream(std::move(name), "odoh"), impl_(new Impl) {
    std::string error;
    if (!parseUrl(targetUrl, impl_->target, error)) {
        throw std::runtime_error(error);
    }
    if (!proxyUrl.empty()) {
        if (!parseUrl(proxyUrl, impl_->proxy, error)) {
            throw std::runtime_error("ODoH proxy: " + error);
        }
        impl_->useProxy = true;
    }
    impl_->bootstrapIps = std::move(bootstrapIps);
}

OdohUpstream::~OdohUpstream() = default;

std::shared_ptr<const OdohConfigSnapshot> OdohUpstream::Impl::loadConfig(std::string& error) {
    Url configUrl = target;
    configUrl.path = widen(kConfigPath);
    configUrl.path8 = kConfigPath;

    DWORD status = 0;
    std::vector<uint8_t> body;
    if (!httpRequest(configUrl, L"GET", kMediaType, nullptr, bootstrapIps, status, body, error)) {
        return nullptr;
    }
    if (status != 200) {
        error = "ODoH config fetch returned HTTP status " + std::to_string(status);
        return nullptr;
    }

    Reader outer(body.data(), body.size());
    const uint8_t* configs = nullptr;
    size_t configsLen = 0;
    if (!outer.lengthPrefixed(configs, configsLen)) {
        error = "ODoH config list is truncated";
        return nullptr;
    }

    Reader list(configs, configsLen);
    while (list.remaining() > 0) {
        uint16_t version = 0;
        uint16_t length = 0;
        const uint8_t* contents = nullptr;
        if (!list.u16(version) || !list.u16(length) || !list.bytes(length, contents)) {
            error = "ODoH config entry is truncated";
            return nullptr;
        }
        if (version != kOdohVersion) {
            continue;
        }
        Reader fields(contents, length);
        uint16_t kem = 0;
        uint16_t kdf = 0;
        uint16_t aead = 0;
        const uint8_t* key = nullptr;
        size_t keyLenField = 0;
        if (!fields.u16(kem) || !fields.u16(kdf) || !fields.u16(aead) ||
            !fields.lengthPrefixed(key, keyLenField)) {
            error = "ODoH config contents are truncated";
            return nullptr;
        }
        if (kem != OSSL_HPKE_KEM_ID_X25519 || kdf != OSSL_HPKE_KDF_ID_HKDF_SHA256) {
            continue;
        }
        const EVP_CIPHER* cipherChoice = nullptr;
        size_t nKey = 0;
        if (aead == OSSL_HPKE_AEAD_ID_AES_GCM_128) {
            cipherChoice = EVP_aes_128_gcm();
            nKey = 16;
        } else if (aead == OSSL_HPKE_AEAD_ID_CHACHA_POLY1305) {
            cipherChoice = EVP_chacha20_poly1305();
            nKey = 32;
        } else {
            continue;
        }

        // Build a complete immutable snapshot; it is published as a whole so an
        // in-flight exchange never sees mixed old/new key state.
        auto next = std::make_shared<OdohConfigSnapshot>();
        next->suite = {kem, kdf, aead};
        next->targetKey.assign(key, key + keyLenField);
        next->cipher = cipherChoice;
        next->keyLen = nKey;

        // The serialized ObliviousDoHConfigContents derives the key id.
        uint8_t prk[32] = {};
        hkdfExtract({}, contents, length, prk);
        next->keyId.resize(kKeyIdLen);
        if (!hkdfExpand(prk, kLabelKeyId, next->keyId.data(), next->keyId.size())) {
            error = "cannot derive the ODoH key id";
            return nullptr;
        }
        return next;
    }
    error = "ODoH target offers no supported key configuration";
    return nullptr;
}

std::shared_ptr<const OdohConfigSnapshot> OdohUpstream::Impl::ensureConfig(std::string& error) {
    // One refresh at a time, as before: this lock serializes fetches while the
    // slot's own mutex only guards the snapshot swap.
    std::lock_guard<std::mutex> refreshLock(refreshMutex);
    std::shared_ptr<const OdohConfigSnapshot> config = configSlot.fresh(kConfigTtl);
    if (config) {
        return config;
    }
    config = loadConfig(error);
    configSlot.publish(config);  // a failed refresh forgets the configuration
    return config;
}

bool OdohUpstream::exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error) {
    if (query.size() < dns::kHeaderSize || query.size() > 0xFFFF) {
        error = "query length is out of range";
        return false;
    }
    // One immutable snapshot drives the whole exchange (encap, seal, export and
    // open); a refresh that lands mid-exchange publishes a new snapshot instead
    // of changing the parameters this exchange reads.
    const std::shared_ptr<const OdohConfigSnapshot> config = impl_->ensureConfig(error);
    if (!config) {
        return false;
    }

    // ObliviousDoHMessagePlaintext: dns_message, padding (RFC 8467 zero padding to 128).
    std::vector<uint8_t> plain;
    appendU16(plain, static_cast<uint16_t>(query.size()));
    plain.insert(plain.end(), query.begin(), query.end());
    const size_t used = plain.size() + 2;
    const size_t pad = (used % kQueryPadBlock == 0) ? 0 : kQueryPadBlock - used % kQueryPadBlock;
    appendU16(plain, static_cast<uint16_t>(pad));
    plain.insert(plain.end(), pad, 0);

    // HPKE-seal the plaintext to the target's public key ("odoh query").
    OSSL_HPKE_CTX* hpke = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, config->suite, OSSL_HPKE_ROLE_SENDER, nullptr,
                                            nullptr);
    if (!hpke) {
        error = "cannot create the HPKE context";
        return false;
    }
    std::vector<uint8_t> enc(64);
    size_t encLen = enc.size();
    const bool encapped =
        OSSL_HPKE_encap(hpke, enc.data(), &encLen, config->targetKey.data(), config->targetKey.size(),
                        reinterpret_cast<const unsigned char*>(kHpkeInfoQuery), sizeof(kHpkeInfoQuery) - 1) == 1;
    std::vector<uint8_t> aad;
    aad.push_back(0x01);
    appendU16(aad, static_cast<uint16_t>(config->keyId.size()));
    aad.insert(aad.end(), config->keyId.begin(), config->keyId.end());
    std::vector<uint8_t> ct(plain.size() + 32);
    size_t ctLen = ct.size();
    const bool sealed = encapped && OSSL_HPKE_seal(hpke, ct.data(), &ctLen, aad.data(), aad.size(), plain.data(),
                                                   plain.size()) == 1;
    if (!sealed) {
        OSSL_HPKE_CTX_free(hpke);
        error = "cannot encrypt the ODoH query";
        return false;
    }
    enc.resize(encLen);
    ct.resize(ctLen);

    // ObliviousDoHMessage for a query.
    std::vector<uint8_t> message;
    message.push_back(0x01);
    appendU16(message, static_cast<uint16_t>(config->keyId.size()));
    message.insert(message.end(), config->keyId.begin(), config->keyId.end());
    std::vector<uint8_t> encrypted = enc;
    encrypted.insert(encrypted.end(), ct.begin(), ct.end());
    appendU16(message, static_cast<uint16_t>(encrypted.size()));
    message.insert(message.end(), encrypted.begin(), encrypted.end());

    // Send to the relay (targethost/targetpath parameters) or to the target directly.
    Url endpoint = impl_->target;
    if (impl_->useProxy) {
        endpoint = impl_->proxy;
        std::string separator = (endpoint.path8.find('?') == std::string::npos) ? "?" : "&";
        endpoint.path8 += separator + "targethost=" + urlEncode(impl_->target.host8) +
                          "&targetpath=" + urlEncode(impl_->target.path8);
        endpoint.path = widen(endpoint.path8);
    }

    DWORD status = 0;
    std::vector<uint8_t> body;
    if (!httpRequest(endpoint, L"POST", kMediaType, &message, impl_->bootstrapIps, status, body, error)) {
        OSSL_HPKE_CTX_free(hpke);
        return false;
    }
    if (status != 200) {
        OSSL_HPKE_CTX_free(hpke);
        error = "ODoH server replied with HTTP status " + std::to_string(status);
        return false;
    }

    // ObliviousDoHMessage for a response: message_type, resp_nonce, ciphertext.
    Reader reader(body.data(), body.size());
    uint8_t messageType = 0;
    const uint8_t* respNoncePtr = nullptr;
    size_t respNonceLen = 0;
    const uint8_t* encryptedPtr = nullptr;
    size_t encryptedLen = 0;
    if (!reader.u8(messageType) || messageType != 0x02 || !reader.lengthPrefixed(respNoncePtr, respNonceLen) ||
        !reader.lengthPrefixed(encryptedPtr, encryptedLen)) {
        OSSL_HPKE_CTX_free(hpke);
        error = "ODoH response message is malformed";
        return false;
    }
    std::vector<uint8_t> respNonce(respNoncePtr, respNoncePtr + respNonceLen);
    std::vector<uint8_t> respCipher(encryptedPtr, encryptedPtr + encryptedLen);

    // derive_secrets: response key and nonce come from the exported secret (RFC 9230, 6.2).
    std::vector<uint8_t> secret(config->keyLen);
    if (OSSL_HPKE_export(hpke, secret.data(), secret.size(), reinterpret_cast<const unsigned char*>(kLabelResponse),
                         sizeof(kLabelResponse) - 1) != 1) {
        OSSL_HPKE_CTX_free(hpke);
        error = "cannot derive the ODoH response secret";
        return false;
    }
    OSSL_HPKE_CTX_free(hpke);

    std::vector<uint8_t> salt = plain;
    appendU16(salt, static_cast<uint16_t>(respNonce.size()));
    salt.insert(salt.end(), respNonce.begin(), respNonce.end());
    uint8_t prk[32] = {};
    hkdfExtract(salt, secret.data(), secret.size(), prk);
    std::vector<uint8_t> aeadKey(config->keyLen);
    uint8_t aeadNonce[12] = {};
    if (!hkdfExpand(prk, kLabelKey, aeadKey.data(), aeadKey.size()) ||
        !hkdfExpand(prk, kLabelNonce, aeadNonce, sizeof(aeadNonce))) {
        error = "cannot derive the ODoH response keys";
        return false;
    }

    std::vector<uint8_t> responseAad;
    responseAad.push_back(0x02);
    appendU16(responseAad, static_cast<uint16_t>(respNonce.size()));
    responseAad.insert(responseAad.end(), respNonce.begin(), respNonce.end());

    std::vector<uint8_t> plainResponse;
    const std::vector<uint8_t> nonce(aeadNonce, aeadNonce + sizeof(aeadNonce));
    if (!aeadOpen(config->cipher, aeadKey, nonce, responseAad, respCipher, plainResponse, error)) {
        return false;
    }

    Reader plainReader(plainResponse.data(), plainResponse.size());
    const uint8_t* dnsMessage = nullptr;
    size_t dnsLen = 0;
    const uint8_t* padding = nullptr;
    size_t padLen = 0;
    if (!plainReader.lengthPrefixed(dnsMessage, dnsLen) || !plainReader.lengthPrefixed(padding, padLen)) {
        error = "ODoH response plaintext is malformed";
        return false;
    }
    for (size_t i = 0; i < padLen; ++i) {
        if (padding[i] != 0) {
            error = "ODoH response padding is invalid";
            return false;
        }
    }
    response.assign(dnsMessage, dnsMessage + dnsLen);
    if (response.size() < dns::kHeaderSize) {
        error = "ODoH reply is too short";
        return false;
    }
    const uint16_t id = static_cast<uint16_t>((query[0] << 8) | query[1]);
    if (!dns::isResponseFor(response, id)) {
        error = "ODoH reply does not match the query";
        return false;
    }
    return true;
}
