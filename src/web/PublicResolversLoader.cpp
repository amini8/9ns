#include "web/PublicResolversLoader.h"

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <QFile>
#include <QSaveFile>

#include "transports/Stamp.h"
#include "core/Text.h"

namespace resolvers {
namespace {

std::string toLower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::filesystem::path getCacheDir() {
    const DWORD required = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (required == 0) {
        throw std::runtime_error("ProgramData lookup failed");
    }
    std::wstring base(required, L'\0');
    const DWORD len = GetEnvironmentVariableW(L"ProgramData", base.data(), required);
    if (len == 0 || len >= required) {
        throw std::runtime_error("ProgramData lookup failed or changed size");
    }
    base.resize(len);
    const std::filesystem::path root(base);
    if (!root.is_absolute()) {
        throw std::runtime_error("ProgramData path is not absolute");
    }
    return root / L"9NS";
}

struct HttpCloser {
    void operator()(void* handle) const { WinHttpCloseHandle(handle); }
};
using HttpHandle = std::unique_ptr<void, HttpCloser>;

bool readCache(const std::filesystem::path& path, std::string& content, std::string& error) {
    QFile file(QString::fromStdWString(path.wstring()));
    if (!file.open(QIODevice::ReadOnly)) {
        error = "cannot read cache '" + path.u8string() + "': " + file.errorString().toStdString();
        return false;
    }
    return readBounded([&](std::string& chunk, bool& eof, std::string& err) {
        char buffer[65536];
        const qint64 count = file.read(buffer, sizeof(buffer));
        if (count < 0) {
            err = "cache read failed: " + file.errorString().toStdString();
            return false;
        }
        chunk.assign(buffer, static_cast<size_t>(count));
        eof = count == 0 && file.atEnd();
        return true;
    }, content, error);
}

bool writeCache(const std::filesystem::path& path, const std::string& content, std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        error = "cannot create cache directory '" + path.parent_path().u8string() + "': " + ec.message();
        return false;
    }
    QSaveFile file(QString::fromStdWString(path.wstring()));
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) ||
        file.write(content.data(), static_cast<qint64>(content.size())) != static_cast<qint64>(content.size()) ||
        !file.commit()) {
        error = "cannot replace cache '" + path.u8string() + "': " + file.errorString().toStdString();
        return false;
    }
    return true;
}

}  // namespace

const char* protocolName(DnsStamp::Protocol protocol) {
    switch (protocol) {
    case DnsStamp::Protocol::DoH: return "DoH";
    case DnsStamp::Protocol::DoQ: return "DoQ";
    case DnsStamp::Protocol::Odoh: return "ODoH";
    case DnsStamp::Protocol::DnsCrypt: return "DNSCrypt";
    case DnsStamp::Protocol::AnonymizedRelay: return "Relay";
    case DnsStamp::Protocol::OdohRelay: return "ODoH Relay";
    }
    return "Unknown";
}

const char* upstreamType(DnsStamp::Protocol protocol) {
    switch (protocol) {
    case DnsStamp::Protocol::DoH: return "doh";
    case DnsStamp::Protocol::DoQ: return "doq";
    case DnsStamp::Protocol::Odoh: return "odoh";
    case DnsStamp::Protocol::DnsCrypt: return "dnscrypt";
    case DnsStamp::Protocol::AnonymizedRelay:
    case DnsStamp::Protocol::OdohRelay: return nullptr;
    }
    return nullptr;
}

bool readBounded(const ReadChunk& read, std::string& content, std::string& error) {
    error.clear();
    std::string candidate;
    for (;;) {
        std::string chunk;
        bool eof = false;
        if (!read(chunk, eof, error)) {
            return false;
        }
        if (chunk.size() > kMaxListBytes - candidate.size()) {
            error = "resolver list exceeds 8 MiB limit";
            return false;
        }
        candidate += chunk;
        if (eof) {
            if (candidate.empty()) {
                error = "resolver list is empty";
                return false;
            }
            content = std::move(candidate);
            return true;
        }
        if (chunk.empty()) {
            error = "resolver list read made no progress";
            return false;
        }
    }
}

bool fetchUrl(const std::string& url, std::string& content, std::string& error) {
    error.clear();
    auto fail = [&](const char* operation) {
        error = std::string(operation) + " failed (WinHTTP " + std::to_string(GetLastError()) + ")";
        return false;
    };
    const std::wstring wideUrl = widen(url);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.size()), 0, &parts)) {
        return fail("URL parsing");
    }
    if (parts.nScheme != INTERNET_SCHEME_HTTPS) {
        error = "resolver list URL must use HTTPS";
        return false;
    }
    std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.dwExtraInfoLength > 0) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    HttpHandle session(WinHttpOpen(L"9NS/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) return fail("HTTP session");
    if (!WinHttpSetTimeouts(session.get(), 5000, 5000, 8000, 8000)) return fail("HTTP timeouts");
    HttpHandle conn(WinHttpConnect(session.get(), host.c_str(), parts.nPort, 0));
    if (!conn) return fail("HTTP connection");
    HttpHandle request(WinHttpOpenRequest(conn.get(), L"GET", path.c_str(), nullptr,
                                          WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request) return fail("HTTP request");
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy))) {
        return fail("HTTP redirect policy");
    }
    if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        return fail("HTTP send");
    }
    if (!WinHttpReceiveResponse(request.get(), nullptr)) return fail("HTTP receive");
    DWORD status = 0;
    DWORD size = sizeof(status);
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
        return fail("HTTP status query");
    }
    if (status != 200) {
        error = "HTTP error " + std::to_string(status);
        return false;
    }
    DWORD expected = 0;
    size = sizeof(expected);
    const bool hasLength = WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                                               WINHTTP_HEADER_NAME_BY_INDEX, &expected, &size, WINHTTP_NO_HEADER_INDEX);
    if (!hasLength && GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND) return fail("HTTP content length query");
    if (hasLength && expected > kMaxListBytes) {
        error = "resolver list exceeds 8 MiB limit";
        return false;
    }
    std::string candidate;
    if (!readBounded([&](std::string& chunk, bool& eof, std::string&) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available)) return fail("HTTP available-data query");
        if (available == 0) {
            eof = true;
            return true;
        }
        chunk.resize(std::min<DWORD>(available, 65536));
        DWORD count = 0;
        if (!WinHttpReadData(request.get(), chunk.data(), static_cast<DWORD>(chunk.size()), &count)) {
            return fail("HTTP body read");
        }
        chunk.resize(count);
        return true;
    }, candidate, error)) return false;
    if (hasLength && candidate.size() != expected) {
        error = "HTTP body length does not match Content-Length";
        return false;
    }
    content = std::move(candidate);
    return true;
}

std::vector<PublicDnsItem> parseMarkdown(const std::string& text) {
    std::vector<PublicDnsItem> result;
    std::istringstream stream(text);
    std::string line;

    PublicDnsItem current;
    bool inItem = false;

    auto finishItem = [&] {
        if (inItem && !current.name.empty() && !current.stamp.empty()) {
            DnsStamp stamp;
            std::string err;
            if (parseStamp(current.stamp, stamp, err)) {
                current.protocol = protocolName(stamp.protocol);
            } else {
                current.protocol = "Invalid";
            }
            result.push_back(current);
        }
        current = PublicDnsItem();
        inItem = false;
    };

    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.rfind("## ", 0) == 0) {
            finishItem();
            current.name = line.substr(3);
            inItem = true;
            continue;
        }
        if (line.rfind("sdns://", 0) == 0) {
            current.stamp = line;
            continue;
        }
        if (inItem && !line.empty()) {
            if (!current.description.empty()) {
                current.description += " ";
            }
            current.description += line;

            const std::string lower = toLower(line);
            if (lower.find("dnssec") != std::string::npos) {
                current.dnssec = true;
            }
            if (lower.find("no log") != std::string::npos || lower.find("no persistent log") != std::string::npos) {
                current.noLog = true;
            }
            if (lower.find("non-filtering") != std::string::npos || lower.find("no filter") != std::string::npos) {
                current.noFilter = true;
            }
        }
    }
    finishItem();
    return result;
}

bool loadList(const std::string& url, const std::filesystem::path& cachePath, bool forceRefresh,
              std::string& text, std::string& error, const ListIo& io) {
    error.clear();
    std::string candidate;
    if (!forceRefresh) {
        std::error_code ec;
        const bool exists = std::filesystem::exists(cachePath, ec);
        if (ec) {
            error = "cannot inspect cache '" + cachePath.u8string() + "': " + ec.message();
            return false;
        }
        if (exists) {
            const bool read = io.read ? io.read(cachePath, candidate, error) : readCache(cachePath, candidate, error);
            if (read && !candidate.empty() && candidate.size() <= kMaxListBytes) {
                const auto items = parseMarkdown(candidate);
                if (std::any_of(items.begin(), items.end(), [](const auto& item) { return item.protocol != "Invalid"; })) {
                    text = std::move(candidate);
                    return true;
                }
            }
        }
    }
    candidate.clear();
    error.clear();
    if (!(io.fetch ? io.fetch(url, candidate, error) : fetchUrl(url, candidate, error))) return false;
    if (candidate.empty() || candidate.size() > kMaxListBytes) {
        error = "download is empty or exceeds 8 MiB";
        return false;
    }
    const auto items = parseMarkdown(candidate);
    if (std::none_of(items.begin(), items.end(), [](const auto& item) { return item.protocol != "Invalid"; })) {
        error = "download has no usable resolver stamps";
        return false;
    }
    if (!(io.write ? io.write(cachePath, candidate, error) : writeCache(cachePath, candidate, error))) return false;
    text = std::move(candidate);
    return true;
}

std::vector<PublicDnsItem> loadAll(bool forceRefresh, std::string& error) {
    try {
        return loadAll(forceRefresh, error, getCacheDir());
    } catch (const std::exception& ex) {
        error = ex.what();
        return {};
    }
}

std::vector<PublicDnsItem> loadAll(bool forceRefresh, std::string& error,
                                 const std::filesystem::path& cacheDir, const ListIo& io) {
    error.clear();
    struct ListSpec {
        const char* url;
        const char* cacheName;
    };
    const ListSpec specs[] = {
        {kPublicResolversUrl, "public-resolvers.cache.md"},
        {kRelaysUrl, "relays.cache.md"},
        {kOdohServersUrl, "odoh-servers.cache.md"},
        {kOdohRelaysUrl, "odoh-relays.cache.md"},
    };

    std::vector<PublicDnsItem> all;
    int failures = 0;
    std::string firstError;
    for (const ListSpec& spec : specs) {
        std::string text;
        std::string listError;
        if (!loadList(spec.url, cacheDir / spec.cacheName, forceRefresh, text, listError, io)) {
            ++failures;
            if (firstError.empty()) {
                firstError = listError;
            }
            continue;
        }
        std::vector<PublicDnsItem> items = parseMarkdown(text);
        all.insert(all.end(), items.begin(), items.end());
    }

    if (failures == static_cast<int>(sizeof(specs) / sizeof(specs[0]))) {
        error = "Failed to download resolvers: " + firstError;
        return {};
    }
    return all;
}

}  // namespace resolvers
