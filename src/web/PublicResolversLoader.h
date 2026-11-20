#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "transports/Stamp.h"

struct PublicDnsItem {
    std::string name;
    std::string description;
    std::string stamp;
    std::string protocol; // "DoH", "DoQ", "ODoH", "ODoH Relay", "DNSCrypt", "Relay"
    bool dnssec = false;
    bool noLog = false;
    bool noFilter = false;
};

// Downloads and parses public resolvers and relays from GitHub.
namespace resolvers {

// Lists are small markdown documents; cap both network and cache input at 8 MiB.
constexpr std::size_t kMaxListBytes = 8 * 1024 * 1024;
using Fetch = std::function<bool(const std::string&, std::string&, std::string&)>;
using CacheRead = std::function<bool(const std::filesystem::path&, std::string&, std::string&)>;
using ReadChunk = std::function<bool(std::string&, bool& eof, std::string&)>;

struct ListIo {
    Fetch fetch;
    CacheRead read;
    std::function<bool(const std::filesystem::path&, const std::string&, std::string&)> write;
};

const char* protocolName(DnsStamp::Protocol protocol);
const char* upstreamType(DnsStamp::Protocol protocol); // nullptr for relay-only stamps
bool readBounded(const ReadChunk& read, std::string& content, std::string& error);
bool loadList(const std::string& url, const std::filesystem::path& cachePath, bool forceRefresh,
              std::string& text, std::string& error, const ListIo& io = {});

constexpr char kPublicResolversUrl[] =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md";
constexpr char kRelaysUrl[] =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md";
constexpr char kOdohServersUrl[] =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md";
constexpr char kOdohRelaysUrl[] =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md";

// Fetches raw content from an HTTPS URL via WinHTTP.
bool fetchUrl(const std::string& url, std::string& content, std::string& error);

// Parses markdown lists; each item's protocol comes from its stamp, not the list.
std::vector<PublicDnsItem> parseMarkdown(const std::string& text);

// Loads resolvers and relays from disk cache or fetches from web.
std::vector<PublicDnsItem> loadAll(bool forceRefresh, std::string& error);
std::vector<PublicDnsItem> loadAll(bool forceRefresh, std::string& error,
                                 const std::filesystem::path& cacheDir, const ListIo& io = {});

}  // namespace resolvers
