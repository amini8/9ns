#include "core/ProxyProtocol.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace proxyproto {
namespace {

bool digit(char c) { return c >= '0' && c <= '9'; }
bool alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; }
std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), lower);
    return s;
}
bool clean(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= 32 && c != 127; });
}
bool credential(const std::string& s, bool allowEmpty = false) {
    return (allowEmpty || !s.empty()) && s.size() <= kMaxAuthLength && clean(s);
}
void require(bool ok, const char* message) {
    if (!ok) throw std::invalid_argument(message);
}
uint16_t word(const Bytes& b, size_t offset) {
    return static_cast<uint16_t>((uint16_t(b[offset]) << 8) | b[offset + 1]);
}
void appendPort(Bytes& bytes, uint16_t port) {
    bytes.push_back(static_cast<uint8_t>(port >> 8));
    bytes.push_back(static_cast<uint8_t>(port));
}
std::string text(const Bytes& bytes, size_t offset, size_t length) {
    return std::string(bytes.begin() + offset, bytes.begin() + offset + length);
}
bool ipv4(const std::string& host, Bytes& result) {
    Bytes parts;
    size_t start = 0;
    for (size_t i = 0; i < 4; ++i) {
        const size_t end = host.find('.', start);
        if ((i == 3) != (end == std::string::npos)) return false;
        const size_t stop = end == std::string::npos ? host.size() : end;
        if (stop == start || stop - start > 3 || (stop - start > 1 && host[start] == '0')) return false;
        unsigned value = 0;
        for (size_t p = start; p < stop; ++p) {
            if (!digit(host[p])) return false;
            value = value * 10 + unsigned(host[p] - '0');
        }
        if (value > 255) return false;
        parts.push_back(static_cast<uint8_t>(value));
        start = stop + 1;
    }
    result = std::move(parts);
    return true;
}
int hex(char c) {
    if (digit(c)) return c - '0';
    c = lower(c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
bool ipv6Part(const std::string& part, bool allowV4, std::vector<uint16_t>& words) {
    if (part.empty()) return true;
    size_t start = 0;
    while (start < part.size()) {
        const size_t colon = part.find(':', start);
        const size_t end = colon == std::string::npos ? part.size() : colon;
        const std::string item = part.substr(start, end - start);
        if (item.find('.') != std::string::npos) {
            Bytes v4;
            if (!allowV4 || colon != std::string::npos || !ipv4(item, v4)) return false;
            words.push_back(word(v4, 0));
            words.push_back(word(v4, 2));
        } else {
            if (item.empty() || item.size() > 4) return false;
            unsigned value = 0;
            for (char c : item) {
                const int h = hex(c);
                if (h < 0) return false;
                value = value * 16 + unsigned(h);
            }
            words.push_back(static_cast<uint16_t>(value));
        }
        if (words.size() > 8) return false;
        if (colon == std::string::npos) return true;
        start = colon + 1;
        if (start == part.size()) return false;
    }
    return true;
}
bool ipv6(const std::string& host, Bytes& result) {
    if (host.empty() || host.size() > 45 || host.find(':') == std::string::npos) return false;
    const size_t gap = host.find("::");
    std::vector<uint16_t> left, right;
    if (gap == std::string::npos) {
        if (!ipv6Part(host, true, left) || left.size() != 8) return false;
    } else {
        if (host.find("::", gap + 2) != std::string::npos ||
            !ipv6Part(host.substr(0, gap), false, left) ||
            !ipv6Part(host.substr(gap + 2), true, right) || left.size() + right.size() >= 8) return false;
        left.resize(8 - right.size(), 0);
        left.insert(left.end(), right.begin(), right.end());
    }
    Bytes bytes;
    for (uint16_t value : left) appendPort(bytes, value);
    result = std::move(bytes);
    return true;
}
std::string ipv4Text(const Bytes& b, size_t offset) {
    return std::to_string(b[offset]) + "." + std::to_string(b[offset + 1]) + "." +
           std::to_string(b[offset + 2]) + "." + std::to_string(b[offset + 3]);
}
std::string ipv6Text(const Bytes& b, size_t offset) {
    std::array<uint16_t, 8> words{};
    size_t bestStart = 8, bestSize = 1;
    for (size_t i = 0; i < 8; ++i) words[i] = word(b, offset + i * 2);
    for (size_t i = 0; i < 8;) {
        if (words[i] != 0) { ++i; continue; }
        const size_t start = i;
        while (i < 8 && words[i] == 0) ++i;
        if (i - start > bestSize) { bestStart = start; bestSize = i - start; }
    }
    std::string result;
    const char* digits = "0123456789abcdef";
    for (size_t i = 0; i < 8;) {
        if (i == bestStart) {
            result += "::";
            i += bestSize;
            continue;
        }
        if (!result.empty() && result.back() != ':') result += ':';
        const uint16_t value = words[i++];
        bool started = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const unsigned nibble = (value >> shift) & 15;
            if (nibble || started || shift == 0) { result += digits[nibble]; started = true; }
        }
    }
    return result;
}
bool domain(const std::string& host) {
    if (host.empty() || host.size() > kMaxDomainLength) return false;
    const size_t end = host.back() == '.' ? host.size() - 1 : host.size();
    if (end == 0 || host[end - 1] == '.') return false;
    size_t start = 0;
    while (start < end) {
        const size_t dot = host.find('.', start);
        const size_t stop = std::min(dot == std::string::npos ? end : dot, end);
        if (stop == start || stop - start > 63 || host[start] == '-' || host[stop - 1] == '-') return false;
        for (size_t i = start; i < stop; ++i)
            if (!alpha(host[i]) && !digit(host[i]) && host[i] != '-') return false;
        start = stop + 1;
    }
    return true;
}
bool validHost(const std::string& host, bool& numeric) {
    Bytes address;
    numeric = ipv4(host, address) || ipv6(host, address);
    if (numeric) return true;
    if (std::all_of(host.begin(), host.end(), [](char c) { return digit(c) || c == '.'; })) return false;
    return domain(host);
}
Stage address(const Bytes& bytes, size_t offset, Target& target, size_t& end) {
    if (bytes.size() <= offset) return Stage::NeedMore;
    const uint8_t type = bytes[offset++];
    size_t length = 0;
    if (type == 1) length = 4;
    else if (type == 4) length = 16;
    else if (type == 3) {
        if (bytes.size() <= offset) return Stage::NeedMore;
        length = bytes[offset++];
        if (length == 0 || length > kMaxDomainLength) return Stage::Malformed;
    } else return Stage::Malformed;
    if (bytes.size() < offset + length + 2) return Stage::NeedMore;
    if (type == 1) target.host = ipv4Text(bytes, offset);
    else if (type == 4) target.host = ipv6Text(bytes, offset);
    else {
        target.host = text(bytes, offset, length);
        if (!domain(target.host) || !validHost(target.host, target.hostIsNumeric)) return Stage::Malformed;
    }
    if (type != 3) target.hostIsNumeric = true;
    target.port = word(bytes, offset + length);
    end = offset + length + 2;
    return Stage::Done;
}
void appendAddress(Bytes& result, const Target& target) {
    Bytes numeric;
    if (ipv4(target.host, numeric)) result.push_back(1);
    else if (ipv6(target.host, numeric)) result.push_back(4);
    else {
        bool isNumeric = false;
        require(!target.hostIsNumeric && validHost(target.host, isNumeric), "invalid proxy target host");
        result.push_back(3);
        result.push_back(static_cast<uint8_t>(target.host.size()));
        numeric.assign(target.host.begin(), target.host.end());
    }
    result.insert(result.end(), numeric.begin(), numeric.end());
    appendPort(result, target.port);
}
Stage pairReply(const Bytes& bytes, uint8_t version, uint8_t& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != version) return Stage::Malformed;
    if (bytes.size() < 2) return Stage::NeedMore;
    out = bytes[1];
    consumed = 2;
    return Stage::Done;
}
Stage terminated(const Bytes& bytes, size_t start, size_t maxLength, std::string& out, size_t& end) {
    for (size_t i = start; i < bytes.size() && i <= start + maxLength; ++i) {
        if (bytes[i] == 0) {
            out = text(bytes, start, i - start);
            end = i + 1;
            return clean(out) ? Stage::Done : Stage::Malformed;
        }
        if (bytes[i] < 32 || bytes[i] == 127) return Stage::Malformed;
    }
    return bytes.size() > start + maxLength ? Stage::Malformed : Stage::NeedMore;
}
bool token(const std::string& s) {
    if (s.empty()) return false;
    const std::string extra = "!#$%&'*+-.^_`|~";
    return std::all_of(s.begin(), s.end(), [&extra](char c) {
        return alpha(c) || digit(c) || extra.find(c) != std::string::npos;
    });
}
std::string trim(const std::string& s) {
    const size_t first = s.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(" \t") - first + 1);
}
struct HttpHead {
    std::string first;
    std::vector<std::pair<std::string, std::string>> headers;
};
Stage httpHead(const Bytes& bytes, HttpHead& out, size_t& end) {
    size_t lineStart = 0;
    bool first = true;
    const size_t limit = std::min(bytes.size(), kMaxHandshakeSize);
    for (size_t i = 0; i < limit; ++i) {
        const uint8_t c = bytes[i];
        if (c == '\r') {
            if (i + 1 == limit) break;
            if (bytes[i + 1] != '\n') return Stage::Malformed;
            const std::string line = text(bytes, lineStart, i - lineStart);
            i += 1;
            lineStart = i + 1;
            if (first) {
                if (line.empty()) return Stage::Malformed;
                out.first = line;
                first = false;
            } else if (line.empty()) {
                end = i + 1;
                return Stage::Done;
            } else {
                const size_t colon = line.find(':');
                if (colon == std::string::npos || !token(line.substr(0, colon))) return Stage::Malformed;
                out.headers.emplace_back(lowercase(line.substr(0, colon)), trim(line.substr(colon + 1)));
            }
        } else if (c == '\n' || (c < 32 && c != '\t') || c == 127) return Stage::Malformed;
    }
    return bytes.size() >= kMaxHandshakeSize ? Stage::Malformed : Stage::NeedMore;
}
bool authority(const std::string& text, Target& target) {
    size_t colon = std::string::npos;
    if (!text.empty() && text[0] == '[') {
        const size_t close = text.find(']');
        if (close == std::string::npos || close + 1 >= text.size() || text[close + 1] != ':') return false;
        target.host = text.substr(1, close - 1);
        Bytes v6;
        if (!ipv6(target.host, v6)) return false;
        target.hostIsNumeric = true;
        colon = close + 1;
    } else {
        colon = text.find(':');
        if (colon == std::string::npos) return false;
        target.host = text.substr(0, colon);
        if (!validHost(target.host, target.hostIsNumeric)) return false;
    }
    const std::string port = text.substr(colon + 1);
    if (port.empty() || port.size() > 5) return false;
    unsigned value = 0;
    for (char c : port) {
        if (!digit(c)) return false;
        value = value * 10 + unsigned(c - '0');
    }
    if (value == 0 || value > 65535) return false;
    target.port = static_cast<uint16_t>(value);
    return true;
}
std::string encodeBase64(const std::string& input) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t i = 0; i < input.size(); i += 3) {
        const unsigned a = static_cast<unsigned char>(input[i]);
        const unsigned b = i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0;
        const unsigned c = i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0;
        result += alphabet[a >> 2];
        result += alphabet[((a & 3) << 4) | (b >> 4)];
        result += i + 1 < input.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        result += i + 2 < input.size() ? alphabet[c & 63] : '=';
    }
    return result;
}

} // namespace

Protocol detectProtocol(uint8_t firstByte) {
    if (firstByte == 5) return Protocol::Socks5;
    if (firstByte == 4) return Protocol::Socks4;
    if (alpha(static_cast<char>(firstByte))) return Protocol::HttpConnect;
    return Protocol::Unknown;
}
Protocol detectProtocol(const Bytes& bytes) {
    return bytes.empty() ? Protocol::Unknown : detectProtocol(bytes[0]);
}

Stage parseSocks5Greeting(const Bytes& bytes, Socks5Greeting& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 5) return Stage::Malformed;
    if (bytes.size() < 2) return Stage::NeedMore;
    if (bytes[1] == 0) return Stage::Malformed;
    const size_t end = size_t(2) + bytes[1];
    if (bytes.size() < end) return Stage::NeedMore;
    out.methods.assign(bytes.begin() + 2, bytes.begin() + end);
    consumed = end;
    return Stage::Done;
}
Bytes makeSocks5Greeting(const Bytes& methods) {
    require(!methods.empty() && methods.size() <= 255, "invalid SOCKS5 method count");
    Bytes result = {5, static_cast<uint8_t>(methods.size())};
    result.insert(result.end(), methods.begin(), methods.end());
    return result;
}
Bytes makeSocks5MethodChoice(uint8_t method) { return {5, method}; }
Stage parseSocks5MethodChoice(const Bytes& bytes, uint8_t& method, size_t& consumed) {
    return pairReply(bytes, 5, method, consumed);
}
Stage parseSocks5Auth(const Bytes& bytes, Socks5Auth& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 1) return Stage::Malformed;
    if (bytes.size() < 2) return Stage::NeedMore;
    const size_t userLength = bytes[1];
    if (userLength == 0) return Stage::Malformed;
    if (bytes.size() < userLength + 3) return Stage::NeedMore;
    const size_t passLength = bytes[userLength + 2];
    if (passLength == 0) return Stage::Malformed;
    if (bytes.size() < userLength + passLength + 3) return Stage::NeedMore;
    Socks5Auth parsed{text(bytes, 2, userLength), text(bytes, userLength + 3, passLength)};
    if (!credential(parsed.username) || !credential(parsed.password)) return Stage::Malformed;
    out = std::move(parsed);
    consumed = userLength + passLength + 3;
    return Stage::Done;
}
Bytes makeSocks5Auth(const Socks5Auth& auth) {
    require(credential(auth.username) && credential(auth.password), "invalid SOCKS5 credentials");
    Bytes result = {1, static_cast<uint8_t>(auth.username.size())};
    result.insert(result.end(), auth.username.begin(), auth.username.end());
    result.push_back(static_cast<uint8_t>(auth.password.size()));
    result.insert(result.end(), auth.password.begin(), auth.password.end());
    return result;
}
Bytes makeSocks5AuthReply(uint8_t status) { return {1, status}; }
Stage parseSocks5AuthReply(const Bytes& bytes, uint8_t& status, size_t& consumed) {
    return pairReply(bytes, 1, status, consumed);
}
Stage parseSocks5Request(const Bytes& bytes, Socks5Request& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 5 || (bytes.size() >= 3 && bytes[2] != 0)) return Stage::Malformed;
    if (bytes.size() < 4) return Stage::NeedMore;
    Socks5Request parsed;
    parsed.command = static_cast<Socks5Command>(bytes[1]);
    size_t end = 0;
    const Stage stage = address(bytes, 3, parsed.target, end);
    if (stage != Stage::Done) return stage;
    // UDP ASSOCIATE may advertise an unspecified source port (RFC 1928).
    if (parsed.command == Socks5Command::Connect && parsed.target.port == 0) return Stage::Malformed;
    out = std::move(parsed);
    consumed = end;
    return Stage::Done;
}
Bytes makeSocks5Request(const Socks5Request& request) {
    require(request.command != Socks5Command::Connect || request.target.port != 0, "invalid SOCKS5 destination port");
    Bytes result = {5, static_cast<uint8_t>(request.command), 0};
    appendAddress(result, request.target);
    return result;
}
Bytes makeSocks5Reply(uint8_t code) {
    require(code <= 8, "invalid SOCKS5 reply code");
    return {5, code, 0, 1, 0, 0, 0, 0, 0, 0};
}
Stage parseSocks5Reply(const Bytes& bytes, Socks5Reply& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 5 || (bytes.size() >= 2 && bytes[1] > 8) ||
        (bytes.size() >= 3 && bytes[2] != 0)) return Stage::Malformed;
    if (bytes.size() < 4) return Stage::NeedMore;
    Socks5Reply parsed;
    parsed.code = bytes[1];
    size_t end = 0;
    const Stage stage = address(bytes, 3, parsed.target, end);
    if (stage != Stage::Done) return stage;
    out = std::move(parsed);
    consumed = end;
    return Stage::Done;
}

Stage parseSocks4Request(const Bytes& bytes, Socks4Request& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 4) return Stage::Malformed;
    if (bytes.size() < 8) return Stage::NeedMore;
    Socks4Request parsed;
    parsed.command = bytes[1];
    parsed.target.port = word(bytes, 2);
    if (parsed.target.port == 0) return Stage::Malformed;
    size_t end = 0;
    Stage stage = terminated(bytes, 8, kMaxAuthLength, parsed.userId, end);
    if (stage != Stage::Done) return stage;
    if (bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] != 0) {
        stage = terminated(bytes, end, kMaxDomainLength, parsed.target.host, end);
        if (stage != Stage::Done) return stage;
        if (!domain(parsed.target.host) || !validHost(parsed.target.host, parsed.target.hostIsNumeric))
            return Stage::Malformed;
    } else {
        parsed.target.host = ipv4Text(bytes, 4);
        parsed.target.hostIsNumeric = true;
    }
    out = std::move(parsed);
    consumed = end;
    return Stage::Done;
}
Bytes makeSocks4Request(const Socks4Request& request) {
    require(request.target.port != 0, "invalid SOCKS4 destination port");
    require(credential(request.userId, true), "invalid SOCKS4 user ID");
    Bytes v4;
    const bool numeric = ipv4(request.target.host, v4);
    bool ignored = false;
    require(numeric || (!request.target.hostIsNumeric && domain(request.target.host) &&
                        validHost(request.target.host, ignored)), "invalid SOCKS4 target host");
    // 0.0.0.x is a protocol marker, not an encodable SOCKS4 numeric target.
    require(!numeric || v4[0] || v4[1] || v4[2] || !v4[3], "SOCKS4 target collides with SOCKS4a marker");
    Bytes result = {4, request.command};
    appendPort(result, request.target.port);
    if (numeric) result.insert(result.end(), v4.begin(), v4.end());
    else result.insert(result.end(), {0, 0, 0, 1});
    result.insert(result.end(), request.userId.begin(), request.userId.end());
    result.push_back(0);
    if (!numeric) {
        result.insert(result.end(), request.target.host.begin(), request.target.host.end());
        result.push_back(0);
    }
    return result;
}
Bytes makeSocks4Reply(uint8_t code) {
    require(code >= 0x5A && code <= 0x5D, "invalid SOCKS4 reply code");
    return {0, code, 0, 0, 0, 0, 0, 0};
}
Stage parseSocks4Reply(const Bytes& bytes, Socks4Reply& out, size_t& consumed) {
    consumed = 0;
    if (bytes.empty()) return Stage::NeedMore;
    if (bytes[0] != 0 || (bytes.size() >= 2 && (bytes[1] < 0x5A || bytes[1] > 0x5D))) return Stage::Malformed;
    if (bytes.size() < 8) return Stage::NeedMore;
    out = {bytes[1], {ipv4Text(bytes, 4), word(bytes, 2), true}};
    consumed = 8;
    return Stage::Done;
}

bool decodeBase64(const std::string& encoded, std::string& decoded) {
    if (encoded.size() % 4 != 0) return false;
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (digit(c)) return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string result;
    result.reserve(encoded.size() / 4 * 3);
    for (size_t i = 0; i < encoded.size(); i += 4) {
        const int a = value(encoded[i]), b = value(encoded[i + 1]);
        const bool pad2 = encoded[i + 2] == '=', pad3 = encoded[i + 3] == '=';
        const int c = pad2 ? 0 : value(encoded[i + 2]);
        const int d = pad3 ? 0 : value(encoded[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != encoded.size()) ||
            (pad2 && (b & 15)) || (pad3 && !pad2 && (c & 3))) return false;
        result += static_cast<char>((a << 2) | (b >> 4));
        if (!pad2) result += static_cast<char>((b << 4) | (c >> 2));
        if (!pad3) result += static_cast<char>((c << 6) | d);
    }
    decoded = std::move(result);
    return true;
}
Stage parseHttpConnect(const Bytes& bytes, HttpConnectRequest& out, size_t& consumed) {
    consumed = 0;
    HttpHead head;
    size_t end = 0;
    const Stage stage = httpHead(bytes, head, end);
    if (stage != Stage::Done) return stage;
    const size_t firstSpace = head.first.find(' ');
    if (firstSpace == std::string::npos) return Stage::Malformed;
    const size_t secondSpace = head.first.find(' ', firstSpace + 1);
    if (secondSpace == std::string::npos) return Stage::Malformed;
    HttpConnectRequest parsed;
    parsed.method = head.first.substr(0, firstSpace);
    if (!token(parsed.method)) return Stage::Malformed;
    const std::string version = head.first.substr(secondSpace + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") return Stage::Malformed;
    const std::string destination = head.first.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    if (destination.empty() || !clean(destination) || destination.find('\t') != std::string::npos)
        return Stage::Malformed;
    parsed.isConnect = lowercase(parsed.method) == "connect";
    if (parsed.isConnect && !authority(destination, parsed.target)) return Stage::Malformed;
    bool sawAuthorization = false;
    bool sawLength = false;
    for (const auto& header : head.headers) {
        if (header.first == "proxy-authorization") {
            if (sawAuthorization) return Stage::Malformed;
            sawAuthorization = true;
            const size_t space = header.second.find_first_of(" \t");
            const std::string scheme = lowercase(header.second.substr(0, space));
            if (scheme != "basic") continue;
            if (space == std::string::npos) return Stage::Malformed;
            const std::string encoded = trim(header.second.substr(space + 1));
            std::string decoded;
            if (encoded.empty() || !decodeBase64(encoded, decoded)) return Stage::Malformed;
            const size_t colon = decoded.find(':');
            if (colon == std::string::npos) return Stage::Malformed;
            parsed.username = decoded.substr(0, colon);
            parsed.password = decoded.substr(colon + 1);
            if (!credential(parsed.username) || !credential(parsed.password, true)) return Stage::Malformed;
            parsed.hasCredentials = true;
        } else if (parsed.isConnect && header.first == "content-length") {
            // CONNECT cannot carry a request body; otherwise trailing bytes are ambiguous.
            if (sawLength || header.second != "0") return Stage::Malformed;
            sawLength = true;
        } else if (parsed.isConnect && header.first == "transfer-encoding") return Stage::Malformed;
    }
    out = std::move(parsed);
    consumed = end;
    return Stage::Done;
}
Bytes makeHttpConnectRequest(const HttpConnectRequest& request) {
    bool numeric = false;
    require(request.target.port != 0 && validHost(request.target.host, numeric) &&
            (!request.target.hostIsNumeric || numeric), "invalid HTTP CONNECT target");
    const std::string host = request.target.host.find(':') == std::string::npos ? request.target.host :
                             "[" + request.target.host + "]";
    const std::string destination = host + ":" + std::to_string(request.target.port);
    std::string result = "CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n";
    if (request.hasCredentials) {
        require(credential(request.username) && request.username.find(':') == std::string::npos &&
                credential(request.password, true), "invalid HTTP proxy credentials");
        result += "Proxy-Authorization: Basic " + encodeBase64(request.username + ":" + request.password) + "\r\n";
    }
    result += "\r\n";
    return Bytes(result.begin(), result.end());
}
Bytes makeHttpResponse(int statusCode) {
    std::string reason;
    switch (statusCode) {
    case 200: reason = "Connection Established"; break;
    case 400: reason = "Bad Request"; break;
    case 403: reason = "Forbidden"; break;
    case 405: reason = "Method Not Allowed"; break;
    case 407: reason = "Proxy Authentication Required"; break;
    case 500: reason = "Internal Server Error"; break;
    case 502: reason = "Bad Gateway"; break;
    case 503: reason = "Service Unavailable"; break;
    case 504: reason = "Gateway Timeout"; break;
    default: throw std::invalid_argument("unsupported HTTP proxy response code");
    }
    std::string result = "HTTP/1.1 " + std::to_string(statusCode) + " " + reason + "\r\n";
    if (statusCode != 200) result += "Connection: close\r\nContent-Length: 0\r\n";
    if (statusCode == 405) result += "Allow: CONNECT\r\n";
    if (statusCode == 407) result += "Proxy-Authenticate: Basic realm=\"9NS\"\r\n";
    result += "\r\n";
    return Bytes(result.begin(), result.end());
}
Stage parseHttpResponse(const Bytes& bytes, HttpResponse& out, size_t& consumed) {
    consumed = 0;
    HttpHead head;
    size_t end = 0;
    const Stage stage = httpHead(bytes, head, end);
    if (stage != Stage::Done) return stage;
    if (head.first.size() < 13 || (head.first.compare(0, 9, "HTTP/1.1 ") != 0 &&
        head.first.compare(0, 9, "HTTP/1.0 ") != 0) || head.first[12] != ' ' ||
        !digit(head.first[9]) || !digit(head.first[10]) || !digit(head.first[11])) return Stage::Malformed;
    const int status = (head.first[9] - '0') * 100 + (head.first[10] - '0') * 10 + head.first[11] - '0';
    if (status < 100 || status > 599) return Stage::Malformed;
    out.statusCode = status;
    consumed = end;
    return Stage::Done;
}
RefusalCodes refusalFor(Refusal refusal) {
    switch (refusal) {
    case Refusal::Blocked: return {2, 0x5B, 403};
    case Refusal::NotFound: return {4, 0x5B, 502};
    case Refusal::Failed: return {1, 0x5B, 502};
    case Refusal::Authentication: return {2, 0x5B, 407};
    case Refusal::UnsupportedCommand: return {7, 0x5B, 405};
    case Refusal::UnsupportedAddress: return {8, 0x5B, 400};
    }
    return {1, 0x5B, 502};
}

} // namespace proxyproto
