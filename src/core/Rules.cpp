#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/Rules.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

namespace {

bool isNumericAddress(const std::string& text) {
    in_addr ipv4{};
    in6_addr ipv6{};
    return inet_pton(AF_INET, text.c_str(), &ipv4) == 1 ||
           inet_pton(AF_INET6, text.c_str(), &ipv6) == 1;
}

std::string normalize(std::string text) {
    while (!text.empty() && text.back() == '.') {
        text.pop_back();
    }
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string typeToString(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";
        case 28: return "AAAA";
        case 5: return "CNAME";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 6: return "SOA";
        case 33: return "SRV";
        case 255: return "ANY";
        default: return std::to_string(qtype);
    }
}

} // namespace

Rules::Rules(const std::vector<RuleConfig>& rules) {
    rules_.reserve(rules.size());
    for (const RuleConfig& rc : rules) {
        CompiledRule cr;
        cr.config = rc;

        // Collect patterns
        std::vector<std::string> rawPatterns = rc.hostnames;
        if (rawPatterns.empty() && !rc.pattern.empty()) {
            rawPatterns.push_back(rc.pattern);
        }
        for (const std::string& p : rawPatterns) {
            if (!p.empty()) {
                cr.patterns.push_back(normalize(p));
            }
        }

        // Load hosts file / blocklist if configured
        if (!rc.hostsFile.empty()) {
            loadHostsFile(rc.hostsFile, cr.hostsSet);
        }

        rules_.push_back(std::move(cr));
    }
}

void Rules::loadHostsFile(const std::string& path, std::unordered_set<std::string>& out) {
    std::ifstream in(path);
    if (!in) {
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        const size_t hash = line.find('#');
        if (hash != std::string::npos) {
            line.resize(hash);
        }
        std::istringstream iss(line);
        std::string first;
        if (!(iss >> first)) {
            continue;
        }
        std::string domain;
        if (isNumericAddress(first)) {
            while (iss >> domain) {
                out.insert(normalize(domain));
            }
        } else {
            out.insert(normalize(first));
        }
    }
}

bool Rules::matchPattern(const std::string& text, const std::string& pattern) {
    if (pattern == "*" || pattern.empty()) {
        return true;
    }
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
        // "*.example.com" matches "sub.example.com" AND "example.com"
        const std::string root = pattern.substr(2);
        if (text == root) {
            return true;
        }
        const std::string suffix = pattern.substr(1);
        return text.size() > suffix.size() && endsWith(text, suffix);
    }

    // Standard glob matching (* and ?)
    const char* str = text.c_str();
    const char* pat = pattern.c_str();
    const char* strStar = nullptr;
    const char* patStar = nullptr;

    while (*str) {
        if (*pat == '?' || *pat == *str) {
            ++pat;
            ++str;
        } else if (*pat == '*') {
            patStar = pat++;
            strStar = str;
        } else if (patStar) {
            pat = patStar + 1;
            str = ++strStar;
        } else {
            return false;
        }
    }
    while (*pat == '*') {
        ++pat;
    }
    return *pat == '\0';
}

const RuleConfig* Rules::find(const std::string& rawName, uint16_t qtype, const std::string& interfaceGuid) const {
    const std::string name = normalize(rawName);
    const std::string typeStr = qtype != 0 ? typeToString(qtype) : "";

    for (const CompiledRule& cr : rules_) {
        // Interface binding fails closed: a bound rule only matches when the
        // originating interface is known and identical. An unknown interface
        // (empty guid) never matches a bound rule.
        if (!cr.config.interfaceGuid.empty()) {
            if (interfaceGuid.empty() || normalize(cr.config.interfaceGuid) != normalize(interfaceGuid)) {
                continue;
            }
        }

        // Check query type filter
        if (!cr.config.queryType.empty() && !typeStr.empty()) {
            if (cr.config.queryType != "ANY" && normalize(cr.config.queryType) != normalize(typeStr)) {
                continue;
            }
        }

        // Check hosts file set
        if (!cr.hostsSet.empty() && cr.hostsSet.count(name) > 0) {
            return &cr.config;
        }

        // Check wildcard patterns
        for (const std::string& p : cr.patterns) {
            if (matchPattern(name, p)) {
                return &cr.config;
            }
        }
    }
    return nullptr;
}
