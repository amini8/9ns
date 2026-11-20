#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "core/Config.h"

// Evaluates rules in priority order. Supports multi-host wildcards, globbing,
// hosts file / blocklist sets, and query types. Interface-bound rules fail closed:
// they only match when the caller supplies a known interface identity.
class Rules {
public:
    explicit Rules(const std::vector<RuleConfig>& rules);

    // Returns the first rule that matches the query parameters, or nullptr.
    // `interfaceGuid` is the originating adapter identity; the empty default means
    // unknown and never matches a rule bound to an interface.
    const RuleConfig* find(const std::string& name, uint16_t qtype = 0, const std::string& interfaceGuid = "") const;

private:
    struct CompiledRule {
        RuleConfig config;
        std::vector<std::string> patterns;
        std::unordered_set<std::string> hostsSet;
    };

    void loadHostsFile(const std::string& path, std::unordered_set<std::string>& out);
    static bool matchPattern(const std::string& text, const std::string& pattern);

    std::vector<CompiledRule> rules_;
};
