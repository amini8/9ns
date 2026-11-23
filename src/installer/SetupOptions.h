#pragma once

#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../core/ProtectedDirectory.h"

namespace setup {

enum class Mode { Install, Uninstall, Repair };

struct Options {
    Mode mode = Mode::Install;
    bool keepData = true;
    std::wstring destination, logPath;
    bool desktop = true;
    bool startMenu = true;
    bool service = false;
    bool driver = false;
    bool launch = true;
    bool silent = false;
    bool acceptLicense = false;
    bool help = false;
};

namespace detail {

inline std::wstring setupOptionsLower(std::wstring value) {
    for (auto& ch : value) {
        if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
    }
    return value;
}

}  // namespace detail

inline bool parseOptions(const std::vector<std::wstring>& arguments,
                         Options& options, std::wstring& error) {
    Options parsed = options;
    std::set<std::wstring> seen;
    for (const auto& argument : arguments) {
        const auto equals = argument.find(L'=');
        auto flag = detail::setupOptionsLower(argument.substr(0, equals));
        if (flag == L"/?") flag = L"/help";
        bool* toggle = nullptr;
        if (flag == L"/desktop") toggle = &parsed.desktop;
        else if (flag == L"/startmenu") toggle = &parsed.startMenu;
        else if (flag == L"/service") toggle = &parsed.service;
        else if (flag == L"/driver") toggle = &parsed.driver;
        else if (flag == L"/launch") toggle = &parsed.launch;
        else if (flag == L"/keepdata") toggle = &parsed.keepData;
        const bool standalone = flag == L"/silent" || flag == L"/acceptlicense" || flag == L"/help" ||
                                flag == L"/uninstall" || flag == L"/repair";
        const bool path = flag == L"/dir" || flag == L"/log";
        if (!toggle && !standalone && !path) {
            error = L"Unknown option: " + argument;
            return false;
        }
        if (!seen.insert(flag).second) {
            error = L"Duplicate option: " + flag;
            return false;
        }
        if (standalone) {
            if (equals != std::wstring::npos) {
                error = L"Option does not take a value: " + flag;
                return false;
            }
            if (flag == L"/silent") parsed.silent = true;
            else if (flag == L"/acceptlicense") parsed.acceptLicense = true;
            else if (flag == L"/uninstall") parsed.mode = Mode::Uninstall;
            else if (flag == L"/repair") parsed.mode = Mode::Repair;
            else parsed.help = true;
        } else {
            if (equals == std::wstring::npos || equals + 1 == argument.size()) {
                error = L"Option requires a nonempty value: " + flag;
                return false;
            }
            const auto value = argument.substr(equals + 1);
            if (path) {
                if (flag == L"/dir") parsed.destination = value;
                else parsed.logPath = value;
            } else {
                const auto lower = detail::setupOptionsLower(value);
                if (lower != L"yes" && lower != L"no") {
                    error = L"Option requires yes or no: " + argument;
                    return false;
                }
                *toggle = lower == L"yes";
            }
        }
    }
    if (seen.count(L"/uninstall") && seen.count(L"/repair")) {
        error = L"/uninstall and /repair are mutually exclusive";
        return false;
    }
    if (parsed.mode == Mode::Uninstall) {
        for (const auto* flag : {L"/desktop", L"/startmenu", L"/service", L"/driver", L"/launch"}) {
            if (seen.count(flag)) { error = L"/uninstall rejects installation option: " + std::wstring(flag); return false; }
        }
    } else if (seen.count(L"/keepdata")) {
        error = L"/keepdata is only valid with /uninstall";
        return false;
    }
    if (parsed.mode != Mode::Install) parsed.launch = false;
    if (parsed.silent && parsed.mode == Mode::Install && !parsed.acceptLicense && !parsed.help) {
        error = L"/silent requires /acceptlicense";
        return false;
    }
    if (parsed.silent) parsed.launch = false;
    options = std::move(parsed);
    error.clear();
    return true;
}

inline bool preserveExistingFile(const std::wstring& relative) {
    return detail::setupOptionsLower(relative) == L"config.json";
}

inline bool parsePreviousManifest(const std::string& text,
                                  protected_paths::InstallManifest& manifest,
                                  std::wstring& error) {
    protected_paths::InstallManifest parsed;
    std::set<std::wstring> entries;
    bool files = false, directories = false;
    std::vector<std::wstring>* section = nullptr;
    std::istringstream input(text);
    std::string line;
    size_t lineNumber = 0;
    const auto fail = [&](const std::wstring& reason) {
        error = L"Invalid previous manifest at line " + std::to_wstring(lineNumber) + L": " + reason;
        return false;
    };
    while (std::getline(input, line)) {
        ++lineNumber;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        for (const unsigned char ch : line) {
            if (ch < 0x20 || ch >= 0x7f) return fail(L"expected printable ASCII text");
        }
        if (line.empty() || line[0] == '#') continue;
        if (line == "[files]") {
            if (files) return fail(L"duplicate [files] section");
            files = true;
            section = &parsed.files;
        } else if (line == "[directories]") {
            if (directories) return fail(L"duplicate [directories] section");
            directories = true;
            section = &parsed.directories;
        } else {
            if (line.front() == '[' || line.back() == ']') return fail(L"malformed section header");
            if (!section) return fail(L"entry before section header");
            const std::wstring entry(line.begin(), line.end());
            if (!protected_paths::validateManifestEntry(entry).ok) return fail(L"unsafe entry: " + entry);
            if (!entries.insert(protected_paths::normalizePath(entry)).second) return fail(L"duplicate entry: " + entry);
            if (!preserveExistingFile(entry)) section->push_back(entry);
        }
    }
    if (!files || !directories) return fail(L"both [files] and [directories] sections are required");
    manifest = std::move(parsed);
    error.clear();
    return true;
}

inline void mergePreviousManifest(const protected_paths::InstallManifest& previous,
                                  protected_paths::InstallManifest& current) {
    protected_paths::InstallManifest merged;
    std::set<std::wstring> seen;
    const auto append = [&](const std::vector<std::wstring>& source, std::vector<std::wstring>& target) {
        for (const auto& entry : source) {
            if (!preserveExistingFile(entry) && seen.insert(protected_paths::normalizePath(entry)).second)
                target.push_back(entry);
        }
    };
    append(current.files, merged.files);
    append(current.directories, merged.directories);
    append(previous.files, merged.files);
    append(previous.directories, merged.directories);
    current = std::move(merged);
}

}  // namespace setup
