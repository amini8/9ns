#include "core/Logger.h"

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <system_error>

#include "core/Text.h"

namespace {

// The active log is renamed to <name>.1 once it reaches this size, replacing any older copy.
constexpr std::uintmax_t kMaxLogBytes = 5ull * 1024 * 1024;

const char* levelName(Logger::Level level) {
    switch (level) {
    case Logger::Level::Error: return "ERROR";
    case Logger::Level::Info: return "INFO";
    case Logger::Level::Debug: return "DEBUG";
    }
    return "INFO";
}

std::string sanitize(const std::string& text) {
    std::string out = text;
    for (auto& ch : out) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7F) {
            ch = '?';
        }
    }
    return out;
}

} // namespace

void Logger::open(const std::filesystem::path& path, Level minLevel) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = minLevel;
    if (file_.is_open()) {
        file_.close();
    }
    file_.clear();
    path_ = path;
    written_ = 0;
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    const std::uintmax_t existing = std::filesystem::file_size(path, ec);
    if (!ec) {
        written_ = existing;
    }
    file_.open(path, std::ios::app);
    if (!file_) {
        file_.clear();
        path_.clear();
        throw std::runtime_error("cannot open log file: " + narrow(path.wstring()));
    }
}

void Logger::setSink(Sink sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = std::move(sink);
}

void Logger::log(Level level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<int>(level) > static_cast<int>(minLevel_)) {
        return;
    }

    const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm localTime{};
    localtime_s(&localTime, &now);
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &localTime);

    const std::string line = std::string(stamp) + " [" + levelName(level) + "] " + sanitize(message);

    if (file_.is_open()) {
        file_ << line << '\n';
        file_.flush();
        written_ += line.size() + 1;
        if (written_ >= kMaxLogBytes) {
            rotate();
        }
    }
    if (sink_) {
        sink_(line);
    }
}

// Called with mutex_ held.
void Logger::rotate() {
    file_.close();
    file_.clear();

    std::filesystem::path previous = path_;
    previous += L".1";
    std::error_code ec;
    std::filesystem::rename(path_, previous, ec); // replaces an older .1 file on Windows

    file_.open(path_, std::ios::app);
    if (!file_) {
        file_.clear(); // logging continues to the sink only
    }
    written_ = 0;
}
