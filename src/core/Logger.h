#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>

class Logger {
public:
    enum class Level { Error = 0, Info = 1, Debug = 2 };

    // Receives each formatted line. It runs on the logging thread while the logger lock is held,
    // so it must be quick and must not call log().
    using Sink = std::function<void(const std::string&)>;

    // Opens the file in append mode, closing any previous file. An empty path means no file.
    // Throws std::runtime_error if the file cannot be opened.
    void open(const std::filesystem::path& path, Level minLevel);

    // Pass nullptr to remove the sink.
    void setSink(Sink sink);

    // Control characters in the message are replaced by '?', so a crafted DNS name cannot forge log lines.
    void log(Level level, const std::string& message);

private:
    void rotate();

    std::mutex mutex_;
    std::filesystem::path path_;
    std::uintmax_t written_ = 0;
    std::ofstream file_;
    Sink sink_;
    Level minLevel_ = Level::Info;
};
