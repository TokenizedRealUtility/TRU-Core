#include "logging.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <system_error>

std::ofstream Logger::logFile;
std::mutex Logger::logMutex;
bool Logger::initialized = false;
std::string Logger::logPath;
Logger::Level Logger::minimumLevel = Logger::Level::Info;
std::uint64_t Logger::maxBytes = 32ULL * 1024ULL * 1024ULL;
std::uint64_t Logger::currentBytes = 0;
std::size_t Logger::retainedFiles = 4;
std::chrono::steady_clock::time_point Logger::lastFlush{};

namespace {
std::string upperCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string timestampNow() {
    const auto now = std::chrono::system_clock::now();
    const auto nowC = std::chrono::system_clock::to_time_t(now);
    std::tm tmParts{};
#if defined(_WIN32)
    localtime_s(&tmParts, &nowC);
#else
    localtime_r(&nowC, &tmParts);
#endif
    char buffer[32]{};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmParts) == 0) {
        return "0000-00-00 00:00:00";
    }
    return std::string(buffer);
}
} // namespace

Logger::Level Logger::parseLevel(const std::string& value) {
    const std::string normalized = upperCopy(value);
    if (normalized == "ERROR") return Level::Error;
    if (normalized == "WARN" || normalized == "WARNING") return Level::Warn;
    if (normalized == "INFO") return Level::Info;
    if (normalized == "DEBUG") return Level::Debug;
    if (normalized == "TRACE") return Level::Trace;
    throw std::invalid_argument(
        "[Logger] Invalid log level '" + value +
        "' (expected ERROR, WARN, INFO, DEBUG, or TRACE)");
}

const char* Logger::levelName(Level level) {
    switch (level) {
        case Level::Error: return "ERROR";
        case Level::Warn:  return "WARN";
        case Level::Info:  return "INFO";
        case Level::Debug: return "DEBUG";
        case Level::Trace: return "TRACE";
    }
    return "INFO";
}

bool Logger::shouldLogLocked(Level level) {
    return static_cast<unsigned>(level) <= static_cast<unsigned>(minimumLevel);
}

std::string Logger::formatLineLocked(Level level, const std::string& message) {
    return "[" + timestampNow() + "] [" + levelName(level) + "] " + message + "\n";
}

void Logger::openCurrentLocked(bool append) {
    const std::ios::openmode mode = std::ios::out | (append ? std::ios::app : std::ios::trunc);
    logFile.open(logPath, mode);
    if (!logFile.is_open()) {
        throw std::runtime_error("[Logger] Cannot open log file => " + logPath);
    }

    std::error_code ec;
    const auto size = std::filesystem::file_size(logPath, ec);
    currentBytes = ec ? 0ULL : static_cast<std::uint64_t>(size);
    lastFlush = std::chrono::steady_clock::now();
}

void Logger::rotateLocked() {
    if (logFile.is_open()) {
        logFile.flush();
        logFile.close();
    }

    namespace fs = std::filesystem;
    std::error_code ec;

    if (retainedFiles == 0) {
        openCurrentLocked(false);
        return;
    }

    const fs::path active(logPath);
    const fs::path oldest(logPath + "." + std::to_string(retainedFiles));
    fs::remove(oldest, ec);
    ec.clear();

    for (std::size_t i = retainedFiles; i > 1; --i) {
        const fs::path from(logPath + "." + std::to_string(i - 1));
        const fs::path to(logPath + "." + std::to_string(i));
        if (!fs::exists(from, ec)) {
            ec.clear();
            continue;
        }
        fs::rename(from, to, ec);
        if (ec) {
            std::cerr << "[Logger] Rotation rename failed: " << from.string()
                      << " -> " << to.string() << ": " << ec.message() << "\n";
            ec.clear();
        }
    }

    if (fs::exists(active, ec)) {
        ec.clear();
        const fs::path first(logPath + ".1");
        fs::remove(first, ec);
        ec.clear();
        fs::rename(active, first, ec);
        if (ec) {
            // A bounded logger must not continue growing forever if rotation
            // cannot rename the active file. Truncate the active file instead.
            std::cerr << "[Logger] Active-log rotation failed; truncating "
                      << active.string() << ": " << ec.message() << "\n";
            ec.clear();
        }
    }

    openCurrentLocked(false);
}

void Logger::rotateIfNeededLocked(std::uint64_t nextWriteBytes) {
    if (maxBytes == 0) return;
    if (currentBytes == 0) return;
    if (nextWriteBytes > maxBytes || currentBytes > maxBytes - nextWriteBytes) {
        rotateLocked();
    }
}

void Logger::flushIfNeededLocked(Level level) {
    if (!logFile.is_open()) return;

    const bool urgent = (level == Level::Error || level == Level::Warn);
    const auto now = std::chrono::steady_clock::now();
    const bool intervalElapsed =
        (lastFlush == std::chrono::steady_clock::time_point{}) ||
        (now - lastFlush >= std::chrono::seconds(1));

    if (urgent || intervalElapsed) {
        logFile.flush();
        lastFlush = now;
    }
}

void Logger::init(
    const std::string& filename,
    const std::string& configuredLevel,
    std::uint64_t configuredMaxBytes,
    std::size_t configuredRetainedFiles) {

    std::lock_guard<std::mutex> lk(logMutex);
    if (initialized) return;

    if (filename.empty()) {
        throw std::invalid_argument("[Logger] Empty log filename");
    }
    if (configuredMaxBytes == 0) {
        throw std::invalid_argument("[Logger] maxBytes must be greater than zero");
    }
    if (configuredRetainedFiles > 32) {
        throw std::invalid_argument("[Logger] retainedFiles must not exceed 32");
    }

    logPath = filename;
    minimumLevel = parseLevel(configuredLevel);
    maxBytes = configuredMaxBytes;
    retainedFiles = configuredRetainedFiles;

    namespace fs = std::filesystem;
    const fs::path path(logPath);
    const fs::path parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        fs::create_directories(parent, ec);
        if (ec) {
            throw std::runtime_error(
                "[Logger] Cannot create log directory '" + parent.string() +
                "': " + ec.message());
        }
    }

    openCurrentLocked(true);
    if (currentBytes >= maxBytes) {
        rotateLocked();
    }

    initialized = true;
    const std::string startLine =
        formatLineLocked(
            Level::Info,
            "[LOGGING-01C] Starting new session; path=" + logPath +
            "; level=" + levelName(minimumLevel) +
            "; maxBytes=" + std::to_string(maxBytes) +
            "; retained=" + std::to_string(retainedFiles));
    rotateIfNeededLocked(static_cast<std::uint64_t>(startLine.size()));
    logFile << startLine;
    currentBytes += static_cast<std::uint64_t>(startLine.size());
    logFile.flush();
    lastFlush = std::chrono::steady_clock::now();
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lk(logMutex);
    if (!initialized) return;

    const std::string line =
        formatLineLocked(Level::Info, "[LOGGING-01C] Shutting down log");
    rotateIfNeededLocked(static_cast<std::uint64_t>(line.size()));
    logFile << line;
    currentBytes += static_cast<std::uint64_t>(line.size());
    logFile.flush();
    logFile.close();
    initialized = false;
}

void Logger::log(const std::string& message) {
    log(Level::Info, message);
}

void Logger::log(Level level, const std::string& message) {
    std::lock_guard<std::mutex> lk(logMutex);
    if (!initialized) {
        std::cerr << "[Logger not init] [" << levelName(level) << "] "
                  << message << "\n";
        return;
    }
    if (!shouldLogLocked(level)) return;

    const std::string line = formatLineLocked(level, message);
    rotateIfNeededLocked(static_cast<std::uint64_t>(line.size()));
    logFile << line;
    currentBytes += static_cast<std::uint64_t>(line.size());

    if (!logFile.good()) {
        std::cerr << "[Logger] Write failure for " << logPath << "\n";
        logFile.clear();
    }
    flushIfNeededLocked(level);
}

void Logger::error(const std::string& message) { log(Level::Error, message); }
void Logger::warn(const std::string& message)  { log(Level::Warn, message); }
void Logger::info(const std::string& message)  { log(Level::Info, message); }
void Logger::debug(const std::string& message) { log(Level::Debug, message); }
void Logger::trace(const std::string& message) { log(Level::Trace, message); }
