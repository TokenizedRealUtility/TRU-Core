#ifndef LOGGING_H
#define LOGGING_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>

class Logger {
public:
    enum class Level : std::uint8_t {
        Error = 0,
        Warn  = 1,
        Info  = 2,
        Debug = 3,
        Trace = 4
    };

    // LOGGING-01C: initialize a bounded logger. Existing one-argument callers
    // remain source-compatible and receive production-safe defaults.
    static void init(
        const std::string& filename,
        const std::string& minimumLevel = "INFO",
        std::uint64_t maxBytes = 32ULL * 1024ULL * 1024ULL,
        std::size_t retainedFiles = 4);

    static void shutdown();

    // Backward-compatible default: existing Logger::log() calls are INFO.
    static void log(const std::string& message);
    static void log(Level level, const std::string& message);

    static void error(const std::string& message);
    static void warn(const std::string& message);
    static void info(const std::string& message);
    static void debug(const std::string& message);
    static void trace(const std::string& message);

    static Level parseLevel(const std::string& value);
    static const char* levelName(Level level);

private:
    static bool shouldLogLocked(Level level);
    static std::string formatLineLocked(Level level, const std::string& message);
    static void openCurrentLocked(bool append);
    static void rotateLocked();
    static void rotateIfNeededLocked(std::uint64_t nextWriteBytes);
    static void flushIfNeededLocked(Level level);

    static std::ofstream logFile;
    static std::mutex logMutex;
    static bool initialized;
    static std::string logPath;
    static Level minimumLevel;
    static std::uint64_t maxBytes;
    static std::uint64_t currentBytes;
    static std::size_t retainedFiles;
    static std::chrono::steady_clock::time_point lastFlush;
};

#endif // LOGGING_H
