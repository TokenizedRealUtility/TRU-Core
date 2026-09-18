#ifndef LOGGING_H
#define LOGGING_H

#include <string>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <iomanip>

class Logger {
public:
    // Initialize logging once near the start of main().
    static void init(const std::string &filename);

    // Close the log during shutdown.
    static void shutdown();

    // Write a message to the log file (thread-safe).
    static void log(const std::string &message);

private:
    static std::ofstream   logFile;
    static std::mutex      logMutex;
    static bool            initialized;
};

#endif // LOGGING_H
