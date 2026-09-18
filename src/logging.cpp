#include "logging.h"
#include <iostream>
#include <chrono>
#include <ctime>

std::ofstream Logger::logFile;
std::mutex    Logger::logMutex;
bool          Logger::initialized = false;

void Logger::init(const std::string &filename)
{
    std::lock_guard<std::mutex> lk(logMutex);
    if (initialized) {
        // Already inited => skip or re-open logic
        return;
    }
    logFile.open(filename, std::ios::out | std::ios::app);
    if(!logFile.is_open()) {
        throw std::runtime_error("[Logger] Cannot open log file => " + filename);
    }
    initialized = true;
    logFile << "\n\n=== Starting new session ===\n";
}

void Logger::shutdown()
{
    std::lock_guard<std::mutex> lk(logMutex);
    if(initialized) {
        logFile << "=== Shutting down log ===\n";
        logFile.close();
        initialized = false;
    }
}

void Logger::log(const std::string &message)
{
    std::lock_guard<std::mutex> lk(logMutex);
    if(!initialized) {
        // If not init, fallback to stderr:
        std::cerr << "[Logger not init] " << message << "\n";
        return;
    }

    // Optional: Add a timestamp to each line
    auto now     = std::chrono::system_clock::now();
    auto now_c   = std::chrono::system_clock::to_time_t(now);
    auto tmParts = *std::localtime(&now_c);

    logFile << "[" 
            << std::put_time(&tmParts, "%Y-%m-%d %H:%M:%S")
            << "] " << message << "\n";
    // flush each line so we don't lose logs if app crashes
    logFile.flush();
}
