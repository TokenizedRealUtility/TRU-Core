#include "tru_network_params.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <random>
#include <cxxopts.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <algorithm>
#include <signal.h>
#include <climits>
#include <memory>
// Custom headers
#include "block.h"
#include "tx.h"
#include "sha256_21e8.h"
#include "utils.h"
#include "address_helpers.h"
#include "logging.h"
#include "rpc_utils.h"  // authenticated node RPC
#include "blockchain.h"

// Modern 2025 Color Palette - Enhanced
#define C_RESET     "\033[0m"
#define C_BOLD      "\033[1m"
#define C_DIM       "\033[2m"

// Primary Colors - More Vibrant
#define C_PRIMARY   "\033[38;2;0;255;187m"    // Bright cyan-green
#define C_SECONDARY "\033[38;2;255;107;129m"  // Coral pink
#define C_ACCENT    "\033[38;2;255;206;84m"   // Golden yellow
#define C_FIRE      "\033[38;2;255;69;0m"     // Fire red-orange

// Status Colors - Enhanced
#define C_SUCCESS   "\033[38;2;46;204;113m"   // Modern green
#define C_WARNING   "\033[38;2;255;159;67m"   // Orange
#define C_ERROR     "\033[38;2;255;107;107m"  // Red
#define C_INFO      "\033[38;2;116;185;255m"  // Blue
#define C_ELECTRIC  "\033[38;2;0;255;255m"    // Electric cyan

// Neutral Colors
#define C_TEXT      "\033[38;2;236;240;241m"  // Light gray
#define C_MUTED     "\033[38;2;149;165;166m"  // Muted gray
#define C_DARK      "\033[38;2;52;73;94m"     // Dark blue-gray

// Background Colors
#define BG_CARD     "\033[48;2;30;39;46m"     // Dark card background
#define BG_ACCENT   "\033[48;2;0;25;20m"      // Subtle accent background

// Unicode Symbols for Modern Aesthetics - Enhanced
#define SYMBOL_BLOCK     "■"
#define SYMBOL_HASH      "⧫"
#define SYMBOL_THREAD    "🔥"
#define SYMBOL_SPEED     "⚡"
#define SYMBOL_TIME      "⏱"
#define SYMBOL_PROGRESS  "▓"
#define SYMBOL_EMPTY     "░"
#define SYMBOL_SUCCESS   "✓"
#define SYMBOL_ERROR     "✗"
#define SYMBOL_ARROW     "→"
#define SYMBOL_DOT       "●"
#define SYMBOL_CPU       "🔥"
#define SYMBOL_MINING    "⛏"
#define SYMBOL_COINS     "💰"
#define SYMBOL_ROCKET    "🚀"

// Modern Animation Frames - Enhanced
const std::string PULSE_FRAMES[] = {
    "🔥", "💥", "⚡", "🌟"
};
const std::string MINING_STATES[] = {
    "🔥 INITIALIZING", "⚡ OPTIMIZING", "💫 PROCESSING", "🌟 ANALYZING", 
    "🚀 COMPUTING", "✨ VALIDATING", "🔮 SYNCHRONIZING", "💎 FINALIZING"
};

// Ultra Modern 2025 Color Palette - Cyberpunk Edition
#define C_NEON_PINK    "\033[38;2;255;20;147m"    // Hot pink
#define C_NEON_BLUE    "\033[38;2;0;255;255m"     // Cyan
#define C_NEON_GREEN   "\033[38;2;57;255;20m"     // Neon green
#define C_NEON_PURPLE  "\033[38;2;191;64;191m"    // Purple
#define C_NEON_ORANGE  "\033[38;2;255;140;0m"     // Dark orange
#define C_LASER_RED    "\033[38;2;255;0;100m"     // Laser red

// Gradient effects
#define GRAD_FIRE_1    "\033[38;2;255;0;0m"       // Red
#define GRAD_FIRE_2    "\033[38;2;255;69;0m"      // Orange red
#define GRAD_FIRE_3    "\033[38;2;255;140;0m"     // Dark orange
#define GRAD_FIRE_4    "\033[38;2;255;215;0m"     // Gold
#define GRAD_FIRE_5    "\033[38;2;255;255;0m"     // Yellow

// Enhanced animation frames
const std::string ULTRA_PULSE_FRAMES[] = {
    "🔥", "💥", "⚡", "🌟", "💫", "✨", "🔮", "💎", "🚀", "🌈"
};

const std::string CPU_HEAT_LEVELS[] = {
    "❄️ COLD", "🟦 COOL", "🟩 WARM", "🟨 HOT", "🟧 BURNING", "🔥 MELTING", "💥 NUCLEAR"
};

const std::string MATRIX_RAIN[] = {
    "░", "▒", "▓", "█", "▀", "▄", "■", "□", "▪", "▫"
};

// Structure to hold CPU information
struct CpuInfo {
    std::string model;
    int threads;
};

// Global variables - Enhanced
std::atomic<bool> g_shutdown(false);
std::atomic<uint64_t> g_totalHashes(0);  // Global hash counter for accurate stats
std::atomic<bool> g_found(false);
std::atomic<uint64_t> g_foundNonce(0);
std::chrono::steady_clock::time_point g_minerStartTime; 

// Signal handler
void signalHandler(int sig) {
    Logger::log("[SIGNAL] Received signal " + std::to_string(sig) + ", initiating shutdown");
    std::cout << C_ERROR << "\n╭─ 🔥 CPU MINER SHUTDOWN 🔥 ─╮\n" 
              << "│ Signal: " << sig << "                │\n"
              << "╰─ Graceful Exit ────────────╯" << C_RESET << "\n";
    g_shutdown.store(true);
}

void showBlockFoundAnimation() {
    const int frames = 30;
    const std::string celebration[] = {"🎆", "🎇", "✨", "💫", "⭐", "🌟", "💎", "🏆", "🎉", "🎊"};
    
    Logger::log("[ANIMATION] Starting block found celebration animation");
    
    for (int frame = 0; frame < frames; frame++) {
        std::cout << "\033[2J\033[1;1H"; // Clear screen
        
        // Create explosive effect
        std::cout << "\n\n\n";
        for (int y = 0; y < 15; y++) {
            for (int x = 0; x < 80; x++) {
                double dist = sqrt(pow(x - 40, 2) + pow(y - 7, 2) * 4);
                if (dist < frame * 2 && dist > frame * 2 - 3) {
                    std::cout << celebration[rand() % 10];
                } else {
                    std::cout << " ";
                }
            }
            std::cout << "\n";
        }
        
        // Central message with pulsing effect
        std::string color = (frame % 2 == 0) ? C_FIRE : C_NEON_PINK;
        std::cout << "\n" << color << C_BOLD;
        std::cout << "                    ╔═══════════════════════════════╗\n";
        std::cout << "                    ║    💎 BLOCK DISCOVERED! 💎    ║\n";
        std::cout << "                    ║      REWARD INCOMING!         ║\n";
        std::cout << "                    ╚═══════════════════════════════╝\n";
        std::cout << C_RESET;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    Logger::log("[ANIMATION] Block found animation completed");
}

bool registerMinerWithRetry(httplib::Client& cli, const std::string& minerAddr, const std::string& minerType) {
    const int maxRetries = 5;
    Logger::log("[REGISTRATION] Starting miner registration for " + minerType + " miner: " + minerAddr);
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            nlohmann::json regReq;
            regReq["jsonrpc"] = "2.0";
            regReq["id"] = 1;
            regReq["method"] = "registerminer";
            regReq["params"] = {{"minerAddress", minerAddr}};
            
            Logger::log("[REGISTRATION] Attempt " + std::to_string(attempt) + "/" + std::to_string(maxRetries) + 
                       " - Sending registration request");
            
            auto regRes = cli.Post("/rpc", regReq.dump(), "application/json");
            
            if (regRes && regRes->status == 200) {
                try {
                    auto jsonResponse = nlohmann::json::parse(regRes->body);
                    if (!jsonResponse.contains("error")) {
                        Logger::log("[REGISTRATION] SUCCESS - " + minerType + " miner registered: " + 
                                   minerAddr + " (attempt " + std::to_string(attempt) + ")");
                        std::cout << C_SUCCESS << "[" << minerType << "] Successfully registered: " 
                                  << minerAddr << " (attempt " << attempt << ")" << C_RESET << "\n";
                        return true;
                    } else {
                        std::string errorMsg = jsonResponse["error"].dump();
                        Logger::log("[REGISTRATION] WARNING - Registration returned error: " + errorMsg);
                    }
                } catch (const std::exception& e) {
                    Logger::log("[REGISTRATION] ERROR - Failed to parse registration response: " + 
                               std::string(e.what()));
                }
            } else {
                std::string status = regRes ? std::to_string(regRes->status) : "no response";
                Logger::log("[REGISTRATION] WARNING - Registration failed, status: " + status + 
                           " (attempt " + std::to_string(attempt) + ")");
            }
        } catch (const std::exception& e) {
            Logger::log("[REGISTRATION] EXCEPTION - " + std::string(e.what()) + 
                       " (attempt " + std::to_string(attempt) + ")");
        }
        
        if (attempt < maxRetries) {
            int backoffSeconds = 2 * attempt;
            Logger::log("[REGISTRATION] Backing off for " + std::to_string(backoffSeconds) + " seconds");
            std::this_thread::sleep_for(std::chrono::seconds(backoffSeconds));
        }
    }
    
    Logger::log("[REGISTRATION] FAILED - Could not register after " + std::to_string(maxRetries) + " attempts");
    std::cout << C_ERROR << "[" << minerType << "] Failed to register after " 
              << maxRetries << " attempts" << C_RESET << "\n";
    return false;
}

// Get CPU information
CpuInfo getCpuInfo() {
    CpuInfo info;
    info.threads = std::thread::hardware_concurrency();
    info.model = "Unknown CPU";

    Logger::log("[CPUINFO] Detecting CPU information");
    
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                size_t colonPos = line.find(':');
                if (colonPos != std::string::npos) {
                    info.model = line.substr(colonPos + 1);
                    info.model.erase(0, info.model.find_first_not_of(" \t"));
                    info.model.erase(info.model.find_last_not_of(" \t") + 1);
                }
                break;
            }
        }
        cpuinfo.close();
    }
    
    Logger::log("[CPUINFO] Detected: " + info.model + " with " + std::to_string(info.threads) + " threads");
    return info;
}

// Format hash rate with modern units
std::string formatHashRate(double hashRate) {
    const char* units[] = {"H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"};
    int unitIndex = 0;
    while (hashRate >= 1000 && unitIndex < 5) {
        hashRate /= 1000;
        unitIndex++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << hashRate << " " << units[unitIndex];
    return oss.str();
}

// Format time duration — show milliseconds
std::string formatDuration(double seconds) {
    int hours = static_cast<int>(seconds) / 3600;
    int minutes = (static_cast<int>(seconds) % 3600) / 60;
    int secs = static_cast<int>(seconds) % 60;
    int millisecs = static_cast<int>((seconds - static_cast<int>(seconds)) * 1000);
    
    std::ostringstream oss;
    if (hours > 0) {
        oss << hours << "h " << minutes << "m " << secs << "s";
    } else if (minutes > 0) {
        oss << minutes << "m " << secs << "s";
    } else if (secs > 0) {
        oss << secs << "." << std::setfill('0') << std::setw(1) << (millisecs / 100) << "s";
    } else {
        oss << "0." << std::setfill('0') << std::setw(3) << millisecs << "s";
    }
    return oss.str();
}

// Create modern progress bar
std::string createProgressBar(double percentage, int width = 30) {
    int filled = static_cast<int>(percentage * width / 100.0);
    std::string bar = "";
    
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            bar += SYMBOL_PROGRESS;
        } else {
            bar += SYMBOL_EMPTY;
        }
    }
    return bar;
}

// Enhanced Modern CPU Miner Interface - GPU Style
void printUltraModernCPUMinerInterface(int statusCode, int blockHeight, int nThreads, int maxThreads, 
                                       uint64_t maxNonce, const std::vector<uint64_t>& threadNonces, 
                                       double hashRate, double elapsed, int animFrame, uint64_t totalHashes, 
                                       uint32_t difficultyBits, bool firstCall, bool quiet, 
                                       const std::string& minerAddr, uint64_t blockCount, const CpuInfo& cpuInfo,
                                       bool foundSolution = false) {
    if (quiet) return;

    // Calculate dynamic values for animations
    double cpuTemp = std::min(90.0, 30.0 + (hashRate / 1000000.0) * 60.0); // Simulated CPU temp
    int heatLevel = std::min(6, (int)(cpuTemp / 15.0));
    double efficiency = nThreads > 0 ? (hashRate / nThreads) : 0.0; // H/s per thread
    
    if (firstCall) {
        Logger::log("[UI] Initializing ultra modern CPU miner interface");
        
        // Clear screen with style
        std::cout << "\033[2J\033[1;1H";
        
        // Ultra header with animated gradient effect
        std::cout << C_NEON_PINK << "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n";
        std::cout << "┃ " << GRAD_FIRE_1 << "████████╗" << GRAD_FIRE_2 << "██████╗ " << GRAD_FIRE_3 << "██╗   ██╗" 
                  << GRAD_FIRE_4 << "    ███╗   ███╗" << GRAD_FIRE_5 << "██╗███╗   ██╗" << C_NEON_GREEN << "███████╗" << C_NEON_BLUE << "██████╗  " << C_NEON_PINK << "┃\n";
        std::cout << "┃ " << GRAD_FIRE_1 << "╚══██╔══╝" << GRAD_FIRE_2 << "██╔══██╗" << GRAD_FIRE_3 << "██║   ██║" 
                  << GRAD_FIRE_4 << "    ████╗ ████║" << GRAD_FIRE_5 << "██║████╗  ██║" << C_NEON_GREEN << "██╔════╝" << C_NEON_BLUE << "██╔══██╗ " << C_NEON_PINK << "┃\n";
        std::cout << "┃ " << GRAD_FIRE_1 << "   ██║   " << GRAD_FIRE_2 << "██████╔╝" << GRAD_FIRE_3 << "██║   ██║" 
                  << GRAD_FIRE_4 << "    ██╔████╔██║" << GRAD_FIRE_5 << "██║██╔██╗ ██║" << C_NEON_GREEN << "█████╗  " << C_NEON_BLUE << "██████╔╝ " << C_NEON_PINK << "┃\n";
        std::cout << "┃ " << GRAD_FIRE_1 << "   ██║   " << GRAD_FIRE_2 << "██╔══██╗" << GRAD_FIRE_3 << "██║   ██║" 
                  << GRAD_FIRE_4 << "    ██║╚██╔╝██║" << GRAD_FIRE_5 << "██║██║╚██╗██║" << C_NEON_GREEN << "██╔══╝  " << C_NEON_BLUE << "██╔══██╗ " << C_NEON_PINK << "┃\n";
        std::cout << "┃ " << GRAD_FIRE_1 << "   ██║   " << GRAD_FIRE_2 << "██║  ██║" << GRAD_FIRE_3 << "╚██████╔╝" 
                  << GRAD_FIRE_4 << "    ██║ ╚═╝ ██║" << GRAD_FIRE_5 << "██║██║ ╚████║" << C_NEON_GREEN << "███████╗" << C_NEON_BLUE << "██║  ██║ " << C_NEON_PINK << "┃\n";
        std::cout << "┃ " << C_RESET << C_MUTED << "                    PROFESSIONAL CPU MINING SUITE v5.0 ULTRA                  " << C_NEON_PINK << "┃\n";
        std::cout << "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" << C_RESET << "\n\n";

        // CPU Configuration with heat visualization
        std::cout << C_NEON_BLUE << "╔═══════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║ " << C_LASER_RED << "⚡ QUANTUM CPU CONFIGURATION ⚡" << std::string(44, ' ') << C_NEON_BLUE << "║\n";
        std::cout << "╠═══════════════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ " << C_TEXT << "Processor  " << C_NEON_GREEN << cpuInfo.model.substr(0, 50) << std::string(53 - std::min(50, (int)cpuInfo.model.length()), ' ') << C_NEON_BLUE << "║\n";
        std::cout << "║ " << C_TEXT << "Cores      " << C_FIRE << nThreads << C_MUTED << "/" << maxThreads 
                  << C_NEON_ORANGE << " BLAZING 🔥 | Architecture: " << C_NEON_PURPLE << "x86_64" << std::string(19, ' ') << C_NEON_BLUE << "║\n";
        std::cout << "║ " << C_TEXT << "Algorithm  " << C_NEON_PINK << "SHA256-21E8 TURBO" << C_MUTED << " | Protocol: " << C_ACCENT << "TRU BLOCKCHAIN" << std::string(17, ' ') << C_NEON_BLUE << "║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════════════╝" << C_RESET << "\n\n";

        // Create space for dynamic content
        for (int i = 0; i < 30; i++) {
            std::cout << std::string(80, ' ') << "\n";
        }
    }

    // Dynamic content starts here - move cursor
    std::cout << "\033[11;1H"; // Move to line 11

    // Live Performance Dashboard with matrix effect
    std::cout << C_NEON_GREEN << "╔══ ⚡ LIVE PERFORMANCE MATRIX ═════════════════════════════════════════════╗\n";
    
    // Create animated matrix background effect
    std::string matrixLine = "║ ";
    for (int i = 0; i < 73; i++) {
        if ((i + animFrame) % 7 == 0) {
            matrixLine += C_NEON_GREEN + MATRIX_RAIN[(animFrame + i) % 10] + C_TEXT;
        } else {
            matrixLine += " ";
        }
    }
    std::cout << matrixLine << " ║\n";

    // Hash rate with pulsing effect
    std::string pulseColor = (animFrame % 2 == 0) ? C_NEON_PINK : C_LASER_RED;
    std::cout << "║ " << pulseColor << "HASH POWER " << ULTRA_PULSE_FRAMES[animFrame % 10] 
              << C_TEXT << " " << C_FIRE << std::setw(12) << formatHashRate(hashRate) 
              << C_MUTED << " │ " << C_NEON_BLUE << "Per Core: " << C_ACCENT 
              << std::fixed << std::setprecision(1) << efficiency << " H/s"  // Changed from KH/s to H/s
              << std::string(20, ' ') << C_NEON_GREEN << "║\n";

    // CPU Temperature with dynamic heat indicator
    std::cout << "║ " << C_TEXT << "CPU TEMP   " << CPU_HEAT_LEVELS[heatLevel] 
              << " " << C_FIRE << std::fixed << std::setprecision(1) << cpuTemp << "°C" 
              << C_MUTED << " │ " << C_NEON_PURPLE << "Load: ";
    
    // CPU load bar with gradient
    int loadPercent = std::min(100, (int)(hashRate / 10000000.0 * 100));
    for (int i = 0; i < 20; i++) {
        if (i < loadPercent / 5) {
            if (i < 5) std::cout << C_NEON_BLUE << "█";
            else if (i < 10) std::cout << C_NEON_GREEN << "█";
            else if (i < 15) std::cout << C_NEON_ORANGE << "█";
            else std::cout << C_LASER_RED << "█";
        } else {
            std::cout << C_MUTED << "░";
        }
    }
    std::cout << " " << loadPercent << "%" << std::string(5, ' ') << C_NEON_GREEN << "║\n";

    std::cout << matrixLine << " ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════╝" << C_RESET << "\n\n";

    // Mining Progress with cyberpunk style
    double progressPercent = (threadNonces.size() > 0) ? (double)threadNonces[0] / maxNonce * 100.0 : 0.0;
    
    std::cout << C_NEON_PURPLE << "╔══ 🔮 QUANTUM MINING PROGRESS ════════════════════════════════════════════╗\n";
    std::cout << "║ " << C_TEXT << "Block #" << C_FIRE << blockHeight 
              << C_MUTED << " | Difficulty: " << C_NEON_BLUE << "0x" << std::hex << difficultyBits << std::dec 
              << C_MUTED << " | Nonce: " << C_ACCENT << (threadNonces.size() > 0 ? std::to_string(threadNonces[0]) : "0")
              << std::string(15, ' ') << C_NEON_PURPLE << "║\n";
    
    // Enhanced progress bar with wave effect
    std::cout << "║ ";
    for (int i = 0; i < 50; i++) {
        double waveOffset = sin((i + animFrame) * 0.3) * 0.5 + 0.5;
        if (i < progressPercent / 2) {
            if (waveOffset > 0.3) {
                std::cout << ((i + animFrame) % 3 == 0 ? C_NEON_PINK : C_LASER_RED) << "█";
            } else {
                std::cout << C_FIRE << "▓";
            }
        } else {
            std::cout << C_DARK << "░";
        }
    }
    std::cout << " " << C_ACCENT << std::fixed << std::setprecision(1) << progressPercent << "%" 
              << std::string(10, ' ') << C_NEON_PURPLE << "║\n";
    
    // Status with animated effect
    std::string statusText = foundSolution ? "💎 BLOCK FOUND! 💎" : MINING_STATES[animFrame % 8];
    std::string statusColor = foundSolution ? C_FIRE : C_NEON_GREEN;
    std::cout << "║ " << statusColor << statusText << std::string(73 - statusText.length(), ' ') << C_NEON_PURPLE << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════╝" << C_RESET << "\n\n";

    // Statistics Dashboard
    std::cout << C_NEON_ORANGE << "╔══ 📊 MINING STATISTICS ═══════════════════════════════════════════════════╗\n";
    std::cout << "║ " << C_TEXT << "Runtime      " << C_NEON_BLUE << formatDuration(elapsed) 
              << C_MUTED << " │ " << C_TEXT << "Total Hashes " << C_ACCENT << std::setw(15) << totalHashes 
              << C_MUTED << " │ " << C_TEXT << "Blocks " << C_NEON_GREEN << blockCount << std::string(10, ' ') << C_NEON_ORANGE << "║\n";
    
    // Efficiency meter with spark effect
    std::cout << "║ " << C_TEXT << "Efficiency   ";
    for (int i = 0; i < 10; i++) {
        if (i < efficiency / 10) {
            std::cout << ((animFrame + i) % 2 == 0 ? C_NEON_GREEN : C_NEON_BLUE) << "⚡";
        } else {
            std::cout << C_DARK << "·";
        }
    }
    std::cout << C_MUTED << " │ " << C_TEXT << "Avg Rate     " << C_FIRE 
              << formatHashRate(elapsed > 0 ? totalHashes / elapsed : 0) << std::string(18, ' ') << C_NEON_ORANGE << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════╝" << C_RESET << "\n\n";

    // Wallet info with glow effect
    std::string glowColor = (animFrame % 3 == 0) ? C_NEON_PINK : ((animFrame % 3 == 1) ? C_NEON_PURPLE : C_NEON_BLUE);
    std::cout << glowColor << "╔══ 💎 WALLET ══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║ " << C_TEXT << minerAddr << std::string(73 - minerAddr.length(), ' ') << glowColor << "║\n";
    std::cout << "║ " << C_TEXT << "Rewards: " << C_NEON_GREEN << blockCount << " blocks " << SYMBOL_COINS 
              << C_MUTED << " │ Status: " << C_SUCCESS << "ACTIVE 🟢" << std::string(30, ' ') << glowColor << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════════════╝" << C_RESET << "\n";

    // Add scrolling message at bottom
    std::string message = ">>> TRU BLOCKCHAIN - NEXT GENERATION MINING - POWERED BY QUANTUM COMPUTING <<<";
    int scrollPos = animFrame % (message.length() + 20);
    std::cout << "\n" << C_NEON_PINK;
    for (int i = 0; i < 78; i++) {
        int msgPos = i - scrollPos + 10;
        if (msgPos >= 0 && msgPos < message.length()) {
            std::cout << message[msgPos];
        } else {
            std::cout << " ";
        }
    }
    std::cout << C_RESET << "\n";

    std::cout << std::flush;
    
    // Log performance metrics periodically
    if (animFrame % 50 == 0) {
        std::ostringstream perfLog;
        perfLog << "[PERFORMANCE] Block: " << blockHeight 
                << ", HashRate: " << formatHashRate(hashRate)
                << ", Efficiency: " << std::fixed << std::setprecision(2) << efficiency << " H/s/thread"  // FIXED
                << ", Progress: " << std::fixed << std::setprecision(1) << progressPercent << "%"
                << ", TotalHashes: " << totalHashes;
        Logger::log(perfLog.str());
    }
}

// Enhanced progress thread — accept blockCount by reference
void progressThread(std::atomic<int>& miningStatus, std::atomic<uint64_t>& totalHashes,
                    int blockHeight, int nThreads, int maxThreads, uint64_t maxNonce,
                    std::vector<uint64_t>& threadNonces, int updateInterval, bool quiet,
                    httplib::Client& cli, const std::string& minerAddr, uint64_t& blockCount, 
                    const CpuInfo& cpuInfo, uint32_t difficultyBits) {  // real bits
    Logger::log("[PROGRESS] Starting progress thread for block " + std::to_string(blockHeight));
    
    auto startTime = std::chrono::steady_clock::now();
    auto previousTime = startTime;
    uint64_t previousHashes = 0;
    int animFrame = 0;
    bool firstCall = true;

    while (miningStatus.load() == 0 && !g_shutdown.load()) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - startTime).count();
        double interval = std::chrono::duration<double>(now - previousTime).count();

        uint64_t currentHashes = totalHashes.load();
        double intervalHashes = currentHashes - previousHashes;
        double currentHashRate = (interval > 0) ? (intervalHashes / interval) : 0.0;

        printUltraModernCPUMinerInterface(0, blockHeight, nThreads, maxThreads, maxNonce, threadNonces,
                                    currentHashRate, elapsed, animFrame, currentHashes, difficultyBits,  // FIX(patch44)
                                    firstCall, quiet, minerAddr, blockCount, cpuInfo, g_found.load());

        // Send activity report with enhanced error handling
        if (!quiet && interval > 0) {
            try {
                nlohmann::json updateReq;
                updateReq["jsonrpc"] = "2.0";
                updateReq["id"] = 1;
                updateReq["method"] = "reportmineractivity";
                updateReq["params"] = {
                    {"minerAddress", minerAddr}, 
                    {"hashesTried", static_cast<uint64_t>(intervalHashes)}, 
                    {"timeTaken", interval}
                };
                
                Logger::log("[PROGRESS] Reporting activity: " + std::to_string(static_cast<uint64_t>(intervalHashes)) + 
                           " hashes in " + std::to_string(interval) + "s");
                
                auto res = cli.Post("/rpc", updateReq.dump(), "application/json");
                
                if (!res || res->status != 200) {
                    Logger::log("[PROGRESS] WARNING - Activity report failed: " + 
                               (res ? "status " + std::to_string(res->status) : "no response"));
                }
            } catch (const std::exception& e) {
                Logger::log("[PROGRESS] ERROR - Exception reporting activity: " + std::string(e.what()));
            }
        }

        firstCall = false;
        previousTime = now;
        previousHashes = currentHashes;
        animFrame++;
        std::this_thread::sleep_for(std::chrono::milliseconds(updateInterval));
    }

    // Enhanced final status update
    double finalElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
    uint64_t finalHashes = totalHashes.load();
    double finalHashRate = (finalElapsed > 0) ? (finalHashes / finalElapsed) : 0.0;
    
    Logger::log("[PROGRESS] Mining completed - Status: " + std::to_string(miningStatus.load()) + 
               ", Total hashes: " + std::to_string(finalHashes) + 
               ", Final rate: " + formatHashRate(finalHashRate));
    
    printUltraModernCPUMinerInterface(miningStatus.load(), blockHeight, nThreads, maxThreads, maxNonce,
                                threadNonces, finalHashRate, finalElapsed, animFrame, finalHashes,
                                difficultyBits, false, quiet, minerAddr, blockCount, cpuInfo, g_found.load());  // FIX(patch44)
    
    if (miningStatus.load() == 1) {
        Logger::log("[PROGRESS] BLOCK FOUND! Nonce: " + std::to_string(g_foundNonce.load()));
        
        std::cout << "\n" << C_FIRE << C_BOLD << "╭─ 🎉 BLOCK FOUND! ──────────────────────────────────────────────╮\n";
        std::cout << "│ " << SYMBOL_SUCCESS << " Successfully mined block #" << blockHeight << std::string(28, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_HASH << " Final hash rate: " << formatHashRate(finalHashRate) << std::string(28, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_TIME << " Mining time: " << formatDuration(finalElapsed) << std::string(33, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_COINS << " Nonce found: " << g_foundNonce.load() << std::string(33, ' ') << "│\n";
        std::cout << "╰─────────────────────────────────────────────────────────────────╯" << C_RESET << "\n";
    }
}

// Double SHA-256 with 21E8 tweak
// allocation-free variant used by the mining hot loop.
// The original returned a std::vector by value, which meant one heap
// allocation and one free for EVERY nonce tried.  Writing into a caller
// supplied 32-byte buffer removes that entirely.
static inline void doubleSha256_21E8(const unsigned char* hdr80, unsigned char out[32]) {
    if (!hdr80) throw std::invalid_argument("Null header pointer");
    unsigned char hash1[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hdr80, 80);
    SHA256_Final(hash1, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash1, 32);
    SHA256_Final(out, &ctx);
    uint32_t last32 = ((uint32_t)out[28] << 24) | ((uint32_t)out[29] << 16) |
                      ((uint32_t)out[30] << 8) | (uint32_t)out[31];
    last32 = (last32 + 0x21E8U) & 0xffffffffU;
    out[28] = (unsigned char)((last32 >> 24) & 0xff);
    out[29] = (unsigned char)((last32 >> 16) & 0xff);
    out[30] = (unsigned char)((last32 >> 8) & 0xff);
    out[31] = (unsigned char)(last32 & 0xff);
}

// Retained for any non-hot-path caller; identical output.
[[maybe_unused]] static std::vector<unsigned char> doubleSha256_21E8(const unsigned char* hdr80) {
    if (!hdr80) throw std::invalid_argument("Null header pointer");
    unsigned char hash1[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hdr80, 80);
    SHA256_Final(hash1, &ctx);
    unsigned char hash2[32];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash1, 32);
    SHA256_Final(hash2, &ctx);
    uint32_t last32 = ((uint32_t)hash2[28] << 24) | ((uint32_t)hash2[29] << 16) |
                      ((uint32_t)hash2[30] << 8) | (uint32_t)hash2[31];
    last32 = (last32 + 0x21E8U) & 0xffffffffU;
    hash2[28] = (unsigned char)((last32 >> 24) & 0xff);
    hash2[29] = (unsigned char)((last32 >> 16) & 0xff);
    hash2[30] = (unsigned char)((last32 >> 8) & 0xff);
    hash2[31] = (unsigned char)(last32 & 0xff);
    return std::vector<unsigned char>(hash2, hash2 + 32);
}

// Enhanced CPU mining function with accurate hash counting — accept blockCount by reference
static bool mineBlockCPU_21E8(Block& candidate, uint64_t maxNonce, int nThreads, httplib::Client& cli,
                              const std::string& minerAddr, int& extraNonce, const CpuInfo& cpuInfo, uint64_t& blockCount) {
    Logger::log("[MINING] Starting CPU mining for block " + std::to_string(candidate.height) + 
               " with " + std::to_string(nThreads) + " threads");
    
    std::vector<unsigned char> header80 = buildBlockHeader80(candidate.header);
    unsigned char targetBE[32];
    bitsToTargetArrayFree(candidate.header.bits, targetBE);

    std::atomic<bool> found(false);
    std::mutex resultMutex;
    uint64_t foundNonce = 0;
    std::atomic<uint64_t> totalHashes(0);
    std::vector<uint64_t> threadNonces(nThreads, 0);
    std::atomic<int> miningStatus(0);

    // MINER-TIME-01A: bound one CPU candidate to 30 seconds of local work.
    // A fresh getblocktemplate is fetched after this attempt ends, so the
    // miner does not keep hashing an increasingly stale header timestamp.
    std::atomic<bool> refreshRequested(false);
    const auto workStartedAt = std::chrono::steady_clock::now();
    constexpr auto kMaxCandidateWorkAge = std::chrono::seconds(30);

    // REMOVED: uint64_t blockCount = 0; - Now using the passed reference

    // reset only per-attempt solution state.
    //
    // g_totalHashes is intentionally NOT reset here. It is a session-wide
    // cumulative counter used by the keepalive thread to calculate:
    //
    //     currentHashes - lastTotalHashes
    //
    // Resetting it for each mining attempt caused unsigned underflow and
    // bogus UINT64_MAX / petahash activity reports.
    g_found.store(false);
    g_foundNonce.store(0);

    // Log mining parameters
    std::ostringstream miningParams;
    miningParams << "[MINING] Parameters - MaxNonce: " << maxNonce 
                 << ", Bits: 0x" << std::hex << candidate.header.bits
                 << ", ExtraNonce: " << std::dec << extraNonce;
    Logger::log(miningParams.str());

    auto worker = [&](unsigned tid) {
        Logger::log("[WORKER] Thread " + std::to_string(tid) + " started");
        
        std::vector<unsigned char> localHdr(header80);
        uint64_t localHashCount = 0;
        // reused stack buffer, see doubleSha256_21E8 overload.
        unsigned char finalHash[32];
        
        for (uint64_t nonce = tid;
             nonce < maxNonce &&
             !found.load(std::memory_order_relaxed) &&
             !refreshRequested.load(std::memory_order_relaxed) &&
             !g_shutdown.load();
             nonce += nThreads) {

            // Check the steady-clock deadline periodically rather than on every
            // hash, keeping hot-loop overhead negligible.
            if ((localHashCount & 0xFFFFULL) == 0ULL &&
                std::chrono::steady_clock::now() - workStartedAt >= kMaxCandidateWorkAge) {
                refreshRequested.store(true, std::memory_order_relaxed);
                break;
            }

            localHdr[76] = (unsigned char)(nonce & 0xff);
            localHdr[77] = (unsigned char)((nonce >> 8) & 0xff);
            localHdr[78] = (unsigned char)((nonce >> 16) & 0xff);
            localHdr[79] = (unsigned char)((nonce >> 24) & 0xff);

            doubleSha256_21E8(localHdr.data(), finalHash);   // no per-hash allocation
            
            // CRITICAL: Increment both local and global hash counters for accurate stats
            totalHashes.fetch_add(1, std::memory_order_relaxed);
            g_totalHashes.fetch_add(1, std::memory_order_relaxed);
            localHashCount++;
            
            // use the canonical PoW comparison. The old loop
            // treated byte 0 as most-significant (big-endian), but the target
            // from bitsToTargetArrayFree() is little-endian, so it never matched
            // valid hashes. compare256LE() (utils.h) iterates byte 31 -> 0, the
            // same as the node and the fixed GPU miner.
            bool below = compare256LE(finalHash, targetBE);
            if (below) {
                std::lock_guard<std::mutex> lk(resultMutex);
                if (!found.exchange(true)) {
                    foundNonce = nonce;
                    g_found.store(true);
                    g_foundNonce.store(nonce);
                    
                    // Log the found solution
                    std::ostringstream foundLog;
                    foundLog << "[WORKER] Thread " << tid << " FOUND SOLUTION! Nonce: " << nonce 
                             << ", Hash: ";
                    for (auto byte : finalHash) {
                        foundLog << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
                    }
                    Logger::log(foundLog.str());
                }
                break;
            }
            if (nonce % 1000 == 0) threadNonces[tid] = nonce;
            
            // Log progress every 1M hashes
            if (localHashCount % 1000000 == 0) {
                Logger::log("[WORKER] Thread " + std::to_string(tid) + " processed " + 
                           std::to_string(localHashCount) + " hashes, current nonce: " + std::to_string(nonce));
            }
        }
        
        Logger::log("[WORKER] Thread " + std::to_string(tid) + " finished - Total hashes: " + 
                   std::to_string(localHashCount));
    };

    std::vector<std::thread> threads;
    threads.reserve(nThreads);
    for (unsigned i = 0; i < nThreads; i++) threads.emplace_back(worker, i);

    std::thread progThread(progressThread, std::ref(miningStatus), std::ref(totalHashes),
                           candidate.height, nThreads, cpuInfo.threads, maxNonce, std::ref(threadNonces),
                           200, false, std::ref(cli), minerAddr, std::ref(blockCount), std::ref(cpuInfo),
                           candidate.header.bits);  // pass real difficulty bits

    for (auto& t : threads) t.join();

    // Hard closeout gate: even if a worker was delayed by scheduling after the
    // periodic deadline check, never submit work held beyond the 30s bound.
    const auto workEndedAt = std::chrono::steady_clock::now();
    if (found.load() && workEndedAt - workStartedAt > kMaxCandidateWorkAge) {
        Logger::log(
            "[MINER-TIME-01A] CPU solution discarded because candidate work age "
            "exceeded 30 seconds; requesting fresh getblocktemplate");
        found.store(false);
        g_found.store(false);
        refreshRequested.store(true, std::memory_order_relaxed);
    }

    if (found.load()) {
        miningStatus.store(1);
        candidate.header.nonce = foundNonce;
        candidate.blockHash = candidate.computeHash();
        
        Logger::log("[MINING] Block found! Nonce: " + std::to_string(foundNonce) + 
                   ", Hash: " + candidate.blockHash);
    } else {
        miningStatus.store(2);
        if (refreshRequested.load(std::memory_order_relaxed)) {
            Logger::log(
                "[MINER-TIME-01A] CPU candidate age limit reached; "
                "requesting fresh getblocktemplate");
        } else {
            Logger::log("[MINING] No solution found within nonce range");
        }
    }
    progThread.join();

    return found.load();
}

// Build coinbase transaction
static Transaction buildCoinbaseTx(const std::string& minerAddr, uint64_t rewardSat, int32_t blockHeight, int extraNonce) {
    Logger::log("[COINBASE] Building coinbase tx for block " + std::to_string(blockHeight) + 
               ", reward: " + std::to_string(rewardSat) + " TRU atoms");
    
    Transaction coinbase(true);
    std::ostringstream oss;
    oss << "TRU:" << blockHeight << "|CPU:" << extraNonce;
    std::string extraNonceStr = oss.str();
    coinbase.vin.emplace_back("COINBASE", 0, std::vector<unsigned char>(extraNonceStr.begin(), extraNonceStr.end()), std::vector<unsigned char>());
    TxOut out;
    out.amount = rewardSat;
    out.scriptPubKey = createP2PKHScriptHexFromAddress(minerAddr);
    coinbase.vout.push_back(out);
    coinbase.computeTxId();
    
    Logger::log("[COINBASE] Created coinbase tx: " + coinbase.txid);
    return coinbase;
}

// Add transactions from template
static void addTemplateTransactions(Block& candidate, const nlohmann::json& tpl) {
    if (!tpl.contains("transactions") || !tpl["transactions"].is_array()) {
        Logger::log("[TEMPLATE] No transactions in template");
        return;
    }
    
    int txCount = 0;
    int skipped = 0;
    
    for (const auto& txItem : tpl["transactions"]) {
        if (!txItem.contains("data")) continue;
        try {
            std::string rawHex = txItem["data"].get<std::string>();
            std::vector<unsigned char> rawBytes = hexDecode(rawHex);
            Transaction memTx = Transaction::deserializeBinary(rawBytes);
            memTx.computeTxId();
            candidate.transactions.push_back(memTx);
            txCount++;
        } catch (const std::exception& e) {
            Logger::log("[TEMPLATE] WARNING - Failed to parse transaction: " + std::string(e.what()));
            skipped++;
        }
    }
    
    Logger::log("[TEMPLATE] Added " + std::to_string(txCount) + " transactions, skipped " + 
               std::to_string(skipped));
}

// Build candidate block
static Block buildCandidateBlockFromTemplate(const nlohmann::json& tpl, const std::string& minerAddr, int extraNonce) {
    Logger::log("[BLOCK] Building candidate block from template");
    
    int32_t height = tpl.value("height", 1);
    int32_t version = tpl.value("version", height);
    std::string prevH = tpl.value("previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000");
    std::string bitsHex = tpl.value("bits", "1d00ffff");
    uint32_t bitsVal = std::stoul(bitsHex, nullptr, 16);
    uint32_t curTime = tpl.value("curtime", (uint32_t)std::time(nullptr));
    uint64_t rewardSat = tpl.value("coinbasevalue", 50ULL * 100000000ULL);
    
    Logger::log("[BLOCK] Height: " + std::to_string(height) + ", Version: " + std::to_string(version) + 
               ", Bits: 0x" + bitsHex + ", Reward: " + std::to_string(rewardSat));
    
    Block candidate(version, prevH, curTime, bitsVal);
    candidate.height = height;
    Transaction coinbaseTx = buildCoinbaseTx(minerAddr, rewardSat, height, extraNonce);
    candidate.transactions.push_back(coinbaseTx);
    addTemplateTransactions(candidate, tpl);
    candidate.header.merkleRoot = computeMerkleRoot(candidate.transactions);
    
    Logger::log("[BLOCK] Built candidate block with " + std::to_string(candidate.transactions.size()) + 
               " transactions, merkle root: " + candidate.header.merkleRoot);
    
    return candidate;
}

// Enhanced mining loop with improved keepalive thread — accept blockCount by reference
static void startMiningLoop(const std::string& nodeIP, int nodePort, const std::string& minerAddr,
                            int nThreads, uint64_t maxNonce, const CpuInfo& cpuInfo, uint64_t& blockCount) {
    Logger::log("[MAIN] Starting mining loop - Node: " + nodeIP + ":" + std::to_string(nodePort) + 
               ", Miner: " + minerAddr);
    
    g_minerStartTime = std::chrono::steady_clock::now();
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(20, 0);
    int extraNonce = 0;

    // remember which chain tip the current extraNonce belongs to.
    // If getblocktemplate returns a new height or previousblockhash, start the
    // extraNonce sequence over at zero. If the same tip is returned, advance
    // extraNonce so we search a different coinbase/merkle-root/header space.
    int32_t lastTemplateHeight = -1;
    std::string lastTemplatePrevHash;

    int retryCount = 0;
    const int maxBackoffSeconds = 30;
    auto retryBackoffSeconds = [&](int failures) {
        const int shift = std::min(std::max(failures - 1, 0), 3);
        return std::min(maxBackoffSeconds, 5 * (1 << shift));
    };

    // MINER-RESILIENCE-01: registration/RPC outages are transport failures, not
    // mining shutdown commands. Stay alive and re-register until the operator
    // explicitly stops the miner. This changes no PoW or block semantics.
    while (!g_shutdown.load() && !registerMinerWithRetry(cli, minerAddr, "CPU")) {
        Logger::log("[MAIN] Registration unavailable; retrying in 15 seconds");
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
    if (g_shutdown.load()) return;

    // Enhanced keepalive thread with accurate hash reporting
    std::thread keepaliveThread([&]() {
        Logger::log("[KEEPALIVE] Starting keepalive thread");
        
        auto lastReport = std::chrono::steady_clock::now();
        uint64_t lastTotalHashes = 0;
        
        while (!g_shutdown.load()) {
            try {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration<double>(now - lastReport).count();
                
                // Report every 10 seconds for more responsive updates
                if (elapsed >= 10.0) {
                    uint64_t currentHashes = g_totalHashes.load();
                    uint64_t hashesInInterval = currentHashes - lastTotalHashes;
                    
                    // Always report something to keep miner alive
                    if (hashesInInterval == 0 && currentHashes > 0) {
                        // If we have total hashes but no new ones in this interval,
                        // report a fraction of our average rate to stay active
                        double avgRate = currentHashes / std::chrono::duration<double>(now - g_minerStartTime).count();
                        hashesInInterval = static_cast<uint64_t>(avgRate * elapsed);
        
                        if (hashesInInterval == 0) {
                            hashesInInterval = 1000; // Minimum to stay alive
                        }
        
                        Logger::log("[KEEPALIVE] No new hashes, reporting average: " + std::to_string(hashesInInterval));
                    }

                    if (elapsed > 0.001) { // Avoid division by zero
                        nlohmann::json updateReq;
                        updateReq["jsonrpc"] = "2.0";
                        updateReq["id"] = 1;
                        updateReq["method"] = "reportmineractivity";
                        updateReq["params"] = {
                            {"minerAddress", minerAddr}, 
                            {"hashesTried", hashesInInterval}, 
                            {"timeTaken", elapsed}
                        };
                        
                        auto res = cli.Post("/rpc", updateReq.dump(), "application/json");
                        
                        if (res && res->status == 200) {
                            // Successfully reported
                            lastTotalHashes = currentHashes;
                            lastReport = now;
                            
                            double reportedRate = hashesInInterval / elapsed;
                            Logger::log("[KEEPALIVE] SUCCESS - Reported " + std::to_string(hashesInInterval) + 
                                       " hashes in " + std::to_string(elapsed) + "s (" + 
                                       formatHashRate(reportedRate) + ")");
                        } else {
                            std::string status = res ? std::to_string(res->status) : "no response";
                            Logger::log("[KEEPALIVE] WARNING - Failed to report activity (status: " + status + ")");
                            
                            // Reset counters on failure to avoid accumulating
                            lastTotalHashes = currentHashes;
                            lastReport = now;
                        }
                    } else {
                        // Reset if timing is invalid
                        lastReport = now;
                    }
                }
            } catch (const std::exception& e) {
                Logger::log("[KEEPALIVE] ERROR - Exception reporting activity: " + std::string(e.what()));
                
                // Reset on error to avoid getting stuck
                auto now = std::chrono::steady_clock::now();
                lastTotalHashes = g_totalHashes.load();
                lastReport = now;
            }
            
            // Check every 2 seconds for responsive updates
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        
        // Unregister miner on shutdown
        try {
            Logger::log("[KEEPALIVE] Unregistering miner on shutdown");
            
            nlohmann::json unregReq;
            unregReq["jsonrpc"] = "2.0";
            unregReq["id"] = 1;
            unregReq["method"] = "unregisterminer";
            unregReq["params"] = {{"minerAddress", minerAddr}};
            auto res = cli.Post("/rpc", unregReq.dump(), "application/json");
            
            if (res && res->status == 200) {
                Logger::log("[KEEPALIVE] Successfully unregistered CPU miner");
            } else {
                Logger::log("[KEEPALIVE] WARNING - Failed to unregister miner");
            }
        } catch (const std::exception& e) {
            Logger::log("[KEEPALIVE] ERROR - Failed to unregister: " + std::string(e.what()));
        }
    });

    while (!g_shutdown.load()) {
        try {
            // Get block template
            Logger::log("[MAIN] Requesting block template");
            
            nlohmann::json tplReq;
            tplReq["jsonrpc"] = "2.0";
            tplReq["id"] = 2;
            tplReq["method"] = "getblocktemplate";
            tplReq["params"] = nlohmann::json::object();
            auto tplRes = cli.Post("/rpc", tplReq.dump(), "application/json");

            if (!tplRes || tplRes->status != 200) {
                Logger::log("[MAIN] ERROR - Failed to get block template: " + 
                           (tplRes ? "status " + std::to_string(tplRes->status) : "no response"));
                retryCount = std::min(retryCount + 1, 1000);
                const int backoff = retryBackoffSeconds(retryCount);
                Logger::log("[MAIN] MINER-RESILIENCE-01 - template RPC unavailable; keeping miner alive, retrying in " +
                           std::to_string(backoff) + " seconds");
                std::this_thread::sleep_for(std::chrono::seconds(backoff));
                continue;
            }

            retryCount = 0; // Reset retry count on success
            
            nlohmann::json tplJson =
                nlohmann::json::parse(tplRes->body).value(
                    "result",
                    nlohmann::json()
                );

            // determine whether the node gave us a new chain tip.
            const int32_t templateHeight =
                tplJson.value("height", 1);

            const std::string templatePrevHash =
                tplJson.value(
                    "previousblockhash",
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );

            if (templateHeight != lastTemplateHeight ||
                templatePrevHash != lastTemplatePrevHash) {

                // New chain tip: begin the new search space at extraNonce 0.
                extraNonce = 0;

                lastTemplateHeight = templateHeight;
                lastTemplatePrevHash = templatePrevHash;

                Logger::log(
                    "[MAIN] Fresh template detected: height=" +
                    std::to_string(templateHeight) +
                    ", resetting extraNonce=0"
                );

            } else {

                // Same tip returned again after an exhausted search.
                // Change the coinbase so the merkle root/header changes and
                // we get an entirely new nonce search space.
                if (extraNonce == INT_MAX) {
                    extraNonce = 0;
                } else {
                    extraNonce++;
                }

                Logger::log(
                    "[MAIN] Same chain tip; advancing extraNonce=" +
                    std::to_string(extraNonce)
                );
            }

            Block candidate =
                buildCandidateBlockFromTemplate(
                    tplJson,
                    minerAddr,
                    extraNonce
                );

            // MINER-TIME-01A: one bounded work attempt per fresh template.
            // At ~30 seconds the workers stop cleanly and the outer loop asks
            // the node for a new template (including a fresh curtime).
            bool success =
                mineBlockCPU_21E8(
                    candidate,
                    maxNonce,
                    nThreads,
                    cli,
                    minerAddr,
                    extraNonce,
                    cpuInfo,
                    blockCount
                );

            if (!success && !g_shutdown.load()) {
                Logger::log(
                    "[MAIN] No solution on current work; requesting fresh "
                    "block template before next attempt."
                );
            }

            if (success) {
                Logger::log("[MAIN] Block found! Submitting to network");
                std::cout << C_SUCCESS << "[MINER] 🎉 Block found! Submitting..." << C_RESET << "\n";
                
                nlohmann::json sbReq;
                sbReq["jsonrpc"] = "2.0";
                sbReq["id"] = 3;
                sbReq["method"] = "submitblock";
                nlohmann::json paramsObj;
                paramsObj["blockHex"] = candidate.serialize();
                sbReq["params"] = paramsObj;
                auto sbRes = cli.Post("/rpc", sbReq.dump(), "application/json");

                // HTTP 200 does NOT mean the node accepted the block.
                // TRU's handleSubmitBlockOptimized() always answers 200 and puts
                // the verdict in an OBJECT result:
                //     {"result":{"status":"accepted"|"rejected"|"duplicate",
                //                "message":"...","hash":"..."}}
                // The old code reported "Block submitted successfully!" for every
                // 200, so rejected blocks looked like wins and hid a chain-halting
                // consensus bug for days. Anything not explicitly "accepted" is
                // now treated as a rejection.
                bool accepted = false;
                std::string rejectReason;

                if (!sbRes) {
                    rejectReason = "no response from node";
                } else if (sbRes->status != 200) {
                    rejectReason = "HTTP status " + std::to_string(sbRes->status);
                } else {
                    try {
                        nlohmann::json sbJson = nlohmann::json::parse(sbRes->body);

                        if (sbJson.contains("error") && !sbJson["error"].is_null()) {
                            rejectReason = sbJson["error"].dump();
                        } else if (sbJson.contains("result") && sbJson["result"].is_object()) {
                            const auto& r = sbJson["result"];
                            const std::string status = r.value("status", "");
                            if (status == "accepted") {
                                accepted = true;
                            } else {
                                rejectReason = status.empty() ? r.dump()
                                             : status + ": " + r.value("message", r.dump());
                            }
                        } else if (sbJson.contains("result") && sbJson["result"].is_string()) {
                            // Defensive: bitcoin-style string result. Empty means OK.
                            const std::string r = sbJson["result"].get<std::string>();
                            if (r.empty()) accepted = true; else rejectReason = r;
                        } else {
                            rejectReason = "unrecognised submitblock response: " + sbJson.dump();
                        }
                    } catch (const std::exception& e) {
                        rejectReason = std::string("unparseable response: ") + e.what() +
                                       " | body=" + sbRes->body;
                    }
                }

                if (accepted) {
                    Logger::log("[MAIN] SUCCESS - Block accepted by node. Response: " +
                                (sbRes ? sbRes->body : std::string("(none)")));
                    std::cout << C_SUCCESS << "[MINER] 💎 Block accepted!" << C_RESET << "\n";
                    blockCount++;
                    extraNonce = 0;
                } else {
                    Logger::log("[MAIN] ERROR - Block REJECTED by node: " + rejectReason);
                    if (sbRes) {
                        Logger::log("[MAIN] Rejected block raw response: " + sbRes->body);
                    }
                    std::cout << C_ERROR << "[MINER] ❌ Block rejected: "
                              << rejectReason << C_RESET << "\n";
                }
            }

            // do not unconditionally reset extraNonce here.
            // Template identity handling above decides whether the next
            // iteration should reset it or advance it.
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
        } catch (const std::exception& e) {
            Logger::log("[MAIN] EXCEPTION - " + std::string(e.what()));
            std::cout << C_ERROR << "[MINER] Error: " << e.what() << C_RESET << "\n";
            retryCount = std::min(retryCount + 1, 1000);
            const int backoff = retryBackoffSeconds(retryCount);
            Logger::log("[MAIN] MINER-RESILIENCE-01 - transient exception; keeping miner alive, retrying in " +
                       std::to_string(backoff) + " seconds");
            std::this_thread::sleep_for(std::chrono::seconds(backoff));
        }
    }
    
    Logger::log("[MAIN] Mining loop ended, waiting for keepalive thread");
    keepaliveThread.join();
}

// Main entry point
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    cxxopts::Options opts("tru_cpu_miner", "🔥 TRU Blockchain CPU Miner v4.0 - Professional Mining Suite 2025");
    opts.add_options()
        ("node-ip", "Node IP address", cxxopts::value<std::string>()->default_value("127.0.0.1"))
        ("node-port", "Node port", cxxopts::value<int>()->default_value(std::to_string(tru_network::MAINNET_RPC_PORT)))
        ("mineraddr", "Miner address", cxxopts::value<std::string>()->default_value("1TruCPUMinerAddr..."))
        ("threads", "Number of mining threads", cxxopts::value<int>()->default_value("4"))
        ("max-nonce", "Maximum nonce value", cxxopts::value<uint64_t>()->default_value("4294967295"))
        ("update-interval", "UI update interval (ms)", cxxopts::value<int>()->default_value("200"))
        ("quiet", "Disable UI display", cxxopts::value<bool>()->default_value("false"))
        ("log-file", "Log file path", cxxopts::value<std::string>()->default_value("cpu_miner.log"))
        ("help", "Show help");
    
    auto args = opts.parse(argc, argv);
    if (args.count("help")) {
        std::cout << opts.help() << "\n";
        return 0;
    }

    std::string nodeIP = args["node-ip"].as<std::string>();
    int nodePort = args["node-port"].as<int>();
    std::string minerAddr = args["mineraddr"].as<std::string>();
    int nThreads = args["threads"].as<int>();
    uint64_t maxNonce = args["max-nonce"].as<uint64_t>();
    int updateInterval = args["update-interval"].as<int>();
    bool quiet = args["quiet"].as<bool>();
    std::string logFile = args["log-file"].as<std::string>();

    // Initialize logger
    try {
        Logger::init(logFile);
        Logger::log("==============================================");
        Logger::log("TRU CPU Miner v4.0 - Starting up");
        Logger::log("==============================================");
        Logger::log("[INIT] Command line: " + std::string(argv[0]));
        for (int i = 1; i < argc; i++) {
            Logger::log("[INIT] Arg[" + std::to_string(i) + "]: " + std::string(argv[i]));
        }
    } catch (const std::exception& e) {
        std::cerr << C_ERROR << "❌ Failed to initialize logger: " << e.what() << C_RESET << "\n";
        return 1;
    }

    // Enhanced validation with better error messages
    if (nodePort < 1 || nodePort > 65535) {
        Logger::log("[INIT] ERROR - Invalid node port: " + std::to_string(nodePort));
        std::cerr << C_ERROR << "❌ Invalid node port: " << nodePort << C_RESET << "\n";
        Logger::shutdown();
        return 1;
    }
    if (minerAddr.length() < 26 || minerAddr.length() > 35) {
        Logger::log("[INIT] ERROR - Invalid miner address: " + minerAddr);
        std::cerr << C_ERROR << "❌ Invalid miner address: " << minerAddr << C_RESET << "\n";
        Logger::shutdown();
        return 1;
    }

    CpuInfo cpuInfo = getCpuInfo();
    if (nThreads > cpuInfo.threads) {
        Logger::log("[INIT] WARNING - Requested threads (" + std::to_string(nThreads) + 
                   ") exceed available (" + std::to_string(cpuInfo.threads) + ")");
        std::cerr << C_WARNING << "⚠️ Warning: Requested threads (" << nThreads 
                  << ") exceed available (" << cpuInfo.threads << "). Using " 
                  << cpuInfo.threads << "." << C_RESET << "\n";
        nThreads = cpuInfo.threads;
    }
    if (nThreads < 1) {
        Logger::log("[INIT] ERROR - Invalid thread count: " + std::to_string(nThreads));
        std::cerr << C_ERROR << "❌ Invalid thread count: " << nThreads << C_RESET << "\n";
        Logger::shutdown();
        return 1;
    }

    // Log configuration
    Logger::log("[INIT] Configuration:");
    Logger::log("[INIT]   Node: " + nodeIP + ":" + std::to_string(nodePort));
    Logger::log("[INIT]   Miner Address: " + minerAddr);
    Logger::log("[INIT]   Threads: " + std::to_string(nThreads));
    Logger::log("[INIT]   Max Nonce: " + std::to_string(maxNonce));
    Logger::log("[INIT]   Update Interval: " + std::to_string(updateInterval) + "ms");
    Logger::log("[INIT]   Quiet Mode: " + std::string(quiet ? "yes" : "no"));
    Logger::log("[INIT]   Log File: " + logFile);

    std::cout << C_FIRE << C_BOLD << "🔥 Starting TRU CPU Miner v4.0..." << C_RESET << "\n";
    
    // Initialize block count
    uint64_t blockCount = 0;
    
    // Start mining — pass blockCount by reference
    startMiningLoop(nodeIP, nodePort, minerAddr, nThreads, maxNonce, cpuInfo, blockCount);

    // Enhanced shutdown message
    Logger::log("[SHUTDOWN] Mining stopped, performing cleanup");
    
    std::cout << "\n" << C_FIRE << "╭─ 🔥 TRU BLOCKCHAIN CPU MINER ──────────────────────────────────╮\n";
    std::cout << "│                         SHUTDOWN COMPLETE                     │\n";
    std::cout << "│                    Thank you for mining TRU! 💎               │\n";
    std::cout << "╰────────────────────────────────────────────────────────────────╯" << C_RESET << "\n";
    
    Logger::log("[SHUTDOWN] CPU Miner terminated successfully");
    Logger::log("==============================================");
    Logger::shutdown();
    
    return 0;
}
