#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 200
#endif

#ifdef __APPLE__
#include "tru_network_params.h"
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <httplib.h>
#include <cxxopts.hpp>

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <signal.h>
#include <algorithm>
#include <memory>

// Shared blockchain headers used by CPU and GPU miners.
#include "block.h"
#include "tx.h"
#include "sha256_21e8.h"
#include "utils.h"
#include "address_helpers.h"
#include "logging.h"
#include "rpc_utils.h"  // authenticated node RPC

// Enhanced 2025 Blockchain Color Palette ⛓️
#define C_RESET     "\033[0m"
#define C_BOLD      "\033[1m"
#define C_DIM       "\033[2m"
#define C_ITALIC    "\033[3m"
#define C_UNDERLINE "\033[4m"
#define C_BLINK     "\033[5m"

// Blockchain Primary Colors ⛓️
#define C_PRIMARY   "\033[38;2;0;255;187m"    // Bright cyan-green
#define C_SECONDARY "\033[38;2;255;107;129m"  // Coral pink
#define C_ACCENT    "\033[38;2;255;206;84m"   // Golden yellow
#define C_FIRE      "\033[38;2;255;69;0m"     // Fire red-orange
#define C_ELECTRIC  "\033[38;2;0;255;255m"    // Electric cyan
#define C_NEON      "\033[38;2;57;255;20m"    // Neon green
#define C_PURPLE    "\033[38;2;138;43;226m"   // Blue violet
#define C_GOLD      "\033[38;2;255;215;0m"    // Pure gold
#define C_SILVER    "\033[38;2;192;192;192m"  // Silver
#define C_BLOCKCHAIN "\033[38;2;100;100;255m" // Blockchain blue

// Enhanced Status Colors 💎
#define C_SUCCESS   "\033[38;2;46;204;113m"   // Modern green
#define C_WARNING   "\033[38;2;255;159;67m"   // Orange
#define C_ERROR     "\033[38;2;255;107;107m"  // Red
#define C_INFO      "\033[38;2;116;185;255m"  // Blue
#define C_DEBUG     "\033[38;2;255;20;147m"   // Deep pink

// Neutral Colors with Style ✨
#define C_TEXT      "\033[38;2;236;240;241m"  // Light gray
#define C_MUTED     "\033[38;2;149;165;166m"  // Muted gray
#define C_DARK      "\033[38;2;52;73;94m"     // Dark blue-gray

// Background Colors for Special Effects 🎨
#define BG_FIRE     "\033[48;2;255;69;0m"     // Fire background
#define BG_SUCCESS  "\033[48;2;46;204;113m"   // Success background
#define BG_WARNING  "\033[48;2;255;159;67m"   // Warning background

// Enhanced Blockchain Symbols - NO RAINBOWS! ⛓️
#define SYMBOL_GPU       "🔥"
#define SYMBOL_HASH      "⧫"
#define SYMBOL_SPEED     "⚡"
#define SYMBOL_TIME      "⏱"
#define SYMBOL_PROGRESS  "▓"
#define SYMBOL_EMPTY     "░"
#define SYMBOL_SUCCESS   "✓"
#define SYMBOL_ERROR     "✗"
#define SYMBOL_WARNING   "⚠"
#define SYMBOL_ARROW     "→"
#define SYMBOL_DOT       "●"
#define SYMBOL_BLOCK     "⬡"    // Hexagon for blocks
#define SYMBOL_ROCKET    "🚀"
#define SYMBOL_DIAMOND   "💎"
#define SYMBOL_STAR      "⭐"
#define SYMBOL_CROWN     "👑"
#define SYMBOL_FIRE      "🔥"
#define SYMBOL_LIGHTNING "⚡"
#define SYMBOL_GEM       "💎"
#define SYMBOL_TROPHY    "🏆"
#define SYMBOL_TARGET    "🎯"
#define SYMBOL_BOOM      "💥"
#define SYMBOL_SPARKLE   "✨"
#define SYMBOL_CHAIN     "⛓️"    // Blockchain chain
#define SYMBOL_LINK      "🔗"    // Link
#define SYMBOL_BRAIN     "🧠"
#define SYMBOL_SHIELD    "🛡️"
#define SYMBOL_TEMP      "🌡️"
#define SYMBOL_KEY       "🔐"    // Crypto key
#define SYMBOL_LOCK      "🔒"    // Security
#define SYMBOL_CUBE      "⬡"     // Block representation

// Global state with enhanced tracking
static std::atomic<uint64_t> g_totalHashes(0);      // per-sweep credited hash work
static std::atomic<uint64_t> g_sessionHashes(0);    // monotonic miner-session credited hash work
static std::atomic<bool> g_shutdown(false);
static std::atomic<bool> g_found(false);
static std::atomic<uint64_t> g_foundNonce(0);
static std::vector<unsigned char> g_foundHash(32);
static std::mutex g_foundMutex;
static std::chrono::steady_clock::time_point g_minerStartTime;

// Enhanced global hash tracking
static std::atomic<uint64_t> g_hashesAtLastReport(0);
static std::atomic<uint64_t> g_totalReports(0);

// GPU-MINER-HARDEN-01:
// Credit only work that completed without observing a solution flag.
// g_totalHashes is intentionally reset per extraNonce sweep for the UI.
// g_sessionHashes is monotonic across sweeps and is the only counter used
// by the keepalive reporter, preventing unsigned subtraction across resets.
static inline void creditCompletedHashWork(uint64_t hashes) {
    if (hashes == 0) return;
    g_totalHashes.fetch_add(hashes, std::memory_order_relaxed);
    g_sessionHashes.fetch_add(hashes, std::memory_order_relaxed);
}

// Helper function to format log messages
std::string formatLogMessage(const std::string& level, const std::string& component, const std::string& message) {
    std::ostringstream oss;
    oss << "[" << level << "] [" << component << "] " << message;
    return oss.str();
}

// 🎯 AUTO-DETECTION: GPU Performance Profiles
struct GPUProfile {
    std::string namePattern;
    std::string performanceClass;
    double coreUsagePercent;      // What % of cores to use safely
    double memoryUsagePercent;    // What % of memory to use
    size_t maxKernelsPerGPU;      // Max concurrent kernels
    double thermalSafetyFactor;   // Conservative multiplier
    size_t preferredWorkGroupSize;
};

// 🔥 PERFORMANCE PROFILES DATABASE - INTELLIGENT AUTO-DETECTION
static std::vector<GPUProfile> GPU_PROFILES = {
    // NVIDIA HIGH-END CARDS (BEAST CLASS)
    {"TITAN", "BEAST", 0.95, 0.85, 20, 0.95, 1024},        // Titan cards
    {"RTX 50", "ULTRABEAST", 0.95, 0.90, 24, 0.90, 1024},  // RTX 5090
    {"RTX 40", "BEAST", 0.88, 0.75, 14, 0.80, 1024},       // RTX 4090, 4080, etc.
    {"RTX 30", "BEAST", 0.85, 0.75, 12, 0.75, 1024},       // RTX 3090, 3080, etc.
    {"RTX 20", "HIGH", 0.80, 0.70, 10, 0.70, 1024},        // RTX 2080 Ti, 2080, etc.
    {"GTX 1080", "HIGH", 0.90, 0.80, 12, 0.85, 1024},       // GTX 1080 Ti, 1080
    {"GTX 1070", "MEDIUM", 0.75, 0.68, 6, 0.70, 512},      // GTX 1070
    {"GTX 1060", "MEDIUM", 0.70, 0.65, 4, 0.65, 512},      // GTX 1060
    
    // AMD HIGH-END CARDS
    {"RX 7900", "BEAST", 0.85, 0.75, 12, 0.75, 1024},      // RX 7900 XTX, XT
    {"RX 6900", "BEAST", 0.82, 0.73, 10, 0.72, 1024},      // RX 6900 XT
    {"RX 6800", "HIGH", 0.80, 0.70, 8, 0.70, 1024},        // RX 6800 XT
    {"RX 580", "MEDIUM", 0.75, 0.65, 6, 0.65, 512},        // RX 580
    
    // INTEL ARC
    {"Arc A", "HIGH", 0.75, 0.70, 8, 0.70, 512},           // Intel Arc series
    
    // GENERIC FALLBACK
    {"", "BASIC", 0.60, 0.50, 4, 0.60, 256}                // Unknown GPU - very conservative
};

// Enhanced GPU device structure with INTELLIGENT AUTO-TUNED SETTINGS
struct GPUDevice {
    cl_platform_id platform;
    cl_device_id device;
    std::string platformName;
    std::string deviceName;
    size_t maxComputeUnits;
    size_t maxWorkGroupSize;
    size_t globalMemSize;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_mem header80_buf;
    cl_mem target_buf;
    cl_mem foundFlag_buf;
    cl_mem foundNonce_buf;
    cl_mem foundHash_buf;
    uint64_t deviceHashes;  
    bool initialized;
    uint64_t totalKernelsLaunched;
    std::string deviceEmoji;

    // 🚀 INTELLIGENT AUTO-TUNED PERFORMANCE SETTINGS
    size_t optimalKernelsPerGPU;
    size_t optimalKernelSize;
    size_t optimalWorkGroupSize;
    size_t maxConcurrentKernels;
    size_t safetyCoreUsage;        // Percentage of cores to use safely
    double thermalSafetyFactor;    // Thermal safety multiplier
    std::string performanceClass;  // "BEAST", "HIGH", "MEDIUM", "BASIC"
    
    // GPU IDENTIFICATION
    std::string vendorName;
    std::string architectureName;
    bool isHighEnd;
    bool hasCooling;  // Assumed based on memory size

    // Constructor
    GPUDevice() {
        platform = nullptr;
        device = nullptr;
        maxComputeUnits = 0;
        maxWorkGroupSize = 0;
        globalMemSize = 0;
        context = nullptr;
        queue = nullptr;
        program = nullptr;
        kernel = nullptr;
        header80_buf = nullptr;
        target_buf = nullptr;
        foundFlag_buf = nullptr;
        foundNonce_buf = nullptr;
        foundHash_buf = nullptr;
        deviceHashes = 0;
        initialized = false;
        totalKernelsLaunched = 0;
        deviceEmoji = "🔥"; // Default emoji
        
        // Initialize auto-tuned settings
        optimalKernelsPerGPU = 4;
        optimalKernelSize = 100000000UL;
        optimalWorkGroupSize = 256;
        maxConcurrentKernels = 8;
        safetyCoreUsage = 0;
        thermalSafetyFactor = 0.7;
        performanceClass = "BASIC";
        isHighEnd = false;
        hasCooling = false;
    }

    // Destructor
    ~GPUDevice() {
        cleanup();
    }

    // Delete copy constructor and copy assignment
    GPUDevice(const GPUDevice&) = delete;
    GPUDevice& operator=(const GPUDevice&) = delete;

    void cleanup() {
        if (header80_buf) { clReleaseMemObject(header80_buf); header80_buf = nullptr; }
        if (target_buf) { clReleaseMemObject(target_buf); target_buf = nullptr; }
        if (foundFlag_buf) { clReleaseMemObject(foundFlag_buf); foundFlag_buf = nullptr; }
        if (foundNonce_buf) { clReleaseMemObject(foundNonce_buf); foundNonce_buf = nullptr; }
        if (foundHash_buf) { clReleaseMemObject(foundHash_buf); foundHash_buf = nullptr; }
        if (kernel) { clReleaseKernel(kernel); kernel = nullptr; }
        if (program) { clReleaseProgram(program); program = nullptr; }
        if (queue) { clReleaseCommandQueue(queue); queue = nullptr; }
        if (context) { clReleaseContext(context); context = nullptr; }
    }
};

static std::vector<std::unique_ptr<GPUDevice>> g_devices;

// Enhanced signal handler with more style 💥
void signalHandler(int sig) {
    Logger::log(formatLogMessage("INFO", "SIGNAL", "Received signal " + std::to_string(sig) + ", initiating shutdown"));
    
    std::cout << C_FIRE << C_BOLD << "\n╭─ " << SYMBOL_BOOM << " GPU MINER EMERGENCY SHUTDOWN " << SYMBOL_BOOM << " ─╮\n" 
              << "│ " << SYMBOL_LIGHTNING << " Signal Received: " << sig << " " << SYMBOL_LIGHTNING << "                    │\n"
              << "│ " << SYMBOL_SPARKLE << " Initiating Graceful Exit... " << SYMBOL_SPARKLE << "              │\n"
              << "╰─ " << SYMBOL_CHAIN << " Thank you for mining TRU! " << SYMBOL_CHAIN << " ──────────╯" << C_RESET << "\n";
    g_shutdown.store(true);
}

// Enhanced registration with more visual feedback 🎨
bool registerMinerWithRetry(httplib::Client& cli, const std::string& minerAddr, const std::string& minerType) {
    const int maxRetries = 5;
    Logger::log(formatLogMessage("INFO", "REGISTRATION", "Attempting to register " + minerType + " miner: " + minerAddr));
    
    std::cout << C_ELECTRIC << C_BOLD << "╭─ " << SYMBOL_ROCKET << " MINER REGISTRATION SEQUENCE " << SYMBOL_ROCKET << " ─╮" << C_RESET << "\n";
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        std::cout << C_INFO << "│ " << SYMBOL_TARGET << " Attempt " << attempt << "/" << maxRetries << " - Registering " << minerType << " miner..." << C_RESET << "\n";
        
        try {
            nlohmann::json regReq;
            regReq["jsonrpc"] = "2.0";
            regReq["id"] = 1;
            regReq["method"] = "registerminer";
            regReq["params"] = {{"minerAddress", minerAddr}};
            
            Logger::log(formatLogMessage("DEBUG", "REGISTRATION", "Sending registration request (attempt " + std::to_string(attempt) + ")"));
            auto regRes = cli.Post("/rpc", regReq.dump(), "application/json");
            
            if (regRes && regRes->status == 200) {
                try {
                    auto jsonResponse = nlohmann::json::parse(regRes->body);
                    if (!jsonResponse.contains("error")) {
                        Logger::log(formatLogMessage("SUCCESS", "REGISTRATION", "Successfully registered " + minerType + " miner"));
                        std::cout << C_SUCCESS << C_BOLD << "│ " << SYMBOL_TROPHY << " SUCCESS! " << minerType << " miner registered!" << C_RESET << "\n";
                        std::cout << C_NEON << "│ " << SYMBOL_DIAMOND << " Address: " << minerAddr << C_RESET << "\n";
                        std::cout << C_SUCCESS << "╰─ " << SYMBOL_SPARKLE << " Ready to mine blocks! " << SYMBOL_SPARKLE << " ──────────────────╯" << C_RESET << "\n\n";
                        return true;
                    } else {
                        std::string error = jsonResponse["error"].dump();
                        Logger::log(formatLogMessage("WARNING", "REGISTRATION", "Server returned error: " + error));
                        std::cout << C_WARNING << "│ " << SYMBOL_ERROR << " Server returned error: " << error << C_RESET << "\n";
                    }
                } catch (const std::exception& e) {
                    Logger::log(formatLogMessage("ERROR", "REGISTRATION", "Failed to parse response: " + std::string(e.what())));
                    std::cout << C_WARNING << "│ " << SYMBOL_ERROR << " Failed to parse response: " << e.what() << C_RESET << "\n";
                }
            } else {
                std::string status = regRes ? std::to_string(regRes->status) : "no response";
                Logger::log(formatLogMessage("WARNING", "REGISTRATION", "Registration failed, status: " + status));
                std::cout << C_WARNING << "│ " << SYMBOL_ERROR << " HTTP Status: " << status << C_RESET << "\n";
            }
        } catch (const std::exception& e) {
            Logger::log(formatLogMessage("ERROR", "REGISTRATION", "Exception: " + std::string(e.what())));
            std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " Exception: " << e.what() << C_RESET << "\n";
        }
        
        if (attempt < maxRetries) {
            int sleepTime = 2 * attempt;
            Logger::log(formatLogMessage("INFO", "REGISTRATION", "Waiting " + std::to_string(sleepTime) + " seconds before retry"));
            std::cout << C_MUTED << "│ " << SYMBOL_TIME << " Waiting " << sleepTime << "s before retry..." << C_RESET << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
        }
    }
    
    Logger::log(formatLogMessage("ERROR", "REGISTRATION", "Failed to register after " + std::to_string(maxRetries) + " attempts"));
    std::cout << C_ERROR << C_BOLD << "╰─ " << SYMBOL_ERROR << " REGISTRATION FAILED AFTER " << maxRetries << " ATTEMPTS " << SYMBOL_ERROR << " ─╯" << C_RESET << "\n";
    return false;
}

// Enhanced OpenCL kernel with proper 21E8 implementation and optimizations
static const char *GPU_KERNEL_SRC = R"CLC(
__constant uint K[64] = {
  0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
  0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
  0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
  0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
  0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
  0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
  0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
  0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

inline uint ROR(uint x, uint n) { return (x >> n) | (x << (32-n)); }

inline void sha256_compress(uint s[8], const uint w[16]) {
    uint ss[64];
    for(int i=0;i<16;i++) ss[i] = w[i];
    for(int i=16;i<64;i++){
        uint s0 = ROR(ss[i-15],7) ^ ROR(ss[i-15],18) ^ (ss[i-15]>>3);
        uint s1 = ROR(ss[i-2],17) ^ ROR(ss[i-2],19) ^ (ss[i-2]>>10);
        ss[i] = ss[i-16] + s0 + ss[i-7] + s1;
    }
    uint a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for(int i=0;i<64;i++){
        uint S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint ch = (e&f) ^ ((~e)&g);
        uint tmp1 = h + S1 + ch + K[i] + ss[i];
        uint S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint maj = (a&b) ^ (a&c) ^ (b&c);
        uint tmp2 = S0 + maj;
        h=g; g=f; f=e; e=d+tmp1; d=c; c=b; b=a; a=tmp1+tmp2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

inline void doubleSha256_21E8(__private const uchar *hdr80, __private uchar *out32) {
    // First SHA256 pass
    uint st[8] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    
    // Process first 64 bytes
    uint w[16];
    for(int i=0;i<16;i++) {
        w[i] = ((uint)hdr80[4*i+0]<<24) | ((uint)hdr80[4*i+1]<<16) | ((uint)hdr80[4*i+2]<<8) | (uint)hdr80[4*i+3];
    }
    sha256_compress(st, w);
    
    // Process remaining 16 bytes with padding
    uchar chunk1[64] = {0};
    for(int i=64; i<80; i++) chunk1[i-64] = hdr80[i];
    chunk1[16] = 0x80;
    ulong bitLen = 80UL * 8UL;
    chunk1[63] = (uchar)(bitLen&0xff);
    chunk1[62] = (uchar)((bitLen>>8)&0xff);
    chunk1[61] = (uchar)((bitLen>>16)&0xff);
    chunk1[60] = (uchar)((bitLen>>24)&0xff);
    chunk1[59] = (uchar)((bitLen>>32)&0xff);
    chunk1[58] = (uchar)((bitLen>>40)&0xff);
    chunk1[57] = (uchar)((bitLen>>48)&0xff);
    chunk1[56] = (uchar)((bitLen>>56)&0xff);
    
    for(int i=0;i<16;i++) {
        w[i] = ((uint)chunk1[4*i+0]<<24) | ((uint)chunk1[4*i+1]<<16) | ((uint)chunk1[4*i+2]<<8) | (uint)chunk1[4*i+3];
    }
    sha256_compress(st, w);
    
    // Convert to bytes for second pass
    uchar hash1[32];
    for(int i=0;i<8;i++){
        hash1[4*i+0] = (uchar)((st[i]>>24)&0xff);
        hash1[4*i+1] = (uchar)((st[i]>>16)&0xff);
        hash1[4*i+2] = (uchar)((st[i]>>8)&0xff);
        hash1[4*i+3] = (uchar)(st[i]&0xff);
    }
    
    // Second SHA256 pass
    uint st2[8] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    uchar chunk2[64] = {0};
    for(int i=0;i<32;i++) chunk2[i] = hash1[i];
    chunk2[32] = 0x80;
    ulong bitLen2 = 32UL * 8UL;
    chunk2[63] = (uchar)(bitLen2&0xff);
    chunk2[62] = (uchar)((bitLen2>>8)&0xff);
    chunk2[61] = (uchar)((bitLen2>>16)&0xff);
    chunk2[60] = (uchar)((bitLen2>>24)&0xff);
    chunk2[59] = (uchar)((bitLen2>>32)&0xff);
    chunk2[58] = (uchar)((bitLen2>>40)&0xff);
    chunk2[57] = (uchar)((bitLen2>>48)&0xff);
    chunk2[56] = (uchar)((bitLen2>>56)&0xff);
    
    for(int i=0;i<16;i++) {
        w[i] = ((uint)chunk2[4*i+0]<<24) | ((uint)chunk2[4*i+1]<<16) | ((uint)chunk2[4*i+2]<<8) | (uint)chunk2[4*i+3];
    }
    sha256_compress(st2, w);
    
    // Convert final hash to bytes
    for(int i=0;i<8;i++){
        out32[4*i+0] = (uchar)((st2[i]>>24)&0xff);
        out32[4*i+1] = (uchar)((st2[i]>>16)&0xff);
        out32[4*i+2] = (uchar)((st2[i]>>8)&0xff);
        out32[4*i+3] = (uchar)(st2[i]&0xff);
    }
    
    // Apply 21E8 puzzle injection (CRITICAL!)
    uint last32 = ((uint)out32[28]<<24) | ((uint)out32[29]<<16) | ((uint)out32[30]<<8) | (uint)out32[31];
    last32 = (last32 + 0x21E8U) & 0xffffffffU;
    out32[28] = (uchar)((last32>>24)&0xff);
    out32[29] = (uchar)((last32>>16)&0xff);
    out32[30] = (uchar)((last32>>8)&0xff);
    out32[31] = (uchar)(last32&0xff);
}

__kernel void tru_gpu_miner(
    __global uchar* header80,
    ulong startNonce,
    ulong endNonceExclusive,
    __global const uchar* targetBE,
    __global int* foundFlag,
    __global ulong* foundNonce,
    __global uchar* foundHash
) {
    ulong gid = get_global_id(0);
    if(atomic_cmpxchg(foundFlag, 0, 0) != 0) return;
    
    ulong nonce = startNonce + gid;
    // Host ranges are half-open [startNonce, endNonceExclusive).
    // This rejects work-group padding after the exact nonce range.
    if(nonce >= endNonceExclusive) return;
    
    // Copy header and set nonce
    uchar localHdr[80];
    for(int i=0; i<80; i++) localHdr[i] = header80[i];
    localHdr[76] = (uchar)(nonce & 0xff);
    localHdr[77] = (uchar)((nonce >> 8) & 0xff);
    localHdr[78] = (uchar)((nonce >> 16) & 0xff);
    localHdr[79] = (uchar)((nonce >> 24) & 0xff);
    
    // Compute hash with 21E8 injection
    uchar finalHash[32];
    doubleSha256_21E8(localHdr, finalHash);
    
    // Check if below target
    // FIX(patch13): canonical TRU PoW comparison.
    // bitsToTargetArrayFree() supplies the target in the node's
    // little-endian 256-bit layout, so compare byte 31 -> byte 0,
    // matching compare256LE() used by the node and CPU miner.
    bool below = true;

    for (int i = 31; i >= 0; i--) {
        uchar h = finalHash[i];
        uchar t = targetBE[i];

        if (h < t) {
            below = true;
            break;
        }

        if (h > t) {
            below = false;
            break;
        }
    }
    
    if(below) {
        if(atomic_cmpxchg(foundFlag, 0, 1) == 0) {
            *foundNonce = nonce;
            for(int i=0; i<32; i++) foundHash[i] = finalHash[i];
        }
    }
}
)CLC";

// Enhanced utility functions with more style 🎨
std::string formatHashRate(double hashRate) {
    const char* units[] = {"H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"};
    const char* colors[] = {C_TEXT, C_SUCCESS, C_WARNING, C_PRIMARY, C_FIRE, C_PURPLE};
    int unitIndex = 0;
    
    while (hashRate >= 1000 && unitIndex < 5) {
        hashRate /= 1000;
        unitIndex++;
    }
    
    std::ostringstream oss;
    oss << colors[unitIndex] << std::fixed << std::setprecision(2) << hashRate << " " << units[unitIndex] << C_RESET;
    return oss.str();
}

std::string formatDuration(double seconds) {
    int hours = static_cast<int>(seconds) / 3600;
    int minutes = (static_cast<int>(seconds) % 3600) / 60;
    int secs = static_cast<int>(seconds) % 60;
    int millisecs = static_cast<int>((seconds - static_cast<int>(seconds)) * 1000);
    
    std::ostringstream oss;
    if (hours > 0) {
        oss << C_GOLD << hours << "h " << C_ACCENT << minutes << "m " << C_INFO << secs << "s" << C_RESET;
    } else if (minutes > 0) {
        oss << C_ACCENT << minutes << "m " << C_INFO << secs << "s" << C_RESET;
    } else if (secs > 0) {
        oss << C_INFO << secs << "." << std::setfill('0') << std::setw(1) << (millisecs / 100) << "s" << C_RESET;
    } else {
        oss << C_INFO << "0." << std::setfill('0') << std::setw(3) << millisecs << "s" << C_RESET;
    }
    return oss.str();
}

std::string createProgressBar(double percentage, int width = 30) {
    int filled = static_cast<int>(percentage * width / 100.0);
    std::string bar = "";
    
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            if (percentage >= 90) bar += C_FIRE + std::string(SYMBOL_PROGRESS) + C_RESET;
            else if (percentage >= 70) bar += C_GOLD + std::string(SYMBOL_PROGRESS) + C_RESET;
            else if (percentage >= 50) bar += C_ACCENT + std::string(SYMBOL_PROGRESS) + C_RESET;
            else bar += C_PRIMARY + std::string(SYMBOL_PROGRESS) + C_RESET;
        } else {
            bar += C_MUTED + std::string(SYMBOL_EMPTY) + C_RESET;
        }
    }
    return bar;
}

// 🧠 INTELLIGENT GPU PROFILE DETECTION
GPUProfile detectGPUProfile(const std::string& deviceName, size_t computeUnits, size_t globalMemSize) {
    std::string upperName = deviceName;
    std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
    
    Logger::log(formatLogMessage("INFO", "PROFILE", "Detecting profile for: " + deviceName + 
        " (CUs: " + std::to_string(computeUnits) + ", Memory: " + std::to_string(globalMemSize/1024/1024/1024) + "GB)"));
    
    // Find matching profile
    for (const auto& profile : GPU_PROFILES) {
        if (!profile.namePattern.empty() && upperName.find(profile.namePattern) != std::string::npos) {
            Logger::log(formatLogMessage("SUCCESS", "PROFILE", "Matched profile: " + profile.namePattern + 
                " (" + profile.performanceClass + " class)"));
            std::cout << C_SUCCESS << "    🎯 Detected: " << C_GOLD << profile.performanceClass 
                      << " class GPU (" << profile.namePattern << ")" << C_RESET << "\n";
            return profile;
        }
    }
    
    // Fallback: Determine by specs
    if (globalMemSize >= 8ULL * 1024 * 1024 * 1024 && computeUnits >= 40) {  // 8GB+ RAM, 40+ CUs
        Logger::log(formatLogMessage("INFO", "PROFILE", "Auto-detected HIGH class based on specs"));
        std::cout << C_SUCCESS << "    🎯 Auto-detected: " << C_GOLD << "HIGH class" 
                  << " (based on " << computeUnits << " CUs, " << (globalMemSize/1024/1024/1024) << "GB)" << C_RESET << "\n";
        return {"AUTO-HIGH", "HIGH", 0.80, 0.70, 10, 0.70, 1024};
    } else if (globalMemSize >= 4ULL * 1024 * 1024 * 1024 && computeUnits >= 20) {  // 4GB+ RAM, 20+ CUs
        Logger::log(formatLogMessage("INFO", "PROFILE", "Auto-detected MEDIUM class based on specs"));
        std::cout << C_WARNING << "    🎯 Auto-detected: " << C_ACCENT << "MEDIUM class" 
                  << " (based on " << computeUnits << " CUs, " << (globalMemSize/1024/1024/1024) << "GB)" << C_RESET << "\n";
        return {"AUTO-MEDIUM", "MEDIUM", 0.70, 0.60, 6, 0.65, 512};
    } else {
        Logger::log(formatLogMessage("INFO", "PROFILE", "Using conservative BASIC profile"));
        std::cout << C_INFO << "    🎯 Auto-detected: " << C_MUTED << "BASIC class" 
                  << " (conservative settings)" << C_RESET << "\n";
        return GPU_PROFILES.back();  // Use conservative fallback
    }
}

// 🧠 INTELLIGENT PERFORMANCE CALCULATION
void calculateOptimalSettings(GPUDevice* device, const GPUProfile& profile) {
    Logger::log(formatLogMessage("INFO", "OPTIMIZE", "Calculating optimal settings for " + device->deviceName));
    
    // Calculate safe core usage
    size_t safeCores = static_cast<size_t>(device->maxComputeUnits * profile.coreUsagePercent);
    device->safetyCoreUsage = safeCores;
    
    // Calculate optimal work group size
    device->optimalWorkGroupSize = std::min(profile.preferredWorkGroupSize, device->maxWorkGroupSize);
    if (device->optimalWorkGroupSize < 256) device->optimalWorkGroupSize = 256;  // Minimum efficiency
    
    // Calculate memory-safe kernel size
    size_t availableMemory = static_cast<size_t>(device->globalMemSize * profile.memoryUsagePercent);
    size_t memoryPerKernel = 1024 * 1024 * 50;  // ~100MB per kernel (conservative)
    size_t maxKernelsByMemory = availableMemory / memoryPerKernel;
    
    // Calculate optimal kernels per GPU (limited by cores, memory, and profile)
    device->optimalKernelsPerGPU = std::min({
        profile.maxKernelsPerGPU,
        maxKernelsByMemory,
        safeCores / 4  // 4 cores per kernel minimum
    });
    if (device->optimalKernelsPerGPU < 2) device->optimalKernelsPerGPU = 2;  // Minimum parallelism
 
    if (device->globalMemSize >= 12ULL * 1024 * 1024 * 1024) {  // 12GB+ cards
        device->optimalKernelSize = static_cast<size_t>(device->optimalKernelSize * 1.3); // 30% boost
        device->optimalKernelsPerGPU = static_cast<size_t>(device->optimalKernelsPerGPU * 1.2); // 20% more kernels
        std::cout << C_FIRE << "      🔥 BEAST MODE: 12GB+ card detected, applying performance boost!" << C_RESET << "\n";
    }

    // Calculate kernel size based on compute units and safety
    size_t baseKernelSize = safeCores * 10000000UL; // 10M hashes per compute unit base
    device->optimalKernelSize = static_cast<size_t>(baseKernelSize * profile.thermalSafetyFactor);

    // Set memory-based limits and optimal kernel counts
    if (device->globalMemSize >= 24ULL * 1024 * 1024 * 1024)
    {                                                                                  // 24GB+ (RTX 5090 class)
        device->optimalKernelSize = std::min(device->optimalKernelSize, 2000000000UL); // 2B max
        device->optimalKernelsPerGPU = std::min(profile.maxKernelsPerGPU, (size_t)12); // Up to 12 kernels
    }
    else if (device->globalMemSize >= 12ULL * 1024 * 1024 * 1024)
    {                                                                                  // 12GB+ (TITAN V)
        device->optimalKernelSize = std::min(device->optimalKernelSize, 1000000000UL); // 1B max
        device->optimalKernelsPerGPU = std::min(profile.maxKernelsPerGPU, (size_t)8);  // Up to 8 kernels
    }
    else if (device->globalMemSize >= 8ULL * 1024 * 1024 * 1024)
    {                                                                                 // 8GB (GTX 1080)
        device->optimalKernelSize = std::min(device->optimalKernelSize, 500000000UL); // 500M max
        device->optimalKernelsPerGPU = std::min(profile.maxKernelsPerGPU, (size_t)6); // Up to 6 kernels
    }
    else if (device->globalMemSize >= 4ULL * 1024 * 1024 * 1024)
    {                                                                                 // 4GB
        device->optimalKernelSize = std::min(device->optimalKernelSize, 200000000UL); // 200M max
        device->optimalKernelsPerGPU = std::min(profile.maxKernelsPerGPU, (size_t)4); // Up to 4 kernels
    }
    else
    {                                                                                 // Less than 4GB
        device->optimalKernelSize = std::min(device->optimalKernelSize, 100000000UL); // 100M max
        device->optimalKernelsPerGPU = std::min(profile.maxKernelsPerGPU, (size_t)2); // Up to 2 kernels
    }

    // Ensure minimum kernel size
    if (device->optimalKernelSize < 50000000UL)
        device->optimalKernelSize = 50000000UL; // Min 50M

    // Calculate max concurrent kernels with memory awareness
    device->maxConcurrentKernels = std::min(
        device->optimalKernelsPerGPU * 2, // Allow double buffering
        maxKernelsByMemory                // But respect memory limits
    );

    // Store profile info
    device->performanceClass = profile.performanceClass;
    device->thermalSafetyFactor = profile.thermalSafetyFactor;
    device->isHighEnd = (profile.performanceClass == "BEAST" || profile.performanceClass == "HIGH" || profile.performanceClass == "ULTRABEAST");
    device->hasCooling = (device->globalMemSize >= 4ULL * 1024 * 1024 * 1024); // Assume good cooling if 4GB+

    // Special handling for ULTRABEAST class (RTX 5090, future cards)
    if (profile.performanceClass == "ULTRABEAST")
    {
        device->optimalKernelSize = std::min(device->optimalKernelSize * 2, 4000000000UL);     // Up to 4B for ULTRABEAST
        device->maxConcurrentKernels = std::min(device->optimalKernelsPerGPU * 3, (size_t)24); // More buffering
        std::cout << C_FIRE << C_BOLD << C_BLINK << "      💥 ULTRABEAST MODE ACTIVATED! 💥" << C_RESET << "\n";
    }

    // Log the final calculated settings
    Logger::log(formatLogMessage("DEBUG", "OPTIMIZE",
                                 "Final settings: " + std::to_string(device->optimalKernelsPerGPU) + " kernels, " +
                                     std::to_string(device->optimalKernelSize) + " kernel size, " +
                                     std::to_string(device->maxConcurrentKernels) + " max concurrent, " +
                                     std::to_string((int)(profile.coreUsagePercent * 100)) + "% core usage"));

    // Display calculated settings
    std::cout << C_ELECTRIC << "    ⚡ Optimal Settings:" << C_RESET << "\n";
    std::cout << C_INFO << "      📊 Performance Class: " << C_BOLD << device->performanceClass << C_RESET << "\n";
    std::cout << C_INFO << "      🔥 Kernels per GPU: " << C_ACCENT << device->optimalKernelsPerGPU << C_RESET << "\n";
    std::cout << C_INFO << "      📏 Kernel Size: " << C_PRIMARY << formatHashRate(device->optimalKernelSize) << " threads" << C_RESET << "\n";
    std::cout << C_INFO << "      👥 Work Group Size: " << C_SUCCESS << device->optimalWorkGroupSize << C_RESET << "\n";
    std::cout << C_INFO << "      🛡️ Core Usage: " << C_WARNING << (int)(profile.coreUsagePercent * 100) << "%" 
              << " (" << safeCores << "/" << device->maxComputeUnits << " CUs)" << C_RESET << "\n";
    std::cout << C_INFO << "      🌡️ Thermal Safety: " << C_GOLD << (int)(profile.thermalSafetyFactor * 100) << "%" << C_RESET << "\n";
}

// GPU mining interface with automatic tuning information.
void printModernGPUInterface(int blockHeight, const std::vector<std::unique_ptr<GPUDevice>>& devices,
                            double totalHashRate, double elapsed, uint64_t totalHashes, 
                            uint64_t currentChunk, uint64_t totalChunks, bool firstCall,
                            const std::string& minerAddr, uint64_t blockCount, bool foundSolution = false) {
    
    if (firstCall) {
        std::cout << "\033[2J\033[1;1H";
        
        // MEGA ENHANCED Header with blockchain theme! ⛓️
        std::string headerLine = std::string(65, '=');
        std::cout << C_BLOCKCHAIN << C_BOLD << "╭─" << headerLine << "─╮\n";
        std::cout << "│" << C_FIRE << "    🔥💎⚡ TRU BLOCKCHAIN GPU MINER v5.0 INTELLIGENT ⚡💎🔥    " << C_BLOCKCHAIN << "│\n";
        std::cout << "│" << C_ELECTRIC << "         ✨🚀 AI-Powered Auto-Tuning Mining Suite 2025 🚀✨        " << C_BLOCKCHAIN << "│\n";
        std::cout << "╰─" << headerLine << "─╯" << C_RESET << "\n\n";

        // GPU Configuration Card with Auto-Tuning Info
        std::cout << C_INFO << C_BOLD << "╭─ " << SYMBOL_ROCKET << " INTELLIGENT GPU ARSENAL " << SYMBOL_ROCKET << " ──────────────────────────────╮" << C_RESET << "\n";
        std::cout << C_TEXT << "│ " << SYMBOL_FIRE << " Active GPUs   " << C_FIRE << C_BOLD << devices.size() << " AUTO-TUNED BEAST DEVICES" << std::string(25, ' ') << C_TEXT << "│\n";
        
        // Enhanced device display with performance classes
        for (size_t i = 0; i < std::min(devices.size(), (size_t)4); i++) {
            std::string deviceName = devices[i]->deviceName.substr(0, 25);
            std::string perfClass = devices[i]->performanceClass;
            std::string classColor = C_MUTED;
            if (perfClass == "ULTRABEAST") classColor = C_FIRE + std::string(C_BOLD) + std::string(C_BLINK); // Blinking fire!
            else if (perfClass == "BEAST") classColor = C_FIRE;
            else if (perfClass == "HIGH") classColor = C_GOLD;
            else if (perfClass == "MEDIUM") classColor = C_ACCENT;
            
            std::cout << C_TEXT << "│ " << devices[i]->deviceEmoji << " GPU-" << (i+1) << " [" << classColor << perfClass << C_TEXT << "] " 
                      << C_NEON << deviceName << std::string(25 - deviceName.length(), ' ') << "│\n";
        }
        
        if (devices.size() > 4) {
            std::cout << C_TEXT << "│ " << SYMBOL_SPARKLE << " ...         " << C_PURPLE << "+" << (devices.size() - 4) 
                      << " MORE AUTO-TUNED DEVICES" << std::string(20, ' ') << C_TEXT << "│\n";
        }
        
        std::cout << C_TEXT << "│ " << SYMBOL_HASH << " Algorithm     " << C_GOLD << C_BOLD << "SHA256-21E8 (TRU QUANTUM PROTOCOL)" << std::string(15, ' ') << C_TEXT << "│\n";
        std::cout << C_TEXT << "│ " << SYMBOL_BRAIN << " AI Mode       " << C_ELECTRIC << C_BOLD << "INTELLIGENT AUTO-OPTIMIZATION" << std::string(18, ' ') << C_TEXT << "│\n";
        
        std::string dashLine = std::string(65, '-');
        std::cout << C_INFO << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";

        // Mining Status Card
        std::cout << C_SUCCESS << C_BOLD << "╭─ " << SYMBOL_LIGHTNING << " QUANTUM MINING STATUS " << SYMBOL_LIGHTNING << " ─────────────────────────────╮" << C_RESET << "\n";
        for (int i = 0; i < 8; i++) {
            std::cout << "│" << std::string(65, ' ') << "│\n";
        }
        std::cout << C_SUCCESS << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";

        // Performance Metrics Card
        std::cout << C_ACCENT << C_BOLD << "╭─ " << SYMBOL_TROPHY << " AI PERFORMANCE METRICS " << SYMBOL_TROPHY << " ─────────────────────────╮" << C_RESET << "\n";
        for (int i = 0; i < 6; i++) {
            std::cout << "│" << std::string(65, ' ') << "│\n";
        }
        std::cout << C_ACCENT << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";

        // Wallet Information Card
        std::cout << C_SECONDARY << C_BOLD << "╭─ " << SYMBOL_DIAMOND << " MINING REWARDS " << SYMBOL_DIAMOND << " ──────────────────────────────────╮" << C_RESET << "\n";
        std::cout << "│" << std::string(65, ' ') << "│\n";
        std::cout << "│" << std::string(65, ' ') << "│\n";
        std::cout << C_SECONDARY << "╰─" << dashLine << "─╯" << C_RESET << "\n";
    }

    // Update Mining Status Card with MAXIMUM VISUAL IMPACT!
    double chunkProgress = totalChunks > 0 ? (double)currentChunk / totalChunks * 100.0 : 100.0;
    std::string progressBar = createProgressBar(chunkProgress);
    std::string statusText = foundSolution ? "🎯 BLOCK DISCOVERED!" : "⚡ AI QUANTUM MINING";
    
    std::string statusColor;
    if (foundSolution) {
        statusColor = std::string(C_FIRE) + std::string(C_BOLD) + std::string(BG_SUCCESS);
    } else {
        statusColor = std::string(C_ELECTRIC) + std::string(C_BOLD);
    }

    std::cout << "\033[8;1H";
    std::cout << C_TEXT << "│ " << SYMBOL_BLOCK << " Block Target  " << C_PRIMARY << C_BOLD << "#" << blockHeight << std::string(40 - std::to_string(blockHeight).length(), ' ') << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_TARGET << " Status        " << statusColor << statusText << std::string(35 - statusText.length(), ' ') << C_TEXT << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_ROCKET << " Progress      " << progressBar << " " << C_GOLD << C_BOLD << std::fixed << std::setprecision(1) << chunkProgress << "%" << std::string(8, ' ') << C_TEXT << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_BRAIN << " AI State      " << C_NEON << "OPTIMALLY SYNCHRONIZED" << std::string(25, ' ') << C_TEXT << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_FIRE << " GPU Arsenal   " << C_FIRE << C_BOLD << devices.size() << " INTELLIGENT DEVICES" << std::string(25, ' ') << C_TEXT << "│\n";
    
    if (foundSolution) {
        std::cout << C_FIRE << C_BOLD << BG_SUCCESS << "│ " << SYMBOL_BOOM << " SOLUTION      🎉 AI QUANTUM NONCE DISCOVERED! 🎉" << std::string(10, ' ') << C_RESET << C_TEXT << "│\n";
    } else {
        std::cout << C_TEXT << "│ " << SYMBOL_SPARKLE << " Mining Engine " << C_PURPLE << "AI GPU QUANTUM ACCELERATION" << std::string(15, ' ') << "│\n";
    }
    
    std::cout << C_TEXT << "│ " << SYMBOL_CROWN << " Blocks Mined  " << C_GOLD << C_BOLD << blockCount << " TOTAL VICTORIES" << std::string(30, ' ') << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_SHIELD << " Thermal State " << C_SUCCESS << "SAFELY OPTIMIZED" << std::string(30, ' ') << "│\n";

    // Update performance metrics.
    std::cout << "\033[19;1H";
    std::cout << C_TEXT << "│ " << SYMBOL_SPEED << " Total Rate    " << formatHashRate(totalHashRate) << std::string(35, ' ') << "│\n";
    auto now = std::chrono::steady_clock::now();
    double totalRuntime = std::chrono::duration<double>(now - g_minerStartTime).count();
    std::cout << C_TEXT << "│ " << SYMBOL_TIME << " Runtime       " << formatDuration(totalRuntime) << std::string(35, ' ') << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_HASH << " Total Hashes  " << C_PURPLE << C_BOLD << std::to_string(totalHashes) << C_RESET << std::string(35, ' ') << "│\n";
    
    double avgRate = devices.size() > 0 ? totalHashRate / devices.size() : 0.0;
    std::cout << C_TEXT << "│ " << SYMBOL_GEM << " Avg GPU Rate  " << formatHashRate(avgRate) << std::string(35, ' ') << "│\n";
    
    double efficiency = (elapsed > 0) ? (totalHashes / elapsed) : 0.0;
    std::cout << C_TEXT << "│ " << SYMBOL_TROPHY << " AI Efficiency " << formatHashRate(efficiency) << std::string(35, ' ') << "│\n";
    
    // Calculate safety percentage
    double safetyPercent = 0.0;
    for (const auto& device : devices) {
        safetyPercent += device->thermalSafetyFactor;
    }
    safetyPercent = devices.size() > 0 ? (safetyPercent / devices.size() * 100) : 0.0;
    std::cout << C_TEXT << "│ " << SYMBOL_TEMP << " Safety Level  " << C_SUCCESS << (int)safetyPercent << "% THERMAL PROTECTION" << std::string(20, ' ') << "│\n";

    // Update Wallet Information with STYLE!
    std::cout << "\033[27;1H";
    std::cout << C_TEXT << "│ " << SYMBOL_DIAMOND << " Wallet        " << C_SECONDARY << C_BOLD << minerAddr.substr(0, 30) << std::string(20, ' ') << "│\n";
    std::cout << C_TEXT << "│ " << SYMBOL_CROWN << " AI Rewards    " << C_GOLD << C_BOLD << blockCount << " INTELLIGENT BLOCKS MINED" << std::string(15, ' ') << "│\n";

    std::cout << std::flush;
}

// 🚀 INTELLIGENT GPU INITIALIZATION WITH AUTO-TUNING
bool initializeGPUDevicesWithAutoTuning() {
    Logger::log(formatLogMessage("INFO", "INIT", "Starting intelligent GPU auto-tuning system"));
    
    std::cout << C_ELECTRIC << C_BOLD << "╭─ " << SYMBOL_BRAIN << " INTELLIGENT GPU AUTO-TUNING SYSTEM " << SYMBOL_BRAIN << " ─╮" << C_RESET << "\n";
    std::cout << C_INFO << "│ " << SYMBOL_SPARKLE << " AI-powered hardware detection and optimization..." << std::string(10, ' ') << "│" << C_RESET << "\n";
    
    try {
        // Get platforms
        cl_uint numPlatforms = 0;
        cl_int err = clGetPlatformIDs(0, nullptr, &numPlatforms);
        if (err != CL_SUCCESS || numPlatforms == 0) {
            Logger::log(formatLogMessage("ERROR", "INIT", "No OpenCL platforms detected"));
            std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " FATAL: No OpenCL platforms detected!" << std::string(25, ' ') << "│" << C_RESET << "\n";
            std::string dashLine = std::string(65, '-');
            std::cout << C_ERROR << "╰─" << dashLine << "─╯" << C_RESET << "\n";
            return false;
        }
        
        Logger::log(formatLogMessage("INFO", "INIT", "Found " + std::to_string(numPlatforms) + " OpenCL platform(s)"));
        std::cout << C_SUCCESS << "│ " << SYMBOL_TARGET << " Discovered " << C_GOLD << C_BOLD << numPlatforms << " OpenCL platform(s)" << std::string(25, ' ') << C_TEXT << "│" << C_RESET << "\n";
        
        std::vector<cl_platform_id> platforms(numPlatforms);
        err = clGetPlatformIDs(numPlatforms, platforms.data(), nullptr);
        if (err != CL_SUCCESS) {
            Logger::log(formatLogMessage("ERROR", "INIT", "Failed to enumerate platforms"));
            std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " Failed to enumerate platforms!" << std::string(30, ' ') << "│" << C_RESET << "\n";
            return false;
        }

        g_devices.clear();
        const std::string deviceEmojis[] = {"🔥", "💎", "⚡", "🚀", "💥", "✨", "🌟", "💫"};

        // Iterate through platforms with enhanced feedback
        for (size_t p = 0; p < platforms.size(); p++) {
            cl_platform_id platform = platforms[p];
            std::cout << C_INFO << "│ " << SYMBOL_ARROW << " AI analyzing platform " << (p+1) << "..." << std::string(35, ' ') << "│" << C_RESET << "\n";
            
            // Get platform info safely
            char platformName[256] = {0};
            size_t platformNameSize = 0;
            err = clGetPlatformInfo(platform, CL_PLATFORM_NAME, 0, nullptr, &platformNameSize);
            if (err == CL_SUCCESS && platformNameSize > 0 && platformNameSize < sizeof(platformName)) {
                err = clGetPlatformInfo(platform, CL_PLATFORM_NAME, platformNameSize, platformName, nullptr);
                if (err != CL_SUCCESS) {
                    snprintf(platformName, sizeof(platformName), "Unknown Platform %zu", p);
                }
            } else {
                snprintf(platformName, sizeof(platformName), "Unknown Platform %zu", p);
            }
            
            Logger::log(formatLogMessage("INFO", "INIT", "Platform " + std::to_string(p) + ": " + platformName));
            std::cout << C_ACCENT << "│   " << SYMBOL_DOT << " Platform: " << C_GOLD << platformName << std::string(30, ' ') << C_TEXT << "│" << C_RESET << "\n";

            // Get GPU devices for this platform
            cl_uint numDevices = 0;
            err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &numDevices);
            if (err != CL_SUCCESS || numDevices == 0) {
                Logger::log(formatLogMessage("WARNING", "INIT", "No GPU devices found on platform " + std::to_string(p)));
                std::cout << C_WARNING << "│   " << SYMBOL_ERROR << " No GPU devices found on this platform" << std::string(20, ' ') << "│" << C_RESET << "\n";
                continue;
            }
            
            Logger::log(formatLogMessage("INFO", "INIT", "Found " + std::to_string(numDevices) + " GPU devices on platform " + std::to_string(p)));
            std::cout << C_SUCCESS << "│   " << SYMBOL_FIRE << " Found " << C_FIRE << C_BOLD << numDevices << " GPU device(s)!" << std::string(30, ' ') << C_TEXT << "│" << C_RESET << "\n";
            
            std::vector<cl_device_id> devices(numDevices);
            err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, numDevices, devices.data(), nullptr);
            if (err != CL_SUCCESS) {
                Logger::log(formatLogMessage("ERROR", "INIT", "Failed to enumerate GPU devices on platform " + std::to_string(p)));
                std::cout << C_ERROR << "│   " << SYMBOL_ERROR << " Failed to enumerate GPU devices!" << std::string(25, ' ') << "│" << C_RESET << "\n";
                continue;
            }

            // Initialize each device with INTELLIGENT AUTO-TUNING
            for (size_t d = 0; d < devices.size(); d++) {
                cl_device_id device = devices[d];
                std::string emoji = deviceEmojis[g_devices.size() % 8];
                std::cout << C_PRIMARY << "│   " << emoji << " Auto-tuning GPU-" << (g_devices.size() + 1) << "..." << std::string(30, ' ') << "│" << C_RESET << "\n";
                
                // Create device
                GPUDevice* gpuDevice = new GPUDevice();
                gpuDevice->platform = platform;
                gpuDevice->device = device;
                gpuDevice->platformName = platformName;
                gpuDevice->deviceEmoji = emoji;

                // Get device name safely
                char deviceName[256] = {0};
                size_t deviceNameSize = 0;
                err = clGetDeviceInfo(device, CL_DEVICE_NAME, 0, nullptr, &deviceNameSize);
                if (err == CL_SUCCESS && deviceNameSize > 0 && deviceNameSize < sizeof(deviceName)) {
                    err = clGetDeviceInfo(device, CL_DEVICE_NAME, deviceNameSize, deviceName, nullptr);
                    if (err == CL_SUCCESS) {
                        gpuDevice->deviceName = deviceName;
                    } else {
                        gpuDevice->deviceName = "Unknown Device";
                    }
                } else {
                    gpuDevice->deviceName = "Unknown Device";
                }

                Logger::log(formatLogMessage("INFO", "INIT", "Initializing device: " + gpuDevice->deviceName));
                std::cout << C_ACCENT << "│     " << SYMBOL_SPARKLE << " Device: " << C_NEON << gpuDevice->deviceName.substr(0, 30) << std::string(15, ' ') << "│" << C_RESET << "\n";

                // Get device properties safely
                err = clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(size_t), &gpuDevice->maxComputeUnits, nullptr);
                if (err != CL_SUCCESS) {
                    gpuDevice->maxComputeUnits = 1;
                }

                err = clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &gpuDevice->maxWorkGroupSize, nullptr);
                if (err != CL_SUCCESS) {
                    gpuDevice->maxWorkGroupSize = 256;
                }

                err = clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(size_t), &gpuDevice->globalMemSize, nullptr);
                if (err != CL_SUCCESS) {
                    gpuDevice->globalMemSize = 0;
                }

                std::cout << C_INFO << "│     " << SYMBOL_GEM << " Specs: " << C_PURPLE << gpuDevice->maxComputeUnits 
                          << " CUs, " << gpuDevice->maxWorkGroupSize << " WG, " 
                          << (gpuDevice->globalMemSize/1024/1024/1024) << "GB" << std::string(10, ' ') << "│" << C_RESET << "\n";

                // 🧠 INTELLIGENT AUTO-TUNING STARTS HERE!
                std::cout << C_PRIMARY << "│     🧠 Auto-tuning: " << gpuDevice->deviceName.substr(0, 30) << std::string(15, ' ') << "│" << C_RESET << "\n";
                
                // Detect GPU profile
                GPUProfile profile = detectGPUProfile(gpuDevice->deviceName, gpuDevice->maxComputeUnits, gpuDevice->globalMemSize);
                
                // Calculate optimal settings
                calculateOptimalSettings(gpuDevice, profile);

                try {
                    // Create context
                    cl_context_properties properties[3] = {CL_CONTEXT_PLATFORM, (cl_context_properties)platform, 0};
                    gpuDevice->context = clCreateContext(properties, 1, &device, nullptr, nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->context) {
                        throw std::runtime_error("clCreateContext failed: " + std::to_string(err));
                    }

                    // Create command queue
                    gpuDevice->queue = clCreateCommandQueue(gpuDevice->context, device, 0, &err);
                    if (err != CL_SUCCESS || !gpuDevice->queue) {
                        throw std::runtime_error("clCreateCommandQueue failed: " + std::to_string(err));
                    }

                    // Build program with optimizations
                    const char* sources[] = {GPU_KERNEL_SRC};
                    size_t lengths[] = {std::strlen(GPU_KERNEL_SRC)};
                    gpuDevice->program = clCreateProgramWithSource(gpuDevice->context, 1, sources, lengths, &err);
                    if (err != CL_SUCCESS || !gpuDevice->program) {
                        throw std::runtime_error("clCreateProgramWithSource failed: " + std::to_string(err));
                    }

                    // Enhanced build options for better performance
                    const char* buildOptions = "-cl-fast-relaxed-math -cl-mad-enable -cl-no-signed-zeros -cl-finite-math-only";
                    Logger::log(formatLogMessage("DEBUG", "INIT", "Building OpenCL program with options: " + std::string(buildOptions)));
                    err = clBuildProgram(gpuDevice->program, 1, &device, buildOptions, nullptr, nullptr);
                    if (err != CL_SUCCESS) {
                        size_t logSize = 0;
                        clGetProgramBuildInfo(gpuDevice->program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logSize);
                        if (logSize > 0) {
                            std::vector<char> buildLog(logSize + 1, 0);
                            clGetProgramBuildInfo(gpuDevice->program, device, CL_PROGRAM_BUILD_LOG, logSize, buildLog.data(), nullptr);
                            Logger::log(formatLogMessage("ERROR", "INIT", "OpenCL build failed: " + std::string(buildLog.data())));
                            std::cout << C_ERROR << "│     " << SYMBOL_ERROR << " Build failed!" << std::string(40, ' ') << "│" << C_RESET << "\n";
                        }
                        throw std::runtime_error("clBuildProgram failed: " + std::to_string(err));
                    }

                    // Create kernel
                    gpuDevice->kernel = clCreateKernel(gpuDevice->program, "tru_gpu_miner", &err);
                    if (err != CL_SUCCESS || !gpuDevice->kernel) {
                        throw std::runtime_error("clCreateKernel failed: " + std::to_string(err));
                    }

                    // Create buffers
                    gpuDevice->header80_buf = clCreateBuffer(gpuDevice->context, CL_MEM_READ_WRITE, 80, nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->header80_buf) {
                        throw std::runtime_error("Failed to create header80_buf: " + std::to_string(err));
                    }
                    
                    gpuDevice->target_buf = clCreateBuffer(gpuDevice->context, CL_MEM_READ_ONLY, 32, nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->target_buf) {
                        throw std::runtime_error("Failed to create target_buf: " + std::to_string(err));
                    }
                    
                    gpuDevice->foundFlag_buf = clCreateBuffer(gpuDevice->context, CL_MEM_READ_WRITE, sizeof(cl_int), nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->foundFlag_buf) {
                        throw std::runtime_error("Failed to create foundFlag_buf: " + std::to_string(err));
                    }
                    
                    gpuDevice->foundNonce_buf = clCreateBuffer(gpuDevice->context, CL_MEM_READ_WRITE, sizeof(cl_ulong), nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->foundNonce_buf) {
                        throw std::runtime_error("Failed to create foundNonce_buf: " + std::to_string(err));
                    }
                    
                    gpuDevice->foundHash_buf = clCreateBuffer(gpuDevice->context, CL_MEM_READ_WRITE, 32, nullptr, &err);
                    if (err != CL_SUCCESS || !gpuDevice->foundHash_buf) {
                        throw std::runtime_error("Failed to create foundHash_buf: " + std::to_string(err));
                    }

                    gpuDevice->initialized = true;
                    gpuDevice->deviceHashes = 0;

                    // Store device info before moving
                    std::string devName = gpuDevice->deviceName.substr(0, 20);
                    std::string perfClass = gpuDevice->performanceClass;

                    // Add to devices vector
                    g_devices.push_back(std::unique_ptr<GPUDevice>(gpuDevice));

                    Logger::log(formatLogMessage("SUCCESS", "INIT", "Successfully initialized " + devName + " [" + perfClass + "]"));
                    std::cout << C_SUCCESS << C_BOLD << "│     " << SYMBOL_TROPHY << " SUCCESS! " << emoji << " " << devName 
                              << " [" << perfClass << "] READY!" << std::string(10, ' ') << "│" << C_RESET << "\n";

                } catch (const std::exception& e) {
                    Logger::log(formatLogMessage("ERROR", "INIT", "Failed to initialize device: " + std::string(e.what())));
                    std::cout << C_ERROR << "│     " << SYMBOL_ERROR << " FAILED: " << e.what() << std::string(30, ' ') << "│" << C_RESET << "\n";
                    delete gpuDevice;
                }
            }
        }

        if (g_devices.empty()) {
            Logger::log(formatLogMessage("ERROR", "INIT", "No GPU devices initialized"));
            std::cout << C_ERROR << C_BOLD << "│ " << SYMBOL_ERROR << " CRITICAL: No GPU devices initialized!" << std::string(25, ' ') << "│" << C_RESET << "\n";
            std::string dashLine = std::string(65, '-');
            std::cout << C_ERROR << "╰─" << dashLine << "─╯" << C_RESET << "\n";
            return false;
        }

        // Display system summary
        std::cout << C_SUCCESS << C_BOLD << "│ " << SYMBOL_CROWN << " AI AUTO-TUNING COMPLETE!" << std::string(30, ' ') << "│" << C_RESET << "\n";
        
        size_t totalKernels = 0;
        uint64_t totalThreads = 0;
        int beastCount = 0, highCount = 0, mediumCount = 0, basicCount = 0;
        
        for (const auto& device : g_devices) {
            totalKernels += device->optimalKernelsPerGPU;
            totalThreads += device->optimalKernelSize * device->optimalKernelsPerGPU;
            
            if (device->performanceClass == "BEAST") beastCount++;
            else if (device->performanceClass == "HIGH") highCount++;
            else if (device->performanceClass == "MEDIUM") mediumCount++;
            else basicCount++;
        }
        
        Logger::log(formatLogMessage("INFO", "INIT", 
            "System summary: " + std::to_string(g_devices.size()) + " GPUs, " +
            std::to_string(totalKernels) + " kernels, " + std::to_string(totalThreads) + " total threads"));
        
        std::cout << C_FIRE << "│ 🔥 System Capacity: " << C_BOLD << totalKernels << " kernels, " 
                  << formatHashRate(totalThreads) << " total threads" << std::string(5, ' ') << "│" << C_RESET << "\n";
        
        std::ostringstream perfSummary;
        if (beastCount > 0) perfSummary << beastCount << " BEAST ";
        if (highCount > 0) perfSummary << highCount << " HIGH ";
        if (mediumCount > 0) perfSummary << mediumCount << " MEDIUM ";
        if (basicCount > 0) perfSummary << basicCount << " BASIC ";
        
        std::cout << C_ELECTRIC << "│ 🧠 Performance Mix: " << C_BOLD << perfSummary.str() << "class GPUs detected" << std::string(10, ' ') << "│" << C_RESET << "\n";
        
        std::string dashLine = std::string(65, '-');
        std::cout << C_SUCCESS << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";
        
        return true;

    } catch (const std::exception& e) {
        Logger::log(formatLogMessage("ERROR", "INIT", "Fatal error: " + std::string(e.what())));
        std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " FATAL ERROR: " << e.what() << std::string(30, ' ') << "│" << C_RESET << "\n";
        std::string dashLine = std::string(65, '-');
        std::cout << C_ERROR << "╰─" << dashLine << "─╯" << C_RESET << "\n";
        return false;
    }
}

// 🎯 INTELLIGENT GPU MINING FUNCTION WITH AUTO-TUNED SETTINGS
bool mineBlockGPU_21E8_AutoTuned(Block& candidate, uint64_t maxNonce, httplib::Client& cli,
                                 const std::string& minerAddr, int& extraNonce, uint64_t& blockCount) {
    
    Logger::log(formatLogMessage("INFO", "MINING", 
        "Starting GPU mining for block " + std::to_string(candidate.height) + 
        " with " + std::to_string(g_devices.size()) + " devices"));
    
    // Reset global state properly
    if (g_devices.empty()) {
        Logger::log(formatLogMessage("ERROR", "MINING", "No initialized GPU devices"));
        return false;
    }

    g_found.store(false);
    g_foundNonce.store(0);
    g_totalHashes.store(0);
    g_hashesAtLastReport.store(0);
    for (auto& device : g_devices) {
        if (device) device->deviceHashes = 0;
    }
    
    std::cout << C_FIRE << C_BOLD << "\n╭─ " << SYMBOL_BRAIN << " INITIATING AI QUANTUM MINING SEQUENCE " << SYMBOL_BRAIN << " ─╮" << C_RESET << "\n";
    std::cout << C_SUCCESS << "│ " << SYMBOL_TARGET << " Target Block: #" << C_GOLD << C_BOLD << candidate.height << std::string(35, ' ') << C_TEXT << "│" << C_RESET << "\n";
    
    // Use existing blockchain function to build header
    std::vector<unsigned char> header80;
    try {
        header80 = buildBlockHeader80(candidate.header);
        Logger::log(formatLogMessage("DEBUG", "MINING", "Block header constructed successfully"));
        std::cout << C_SUCCESS << "│ " << SYMBOL_SUCCESS << " Block header constructed successfully" << std::string(20, ' ') << "│" << C_RESET << "\n";
    } catch (const std::exception& e) {
        Logger::log(formatLogMessage("ERROR", "MINING", "Header build failed: " + std::string(e.what())));
        std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " Header build failed: " << e.what() << std::string(15, ' ') << "│" << C_RESET << "\n";
        std::string dashLine = std::string(65, '-');
        std::cout << C_ERROR << "╰─" << dashLine << "─╯" << C_RESET << "\n";
        return false;
    }
    
    // Use existing blockchain function for target conversion
    unsigned char targetBE[32];
    try {
        bitsToTargetArrayFree(candidate.header.bits, targetBE);
        
        // Log target difficulty
        std::ostringstream targetHex;
        for (int i = 0; i < 32; i++) {
            targetHex << std::hex << std::setw(2) << std::setfill('0') << (int)targetBE[i];
        }
        std::ostringstream bitsHex;
        bitsHex << std::hex << std::setw(8) << std::setfill('0') << candidate.header.bits;
        Logger::log(formatLogMessage("DEBUG", "MINING",
            "Target: " + targetHex.str() + ", Bits: 0x" + bitsHex.str()));
        
        std::cout << C_SUCCESS << "│ " << SYMBOL_SUCCESS << " Mining target configured" << std::string(30, ' ') << "│" << C_RESET << "\n";
    } catch (const std::exception& e) {
        Logger::log(formatLogMessage("ERROR", "MINING", "Target conversion failed: " + std::string(e.what())));
        std::cout << C_ERROR << "│ " << SYMBOL_ERROR << " Target conversion failed: " << e.what() << std::string(10, ' ') << "│" << C_RESET << "\n";
        std::string dashLine = std::string(65, '-');
        std::cout << C_ERROR << "╰─" << dashLine << "─╯" << C_RESET << "\n";
        return false;
    }
    std::vector<unsigned char> targetVec(targetBE, targetBE + 32);
    
    std::cout << C_ELECTRIC << "│ " << SYMBOL_LIGHTNING << " AI Quantum mining engines: ARMED & OPTIMIZED!" << std::string(10, ' ') << "│" << C_RESET << "\n";
    std::string dashLine = std::string(65, '-');
    std::cout << C_FIRE << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";
    
    auto startTime = std::chrono::steady_clock::now();
    bool firstCall = true;
    
    // lets the progress thread exit when a full nonce sweep
    // finishes with NO solution (g_found stays false, g_shutdown stays false).
    std::atomic<bool> miningDone{false};
    
    // Enhanced progress reporting thread with hash tracking
    std::thread progressThread([&]() {
        auto lastUpdate = std::chrono::steady_clock::now();
        uint64_t lastHashes = 0;
        
        while (!g_found.load() && !g_shutdown.load() &&
               !miningDone.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - startTime).count();
            uint64_t currentHashes = g_totalHashes.load();
            
            double intervalTime = std::chrono::duration<double>(now - lastUpdate).count();
            uint64_t intervalHashes = currentHashes - lastHashes;
            double hashRate = (intervalTime > 0) ? (intervalHashes / intervalTime) : 0.0;
            
            // Log performance stats periodically
            static auto lastLogTime = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastLogTime).count() >= 30) {
                Logger::log(formatLogMessage("STATS", "PERFORMANCE", 
                    "Hash rate: " + std::to_string(hashRate) + " H/s, Total hashes: " + std::to_string(currentHashes)));
                lastLogTime = now;
            }
            
            printModernGPUInterface(candidate.height, g_devices, hashRate, elapsed, currentHashes,
                                  1, 1, firstCall, minerAddr, blockCount);
            
            firstCall = false;
            lastUpdate = now;
            lastHashes = currentHashes;
        }
    });
    
    // INTELLIGENT: Enhanced device mining threads with AUTO-TUNED settings
    std::vector<std::thread> deviceThreads;

    // MINER-TIME-01B: performance-preserving fresh-template sweep.
    // Search the complete uint32 nonce space once, then return immediately to
    // the outer loop for a fresh getblocktemplate. This preserves sustained
    // GPU occupancy while retaining the >30s stale-solution rejection gate.
    const uint64_t totalNonces = maxNonce + 1ULL;
    const uint64_t sweepNonces = totalNonces;
    const uint64_t deviceCount = static_cast<uint64_t>(g_devices.size());
    const uint64_t baseNoncesPerDevice = sweepNonces / deviceCount;
    const uint64_t remainderNonces = sweepNonces % deviceCount;

    uint64_t partitionCursor = 0;
    for (size_t i = 0; i < g_devices.size(); i++) {
        auto& device = g_devices[i];
        const uint64_t extra = (static_cast<uint64_t>(i) < remainderNonces) ? 1ULL : 0ULL;
        const uint64_t deviceStart = partitionCursor;
        const uint64_t deviceEndExclusive = deviceStart + baseNoncesPerDevice + extra;
        partitionCursor = deviceEndExclusive;

        deviceThreads.emplace_back([&device, &header80, &targetVec, deviceStart, deviceEndExclusive, i]() {
            if (g_found.load()) return;
            
            Logger::log(formatLogMessage("INFO", "DEVICE", 
                "GPU-" + std::to_string(i+1) + " starting with " + device->performanceClass + " settings"));
            std::cout << C_PRIMARY << "[GPU-" << (i+1) << "] " << device->deviceEmoji << " " << device->deviceName 
                      << " using " << C_BOLD << device->performanceClass << " AI settings" << C_RESET << "\n";
            
            try {
                cl_int err = 0;
                
                // 🚀 USE AUTO-TUNED SETTINGS (NO MORE GUESSING!)
                
		size_t KERNELS_PER_GPU = device->optimalKernelsPerGPU;
		size_t KERNEL_SIZE = device->optimalKernelSize;
		size_t MAX_KERNELS_TOTAL = device->maxConcurrentKernels;
		size_t LOCAL_WORK = device->optimalWorkGroupSize;

		if (device->performanceClass == "BEAST" || device->performanceClass == "HIGH") {
    		    if (device->globalMemSize >= 12ULL * 1024 * 1024 * 1024) {  // TITAN V
        		KERNEL_SIZE = 1000000000UL;  // 1 billion threads
        		KERNELS_PER_GPU = 8;          // 8 concurrent kernels
    		    } else if (device->globalMemSize >= 8ULL * 1024 * 1024 * 1024) {  // GTX 1080
        		KERNEL_SIZE = 500000000UL;    // 500M threads
        		KERNELS_PER_GPU = 6;          // 6 concurrent kernels
    		    }
		    MAX_KERNELS_TOTAL = KERNELS_PER_GPU * 2;
    		    LOCAL_WORK = 256;  // Optimal for most GPUs
    
    		    std::cout << C_FIRE << C_BOLD << "[GPU-" << (i+1) << "] " << SYMBOL_BOOM 
                    << " OVERRIDE: " << formatHashRate(KERNEL_SIZE) 
                    << " threads × " << KERNELS_PER_GPU << " kernels = "
                    << formatHashRate(KERNEL_SIZE * KERNELS_PER_GPU) << " total!" << C_RESET << "\n";
		}

                Logger::log(formatLogMessage("DEBUG", "DEVICE", 
                    "GPU-" + std::to_string(i+1) + " auto-tuned settings: " +
                    std::to_string(KERNELS_PER_GPU) + " kernels × " + std::to_string(KERNEL_SIZE) + 
                    " threads (WG: " + std::to_string(LOCAL_WORK) + ")"));
                
                std::cout << C_FIRE << "[GPU-" << (i+1) << "] " << SYMBOL_ROCKET << " AI Auto-tuned: " 
                          << KERNELS_PER_GPU << " kernels × " << formatHashRate(KERNEL_SIZE) 
                          << " threads (WG: " << LOCAL_WORK << ")" << C_RESET << "\n";
                
                // Atomic counters for accurate tracking
                std::atomic<uint64_t> kernelsLaunched(0);
                std::atomic<uint64_t> kernelsCompleted(0);
                std::vector<cl_event> events;
                std::vector<size_t> kernelWorkSizes;
                std::vector<cl_command_queue> queues;
                std::mutex eventMutex;
                
                // Create multiple command queues for maximum parallelism
                for (size_t q = 0; q < KERNELS_PER_GPU; q++) {
                    cl_command_queue queue = clCreateCommandQueue(device->context, device->device, 0, &err);
                    if (err == CL_SUCCESS) {
                        queues.push_back(queue);
                    }
                }
                
                // Write initial buffers
                int zeroFlag = 0;
                cl_ulong startN = deviceStart;
                std::vector<unsigned char> zeroHash(32, 0);
                
                err = clEnqueueWriteBuffer(device->queue, device->header80_buf, CL_FALSE, 0, 80, header80.data(), 0, nullptr, nullptr);
                err |= clEnqueueWriteBuffer(device->queue, device->target_buf, CL_FALSE, 0, 32, targetVec.data(), 0, nullptr, nullptr);
                err |= clEnqueueWriteBuffer(device->queue, device->foundFlag_buf, CL_FALSE, 0, sizeof(int), &zeroFlag, 0, nullptr, nullptr);
                err |= clEnqueueWriteBuffer(device->queue, device->foundNonce_buf, CL_FALSE, 0, sizeof(cl_ulong), &startN, 0, nullptr, nullptr);
                err |= clEnqueueWriteBuffer(device->queue, device->foundHash_buf, CL_FALSE, 0, 32, zeroHash.data(), 0, nullptr, nullptr);
                
                if (err == CL_SUCCESS) {
                    cl_ulong currentStart = deviceStart;
                    size_t kernelIndex = 0;
                    size_t localWork = LOCAL_WORK;
                    
                    // Launch kernels with AI-optimized settings
                    while (currentStart < deviceEndExclusive && !g_found.load() && kernelIndex < MAX_KERNELS_TOTAL) {
                        cl_command_queue currentQueue = queues[kernelIndex % queues.size()];
                        cl_ulong kernelEndExclusive = std::min(
                            currentStart + static_cast<cl_ulong>(KERNEL_SIZE),
                            static_cast<cl_ulong>(deviceEndExclusive));
                        size_t actualWork = static_cast<size_t>(kernelEndExclusive - currentStart);
                        
                        if (actualWork < localWork) break;
                        
                        // Round up to work group size
                        actualWork = ((actualWork + localWork - 1) / localWork) * localWork;
                        
                        // Set kernel arguments
                        err = clSetKernelArg(device->kernel, 0, sizeof(cl_mem), &device->header80_buf);
                        err |= clSetKernelArg(device->kernel, 1, sizeof(cl_ulong), &currentStart);
                        err |= clSetKernelArg(device->kernel, 2, sizeof(cl_ulong), &kernelEndExclusive);
                        err |= clSetKernelArg(device->kernel, 3, sizeof(cl_mem), &device->target_buf);
                        err |= clSetKernelArg(device->kernel, 4, sizeof(cl_mem), &device->foundFlag_buf);
                        err |= clSetKernelArg(device->kernel, 5, sizeof(cl_mem), &device->foundNonce_buf);
                        err |= clSetKernelArg(device->kernel, 6, sizeof(cl_mem), &device->foundHash_buf);
                        
                        if (err != CL_SUCCESS) {
                            Logger::log(formatLogMessage("ERROR", "DEVICE", 
                                "GPU-" + std::to_string(i+1) + " kernel args failed: " + std::to_string(err)));
                            std::cout << C_ERROR << "[GPU-" << (i+1) << "] " << SYMBOL_ERROR << " Kernel args failed: " << err << C_RESET << "\n";
                            break;
                        }
                        
                        // Launch kernel with event tracking
                        cl_event kernelEvent;
                        err = clEnqueueNDRangeKernel(currentQueue, device->kernel, 1, nullptr, 
                                                   &actualWork, &localWork, 0, nullptr, &kernelEvent);
                        
                        if (err == CL_SUCCESS) {
                            {
                                std::lock_guard<std::mutex> lock(eventMutex);
                                events.push_back(kernelEvent);
                                kernelWorkSizes.push_back(actualWork);
                            }
                            
                            kernelsLaunched.fetch_add(1);
                            device->totalKernelsLaunched++;
                            
                            if (kernelIndex % 10 == 0) {  // Log every 10th kernel
                                Logger::log(formatLogMessage("DEBUG", "DEVICE", 
                                    "GPU-" + std::to_string(i+1) + " kernel " + std::to_string(kernelIndex) + 
                                    " launched: " + std::to_string(actualWork) + " threads"));
                            }
                            
                            if (kernelIndex % 3 == 0) {  // Show progress every 3rd kernel
                                std::cout << C_SUCCESS << "[GPU-" << (i+1) << "] " << SYMBOL_LIGHTNING << " AI Kernel " << kernelIndex 
                                          << " launched: " << formatHashRate(actualWork) << " threads" << C_RESET << "\n";
                            }
                        } else {
                            Logger::log(formatLogMessage("ERROR", "DEVICE", 
                                "GPU-" + std::to_string(i+1) + " kernel launch failed: " + std::to_string(err)));
                            std::cout << C_ERROR << "[GPU-" << (i+1) << "] " << SYMBOL_ERROR << " Kernel launch failed: " << err << C_RESET << "\n";
                            break;
                        }
                        
                        currentStart = kernelEndExclusive;
                        kernelIndex++;
                        
                        // Quick solution check - optimized frequency based on device class
                        int checkFreq = (device->performanceClass == "BEAST") ? 4 : 
                                       (device->performanceClass == "HIGH") ? 3 : 2;
                        if (kernelIndex % checkFreq == 0) {
                            int foundFlag = 0;
                            clEnqueueReadBuffer(device->queue, device->foundFlag_buf, CL_FALSE, 0, sizeof(int), &foundFlag, 0, nullptr, nullptr);
                            clFinish(device->queue);
                            
                            if (foundFlag) {
                                g_found.store(true);
                                Logger::log(formatLogMessage("SUCCESS", "DEVICE", 
                                    "GPU-" + std::to_string(i+1) + " found solution!"));
                                std::cout << C_FIRE << C_BOLD << "[GPU-" << (i+1) << "] " << SYMBOL_BOOM << " AI QUANTUM SOLUTION DISCOVERED!" << C_RESET << "\n";
                                break;
                            }
                        }
                    }
                    
                    // INTELLIGENT: Concurrent kernel completion monitoring
                    std::thread completionThread([&]() {
                        auto monitorStart = std::chrono::steady_clock::now();
                        
                        while (kernelsCompleted.load() < kernelsLaunched.load() && !g_found.load()) {
                            {
                                std::lock_guard<std::mutex> lock(eventMutex);
                                
                                for (auto it = events.begin(); it != events.end();) {
                                    cl_int eventStatus;
                                    err = clGetEventInfo(*it, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &eventStatus, nullptr);
                                    
                                    if (err == CL_SUCCESS && eventStatus == CL_COMPLETE) {
                                        // capture the index ONCE, before any erase,
                                        // so `events` and `kernelWorkSizes` stay in lockstep.
                                        size_t idx = static_cast<size_t>(it - events.begin());
                                        size_t workCompleted = kernelWorkSizes[idx];

                                        // Check the device-local solution flag BEFORE crediting the
                                        // NDRange. If a solution was observed, some work-items may
                                        // have returned early, so queued size is not exact hashes tried.
                                        int foundFlag = 0;
                                        clEnqueueReadBuffer(device->queue, device->foundFlag_buf, CL_TRUE, 0,
                                                            sizeof(int), &foundFlag, 0, nullptr, nullptr);

                                        if (foundFlag && !g_found.load()) {
                                            cl_ulong foundNonce = 0;
                                            std::vector<unsigned char> foundHash(32);
                                            clEnqueueReadBuffer(device->queue, device->foundNonce_buf, CL_TRUE, 0, sizeof(cl_ulong), &foundNonce, 0, nullptr, nullptr);
                                            clEnqueueReadBuffer(device->queue, device->foundHash_buf, CL_TRUE, 0, 32, foundHash.data(), 0, nullptr, nullptr);

                                            std::lock_guard<std::mutex> foundLock(g_foundMutex);
                                            if (!g_found.exchange(true)) {
                                                g_foundNonce.store(foundNonce);
                                                g_foundHash = foundHash;

                                                std::ostringstream hashHex;
                                                for (int i = 0; i < 32; i++) {
                                                    hashHex << std::hex << std::setw(2) << std::setfill('0') << (int)foundHash[i];
                                                }
                                                Logger::log(formatLogMessage("SUCCESS", "DEVICE",
                                                    "GPU-" + std::to_string(i+1) + " found valid hash! Nonce: " +
                                                    std::to_string(foundNonce) + ", Hash: " + hashHex.str()));

                                                std::cout << C_FIRE << C_BOLD << BG_SUCCESS << "[GPU-" << (i+1) << "] " << SYMBOL_CROWN
                                                          << " AI VICTORY! NONCE " << foundNonce << " DISCOVERED!" << C_RESET << "\n";
                                            }
                                        }

                                        bool credited = false;
                                        // GPU-CREDIT-01: credit is decided by THIS kernel's own
                                        // foundFlag, not by the process-wide g_found.
                                        //
                                        // The kernel aborts on its own device flag:
                                        //     if(atomic_cmpxchg(foundFlag, 0, 0) != 0) return;
                                        // so any kernel that exited early already reads back
                                        // foundFlag != 0 and is correctly denied credit by
                                        // !foundFlag alone.
                                        //
                                        // The former extra "&& !g_found.load()" denied credit to
                                        // kernels that ran a FULL sweep and found nothing, purely
                                        // because some other kernel on some other device had won
                                        // in the meantime. At short block times g_found is set most
                                        // of the time, so nearly all honest work scored zero:
                                        //     "Found: 1, Credited hashes: 0, Rate: 0.000000 H/s"
                                        // g_sessionHashes then stayed 0 and the keepalive reporter
                                        // published hashRate 0, so the explorer counted no active
                                        // miners even while both GPUs ran at 100%.
                                        if (!foundFlag) {
                                            creditCompletedHashWork(workCompleted);
                                            device->deviceHashes += workCompleted;
                                            credited = true;
                                        }
                                        kernelsCompleted.fetch_add(1);

                                        if (kernelsCompleted.load() % 10 == 0) {
                                            Logger::log(formatLogMessage("DEBUG", "DEVICE",
                                                "GPU-" + std::to_string(i+1) + " completed " +
                                                std::to_string(kernelsCompleted.load()) + " kernels, " +
                                                std::to_string(device->deviceHashes) + " credited hash work"));
                                        }

                                        if (credited && kernelsCompleted.load() % 4 == 0) {
                                            std::cout << C_SUCCESS << "[GPU-" << (i+1) << "] " << SYMBOL_GEM << " AI Kernel completed: "
                                                      << formatHashRate(workCompleted) << " credited hashes (Sweep total: "
                                                      << formatHashRate(g_totalHashes.load()) << ")" << C_RESET << "\n";
                                        }

                                        clReleaseEvent(*it);
                                        it = events.erase(it);
                                        // erase the SAME index captured above; using
                                        // (it - events.begin()) here points at the NEXT element after
                                        // erase, which desynced the vectors and hung the monitor loop.
                                        kernelWorkSizes.erase(kernelWorkSizes.begin() + idx);
                                    } else {
                                        ++it;
                                    }
                                }
                            }
                            
                            std::this_thread::sleep_for(std::chrono::microseconds(100));
                            
                            // Adaptive timeout based on device class
                            int timeoutSecs = (device->performanceClass == "BEAST") ? 45 : 
                                             (device->performanceClass == "HIGH") ? 35 : 25;
                            auto elapsed = std::chrono::steady_clock::now() - monitorStart;
                            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > timeoutSecs) {
                                Logger::log(formatLogMessage("WARNING", "DEVICE",
                                    "GPU-" + std::to_string(i+1) + " monitor timeout - deferring accounting to final event wait"));
                                std::cout << C_WARNING << "[GPU-" << (i+1) << "] " << SYMBOL_WARNING
                                          << " AI Monitor timeout - pending work will not be pre-counted" << C_RESET << "\n";
                                break;
                            }
                        }
                    });
                    
                    completionThread.join();
                    
                    // Final cleanup
                    {
                        std::lock_guard<std::mutex> lock(eventMutex);
                        for (size_t j = 0; j < events.size(); j++) {
                            clWaitForEvents(1, &events[j]);
                            
                            // GPU-CREDIT-01: same correction as the monitor loop above.
                            // This kernel's own foundFlag already covers early-returning
                            // work-items; g_found only says some OTHER device won, which
                            // is not a reason to discard this device's completed sweep.
                            size_t remainingWork = kernelWorkSizes[j];
                            int foundFlag = 0;
                            clEnqueueReadBuffer(device->queue, device->foundFlag_buf, CL_TRUE, 0,
                                                sizeof(int), &foundFlag, 0, nullptr, nullptr);
                            if (!foundFlag) {
                                creditCompletedHashWork(remainingWork);
                                device->deviceHashes += remainingWork;
                            }

                            clReleaseEvent(events[j]);
                        }
                    }
                    
                    // Final solution check
                    if (!g_found.load()) {
                        int foundFlag = 0;
                        clEnqueueReadBuffer(device->queue, device->foundFlag_buf, CL_TRUE, 0, sizeof(int), &foundFlag, 0, nullptr, nullptr);
                        
                        if (foundFlag && !g_found.load()) {
                            cl_ulong foundNonce = 0;
                            std::vector<unsigned char> foundHash(32);
                            clEnqueueReadBuffer(device->queue, device->foundNonce_buf, CL_TRUE, 0, sizeof(cl_ulong), &foundNonce, 0, nullptr, nullptr);
                            clEnqueueReadBuffer(device->queue, device->foundHash_buf, CL_TRUE, 0, 32, foundHash.data(), 0, nullptr, nullptr);
                            
                            std::lock_guard<std::mutex> lock(g_foundMutex);
                            if (!g_found.exchange(true)) {
                                g_foundNonce.store(foundNonce);
                                g_foundHash = foundHash;
                            }
                        }
                    }
                } else {
                    Logger::log(formatLogMessage("ERROR", "DEVICE", 
                        "GPU-" + std::to_string(i+1) + " buffer operations failed: " + std::to_string(err)));
                    std::cout << C_ERROR << "[GPU-" << (i+1) << "] " << SYMBOL_ERROR << " Buffer operations failed: " << err << C_RESET << "\n";
                }
                
                // Clean up additional queues
                for (size_t q = 1; q < queues.size(); q++) {
                    clReleaseCommandQueue(queues[q]);
                }
                
                Logger::log(formatLogMessage("INFO", "DEVICE", 
                    "GPU-" + std::to_string(i+1) + " completed. Kernels launched: " + std::to_string(kernelsLaunched.load()) +
                    ", completed: " + std::to_string(kernelsCompleted.load()) + 
                    ", creditedHashes: " + std::to_string(device->deviceHashes)));
                
                std::cout << C_INFO << "[GPU-" << (i+1) << "] " << device->deviceEmoji << " AI Mining complete. " 
                          << "Class: " << device->performanceClass << ", Kernels: " << kernelsLaunched.load() 
                          << " launched, " << kernelsCompleted.load() << " completed, Credited Hash Work: "
                          << formatHashRate(device->deviceHashes) << C_RESET << "\n";
                
            } catch (const std::exception& e) {
                Logger::log(formatLogMessage("ERROR", "DEVICE", 
                    "GPU-" + std::to_string(i+1) + " exception: " + std::string(e.what())));
                std::cout << C_ERROR << "[GPU-" << (i+1) << "] " << SYMBOL_ERROR << " Device error: " << e.what() << C_RESET << "\n";
            }
        });
    }
    
    // Wait for all devices
    for (auto& thread : deviceThreads) {
        thread.join();
    }
    
    // all device workers finished; release the progress thread
    // even when no solution was found, so join() below cannot hang.
    miningDone.store(true, std::memory_order_release);
    
    if (progressThread.joinable()) {
        progressThread.join();
    }
    
    // Final status with enhanced visuals
    auto endTime = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(endTime - startTime).count();
    uint64_t finalHashes = g_totalHashes.load();
    double finalHashRate = (elapsed > 0) ? (finalHashes / elapsed) : 0.0;
    
    Logger::log(formatLogMessage("INFO", "MINING", 
        "Mining completed. Found: " + std::to_string(g_found.load()) + 
        ", Credited hashes: " + std::to_string(finalHashes) +
        ", Time: " + std::to_string(elapsed) + "s" +
        ", Rate: " + std::to_string(finalHashRate) + " H/s"));
    
    printModernGPUInterface(candidate.height, g_devices, finalHashRate, elapsed, finalHashes,
                          1, 1, false, minerAddr, blockCount, g_found.load());
    
    // MINER-TIME-01A hard freshness gate. Even if an OpenCL driver/device
    // takes unexpectedly long to drain queued work, a solution from a
    // candidate held for more than 30 seconds is discarded instead of being
    // submitted with an old template timestamp.
    constexpr double kMaxGpuCandidateHoldSeconds = 30.0;
    if (g_found.load() && elapsed > kMaxGpuCandidateHoldSeconds) {
        Logger::log(formatLogMessage(
            "WARNING", "MINER-TIME-01A",
            "GPU solution discarded: candidate was held for " +
            std::to_string(elapsed) +
            "s (>30s); requesting fresh getblocktemplate"));
        std::cout << C_WARNING
                  << "[AI MINING] " << SYMBOL_WARNING
                  << " Stale GPU solution discarded after "
                  << std::fixed << std::setprecision(1) << elapsed
                  << "s; refreshing template"
                  << C_RESET << "\n";
        g_found.store(false);
        return false;
    }

    if (g_found.load()) {
        std::string headerLine = std::string(65, '=');
        std::cout << "\n" << C_FIRE << C_BOLD << BG_SUCCESS;
        std::cout << "╭─" << headerLine << "─╮\n";
        std::cout << "│ " << SYMBOL_BOOM << " AI QUANTUM BLOCK DISCOVERY! " << SYMBOL_BOOM << " Block #" << candidate.height << std::string(15, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_CROWN << " Final hash rate: " << formatHashRate(finalHashRate) << std::string(30, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_LIGHTNING << " Mining time: " << formatDuration(elapsed) << std::string(35, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_TARGET << " Victory nonce: " << C_GOLD << g_foundNonce.load() << std::string(30, ' ') << C_FIRE << "│\n";
        std::cout << "│ " << SYMBOL_GEM << " Credited hash work: " << formatHashRate(finalHashes) << std::string(22, ' ') << "│\n";
        std::cout << "│ " << SYMBOL_BRAIN << " AI Efficiency: MAXIMUM OPTIMIZATION ACHIEVED!" << std::string(10, ' ') << "│\n";
        std::cout << "╰─" << headerLine << "─╯" << C_RESET << "\n";
        
        candidate.header.nonce = static_cast<uint32_t>(g_foundNonce.load());
        candidate.blockHash = candidate.computeHash();
        
	Logger::log(formatLogMessage("SUCCESS", "MINING", 
    	    "Block " + std::to_string(candidate.height) + " mined successfully! " +
    	    "Block hash: " + candidate.blockHash));
        
        blockCount++;
        return true;
    }
    
    return false;
}

// Build coinbase transaction (enhanced with emojis)
static Transaction buildCoinbaseTx(const std::string& minerAddr, uint64_t rewardSat, int32_t blockHeight, int extraNonce) {
    Logger::log(formatLogMessage("DEBUG", "COINBASE", 
        "Building coinbase for block " + std::to_string(blockHeight) + 
        ", reward: " + std::to_string(rewardSat) + " TRU atoms"));
    
    Transaction coinbase(true);
    std::ostringstream oss;
    oss << "TRU:" << blockHeight << "|AI-GPU🧠:" << extraNonce;  // Enhanced with AI emoji
    std::string extraNonceStr = oss.str();
    coinbase.vin.emplace_back("COINBASE", 0, std::vector<unsigned char>(extraNonceStr.begin(), extraNonceStr.end()), std::vector<unsigned char>());
    TxOut out;
    out.amount = rewardSat;
    out.scriptPubKey = createP2PKHScriptHexFromAddress(minerAddr);
    coinbase.vout.push_back(out);
    coinbase.computeTxId();
    
    Logger::log(formatLogMessage("DEBUG", "COINBASE", "Coinbase TX ID: " + coinbase.txid));
    return coinbase;
}

static void addTemplateTransactions(Block& candidate, const nlohmann::json& tpl) {
    if (!tpl.contains("transactions") || !tpl["transactions"].is_array()) {
        Logger::log(formatLogMessage("DEBUG", "TEMPLATE", "No transactions in template"));
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
            skipped++;
            Logger::log(formatLogMessage("WARNING", "TEMPLATE", 
                "Failed to parse transaction: " + std::string(e.what())));
        }
    }
    
    Logger::log(formatLogMessage("INFO", "TEMPLATE", 
        "Added " + std::to_string(txCount) + " transactions, skipped " + std::to_string(skipped)));
}

static Block buildCandidateBlockFromTemplate(const nlohmann::json& tpl, const std::string& minerAddr, int extraNonce) {
    Logger::log(formatLogMessage("INFO", "TEMPLATE", "Building candidate block from template"));
    
    int32_t height = tpl.value("height", 1);
    int32_t version = tpl.value("version", height);
    std::string prevH = tpl.value("previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000");
    std::string bitsHex = tpl.value("bits", "1d00ffff");
    uint32_t bitsVal = std::stoul(bitsHex, nullptr, 16);
    uint32_t curTime = tpl.value("curtime", (uint32_t)std::time(nullptr));
    uint64_t rewardSat = tpl.value("coinbasevalue", 50ULL * 100000000ULL);
    
    Logger::log(formatLogMessage("DEBUG", "TEMPLATE", 
        "Height: " + std::to_string(height) + 
        ", Version: " + std::to_string(version) + 
        ", Bits: " + bitsHex + 
        ", Reward: " + std::to_string(rewardSat)));
    
    Block candidate(height, prevH, curTime, bitsVal);
    candidate.height = height;
    
    Transaction coinbaseTx = buildCoinbaseTx(minerAddr, rewardSat, height, extraNonce);
    candidate.transactions.push_back(coinbaseTx);
    addTemplateTransactions(candidate, tpl);
    candidate.header.merkleRoot = computeMerkleRoot(candidate.transactions);
    
    Logger::log(formatLogMessage("INFO", "TEMPLATE", 
        "Built candidate block with " + std::to_string(candidate.transactions.size()) + 
        " transactions, merkle root: " + candidate.header.merkleRoot));
    
    return candidate;
}

// ENHANCED: Intelligent mining loop with improved keepalive and hash reporting! 🎯
static void startGPUMiningLoop(const std::string& nodeIP, int nodePort, const std::string& minerAddr) {
    Logger::log(formatLogMessage("INFO", "MAIN", 
        "Starting GPU mining loop - Node: " + nodeIP + ":" + std::to_string(nodePort) + 
        ", Miner: " + minerAddr));

    g_minerStartTime = std::chrono::steady_clock::now();
    g_sessionHashes.store(0, std::memory_order_relaxed);
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(20, 0);
    int extraNonce = 0;

    // MINER-TIME-01B: one full uint32 GPU sweep per fresh getblocktemplate.
    // Same-tip refreshes advance extraNonce so each new template searches a
    // different coinbase / merkle-root / header space.
    int32_t lastTemplateHeight = -1;
    std::string lastTemplatePrevHash;

    int retryCount = 0;
    uint64_t blockCount = 0;
    const int maxBackoffSeconds = 30;
    const uint64_t maxNonce = 0xFFFFFFFFULL;
    auto retryBackoffSeconds = [&](int failures) {
        const int shift = std::min(std::max(failures - 1, 0), 3);
        return std::min(maxBackoffSeconds, 5 * (1 << shift));
    };

    // MINER-RESILIENCE-01: node/RPC outages no longer terminate a healthy GPU
    // miner process. Re-register until the operator explicitly shuts it down.
    while (!g_shutdown.load() && !registerMinerWithRetry(cli, minerAddr, "AI-GPU")) {
        Logger::log(formatLogMessage("WARNING", "MAIN", "Registration unavailable; retrying in 15 seconds"));
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
    if (g_shutdown.load()) return;

    // INTELLIGENT: Enhanced keepalive thread with proper hash tracking! 🔧
    std::thread keepaliveThread([&]() {
        Logger::log(formatLogMessage("INFO", "KEEPALIVE", "Starting keepalive thread"));
        
        auto lastReport = std::chrono::steady_clock::now();
        uint64_t lastTotalHashes = 0;
        uint64_t reportCounter = 0;
        
        std::cout << C_ELECTRIC << C_BOLD << "╭─ " << SYMBOL_BRAIN << " AI KEEPALIVE THREAD STARTED " << SYMBOL_BRAIN << " ─╮" << C_RESET << "\n";
        std::cout << C_INFO << "│ " << SYMBOL_TIME << " Reporting interval: 10 seconds" << std::string(25, ' ') << "│" << C_RESET << "\n";
        std::cout << C_INFO << "│ " << SYMBOL_TARGET << " AI Target miner: " << C_GOLD << minerAddr.substr(0, 22) << std::string(15, ' ') << "│" << C_RESET << "\n";
        
        std::string dashLine = std::string(60, '-');
        std::cout << C_ELECTRIC << "╰─" << dashLine << "─╯" << C_RESET << "\n\n";
        
        while (!g_shutdown.load()) {
            try {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration<double>(now - lastReport).count();
                
                if (elapsed >= 10.0) {
                    reportCounter++;
                    uint64_t currentHashes = g_sessionHashes.load(std::memory_order_relaxed);
                    uint64_t hashesInInterval = 0;
                    if (currentHashes >= lastTotalHashes) {
                        hashesInInterval = currentHashes - lastTotalHashes;
                    } else {
                        Logger::log(formatLogMessage("ERROR", "KEEPALIVE",
                            "Monotonic session hash counter regressed; reporting zero for this interval"));
                    }

                    double reportedRate = hashesInInterval / elapsed;
                    
                    if (elapsed > 0.001) {
                        nlohmann::json updateReq;
                        updateReq["jsonrpc"] = "2.0";
                        updateReq["id"] = 1;
                        updateReq["method"] = "reportmineractivity";
                        updateReq["params"] = {
                            {"minerAddress", minerAddr}, 
                            {"hashesTried", hashesInInterval}, 
                            {"timeTaken", elapsed}
                        };
                        
                        Logger::log(formatLogMessage("DEBUG", "KEEPALIVE", 
                            "Reporting " + std::to_string(hashesInInterval) +
                            " credited hashes in " + std::to_string(elapsed) + "s"));
                        
                        auto res = cli.Post("/rpc", updateReq.dump(), "application/json");
                        
                        if (res && res->status == 200) {
                            lastTotalHashes = currentHashes;
                            lastReport = now;
                            
                            Logger::log(formatLogMessage("SUCCESS", "KEEPALIVE", 
                                "Report #" + std::to_string(reportCounter) + " sent successfully"));
                            std::cout << C_SUCCESS << C_BOLD << "[AI KEEPALIVE] " << SYMBOL_SUCCESS << " AI Report #" << reportCounter 
                                      << " sent successfully!" << C_RESET << "\n";
                            std::cout << C_SUCCESS << "  " << SYMBOL_LIGHTNING << " Reported: " << hashesInInterval 
                                      << " hashes in " << std::fixed << std::setprecision(1) << elapsed 
                                      << "s (" << formatHashRate(reportedRate) << ")" << C_RESET << "\n\n";
                        } else {
                            Logger::log(formatLogMessage("WARNING", "KEEPALIVE", 
                                "Report failed, status: " + (res ? std::to_string(res->status) : "no response")));
                            std::cout << C_ERROR << "[AI KEEPALIVE] " << SYMBOL_ERROR << " Report failed! Status: " 
                                      << (res ? std::to_string(res->status) : "No Response") << C_RESET << "\n";
                            lastTotalHashes = currentHashes;
                            lastReport = now;
                        }
                    } else {
                        lastReport = now;
                    }
                }
            } catch (const std::exception& e) {
                Logger::log(formatLogMessage("ERROR", "KEEPALIVE", "Exception: " + std::string(e.what())));
                std::cout << C_ERROR << "[AI KEEPALIVE] " << SYMBOL_ERROR << " Exception: " << e.what() << C_RESET << "\n";
                auto now = std::chrono::steady_clock::now();
                lastTotalHashes = g_sessionHashes.load(std::memory_order_relaxed);
                lastReport = now;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        
        // Enhanced shutdown sequence
        try {
            nlohmann::json unregReq;
            unregReq["jsonrpc"] = "2.0";
            unregReq["id"] = 1;
            unregReq["method"] = "unregisterminer";
            unregReq["params"] = {{"minerAddress", minerAddr}};
            auto res = cli.Post("/rpc", unregReq.dump(), "application/json");
            
            Logger::log(formatLogMessage("INFO", "KEEPALIVE", "AI-GPU Miner unregistered gracefully"));
            std::cout << C_SUCCESS << "[AI KEEPALIVE] " << SYMBOL_SUCCESS << " AI-GPU Miner unregistered gracefully" << C_RESET << "\n";
        } catch (const std::exception& e) {
            Logger::log(formatLogMessage("ERROR", "KEEPALIVE", "Failed to unregister: " + std::string(e.what())));
        }
    });

    // Enhanced main mining loop
    std::string headerLine = std::string(65, '-');
    std::cout << C_FIRE << C_BOLD << "\n╭─ " << SYMBOL_ROCKET << " STARTING AI QUANTUM MINING OPERATIONS " << SYMBOL_ROCKET << " ─╮" << C_RESET << "\n";
    std::cout << C_PRIMARY << "│ " << SYMBOL_TARGET << " Node: " << C_GOLD << nodeIP << ":" << nodePort << std::string(30, ' ') << "│" << C_RESET << "\n";
    std::cout << C_PRIMARY << "│ " << SYMBOL_DIAMOND << " AI Miner: " << C_ELECTRIC << minerAddr.substr(0, 26) << std::string(15, ' ') << "│" << C_RESET << "\n";
    std::cout << C_FIRE << "╰─" << headerLine << "─╯" << C_RESET << "\n\n";

    while (!g_shutdown.load()) {
        try {
            // Get block template
            Logger::log(formatLogMessage("DEBUG", "MAIN", "Requesting block template"));
            
            nlohmann::json tplReq;
            tplReq["jsonrpc"] = "2.0";
            tplReq["id"] = 2;
            tplReq["method"] = "getblocktemplate";
            tplReq["params"] = nlohmann::json::object();
            auto tplRes = cli.Post("/rpc", tplReq.dump(), "application/json");

            if (!tplRes || tplRes->status != 200) {
                Logger::log(formatLogMessage("ERROR", "MAIN", 
                    "Failed to get block template, status: " + (tplRes ? std::to_string(tplRes->status) : "no response")));
                std::cout << C_WARNING << "[AI MINING] " << SYMBOL_WARNING << " Failed to get block template" << C_RESET << "\n";
                retryCount = std::min(retryCount + 1, 1000);
                const int backoff = retryBackoffSeconds(retryCount);
                Logger::log(formatLogMessage("WARNING", "MAIN",
                    "MINER-RESILIENCE-01 - template RPC unavailable; keeping miner alive, retrying in " +
                    std::to_string(backoff) + " seconds"));
                std::this_thread::sleep_for(std::chrono::seconds(backoff));
                continue;
            }

            retryCount = 0; // Reset retry count on success
            
            nlohmann::json tplJson =
                nlohmann::json::parse(tplRes->body).value(
                    "result",
                    nlohmann::json()
                );

            const int32_t templateHeight = tplJson.value("height", 1);
            const std::string templatePrevHash = tplJson.value(
                "previousblockhash",
                "0000000000000000000000000000000000000000000000000000000000000000"
            );

            if (templateHeight != lastTemplateHeight ||
                templatePrevHash != lastTemplatePrevHash) {
                extraNonce = 0;
                lastTemplateHeight = templateHeight;
                lastTemplatePrevHash = templatePrevHash;
                Logger::log(formatLogMessage(
                    "INFO", "MINER-TIME-01A",
                    "Fresh GPU tip/template: height=" +
                    std::to_string(templateHeight) +
                    ", resetting extraNonce=0"));
            } else {
                extraNonce = (extraNonce >= 1000) ? 0 : (extraNonce + 1);
                Logger::log(formatLogMessage(
                    "INFO", "MINER-TIME-01A",
                    "Same GPU tip; fresh template acquired; advancing extraNonce=" +
                    std::to_string(extraNonce)));
            }

            Block candidate =
                buildCandidateBlockFromTemplate(
                    tplJson,
                    minerAddr,
                    extraNonce
                );

            // Exactly one full uint32 GPU sweep per newly fetched GBT. A
            // miss returns immediately to this outer loop, fetches a fresh
            // curtime, and advances extraNonce if the tip is unchanged.
            bool success =
                mineBlockGPU_21E8_AutoTuned(
                    candidate,
                    maxNonce,
                    cli,
                    minerAddr,
                    extraNonce,
                    blockCount
                );

            if (success) {
                Logger::log(formatLogMessage("SUCCESS", "MAIN", "Block found! Submitting to network..."));
                std::cout << C_FIRE << C_BOLD << BG_SUCCESS << "[AI MINING] " << SYMBOL_CROWN << " AI QUANTUM BLOCK DISCOVERED! Submitting..." << C_RESET << "\n";
                
                // Submit block
                nlohmann::json sbReq;
                sbReq["jsonrpc"] = "2.0";
                sbReq["id"] = 3;
                sbReq["method"] = "submitblock";
                nlohmann::json paramsObj;
                paramsObj["blockHex"] = candidate.serialize();
                sbReq["params"] = paramsObj;
                auto sbRes = cli.Post("/rpc", sbReq.dump(), "application/json");

                // HTTP 200 does not mean the node accepted the block.
                // TRU returns {"result":{"status":"accepted"|"rejected"|"duplicate",...}}.
                // See the matching change in my_miner.cpp.
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
                    Logger::log(formatLogMessage("SUCCESS", "MAIN", 
                        "Block accepted by node. Total blocks: " + std::to_string(blockCount)));
                    std::cout << C_SUCCESS << C_BOLD << "[AI MINING] " << SYMBOL_TROPHY << " AI BLOCK ACCEPTED! 🧠🎉" << C_RESET << "\n";
                    extraNonce = 0;
                } else {
                    Logger::log(formatLogMessage("ERROR", "MAIN", 
                        "Block REJECTED by node: " + rejectReason));
                    if (sbRes) {
                        Logger::log(formatLogMessage("ERROR", "MAIN",
                            "Rejected block raw response: " + sbRes->body));
                    }
                    std::cout << C_ERROR << "[AI MINING] " << SYMBOL_ERROR << " Block rejected: "
                              << rejectReason << C_RESET << "\n";
                }
            }

            // MINER-TIME-01B: template identity above owns extraNonce
            // reset/advance. Do not impose a fixed post-sweep idle delay;
            // immediately request the next fresh getblocktemplate.
            
        } catch (const std::exception &e) {
            Logger::log(formatLogMessage("ERROR", "MAIN", "Exception in mining loop: " + std::string(e.what())));
            std::cout << C_ERROR << "[AI MINING] " << SYMBOL_ERROR << " Error: " << e.what() << C_RESET << "\n";
            retryCount = std::min(retryCount + 1, 1000);
            const int backoff = retryBackoffSeconds(retryCount);
            Logger::log(formatLogMessage("WARNING", "MAIN",
                "MINER-RESILIENCE-01 - transient exception; keeping miner alive, retrying in " +
                std::to_string(backoff) + " seconds"));
            std::this_thread::sleep_for(std::chrono::seconds(backoff));
        }
    }
    
    Logger::log(formatLogMessage("INFO", "MAIN", "Mining loop ended, waiting for keepalive thread"));
    keepaliveThread.join();
}

// Enhanced cleanup with visual feedback
void cleanupGPU() {
    Logger::log(formatLogMessage("INFO", "CLEANUP", "Starting GPU cleanup sequence"));
    
    std::string dashLine = std::string(65, '-');
    std::cout << C_WARNING << C_BOLD << "\n╭─ " << SYMBOL_SPARKLE << " INTELLIGENT GPU CLEANUP SEQUENCE " << SYMBOL_SPARKLE << " ─╮" << C_RESET << "\n";
    
    for (size_t i = 0; i < g_devices.size(); i++) {
        if (g_devices[i]) {
            Logger::log(formatLogMessage("INFO", "CLEANUP", 
                "Cleaning up GPU-" + std::to_string(i+1) + " [" + g_devices[i]->performanceClass + "]: " + 
                g_devices[i]->deviceName));
            
            std::cout << C_INFO << "│ " << g_devices[i]->deviceEmoji << " Cleaning up GPU-" << (i+1) << " [" 
                      << g_devices[i]->performanceClass << "]: " 
                      << g_devices[i]->deviceName.substr(0, 20) << std::string(10, ' ') << "│" << C_RESET << "\n";
            g_devices[i]->cleanup();
        }
    }
    g_devices.clear();
    
    Logger::log(formatLogMessage("SUCCESS", "CLEANUP", "All GPU resources released"));
    std::cout << C_SUCCESS << "│ " << SYMBOL_SUCCESS << " All AI-optimized GPU resources released" << std::string(15, ' ') << "│" << C_RESET << "\n";
    std::cout << C_WARNING << "╰─" << dashLine << "─╯" << C_RESET << "\n";
}

// GPU miner entry point.
int main(int argc, char* argv[]) {
    // Setup signal handlers first
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Parse command line arguments with cxxopts
    cxxopts::Options opts("tru_gpu_miner", "🔥 TRU Blockchain GPU Miner v5.0 - AI-Powered Professional Mining Suite 2025");
    opts.add_options()
        ("node-ip", "Node IP address", cxxopts::value<std::string>()->default_value("127.0.0.1"))
        ("node-port", "Node port", cxxopts::value<int>()->default_value(std::to_string(tru_network::MAINNET_RPC_PORT)))
        ("mineraddr", "Miner address", cxxopts::value<std::string>()->default_value("1TruAIGPUQuantumMinerAddr"))
        ("log-file", "Log file path", cxxopts::value<std::string>()->default_value("gpu_miner.log"))
        ("quiet", "Disable visual UI (log only)", cxxopts::value<bool>()->default_value("false"))
        ("help", "Show help");
    
    auto args = opts.parse(argc, argv);
    if (args.count("help")) {
        std::cout << opts.help() << "\n";
        return 0;
    }
    
    std::string nodeIP = args["node-ip"].as<std::string>();
    int nodePort = args["node-port"].as<int>();
    std::string minerAddr = args["mineraddr"].as<std::string>();
    std::string logFile = args["log-file"].as<std::string>();
    bool quiet = args["quiet"].as<bool>();
    
    // Initialize logger
    try {
        Logger::init(logFile);
        Logger::log(formatLogMessage("INFO", "MAIN", "TRU GPU Miner v5.0 starting..."));
        Logger::log(formatLogMessage("INFO", "MAIN", 
            "Configuration: Node=" + nodeIP + ":" + std::to_string(nodePort) + 
            ", Miner=" + minerAddr + ", LogFile=" + logFile));
    } catch (const std::exception& e) {
        std::cerr << C_ERROR << "❌ Failed to initialize logger: " << e.what() << C_RESET << "\n";
        return 1;
    }
    
    // Validate arguments
    if (nodePort < 1 || nodePort > 65535) {
        Logger::log(formatLogMessage("ERROR", "MAIN", "Invalid node port: " + std::to_string(nodePort)));
        std::cerr << C_ERROR << "❌ Invalid node port: " << nodePort << C_RESET << "\n";
        Logger::shutdown();
        return 1;
    }
    
    if (minerAddr.length() < 26 || minerAddr.length() > 35) {
        Logger::log(formatLogMessage("ERROR", "MAIN", "Invalid miner address: " + minerAddr));
        std::cerr << C_ERROR << "❌ Invalid miner address: " << minerAddr << C_RESET << "\n";
        Logger::shutdown();
        return 1;
    }
    
    // Startup display.
    if (!quiet) {
        std::cout << "\033[2J\033[1;1H"; // Clear screen
        std::cout << C_BLOCKCHAIN << C_BOLD;
        std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║ " << C_FIRE << "🧠💎⚡ TRU BLOCKCHAIN AI-GPU MINER v5.0 INTELLIGENT ⚡💎🧠" << C_BLOCKCHAIN << " ║\n";
        std::cout << "║ " << C_ELECTRIC << "        ✨🚀 AI-Powered Auto-Tuning Mining Experience 🚀✨        " << C_BLOCKCHAIN << " ║\n";
        std::cout << "║ " << C_GOLD << "                  ⛓️ Powered by Quantum AI Energy ⛓️                 " << C_BLOCKCHAIN << " ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝" << C_RESET << "\n\n";
        
        std::cout << C_PRIMARY << C_BOLD << "🧠 INITIALIZING AI QUANTUM MINING SYSTEMS..." << C_RESET << "\n\n";
    }
    
    Logger::log(formatLogMessage("INFO", "MAIN", "Initializing GPU devices with AI auto-tuning"));
    
    try {
        // Initialize GPU devices with intelligent auto-tuning
        if (!initializeGPUDevicesWithAutoTuning()) {
            Logger::log(formatLogMessage("ERROR", "MAIN", "No GPU devices initialized"));
            std::cout << C_ERROR << C_BOLD << "\n" << SYMBOL_ERROR << " CRITICAL FAILURE: No AI-optimized GPU devices initialized!" << C_RESET << "\n";
            Logger::shutdown();
            return 1;
        }
        
        Logger::log(formatLogMessage("SUCCESS", "MAIN", 
            "Initialized " + std::to_string(g_devices.size()) + " GPU devices successfully"));
        
        if (!quiet) {
            std::cout << C_SUCCESS << C_BOLD << "\n" << SYMBOL_ROCKET << " AI QUANTUM ARSENAL READY! Starting intelligent mining operations..." << C_RESET << "\n\n";
        }
        
        // Start the main mining loop
        startGPUMiningLoop(nodeIP, nodePort, minerAddr);
        
    } catch (const std::exception& e) {
        Logger::log(formatLogMessage("ERROR", "MAIN", "Fatal error: " + std::string(e.what())));
        std::cout << C_ERROR << C_BOLD << "\n" << SYMBOL_ERROR << " FATAL AI QUANTUM ERROR: " << e.what() << C_RESET << "\n";
    }
    
    // Cleanup GPU resources
    cleanupGPU();
    
    // Shutdown display.
    if (!quiet) {
        std::cout << "\n" << C_BLOCKCHAIN << C_BOLD;
        std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║ " << C_FIRE << "          🧠💎 TRU AI QUANTUM MINER SHUTDOWN COMPLETE 💎🧠          " << C_BLOCKCHAIN << " ║\n";
        std::cout << "║ " << C_ELECTRIC << "                ✨ Thank you for AI mining TRU! ✨                " << C_BLOCKCHAIN << " ║\n";
        std::cout << "║ " << C_GOLD << "               ⛓️ May the blockchain be with you! ⛓️               " << C_BLOCKCHAIN << " ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝" << C_RESET << "\n";
    }
    
    // Shutdown logger
    Logger::log(formatLogMessage("INFO", "MAIN", "TRU GPU Miner shutdown complete"));
    Logger::shutdown();
    
    return 0;
}
