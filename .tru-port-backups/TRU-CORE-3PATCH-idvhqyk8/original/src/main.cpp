#ifdef BUILD_WITH_QT
#include <QtWidgets/QApplication>
#include <QInputDialog>
#include <QLineEdit>
#include <QTimer>
#include "walletgui.h"
#endif
#include "smart_contract.h"
#include "oobalooga_ai_.h"
#include "blockchain.h"
#include "p2p.h"
#include "wallet.h"
#include "tx.h"
#include "mempool.h"
#include "utils.h"
#include "rpc_server.h"
#include "rpc_utils.h"  // RPC transport authentication
#include "ai_oracle_service.h"
#include "ai_providers.h"          // TOKEN-AI-03A wallet evolution provider factories
#include "token_evolution.h"       // TOKEN-AI-03A wallet evolution engine
#include "globals.h"
#include <fmt/core.h>
#include <cxxopts.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <cctype>
#include <cstdlib>  
#include <ctime>    
#include "gpu_miner.h"

// vendor-neutral GPU discovery uses the same
// OpenCL runtime family as the TRU GPU miner. CPU-only builds remain valid.
#ifdef USE_OPENCL
#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 200
#endif
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#endif
#include <fmt/format.h>
#include <iomanip>
#include <unordered_map>
#include "tokens.h"
#include "token_burn_v1.h"  // TOKEN-BURN-01 CLI retirement UX
#include <iomanip>
#include <unordered_map>
#include "stb_image_write.h"
#include "wallet_cli.h"
#include "address_helpers.h"
#include "contract_storage.h"
#include "config_reader.h"
#include "logging.h"
#include "utils.h"
#include <wally_core.h>
#include <wally_address.h> 
#include <wally_crypto.h> 
#include "main.h"
#include <csignal>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <poll.h>
#include <sys/wait.h>   // waitpid for spawned miner processes
#include <fcntl.h>   // open() for miner log redirect
#include <future>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include "script_interpreter.h"
#include "contract_call_policy.h"  // Stateful K/V V1 creation
#include "contract_state_lineage.h"  // stable root/live/owner call resolution
#include "contract_state_runtime.h"  // shared confirmed-state/Voting runtime helpers
#include <curl/curl.h>
#include <fstream>
#include <stdexcept>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <qrencode.h>
#include <limits>
#include "globals.h"
#include <cmath>
#include <nlohmann/json.hpp>
#include "tru_network_params.h"
#include "tru_amount.h"
#include "network_identity.h"  // MULTINODE-01D local-endpoint self-peer guard

// -------------------------------------------------------------------
// OPENCL GPU DISCOVERY
// -------------------------------------------------------------------
// This is intentionally read-only hardware discovery. It enumerates the same
// vendor-neutral OpenCL GPU class used by TRU's GPU mining backends, but it
// does not create contexts, compile kernels, or start mining.
struct TruCliGpuDeviceInfo {
    std::string platform;
    std::string vendor;
    std::string name;
    std::string openclVersion;
    std::string driverVersion;
    std::uint32_t computeUnits{0};
    std::uint64_t globalMemoryBytes{0};
};

struct TruCliGpuInventory {
    bool openclEnabled{false};
    std::string status;
    std::vector<TruCliGpuDeviceInfo> devices;
};

#ifdef USE_OPENCL
static std::string truOpenCLPlatformString(cl_platform_id platform,
                                           cl_platform_info field) {
    size_t size = 0;
    if (clGetPlatformInfo(platform, field, 0, nullptr, &size) != CL_SUCCESS ||
        size == 0) {
        return "unknown";
    }
    std::vector<char> buffer(size, '\0');
    if (clGetPlatformInfo(platform, field, size, buffer.data(), nullptr) != CL_SUCCESS) {
        return "unknown";
    }
    return std::string(buffer.data());
}

static std::string truOpenCLDeviceString(cl_device_id device,
                                         cl_device_info field) {
    size_t size = 0;
    if (clGetDeviceInfo(device, field, 0, nullptr, &size) != CL_SUCCESS ||
        size == 0) {
        return "unknown";
    }
    std::vector<char> buffer(size, '\0');
    if (clGetDeviceInfo(device, field, size, buffer.data(), nullptr) != CL_SUCCESS) {
        return "unknown";
    }
    return std::string(buffer.data());
}
#endif

static TruCliGpuInventory detectTruOpenCLGpus() {
    TruCliGpuInventory inventory;
#ifdef USE_OPENCL
    inventory.openclEnabled = true;

    cl_uint platformCount = 0;
    const cl_int platformErr = clGetPlatformIDs(0, nullptr, &platformCount);
    if (platformErr != CL_SUCCESS) {
        inventory.status = "OpenCL platform query failed (error " +
                           std::to_string(platformErr) + ")";
        return inventory;
    }
    if (platformCount == 0) {
        inventory.status = "No OpenCL platforms detected";
        return inventory;
    }

    std::vector<cl_platform_id> platforms(platformCount);
    if (clGetPlatformIDs(platformCount, platforms.data(), nullptr) != CL_SUCCESS) {
        inventory.status = "OpenCL platform enumeration failed";
        return inventory;
    }

    for (cl_platform_id platform : platforms) {
        cl_uint deviceCount = 0;
        const cl_int countErr =
            clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &deviceCount);
        if (countErr == CL_DEVICE_NOT_FOUND || deviceCount == 0) {
            continue;
        }
        if (countErr != CL_SUCCESS) {
            continue;
        }

        std::vector<cl_device_id> devices(deviceCount);
        if (clGetDeviceIDs(platform,
                           CL_DEVICE_TYPE_GPU,
                           deviceCount,
                           devices.data(),
                           nullptr) != CL_SUCCESS) {
            continue;
        }

        const std::string platformName =
            truOpenCLPlatformString(platform, CL_PLATFORM_NAME);

        for (cl_device_id device : devices) {
            TruCliGpuDeviceInfo info;
            info.platform = platformName;
            info.vendor = truOpenCLDeviceString(device, CL_DEVICE_VENDOR);
            info.name = truOpenCLDeviceString(device, CL_DEVICE_NAME);
            info.openclVersion = truOpenCLDeviceString(device, CL_DEVICE_VERSION);
            info.driverVersion = truOpenCLDeviceString(device, CL_DRIVER_VERSION);

            cl_uint computeUnits = 0;
            if (clGetDeviceInfo(device,
                                CL_DEVICE_MAX_COMPUTE_UNITS,
                                sizeof(computeUnits),
                                &computeUnits,
                                nullptr) == CL_SUCCESS) {
                info.computeUnits = static_cast<std::uint32_t>(computeUnits);
            }

            cl_ulong globalMemory = 0;
            if (clGetDeviceInfo(device,
                                CL_DEVICE_GLOBAL_MEM_SIZE,
                                sizeof(globalMemory),
                                &globalMemory,
                                nullptr) == CL_SUCCESS) {
                info.globalMemoryBytes = static_cast<std::uint64_t>(globalMemory);
            }

            inventory.devices.push_back(info);
        }
    }

    if (inventory.devices.empty()) {
        inventory.status = "No OpenCL GPU devices detected";
    } else {
        inventory.status = "OpenCL GPU discovery successful";
    }
#else
    inventory.openclEnabled = false;
    inventory.status = "OpenCL support disabled in this build";
#endif
    return inventory;
}

static std::string formatTruGpuInventory(const TruCliGpuInventory& inventory) {
    std::ostringstream out;
    out << "Backend: " << (inventory.openclEnabled ? "OpenCL" : "disabled") << "\n";
    out << "Detected OpenCL GPUs: " << inventory.devices.size() << "\n";

    for (size_t i = 0; i < inventory.devices.size(); ++i) {
        const auto& gpu = inventory.devices[i];
        const double gib = static_cast<double>(gpu.globalMemoryBytes) /
                           (1024.0 * 1024.0 * 1024.0);
        out << "\nGPU " << (i + 1) << ": " << gpu.name << "\n"
            << "       " << gpu.vendor
            << " | " << std::fixed << std::setprecision(1) << gib << " GiB"
            << " | " << gpu.computeUnits << " CUs"
            << " | " << gpu.platform << "\n";
    }

    if (!inventory.devices.empty()) {
        out << "\nMining Mode: ALL compatible detected GPUs";
    } else {
        out << "\nGPU Detection: " << inventory.status;
    }
    return out.str();
}

// -------------------------------------------------------------------
//              HELPERS FOR AI TOKEN
// -------------------------------------------------------------------
using nlohmann::json;
// -------------------------------------------------------------------
//              HELPERS FOR DISPLAY
// -------------------------------------------------------------------
// explicit terminal ownership.
//
// Normal deck mode:
//   rows 1..15  = persistent TRU / miner header
//   row 16      = one-shot status notice
//   rows 17+    = Command Deck
//
// Output Focus:
//   rows 1..15  = persistent TRU / miner header
//   rows 16+    = command result
//   mid-screen  = nested INPUT REQUIRED question card
//   bottom rows = heartbeat + top-level command prompt
//
// The spinner is intentionally preserved as TRU's live heartbeat. It paints
// only while the top-level command prompt is active; nested data-entry prompts
// pause it automatically.
static std::atomic<bool>         g_cliContentFocus{false};
static std::atomic<bool>         g_cliMenuPromptActive{false};
static std::atomic<unsigned int> g_cliInputDepth{0};

// -------------------------------------------------------------------
// RESULT / APPEND / PROMPT OWNERSHIP
// -------------------------------------------------------------------
// `displayOutput()` used to clear row 16 through the bottom on *every* call.
// That made multi-line command reports erase themselves one line at a time.
// 30B4 keeps a command-scoped result buffer: the first result in a new command
// replaces the previous command, subsequent results append, and rendering is
// clipped to the owned content rows so heartbeat/prompt rows are never erased.
struct TruCliResultLine {
    std::string text;
    int color{96};
};

static std::mutex                    g_cliResultStateMutex;
static std::vector<TruCliResultLine> g_cliResultLines;
static bool                          g_cliCommandOutputStarted{false};

// background sync owns a dedicated status lane.
// Sync state is stored independently of result text so it can remain visible
// without stealing the active input cursor or erasing command output.
static std::mutex g_cliSyncStatusMutex;
static std::string g_cliSyncStatus{"Starting blockchain synchronization..."};

// fixed three-line footer stack.
// The command entry is deliberately ABOVE both asynchronous status lanes so
// neither the heartbeat nor background sync can ever replace typed commands.
static int truMenuPromptRow(int rows) {
    return std::max(3, rows - 4);
}

static int truHeartbeatRow(int rows) {
    return std::max(2, truMenuPromptRow(rows) + 1);
}

static int truTopLevelSyncRow(int rows) {
    const int candidate = truHeartbeatRow(rows) + 1;
    return candidate < rows ? candidate : -1;
}

static int truResultFirstRow() {
    return 16;
}

// nested questions must remain in the user's visual
// focus instead of sharing the bottom command/sync lanes. The prompt is placed
// midway between the result origin and the heartbeat, with a dedicated banner
// row immediately above it.
static int truInputFocusPromptRow(int rows) {
    const int first = truResultFirstRow();
    const int last = truMenuPromptRow(rows) - 2;
    if (last <= first) return first;
    return first + ((last - first) / 2);
}

static int truInputFocusBannerRow(int rows) {
    return std::max(truResultFirstRow(), truInputFocusPromptRow(rows) - 1);
}

// Put sync immediately below the active nested question. If a short terminal
// has no safe row between the question and heartbeat, omit sync rather than
// overwrite user input.
static int truInputFocusSyncRow(int rows) {
    const int candidate = truInputFocusPromptRow(rows) + 2;
    const int lastSafe = truMenuPromptRow(rows) - 2;
    return candidate <= lastSafe ? candidate : -1;
}

static int truReceiptResultLastRow(int rows) {
    return std::max(
        truResultFirstRow(),
        truInputFocusBannerRow(rows) - 1);
}

static int truResultLastRow(int rows) {
    return std::max(truResultFirstRow(), truMenuPromptRow(rows) - 1);
}

static void resetCliCommandOutputGeneration() {
    std::lock_guard<std::mutex> lock(g_cliResultStateMutex);
    g_cliCommandOutputStarted = false;
}

static void clearCliResultState() {
    std::lock_guard<std::mutex> lock(g_cliResultStateMutex);
    g_cliResultLines.clear();
    g_cliCommandOutputStarted = false;
}

static void appendCliResultMessageLocked(const std::string& message, int color) {
    if (message.empty()) {
        g_cliResultLines.push_back({"", color});
        return;
    }

    std::size_t start = 0;
    while (start <= message.size()) {
        const std::size_t nl = message.find('\n', start);
        if (nl == std::string::npos) {
            g_cliResultLines.push_back({message.substr(start), color});
            break;
        }
        g_cliResultLines.push_back({message.substr(start, nl - start), color});
        start = nl + 1;
        if (start == message.size()) {
            g_cliResultLines.push_back({"", color});
            break;
        }
    }
}

static void renderCliResultBuffer(int rows, std::mutex& coutMutex) {
    std::vector<TruCliResultLine> snapshot;
    {
        std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
        snapshot = g_cliResultLines;
    }

    const int firstRow = truResultFirstRow();
    const int lastRow = truResultLastRow(rows);
    const int capacity = std::max(1, lastRow - firstRow + 1);

    std::vector<TruCliResultLine> visible;
    if (static_cast<int>(snapshot.size()) <= capacity) {
        visible = snapshot;
    } else if (capacity == 1) {
        visible.push_back(snapshot.back());
    } else {
        const std::size_t keep = static_cast<std::size_t>(capacity - 1);
        const std::size_t hidden = snapshot.size() - keep;
        visible.push_back({
            "[TRU OUTPUT] ... " + std::to_string(hidden) +
                " earlier line" + (hidden == 1 ? "" : "s") + " hidden ...",
            90
        });
        visible.insert(
            visible.end(),
            snapshot.end() - static_cast<std::ptrdiff_t>(keep),
            snapshot.end());
    }

    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");
    fmt::print("\033[?7l");

    for (int row = firstRow; row <= lastRow; ++row) {
        fmt::print("\033[{};1H\033[K", row);
    }
    fmt::print("\033[{};1H\033[K", truMenuPromptRow(rows));

    for (std::size_t i = 0; i < visible.size(); ++i) {
        const int row = firstRow + static_cast<int>(i);
        if (row > lastRow) break;
        fmt::print("\033[{};1H{}", row,
                   colorText(visible[i].text, visible[i].color));
    }

    fmt::print("\033[?7h");
    fmt::print("\033[u");
}

void clearOutput(int rows, std::mutex &coutMutex) {
    g_cliContentFocus.store(false, std::memory_order_release);
    clearCliResultState();

    const int firstRow = truResultFirstRow();
    const int lastRow = std::max(truMenuPromptRow(rows), truResultLastRow(rows));

    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");
    for (int row = firstRow; row <= lastRow; ++row) {
        fmt::print("\033[{};1H\033[K", row);
    }
    fmt::print("\033[u");
}

static void displayResult(const std::string& message,
                          int rows,
                          std::mutex& coutMutex,
                          int color = 96) {
    g_cliContentFocus.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
        g_cliResultLines.clear();
        appendCliResultMessageLocked(message, color);
        g_cliCommandOutputStarted = true;
    }
    renderCliResultBuffer(rows, coutMutex);
}

static void appendResult(const std::string& message,
                         int rows,
                         std::mutex& coutMutex,
                         int color = 96) {
    g_cliContentFocus.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
        if (!g_cliCommandOutputStarted) {
            g_cliResultLines.clear();
            g_cliCommandOutputStarted = true;
        }
        appendCliResultMessageLocked(message, color);
    }
    renderCliResultBuffer(rows, coutMutex);
}

// Compatibility surface for existing handlers.
static bool cliCommandOutputStarted() {
    std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
    return g_cliCommandOutputStarted;
}

static void displayOutput(const std::string &message, int rows, std::mutex &coutMutex) {
    if (cliCommandOutputStarted()) {
        appendResult(message, rows, coutMutex, 96);
    } else {
        displayResult(message, rows, coutMutex, 96);
    }
}

static std::string getCliSyncStatusSnapshot() {
    std::lock_guard<std::mutex> lock(g_cliSyncStatusMutex);
    return g_cliSyncStatus;
}

static void paintCliSyncStatus(const std::string& status,
                               int rows,
                               std::mutex& coutMutex,
                               bool nestedInput) {
    int row = -1;
    if (nestedInput) {
        row = truInputFocusSyncRow(rows);
    } else if (g_cliMenuPromptActive.load(std::memory_order_acquire)) {
        row = truTopLevelSyncRow(rows);
    }

    if (row <= 0) return;

    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");
    fmt::print("\033[{};1H\033[K  {}",
               row, colorText("[SYNC] " + status, 90));
    fmt::print("\033[u");
    std::cout.flush();
}

static void displayPrompt(const std::string& prompt,
                          int rows,
                          std::mutex& coutMutex,
                          int color = 33) {
    g_cliContentFocus.store(true, std::memory_order_release);

    bool newGeneration = false;
    {
        std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
        if (!g_cliCommandOutputStarted) {
            g_cliResultLines.clear();
            g_cliCommandOutputStarted = true;
            newGeneration = true;
        }
    }

    if (newGeneration) {
        renderCliResultBuffer(rows, coutMutex);
    }

    const int bannerRow = truInputFocusBannerRow(rows);
    const int promptRow = truInputFocusPromptRow(rows);
    const int syncRow = truInputFocusSyncRow(rows);
    const std::string syncStatus = getCliSyncStatusSnapshot();

    std::lock_guard<std::mutex> lock(coutMutex);

    // Clear the entire top-level footer stack before a nested question takes
    // focus. Nested input then owns its mid-screen card and local sync lane.
    fmt::print("\033[{};1H\033[K", truMenuPromptRow(rows));
    fmt::print("\033[{};1H\033[K", truHeartbeatRow(rows));
    const int topLevelSyncRow = truTopLevelSyncRow(rows);
    if (topLevelSyncRow > 0) {
        fmt::print("\033[{};1H\033[K", topLevelSyncRow);
    }

    // High-visibility, mid-screen input card. Leave the cursor immediately after
    // the question so normal getline/extract input appears beside the prompt.
    fmt::print("\033[{};1H\033[K  {}",
               bannerRow, colorText("▶ INPUT REQUIRED", 36, true));
    fmt::print("\033[{};1H\033[K  {}",
               promptRow, colorText(prompt, color));

    // 30B5A: sync has its own fixed row below the question.
    if (syncRow > 0) {
        fmt::print("\033[{};1H\033[K  {}",
                   syncRow, colorText("[SYNC] " + syncStatus, 90));
        // Return cursor to the active question for getline/extract.
        fmt::print("\033[{};{}H",
                   promptRow, static_cast<int>(prompt.size()) + 3);
    }

    std::cout.flush();
}

static void beginProgressiveResult(int rows, std::mutex& coutMutex) {
    g_cliContentFocus.store(true, std::memory_order_release);
    clearCliResultState();

    // progressive workflows already own visible
    // result rows before a nested displayPrompt() is invoked. Mark the command
    // generation active here so displayPrompt() does not initialize an empty
    // owned-result buffer and erase those progressive rows.
    {
        std::lock_guard<std::mutex> stateLock(g_cliResultStateMutex);
        g_cliCommandOutputStarted = true;
    }

    const int firstRow = truResultFirstRow();
    const int lastRow = std::max(truMenuPromptRow(rows), truResultLastRow(rows));

    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");
    for (int row = firstRow; row <= lastRow; ++row) {
        fmt::print("\033[{};1H\033[K", row);
    }
    fmt::print("\033[u");
}


// -------------------------------------------------------------------
// SHARED EXACT TRU AMOUNTS
// -------------------------------------------------------------------
// Human decimal parsing and atom formatting now live in tru_amount.h so CLI,
// wallet, smart-contract and RPC transaction builders share one exact parser.
static bool parseTRUAmountExact(const std::string& raw,
                                std::uint64_t& atomsOut,
                                std::string& reason)
{
    return tru_amount::parse(raw, atomsOut, reason);
}

static std::string formatTRUAmountExact(std::uint64_t atoms)
{
    return tru_amount::format(atoms);
}

static std::string formatTRUAtomValue(std::uint64_t atoms)
{
    return std::to_string(atoms) +
           (atoms == 1 ? " TRU atom" : " TRU atoms");
}

static std::string formatTRUAmountDetailed(std::uint64_t atoms)
{
    return formatTRUAmountExact(atoms) + " (" +
           formatTRUAtomValue(atoms) + ")";
}

// -------------------------------------------------------------------
//              HELPERS FOR MAIN
// -------------------------------------------------------------------


struct TerminalSize {
    int rows;
    int cols;
    std::mutex mutex;
    
    TerminalSize() : rows(24), cols(80) {
        update();
    }
    
    void update() {
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
            std::lock_guard<std::mutex> lock(mutex);
            rows = ws.ws_row;
            cols = ws.ws_col;
        }
    }
    
    std::pair<int, int> get() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        return {rows, cols};
    }
    
    int getrows() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        return rows;
    }
    
    int getCols() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        return cols;
    }
};

// Global terminal size instance
TerminalSize g_terminalSize;

static void updateCliSyncStatus(const std::string& status,
                                std::mutex& coutMutex) {
    {
        std::lock_guard<std::mutex> lock(g_cliSyncStatusMutex);
        g_cliSyncStatus = status;
    }

    const bool topLevel =
        g_cliMenuPromptActive.load(std::memory_order_acquire);
    // signalAwareGetline() increments g_cliInputDepth for BOTH top-level and
    // nested reads. Only classify the read as nested when the menu-prompt guard
    // is not active. This prevents top-level sync from being routed into the
    // mid-screen nested-input lane.
    const bool nested =
        !topLevel &&
        g_cliInputDepth.load(std::memory_order_acquire) != 0;

    if (nested || topLevel) {
        auto [rows, cols] = g_terminalSize.get();
        (void)cols;
        paintCliSyncStatus(status, rows, coutMutex, nested);
    }
}

extern httplib::Server g_rpcServer;
extern httplib::Server g_explorerServer;
std::atomic<bool> g_serverRunning{true};

bool directoryExists(const std::string &path) {
    struct stat info;
    return (stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR));
}

std::atomic<bool> g_running(true);

// TRU_TOKEN_VAULT_UI_V1: a full-screen CLI view owns the terminal while true.
// The spinner thread stays alive but temporarily stops painting.
static std::atomic<bool> g_cliFullscreenView{false};

std::atomic<bool> g_shuttingDown{false};

// POSIX signal handlers remain async-signal-safe.
// Handlers only update sig_atomic_t state and write one byte to a non-blocking
// self-pipe. Logging, atomics, mutexes and terminal resizing happen later in
// normal C++ execution context.
static int g_signalWakePipe[2] = {-1, -1};
static volatile sig_atomic_t g_pendingShutdownSignal = 0;
static volatile sig_atomic_t g_pendingWinch = 0;

struct CliShutdownInterrupt {};

static void writeSignalWakeByte(int signum) noexcept {
    const int savedErrno = errno;
    const int fd = g_signalWakePipe[1];

    if (fd >= 0) {
        const unsigned char byte =
            static_cast<unsigned char>(signum & 0xff);
        const ssize_t ignored = ::write(fd, &byte, sizeof(byte));
        (void)ignored;
    }

    errno = savedErrno;
}

// normal C++ execution-context bridge for a future
// post-mutation reorg fail-stop. This does not impersonate a POSIX signal; it
// sets the existing shutdown atomics and writes one wake byte so a blocked CLI
// poll exits through the already-reviewed graceful shutdown path.
static void requestOrderlyShutdownFromBlockchain(const std::string& reason) noexcept {
    try {
        Logger::log(
            "[Patch08B.4D.9A] Blockchain requested orderly fail-stop shutdown: " +
            reason);
    } catch (...) {}

    g_shuttingDown.store(true, std::memory_order_release);
    g_running.store(false, std::memory_order_release);
    writeSignalWakeByte(0);
}

static void signalHandler(int signum) noexcept {
    g_pendingShutdownSignal = signum;
    writeSignalWakeByte(signum);
}

static void handleWinch(int signum) noexcept {
    (void)signum;
    g_pendingWinch = 1;
    writeSignalWakeByte(SIGWINCH);
}

static void initializeSignalWakePipe() {
    if (::pipe(g_signalWakePipe) != 0) {
        throw std::runtime_error(
            std::string("Unable to create signal wake pipe: ") +
            std::strerror(errno));
    }

    for (int i = 0; i < 2; ++i) {
        const int flags = ::fcntl(g_signalWakePipe[i], F_GETFL, 0);
        if (flags < 0 ||
            ::fcntl(g_signalWakePipe[i], F_SETFL, flags | O_NONBLOCK) < 0) {
            const int savedErrno = errno;
            ::close(g_signalWakePipe[0]);
            ::close(g_signalWakePipe[1]);
            g_signalWakePipe[0] = -1;
            g_signalWakePipe[1] = -1;
            throw std::runtime_error(
                std::string("Unable to make signal wake pipe non-blocking: ") +
                std::strerror(savedErrno));
        }

        const int fdFlags = ::fcntl(g_signalWakePipe[i], F_GETFD, 0);
        if (fdFlags < 0 ||
            ::fcntl(g_signalWakePipe[i], F_SETFD, fdFlags | FD_CLOEXEC) < 0) {
            const int savedErrno = errno;
            ::close(g_signalWakePipe[0]);
            ::close(g_signalWakePipe[1]);
            g_signalWakePipe[0] = -1;
            g_signalWakePipe[1] = -1;
            throw std::runtime_error(
                std::string("Unable to set signal wake pipe CLOEXEC: ") +
                std::strerror(savedErrno));
        }
    }

    struct sigaction shutdownAction {};
    sigemptyset(&shutdownAction.sa_mask);
    shutdownAction.sa_handler = signalHandler;

    // Patch 08B.4A.1b v2 / N1: keep unrelated blocking syscalls restartable.
    // poll(2) still wakes via the self-pipe and is explicitly EINTR-safe.
    shutdownAction.sa_flags = SA_RESTART;

    if (::sigaction(SIGINT, &shutdownAction, nullptr) != 0 ||
        ::sigaction(SIGTERM, &shutdownAction, nullptr) != 0) {
        throw std::runtime_error(
            std::string("Unable to install shutdown signal handlers: ") +
            std::strerror(errno));
    }

    struct sigaction winchAction {};
    sigemptyset(&winchAction.sa_mask);
    winchAction.sa_handler = handleWinch;
    winchAction.sa_flags = SA_RESTART;

    if (::sigaction(SIGWINCH, &winchAction, nullptr) != 0) {
        throw std::runtime_error(
            std::string("Unable to install SIGWINCH handler: ") +
            std::strerror(errno));
    }
}

static void drainSignalWakePipe() noexcept {
    if (g_signalWakePipe[0] < 0) {
        return;
    }

    const int savedErrno = errno;
    unsigned char buffer[64];

    for (;;) {
        const ssize_t n =
            ::read(g_signalWakePipe[0], buffer, sizeof(buffer));
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    errno = savedErrno;
}

static bool dispatchPendingSignalEvents() {
    if (g_pendingWinch != 0) {
        g_pendingWinch = 0;
        g_terminalSize.update();
    }

    const sig_atomic_t signum = g_pendingShutdownSignal;
    if (signum == 0) {
        return false;
    }

    g_pendingShutdownSignal = 0;
    g_shuttingDown.store(true, std::memory_order_release);
    g_running.store(false, std::memory_order_release);

    Logger::log(
        "[signalDispatch] Received signal: " +
        std::to_string(static_cast<int>(signum)) +
        ", waking CLI and initiating shutdown...");
    return true;
}

static void waitForSignalAwareStdin() {
    for (;;) {
        // Patch 08B.4A.1b v2 / N2: shutdown is sticky. If a nested bare
        // catch (...) swallowed CliShutdownInterrupt, every later input wait
        // immediately rethrows instead of blocking forever on an emptied pipe.
        if (!g_running.load(std::memory_order_acquire)) {
            throw CliShutdownInterrupt{};
        }

        if (dispatchPendingSignalEvents()) {
            throw CliShutdownInterrupt{};
        }

        if (std::cin.rdbuf()->in_avail() > 0) {
            return;
        }

        struct pollfd fds[2] {};
        fds[0].fd = STDIN_FILENO;
        fds[0].events = POLLIN | POLLHUP | POLLERR;
        fds[1].fd = g_signalWakePipe[0];
        fds[1].events = POLLIN | POLLHUP | POLLERR;

        const int nfds = (g_signalWakePipe[0] >= 0) ? 2 : 1;
        const int rc = ::poll(fds, nfds, -1);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(
                std::string("poll() failed while waiting for CLI input: ") +
                std::strerror(errno));
        }

        if (nfds == 2 &&
            (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            drainSignalWakePipe();

            if (dispatchPendingSignalEvents()) {
                throw CliShutdownInterrupt{};
            }

            continue;
        }

        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            return;
        }
    }
}

// every signal-aware input path owns the cursor
// while blocked. The top-level command prompt gets a second guard so the
// heartbeat may continue there while remaining paused for nested input.
class TruCliInputPaintGuard {
public:
    TruCliInputPaintGuard() noexcept {
        g_cliInputDepth.fetch_add(1, std::memory_order_acq_rel);
    }
    ~TruCliInputPaintGuard() noexcept {
        g_cliInputDepth.fetch_sub(1, std::memory_order_acq_rel);
    }
    TruCliInputPaintGuard(const TruCliInputPaintGuard&) = delete;
    TruCliInputPaintGuard& operator=(const TruCliInputPaintGuard&) = delete;
};

class TruCliMenuPromptGuard {
public:
    TruCliMenuPromptGuard() noexcept {
        g_cliMenuPromptActive.store(true, std::memory_order_release);
    }
    ~TruCliMenuPromptGuard() noexcept {
        g_cliMenuPromptActive.store(false, std::memory_order_release);
    }
    TruCliMenuPromptGuard(const TruCliMenuPromptGuard&) = delete;
    TruCliMenuPromptGuard& operator=(const TruCliMenuPromptGuard&) = delete;
};

static std::istream& signalAwareGetline(std::string& out) {
    TruCliInputPaintGuard inputGuard;
    waitForSignalAwareStdin();
    std::getline(static_cast<std::istream&>(std::cin), out);
    return std::cin;
}

template <typename T>
static std::istream& signalAwareExtract(T& out) {
    TruCliInputPaintGuard inputGuard;
    waitForSignalAwareStdin();
    std::cin >> out;
    return std::cin;
}

static std::istream& signalAwareIgnoreLine() {
    TruCliInputPaintGuard inputGuard;
    if (std::cin.rdbuf()->in_avail() <= 0) {
        waitForSignalAwareStdin();
    }

    std::cin.ignore(
        std::numeric_limits<std::streamsize>::max(), '\n');
    return std::cin;
}

// ---- One-shot CLI status notice --------------------------------------------
// A temporary message painted below the [Chain Info] panel on the next menu
// redraw, then cleared so it does not remain permanently on screen.
static std::mutex g_statusNoticeMutex;
static std::string g_statusNotice;      // message text ("" = nothing to show)
static int         g_statusNoticeColor = 33;  // ANSI color code (33=yellow)

void setStatusNotice(const std::string& text, int colorCode = 33) {
    std::lock_guard<std::mutex> lk(g_statusNoticeMutex);
    g_statusNotice = text;
    g_statusNoticeColor = colorCode;
}

// row 16 is the normal-mode status lane.
// Output Focus owns row 16+, so a notice is preserved until the deck returns.
void paintStatusNotice() {
    if (g_cliContentFocus.load(std::memory_order_acquire) ||
        g_cliInputDepth.load(std::memory_order_acquire) != 0) {
        return;
    }

    std::string text; int color;
    {
        std::lock_guard<std::mutex> lk(g_statusNoticeMutex);
        text = g_statusNotice; color = g_statusNoticeColor;
        g_statusNotice.clear();
    }

    fmt::print("\033[s");
    fmt::print("\033[16;1H\033[K");
    if (!text.empty()) {
        // Absolute-position painter: never emit a newline that could scroll.
        fmt::print("{}", colorText(text, color));
    }
    fmt::print("\033[u");
}

std::string getCurrentPubkeyhash(const Wallet& wallet) {
    std::string currentAddr = wallet.getCurrentAddress();
    if (currentAddr.empty()) {
        throw std::runtime_error("No current address set in wallet.");
    }
    // Decode base58 address to get the pubkeyhash
    std::vector<unsigned char> decoded = base58Decode(currentAddr);
    if (decoded.size() != 25) {  // 1 byte version + 20 bytes hash + 4 bytes checksum
        throw std::runtime_error("Invalid address format.");
    }
    // Extract the pubkeyhash (bytes 1 to 21, excluding version and checksum)
    std::vector<unsigned char> pubkeyhash(decoded.begin() + 1, decoded.begin() + 21);
    return bytesToHex(pubkeyhash);
}

uint64_t foundNonce = 0;

std::vector<unsigned char> finalH(32);

std::thread startMinerCleanupThread(Blockchain *blockchain)
{
    return std::thread([blockchain]()
                       {
        Logger::log("[Cleanup] Miner cleanup thread started");

        while (g_running.load(std::memory_order_acquire))
        {
            // Wait 30 seconds between cleanup passes,
            // but check shutdown every 1 second.
            for (int i = 0;
                 i < 30 && g_running.load(std::memory_order_acquire);
                 ++i)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            // Shutdown requested while waiting.
            if (!g_running.load(std::memory_order_acquire))
                break;

            if (blockchain == nullptr)
            {
                Logger::log(
                    "[Cleanup] Blockchain pointer is null; stopping cleanup thread");
                break;
            }

            try
            {
                blockchain->cleanupInactiveMiners();
            }
            catch (const std::exception& e)
            {
                Logger::log(
                    "[Cleanup] Error in miner cleanup: " +
                    std::string(e.what()));
            }
            catch (...)
            {
                Logger::log(
                    "[Cleanup] Unknown error in miner cleanup");
            }
        }

        Logger::log("[Cleanup] Miner cleanup thread stopped"); });
}
//============================================================================================
// 			Helper: Format a token table for dispAlay.
//============================================================================================
void displayFormattedTokenList(const Wallet &wallet, int rows, std::mutex &coutMutex);
std::string formatTokenTable2(const Wallet &wallet);
void displayFormattedTokenList2(const Wallet &wallet, int rows, std::mutex &coutMutex);
//============================================================================================
// 			Function to list mempool transactions
//============================================================================================
void listMempoolTransactions(const Blockchain& chain, int rows, std::mutex& coutMutex);
//============================================================================================
// 			QUERY CONTRACT STATE
//============================================================================================
void queryContractState(const Blockchain& chain, int rows, std::mutex& coutMutex);
//============================================================================================
//                      Display Voting V1 Confirmed Results
//============================================================================================
// canonical reader only. Voting results are derived from the
// confirmed stable-root/live-anchor state domain. Legacy "contract:<addr>:*"
// mirrors are intentionally ignored and are no longer an authority.
void displayVotingResults(const Blockchain& chain, const std::string& contractInput,
                          int rows, std::mutex& coutMutex) {
    const LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        displayResult("[VOTING V1] Blockchain storage is unavailable.", rows, coutMutex, 91);
        return;
    }

    const std::string root = trim(contractInput);
    if (!tru_contract_state::IsCanonicalContractOutpoint(root)) {
        displayResult(
            "[VOTING V1] Stable root must be canonical lowercase <64-hex-txid>:<vout>.",
            rows, coutMutex, 91);
        return;
    }

    const std::string liveKey =
        tru_contract_state::BuildContractLiveKey(root);
    std::string live;
    bool found = false;
    if (liveKey.empty() ||
        !storage->getRaw(liveKey, live, found) || !found ||
        !tru_contract_state::IsCanonicalContractOutpoint(live)) {
        displayResult(
            "[VOTING V1] No canonical confirmed live anchor exists for this root.",
            rows, coutMutex, 91);
        return;
    }

    tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
    std::string reason;
    if (!tru_contract_state_runtime::LoadConfirmedStateDomain(
            *storage, live, snapshot, reason)) {
        displayResult(
            "[VOTING V1] Unable to load confirmed state: " + reason,
            rows, coutMutex, 91);
        return;
    }
    if (snapshot.root != root || snapshot.family != "voting_v1") {
        displayResult(
            "[VOTING V1] Supplied root is not an activated Voting V1 contract.",
            rows, coutMutex, 91);
        return;
    }

    std::size_t numOptions = 0;
    std::uint64_t endTime = 0;
    if (!tru_contract_state_runtime::ValidateVotingV1State(
            snapshot.state, numOptions, endTime, reason)) {
        displayResult(
            "[VOTING V1] Confirmed state failed tally validation: " + reason,
            rows, coutMutex, 91);
        return;
    }

    const auto proposalIt = snapshot.state.find("proposal");
    const std::string proposal(
        proposalIt->second.begin(), proposalIt->second.end());

    std::uint64_t totalVotes = 0;
    if (!tru_contract_state_runtime::ReadVotingU64(
            snapshot.state, "totalvotes", totalVotes)) {
        displayResult(
            "[VOTING V1] Confirmed totalvotes is malformed.",
            rows, coutMutex, 91);
        return;
    }

    std::ostringstream report;
    report << "=== VOTING V1 — CONFIRMED RESULTS ===\n"
           << "Family: voting_v1\n"
           << "Stable Root: " << root << "\n"
           << "Live Anchor: " << live << "\n"
           << "Proposal: " << proposal << "\n"
           << "End Time: " << endTime << " (Unix)\n"
           << "Total Votes: " << totalVotes << "\n"
           << "Recorded Voters: " << totalVotes << "\n"
           << "\nResults:\n";

    for (std::size_t i = 0; i < numOptions; ++i) {
        const auto optionIt =
            snapshot.state.find("option" + std::to_string(i));
        const std::string option(
            optionIt->second.begin(), optionIt->second.end());

        std::uint64_t count = 0;
        if (!tru_contract_state_runtime::ReadVotingU64(
                snapshot.state, "count" + std::to_string(i), count)) {
            displayResult(
                "[VOTING V1] Confirmed option count is malformed.",
                rows, coutMutex, 91);
            return;
        }

        const long double pct =
            totalVotes == 0
                ? 0.0L
                : (static_cast<long double>(count) * 100.0L /
                   static_cast<long double>(totalVotes));
        report << "  " << i << ") " << option
               << " — " << count << " vote";
        if (count != 1) report << "s";
        report << " (" << std::fixed << std::setprecision(1)
               << pct << "%)\n";
    }

    const std::time_t nowRaw = std::time(nullptr);
    if (nowRaw >= 0) {
        const std::uint64_t now =
            static_cast<std::uint64_t>(nowRaw);
        report << "\nWall Clock View: "
               << (now <= endTime ? "OPEN" : "CLOSED")
               << " at Unix " << now << "\n";
    }
    report << "Consensus Rule: vote candidate block time must be <= "
           << endTime << ".\n";

    displayResult(report.str(), rows, coutMutex, 96);
}

//===========================================================================================
//				SMART CONTRACT TOKENS
//===========================================================================================
// Token Issuer V1 reads use the canonical root-scoped LevelDB
// namespace. Legacy ContractStorage is not authoritative.
uint64_t getTokenBalance(
    const Blockchain& chain,
    const std::string& contractRoot,
    const std::string& buyerHash160)
{
    if (!tru_contract_state::IsCanonicalContractOutpoint(contractRoot) ||
        !tru_contract_state_runtime::IsCanonicalLowerHash160Hex(
            buyerHash160)) {
        Logger::log(
            "[getTokenBalance] Non-canonical Token Issuer V1 root/buyer");
        return 0;
    }

    const LevelDBStorage* storage = chain.getStorage();
    if (!storage) return 0;

    const std::string liveKey =
        tru_contract_state::BuildContractLiveKey(contractRoot);
    std::string live;
    bool found = false;
    if (liveKey.empty() ||
        !storage->getRaw(liveKey, live, found) || !found ||
        !tru_contract_state::IsCanonicalContractOutpoint(live)) {
        Logger::log(
            "[getTokenBalance] Missing canonical Token Issuer V1 live anchor");
        return 0;
    }

    tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
    std::string reason;
    if (!tru_contract_state_runtime::LoadConfirmedStateDomain(
            *storage, live, snapshot, reason) ||
        snapshot.root != contractRoot ||
        snapshot.family != "token_issuer_v1") {
        Logger::log(
            "[getTokenBalance] Unable to load Token Issuer V1 root state: " +
            reason);
        return 0;
    }

    std::uint64_t rate = 0;
    std::uint64_t maxSupply = 0;
    std::uint64_t totalIssued = 0;
    if (!tru_contract_state_runtime::ValidateTokenIssuerV1State(
            snapshot.state, rate, maxSupply, totalIssued, reason)) {
        Logger::log(
            "[getTokenBalance] Invalid Token Issuer V1 state: " + reason);
        return 0;
    }

    const std::string balanceKey = "balance:" + buyerHash160;
    const auto it = snapshot.state.find(balanceKey);
    if (it == snapshot.state.end()) return 0;

    std::uint64_t balance = 0;
    if (!tru_contract_state_runtime::ReadTokenIssuerU64(
            snapshot.state, balanceKey, balance)) {
        Logger::log("[getTokenBalance] Malformed persistent buyer balance");
        return 0;
    }
    return balance;
}

struct TokenContractInfo {
    std::string tokenName;
    uint64_t exchangeRate{0};
    uint64_t maxSupply{0};
    uint64_t totalIssued{0};
    bool isValid{false};
};

TokenContractInfo getTokenContractInfo(
    const Blockchain& chain,
    const std::string& contractRoot)
{
    TokenContractInfo info;

    if (!tru_contract_state::IsCanonicalContractOutpoint(contractRoot)) {
        Logger::log(
            "[getTokenContractInfo] Token Issuer V1 root is not canonical");
        return info;
    }

    const LevelDBStorage* storage = chain.getStorage();
    if (!storage) return info;

    const std::string liveKey =
        tru_contract_state::BuildContractLiveKey(contractRoot);
    std::string live;
    bool found = false;
    if (liveKey.empty() ||
        !storage->getRaw(liveKey, live, found) || !found ||
        !tru_contract_state::IsCanonicalContractOutpoint(live)) {
        Logger::log(
            "[getTokenContractInfo] Missing canonical Token Issuer V1 live anchor");
        return info;
    }

    tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
    std::string reason;
    if (!tru_contract_state_runtime::LoadConfirmedStateDomain(
            *storage, live, snapshot, reason) ||
        snapshot.root != contractRoot ||
        snapshot.family != "token_issuer_v1") {
        Logger::log(
            "[getTokenContractInfo] Unable to load Token Issuer V1 root: " +
            reason);
        return info;
    }

    if (!tru_contract_state_runtime::ValidateTokenIssuerV1State(
            snapshot.state,
            info.exchangeRate,
            info.maxSupply,
            info.totalIssued,
            reason)) {
        Logger::log(
            "[getTokenContractInfo] Invalid Token Issuer V1 state: " + reason);
        return info;
    }

    const auto nameIt = snapshot.state.find("token_name");
    if (nameIt == snapshot.state.end()) {
        Logger::log("[getTokenContractInfo] Missing token_name");
        return info;
    }
    info.tokenName.assign(nameIt->second.begin(), nameIt->second.end());
    info.isValid = true;
    return info;
}

//============================================================================================
// 			Render a simple ASCII QR code
//============================================================================================
static void printQRCode(const std::string &data) {
    QRcode *q = QRcode_encodeString(
        data.c_str(),
        0,               // auto version
        QR_ECLEVEL_L,    // error correction: Low
        QR_MODE_8,       // 8‑bit mode
        1                // case‑sensitive
    );
    if (!q) return;
    int sz = q->width;
    unsigned char *d = q->data;
    const std::string black = "██";
    const std::string white = "  ";

    // Top margin
    for (int i = 0; i < sz + 2; i++) std::cout << white;
    std::cout << "\n";

    // QR rows
    for (int y = 0; y < sz; y++) {
        std::cout << white;
        for (int x = 0; x < sz; x++) {
            bool bit = d[y * sz + x] & 1;
            std::cout << (bit ? black : white);
        }
        std::cout << white << "\n";
    }

    // Bottom margin
    for (int i = 0; i < sz + 2; i++) std::cout << white;
    std::cout << "\n";

    QRcode_free(q);
}

//============================================================================================
//                      View QR code
//============================================================================================
static void viewAddressQRCode(const std::string &addr) {
    // ANSI clear + home
    std::cout << "\033[2J\033[H";

    // Show the address in bold green
    std::cout << colorText("Address: ", 32, true)
              << colorText(addr, 32) << "\n\n";

    // Render the QR
    printQRCode(addr);

    // Prompt and wait
    std::cout << "\nPress Enter to return to menu...";
    signalAwareIgnoreLine();
    // Clear again so next menu draw is clean
    std::cout << "\033[2J\033[H";
}
//============================================================================================
//            		Spinner at row=60
//============================================================================================
void runBlockchainSpinner(std::atomic<bool> &running, std::mutex &coutMutex) {
    // restore the original TRU spinner identity while
    // retaining the new fixed heartbeat lane and cursor-safety architecture.
    // Original pre-UI sequence:
    //   ⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷  Blockchain Running Smoothly...
    const std::vector<std::string> spinnerChars = {
        "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"
    };

    size_t idx = 0;
    int lastRow = -1;
    bool lanePrimed = false;

    while (running.load(std::memory_order_acquire)) {
        const bool topLevelPrompt =
            g_cliMenuPromptActive.load(std::memory_order_acquire);
        const bool fullscreen =
            g_cliFullscreenView.load(std::memory_order_acquire);

        // The spinner is a top-level liveness indicator. Nested data-entry and
        // full-screen views still own the cursor exclusively.
        if (!topLevelPrompt || fullscreen) {
            if (lanePrimed && lastRow > 0) {
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("\033[s");
                fmt::print("\033[{};1H\033[K", lastRow);
                fmt::print("\033[u");
                lanePrimed = false;
                lastRow = -1;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(55));
            continue;
        }

        auto [rows, cols] = g_terminalSize.get();
        (void)cols;
        const int heartbeatRow = truHeartbeatRow(rows);

        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[s");

            // Paint the static status label only when entering/moving the lane.
            // Thereafter only the rotor cell changes, eliminating line flash.
            if (!lanePrimed || lastRow != heartbeatRow) {
                if (lanePrimed && lastRow > 0 && lastRow != heartbeatRow) {
                    fmt::print("\033[{};1H\033[K", lastRow);
                }

                fmt::print("\033[{};1H\033[K", heartbeatRow);
                fmt::print("  {}", colorText("Blockchain Running Smoothly...", 97));
                lanePrimed = true;
                lastRow = heartbeatRow;
            }

            const auto spinSymbol =
                colorText(spinnerChars[idx % spinnerChars.size()], 32, true);
            fmt::print("\033[{};1H{}", heartbeatRow, spinSymbol);
            fmt::print("\033[u");
        }

        ++idx;
        std::this_thread::sleep_for(std::chrono::milliseconds(55));
    }

    if (lanePrimed && lastRow > 0) {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[s");
        fmt::print("\033[{};1H\033[K", lastRow);
        fmt::print("\033[u");
    }
}

//============================================================================================
// TRANSACTION RECEIPTS
//============================================================================================
// Receipts are presentation/read-only. They never classify an arbitrary
// script as a contract. Canonical contract family/root fields are emitted only
// when the command itself knows the V1 family/root or an already-confirmed
// stable root is supplied by the caller.
struct TruTransactionReceipt {
    std::string status{"MEMPOOL ACCEPTED"};
    std::string type;
    std::string txid;
    std::string confirmation{"Pending — not yet mined"};
    std::vector<std::pair<std::string, std::string>> fields;
    std::string next;
};

static void appendReceiptFieldLines(std::vector<std::string>& lines,
                                    const std::string& label,
                                    const std::string& value) {
    if (value.empty()) return;

    if (value.size() > 54) {
        lines.push_back(label + ":");
        lines.push_back("  " + value);
        return;
    }

    std::ostringstream row;
    row << std::left << std::setw(15) << (label + ":") << value;
    lines.push_back(row.str());
}

static std::string canonicalReceiptFamilyForContractType(
    const std::string& contractType) {
    if (contractType == "TOKEN ISSUER") return "token_issuer_v1";
    if (contractType == "VOTING") return "voting_v1";
    if (contractType == "STATEFUL CONTRACT") return "stateful_kv_v1";
    return "";
}

static std::string joinReceiptLines(const std::vector<std::string>& lines,
                                    std::size_t begin,
                                    std::size_t end) {
    std::ostringstream out;
    for (std::size_t i = begin; i < end; ++i) {
        if (i != begin) out << "\n";
        out << lines[i];
    }
    return out.str();
}

static void displayTransactionReceipt(const TruTransactionReceipt& receipt,
                                      std::mutex& coutMutex) {
    auto [rows, cols] = g_terminalSize.get();
    (void)cols;

    std::vector<std::string> lines;
    lines.push_back("TRU TRANSACTION RECEIPT");
    lines.push_back("────────────────────────────────────────────────────────────");
    appendReceiptFieldLines(lines, "STATUS", receipt.status);
    appendReceiptFieldLines(lines, "TYPE", receipt.type);
    appendReceiptFieldLines(lines, "CONFIRMATION", receipt.confirmation);
    if (!receipt.txid.empty()) {
        appendReceiptFieldLines(lines, "TXID", receipt.txid);
    }
    for (const auto& [label, value] : receipt.fields) {
        appendReceiptFieldLines(lines, label, value);
    }
    if (!receipt.next.empty()) {
        appendReceiptFieldLines(lines, "NEXT", receipt.next);
    }
    lines.push_back("────────────────────────────────────────────────────────────");

    // Receipt-specific paging keeps every field readable even on a short
    // terminal. Each page is deliberately <= the 30B4 owned result zone, so
    // the generic renderer never has to hide receipt lines.
    // 30B5: receipt pages stop above the mid-screen input card so the
    // "Enter for next page" question never covers a receipt field.
    const int capacity = std::max(
        1, truReceiptResultLastRow(rows) - truResultFirstRow() + 1);
    const std::size_t pageSize = static_cast<std::size_t>(capacity);
    const std::size_t pageCount = std::max<std::size_t>(
        1, (lines.size() + pageSize - 1) / pageSize);

    for (std::size_t page = 0; page < pageCount; ++page) {
        const std::size_t begin = page * pageSize;
        const std::size_t end = std::min(lines.size(), begin + pageSize);
        displayResult(joinReceiptLines(lines, begin, end), rows, coutMutex, 96);

        if (page + 1 < pageCount) {
            displayPrompt(
                "Receipt page " + std::to_string(page + 1) + "/" +
                    std::to_string(pageCount) + " — Enter for next page...",
                rows, coutMutex, 33);
        } else {
            displayPrompt(
                "Receipt page " + std::to_string(page + 1) + "/" +
                    std::to_string(pageCount) + " — Enter to return to menu...",
                rows, coutMutex, 33);
        }
        signalAwareIgnoreLine();
    }
}

//============================================================================================
//                              Display TOKEN Creation
//============================================================================================


int getColorForTokenType(const std::string& tokenType) {
    if (tokenType == "FT") return 34;   // Blue
    if (tokenType == "NFT") return 35;  // Magenta
    if (tokenType == "SFT") return 36;  // Cyan
    if (tokenType == "NCFT") return 33; // Yellow
    return 32; // Default to Green
}

void displayTokenCreationSuccess(
    const std::string& tokenType,
    const std::string& txid,
    const std::map<std::string, std::string>& tokenDetails,
    std::mutex& coutMutex
) {
    TruTransactionReceipt receipt;
    receipt.type = "TOKEN ISSUE / " + tokenType;
    receipt.txid = txid;
    receipt.fields.push_back({"Token Type", tokenType});

    std::size_t detailCount = 0;
    for (const auto& [key, value] : tokenDetails) {
        if (value.empty()) continue;
        receipt.fields.push_back({key, value});
        if (++detailCount >= 5) break;
    }

    receipt.next = "Mine one block, then inspect the confirmed token index.";
    displayTransactionReceipt(receipt, coutMutex);
}

//============================================================================================
//				Display Success Token Send
//============================================================================================

void displaySuccessMessageTokenSend(
    const std::string& txid,
    const std::string& tokenID,
    uint64_t quantity,
    const std::string& recipient,
    const std::string& sender,
    const std::string& tokenType,
    const std::unordered_map<std::string, std::string>& metadata,
    std::mutex& coutMutex
) {
    TruTransactionReceipt receipt;
    receipt.type = "TOKEN TRANSFER / " + tokenType;
    receipt.txid = txid;
    receipt.fields = {
        {"Token ID", tokenID},
        {"Quantity", std::to_string(quantity)},
        {"From", sender},
        {"To", recipient},
        {"Metadata", metadata.empty()
            ? std::string("none")
            : std::to_string(metadata.size()) + " field(s)"}
    };
    receipt.next = "Mine one block, then verify confirmed token ownership.";
    displayTransactionReceipt(receipt, coutMutex);
}
//============================================================================================
//                              Display Success Send TRU
//============================================================================================

void displaySuccessMessageTX(
    const std::string& txid,
    const std::string& sender,
    const std::string& recipient,
    std::uint64_t amountAtoms,
    const std::string& nodeIP,
    int nodePort,
    std::mutex& coutMutex
) {
    TruTransactionReceipt receipt;
    receipt.type = "TRU TRANSFER";
    receipt.txid = txid;
    receipt.fields = {
        {"Amount", tru_amount::format(amountAtoms)},
        {"Atomic Value", std::to_string(amountAtoms) + " TRU atoms"},
        {"From", sender},
        {"To", recipient},
        {"Node", nodeIP + ":" + std::to_string(nodePort)}
    };
    receipt.next = "Mine one block, then re-check the recipient balance.";
    displayTransactionReceipt(receipt, coutMutex);
}


//============================================================================================
//                              DISPLAY SUCCESS CONTRACT MESSAGE
//============================================================================================
int getColorForContractType(const std::string& contractType) {
    if (contractType == "TIME LOCK") return 34;        // Blue
    if (contractType == "OP_RETURN") return 33;        // Yellow
    if (contractType == "HASH LOCK") return 35;        // Magenta
    if (contractType == "CUSTOM SCRIPT") return 36;    // Cyan
    if (contractType == "ORACLE LOCK") return 32;      // Green
    if (contractType == "STATEFUL CONTRACT") return 95; // Light Magenta
    if (contractType == "MULTISIG / ESCROW V1") return 96; // Bright Cyan
    if (contractType == "HTLC / ATOMIC SWAP V1") return 93; // Bright Yellow
    return 37;                                          // White for unknown
}

std::string getContractTypeEmoji(const std::string& contractType) {
    if (contractType == "TIME LOCK") return "🔒";
    if (contractType == "OP_RETURN") return "📝";
    if (contractType == "HASH LOCK") return "🔐";
    if (contractType == "CUSTOM SCRIPT") return "⚙️";
    if (contractType == "ORACLE LOCK") return "🔮";
    if (contractType == "STATEFUL CONTRACT") return "💾";
    if (contractType == "MULTISIG / ESCROW V1") return "🤝";
    if (contractType == "HTLC / ATOMIC SWAP V1") return "🔁";
    return "📜";
}

std::string formatAmount(uint64_t atoms) {
    return formatTRUAmountDetailed(atoms);
}

std::string formatTimestamp(uint32_t timestamp) {
    time_t timeT = static_cast<time_t>(timestamp);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", gmtime(&timeT));
    return std::string(buffer);
}

std::string truncateHex(const std::string& hex, size_t maxLen = 64) {
    if (hex.length() <= maxLen) return hex;
    return hex.substr(0, maxLen/2) + "..." + hex.substr(hex.length() - maxLen/2);
}

void displaySuccessMessageContract(
    const std::string& contractType,
    const std::string& txid,
    const std::string& contractAddress,
    const std::string& scriptHex,
    const std::string& broadcastStatus,
    const std::string& senderAddress,
    const std::string& contractName,
    const std::string& lockReason,
    uint64_t contractAmount,
    uint64_t fee,
    uint32_t lockTime,
    const std::string& preimageHash,
    std::mutex& coutMutex
) {
    TruTransactionReceipt receipt;
    receipt.type = "CONTRACT DEPLOY / " + contractType;
    receipt.txid = txid;

    receipt.fields.push_back({"Contract", contractName.empty()
        ? std::string("Unnamed Contract") : contractName});
    receipt.fields.push_back({"Output", contractAddress});
    receipt.fields.push_back({"Amount", tru_amount::format(contractAmount)});
    receipt.fields.push_back({"Atomic Value",
        std::to_string(contractAmount) + " TRU atoms"});
    receipt.fields.push_back({"Fee", tru_amount::format(fee)});
    receipt.fields.push_back({"Sender", senderAddress});
    receipt.fields.push_back({"Broadcast", broadcastStatus});

    const std::string family =
        canonicalReceiptFamilyForContractType(contractType);
    if (!family.empty()) {
        receipt.fields.push_back({"Family", family});
        receipt.fields.push_back({"Stable Root",
            contractAddress + " (pending confirmation)"});
        receipt.fields.push_back({"Live Anchor",
            contractAddress + " (pending confirmation)"});
        receipt.next =
            "Mine one block; registry root/live become confirmed after block acceptance.";
    } else {
        receipt.next = "Mine one block, then inspect the contract output.";
    }

    if (contractType == "TIME LOCK" && lockTime > 0) {
        receipt.fields.push_back({"Lock Until", formatTimestamp(lockTime)});
        if (!lockReason.empty()) receipt.fields.push_back({"Reason", lockReason});
        receipt.next =
            "Mine one block; after parent-chain MTP reaches Lock Until, run 'timeredeem' with this Output.";
    }
    if (contractType == "HASH LOCK" && !preimageHash.empty()) {
        receipt.fields.push_back({"HASH160", preimageHash});
        receipt.next =
            "Mine one block, then run 'hashredeem' with this Output and the original preimage.";
    }
    if (!scriptHex.empty()) {
        receipt.fields.push_back({"Script", truncateHex(scriptHex, 48)});
    }

    displayTransactionReceipt(receipt, coutMutex);
}

//====================================================================
//			AI TOKEN HELPERS and CREATION
//====================================================================

static std::string readLineTrimmed(const std::string& prompt,
                                   int rows,
                                   std::mutex& coutMutex) {
    std::string s;
    displayPrompt(prompt + " ", rows, coutMutex);
    signalAwareGetline(s);
    // trim both ends
    auto l = s.find_first_not_of(" \t\r\n");
    auto r = s.find_last_not_of(" \t\r\n");
    if (l == std::string::npos) return "";
    return s.substr(l, r - l + 1);
}

static bool askYesNo(const std::string& prompt,
                     int rows,
                     std::mutex& coutMutex,
                     bool def=false) {
    while (true) {
        std::string p = prompt + (def ? " [Y/n]:" : " [y/N]:");
        std::string s = readLineTrimmed(p, rows, coutMutex);
        if (s.empty()) return def;
        for (auto& c : s) c = (char)tolower(c);
        if (s=="y" || s=="yes") return true;
        if (s=="n" || s=="no")  return false;
        displayResult("Please answer y/n.", rows, coutMutex, 91);
    }
}

//============================================================
// 			STORE TOKEN CONVO
//============================================================
void storeTokenConversation(const std::string& tokenID, 
                           const std::string& userMessage, 
                           const std::string& tokenResponse,
                           Blockchain& blockchain) {  // Pass blockchain as parameter
    if (!blockchain.getStorage()) return;
    
    auto storage = blockchain.getStorage();
    std::string historyKey = "ai_token:" + tokenID + ":history";
    
    std::string historyData;
    nlohmann::json history = nlohmann::json::array();
    
    if (storage->getWithDataChecksum(historyKey, historyData)) {
        history = nlohmann::json::parse(historyData);
    }
    
    history.push_back({
        {"timestamp", std::time(nullptr)},
        {"user", userMessage},
        {"token", tokenResponse}
    });
    
    // Keep last 100 conversations
    if (history.size() > 100) {
        history.erase(history.begin());
    }
    
    storage->putWithDataChecksum(historyKey, history.dump());
}

//============================================================
//		GET PERSIONALITY TOKEN
//============================================================
std::string getTokenPersonality(const std::string& tokenID, Blockchain& blockchain) {
    if (!blockchain.getStorage()) return "nascent";
    
    auto storage = blockchain.getStorage();
    std::string historyKey = "ai_token:" + tokenID + ":history";
    
    std::string historyData;
    if (storage->getWithDataChecksum(historyKey, historyData)) {
        nlohmann::json history = nlohmann::json::parse(historyData);
        size_t interactions = history.size();
        
        if (interactions < 5) return "nascent";
        else if (interactions < 20) return "developing";
        else if (interactions < 50) return "mature";
        else return "evolved";
    }
    
    return "nascent";
}

//============================================================
// 		MenuIssueAI_Tokens
//============================================================
void menuIssueAI_Tokens(Wallet& wallet, std::mutex& coutMutex) {
    try {
        // terminal size (utils.h returns pair<int,int>)
        int rows = 24, cols = 80;
        {
            auto [c, r] = getTerminalSize();
            cols = c; rows = r;
        }

        // clear screen + header via our static ::displayOutput
        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[2J\033[1;1H");
        }
        ::displayOutput("╔════════════════════════════════════════════╗", rows, coutMutex);
        ::displayOutput("║     🤖 AI-ENRICHED TOKEN CREATION 🧠      ║", rows, coutMutex);
        ::displayOutput("╚════════════════════════════════════════════╝", rows, coutMutex);

        // --- Choose type ---  (keep original logic/UI)
        fmt::print("\n=== Issue AI-Enriched Token ===\n");
        fmt::print("1) SFT (Sentient Fungible Token)\n");
        fmt::print("2) NCFT (Neural Canvas Fungible Token)\n");

        int choice = 0;
        {
            std::string c = readLineTrimmed("Select [1/2]:", rows, coutMutex);
            choice = c.empty() ? 1 : std::stoi(c);
            if (choice != 1 && choice != 2) choice = 1;
        }

        // Oobabooga configuration defaults.
        OobaConfig cfg;
        {
            std::string baseUrl = readLineTrimmed("Oobabooga base URL (enter to use " + cfg.baseUrl + "):", rows, coutMutex);
            if (!baseUrl.empty()) cfg.baseUrl = baseUrl;

            std::string key = readLineTrimmed("API key (enter to use default " + cfg.apiKey + "):", rows, coutMutex);
            if (!key.empty()) cfg.apiKey = key;

            std::string maxTok = readLineTrimmed("max_new_tokens (enter to use default " + std::to_string(cfg.maxNewTokens) + "):", rows, coutMutex);
            if (!maxTok.empty()) cfg.maxNewTokens = std::stoi(maxTok);
        }

        // --- Common fields ---
        const bool isSFT = (choice == 1);
        fmt::print("\n-- {} fields --\n", isSFT ? "SFT" : "NCFT");

        const std::string tokenID = readLineTrimmed("tokenID (any unique id):", rows, coutMutex);
        if (tokenID.empty()) throw std::runtime_error("tokenID is required");

        const std::string name        = readLineTrimmed("name:", rows, coutMutex);
        const std::string description = readLineTrimmed("description (human text):", rows, coutMutex);
        const std::string imageUrl    = readLineTrimmed("image/media URL (optional):", rows, coutMutex);

        std::string txid;

        if (isSFT) {
            // SFT specifics
            std::string supplyStr = readLineTrimmed("total supply (e.g., 1000000):", rows, coutMutex);
            if (supplyStr.empty()) throw std::runtime_error("total supply is required");
            uint64_t totalSupply = std::stoull(supplyStr);

            std::string symbol = readLineTrimmed("symbol (e.g., TAC):", rows, coutMutex);
            if (symbol.empty()) symbol = "SFT";

            std::string decimalsStr = readLineTrimmed("decimals (e.g., 2):", rows, coutMutex);
            uint32_t decimals = decimalsStr.empty() ? 2u : static_cast<uint32_t>(std::stoul(decimalsStr));

            if (!askYesNo("Proceed to call Oobabooga and issue SFT?", rows, coutMutex, true)) {
                fmt::print("Cancelled.\n");
                return;
            }

            txid = createSFTWithOoba(
                wallet, cfg, tokenID, totalSupply, name, symbol, description, imageUrl, decimals
            );

            std::map<std::string,std::string> details{
                {"Name", name},
                {"Symbol", symbol},
                {"Decimals", std::to_string(decimals)},
                {"Total Supply", supplyStr}
            };
            if (!imageUrl.empty()) details["Image"] = imageUrl;

            displayTokenCreationSuccess("SFT", txid, details, coutMutex);
        } else {
            // NCFT specifics
            std::string qtyStr = readLineTrimmed("quantity (e.g., 1000):", rows, coutMutex);
            if (qtyStr.empty()) throw std::runtime_error("quantity is required");
            uint64_t quantity = std::stoull(qtyStr);

            if (!askYesNo("Proceed to call Oobabooga and issue NCFT?", rows, coutMutex, true)) {
                fmt::print("Cancelled.\n");
                return;
            }

            txid = createNCFTWithOoba(
                wallet, cfg, tokenID, quantity, name, description, imageUrl
            );

            std::map<std::string,std::string> details{
                {"Name", name},
                {"Quantity", qtyStr}
            };
            if (!imageUrl.empty()) details["Media"] = imageUrl;

            displayTokenCreationSuccess("NCFT", txid, details, coutMutex);
        }

        fmt::print("\nIssued successfully. TXID: {}\n", txid);
        fmt::print("Press Enter to return to menu...");
        signalAwareIgnoreLine();

    } catch (const std::exception& e) {
        Logger::log(std::string("[menuIssueAI_Tokens] ERROR: ")+e.what());
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("{}\n", colorText(std::string("Issuance failed: ")+e.what(), 91, true));
        fmt::print("Press Enter to return...");
        signalAwareIgnoreLine();
    }
}


//============================================================================================
// TOKEN-AI-03A — AI Evolution wallet menu / preview -> explicit exact commit
//============================================================================================
// This is a wallet UX surface over the already-hardened TOKEN_EVOLUTION engine.
// It does not implement a new evolution state machine and does not bypass the
// TOKEN-AI-02A atomic persistence / queue path.
static constexpr const char* TRU_TOKEN_EVOLUTION_UI_DISCLAIMER =
    "Evolved metadata is an off-chain record. Its provenance chain is anchored on-chain\n"
    "and verifiable against the anchor. The chain proves what was recorded and when;\n"
    "it does not establish that an AI-generated claim is true.";

struct TruEvolutionWalletToken {
    std::string tokenID;
    std::string tokenType;
    std::string name;
    std::string issuanceTxid;
    nlohmann::json issuanceMetadata = nlohmann::json::object();
};

static bool truEvolutionUiCanonicalTokenID(const std::string& tokenID) {
    if (tokenID.size() != 8U && tokenID.size() != 16U) return false;
    for (const char c : tokenID) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static std::string truEvolutionUiSafeLabel(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        // Terminal labels never need raw control bytes. JSON detail views use
        // nlohmann::json::dump(), which escapes embedded controls itself.
        if (c >= 0x20U && c != 0x7fU) out.push_back(static_cast<char>(c));
        else out.push_back(' ');
    }
    return out;
}

static void truEvolutionUiRegisterProviders() {
    auto& registry = AIProviderRegistry::getInstance();
    const auto available = registry.getAvailableProviders();
    const std::set<std::string> existing(available.begin(), available.end());

    // Never overwrite an already-registered/configured provider instance.
    if (!existing.count("oobabooga")) registry.registerProvider("oobabooga", makeOobaboogaProvider());
    if (!existing.count("nemotron"))  registry.registerProvider("nemotron",  makeNemotronProvider());
    if (!existing.count("ollama"))    registry.registerProvider("ollama",    makeOllamaProvider());
    if (!existing.count("openai"))    registry.registerProvider("openai",    makeOpenAIProvider());
    if (!existing.count("anthropic")) registry.registerProvider("anthropic", makeAnthropicProvider());
    if (!existing.count("grok"))      registry.registerProvider("grok",      makeGrokProvider());
    if (!existing.count("gemini"))    registry.registerProvider("gemini",    makeGeminiProvider());
    if (!existing.count("custom"))    registry.registerProvider("custom",    makeCustomProvider());
}

static bool truEvolutionUiLoadIssuanceMetadata(
    LevelDBStorage& storage,
    const std::string& tokenID,
    std::string& tokenType,
    std::string& issuanceTxid,
    nlohmann::json& issuanceMetadata,
    std::string& displayName,
    std::string& error)
{
    tokenType.clear();
    issuanceTxid.clear();
    issuanceMetadata = nlohmann::json::object();
    displayName = tokenID;
    error.clear();

    if (!truEvolutionUiCanonicalTokenID(tokenID)) {
        error = "non-canonical token ID";
        return false;
    }

    if (!storage.getWithDataChecksum("tokenIssuance:" + tokenID, issuanceTxid) ||
        issuanceTxid.size() != 64U)
    {
        error = "missing or invalid tokenIssuance mapping";
        return false;
    }

    std::string raw;
    if (!storage.getWithDataChecksum("tokenMetadata:" + issuanceTxid, raw)) {
        error = "missing issuance tokenMetadata";
        return false;
    }

    try {
        const auto stored = nlohmann::json::parse(raw);
        if (!stored.is_object()) {
            error = "issuance tokenMetadata is not an object";
            return false;
        }

        tokenType = stored.value("type", "");
        if (tokenType != "SFT" && tokenType != "NCFT") {
            error = "token is not SFT/NCFT";
            return false;
        }

        if (stored.contains("meta") && stored["meta"].is_object()) {
            issuanceMetadata = stored["meta"];
        }

        // Keep this canonical issuance-root loader aligned with the standalone
        // token evolution CLI / TOKEN-AI-02D verifier.
        for (const char* key : {"name", "symbol", "description", "image", "imageUrl"}) {
            if (stored.contains(key) && !issuanceMetadata.contains(key)) {
                issuanceMetadata[key] = stored[key];
            }
        }

        if (issuanceMetadata.contains("name") && issuanceMetadata["name"].is_string()) {
            displayName = issuanceMetadata["name"].get<std::string>();
        } else if (stored.contains("name") && stored["name"].is_string()) {
            displayName = stored["name"].get<std::string>();
        }

        displayName = truEvolutionUiSafeLabel(displayName);
        return true;
    } catch (const std::exception& e) {
        error = std::string("invalid issuance tokenMetadata JSON: ") + e.what();
        return false;
    }
}

static std::vector<TruEvolutionWalletToken> truEvolutionUiOwnedTokens(Wallet& wallet) {
    std::vector<TruEvolutionWalletToken> result;

    Blockchain& chain = const_cast<Blockchain&>(wallet.getBlockchain());
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) return result;

    const auto addresses = wallet.getAllAddresses();
    const std::unordered_set<std::string> myAddresses(addresses.begin(), addresses.end());
    std::set<std::string> seenTokenIDs;

    // Confirmed/current ownership only: tokenUTXO index entry PLUS the matching
    // live confirmed utxo:<txid>:<vout>. Historical/spent token indexes are not
    // eligible to authorize a wallet evolution commit.
    storage->iteratePrefix("tokenUTXO:", [&](const std::string& key, const std::string& value) {
        const auto colon = key.find(':');
        if (colon == std::string::npos) return;

        const std::string txid = key.substr(0, colon);
        const std::string voutText = key.substr(colon + 1U);
        if (txid.size() != 64U || voutText.empty()) return;

        uint32_t vout = 0;
        try {
            const unsigned long parsed = std::stoul(voutText);
            if (parsed > std::numeric_limits<uint32_t>::max()) return;
            vout = static_cast<uint32_t>(parsed);
        } catch (...) {
            return;
        }

        if (!storage->exists("utxo:" + txid + ":" + std::to_string(vout))) return;

        try {
            const auto indexed = nlohmann::json::parse(value);
            if (!indexed.is_object() ||
                !indexed.contains("tokenID") || !indexed["tokenID"].is_string() ||
                !indexed.contains("owner") || !indexed["owner"].is_string())
            {
                return;
            }

            const std::string owner = indexed["owner"].get<std::string>();
            if (!myAddresses.count(owner)) return;

            if (indexed.contains("controllingVout")) {
                try {
                    if (indexed["controllingVout"].get<uint32_t>() != vout) return;
                } catch (...) {
                    return;
                }
            }

            const std::string tokenID = indexed["tokenID"].get<std::string>();
            if (!truEvolutionUiCanonicalTokenID(tokenID) || seenTokenIDs.count(tokenID)) return;

            TruEvolutionWalletToken token;
            token.tokenID = tokenID;
            std::string loadError;
            if (!truEvolutionUiLoadIssuanceMetadata(
                    *storage,
                    tokenID,
                    token.tokenType,
                    token.issuanceTxid,
                    token.issuanceMetadata,
                    token.name,
                    loadError))
            {
                Logger::log("[TOKEN-AI-03A] Skipping token=" + tokenID + " reason=" + loadError);
                return;
            }

            seenTokenIDs.insert(tokenID);
            result.push_back(std::move(token));
        } catch (...) {
            return;
        }
    });

    std::sort(result.begin(), result.end(),
              [](const TruEvolutionWalletToken& a, const TruEvolutionWalletToken& b) {
                  return a.tokenID < b.tokenID;
              });
    return result;
}

static bool truEvolutionUiStillOwnsToken(
    Wallet& wallet,
    const TruEvolutionWalletToken& selected)
{
    const auto current = truEvolutionUiOwnedTokens(wallet);
    for (const auto& token : current) {
        if (token.tokenID == selected.tokenID &&
            token.issuanceTxid == selected.issuanceTxid &&
            token.tokenType == selected.tokenType)
        {
            return true;
        }
    }
    return false;
}

static bool truEvolutionUiPreviewParentStillCurrent(
    const nlohmann::json& latest,
    const nlohmann::json& previewRecord,
    std::string& reason)
{
    reason.clear();
    if (!previewRecord.is_object()) {
        reason = "preview record is malformed";
        return false;
    }

    const std::string tokenID = previewRecord.value("tokenID", "");
    const std::string expectedHash =
        previewRecord.value("previous_metadata_hash", "");
    uint64_t expectedEpoch = 0;
    try {
        expectedEpoch = previewRecord.at("epoch_before").get<uint64_t>();
    } catch (...) {
        reason = "preview parent epoch is malformed";
        return false;
    }

    // The caller must supply a freshly loaded TOKEN_EVOLUTION latest record.
    // Keeping the actual load at the action boundary makes ordering testable.

    if (expectedEpoch == 0U) {
        if (!latest.empty()) {
            reason = "persisted evolution history appeared after this preview";
            return false;
        }
        return true;
    }

    if (!latest.is_object() || latest.empty()) {
        reason = "persisted parent evolution is missing";
        return false;
    }

    uint64_t currentEpoch = 0;
    try {
        currentEpoch = latest.at("epoch_after").get<uint64_t>();
    } catch (...) {
        reason = "persisted parent epoch is malformed";
        return false;
    }

    const std::string currentHash = latest.value("new_metadata_hash", "");
    if (currentEpoch != expectedEpoch || currentHash != expectedHash) {
        reason = "persisted parent epoch/hash changed";
        return false;
    }

    return true;
}

static bool truEvolutionUiPreviewHasEffectiveChange(
    TokenEvolutionEngine& engine,
    const TruEvolutionWalletToken& token,
    const nlohmann::json& previewRecord)
{
    if (!previewRecord.is_object() ||
        !previewRecord.contains("updated_fields") ||
        !previewRecord["updated_fields"].is_object())
    {
        return false;
    }

    uint64_t parentEpoch = 0;
    try {
        parentEpoch = previewRecord.at("epoch_before").get<uint64_t>();
    } catch (...) {
        return false;
    }

    nlohmann::json parentMetadata;
    if (parentEpoch == 0U) {
        parentMetadata = token.issuanceMetadata;
        parentMetadata["evolution_epoch"] = "0";
    } else {
        const nlohmann::json latest = engine.loadLatest(token.tokenID);
        if (!latest.is_object() || !latest.contains("metadata") ||
            !latest["metadata"].is_object())
        {
            return false;
        }
        parentMetadata = latest["metadata"];
    }

    const std::string provider = previewRecord.value("provider", "");
    const nlohmann::json normalized =
        engine.normalizeMetadata(token.tokenType, parentMetadata, provider);
    const nlohmann::json& updates = previewRecord["updated_fields"];

    // Compare accepted allow-listed values after normalization/merge semantics.
    // A returned key whose value is byte-for-byte/JSON-equivalent to the
    // current value is not an evolution, even though it is an allowed key.
    for (auto it = updates.begin(); it != updates.end(); ++it) {
        if (!normalized.contains(it.key()) || normalized[it.key()] != it.value()) {
            return true;
        }
    }
    return false;
}

static bool truEvolutionUiPreviousAnchorConfirmed(
    Blockchain& chain,
    TokenEvolutionEngine& engine,
    const TruEvolutionWalletToken& token,
    const nlohmann::json& previewRecord,
    std::string& reason)
{
    reason.clear();

    uint64_t parentEpoch = 0;
    try {
        parentEpoch = previewRecord.at("epoch_before").get<uint64_t>();
    } catch (...) {
        reason = "preview parent epoch is malformed";
        return false;
    }

    // Epoch 1 is rooted directly in the already-confirmed issuance metadata;
    // there is no prior evolution anchor to wait for.
    if (parentEpoch == 0U) return true;

    const nlohmann::json history =
        engine.verifyHistory(token.tokenID, token.issuanceMetadata);
    if (!history.is_object() || !history.value("ok", false) ||
        !history.contains("epochs") || !history["epochs"].is_array())
    {
        reason = "prior evolution history is not internally verifiable";
        return false;
    }

    std::string anchorTxid;
    bool foundParent = false;
    for (const auto& epochReport : history["epochs"]) {
        if (!epochReport.is_object() ||
            epochReport.value("epoch", 0ULL) != parentEpoch)
        {
            continue;
        }

        foundParent = true;
        anchorTxid = epochReport.value("anchor_txid", "");
        break;
    }

    if (!foundParent || anchorTxid.size() != 64U) {
        reason = "previous evolution epoch has no submitted anchor transaction";
        return false;
    }

    // Blockchain::getTransaction() searches the active confirmed block chain,
    // not the mempool.  Therefore success here is the one-confirmed-anchor-
    // behind gate, not merely evidence that a receipt/watch entry exists.
    Transaction confirmedAnchor;
    if (!chain.getTransaction(anchorTxid, confirmedAnchor) ||
        confirmedAnchor.txid != anchorTxid)
    {
        reason = "previous evolution anchor is not confirmed on the active chain";
        return false;
    }

    return true;
}

static std::string truEvolutionUiTransactionStatus(
    Blockchain& chain,
    const std::string& txid)
{
    if (txid.size() != 64U) return "MISSING";

    Transaction confirmed;
    if (chain.getTransaction(txid, confirmed) && confirmed.txid == txid) {
        return "CONFIRMED";
    }

    const auto mempool = chain.getMempoolTransactions();
    for (const auto& tx : mempool) {
        if (tx.txid == txid) return "MEMPOOL";
    }
    return "MISSING";
}

static void truEvolutionUiShowTokenHistory(
    Wallet& wallet,
    int rows,
    std::mutex& coutMutex)
{
    const std::string tokenID = readLineTrimmed(
        "TokenID (8/16 lowercase hex, 0=cancel):", rows, coutMutex);
    if (tokenID.empty() || tokenID == "0" || tokenID == "back") return;

    if (!truEvolutionUiCanonicalTokenID(tokenID)) {
        displayResult("Invalid canonical token ID.", rows, coutMutex, 91);
        (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
        return;
    }

    Blockchain& chain = const_cast<Blockchain&>(wallet.getBlockchain());
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        displayResult("Storage unavailable; history lookup refused.", rows, coutMutex, 91);
        (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
        return;
    }

    std::string tokenType;
    std::string issuanceTxid;
    nlohmann::json issuanceMetadata;
    std::string displayName;
    std::string loadError;
    if (!truEvolutionUiLoadIssuanceMetadata(
            *storage,
            tokenID,
            tokenType,
            issuanceTxid,
            issuanceMetadata,
            displayName,
            loadError))
    {
        displayResult(
            "Token history unavailable: " + loadError,
            rows, coutMutex, 91);
        (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
        return;
    }

    ContractStorage contractStorage(storage);
    TokenEvolutionEngine engine(&contractStorage);
    const nlohmann::json history = engine.verifyHistory(tokenID, issuanceMetadata);

    const std::string issuanceStatus =
        truEvolutionUiTransactionStatus(chain, issuanceTxid);

    std::ostringstream report;
    report
        << "=== TOKEN-CENTRIC EVOLUTION HISTORY ===\n"
        << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
        << "Token       : " << tokenID << "\n"
        << "Name        : " << truEvolutionUiSafeLabel(displayName) << "\n"
        << "Type        : " << tokenType << "\n"
        << "Issuance TX : " << issuanceTxid << "\n"
        << "Issuance    : " << issuanceStatus << "\n"
        << "Root verify : " << (history.value("root_verified", false) ? "VERIFIED" : "FAILED") << "\n"
        << "History     : " << (history.value("ok", false) ? "VERIFIED" : "FAILED") << "\n"
        << "Epochs      : " << history.value("verified_epochs", 0ULL) << " verified\n"
        << "Anchoring   : " << (history.value("fully_anchored", false) ? "FULLY SUBMITTED" : "PENDING/INCOMPLETE") << "\n\n";

    if (history.contains("errors") && history["errors"].is_array() &&
        !history["errors"].empty())
    {
        report << "Verification errors:\n";
        for (const auto& error : history["errors"]) {
            if (error.is_string()) {
                report << "  - " << truEvolutionUiSafeLabel(error.get<std::string>()) << "\n";
            }
        }
        report << "\n";
    }

    if (!history.contains("epochs") || !history["epochs"].is_array() ||
        history["epochs"].empty())
    {
        report << "No persisted evolution epochs. Issuance metadata is the history root.\n";
    } else {
        report << "=== EPOCH LINEAGE ===\n";
        for (const auto& epoch : history["epochs"]) {
            if (!epoch.is_object()) continue;

            const uint64_t epochNumber = epoch.value("epoch", 0ULL);
            const std::string anchorTxid = epoch.value("anchor_txid", "");
            std::string chainStatus = "PENDING";
            if (!anchorTxid.empty()) {
                chainStatus = truEvolutionUiTransactionStatus(chain, anchorTxid);
            } else if (epoch.value("anchor_status", "") != "QUEUED_PENDING" &&
                       epoch.value("anchor_status", "") != "PREPARED_PENDING") {
                chainStatus = "MISSING";
            }

            report
                << "\nEpoch " << epochNumber << "\n"
                << "  Integrity       : " << (epoch.value("integrity", false) ? "VERIFIED" : "FAILED") << "\n"
                << "  Record format   : V" << epoch.value("record_format_version", 1ULL) << "\n"
                << "  Writer type     : " << truEvolutionUiSafeLabel(epoch.value("writer_type", "")) << "\n"
                << "  Provider        : " << truEvolutionUiSafeLabel(epoch.value("provider", "")) << "\n"
                << "  Provider version: " << truEvolutionUiSafeLabel(epoch.value("provider_version", "")) << "\n"
                << "  Model ID        : " << truEvolutionUiSafeLabel(epoch.value("model_id", "")) << "\n"
                << "  Trigger         : " << truEvolutionUiSafeLabel(epoch.value("trigger", "")) << "\n"
                << "  Timestamp       : " << epoch.value("timestamp", 0ULL) << "\n"
                << "  Parent hash     : " << epoch.value("previous_metadata_hash", "") << "\n"
                << "  Metadata hash   : " << epoch.value("new_metadata_hash", "") << "\n"
                << "  Input meta hash : " << epoch.value("input_metadata_hash", "") << "\n"
                << "  Request hash    : " << epoch.value("request_hash", "") << "\n"
                << "  Record hash     : " << epoch.value("record_hash", "") << "\n"
                << "  Local anchor    : " << epoch.value("anchor_status", "UNKNOWN") << "\n"
                << "  Anchor TX       : " << (anchorTxid.empty() ? "(not submitted)" : anchorTxid) << "\n"
                << "  Chain status    : " << chainStatus << "\n";
        }
    }

    report
        << "\nHistory is token-centric and remains attached to the token across ownership transfers.\n"
        << "03B verifies durable lineage and reports anchor observability.\n"
        << "Exact on-chain anchor payload verification remains the 03D verification surface.";

    // TOKEN-AI-03B1: history reports can exceed the generic result viewport.
    // Page the report inside the owned result region and keep the navigation
    // prompt in the normal bottom command lane.  This avoids the mid-screen
    // INPUT REQUIRED card covering history fields.
    std::vector<std::string> historyLines;
    {
        std::istringstream input(report.str());
        std::string line;
        while (std::getline(input, line)) historyLines.push_back(line);
        if (historyLines.empty()) historyLines.push_back("");
    }

    const int historyCapacity = std::max(
        1, truResultLastRow(rows) - truResultFirstRow() + 1);
    const std::size_t historyPageSize =
        static_cast<std::size_t>(historyCapacity);
    const std::size_t historyPageCount = std::max<std::size_t>(
        1, (historyLines.size() + historyPageSize - 1) / historyPageSize);

    for (std::size_t page = 0; page < historyPageCount; ++page) {
        const std::size_t begin = page * historyPageSize;
        const std::size_t end =
            std::min(historyLines.size(), begin + historyPageSize);

        // ANSI 96 is foreground cyan.  03B accidentally used ANSI 100, which
        // is a bright-black BACKGROUND code and produced gray/white blocks.
        displayResult(joinReceiptLines(historyLines, begin, end), rows, coutMutex, 96);

        const std::string pagePrompt =
            "History page " + std::to_string(page + 1) + "/" +
            std::to_string(historyPageCount) +
            (page + 1 < historyPageCount
                ? " - Enter for next page..."
                : " - Enter to return to AI Evolution menu...");

        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[{};1H\033[K  {}",
                       truMenuPromptRow(rows), colorText(pagePrompt, 33));
            fmt::print("\033[{};1H\033[K", truHeartbeatRow(rows));
            const int syncRow = truTopLevelSyncRow(rows);
            if (syncRow > 0) {
                fmt::print("\033[{};1H\033[K  {}",
                           syncRow, colorText("[SYNC] " + getCliSyncStatusSnapshot(), 90));
            }
            fmt::print("\033[{};{}H",
                       truMenuPromptRow(rows),
                       static_cast<int>(pagePrompt.size()) + 3);
            std::cout.flush();
        }

        // Classify this wait as bottom-lane input so asynchronous sync updates
        // stay in the bottom sync lane instead of repainting the mid-screen
        // nested-input card.
        TruCliMenuPromptGuard historyPromptGuard;
        signalAwareIgnoreLine();
    }
}

static void menuTokenEvolution(Wallet& wallet, int rows, std::mutex& coutMutex) {
    struct PreviewState {
        bool valid{false};
        TruEvolutionWalletToken token;
        TokenEvolutionResult result;
        std::string provider;
        std::string trigger;
    } preview;

    truEvolutionUiRegisterProviders();

    while (g_running) {
        auto [termRows, termCols] = g_terminalSize.get();
        (void)termCols;
        rows = std::max(20, termRows);

        std::ostringstream menu;
        menu
            << "=== TOKEN / AI TOOLS — AI EVOLUTION ===\n"
            << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
            << "1. Preview AI Evolution\n"
            << "2. Commit Exact Preview";
        if (preview.valid) {
            menu << "  [READY: token " << preview.token.tokenID
                 << " epoch " << preview.result.record.value("epoch_after", 0ULL) << "]";
        }
        menu << "\n3. View Token History\n"
             << "0. Back\n\n"
             << "Preview makes an AI call but writes no TOKEN_EVOLUTION state.\n"
             << "Commit persists the exact preview; it never makes a second AI call.\n"
             << "History is token-centric and does not require current wallet ownership.";

        displayResult(menu.str(), rows, coutMutex, 96);
        const std::string action = readLineTrimmed("Select [0/1/2/3]:", rows, coutMutex);

        if (action == "0" || action == "back" || action == "q") return;

        if (action == "3") {
            truEvolutionUiShowTokenHistory(wallet, rows, coutMutex);
            continue;
        }

        if (action == "1") {
            const auto tokens = truEvolutionUiOwnedTokens(wallet);
            if (tokens.empty()) {
                displayResult(
                    std::string("AI Evolution requires a wallet-owned, currently confirmed SFT or NCFT.\n") +
                    TRU_TOKEN_EVOLUTION_UI_DISCLAIMER,
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            std::ostringstream tokenReport;
            tokenReport << "=== CONFIRMED WALLET SFT / NCFT ===\n"
                        << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n";
            for (size_t i = 0; i < tokens.size(); ++i) {
                tokenReport
                    << (i + 1U) << ". " << tokens[i].name
                    << "  [" << tokens[i].tokenType << "]\n"
                    << "   TokenID : " << tokens[i].tokenID << "\n"
                    << "   Issuance: " << tokens[i].issuanceTxid << "\n";
            }
            tokenReport << "\n0. Cancel";
            displayResult(tokenReport.str(), rows, coutMutex, 96);

            const std::string selection = readLineTrimmed("Select token number:", rows, coutMutex);
            if (selection == "0" || selection == "back" || selection.empty()) continue;

            size_t tokenIndex = 0;
            try {
                const unsigned long parsed = std::stoul(selection);
                if (parsed == 0U || parsed > tokens.size()) throw std::out_of_range("selection");
                tokenIndex = static_cast<size_t>(parsed - 1U);
            } catch (...) {
                displayResult("Invalid token selection.", rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            const TruEvolutionWalletToken selected = tokens[tokenIndex];

            const std::vector<std::string> providers = {
                "nemotron", "oobabooga", "ollama", "openai",
                "anthropic", "grok", "gemini", "custom"
            };

            std::ostringstream providerReport;
            providerReport << "=== AI PROVIDER ===\n";
            for (size_t i = 0; i < providers.size(); ++i) {
                providerReport << (i + 1U) << ". " << providers[i];
                if (i == 0U) providerReport << "  [default]";
                providerReport << "\n";
            }
            providerReport << "\n0. Cancel";
            displayResult(providerReport.str(), rows, coutMutex, 96);

            std::string providerSelection = readLineTrimmed(
                "Select provider [Enter=1]:", rows, coutMutex);
            if (providerSelection.empty()) providerSelection = "1";
            if (providerSelection == "0" || providerSelection == "back") continue;

            size_t providerIndex = 0;
            try {
                const unsigned long parsed = std::stoul(providerSelection);
                if (parsed == 0U || parsed > providers.size()) throw std::out_of_range("provider");
                providerIndex = static_cast<size_t>(parsed - 1U);
            } catch (...) {
                displayResult("Invalid provider selection.", rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            std::string trigger = readLineTrimmed(
                "Evolution trigger/reason [Enter=manual]:", rows, coutMutex);
            if (trigger.empty()) trigger = "manual";

            // Re-prove current confirmed ownership immediately before the AI call.
            if (!truEvolutionUiStillOwnsToken(wallet, selected)) {
                preview.valid = false;
                displayResult(
                    "Token ownership changed before preview; refusing stale selection.",
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            Blockchain& chain = const_cast<Blockchain&>(wallet.getBlockchain());
            LevelDBStorage* storage = chain.getStorage();
            if (!storage) {
                preview.valid = false;
                displayResult("Storage unavailable; preview refused.", rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            ContractStorage contractStorage(storage);
            TokenEvolutionEngine engine(&contractStorage);

            // TOKEN-AI-03A1: when option 1 is being used to regenerate a
            // preview for the same token, reject a moved parent BEFORE another
            // provider call is spent.  evolvePreview() independently performs
            // its own fresh latest-state load as well.
            if (preview.valid && preview.token.tokenID == selected.tokenID) {
                const nlohmann::json latestBeforeRegenerate =
                    engine.loadLatest(selected.tokenID);
                std::string freshnessReason;
                if (!truEvolutionUiPreviewParentStillCurrent(
                        latestBeforeRegenerate, preview.result.record, freshnessReason))
                {
                    preview.valid = false;
                    displayResult(
                        "State moved since this preview was created.\n"
                        "Re-run Preview from the current token state.\n"
                        "No AI provider call was made.\nReason: " + freshnessReason,
                        rows, coutMutex, 91);
                    (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                    continue;
                }
            }

            displayResult(
                "Generating constrained AI evolution preview...\nNo TOKEN_EVOLUTION state is being written.",
                rows, coutMutex, 93);

            TokenEvolutionResult generated = engine.evolvePreview(
                selected.tokenID,
                selected.tokenType,
                selected.issuanceMetadata,
                providers[providerIndex],
                trigger);

            if (!generated.ok) {
                preview.valid = false;
                displayResult(
                    "AI Evolution preview failed:\n" + generated.error,
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            preview.valid = true;
            preview.token = selected;
            preview.result = std::move(generated);
            preview.provider = providers[providerIndex];
            preview.trigger = trigger;

            const auto& record = preview.result.record;
            std::ostringstream report;
            report
                << "=== AI EVOLUTION PREVIEW — NOT COMMITTED ===\n"
                << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
                << "Token       : " << preview.token.tokenID << "\n"
                << "Type        : " << preview.token.tokenType << "\n"
                << "Provider    : " << preview.provider << "\n"
                << "Trigger     : " << truEvolutionUiSafeLabel(preview.trigger) << "\n"
                << "Epoch       : " << record.value("epoch_before", 0ULL)
                << " -> " << record.value("epoch_after", 0ULL) << "\n"
                << "PreviousHash: " << record.value("previous_metadata_hash", "") << "\n"
                << "NewHash     : " << record.value("new_metadata_hash", "") << "\n\n"
                << "Allowed updates:\n" << record.value("updated_fields", nlohmann::json::object()).dump(2)
                << "\n\nResulting metadata:\n" << record.value("metadata", nlohmann::json::object()).dump(2)
                << "\n\nNothing above has been persisted. Choose option 2 to commit THIS exact preview.";
            displayResult(report.str(), rows, coutMutex, 96);
            (void)readLineTrimmed("Press Enter to return to AI Evolution menu:", rows, coutMutex);
            continue;
        }

        if (action == "2") {
            if (!preview.valid || !preview.result.ok || !preview.result.record.is_object()) {
                displayResult(
                    "No valid in-memory preview is ready. Run option 1 first.",
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            const auto& record = preview.result.record;
            std::ostringstream commitReport;
            commitReport
                << "=== COMMIT EXACT AI EVOLUTION PREVIEW ===\n"
                << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
                << "Token       : " << preview.token.tokenID << "\n"
                << "Type        : " << preview.token.tokenType << "\n"
                << "Provider    : " << preview.provider << "\n"
                << "Epoch       : " << record.value("epoch_before", 0ULL)
                << " -> " << record.value("epoch_after", 0ULL) << "\n"
                << "PreviousHash: " << record.value("previous_metadata_hash", "") << "\n"
                << "NewHash     : " << record.value("new_metadata_hash", "") << "\n\n"
                << "This persists the exact preview and atomically queues its anchor.\n"
                << "It does NOT call the AI provider again.\n\n"
                << "Type COMMIT exactly to continue; anything else cancels.";
            displayResult(commitReport.str(), rows, coutMutex, 93);

            std::string confirmation;
            displayPrompt("Confirmation: ", rows, coutMutex);
            signalAwareGetline(confirmation);
            if (confirmation != "COMMIT") {
                displayResult("Commit cancelled; in-memory preview retained.", rows, coutMutex, 90);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            Blockchain& chain = const_cast<Blockchain&>(wallet.getBlockchain());
            LevelDBStorage* storage = chain.getStorage();
            if (!storage) {
                preview.valid = false;
                displayResult(
                    "COMMIT REFUSED: storage unavailable. Preview invalidated.",
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            ContractStorage contractStorage(storage);
            TokenEvolutionEngine engine(&contractStorage);

            // TOKEN-AI-03A1 ORDERING INVARIANT:
            // exact COMMIT -> fresh loadLatest -> parent epoch/hash check ->
            // confirmed-parent anchor gate -> ownership re-proof -> persist.
            // TOKEN-AI-02A then independently re-checks lineage atomically.
            const nlohmann::json latestAtCommit =
                engine.loadLatest(preview.token.tokenID);
            std::string freshnessReason;
            if (!truEvolutionUiPreviewParentStillCurrent(
                    latestAtCommit, preview.result.record, freshnessReason))
            {
                preview.valid = false;
                displayResult(
                    "COMMIT REFUSED: State moved. Re-run preview.\n"
                    "Nothing was persisted or anchored.\nReason: " + freshnessReason,
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            std::string anchorReason;
            if (!truEvolutionUiPreviousAnchorConfirmed(
                    chain, engine, preview.token, preview.result.record, anchorReason))
            {
                displayResult(
                    "COMMIT REFUSED: Previous evolution epoch is not yet confirmed on-chain.\n"
                    "Preview is allowed; commit is temporarily unavailable.\n"
                    "The in-memory preview has been retained.\nReason: " + anchorReason,
                    rows, coutMutex, 93);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            // Authorization is deliberately checked AFTER freshness so a moved
            // parent and lost ownership remain distinct user-visible failures.
            if (!truEvolutionUiStillOwnsToken(wallet, preview.token)) {
                preview.valid = false;
                displayResult(
                    "COMMIT REFUSED: You no longer own this token.\n"
                    "Nothing was persisted or anchored. The preview has been invalidated.",
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            if (!truEvolutionUiPreviewHasEffectiveChange(
                    engine, preview.token, preview.result.record))
            {
                preview.valid = false;
                displayResult(
                    "AI proposed no permitted metadata changes; nothing committed.\n"
                    "No epoch was consumed, no anchor was queued, and no fee was incurred.",
                    rows, coutMutex, 93);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            // TOKEN-AI-02A persistPreview() is the authority here. It rejects
            // duplicate/stale epochs, broken hash lineage, queue overflow and
            // any non-atomic persistence outcome. The UI never rebuilds or
            // regenerates the record after the user's COMMIT confirmation.
            const nlohmann::json exactPreview = preview.result.record;
            if (!engine.persistPreview(exactPreview)) {
                preview.valid = false;
                displayResult(
                    "COMMIT FAILED CLOSED.\n"
                    "The preview was not acknowledged as persisted and has been invalidated.\n"
                    "Generate a fresh preview before trying again.",
                    rows, coutMutex, 91);
                (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
                continue;
            }

            const uint64_t committedEpoch = exactPreview.value("epoch_after", 0ULL);
            const std::string committedHash = exactPreview.value("new_metadata_hash", "");
            preview.valid = false; // prevents accidental duplicate commit from the UI

            std::ostringstream success;
            success
                << "=== AI EVOLUTION COMMIT ACCEPTED ===\n"
                << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
                << "Token    : " << exactPreview.value("tokenID", "") << "\n"
                << "Epoch    : " << committedEpoch << "\n"
                << "Meta Hash: " << committedHash << "\n\n"
                << "TOKEN-AI-02A atomically persisted epoch/latest/anchor_queue.\n"
                << "TOKEN-AI-02B2/B3 will prepare, submit, watch, and recover the exact anchor.\n"
                << "Confirmation is NOT claimed here; verify the anchor separately.";
            displayResult(success.str(), rows, coutMutex, 92);
            (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
            continue;
        }

        displayResult("Invalid AI Evolution option.", rows, coutMutex, 91);
        (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
    }
}

static void menuTokenAiTools(Wallet& wallet, int rows, std::mutex& coutMutex) {
    while (g_running) {
        std::ostringstream menu;
        menu
            << "=== TOKEN / AI TOOLS ===\n"
            << TRU_TOKEN_EVOLUTION_UI_DISCLAIMER << "\n\n"
            << "1. Create AI Token (SFT / NCFT)\n"
            << "2. AI Evolution\n"
            << "0. Back";
        displayResult(menu.str(), rows, coutMutex, 96);

        const std::string action = readLineTrimmed("Select [0/1/2]:", rows, coutMutex);
        if (action == "0" || action == "back" || action == "q") return;
        if (action == "1") {
            menuIssueAI_Tokens(wallet, coutMutex);
            continue;
        }
        if (action == "2") {
            menuTokenEvolution(wallet, rows, coutMutex);
            continue;
        }

        displayResult("Invalid TOKEN / AI TOOLS option.", rows, coutMutex, 91);
        (void)readLineTrimmed("Press Enter to continue:", rows, coutMutex);
    }
}

//=====================================================================
// Callback function for CURL to write data to a file
//=====================================================================
static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    FILE* fp = static_cast<FILE*>(userp);
    return fwrite(contents, size, nmemb, fp);
}
//=====================================================================
// Download image from URL and return the local file path
//=====================================================================
std::string downloadImage(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string tempFile = "/tmp/ipfs_image_" + std::to_string(std::time(nullptr)); // Unique temp file
    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to open temporary file");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        remove(tempFile.c_str()); // Clean up on failure
        throw std::runtime_error("Failed to download image: " + std::string(curl_easy_strerror(res)));
    }

    return tempFile;
}


//=====================================================================
// Upload image to IPFS and return the hash
//=====================================================================
std::string uploadToIPFS(const std::string& filePath, const std::string& ipfsApi = "") {
    std::string command;
    if (ipfsApi.empty()) {
        // Local IPFS node (default: localhost:5001)
        command = "ipfs add -Q \"" + filePath + "\"";
    } else {
        // Remote IPFS node with specified API
        command = "ipfs --api " + ipfsApi + " add -Q \"" + filePath + "\"";
    }

    // Execute the command and capture the output
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to run IPFS command");
    }

    char buffer[128];
    std::string ipfsHash;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        ipfsHash += buffer;
    }
    int status = pclose(pipe);

    if (status != 0) {
        throw std::runtime_error("IPFS upload failed with exit code: " + std::to_string(status));
    }

    // Remove trailing newline from the hash
    if (!ipfsHash.empty() && ipfsHash.back() == '\n') {
        ipfsHash.pop_back();
    }

    if (ipfsHash.empty()) {
        throw std::runtime_error("IPFS returned an empty hash");
    }

    return ipfsHash;
}
//=====================================================================
// A multi-line table that displays main fields plus selected metadata
// -------------------------------------------------------------------
// Creates a hex-encoded OP_RETURN script pubkey for token issuance
std::string createExtendedTokenScriptPubKeyHex_Main(
    const ExtendedTokenData& data,
    const std::string& ownerAddress)
{
    // TOKEN-AI-01B2: this historical Main helper must not maintain a second
    // token binary format. Delegate to the canonical tokens.cpp serializer,
    // which emits 16-hex / 64-bit IDs for V2 and retains legacy V1 support.
    return createExtendedTokenScriptPubKeyHex(data, ownerAddress);
}

//===================================================================================================
//                Parse Token Script
//===================================================================================================

bool parseExtendedTokenScript_Main(
    const std::string& scriptPubKeyHex,
    const std::string& txid,
    ExtendedTokenData& tokenData,
    std::string& ownerAddress,
    const Blockchain* blockchainPtr)
{
    // TOKEN-AI-01B2: one canonical parser. No independent 32-bit token-ID
    // decoder is allowed to drift inside main.cpp.
    return parseExtendedTokenScript(
        scriptPubKeyHex, txid, tokenData, ownerAddress, blockchainPtr);
}

//===================================================================================================
//				HELPER
//===================================================================================================
int getTypeColor(const std::string& type) {
    if (type == "FT") return 32;     // Green
    else if (type == "NFT") return 35; // Magenta
    else if (type == "SFT") return 33; // Yellow
    else if (type == "NCFT") return 36; // Cyan
    return 37; // Default white
}

//===================================================================================================
//                              HELPER
//===================================================================================================
std::string formatTokenAmount(uint64_t rawAmount, const std::unordered_map<std::string, std::string>& meta) {
    int decimals = 0;
    if (meta.count("decimals")) {
        try {
            decimals = std::stoi(meta.at("decimals"));
        } catch (const std::exception& ex) {
            Logger::log("[formatTokenAmount] Invalid decimals value: " + std::string(ex.what()));
        }
    }
    double displayAmount = static_cast<double>(rawAmount) / std::pow(10.0, decimals);
    std::ostringstream amountStream;
    amountStream << std::fixed << std::setprecision(decimals) << displayAmount;
    return amountStream.str();
}
//===================================================================================================
//                              FORMAT TABLE FOR TOKENS
//===================================================================================================
std::string formatTokenTable(const Wallet &wallet) {
    struct RawEntry {
        std::string owner;
        std::string tokenID;
        std::string txid;
        std::string type;
        uint32_t vout;
        uint64_t amount;
    };
    std::vector<RawEntry> rawEntries;

    // Gather wallet addresses
    auto addrs = wallet.getAllAddresses();
    std::unordered_set<std::string> myAddrs(addrs.begin(), addrs.end());
    Logger::log("[formatTokenTable] Found " + std::to_string(myAddrs.size()) + " wallet addresses");

    // Access storage
    const auto &chain = wallet.getBlockchain();
    const auto *storage = chain.getStorage();
    const std::string prefix = "tokenUTXO:";

    // Use a set to track processed tokens and avoid duplicates
    std::set<std::string> processedTokens;

    // Iterate over tokenUTXO entries
    storage->iteratePrefix(prefix, [&](const std::string &key, const std::string &val) {
        Logger::log("[formatTokenTable] Processing key: " + prefix + key);
        
        // Parse key correctly: key format is "txid:vout" (without prefix)
        size_t colonPos = key.find(':');
        if (colonPos == std::string::npos) {
            Logger::log("[formatTokenTable] ERROR: Invalid key format: " + key);
            return;
        }
        
        std::string txid = key.substr(0, colonPos);
        std::string voutStr = key.substr(colonPos + 1);
        uint32_t vout = 0;
        
        try {
            vout = static_cast<uint32_t>(std::stoul(voutStr));
            Logger::log("[formatTokenTable] Parsed txid: " + txid + ", vout: " + std::to_string(vout));
        } catch (const std::exception& ex) {
            Logger::log("[formatTokenTable] ERROR: Invalid vout: " + voutStr + ", " + ex.what());
            return;
        }

        // Check if txid is valid (should be 64 hex chars)
        if (txid.size() != 64 || !std::all_of(txid.begin(), txid.end(), ::isxdigit)) {
            Logger::log("[formatTokenTable] ERROR: Invalid txid format: " + txid);
            return;
        }

        try {
            auto j = nlohmann::json::parse(val);
            
            // Skip if this isn't a token UTXO (check for required fields)
            if (!j.contains("tokenID") || !j.contains("owner") || !j.contains("type")) {
                Logger::log("[formatTokenTable] Skipping non-token UTXO: " + key);
                return;
            }
            
            std::string owner = j["owner"].get<std::string>();
            if (!myAddrs.count(owner)) {
                Logger::log("[formatTokenTable] Skipping non-owned address: " + owner);
                return;
            }

            // tokenUTXO is a derived
            // current-ownership index.  Never display a record whose
            // controlling confirmed UTXO has already been spent.
            const std::string liveUtxoKey =
                "utxo:" + txid + ":" + std::to_string(vout);
            if (!storage->exists(liveUtxoKey)) {
                Logger::log("[formatTokenTable] Skipping stale/spent token index: " +
                            prefix + key);
                return;
            }
            
            // Check if this is the controlling output
            if (j.contains("controllingVout")) {
                uint32_t controllingVout = j["controllingVout"].get<uint32_t>();
                if (vout != controllingVout) {
                    Logger::log("[formatTokenTable] Skipping non-controlling output: vout=" + 
                               std::to_string(vout) + ", controlling=" + std::to_string(controllingVout));
                    return;
                }
            }

            // Create unique key to avoid duplicates
            std::string tokenID = j["tokenID"].get<std::string>();
            std::string uniqueKey = tokenID + ":" + txid + ":" + std::to_string(vout);
            if (processedTokens.count(uniqueKey)) {
                Logger::log("[formatTokenTable] Skipping duplicate token entry: " + uniqueKey);
                return;
            }
            processedTokens.insert(uniqueKey);

            RawEntry e;
            e.owner = owner;
            e.tokenID = tokenID;
            e.amount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
            e.type = j["type"].get<std::string>();
            e.txid = txid;
            e.vout = vout;

            Logger::log("[formatTokenTable] Added entry: tokenID=" + e.tokenID + ", txid=" + e.txid + ", owner=" + e.owner);
            rawEntries.push_back(e);
        } catch (const std::exception& ex) {
            Logger::log("[formatTokenTable] ERROR: JSON parsing failed: " + std::string(ex.what()));
        }
    });

    if (rawEntries.empty()) {
        Logger::log("[formatTokenTable] No token entries found");
        return colorText("🔗 No tokens owned by this wallet.\n", 31);
    }

    // Build table rows with metadata
    struct Row {
        std::string tokenID, type, owner, txid;
        uint64_t amount;
        std::unordered_map<std::string, std::string> meta;
    };
    std::vector<Row> rows;
    rows.reserve(rawEntries.size());

    for (const auto &e : rawEntries) {
        Row r{e.tokenID, e.type, e.owner, e.txid, e.amount, {}};
        
        // Fetch metadata using the full txid
        std::string metaKey = "tokenMetadata:" + e.txid;
        std::string metaVal;
        Logger::log("[formatTokenTable] Fetching metadata with key: " + metaKey);
        
        if (storage->getWithDataChecksum(metaKey, metaVal)) {
            try {
                auto jm = nlohmann::json::parse(metaVal);
                
                // Check if metadata has the new structure with "meta" field
                if (jm.contains("meta") && jm["meta"].is_object()) {
                    for (const auto &it : jm["meta"].items()) {
                        if (it.value().is_string()) {
                            r.meta[it.key()] = it.value().get<std::string>();
                        } else if (it.value().is_number()) {
                            r.meta[it.key()] = std::to_string(it.value().get<int>());
                        } else {
                            r.meta[it.key()] = it.value().dump();
                        }
                    }
                    Logger::log("[formatTokenTable] Metadata parsed successfully, found " + 
                               std::to_string(r.meta.size()) + " fields");
                }
            } catch (const std::exception& ex) {
                Logger::log("[formatTokenTable] ERROR: Metadata parsing failed: " + std::string(ex.what()));
                r.meta["name"] = "Unknown_" + e.tokenID;
                r.meta["description"] = "Metadata parsing error";
            }
        } else {
            Logger::log("[formatTokenTable] WARNING: Metadata not found for key: " + metaKey);
            // Try to fetch from issuance txid if this is a transfer
            std::string issuanceKey = "tokenIssuance:" + e.tokenID;
            std::string issuanceTxid;
            if (storage->getWithDataChecksum(issuanceKey, issuanceTxid)) {
                Logger::log("[formatTokenTable] Found issuance txid: " + issuanceTxid);
                std::string altMetaKey = "tokenMetadata:" + issuanceTxid;
                if (storage->getWithDataChecksum(altMetaKey, metaVal)) {
                    Logger::log("[formatTokenTable] Found metadata using issuance txid");
                    try {
                        auto jm = nlohmann::json::parse(metaVal);
                        if (jm.contains("meta") && jm["meta"].is_object()) {
                            for (const auto &it : jm["meta"].items()) {
                                if (it.value().is_string()) {
                                    r.meta[it.key()] = it.value().get<std::string>();
                                }
                            }
                        }
                    } catch (...) {}
                }
            }
            
            if (r.meta.empty()) {
                r.meta["name"] = "Token_" + e.tokenID;
                r.meta["description"] = "No metadata recorded";
            }
        }
        rows.push_back(r);
    }

    // Render table
    std::ostringstream oss;
    oss << colorText("⛓️════ MY TOKEN VAULT ════⛓️\n", 36, true)
        << colorText(fmt::format("{:<20} | {:<6} | {:>12} | {:<34} | {:<34} | {:<100}\n",
                                 "Token ID", "Type", "Amount", "Owner", "Txid", "Metadata"), 33)
        << colorText("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n", 36);

    for (const auto &r : rows) {
        std::string md;
        // Prioritize important metadata fields
        std::vector<std::string> priorityFields = {"name", "symbol", "decimals", "description"};
        for (const auto& field : priorityFields) {
            if (r.meta.count(field)) {
                if (!md.empty()) md += "; ";
                md += field + "=" + r.meta.at(field);
            }
        }
        // Add remaining fields if space permits
        for (const auto& [key, value] : r.meta) {
            if (std::find(priorityFields.begin(), priorityFields.end(), key) == priorityFields.end()) {
                if (md.size() < 80) { // Limit metadata display
                    if (!md.empty()) md += "; ";
                    md += key + "=" + value;
                }
            }
        }
        if (md.empty()) md = "No metadata";

        int color = getTypeColor(r.type);
        auto tokTr = r.tokenID.size() > 20 ? r.tokenID.substr(0, 20) : r.tokenID;
        auto ownTr = r.owner.size() > 34 ? r.owner.substr(0, 34) : r.owner;
        auto txTr = r.txid.size() > 34 ? r.txid.substr(0, 31) + "..." : r.txid;
        auto mdTr = md.size() > 100 ? md.substr(0, 97) + "..." : md;
        
        // Use formatTokenAmount helper
        std::string formattedAmount = formatTokenAmount(r.amount, r.meta);

        oss << colorText(fmt::format("🔗 {:<20} | {:<6} | {:>12} | {:<34} | {:<34} | {:<100}\n",
                                     tokTr, r.type, formattedAmount, ownTr, txTr, mdTr), color);
    }

    oss << colorText("⛓️═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════⛓️\n", 36, true);
    Logger::log("[formatTokenTable] Table rendered with " + std::to_string(rows.size()) + " rows");
    return oss.str();
}

//========================================================================
//               DISPLAY FORMATTED TOKEN LIST
//========================================================================
// TRU_TOKEN_VAULT_UI_V1: render arbitrary ANSI token text in an alternate
// terminal buffer with paging.  The main menu cannot repaint until this
// function returns, and the background spinner is suppressed by the global
// full-screen flag.
static void displayPagedTokenText(const std::string& text,
                                  const std::string& title,
                                  int rows,
                                  std::mutex& coutMutex) {
    std::vector<std::string> lines;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    if (lines.empty()) lines.push_back("(no token data)");

    rows = std::max(rows, 20);
    const size_t pageSize = static_cast<size_t>(std::max(8, rows - 8));
    const size_t pageCount = std::max<size_t>(1, (lines.size() + pageSize - 1) / pageSize);
    size_t page = 0;

    g_cliFullscreenView.store(true, std::memory_order_release);
    auto leave = [&]() {
        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[?25h\033[?1049l");
            std::cout.flush();
        }
        g_cliFullscreenView.store(false, std::memory_order_release);
    };

    {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[?1049h\033[2J\033[H\033[?25h");
        std::cout.flush();
    }

    try {
        for (;;) {
            const size_t begin = page * pageSize;
            const size_t end = std::min(begin + pageSize, lines.size());

            std::ostringstream out;
            out << "\033[2J\033[H";
            out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
            out << colorText("   " + title + "   PAGE " + std::to_string(page + 1) + "/" + std::to_string(pageCount) + "\n", 96, true);
            out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
            for (size_t i = begin; i < end; ++i) out << lines[i] << "\n";
            out << colorText("──────────────────────────────────────────────────────────────────────\n", 36);
            out << "[Enter/N] Next   [P] Previous   [Q] Back to menu\nCommand: ";

            {
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("{}", out.str());
                std::cout.flush();
            }

            std::string cmd;
            if (!signalAwareGetline(cmd)) break;
            const auto first = cmd.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) cmd.clear();
            else {
                const auto last = cmd.find_last_not_of(" \t\r\n");
                cmd = cmd.substr(first, last - first + 1);
            }
            std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (cmd == "q" || cmd == "back" || cmd == "exit") break;
            if (cmd == "p") page = (page + pageCount - 1) % pageCount;
            else page = (page + 1) % pageCount; // Enter, N, or any other key
        }
    } catch (...) {
        leave();
        throw;
    }
    leave();
}

void displayFormattedTokenList(const Wallet &wallet, int rows, std::mutex &coutMutex) {
    // CLI option 10 now uses the readable vertical format with ALL metadata fields.
    // This replaces the old >200-column table that was hard to see even before
    // the menu painted over it.
    displayPagedTokenText(formatTokenTable2(wallet), "TRU TOKEN VAULT", rows, coutMutex);
}


//========================================================================
//               TRU CONTRACT VAULT — PAGED CONTRACT LIST
//========================================================================
// contract listing follows the same alternate-buffer ownership
// model as the Token Vault, but packs complete contract cards onto pages so
// one contract is never split merely because the wallet has many contracts.
static void displayPagedContractVault(const Blockchain& chain,
                                      int rows,
                                      std::mutex& coutMutex) {
    const auto result = chain.getContracts();

    nlohmann::json contracts;
    if (result.is_object() && result.contains("contracts") && result["contracts"].is_array()) {
        contracts = result["contracts"];
    } else if (result.is_array()) {
        contracts = result;
    } else {
        throw std::runtime_error("Unexpected format from Blockchain::getContracts()");
    }

    std::vector<std::vector<std::string>> cards;
    cards.reserve(contracts.size());

    auto jsonString = [](const nlohmann::json& obj,
                         const char* key,
                         const std::string& fallback = std::string()) {
        if (!obj.is_object() || !obj.contains(key) || !obj[key].is_string()) {
            return fallback;
        }
        return obj[key].get<std::string>();
    };

    auto jsonU64 = [](const nlohmann::json& obj, const char* key) -> std::uint64_t {
        if (!obj.is_object() || !obj.contains(key)) return 0;
        try {
            if (obj[key].is_number_unsigned()) return obj[key].get<std::uint64_t>();
            if (obj[key].is_number_integer()) {
                const auto v = obj[key].get<std::int64_t>();
                return v > 0 ? static_cast<std::uint64_t>(v) : 0;
            }
            if (obj[key].is_string()) return std::stoull(obj[key].get<std::string>());
        } catch (...) {}
        return 0;
    };

    std::size_t ordinal = 0;
    for (const auto& contract : contracts) {
        ++ordinal;
        std::vector<std::string> card;
        card.reserve(16);

        if (!contract.is_object()) {
            card.push_back(colorText("Contract #" + std::to_string(ordinal), 96, true));
            card.push_back("  Raw: " + contract.dump());
            card.push_back(colorText("──────────────────────────────────────────────────────────────────────", 36));
            cards.push_back(std::move(card));
            continue;
        }

        std::string txid = jsonString(contract, "txid");
        std::uint64_t vout = jsonU64(contract, "vout");
        std::string address = jsonString(contract, "address");
        if (address.empty()) address = jsonString(contract, "contractAddress");
        if (address.empty()) address = jsonString(contract, "identifier");
        if (address.empty() && !txid.empty()) {
            address = txid + ":" + std::to_string(vout);
        }

        std::string name = jsonString(contract, "name", "Unnamed");
        std::string type = jsonString(contract, "type");
        if (type.empty()) type = jsonString(contract, "contractType", "Unknown");
        std::string status = jsonString(contract, "status", "Unknown");
        const std::uint64_t amount = jsonU64(contract, "amount");
        std::string script = jsonString(contract, "scriptPubKey");

        int headingColor = 96;
        if (type == "HASH LOCK") headingColor = 95;
        else if (type == "TIME LOCK") headingColor = 94;
        else if (type == "TOKEN ISSUER") headingColor = 92;
        else if (type == "VOTING" || type == "STATEFUL CONTRACT") headingColor = 96;
        else if (type == "MULTISIG / ESCROW V1") headingColor = 96;
        else if (type == "HTLC / ATOMIC SWAP V1") headingColor = 93;
        else if (type == "BRIDGE") headingColor = 93;

        card.push_back(colorText("┌─ Contract #" + std::to_string(ordinal) + " // " + type, headingColor, true));
        if (!address.empty()) {
            if (type == "MULTISIG / ESCROW V1" ||
                type == "HTLC / ATOMIC SWAP V1")
                card.push_back("│ Outpoint : " + address);
            else
                card.push_back("│ Address : " + address);
        }
        card.push_back("│ Name    : " + name);
        if (status != "Unknown") card.push_back("│ Status  : " + status);
        if (amount > 0) card.push_back("│ Locked  : " + formatTRUAmountDetailed(amount));

        const auto family = jsonString(contract, "family");
        const auto stableRoot = jsonString(contract, "stableRoot");
        const auto liveAnchor = jsonString(contract, "liveAnchor");
        const auto registryOwner = jsonString(contract, "ownerHash160");
        if (!family.empty()) card.push_back("│ Family  : " + family);
        if (!stableRoot.empty()) card.push_back("│ Root    : " + stableRoot);
        if (!liveAnchor.empty()) card.push_back("│ Live    : " + liveAnchor);
        if (!registryOwner.empty()) card.push_back("│ Owner   : " + registryOwner);
        if (contract.contains("registryValid") && contract["registryValid"].is_boolean() &&
            !contract["registryValid"].get<bool>()) {
            card.push_back("│ Registry: INVALID");
        }

        if (!script.empty()) {
            if (script.size() > 86) script = script.substr(0, 83) + "...";
            card.push_back("│ Script  : " + script);
        }

        if (type == "HASH LOCK" && contract.contains("details") &&
            contract["details"].is_object()) {
            const auto hash = jsonString(contract["details"], "hash");
            if (!hash.empty()) card.push_back("│ HASH160 : " + hash);
            if (status == "Active") card.push_back("│ Redeem  : hashredeem");
        }

        if (type == "TIME LOCK" && contract.contains("details") &&
            contract["details"].is_object()) {
            const auto& td = contract["details"];
            const auto lockTs = jsonU64(td, "lockTime");
            if (lockTs > 0 && lockTs <= std::numeric_limits<uint32_t>::max()) {
                card.push_back("│ Unlock  : " +
                    formatTimestamp(static_cast<uint32_t>(lockTs)));
            }
            const auto owner = jsonString(td, "ownerHash160");
            if (!owner.empty()) card.push_back("│ Owner   : " + owner);
            const auto mtp = jsonU64(td, "medianTimePast");
            if (mtp > 0 && mtp <= std::numeric_limits<uint32_t>::max()) {
                card.push_back("│ MTP     : " +
                    formatTimestamp(static_cast<uint32_t>(mtp)));
            }
            if (status == "Active") card.push_back("│ Redeem  : timeredeem");
        }

        if (type == "ORACLE LOCK" && contract.contains("details") &&
            contract["details"].is_object()) {
            const auto& od = contract["details"];
            const auto feed = jsonString(od, "feed");
            const auto cmp = jsonString(od, "comparator");
            const auto threshold = jsonU64(od, "threshold");
            const auto owner = jsonString(od, "ownerHash160");
            if (!feed.empty()) card.push_back("│ Feed    : " + feed);
            if (!cmp.empty()) card.push_back("│ Compare : " + cmp + " " + std::to_string(threshold));
            if (!owner.empty()) card.push_back("│ Owner   : " + owner);
        }

        if (type == "MULTISIG / ESCROW V1" && contract.contains("multisig") &&
            contract["multisig"].is_object()) {
            const auto& ms = contract["multisig"];
            const auto threshold = jsonU64(ms, "threshold");
            const auto participantCount = jsonU64(ms, "participantCount");
            const auto fundingOutpoint = jsonString(ms, "fundingOutpoint");
            if (threshold > 0 && participantCount > 0) {
                card.push_back("│ Threshold: " + std::to_string(threshold) +
                               " of " + std::to_string(participantCount));
            }
            if (!fundingOutpoint.empty() && fundingOutpoint != address) {
                card.push_back("│ Outpoint : " + fundingOutpoint);
            }
            if (ms.contains("participantPubkeys") &&
                ms["participantPubkeys"].is_array()) {
                std::size_t signer = 0;
                for (const auto& key : ms["participantPubkeys"]) {
                    if (!key.is_string()) continue;
                    ++signer;
                    card.push_back("│ Signer " + std::to_string(signer) + ": " +
                                   key.get<std::string>());
                }
            }
            card.push_back(std::string("│ Escrow  : ") +
                           (status == "Active" ? "UNSPENT" : "SPENT"));
            if (status == "Active") {
                card.push_back("│ Actions : multisig sign / redeem");
            }
        }

        if (type == "HTLC / ATOMIC SWAP V1" && contract.contains("htlc") &&
            contract["htlc"].is_object()) {
            const auto& hs = contract["htlc"];
            const auto hash = jsonString(hs, "secretHash160");
            const auto claimKey = jsonString(hs, "claimPubkey");
            const auto refundKey = jsonString(hs, "refundPubkey");
            const auto fundingOutpoint = jsonString(hs, "fundingOutpoint");
            const auto refundTime = jsonU64(hs, "refundTime");
            const auto mtp = jsonU64(hs, "medianTimePast");

            if (!fundingOutpoint.empty() && fundingOutpoint != address) {
                card.push_back("│ Outpoint : " + fundingOutpoint);
            }
            if (!hash.empty()) card.push_back("│ HASH160 : " + hash);
            if (!claimKey.empty()) card.push_back("│ Claim   : " + claimKey);
            if (!refundKey.empty()) card.push_back("│ Refund  : " + refundKey);
            if (refundTime > 0 &&
                refundTime <= std::numeric_limits<uint32_t>::max()) {
                card.push_back("│ Refund @: " +
                    formatTimestamp(static_cast<uint32_t>(refundTime)));
            }
            if (mtp > 0 && mtp <= std::numeric_limits<uint32_t>::max()) {
                card.push_back("│ MTP     : " +
                    formatTimestamp(static_cast<uint32_t>(mtp)));
            }

            bool refundMature = false;
            if (hs.contains("refundMature") && hs["refundMature"].is_boolean()) {
                refundMature = hs["refundMature"].get<bool>();
            }
            card.push_back(std::string("│ HTLC    : ") +
                           (status == "Active" ? "UNSPENT" : "SPENT"));
            if (status == "Active") {
                card.push_back("│ Claim   : READY (valid preimage + claim key)");
                card.push_back(std::string("│ Refund  : ") +
                               (refundMature ? "READY" : "LOCKED"));
                card.push_back("│ Actions : htlc claim / refund");
            }
        }

        if (type == "TOKEN ISSUER" && contract.contains("token") &&
            contract["token"].is_object()) {
            const auto& token = contract["token"];
            const auto tokenName = jsonString(token, "name");
            if (!tokenName.empty()) card.push_back("│ Token   : " + tokenName);
            const auto rate = jsonU64(token, "exchangeRate");
            if (rate > 0) card.push_back("│ Rate    : " + std::to_string(rate) + " token units / TRU atom");
            const auto issued = jsonU64(token, "totalIssued");
            const auto maxSupply = jsonU64(token, "maxSupply");
            card.push_back("│ Issued  : " + std::to_string(issued) +
                           (maxSupply > 0 ? (" / " + std::to_string(maxSupply)) : " / unlimited"));
        }

        if (type == "BRIDGE" && contract.contains("bridge") &&
            contract["bridge"].is_object()) {
            const auto& bridge = contract["bridge"];
            const auto asset = jsonString(bridge, "asset");
            if (!asset.empty()) card.push_back("│ Asset   : " + asset);
            const auto conf = jsonU64(bridge, "minConfirmations");
            if (conf > 0) card.push_back("│ MinConf : " + std::to_string(conf));
        }

        if (contract.contains("call") && contract["call"].is_object()) {
            const auto style = jsonString(contract["call"], "callStyle");
            if (!style.empty()) card.push_back("│ Call    : " + style);
        }

        card.push_back(colorText("└─────────────────────────────────────────────────────────────────────", 36));
        cards.push_back(std::move(card));
    }

    rows = std::max(rows, 20);
    const std::size_t pageCapacity = static_cast<std::size_t>(std::max(8, rows - 9));
    std::vector<std::vector<std::string>> pages;
    std::vector<std::string> current;
    std::size_t used = 0;

    for (const auto& card : cards) {
        const std::size_t need = card.size() + (current.empty() ? 0 : 1);
        if (!current.empty() && used + need > pageCapacity) {
            pages.push_back(std::move(current));
            current.clear();
            used = 0;
        }
        if (!current.empty()) {
            current.emplace_back();
            ++used;
        }
        current.insert(current.end(), card.begin(), card.end());
        used += card.size();
    }
    if (!current.empty()) pages.push_back(std::move(current));
    if (pages.empty()) pages.push_back({"No contracts deployed yet."});

    std::size_t page = 0;
    g_cliFullscreenView.store(true, std::memory_order_release);
    auto leave = [&]() {
        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[?25h\033[?1049l");
            std::cout.flush();
        }
        g_cliFullscreenView.store(false, std::memory_order_release);
    };

    {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[?1049h\033[2J\033[H\033[?25h");
        std::cout.flush();
    }

    try {
        for (;;) {
            std::ostringstream out;
            out << "\033[2J\033[H";
            out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
            out << colorText("   TRU CONTRACT VAULT   PAGE " + std::to_string(page + 1) + "/" +
                             std::to_string(pages.size()) + "   //   " +
                             std::to_string(contracts.size()) + " CONTRACT(S)\n", 96, true);
            out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
            out << "\n";
            for (const auto& line : pages[page]) out << line << "\n";
            out << "\n";
            out << colorText("──────────────────────────────────────────────────────────────────────\n", 36);
            out << "[Enter/N] Next   [P] Previous   [Q] Back to menu\nCommand: ";

            {
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("{}", out.str());
                std::cout.flush();
            }

            std::string cmd;
            if (!signalAwareGetline(cmd)) break;
            const auto first = cmd.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) cmd.clear();
            else {
                const auto last = cmd.find_last_not_of(" \t\r\n");
                cmd = cmd.substr(first, last - first + 1);
            }
            std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (cmd == "q" || cmd == "back" || cmd == "exit") break;
            if (cmd == "p") page = (page + pages.size() - 1) % pages.size();
            else page = (page + 1) % pages.size();
        }
    } catch (...) {
        leave();
        throw;
    }
    leave();
}

//===================================================================================================
//                              FORMAT TABLE 2
//===================================================================================================
std::string formatTokenTable2(const Wallet &wallet) {
    struct RawEntry {
        std::string owner;
        std::string tokenID;
        std::string txid;
        std::string type;
        uint32_t vout;
        uint64_t amount;
    };
    std::vector<RawEntry> rawEntries;

    // Gather wallet addresses
    auto addrs = wallet.getAllAddresses();
    std::unordered_set<std::string> myAddrs(addrs.begin(), addrs.end());
    Logger::log("[formatTokenTable2] Found " + std::to_string(myAddrs.size()) + " wallet addresses");

    // Access storage
    const auto &chain = wallet.getBlockchain();
    const auto *storage = chain.getStorage();
    const std::string prefix = "tokenUTXO:";

    // Use a set to track processed tokens and avoid duplicates
    std::set<std::string> processedTokens;

    // Iterate over tokenUTXO entries
    storage->iteratePrefix(prefix, [&](const std::string &key, const std::string &val) {
        Logger::log("[formatTokenTable2] Processing key: " + prefix + key);
        
        // Parse key correctly: key format is "txid:vout" (without prefix)
        size_t colonPos = key.find(':');
        if (colonPos == std::string::npos) {
            Logger::log("[formatTokenTable2] ERROR: Invalid key format: " + key);
            return;
        }
        
        std::string txid = key.substr(0, colonPos);
        std::string voutStr = key.substr(colonPos + 1);
        uint32_t vout = 0;
        
        try {
            vout = static_cast<uint32_t>(std::stoul(voutStr));
            Logger::log("[formatTokenTable2] Parsed txid: " + txid + ", vout: " + std::to_string(vout));
        } catch (const std::exception& ex) {
            Logger::log("[formatTokenTable2] ERROR: Invalid vout: " + voutStr + ", " + ex.what());
            return;
        }

        // Check if txid is valid (should be 64 hex chars)
        if (txid.size() != 64 || !std::all_of(txid.begin(), txid.end(), ::isxdigit)) {
            Logger::log("[formatTokenTable2] ERROR: Invalid txid format: " + txid);
            return;
        }

        try {
            auto j = nlohmann::json::parse(val);
            
            // Skip if this isn't a token UTXO
            if (!j.contains("tokenID") || !j.contains("owner") || !j.contains("type")) {
                Logger::log("[formatTokenTable2] Skipping non-token UTXO: " + key);
                return;
            }
            
            std::string owner = j["owner"].get<std::string>();
            if (!myAddrs.count(owner)) {
                Logger::log("[formatTokenTable2] Skipping non-owned address: " + owner);
                return;
            }

            // debug view must also
            // distinguish current holdings from historical/stale indexes.
            const std::string liveUtxoKey =
                "utxo:" + txid + ":" + std::to_string(vout);
            if (!storage->exists(liveUtxoKey)) {
                Logger::log("[formatTokenTable2] Skipping stale/spent token index: " +
                            prefix + key);
                return;
            }
            
            // Check if this is the controlling output
            if (j.contains("controllingVout")) {
                uint32_t controllingVout = j["controllingVout"].get<uint32_t>();
                if (vout != controllingVout) {
                    Logger::log("[formatTokenTable2] Skipping non-controlling output");
                    return;
                }
            }

            // Create unique key to avoid duplicates
            std::string tokenID = j["tokenID"].get<std::string>();
            std::string uniqueKey = tokenID + ":" + txid + ":" + std::to_string(vout);
            if (processedTokens.count(uniqueKey)) {
                Logger::log("[formatTokenTable2] Skipping duplicate token entry: " + uniqueKey);
                return;
            }
            processedTokens.insert(uniqueKey);

            RawEntry e;
            e.owner = owner;
            e.tokenID = tokenID;
            e.amount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
            e.type = j["type"].get<std::string>();
            e.txid = txid;
            e.vout = vout;

            Logger::log("[formatTokenTable2] Parsed tokenUTXO: " + key + ", type=" + e.type);
            rawEntries.push_back(e);
        } catch (const std::exception& ex) {
            Logger::log("[formatTokenTable2] Error parsing JSON for key " + key + ": " + ex.what());
        }
    });

    if (rawEntries.empty()) {
        Logger::log("[formatTokenTable2] No token entries found");
        return colorText("No tokens owned by this wallet.\n", 31);
    }

    // Build table rows
    struct Row {
        std::string tokenID, type, owner, txid;
        uint64_t amount;
        std::unordered_map<std::string, std::string> meta;
    };
    std::vector<Row> rows;
    rows.reserve(rawEntries.size());

    for (const auto &e : rawEntries) {
        Row r{e.tokenID, e.type, e.owner, e.txid, e.amount, {}};
        std::string metaVal;
        std::string metaKey = "tokenMetadata:" + e.txid;
        Logger::log("[formatTokenTable2] Fetching metadata with key: " + metaKey);
        
        if (storage->getWithDataChecksum(metaKey, metaVal)) {
            try {
                auto jm = nlohmann::json::parse(metaVal);
                if (jm.contains("meta") && jm["meta"].is_object()) {
                    for (const auto &it : jm["meta"].items()) {
                        if (it.value().is_string()) {
                            r.meta[it.key()] = it.value().get<std::string>();
                        } else if (it.value().is_number()) {
                            r.meta[it.key()] = std::to_string(it.value().get<int>());
                        } else {
                            r.meta[it.key()] = it.value().dump();
                        }
                    }
                    Logger::log("[formatTokenTable2] Metadata parsed successfully for " + metaKey);
                }
            } catch (const std::exception& ex) {
                Logger::log("[formatTokenTable2] Error parsing metadata for txid=" + e.txid + ": " + ex.what());
                r.meta["name"] = "Unknown_" + e.tokenID;
                r.meta["description"] = "Metadata unavailable";
            }
        } else {
            Logger::log("[formatTokenTable2] Metadata not found for " + metaKey);
            // Try issuance txid
            std::string issuanceKey = "tokenIssuance:" + e.tokenID;
            std::string issuanceTxid;
            if (storage->getWithDataChecksum(issuanceKey, issuanceTxid)) {
                std::string altMetaKey = "tokenMetadata:" + issuanceTxid;
                if (storage->getWithDataChecksum(altMetaKey, metaVal)) {
                    try {
                        auto jm = nlohmann::json::parse(metaVal);
                        if (jm.contains("meta") && jm["meta"].is_object()) {
                            for (const auto &it : jm["meta"].items()) {
                                if (it.value().is_string()) {
                                    r.meta[it.key()] = it.value().get<std::string>();
                                }
                            }
                        }
                    } catch (...) {}
                }
            }
            
            if (r.meta.empty()) {
                r.meta["name"] = "Token_" + e.tokenID;
                r.meta["description"] = "No metadata recorded";
            }
        }
        rows.push_back(r);
    }

    // Define prioritized metadata fields
    static const std::vector<std::string> metaFields = {
        "name", "symbol", "decimals", "description", "image"
    };

    // Render table
    std::ostringstream oss;
    // Header with bright cyan (36, bold)
    oss << colorText("══════════════════════════════════════════════════════==═══════=====══ MY TOKENS ===══════====═════════════════════════════════════════════════════════\n", 36, true);

    for (const auto& r : rows) {
        // TRU_TOKEN_VAULT_UI_V1: readable multi-line card.  Do not truncate
        // the owner or txid; this view is intended to expose every detail.
        int typeColor = getTypeColor(r.type);
        std::string formattedAmount = formatTokenAmount(r.amount, r.meta);
        oss << colorText(fmt::format("╭─ [{}] Token {} ─────────────────────────────────────────\n",
                                     r.type, r.tokenID), typeColor, true);
        oss << colorText(fmt::format("│ Amount : {}\n", formattedAmount), typeColor);
        oss << colorText(fmt::format("│ Owner  : {}\n", r.owner), typeColor);
        oss << colorText(fmt::format("│ TXID   : {}\n", r.txid), typeColor);

        // Metadata header in bright cyan (36)
        oss << colorText("│ Metadata:\n", 36);

        // Display prioritized metadata fields first
        for (const auto& fld : metaFields) {
            if (r.meta.count(fld)) {
                oss << colorText(fmt::format("    {:<15}: {}\n", fld, r.meta.at(fld)), 37); // White (37) for fields
            }
        }

        // Display remaining metadata fields
        for (const auto& [key, value] : r.meta) {
            if (std::find(metaFields.begin(), metaFields.end(), key) == metaFields.end()) {
                oss << colorText(fmt::format("    {:<15}: {}\n", key, value), 37); // White (37) for fields
            }
        }

        // Separator in bright cyan (36)
        oss << colorText("──────────────────────────────────────────────────────────────────────────────────────\n", 36);
    }

    // Footer with bright cyan (36, bold)
    oss << colorText("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n", 36, true);
    Logger::log("[formatTokenTable2] Table rendered with " + std::to_string(rows.size()) + " rows");
    return oss.str();
}
//========================================================================
//               DISPLAY FORMATTED TOKEN LIST 2
//========================================================================
void displayFormattedTokenList2(const Wallet &wallet, int rows, std::mutex &coutMutex) {
    displayPagedTokenText(formatTokenTable2(wallet), "TRU TOKEN INDEX DEBUG", rows, coutMutex);
}

//===================================================================================================
//                              PRINT BANNER 3
//===================================================================================================
// Helper function to get terminal dimensions
bool getTerminalSize(int& rows, int& columns) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        return false; // Failed to get terminal size
    }
    rows = ws.ws_row;
    columns = ws.ws_col;
    return true;
}

void printBanner3(std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex); // Lock for thread-safe output
    srand(time(nullptr)); // Seed the random number generator once

    // Get terminal dimensions
    int rows, columns;
    if (!getTerminalSize(rows, columns)) {
        // Fallback to default values if terminal size detection fails
        rows = 45;
        columns = 80;
    }

    // Ensure minimum dimensions to prevent issues
    rows = std::max(rows, 20);
    columns = std::max(columns, 80);

    const int numFrames = 100; // Number of frames for the animation

    // Character set for random streams
    const std::string charSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()";

    // Words to display in the rain
    const std::vector<std::string> words = {
        "TRU", "NFT", "SFT", "NCFT", "FT", "blockchain", "A.i", "Tokenized Real Utility",
        "crypto", "decentralized", "ledger", "smart contract", "hash", "node", "peer", "wallet",
        "transaction", "consensus", "proof of work", "proof of stake", "mining", "block", "blockchain"
    };

    // Lambda to generate random characters for streams
    auto generateRandomCharacters = [&charSet](int length) {
        std::string result;
        for (int i = 0; i < length; i++) {
            result += charSet[rand() % charSet.size()];
        }
        return result;
    };

    // Structure to represent a stream in the Matrix rain
    struct Stream {
        int position;           // Current row of the head (bottom-most character)
        int length;             // Length of the stream or word
        int speed;              // Speed of falling (rows per frame)
        std::string characters; // Characters or word in the stream
        bool isWordStream;      // Flag to distinguish word streams
    };

    // Initialize streams for each column
    std::vector<Stream> streams(columns);
    for (int col = 0; col < columns; ++col) {
        Stream& stream = streams[col];
        if (rand() % 5 == 0) { // 20% chance to be a word stream
            int wordIndex = rand() % words.size();
            stream.characters = words[wordIndex];
            stream.length = stream.characters.length();
            stream.speed = 2; // Faster for words
            stream.isWordStream = true;
        } else {
            stream.length = rand() % 10 + 5; // Random length between 5 and 15
            stream.characters = generateRandomCharacters(stream.length);
            stream.speed = 1; // Slower for random characters
            stream.isWordStream = false;
        }
        // Random starting position to simulate continuous rain
        stream.position = rand() % (rows + stream.length);
    }

    // Animation loop
    for (int frame = 0; frame < numFrames; ++frame) {
        // Clear screen and move cursor to top-left
        fmt::print("\033[2J\033[1;1H");

        // Update and render each stream
        for (int col = 0; col < columns; ++col) {
            Stream& stream = streams[col];
            if (stream.isWordStream) {
                // Print word vertically, first character at the bottom
                for (size_t i = 0; i < stream.characters.length(); ++i) {
                    int row = stream.position - i;
                    if (row >= 0 && row < rows) {
                        char c = stream.characters[stream.characters.length() - 1 - i];
                        fmt::print("\033[{};{}H\033[32m{}\033[0m", row + 1, col + 1, c); // Green color
                    }
                }
            } else {
                // Print random character stream, head at bottom
                for (int i = 0; i < stream.length; ++i) {
                    int row = stream.position - i;
                    if (row >= 0 && row < rows) {
                        char c = stream.characters[i];
                        int color = (i == 0) ? 92 : 32; // Head light green, tail green
                        fmt::print("\033[{};{}H\033[{}m{}\033[0m", row + 1, col + 1, color, c);
                    }
                }
            }

            // Move stream downward
            stream.position += stream.speed;

            // Reset stream when it falls off the screen
            if (stream.position >= rows + stream.length - 1) {
                if (rand() % 5 == 0) { // 20% chance to become a word stream
                    int wordIndex = rand() % words.size();
                    stream.characters = words[wordIndex];
                    stream.length = stream.characters.length();
                    stream.speed = 2;
                    stream.isWordStream = true;
                } else {
                    stream.length = rand() % 10 + 5;
                    stream.characters = generateRandomCharacters(stream.length);
                    stream.speed = 1;
                    stream.isWordStream = false;
                }
                stream.position = 0; // Restart at top
            }
        }

        // Pause for 20 milliseconds per frame
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    // Clear screen and display the final banner
    fmt::print("\033[2J\033[1;1H");

    int bannerHeight = 8;
    int bannerTop = std::max(3, std::min(rows - bannerHeight - 2, rows / 10)); // e.g., row 3..(rows-10)
    fmt::print("\033[{};1H", bannerTop);

    fmt::print("\033[36m" // Cyan color for the banner
               "    ████████╗██████╗ ██╗   ██╗    ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗\n"
               "    ╚══██╔══╝██╔══██╗██║   ██║    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║\n"
               "       ██║   ██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║██║     █████╔╝ ██║     ███████║███████║██║██╔██╗ ██║\n"
               "       ██║   ██╔══██╗██║   ██║    ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██║██║██║╚██╗██║\n"
               "       ██║   ██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗╚██████╗██║  ██║██║  ██║██║██║ ╚████║\n"
               "       ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝\n"
               "\033[0m");
    fmt::print("\033[90m" // Gray color for the subtitle
               "      T O K E N I Z E D  R E A L  U T I L I T Y   A N E X T - G E N   C O N S O L E   E X P E R I E N C E         \n\n"
               "\033[0m");
}

//===================================================================================================
//                              PRINT BANNER
//===================================================================================================
void printBanner(std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    // Clear screen, move cursor
    fmt::print("\033[2J\033[1;1H");

    int bannerTop = 7; // adjust this number (3–10 works nicely)
    fmt::print("\033[{};1H", bannerTop);

    // ASCII banner
    fmt::print(colorText(R"(
    ████████╗██████╗ ██╗   ██╗    ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
    ╚══██╔══╝██╔══██╗██║   ██║    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║
       ██║   ██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║██║     █████╔╝ ██║     ███████║███████║██║██╔██╗ ██║
       ██║   ██╔══██╗██║   ██║    ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██║██║██║╚██╗██║
       ██║   ██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗╚██████╗██║  ██║██║  ██║██║██║ ╚████║
       ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
)",
    36, true));
    fmt::print(colorText("      T O K E N I Z E D  R E A L  U T I L I T Y   A N E X T - G E N   C O N S O L E   E X P E R I E N C E         \n\n", 90, false));
}

// no-flicker header repaint.
//
// The legacy printBanner() remains the startup/full-reset painter. This helper
// restores the same TRU identity into the shared rows 9..15 without clearing
// the terminal. When mining is active, displayMinerStats() immediately owns
// and overwrites these same rows; when idle, the logo owns them.
static void paintHeader(std::mutex& coutMutex) {
    static const std::vector<std::string> art = {
        "    ████████╗██████╗ ██╗   ██╗    ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗",
        "    ╚══██╔══╝██╔══██╗██║   ██║    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║",
        "       ██║   ██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║██║     █████╔╝ ██║     ███████║███████║██║██╔██╗ ██║",
        "       ██║   ██╔══██╗██║   ██║    ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██║██║██║╚██╗██║",
        "       ██║   ██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗╚██████╗██║  ██║██║  ██║██║██║ ╚████║",
        "       ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝"
    };

    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");

    // clean stale full-screen instructions above the
    // persistent logo without a destructive whole-screen clear.
    for (int row = 1; row <= 8; ++row) {
        fmt::print("\033[{};1H\033[K", row);
    }

    for (size_t i = 0; i < art.size(); ++i) {
        const int row = 9 + static_cast<int>(i);
        fmt::print("\033[{};1H\033[K{}", row, colorText(art[i], 36, true));
    }
    fmt::print(
        "\033[15;1H\033[K{}",
        colorText(
            "      T O K E N I Z E D  R E A L  U T I L I T Y   A N E X T - G E N   C O N S O L E   E X P E R I E N C E",
            90, false));
    fmt::print("\033[u");
}

// -------------------------------------------------------------------
//         Print chain info at row=12
// -------------------------------------------------------------------
void printChainInfo(const Blockchain &chain) {
    try {
        // build ALL lines as one atomic string and clear each
        // target row explicitly, drawn at rows 9-14 (above where the menu sits
        // on a normal terminal). Previously this drew at row 12 -- the same row
        // the menu starts at -- so a menu repaint truncated the lower lines.
        std::string valid = chain.isChainValid() ? colorText("yes", 32) : colorText("no", 31);
        std::ostringstream ci;
        ci << "\033[s";
        ci << "\033[9;1H"  << "\033[K" << colorText("[Chain Info]", 95, true) << "\n";
        ci << "\033[10;1H" << "\033[K" << "  " << colorText("Chain size:     ", 94) << chain.getChainSize() << "\n";
        ci << "\033[11;1H" << "\033[K" << "  " << colorText("Best tip height:", 94) << " " << chain.getBestTipHeight() << "\n";
        ci << "\033[12;1H" << "\033[K" << "  " << colorText("Best tip hash:  ", 94) << " " << chain.getBestTipHash() << "\n";
        {
            std::ostringstream dhex; dhex << std::hex << chain.getDifficulty();
            ci << "\033[13;1H" << "\033[K" << "  " << colorText("Difficulty:     ", 94) << " 0x" << dhex.str() << "\n";
        }
        ci << "\033[14;1H" << "\033[K" << "  " << colorText("Chain valid:    ", 94) << " " << valid << "\n";
        ci << "\033[u";
        fmt::print("{}", ci.str());
    } catch (const std::exception &e) {
        fmt::print(stderr, colorText("[Chain Info] Error: ", 31) + "{}\n", e.what());
    }
}


// -------------------------------------------------------------------
//            Clear lines & show menu
// -------------------------------------------------------------------

// ---------------------------------------------------------------------------
// external miner process manager.
//
// The node must NOT mine on its own threads (that starves its RPC). Instead we
// spawn the standalone miner executables as child processes and just track them.
// ---------------------------------------------------------------------------
namespace tru_miner_proc {

static pid_t g_cpuMinerPid = -1;
static pid_t g_gpuMinerPid = -1;

// Reap a finished child without blocking; returns true if still running.
static bool isAlive(pid_t pid) {
    if (pid <= 0) return false;
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    return (r == 0);  // 0 => still running
}

// Spawn miner. argv must be null-terminated. Redirects child stdout/stderr to logFile.
static pid_t spawnMiner(const char* exePath, char* const argv[], const char* logFile) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;  // fork failed
    }
    if (pid == 0) {
        // Child: detach from the node's controlling terminal so the miner's
        // own UI/logging can't scribble over the node TUI. Send output to log.
        setsid();
        int fd = open(logFile, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }
        execvp(exePath, argv);
        // If execvp returns, it failed.
        _exit(127);
    }
    return pid;  // parent: child's pid
}

static void stopMiner(pid_t& pid, const std::string& label, int rows, std::mutex& coutMutex) {
    if (pid > 0 && isAlive(pid)) {
        kill(pid, SIGTERM);
        // Give it a moment to unregister/cleanup, then reap.
        for (int i = 0; i < 20 && isAlive(pid); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (isAlive(pid)) kill(pid, SIGKILL);
        int st = 0; waitpid(pid, &st, 0);
        displayOutput("[CLI] " + label + " miner stopped.", rows, coutMutex);
    } else {
        displayOutput("[CLI] " + label + " miner is not running.", rows, coutMutex);
    }
    pid = -1;
}

} // namespace tru_miner_proc

// ---------------------------------------------------------------------------
// live miner-stats banner rendered in the node's own TUI.
// Reads the stats the node already tracks (updated by the miners' periodic
// reportmineractivity RPC), so it works with the decoupled child-process
// miners from patch36 without sharing their terminal.
// ---------------------------------------------------------------------------
static std::string tru_fmtHashRate(double hr) {
    const char* u[] = {"H/s","KH/s","MH/s","GH/s","TH/s","PH/s"};
    int i = 0;
    while (hr >= 1000.0 && i < 5) { hr /= 1000.0; ++i; }
    std::ostringstream o; o << std::fixed << std::setprecision(2) << hr << " " << u[i];
    return o.str();
}

void displayMinerStats(const Blockchain& chain, const Wallet& wallet,
                       int rows, std::mutex& coutMutex) {
    (void)rows;
    std::string addr;
    try { addr = wallet.getCurrentAddress(); } catch (...) { addr = ""; }

    // Pull stats the node already maintains for this address.
    bool   registered = false;
    bool   active     = false;
    double hashRate   = 0.0;
    uint64_t blocks   = 0;
    if (!addr.empty()) {
        try { registered = chain.isMinerRegistered(addr); } catch (...) {}
        auto hit = chain.minerHashRates.find(addr);
        if (hit != chain.minerHashRates.end()) hashRate = hit->second;
        blocks = chain.getMinerBlockCount(addr);
        auto lit = chain.minerLastActivity.find(addr);
        if (lit != chain.minerLastActivity.end()) {
            auto since = std::chrono::steady_clock::now() - lit->second;
            active = since < std::chrono::minutes(2);
        }
    }

    // only show the banner while mining is actually running.
    // If not active, clear the banner rows (2..6) and draw nothing, so the
    // stats disappear when mining stops and reappear when it resumes.
    if (!active) {
        // do NOT erase rows 9..19 on every CLI loop.
        // Those rows are also used by the TRU logo, Chain Info and command output.
        return;
    }

    int    height = 0;
    uint32_t bits = 0;
    uint64_t reward = 0;
    try { height = chain.getBestTipHeight(); } catch (...) {}
    try { bits   = chain.getDifficulty(); }    catch (...) {}
    try { reward = chain.getBlockReward(); }   catch (...) {}

    std::string shortAddr = addr.size() > 10 ? (addr.substr(0,10) + "...") : addr;
    std::string state = active ? "MINING" : (registered ? "registered (idle)" : "idle");

    std::ostringstream bx; bx << std::hex << bits;

    // rich neon dashboard owns rows 9..15 only.
    // Row 16 is reserved for status/output, so the dashboard never clears it.
    static const char* NEON_PINK  = "\033[38;2;255;20;147m";
    static const char* NEON_BLUE  = "\033[38;2;0;255;255m";
    static const char* NEON_GREEN = "\033[38;2;57;255;20m";
    static const char* NEON_ORANGE= "\033[38;2;255;140;0m";
    static const char* NEON_PURPLE= "\033[38;2;191;64;191m";
    static const char* FIRE       = "\033[38;2;255;69;0m";
    static const char* TEXTC      = "\033[38;2;236;240;241m";
    static const char* MUTED      = "\033[38;2;149;165;166m";
    static const char* RESETC     = "\033[0m";

    // Elapsed since last activity report (seconds), for a live "uptime"-ish feel.
    long secsSince = 0;
    {
        auto lit = chain.minerLastActivity.find(addr);
        if (lit != chain.minerLastActivity.end()) {
            secsSince = (long)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - lit->second).count();
        }
    }

    // Animated progress bar (advances with wall-clock so it visibly moves).
    static int s_anim = 0; s_anim = (s_anim + 1) % 28;
    std::string bar;
    for (int i = 0; i < 28; ++i) bar += (i <= s_anim) ? "\u2593" : "\u2591";

    const int W = 60;  // inner width
    auto padline = [&](const std::string& visible, int vislen) {
        std::string out = visible;
        int pad = W - vislen; if (pad < 0) pad = 0;
        out += std::string(pad, ' ');
        return out;
    };

    std::string hrStr = tru_fmtHashRate(hashRate);
    std::string diffStr = "0x" + bx.str();
    std::string rewardStr = std::to_string(reward / 100000000ULL) + " TRU";

    std::lock_guard<std::mutex> lock(coutMutex);
    std::stringstream ss;

    // Row 9: top border + title
    ss << "\033[9;1H\033[K" << NEON_PINK
       << "\u250f\u2501\u2501 " << "\033[38;2;0;255;255m" << "TRU MINER  " << NEON_PINK
       << "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501 " << shortAddr << " \u2501\u2501\u2513" << RESETC;

    // Row 10: state + hashrate
    ss << "\033[10;1H\033[K" << NEON_PINK << "\u2503 " << TEXTC << "State     "
       << NEON_GREEN << "\u26a1 MINING" << MUTED << "    "
       << TEXTC << "Hashrate  " << FIRE << hrStr << RESETC;

    // Row 11: blocks found + reward
    ss << "\033[11;1H\033[K" << NEON_PINK << "\u2503 " << TEXTC << "Blocks    "
       << NEON_ORANGE << std::to_string(blocks) << MUTED << " found   "
       << TEXTC << "Reward    " << NEON_GREEN << rewardStr << RESETC;

    // Row 12: chain height + difficulty
    ss << "\033[12;1H\033[K" << NEON_PINK << "\u2503 " << TEXTC << "Height    "
       << NEON_BLUE << std::to_string(height) << MUTED << "        "
       << TEXTC << "Difficulty " << NEON_PURPLE << diffStr << RESETC;

    // Row 13: last report age + algorithm
    ss << "\033[13;1H\033[K" << NEON_PINK << "\u2503 " << TEXTC << "Last rpt  "
       << MUTED << std::to_string(secsSince) << "s ago   "
       << TEXTC << "Algo      " << NEON_PINK << "SHA256-21E8" << RESETC;

    // Row 14: animated activity bar
    ss << "\033[14;1H\033[K" << NEON_PINK << "\u2503 " << TEXTC << "Activity  "
       << NEON_GREEN << bar << RESETC;

    // Row 15: bottom border
    ss << "\033[15;1H\033[K" << NEON_PINK
       << "\u2517\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u251b" << RESETC;

    // Do not clear row 16 or below. Those rows belong to status/output/menu.
    std::cout << ss.str() << std::flush;
}

// stable responsive menu.
//
// Important design rules:
//   1. Draw menu lines with ABSOLUTE cursor positions -- never a long stream
//      of '\n' characters. That prevents terminal scrolling / stacked menus.
//   2. Keep rows 1..16 available for the TRU banner / Chain Info / miner panel.
//   3. FULL mode is used only when it actually fits below row 16.
//   4. COMPACT mode is used when requested with M, or automatically if FULL
//      cannot fit.
//   5. Menu input remains the normal std::getline() path, so every existing
//      public command (7, 28, 35, 11, sync, etc.) keeps working.

static bool g_compactMenu = false;

static const std::string& truNormalPromptText()
{
    static const std::string text =
        "TRU:// command > ";
    return text;
}

static const std::string& truFocusPromptText()
{
    static const std::string text =
        "[OUTPUT://FOCUS]  M = Menu  C = Clear  36 = Exit  > ";
    return text;
}

static int truCurrentPromptCol()
{
    const std::string& text =
        g_cliContentFocus.load(std::memory_order_acquire)
            ? truFocusPromptText()
            : truNormalPromptText();
    return static_cast<int>(text.size()) + 1;
}

// Time Lock command discoverability.
// Both canonical redemption commands are first-class deck tokens.
static bool truDeckHighlightToken(const std::string& token)
{
    if (token.empty()) return false;
    if (token[0] >= '0' && token[0] <= '9') return true;
    return token == "C" || token == "M" || token == "sync" ||
           token == "hashredeem" || token == "timeredeem";
}

static std::string truColorizeDeckBody(const std::string& body)
{
    std::ostringstream out;
    size_t i = 0;

    while (i < body.size()) {
        if (body[i] == ' ') {
            out << ' ';
            ++i;
            continue;
        }

        size_t j = i;
        while (j < body.size() && body[j] != ' ') ++j;
        const std::string token = body.substr(i, j - i);

        if (truDeckHighlightToken(token)) {
            out << colorText(token, 93, true);
        } else if (token == "//") {
            out << colorText(token, 90, false);
        } else {
            out << colorText(token, 96, false);
        }

        i = j;
    }

    return out.str();
}

static void truDrawMenuLine(std::stringstream& ss,
                            int row,
                            const std::string& text,
                            int color,
                            bool bold = false)
{
    (void)color;
    (void)bold;

    ss << "\033[" << row << ";1H\033[K";

    if (text.empty()) return;

    // box-drawing glyphs are UTF-8 strings, not
    // single-byte C++ char literals. Compare complete byte sequences and slice
    // by their encoded width so borders are never split mid-codepoint.
    const std::string boxTopLeft = u8"╔";
    const std::string boxMidLeft = u8"╠";
    const std::string boxBotLeft = u8"╚";
    const std::string boxVertical = u8"║";

    // keep the frame rails purple but promote the
    // title and section-header names to green for the requested TRU CORE look.
    const std::string boxTopRight = u8"╗";
    const std::string boxMidRight = u8"╣";

    if (text.compare(0, boxTopLeft.size(), boxTopLeft) == 0 &&
        text.size() >= (boxTopLeft.size() + boxTopRight.size()) &&
        text.compare(text.size() - boxTopRight.size(),
                     boxTopRight.size(), boxTopRight) == 0) {
        const size_t titleStart = text.find(" T R U");
        const size_t titleEnd   = text.rfind(u8" ═");

        if (titleStart != std::string::npos &&
            titleEnd   != std::string::npos &&
            titleEnd   > titleStart + 1) {
            ss << colorText(text.substr(0, titleStart + 1), 94, true)
               << colorText(text.substr(titleStart + 1,
                                        titleEnd - (titleStart + 1)),
                            92, true)
               << colorText(text.substr(titleEnd), 94, true);
            return;
        }

        ss << colorText(text, 94, true);
        return;
    }

    if (text.compare(0, boxMidLeft.size(), boxMidLeft) == 0 &&
        text.size() >= (boxMidLeft.size() + boxMidRight.size()) &&
        text.compare(text.size() - boxMidRight.size(),
                     boxMidRight.size(), boxMidRight) == 0) {
        // section names may be centered anywhere in
        // the rail. Only the semantic label is green; every ═/╠/╣ stays purple.
        static const std::vector<std::string> sectionLabels = {
            "WALLET // IDENTITY & VALUE",
            "TOKENS // ASSETS & SCRIPTS",
            "CONTRACTS // STATE & BRIDGE",
            "NETWORK // CHAIN & PEERS",
            "COMPUTE // MINING",
            "WALLET",
            "TOKENS / CONTRACTS",
            "CHAIN / COMPUTE"
        };

        for (const auto& label : sectionLabels) {
            const size_t pos = text.find(label);
            if (pos != std::string::npos) {
                ss << colorText(text.substr(0, pos), 94, true)
                   << colorText(label, 92, true)
                   << colorText(text.substr(pos + label.size()), 94, true);
                return;
            }
        }

        ss << colorText(text, 94, true);
        return;
    }

    if (text.compare(0, boxBotLeft.size(), boxBotLeft) == 0) {
        ss << colorText(text, 94, true);
        return;
    }

    if (text.size() >= (2 * boxVertical.size()) &&
        text.compare(0, boxVertical.size(), boxVertical) == 0 &&
        text.compare(text.size() - boxVertical.size(),
                     boxVertical.size(), boxVertical) == 0) {
        ss << colorText(boxVertical, 94, true)
           << truColorizeDeckBody(
                  text.substr(boxVertical.size(),
                              text.size() - (2 * boxVertical.size())))
           << colorText(boxVertical, 94, true);
        return;
    }

    ss << colorText(text, 96, false);
}

void displayMenu(int rows, std::mutex &coutMutex)
{
    std::lock_guard<std::mutex> lock(coutMutex);

    const int HEADER_BOTTOM = 16;
    const int SAFE_MENU_TOP  = HEADER_BOTTOM + 1;
    const int promptRow      = truMenuPromptRow(rows);
    const int heartbeatRow   = truHeartbeatRow(rows);

    // Output Focus: preserve the command result. The fixed footer stack is:
    // command prompt, heartbeat, then sync status.
    if (g_cliContentFocus.load(std::memory_order_acquire)) {
        std::stringstream ss;
        ss << "\033[" << promptRow << ";1H\033[K"
           << colorText(truFocusPromptText(), 93, true)
           << "\033[" << promptRow << ";"
           << truCurrentPromptCol() << "H";
        fmt::print("{}", ss.str());
        return;
    }

    // neon hierarchy + aligned Command Deck.
    // Option codes are presentation-only; dispatcher branches are unchanged.
    // sequential public CLI navigation.
    const std::vector<std::string> fullLines = {
        "╔═════════════════════════════ T R U   C O R E ══════════════════════════════╗",
        "║  MENU NAVIGATION // command code + ENTER // M switches deck view           ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "╠════════════════════════ WALLET // IDENTITY & VALUE ════════════════════════╣",
        "║                                                                            ║",
        "║  1 Create      2 Load      3 Save      4 New Address      5 Private Keys   ║",
        "║  6 Send TRU    7 Balance   8 My Addresses      9 Pubkeyhash                ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "╠════════════════════════ TOKENS // ASSETS & SCRIPTS ════════════════════════╣",
        "║                                                                            ║",
        "║  10 Vault      11 Contract Tokens      12 Index Debug                      ║",
        "║  13 Issue      14 Create Script        15 Script Vault                     ║",
        "║  16 Send Script      17 AI Tools               18 Send Token               ║",
        "║  burntoken Burn Token // permanent retirement sink                         ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "╠═══════════════════════ CONTRACTS // STATE & BRIDGE ════════════════════════╣",
        "║                                                                            ║",
        "║  19 Create     20 Bridge Options       21 Query State                      ║",
        "║  22 List       23 Update K/V           24 Vote      25 Voting Results      ║",
        "║  26 Mint Tokens    27 Token Supply                                         ║",
        "║  hashredeem Hash Redeem      timeredeem Time Redeem                        ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "╠═════════════════════════ NETWORK // CHAIN & PEERS ═════════════════════════╣",
        "║                                                                            ║",
        "║  28 Chain Info    29 Peers     30 Lookup Block      31 Mempool             ║",
        "║  32 Connect Peer      33 Message Peer      sync Check Sync                 ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "╠════════════════════════════ COMPUTE // MINING ═════════════════════════════╣",
        "║                                                                            ║",
        "║  34 CPU Mine      35 GPU Mine                                              ║",
        "╠════════════════════════════════════════════════════════════════════════════╣",
        "║                                                                            ║",
        "║  C Clear Output      M Compact / Full Deck      36 Exit                    ║",
        "╚════════════════════════════════════════════════════════════════════════════╝"
    };

    const std::vector<std::string> compactLines = {
        "╔═══════════════ T R U   C O R E // Q U I C K   N A V ═══════════════╗",
        "║  MENU NAVIGATION // command code + ENTER // M returns full deck    ║",
        "╠════════════════════════════════════════════════════════════════════╣",
        "╠══════════════════════════════ WALLET ══════════════════════════════╣",
        "║                                                                    ║",
        "║  1 New  2 Load  3 Save  4 Addr  5 Keys  6 Send  7 Balance          ║",
        "║  8 Addrs  9 Hash                                                   ║",
        "╠════════════════════════════════════════════════════════════════════╣",
        "╠════════════════════════ TOKENS / CONTRACTS ════════════════════════╣",
        "║                                                                    ║",
        "║  10 Vault  11 SC  12 Dbg  13 Issue  14 Script  15 Vault            ║",
        "║  16 Send  17 AITools  18 SendTok  burntoken Burn                   ║",
        "║  19 New  20 Bridge  21 Query  22 List  23 K/V  24 Vote            ║",
        "║  25 Results  26 Mint  27 Supply                                   ║",
        "║  hashredeem HLock      timeredeem TLock                            ║",
        "╠════════════════════════════════════════════════════════════════════╣",
        "╠═════════════════════════ CHAIN / COMPUTE ══════════════════════════╣",
        "║                                                                    ║",
        "║  28 Info 29 Peers 30 Block 31 Mempool 32 Connect 33 Msg            ║",
        "║  34 CPU 35 GPU  sync Sync  C Clear  M Full  36 Exit                ║",
        "╚════════════════════════════════════════════════════════════════════╝"
    };

    // Menu content must stop ABOVE the command row. The footer owns three
    // dedicated rows: command prompt, heartbeat, then sync status.
    const int availableBelowHeader = promptRow - SAFE_MENU_TOP;
    const bool fullFits =
        availableBelowHeader >= static_cast<int>(fullLines.size());
    const bool compactFits =
        availableBelowHeader >= static_cast<int>(compactLines.size());

    const bool compact = g_compactMenu || !fullFits;
    const auto& lines = compact ? compactLines : fullLines;

    int menuTop = SAFE_MENU_TOP;
    if (compact && !compactFits) {
        // Tiny-terminal fallback: preserve command access even when there is
        // physically no room below the persistent header.
        menuTop = std::max(2, promptRow - static_cast<int>(lines.size()));
    }

    static int lastTop = -1;
    static int lastBottom = -1;

    std::stringstream ss;

    if (lastTop > 0 && lastBottom >= lastTop) {
        const int clearBottom = std::min(lastBottom, rows - 1);
        for (int r = lastTop; r <= clearBottom; ++r)
            ss << "\033[" << r << ";1H\033[K";
    }

    int row = menuTop;
    for (size_t i = 0;
         i < lines.size() && row < promptRow;
         ++i, ++row) {
        const bool border = (i == 0 || i + 1 == lines.size());
        truDrawMenuLine(ss, row, lines[i], border ? 94 : 96, border);
    }

    lastTop = menuTop;
    lastBottom = row - 1;

    ss << "\033[" << promptRow << ";1H\033[K"
       << colorText(truNormalPromptText(), 93)
       << "\033[" << heartbeatRow << ";1H\033[K";
    const int syncRow = truTopLevelSyncRow(rows);
    if (syncRow > 0) {
        ss << "\033[" << syncRow << ";1H\033[K";
    }
    ss << "\033[" << promptRow << ";"
       << truCurrentPromptCol() << "H";

    fmt::print("{}", ss.str());
}


//std::string createSmartContract(Wallet& wallet, Blockchain& chain, P2PNode& node);

//============================================================================================
//                              Display TRUScripts (via displayOutput)
//============================================================================================
//============================================================================================
// TRU_TRUSCRIPT_VAULT_UI_V1
// Full-screen TRUScript Vault. Reuses the Token Vault terminal-ownership flag.
//============================================================================================
void displayTRUscriptsCLI(const std::vector<TRUScriptInfo>& scripts,
                          int rows,
                          std::mutex& coutMutex)
{
    if (scripts.empty()) {
        displayOutput("You have no TRUScripts yet.", rows, coutMutex);
        return;
    }

    auto formatNumber = [](uint64_t num) -> std::string {
        std::string str = std::to_string(num);
        for (int pos = static_cast<int>(str.length()) - 3; pos > 0; pos -= 3)
            str.insert(static_cast<size_t>(pos), ",");
        return str;
    };

    auto formatTimestamp = [](uint64_t timestamp) -> std::string {
        if (timestamp == 0) return "N/A";
        time_t t = static_cast<time_t>(timestamp);
        char buffer[100] = {0};
        std::tm* tmPtr = std::localtime(&t);
        if (!tmPtr) return "N/A";
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tmPtr);
        return std::string(buffer);
    };

    auto jsonValueText = [](const nlohmann::json& value) -> std::string {
        if (value.is_string()) return value.get<std::string>();
        if (value.is_null()) return "null";
        return value.dump();
    };

    auto clipForTerminal = [](const std::string& value, size_t maxLen) -> std::string {
        if (value.size() <= maxLen) return value;
        if (maxLen < 5) return value.substr(0, maxLen);
        return value.substr(0, maxLen - 3) + "...";
    };

    g_cliFullscreenView.store(true, std::memory_order_release);

    struct TRUScriptVaultGuard {
        std::mutex& mutex;
        ~TRUScriptVaultGuard() {
            {
                std::lock_guard<std::mutex> lock(mutex);
                fmt::print("\033[?25h");
                fmt::print("\033[?1049l");
                std::cout.flush();
            }
            g_cliFullscreenView.store(false, std::memory_order_release);
        }
    } guard{coutMutex};

    {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[?1049h");
        fmt::print("\033[2J\033[H\033[?25h");
        std::cout.flush();
    }

    size_t scriptIndex = 0;
    size_t metadataPage = 0;

    while (true) {
        if (scriptIndex >= scripts.size()) scriptIndex = 0;
        const auto& s = scripts[scriptIndex];

        std::vector<std::string> metaLines;
        if (s.metadata.is_object()) {
            for (const auto& item : s.metadata.items())
                metaLines.push_back(item.key() + " = " + jsonValueText(item.value()));
        }
        if (metaLines.empty()) metaLines.push_back("(no additional metadata)");

        auto [termRows, termCols] = g_terminalSize.get();
        if (termRows < 20) termRows = 20;
        if (termCols < 80) termCols = 80;
        const size_t metaPerPage = static_cast<size_t>(std::max(3, termRows - 19));
        const size_t metaPageCount = std::max<size_t>(1, (metaLines.size() + metaPerPage - 1) / metaPerPage);
        if (metadataPage >= metaPageCount) metadataPage = metaPageCount - 1;
        const size_t metaBegin = metadataPage * metaPerPage;
        const size_t metaEnd = std::min(metaBegin + metaPerPage, metaLines.size());
        const size_t clipWidth = static_cast<size_t>(std::max(45, termCols - 5));

        std::ostringstream out;
        out << "\033[2J\033[H";
        out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
        out << colorText("        🐸  TRUSCRIPT VAULT  🐸      INSCRIPTION " +
                         std::to_string(scriptIndex + 1) + "/" + std::to_string(scripts.size()) + "\n", 96, true);
        out << colorText("⛓════════════════════════════════════════════════════════════════════⛓\n", 36, true);
        out << colorText("INSCRIPTION DETAILS\n", 35, true);
        out << "  Inscription # : " << formatNumber(s.inscriptionIndex) << "\n";
        out << "  TXID          : " << s.txid << "\n";
        out << "  Owner         : " << s.owner << "\n";
        out << "  Block Height  : " << s.height << "\n";
        out << "  Atom Number   : " << formatNumber(s.satNumber) << "\n";
        out << "  Size          : " << s.sizeBytes << " bytes\n";
        out << "  Content Type  : " << s.contentType << "\n";
        out << "  Created       : " << formatTimestamp(s.timestamp) << "\n";
        out << colorText("──────────────────────── INSCRIBED DATA ────────────────────────\n", 36, true);
        out << "  " << clipForTerminal(s.data, clipWidth) << "\n";
        out << colorText("────────────────────────── METADATA ────────────────────────────\n", 36, true);
        out << "  Metadata page " << (metadataPage + 1) << "/" << metaPageCount << "\n";
        for (size_t i = metaBegin; i < metaEnd; ++i)
            out << "  " << clipForTerminal(metaLines[i], clipWidth) << "\n";
        out << colorText("──────────────────────────────────────────────────────────────────────\n", 36);
        out << "[N/Enter] Next inscription   [P] Previous inscription\n";
        out << "[J] Next metadata page       [K] Previous metadata page\n";
        out << "[Q] Back to main menu\nCommand: ";

        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("{}", out.str());
            std::cout.flush();
        }

        std::string cmd;
        if (!signalAwareGetline(cmd)) break;
        const auto first = cmd.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) cmd.clear();
        else {
            const auto last = cmd.find_last_not_of(" \t\r\n");
            cmd = cmd.substr(first, last - first + 1);
        }
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        if (cmd == "q" || cmd == "quit" || cmd == "back") break;
        if (cmd.empty() || cmd == "n" || cmd == "next") {
            scriptIndex = (scriptIndex + 1) % scripts.size(); metadataPage = 0; continue;
        }
        if (cmd == "p" || cmd == "prev" || cmd == "previous") {
            scriptIndex = (scriptIndex + scripts.size() - 1) % scripts.size(); metadataPage = 0; continue;
        }
        if (cmd == "j") { metadataPage = (metadataPage + 1) % metaPageCount; continue; }
        if (cmd == "k") { metadataPage = (metadataPage + metaPageCount - 1) % metaPageCount; continue; }
        try {
            const size_t requested = static_cast<size_t>(std::stoul(cmd));
            if (requested >= 1 && requested <= scripts.size()) {
                scriptIndex = requested - 1; metadataPage = 0;
            }
        } catch (...) {}
    }
}
// -------------------------------------------------------------------
//                  The CLI loop
// -------------------------------------------------------------------
void startCLI(Blockchain &chain, P2PNode &node, Wallet &wallet,
              std::atomic<bool> &spinnerRunning, std::mutex &coutMutex)
{
    // Display the newly minted banner
    printBanner(coutMutex);

    //
    // The CLI heartbeat worker is started exactly once by main(). startCLI()
    // does not spawn a second terminal painter.

    // Define how many lines the terminal might have
    //const int rows = 45;

    // Start terminal size monitoring thread
    std::atomic<bool> sizeMonitorRunning(true);
    std::thread sizeMonitorThread([&sizeMonitorRunning]() {
        while (sizeMonitorRunning) {
            g_terminalSize.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });

    ThreadJoiner sizeMonitorJoiner(sizeMonitorThread);

    // Patch 08B.4A.1b v3 / UI 30A v2:
    // startCLI owns only the terminal-size worker. The single heartbeat worker
    // is owned/joined by main(), so no duplicate spinner is created here.
    struct CliWorkerStopGuard {
        std::atomic<bool>& sizeMonitorRunningRef;

        ~CliWorkerStopGuard() noexcept {
            sizeMonitorRunningRef.store(false, std::memory_order_release);
        }
    };

    CliWorkerStopGuard cliWorkerStopGuard{
        sizeMonitorRunning
    };

    while (g_running) {
        // Get current terminal size
        auto [rows, cols] = g_terminalSize.get();
        
        // Ensure minimum size for proper display
        if (rows < 20) rows = 20;
        if (cols < 80) cols = 80;
        
        displayMenu(rows, coutMutex);

        // Status belongs only to normal deck mode. In Output Focus its pending
        // text is preserved until the deck returns.
        if (!g_cliContentFocus.load(std::memory_order_acquire)) {
            paintStatusNotice();
        }

        // The live miner header owns rows 9..15 in BOTH deck and Output Focus.
        displayMinerStats(chain, wallet, rows, coutMutex);

        // displayMinerStats uses absolute cursor positions and finishes on the
        // header, so restore the active command prompt afterwards.
        fmt::print("\033[{};{}H",
                   truMenuPromptRow(rows), truCurrentPromptCol());

        std::string choice;
        {
            // Fixed footer ownership while waiting for a top-level command:
            //   command prompt
            //   heartbeat
            //   sync status
            TruCliMenuPromptGuard menuPromptGuard;
            paintCliSyncStatus(
                getCliSyncStatusSnapshot(), rows, coutMutex, false);
            // Restore the command cursor after the initial sync paint.
            fmt::print("\033[{};{}H",
                       truMenuPromptRow(rows), truCurrentPromptCol());
            signalAwareGetline(choice);
        }

        // Normalize accidental leading/trailing spaces only.
        {
            const auto first = choice.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) {
                choice.clear();
            } else {
                const auto last = choice.find_last_not_of(" \t\r\n");
                choice = choice.substr(first, last - first + 1);
            }
        }
        
        // New command, new result generation. Output Focus itself remains
        // active so M still distinguishes "return to deck" from view toggle.
        resetCliCommandOutputGeneration();

#ifdef TRU_08B3T_TEST_HOOKS
        // hidden LOCAL-CLI-only runtime test commands.
        // this parser is absent from production builds by default.
        // Deliberately absent from displayMenu() and never routed through RPC.
        if (choice == "08b3t" || choice.rfind("08b3t ", 0) == 0) {
            std::istringstream testInput(choice);
            std::string rootCommand, subCommand;
            testInput >> rootCommand >> subCommand;

            if (subCommand.empty() || subCommand == "help") {
                displayOutput(
                    "08B.3T LOCAL TEST COMMANDS (hidden; no RPC):\n"
                    "  08b3t status\n"
                    "  08b3t probe\n"
                    "  08b3t validate <64-hex-side-tip> [repeat 1..20]\n"
                    "  08b3t validate-live <64-hex-side-tip> [repeat 1..20]\n"
                    "  08b3t roundtrip\n"
                    "Start validate with repeat=1; lock-held mode intentionally stalls block submission.\n"
                    "roundtrip requires zero P2P peers AND no active miner.",
                    rows, coutMutex);
                continue;
            }
            if (subCommand == "status") {
                displayOutput(chain.debug08B3TStatus(), rows, coutMutex);
                continue;
            }
            std::string report;
            if (subCommand == "probe") {
                chain.debug08B3TProbeTipUndoJournal(report);
                displayOutput(report, rows, coutMutex);
                continue;
            }
            if (subCommand == "validate" || subCommand == "validate-live") {
                std::string candidateHash;
                int repeat = 1;
                testInput >> candidateHash;
                if (!(testInput >> repeat)) repeat = 1;
                chain.debug08B3TValidateCandidate(
                    candidateHash, repeat, subCommand == "validate-live", report);
                displayOutput(report, rows, coutMutex);
                continue;
            }
            if (subCommand == "roundtrip") {
                chain.debug08B3TDisconnectReapplyTip(report);
                displayOutput(report, rows, coutMutex);
                continue;
            }
            displayOutput("Unknown 08B.3T command. Enter: 08b3t help", rows, coutMutex);
            continue;
        }

        // hidden LOCAL-CLI-only positive-cache FIFO fixture.
        // Entire branch is compiled out when TRU_08B3T_TEST_HOOKS=OFF.
        // No RPC registration exists.
        // hidden LOCAL-CLI-only immutable negative-cache FIFO fixture.
        // Entire branch is compiled out when TRU_08B3T_TEST_HOOKS=OFF.
        // No RPC registration exists.
        if (choice == "08b4d5t" || choice.rfind("08b4d5t ", 0) == 0) {
            std::istringstream testInput(choice);
            std::string rootCommand, subCommand;
            testInput >> rootCommand >> subCommand;

            if (subCommand.empty() || subCommand == "help") {
                displayOutput(
                    "08B.4D.5T IMMUTABLE NEGATIVE-CACHE FIFO FIXTURE (hidden; no RPC):\n"
                    "  08b4d5t fifo257\n"
                    "Requires TRU_ENABLE_08B3T_TEST_HOOKS and dedicated 4D5T gate.\n"
                    "Cache is restored before return; durable state is never touched.\n"
                    "Automatic/network reorganization remains DISABLED.",
                    rows, coutMutex);
                continue;
            }

            if (subCommand != "fifo257") {
                displayOutput(
                    "Unknown 08B.4D.5T command. Enter: 08b4d5t help",
                    rows, coutMutex);
                continue;
            }

            std::string report;
            chain.debug08B4D5TNegativeCacheFifo(report);
            displayOutput(report, rows, coutMutex);
            continue;
        }

        if (choice == "08b4d4t" || choice.rfind("08b4d4t ", 0) == 0) {
            std::istringstream testInput(choice);
            std::string rootCommand, subCommand;
            testInput >> rootCommand >> subCommand;

            if (subCommand.empty() || subCommand == "help") {
                displayOutput(
                    "08B.4D.4T POSITIVE-CACHE FIFO FIXTURE (hidden; no RPC):\n"
                    "  08b4d4t fifo33\n"
                    "Requires TRU_ENABLE_08B3T_TEST_HOOKS and dedicated 4D4T gate.\n"
                    "Cache is restored before return; durable state is never touched.\n"
                    "Automatic/network reorganization remains DISABLED.",
                    rows, coutMutex);
                continue;
            }

            if (subCommand != "fifo33") {
                displayOutput(
                    "Unknown 08B.4D.4T command. Enter: 08b4d4t help",
                    rows, coutMutex);
                continue;
            }

            std::string report;
            chain.debug08B4D4TPositiveCacheFifo(report);
            displayOutput(report, rows, coutMutex);
            continue;
        }

        // hidden LOCAL-CLI-only pressure fixture.
        // Compiled out when TRU_08B3T_TEST_HOOKS=OFF; never routed through RPC.
        if (choice == "08b4d2t" || choice.rfind("08b4d2t ", 0) == 0) {
            std::istringstream testInput(choice);
            std::string rootCommand, subCommand;
            testInput >> rootCommand >> subCommand;

            if (subCommand.empty() || subCommand == "help") {
                displayOutput(
                    "08B.4D.2T LOCAL PRESSURE FIXTURE (hidden; no RPC):\\n"
                    "  08b4d2t equal\\n"
                    "  08b4d2t higher\\n"
                    "Requires the existing 08B.3T enable + mutation gates, plus the 4D.2T gate.\\n"
                    "Automatic/network reorganization remains DISABLED.",
                    rows, coutMutex);
                continue;
            }

            if (subCommand != "equal" && subCommand != "higher") {
                displayOutput(
                    "Unknown 08B.4D.2T command. Enter: 08b4d2t help",
                    rows, coutMutex);
                continue;
            }

            std::string report;
            chain.debug08B4D2TRunFixture(subCommand, report);
            displayOutput(report, rows, coutMutex);
            continue;
        }

        // Patch 08B.4A/4B.1: hidden development-only reorg preflight and
        // MANUAL controlled executor. Automatic network reorganization remains
        // disabled. Production builds compile this parser out with test hooks.
        if (choice == "08b4a" || choice.rfind("08b4a ", 0) == 0) {
            std::istringstream testInput(choice);
            std::string rootCommand, subCommand;
            testInput >> rootCommand >> subCommand;

            if (subCommand.empty() || subCommand == "help") {
                displayOutput(
                    "08B.4A / 08B.4B.1 v2 LOCAL REORG COMMANDS (hidden; no RPC):\n"
                    "  08b4a status\n"
                    "  08b4a preflight <64-hex-side-tip>\n"
                    "  08b4a prepare <64-hex-side-tip>\n"
                    "  08b4a execute <64-hex-side-tip>\n"
                    "preflight validates a strict ChainWork256-winning plan in the 08B.3 sandbox.\n"
                    "prepare persists only an authenticated PREPARED marker.\n"
                    "execute is MANUAL/GATED and requires that exact PREPARED plan, both runtime gates, "
                    "zero peers and no active miner. Mid-execution crash recovery is NOT present until 08B.4C.\n"
                    "Automatic/network reorganization remains DISABLED.",
                    rows, coutMutex);
                continue;
            }
            if (subCommand == "status") {
                displayOutput(chain.debug08B4AStatus(), rows, coutMutex);
                continue;
            }

            std::string candidateHash;
            testInput >> candidateHash;
            std::string report;
            if (subCommand == "preflight") {
                chain.debug08B4APreflightCandidate(candidateHash, report);
                displayOutput(report, rows, coutMutex);
                continue;
            }
            if (subCommand == "prepare") {
                chain.debug08B4APrepareCandidateForRestartTest(candidateHash, report);
                displayOutput(report, rows, coutMutex);
                continue;
            }
            if (subCommand == "execute") {
                bool shutdownRequired = false;
                chain.debug08B4BExecutePreparedCandidate(
                    candidateHash, report, shutdownRequired);
                displayOutput(report, rows, coutMutex);
                if (shutdownRequired) {
                    Logger::log(
                        "[Patch08B.4B.1 v2] Controlled executor requested fail-stop shutdown after partial mutation");
                    g_running.store(false, std::memory_order_release);
                    throw CliShutdownInterrupt{};
                }
                continue;
            }

            displayOutput("Unknown 08B.4A/4B command. Enter: 08b4a help", rows, coutMutex);
            continue;
        }
#endif  // TRU_08B3T_TEST_HOOKS

        // public sequential navigation adapter.
        // The visible CLI is 1..36 in screen order. Internally, route those
        // numbers to the established handler codes so command logic remains
        // untouched. Lettered legacy aliases remain accepted but unadvertised.
        static const std::unordered_map<std::string, std::string>
            kPublicCliToLegacy = {
                {"1",  "1"},   {"2",  "2"},   {"3",  "3"},
                {"4",  "4"},   {"5",  "4a"},  {"6",  "5"},
                {"7",  "6"},   {"8",  "14"},  {"9",  "18a"},
                {"10", "12"},  {"11", "12a"}, {"12", "12b"},
                {"13", "13"},  {"14", "13a"}, {"15", "13b"},
                {"16", "13c"}, {"17", "13f"}, {"18", "15"},
                {"19", "18"},  {"20", "18b"}, {"21", "20"},
                {"22", "20a"}, {"23", "20u"}, {"24", "21"},
                {"25", "22"},  {"26", "23"},  {"27", "24"},
                {"28", "8"},   {"29", "9"},   {"30", "10"},
                {"31", "19"},  {"32", "16"},  {"33", "17"},
                {"34", "7"},   {"35", "7a"},  {"36", "11"}
            };

        if (const auto it = kPublicCliToLegacy.find(choice);
            it != kPublicCliToLegacy.end()) {
            choice = it->second;
        }

        if (choice == "1") {
            // Create new wallet
            try {
                std::string newAddr = wallet.generateNewAddress();
                displayOutput("[ NEW ADDRESS ]" + newAddr, rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to create wallet: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "2") {
            // Load wallet
            displayPrompt("Enter wallet file path: ", rows, coutMutex);
            std::string filename;
            signalAwareGetline(filename);
            try {
                if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::LEGACY_PLAINTEXT) {
                    wallet.loadFromFile(filename);
                } else {
                    Logger::log("[SEC-14R.1] encrypted wallet already loaded by constructor; skipping legacy plaintext load");
                }
                displayOutput("[CLI] Wallet loaded from: " + filename, rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to load wallet: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "3") {
            // Save wallet
            displayPrompt("Enter filename to save: ", rows, coutMutex);
            std::string filename;
            signalAwareGetline(filename);
            try {
                if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::LEGACY_PLAINTEXT) {
                    wallet.saveToFile(filename);
                } else {
                    Logger::log("[SEC-14R.1] encrypted wallet persistence is authenticated; skipping legacy plaintext save");
                }
                displayOutput("[CLI] Wallet saved to: " + filename, rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to save wallet: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "4") {
            // Generate new address
            try {
                std::string newAddress = wallet.generateNewAddress();
                uint32_t idx = wallet.getAddressIndex() - 1;
                //printQRCode(newAddress);
                viewAddressQRCode(newAddress);
                // Derive private key and public key
                std::string privPEM = wallet.deriveHDPrivateKey(idx);
                ECDSAKey newKey = ECDSAKey::fromPrivateKey(privPEM);
                std::vector<unsigned char> derivedPubKey = newKey.getCompressedSec1();

                // Get the original public key for comparison
                std::vector<unsigned char> originalPubKey = wallet.deriveHDPublicKey(idx);
                std::string derivedPubKeyHex = bytesToHex(derivedPubKey);
                std::string originalPubKeyHex = bytesToHex(originalPubKey);
                displayOutput("[CLI] Derived PubKey: " + derivedPubKeyHex, rows, coutMutex);
                displayOutput("[CLI] Original PubKey: " + originalPubKeyHex, rows, coutMutex);

                // Compute address from derived public key
                unsigned char hash160[HASH160_LEN];
                if (wally_hash160(derivedPubKey.data(), derivedPubKey.size(), hash160, HASH160_LEN) != WALLY_OK) {
                    throw std::runtime_error("Failed to compute hash160");
                }
                unsigned char verplus[1 + HASH160_LEN];
                verplus[0] = tru_network::MAINNET_P2PKH_VERSION;
                memcpy(verplus + 1, hash160, HASH160_LEN);
                char* computedAddr = nullptr;
                if (wally_base58_from_bytes(verplus, sizeof(verplus), BASE58_FLAG_CHECKSUM, &computedAddr) != WALLY_OK) {
                    throw std::runtime_error("Failed to compute address from public key");
                }
                std::string computedAddress(computedAddr);
                wally_free_string(computedAddr);

                // Verify
                if (computedAddress != newAddress) {
                    displayOutput("[CLI] Error: Generated address does not match derived public key! " +
                                  newAddress + " != " + computedAddress, rows, coutMutex);
                } else {
                    displayOutput("[CLI] New address generated and verified: " + newAddress, rows, coutMutex);
                }
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to generate new address: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "4a" || choice == "4A") {
            try {
                auto allAddrs = wallet.getAllAddresses();
                if (allAddrs.empty()) {
                    displayOutput("[CLI] No addresses in wallet!", rows, coutMutex);
                } else {
                    // 1) Clear screen
                    std::cout << "\033[2J\033[H";
        
                    // 2) Header in bold magenta
                    std::cout << colorText("[CLI] Private keys for all addresses:\n\n", 95, true);
        
                    // 3) List each address (green) + key (magenta)
                    for (size_t i = 0; i < allAddrs.size(); ++i) {
                        const auto& addr = allAddrs[i];
                        std::string priv;
                        try {
                            priv = wallet.getPrivateKeyForAddress(addr);
                        } catch (const std::exception& e) {
                            priv = std::string("Error: ") + e.what();
                        }
                        // Address
                        std::cout << "  [" << i << "] "
                                  << colorText(addr, 32, true) << "\n";
                        // Private Key
                        std::cout << "       "
                                  << colorText("Private Key:", 95, true) << " "
                                  << colorText(priv, 95) << "\n\n";
                    }
        
                    // 4) Pause until user hits Enter
                    std::cout << "Press Enter to return to menu...";
                    signalAwareIgnoreLine();
        
                    // 5) Clear screen before redrawing the menu
                    std::cout << "\033[2J\033[H";
                }
            } catch (...) {
                displayOutput("[CLI] Failed to retrieve private keys.", rows, coutMutex);
            }
        }
        else if (choice == "5") {
            beginProgressiveResult(rows, coutMutex);
            std::string outputBuffer;
            int currentRow = truResultFirstRow();
        
            try {
                std::string senderAddr = wallet.getCurrentAddress();
                displayOutputProgressive(outputBuffer, "Sender Address: " + senderAddr, currentRow, rows, coutMutex, 32, true); // Green with spacing
        
                displayPrompt("Enter recipient address (or 'back' to return): ", rows, coutMutex);
                std::string recipient;
                signalAwareGetline(recipient);
                recipient = trim(recipient); // Assuming trim is defined
                if (recipient == "back") {
                    displayOutputProgressive(outputBuffer, "Transaction cancelled. Returning to menu.", currentRow, rows, coutMutex, 31); // Red
                    continue;
                }
                displayOutputProgressive(outputBuffer, "Recipient Address: " + recipient, currentRow, rows, coutMutex, 32, true); // Green with spacing
        
                displayPrompt("Enter amount in TRU (or 'back' to return): ", rows, coutMutex);
                std::string amountStr;
                signalAwareGetline(amountStr);
                amountStr = trim(amountStr);
                if (amountStr == "back") {
                    displayOutputProgressive(outputBuffer, "Transaction cancelled. Returning to menu.", currentRow, rows, coutMutex, 31); // Red
                    continue;
                }
                std::uint64_t sendAtoms = 0;
                std::string sendAmountReason;
                if (!parseTRUAmountExact(amountStr, sendAtoms, sendAmountReason) ||
                    sendAtoms == 0) {
                    displayOutputProgressive(
                        outputBuffer,
                        "[CLI] Invalid TRU amount: " +
                            (sendAmountReason.empty()
                                 ? std::string("amount must be greater than 0")
                                 : sendAmountReason),
                        currentRow, rows, coutMutex, 31);
                    continue;
                }
                displayOutputProgressive(
                    outputBuffer,
                    "Amount: " + formatTRUAmountExact(sendAtoms),
                    currentRow, rows, coutMutex, 32, true);
        
                displayPrompt("Enter node IP (default 127.0.0.1, or 'back' to return): ", rows, coutMutex);
                std::string nodeIP;
                signalAwareGetline(nodeIP);
                nodeIP = trim(nodeIP);
                if (nodeIP == "back") {
                    displayOutputProgressive(outputBuffer, "Transaction cancelled. Returning to menu.", currentRow, rows, coutMutex, 31); // Red
                    continue;
                }
                if (nodeIP.empty()) nodeIP = "127.0.0.1";
                displayOutputProgressive(outputBuffer, "Node IP: " + nodeIP, currentRow, rows, coutMutex, 32, true); // Green with spacing
        
                displayPrompt(
                    "Enter node port (default " +
                        std::to_string(tru_network::MAINNET_RPC_PORT) +
                        ", or 'back' to return): ",
                    rows, coutMutex);
                std::string portStr;
                signalAwareGetline(portStr);
                portStr = trim(portStr);
                if (portStr == "back") {
                    displayOutputProgressive(outputBuffer, "Transaction cancelled. Returning to menu.", currentRow, rows, coutMutex, 31); // Red
                    continue;
                }
                int nodePort = tru_network::MAINNET_RPC_PORT;
                if (!portStr.empty()) {
                    try {
                        nodePort = std::stoi(portStr);
                        if (nodePort <= 0 || nodePort > 65535) {
                            displayOutputProgressive(outputBuffer, "[CLI] Invalid port number: Must be between 1 and 65535.", currentRow, rows, coutMutex, 31); // Red
                            continue;
                        }
                    } catch (const std::exception& e) {
                        displayOutputProgressive(outputBuffer, "[CLI] Invalid port number: " + std::string(e.what()), currentRow, rows, coutMutex, 31); // Red
                        continue;
                    }
                }
                displayOutputProgressive(outputBuffer, "Node Port: " + std::to_string(nodePort), currentRow, rows, coutMutex, 32, true); // Green with spacing
        
                Logger::log("[CLI] Sending transaction: sender=" + senderAddr + ", recipient=" + recipient +
                            ", amount=" + formatTRUAmountExact(sendAtoms) +
                            ", atoms=" + std::to_string(sendAtoms) +
                            ", nodeIP=" + nodeIP + ", nodePort=" + std::to_string(nodePort));
                std::string txid = wallet.send_transaction(recipient, sendAtoms, nodeIP, nodePort);
                displayOutputProgressive(outputBuffer, "[CLI] Transaction sent: " + txid, currentRow, rows, coutMutex, 32, true); // Green with spacing
        
                displaySuccessMessageTX(txid, senderAddr, recipient, sendAtoms, nodeIP, nodePort, coutMutex);
            } catch (const std::exception& e) {
                displayOutputProgressive(outputBuffer, "[CLI] Failed to send transaction: " + std::string(e.what()), currentRow, rows, coutMutex, 31, true); // Red with spacing
            }
        }
        else if (choice == "6") {
            try {
                double balConfirmed = wallet.check_balance(false);
                double balAll = wallet.check_balance(true);
                displayOutput(fmt::format("[CLI] Confirmed balance: {:.8f} TRU", balConfirmed), rows, coutMutex);
                displayOutput(fmt::format("[CLI] With unconfirmed: {:.8f} TRU", balAll), rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to check balance: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "6a") {
            wallet.forceClearUTXOCache();
            wallet.updateLocalUTXOSetFromChain();
            double refreshedBalance = wallet.check_balance();
            displayOutput(fmt::format("[CLI] Balance after manual refresh: {:.8f} TRU", refreshedBalance), rows, coutMutex);
        }
        else if (choice == "7") {
            // CPU mining submenu -> spawn standalone tru_miner_cpu.
            // The node no longer mines on its own threads; it stays responsive.
            using namespace tru_miner_proc;
            std::string minerAddr = wallet.getCurrentAddress();
            unsigned int hw = std::thread::hardware_concurrency();
            // mining submenu is owned result content.
            // Raw std::cout here was erased when displayPrompt() began a new
            // command-output generation, leaving only the final "4. Back" line.
            std::ostringstream cpuMenu;
            cpuMenu << "=== CPU MINING ===\n"
                    << "Mining Address: " << minerAddr << "\n"
                    << "Available CPU threads: " << (hw ? hw : 8) << "\n\n"
                    << "  1. Start Mining\n"
                    << "  2. Stop Mining\n"
                    << "  3. Mining Status\n"
                    << "  4. Back";
            displayResult(cpuMenu.str(), rows, coutMutex, 96);
            displayPrompt("CPU miner action [1-4]: ", rows, coutMutex);
            std::string sub; signalAwareGetline(sub);
            if (sub == "1") {
                if (g_cpuMinerPid > 0 && isAlive(g_cpuMinerPid)) {
                    displayOutput("[CLI] CPU miner already running (pid " + std::to_string(g_cpuMinerPid) + ").", rows, coutMutex);
                } else {
                    std::string threadsStr = "8";
                    displayPrompt("CPU threads [default 8]: ", rows, coutMutex);
                    std::string t; signalAwareGetline(t);
                    if (!t.empty()) threadsStr = t;
                    std::string portStr = std::to_string(tru_network::MAINNET_RPC_PORT);
                    // argv for execvp
                    std::vector<std::string> args = {
                        "tru_miner_cpu",
                        "--node-ip", "127.0.0.1",
                        "--node-port", portStr,
                        "--mineraddr", minerAddr,
                        "--threads", threadsStr
                    };
                    std::vector<char*> argv;
                    for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
                    argv.push_back(nullptr);
                    pid_t pid = spawnMiner("./tru_miner_cpu", argv.data(), "cpu_miner.log");
                    if (pid > 0) {
                        g_cpuMinerPid = pid;
                        displayOutput("[CLI] CPU miner started (pid " + std::to_string(pid) +
                                      ", threads=" + threadsStr + "). Output -> cpu_miner.log", rows, coutMutex);
                    } else {
                        displayOutput("[CLI] Failed to spawn ./tru_miner_cpu (is it in this directory?).", rows, coutMutex);
                    }
                }
            } else if (sub == "2") {
                stopMiner(g_cpuMinerPid, "CPU", rows, coutMutex);
            } else if (sub == "3") {
                bool up = (g_cpuMinerPid > 0 && isAlive(g_cpuMinerPid));
                displayOutput(std::string("[CLI] CPU miner status: ") +
                              (up ? ("RUNNING (pid " + std::to_string(g_cpuMinerPid) + ")") : "stopped"),
                              rows, coutMutex);
            }
            // sub == "4" or anything else: back to menu.
        }
        else if (choice == "7a") {
            // GPU mining submenu -> spawn standalone tru_miner.
            using namespace tru_miner_proc;
            std::string minerAddr = wallet.getCurrentAddress();
            // keep all GPU submenu choices inside
            // the owned result buffer so the mid-screen input card cannot erase them.
            const TruCliGpuInventory gpuInventory = detectTruOpenCLGpus();
            std::ostringstream gpuMenu;
            gpuMenu << "=== GPU MINING ===\n"
                    << "Mining Address: " << minerAddr << "\n"
                    << formatTruGpuInventory(gpuInventory) << "\n\n"
                    << "  1. Start GPU Mining\n"
                    << "  2. Stop GPU Mining\n"
                    << "  3. Mining Status\n"
                    << "  4. Back";
            displayResult(gpuMenu.str(), rows, coutMutex, 96);
            displayPrompt("GPU miner action [1-4]: ", rows, coutMutex);
            std::string sub; signalAwareGetline(sub);
            if (sub == "1") {
                if (g_gpuMinerPid > 0 && isAlive(g_gpuMinerPid)) {
                    displayOutput("[CLI] GPU miner already running (pid " + std::to_string(g_gpuMinerPid) + ").", rows, coutMutex);
                } else {
                    std::string portStr = std::to_string(tru_network::MAINNET_RPC_PORT);
                    std::vector<std::string> args = {
                        "tru_miner",
                        "--node-ip", "127.0.0.1",
                        "--node-port", portStr,
                        "--mineraddr", minerAddr
                    };
                    std::vector<char*> argv;
                    for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
                    argv.push_back(nullptr);
                    pid_t pid = spawnMiner("./tru_miner", argv.data(), "gpu_miner.log");
                    if (pid > 0) {
                        g_gpuMinerPid = pid;
                        displayOutput("[CLI] GPU miner started (pid " + std::to_string(pid) +
                                      "). Output -> gpu_miner.log", rows, coutMutex);
                    } else {
                        displayOutput("[CLI] Failed to spawn ./tru_miner (is it in this directory?).", rows, coutMutex);
                    }
                }
            } else if (sub == "2") {
                stopMiner(g_gpuMinerPid, "GPU", rows, coutMutex);
            } else if (sub == "3") {
                bool up = (g_gpuMinerPid > 0 && isAlive(g_gpuMinerPid));
                displayOutput(std::string("[CLI] GPU miner status: ") +
                              (up ? ("RUNNING (pid " + std::to_string(g_gpuMinerPid) + ")") : "stopped"),
                              rows, coutMutex);
            }
            // sub == "4" or anything else: back to menu.
        }
        else if (choice == "8") {
            // Print chain info
            try {
                printChainInfo(chain);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to print chain info: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "9") {
            // List peers
            try {
                node.listPeers();
                displayOutput("[CLI] Peer list updated.", rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to list peers: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "10") {
            // Lookup block
            displayPrompt("Enter block hash:", rows, coutMutex);
            std::string blockHash;
            signalAwareGetline(blockHash);
            try {
                Block b = chain.getBlock(blockHash);
                std::string info = fmt::format(
                    "Block Found:\nHash: {}\nHeight: {}\nTransactions: {}",
                    b.blockHash, b.header.version, b.transactions.size()
                );
                displayOutput(info, rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Block not found or error: " + std::string(e.what()), rows, coutMutex);
            }
        }
        else if (choice == "11") {
            // Exit
            displayOutput("Exiting... Goodbye!", rows, coutMutex);
            g_running = false;
            sizeMonitorRunning = false;
            break;
        }
        else if (choice == "12") {
            try {
                displayFormattedTokenList(wallet, rows, coutMutex);
            } catch (const std::exception& e) {
                std::string error = "[CLI] Failed to list tokens: " + std::string(e.what());
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("{}", error);
            }
        }
        else if (choice == "12b") {
            try {
                displayFormattedTokenList2(wallet, rows, coutMutex);
            } catch (const std::exception& e) {
                std::string error = "[CLI] Failed to list tokens: " + std::string(e.what());
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("{}", error);
            }
        }
        else if (choice == "13") {
            beginProgressiveResult(rows, coutMutex);
            std::string outputBuffer;
            int currentRow = truResultFirstRow();
        
            // Prompt user to select token type
            displayOutputProgressive(outputBuffer, "Which token type to create?\n1) FT\n2) NFT\n3) SFT\n4) NCFT\nEnter choice (or 'back' to return): ", currentRow, rows, coutMutex, 33, true); // Yellow
            std::string typeChoice = readLineWithTimeout(30); // Users can see and edit input
            typeChoice = trim(typeChoice);
            if (typeChoice == "back") {
                displayOutputProgressive(outputBuffer, "Token creation cancelled. Returning to menu.", currentRow, rows, coutMutex, 31, true); // Red
                continue;
            }
        
            std::string tokenType;
            if (typeChoice == "1") tokenType = "FT";
            else if (typeChoice == "2") tokenType = "NFT";
            else if (typeChoice == "3") tokenType = "SFT";
            else if (typeChoice == "4") tokenType = "NCFT";
            else {
                displayOutputProgressive(outputBuffer, "[CLI] Invalid choice. Use 1-4.", currentRow, rows, coutMutex, 31, true); // Red
                continue;
            }
            displayOutputProgressive(outputBuffer, "Token Type: " + tokenType, currentRow, rows, coutMutex, 32, true); // Green
        
            try {
                std::string txid;
                std::map<std::string, std::string> tokenDetails;
        
                // **Fungible Token (FT)**
                if (tokenType == "FT") {
                    displayOutputProgressive(outputBuffer, "Enter TokenID (e.g., MYTOKEN, or 'back' to return): ", currentRow, rows, coutMutex, 33, true); // Yellow
                    std::string tokenID = readLineWithTimeout(30); // Editable input
                    tokenID = trim(tokenID);
                    if (tokenID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["TokenID"] = tokenID;
                    displayOutputProgressive(outputBuffer, "TokenID: " + tokenID, currentRow, rows, coutMutex, 32, true); // Green
        
                    displayOutputProgressive(outputBuffer, "Enter total supply (uint64_t, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string supplyStr = readLineWithTimeout(30);
                    supplyStr = trim(supplyStr);
                    if (supplyStr == "back") throw std::runtime_error("User cancelled");
                    uint64_t supply = std::stoull(supplyStr);
                    if (supply == 0) throw std::runtime_error("Total supply must be greater than 0");
                    tokenDetails["Total Supply"] = supplyStr;
                    displayOutputProgressive(outputBuffer, "Total Supply: " + supplyStr, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter name (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string name = readLineWithTimeout(30);
                    name = trim(name);
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    displayOutputProgressive(outputBuffer, "Name: " + name, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter symbol (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string symbol = readLineWithTimeout(30);
                    symbol = trim(symbol);
                    if (symbol == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Symbol"] = symbol;
                    displayOutputProgressive(outputBuffer, "Symbol: " + symbol, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter description (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string desc = readLineWithTimeout(30);
                    desc = trim(desc);
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    displayOutputProgressive(outputBuffer, "Description: " + desc, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter image URL (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string img = readLineWithTimeout(30);
                    img = trim(img);
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    displayOutputProgressive(outputBuffer, "Image URL: " + img, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter decimals (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string decStr = readLineWithTimeout(30);
                    decStr = trim(decStr);
                    if (decStr == "back") throw std::runtime_error("User cancelled");
                    uint32_t decimals = std::stoi(decStr);
                    tokenDetails["Decimals"] = decStr;
                    displayOutputProgressive(outputBuffer, "Decimals: " + decStr, currentRow, rows, coutMutex, 32, true);
        
                    // Additional Metadata
                    std::unordered_map<std::string, std::string> additionalMeta;
                    displayOutputProgressive(outputBuffer, "Add additional metadata? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string addMeta = readLineWithTimeout(30);
                    addMeta = trim(addMeta);
                    if (addMeta == "back") throw std::runtime_error("User cancelled");
                    if (addMeta == "y" || addMeta == "Y") {
                        while (true) {
                            displayOutputProgressive(outputBuffer, "Enter key (or 'done' to finish, 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string key = readLineWithTimeout(30);
                            key = trim(key);
                            if (key == "back") throw std::runtime_error("User cancelled");
                            if (key == "done") break;
                            displayOutputProgressive(outputBuffer, "Key: " + key, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Enter value for " + key + " (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string value = readLineWithTimeout(30);
                            value = trim(value);
                            if (value == "back") throw std::runtime_error("User cancelled");
                            additionalMeta[key] = value;
                            displayOutputProgressive(outputBuffer, "Value: " + value, currentRow, rows, coutMutex, 32, true);
                        }
                    }
        
                    // IPFS Upload Logic
                    displayOutputProgressive(outputBuffer, "Upload image to IPFS? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string useIPFS = readLineWithTimeout(30);
                    useIPFS = trim(useIPFS);
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::string ipfsApi;
                        displayOutputProgressive(outputBuffer, "Upload to local IPFS node? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string useLocal = readLineWithTimeout(30);
                        useLocal = trim(useLocal);
                        if (useLocal == "back") throw std::runtime_error("User cancelled");
                        if (useLocal != "y" && useLocal != "Y") {
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server IP address (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string remoteIP = readLineWithTimeout(30);
                            remoteIP = trim(remoteIP);
                            if (remoteIP == "back") throw std::runtime_error("User cancelled");
                            displayOutputProgressive(outputBuffer, "Remote IPFS IP: " + remoteIP, currentRow, rows, coutMutex, 32, true);
        
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server port (default 5001, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string portStr = readLineWithTimeout(30);
                            portStr = trim(portStr);
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            int port = portStr.empty() ? 5001 : std::stoi(portStr);
                            displayOutputProgressive(outputBuffer, "Remote IPFS Port: " + std::to_string(port), currentRow, rows, coutMutex, 32, true);
                            ipfsApi = "/ip4/" + remoteIP + "/tcp/" + std::to_string(port);
                        }
        
                        std::string ipfsHash, localFile;
                        try {
                            displayOutputProgressive(outputBuffer, "Downloading image...", currentRow, rows, coutMutex, 33, true);
                            localFile = downloadImage(img);
                            displayOutputProgressive(outputBuffer, "Image downloaded to: " + localFile, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Uploading to IPFS...", currentRow, rows, coutMutex, 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsApi);
                            displayOutputProgressive(outputBuffer, "Image uploaded to IPFS with hash: " + ipfsHash, currentRow, rows, coutMutex, 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            displayOutputProgressive(outputBuffer, "Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.", currentRow, rows, coutMutex, 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }
        
                    // Issue FT and display success
                    txid = wallet.issueExtendedFT(tokenID, supply, name, symbol, desc, img, decimals, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("FT", txid, tokenDetails, coutMutex);
                    setStatusNotice("Token submitted (tx " + txid.substr(0, 12) +
                                    "...). PENDING until mined. Keep a miner running.", 32);
                }
        
                // **Non-Fungible Token (NFT)**
                else if (tokenType == "NFT") {
                    displayOutputProgressive(outputBuffer, "Enter NFT ID (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string nftID = readLineWithTimeout(30);
                    nftID = trim(nftID);
                    if (nftID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["NFT ID"] = nftID;
                    displayOutputProgressive(outputBuffer, "NFT ID: " + nftID, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter NFT Name (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string nftName = readLineWithTimeout(30);
                    nftName = trim(nftName);
                    if (nftName == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = nftName;
                    displayOutputProgressive(outputBuffer, "Name: " + nftName, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter description (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string desc = readLineWithTimeout(30);
                    desc = trim(desc);
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    displayOutputProgressive(outputBuffer, "Description: " + desc, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter image URL (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string img = readLineWithTimeout(30);
                    img = trim(img);
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    displayOutputProgressive(outputBuffer, "Image URL: " + img, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter creator (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string creator = readLineWithTimeout(30);
                    creator = trim(creator);
                    if (creator == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Creator"] = creator;
                    displayOutputProgressive(outputBuffer, "Creator: " + creator, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter external link (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string link = readLineWithTimeout(30);
                    link = trim(link);
                    if (link == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["External Link"] = link;
                    displayOutputProgressive(outputBuffer, "External Link: " + link, currentRow, rows, coutMutex, 32, true);
        
                    // Additional Metadata
                    std::unordered_map<std::string, std::string> additionalMeta;
                    displayOutputProgressive(outputBuffer, "Add additional metadata? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string addMeta = readLineWithTimeout(30);
                    addMeta = trim(addMeta);
                    if (addMeta == "back") throw std::runtime_error("User cancelled");
                    if (addMeta == "y" || addMeta == "Y") {
                        while (true) {
                            displayOutputProgressive(outputBuffer, "Enter key (or 'done' to finish, 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string key = readLineWithTimeout(30);
                            key = trim(key);
                            if (key == "back") throw std::runtime_error("User cancelled");
                            if (key == "done") break;
                            displayOutputProgressive(outputBuffer, "Key: " + key, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Enter value for " + key + " (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string value = readLineWithTimeout(30);
                            value = trim(value);
                            if (value == "back") throw std::runtime_error("User cancelled");
                            additionalMeta[key] = value;
                            displayOutputProgressive(outputBuffer, "Value: " + value, currentRow, rows, coutMutex, 32, true);
                        }
                    }
        
                    // IPFS Upload Logic (same as FT, omitted for brevity)
                    displayOutputProgressive(outputBuffer, "Upload image to IPFS? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string useIPFS = readLineWithTimeout(30);
                    useIPFS = trim(useIPFS);
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::string ipfsApi;
                        displayOutputProgressive(outputBuffer, "Upload to local IPFS node? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string useLocal = readLineWithTimeout(30);
                        useLocal = trim(useLocal);
                        if (useLocal == "back") throw std::runtime_error("User cancelled");
                        if (useLocal != "y" && useLocal != "Y") {
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server IP address (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string remoteIP = readLineWithTimeout(30);
                            remoteIP = trim(remoteIP);
                            if (remoteIP == "back") throw std::runtime_error("User cancelled");
                            displayOutputProgressive(outputBuffer, "Remote IPFS IP: " + remoteIP, currentRow, rows, coutMutex, 32, true);
        
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server port (default 5001, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string portStr = readLineWithTimeout(30);
                            portStr = trim(portStr);
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            int port = portStr.empty() ? 5001 : std::stoi(portStr);
                            displayOutputProgressive(outputBuffer, "Remote IPFS Port: " + std::to_string(port), currentRow, rows, coutMutex, 32, true);
                            ipfsApi = "/ip4/" + remoteIP + "/tcp/" + std::to_string(port);
                        }
        
                        std::string ipfsHash, localFile;
                        try {
                            displayOutputProgressive(outputBuffer, "Downloading image...", currentRow, rows, coutMutex, 33, true);
                            localFile = downloadImage(img);
                            displayOutputProgressive(outputBuffer, "Image downloaded to: " + localFile, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Uploading to IPFS...", currentRow, rows, coutMutex, 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsApi);
                            displayOutputProgressive(outputBuffer, "Image uploaded to IPFS with hash: " + ipfsHash, currentRow, rows, coutMutex, 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            displayOutputProgressive(outputBuffer, "Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.", currentRow, rows, coutMutex, 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }
        
                    // Issue NFT and display success
                    txid = wallet.issueExtendedNFT(nftID, nftName, desc, img, creator, link, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("NFT", txid, tokenDetails, coutMutex);
                }
        
                // **Semi-Fungible Token (SFT)**
                else if (tokenType == "SFT") {
                    displayOutputProgressive(outputBuffer, "Enter SFT TokenID (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string tokenID = readLineWithTimeout(30);
                    tokenID = trim(tokenID);
                    if (tokenID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["SFT TokenID"] = tokenID;
                    displayOutputProgressive(outputBuffer, "SFT TokenID: " + tokenID, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter total supply (uint64_t, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string supplyStr = readLineWithTimeout(30);
                    supplyStr = trim(supplyStr);
                    if (supplyStr == "back") throw std::runtime_error("User cancelled");
                    uint64_t supply = std::stoull(supplyStr);
                    if (supply == 0) throw std::runtime_error("Total supply must be greater than 0");
                    tokenDetails["Total Supply"] = supplyStr;
                    displayOutputProgressive(outputBuffer, "Total Supply: " + supplyStr, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter name (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string name = readLineWithTimeout(30);
                    name = trim(name);
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    displayOutputProgressive(outputBuffer, "Name: " + name, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter symbol (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string symbol = readLineWithTimeout(30);
                    symbol = trim(symbol);
                    if (symbol == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Symbol"] = symbol;
                    displayOutputProgressive(outputBuffer, "Symbol: " + symbol, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter description (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string desc = readLineWithTimeout(30);
                    desc = trim(desc);
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    displayOutputProgressive(outputBuffer, "Description: " + desc, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter image URL (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string img = readLineWithTimeout(30);
                    img = trim(img);
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    displayOutputProgressive(outputBuffer, "Image URL: " + img, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter decimals (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string decStr = readLineWithTimeout(30);
                    decStr = trim(decStr);
                    if (decStr == "back") throw std::runtime_error("User cancelled");
                    uint32_t decimals = std::stoi(decStr);
                    tokenDetails["Decimals"] = decStr;
                    displayOutputProgressive(outputBuffer, "Decimals: " + decStr, currentRow, rows, coutMutex, 32, true);
        
                    // Advanced AI Metadata
                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::vector<std::string> sftFields = {"ai_version", "learning_mode", "growth_algorithm", "adaptation_rate", "evolution_epoch", "description_ai"};
                    displayOutputProgressive(outputBuffer, "Enter advanced AI metadata (leave blank to skip, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    for (const auto& field : sftFields) {
                        displayOutputProgressive(outputBuffer, "Enter " + field + " (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string value = readLineWithTimeout(30);
                        value = trim(value);
                        if (value == "back") throw std::runtime_error("User cancelled");
                        if (!value.empty()) {
                            additionalMeta[field] = value;
                            displayOutputProgressive(outputBuffer, field + ": " + value, currentRow, rows, coutMutex, 32, true);
                        }
                    }
        
                    // IPFS Upload Logic (same as FT, omitted for brevity)
                    displayOutputProgressive(outputBuffer, "Upload image to IPFS? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string useIPFS = readLineWithTimeout(30);
                    useIPFS = trim(useIPFS);
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::string ipfsApi;
                        displayOutputProgressive(outputBuffer, "Upload to local IPFS node? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string useLocal = readLineWithTimeout(30);
                        useLocal = trim(useLocal);
                        if (useLocal == "back") throw std::runtime_error("User cancelled");
                        if (useLocal != "y" && useLocal != "Y") {
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server IP address (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string remoteIP = readLineWithTimeout(30);
                            remoteIP = trim(remoteIP);
                            if (remoteIP == "back") throw std::runtime_error("User cancelled");
                            displayOutputProgressive(outputBuffer, "Remote IPFS IP: " + remoteIP, currentRow, rows, coutMutex, 32, true);
        
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server port (default 5001, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string portStr = readLineWithTimeout(30);
                            portStr = trim(portStr);
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            int port = portStr.empty() ? 5001 : std::stoi(portStr);
                            displayOutputProgressive(outputBuffer, "Remote IPFS Port: " + std::to_string(port), currentRow, rows, coutMutex, 32, true);
                            ipfsApi = "/ip4/" + remoteIP + "/tcp/" + std::to_string(port);
                        }
        
                        std::string ipfsHash, localFile;
                        try {
                            displayOutputProgressive(outputBuffer, "Downloading image...", currentRow, rows, coutMutex, 33, true);
                            localFile = downloadImage(img);
                            displayOutputProgressive(outputBuffer, "Image downloaded to: " + localFile, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Uploading to IPFS...", currentRow, rows, coutMutex, 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsApi);
                            displayOutputProgressive(outputBuffer, "Image uploaded to IPFS with hash: " + ipfsHash, currentRow, rows, coutMutex, 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            displayOutputProgressive(outputBuffer, "Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.", currentRow, rows, coutMutex, 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }
        
                    // Issue SFT and display success
                    txid = wallet.issueExtendedSFT(tokenID, supply, name, symbol, desc, img, decimals, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("SFT", txid, tokenDetails, coutMutex);
                }
        
                // **Non-Compliant Fungible Token (NCFT)**
                else if (tokenType == "NCFT") {
                    displayOutputProgressive(outputBuffer, "Enter NCFT ID (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string ncftID = readLineWithTimeout(30);
                    ncftID = trim(ncftID);
                    if (ncftID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["NCFT ID"] = ncftID;
                    displayOutputProgressive(outputBuffer, "NCFT ID: " + ncftID, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter name (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string name = readLineWithTimeout(30);
                    name = trim(name);
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    displayOutputProgressive(outputBuffer, "Name: " + name, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter description (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string desc = readLineWithTimeout(30);
                    desc = trim(desc);
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    displayOutputProgressive(outputBuffer, "Description: " + desc, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter image/multimedia URL (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string img = readLineWithTimeout(30);
                    img = trim(img);
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image/Multimedia URL"] = img;
                    displayOutputProgressive(outputBuffer, "Image/Multimedia URL: " + img, currentRow, rows, coutMutex, 32, true);
        
                    displayOutputProgressive(outputBuffer, "Enter quantity (uint64_t, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string qtyStr = readLineWithTimeout(30);
                    qtyStr = trim(qtyStr);
                    if (qtyStr == "back") throw std::runtime_error("User cancelled");
                    uint64_t quantity = std::stoull(qtyStr);
                    if (quantity == 0) throw std::runtime_error("Quantity must be greater than 0");
                    tokenDetails["Quantity"] = qtyStr;
                    displayOutputProgressive(outputBuffer, "Quantity: " + qtyStr, currentRow, rows, coutMutex, 32, true);
        
                    // Advanced AI/Art Metadata
                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::vector<std::string> ncftFields = {"ai_engine", "style_descriptor", "dynamic_morph", "update_interval", "creator_signature", "last_evolution"};
                    displayOutputProgressive(outputBuffer, "Enter advanced AI/art metadata (leave blank to skip, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    for (const auto& field : ncftFields) {
                        displayOutputProgressive(outputBuffer, "Enter " + field + " (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string value = readLineWithTimeout(30);
                        value = trim(value);
                        if (value == "back") throw std::runtime_error("User cancelled");
                        if (!value.empty()) {
                            additionalMeta[field] = value;
                            displayOutputProgressive(outputBuffer, field + ": " + value, currentRow, rows, coutMutex, 32, true);
                        }
                    }
        
                    // IPFS Upload Logic (same as FT, omitted for brevity)
                    displayOutputProgressive(outputBuffer, "Upload image to IPFS? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                    std::string useIPFS = readLineWithTimeout(30);
                    useIPFS = trim(useIPFS);
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::string ipfsApi;
                        displayOutputProgressive(outputBuffer, "Upload to local IPFS node? (y/n, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                        std::string useLocal = readLineWithTimeout(30);
                        useLocal = trim(useLocal);
                        if (useLocal == "back") throw std::runtime_error("User cancelled");
                        if (useLocal != "y" && useLocal != "Y") {
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server IP address (or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string remoteIP = readLineWithTimeout(30);
                            remoteIP = trim(remoteIP);
                            if (remoteIP == "back") throw std::runtime_error("User cancelled");
                            displayOutputProgressive(outputBuffer, "Remote IPFS IP: " + remoteIP, currentRow, rows, coutMutex, 32, true);
        
                            displayOutputProgressive(outputBuffer, "Enter remote IPFS server port (default 5001, or 'back' to return): ", currentRow, rows, coutMutex, 33, true);
                            std::string portStr = readLineWithTimeout(30);
                            portStr = trim(portStr);
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            int port = portStr.empty() ? 5001 : std::stoi(portStr);
                            displayOutputProgressive(outputBuffer, "Remote IPFS Port: " + std::to_string(port), currentRow, rows, coutMutex, 32, true);
                            ipfsApi = "/ip4/" + remoteIP + "/tcp/" + std::to_string(port);
                        }
        
                        std::string ipfsHash, localFile;
                        try {
                            displayOutputProgressive(outputBuffer, "Downloading image...", currentRow, rows, coutMutex, 33, true);
                            localFile = downloadImage(img);
                            displayOutputProgressive(outputBuffer, "Image downloaded to: " + localFile, currentRow, rows, coutMutex, 32, true);
                            displayOutputProgressive(outputBuffer, "Uploading to IPFS...", currentRow, rows, coutMutex, 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsApi);
                            displayOutputProgressive(outputBuffer, "Image uploaded to IPFS with hash: " + ipfsHash, currentRow, rows, coutMutex, 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            displayOutputProgressive(outputBuffer, "Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.", currentRow, rows, coutMutex, 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }
        
                    // Issue NCFT and display success
                    txid = wallet.issueExtendedNCFT(ncftID, quantity, name, desc, img, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("NCFT", txid, tokenDetails, coutMutex);
                }
            } catch (const std::exception& e) {
                displayOutputProgressive(outputBuffer, "[CLI] Failed to issue token: " + std::string(e.what()), currentRow, rows, coutMutex, 31, true); // Red
                // also pin the failure as a sticky notice so it isn't
                // covered by the menu redraw (e.g. immature-coinbase rejection).
                setStatusNotice("Token FAILED: " + std::string(e.what()) +
                                "  (see node log for details)", 31);
            }
        }
        else if (choice == "13a") {
            // 0) Friendly size reminder
            displayOutput(
              "💡 Reminder: TRUScripts live in an 80-byte OP_RETURN; after JSON & prefix you get ~30–40 chars.",
              rows, coutMutex
            );
        
            // 1) Prompt
            displayPrompt("Enter text to inscribe:", rows, coutMutex);
            std::string data;
            signalAwareGetline(data);
        
            // 2) Blank → back to menu
            if (data.empty()) {
                displayOutput("⟵ No input provided. Returning to menu.", rows, coutMutex);
                continue;   // <-- was `break;`
            }
        
            // 3) Try inscribing
            try {
                std::string txid = wallet.inscribeTRUScript(data, wallet.getCurrentAddress());
                TruTransactionReceipt receipt;
                receipt.type = "TRUSCRIPT INSCRIPTION";
                receipt.txid = txid;
                receipt.fields = {{"Owner", wallet.getCurrentAddress()}};
                receipt.next = "Mine one block, then inspect the confirmed TRUScript index.";
                displayTransactionReceipt(receipt, coutMutex);
            } catch (const std::exception &e) {
                displayOutput("[Error] " + std::string(e.what()), rows, coutMutex);
            }
        
            continue; // make sure we go right back to the menu
        }
        else if (choice == "13b") {
            auto scripts = wallet.getTRUScripts(wallet.getCurrentAddress());
            if (scripts.empty()) {
                displayOutput("You have no TRUScripts yet.", rows, coutMutex);
            } else {
                //printTRUscriptsCLI(scripts);
                displayTRUscriptsCLI(scripts, rows, coutMutex);
            }
            continue;
        }
        else if (choice == "13c")
        {
            displayOutput("=== Transfer TRUScript ===", rows, coutMutex);

            // Show owned TRUScripts
            auto scripts = wallet.getTRUScripts(wallet.getCurrentAddress());
            if (scripts.empty())
            {
                displayOutput("You have no TRUScripts to transfer.", rows, coutMutex);
                continue;
            }

            displayOutput("Your TRUScripts:", rows, coutMutex);
            for (size_t i = 0; i < scripts.size(); ++i)
            {
                std::ostringstream oss;
                oss << i + 1 << ". \"" << scripts[i].data << "\" (tx: "
                    << scripts[i].txid.substr(0, 8) << "...)";
                displayOutput(oss.str(), rows, coutMutex);
            }

            displayPrompt("Enter number to transfer (or 0 to cancel):", rows, coutMutex);
            std::string indexStr;
            signalAwareGetline(indexStr);

            size_t index;
            try
            {
                index = std::stoull(indexStr);
            }
            catch (...)
            {
                displayOutput("Invalid input.", rows, coutMutex);
                continue;
            }

            if (index == 0 || index > scripts.size())
            {
                displayOutput("Cancelled.", rows, coutMutex);
                continue;
            }

            displayPrompt("Enter recipient address:", rows, coutMutex);
            std::string recipient;
            signalAwareGetline(recipient);

            if (recipient.empty())
            {
                displayOutput("Cancelled.", rows, coutMutex);
                continue;
            }

            try
            {
                std::string transferTxid = wallet.transferTRUScript(
                    scripts[index - 1].txid,
                    recipient);
                displayOutput("✅ TRUScript transferred! TX: " + transferTxid, rows, coutMutex);
            }
            catch (const std::exception &e)
            {
                displayOutput("❌ Transfer failed: " + std::string(e.what()), rows, coutMutex);
            }
            continue;
        }
        else if (choice == "13d") {
            menuIssueAI_Tokens(wallet, coutMutex);
        }

        else if (choice == "13e")
        {
            using nlohmann::json;

            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("\033[2J\033[1;1H"); // Clear screen
            }

            // Terminal rows for ::displayOutput
            int rows = 24, cols = 80;
            {
                auto [c, r] = getTerminalSize();
                cols = c;
                rows = r;
            }

            ::displayOutput("=== AI Token Communication ===\n", rows, coutMutex);

            // ---- REAL SCAN of user's AI-enabled tokens ----
            std::vector<std::string> aiTokens;     // canonical token namespace IDs
            std::vector<std::string> aiTokenTxids; // matching txids (same index)
            std::vector<std::string> aiTokenNames; // pretty names from metadata
            std::vector<std::string> walletAddrs = wallet.getAllAddresses();

            const auto &chain = wallet.getBlockchain();
            const LevelDBStorage *storage = chain.getStorage();

            if (!storage)
            {
                ::displayOutput("Storage unavailable. Cannot scan tokens.", rows, coutMutex);
                continue;
            }

            // For each wallet address, scan ownership index:
            // keys: "tokenOwnership:<address>:<tokenID>" => value JSON {"amount", "txid"} (checksum stripped by iteratePrefix)
            for (const auto &addr : walletAddrs)
            {
                const std::string prefix = "tokenOwnership:" + addr + ":";
                try
                {
                    storage->iteratePrefix(prefix, [&](const std::string &keySansPrefix, const std::string &valueJson)
                                           {
                // keySansPrefix == canonical token namespace ID (16 hex for V2; 8 hex legacy)
                std::string tokenNamespaceID = keySansPrefix;

                // parse stored JSON to get the birth txid
                std::string txid;
                try {
                    auto j = json::parse(valueJson);
                    if (j.contains("txid") && j["txid"].is_string()) {
                        txid = j["txid"].get<std::string>();
                    }
                } catch (...) {
                    // skip malformed
                    return;
                }
                if (txid.empty()) return;

                // Load token metadata at "tokenMetadata:<txid>" and detect AI marker
                bool isAI = false;
                std::string tokenName = tokenNamespaceID;
                try {
                    ExtendedTokenData metaPack = chain.fetchTokenMetadata("tokenMetadata:" + txid);
                    // Heuristics: look for common AI markers in metadata map
                    const auto& md = metaPack.meta.data;
                    auto has = [&](const char* k){ return md.find(k) != md.end(); };
                    if (has("ai_engine") || has("ai") || has("sentient") || has("oobabooga_model") || has("neural_canvas")) {
                        isAI = true;
                    }
                   // if (auto it = md.find("name"); it != md.end()) tokenName = it->second;
                    if (auto it = md.find("name"); it != md.end())
                    {
                        tokenName = it.value().is_string() ? it.value().get<std::string>()
                                                           : it.value().dump();
                    }
                } catch (...) {
                    // couldn't fetch metadata; keep fallback name
                }

                if (isAI) {
                    aiTokens.push_back(tokenNamespaceID);
                    aiTokenTxids.push_back(txid);
                    aiTokenNames.push_back(tokenName);
                } });
                }
                catch (const std::exception &e)
                {
                    Logger::log(std::string("[13e] iteratePrefix exception: ") + e.what());
                }
            }

            if (aiTokens.empty())
            {
                ::displayOutput("No AI-enabled tokens found for your wallet addresses.", rows, coutMutex);
                ::displayOutput("Tip: Issue an SFT/NCFT with AI metadata first.", rows, coutMutex);
                continue;
            }

            // Render list
            ::displayOutput("Your AI-Enabled Tokens:\n", rows, coutMutex);
            for (size_t i = 0; i < aiTokens.size(); ++i)
            {
                ::displayOutput(fmt::format("{}). {}  (TokenID: {}, txid: {})",
                                            i + 1, aiTokenNames[i], aiTokens[i], aiTokenTxids[i]),
                                rows, coutMutex);
            }

            ::displayOutput("\nSelect token (number) or 'back': ", rows, coutMutex);
            std::string selection = readLineWithTimeout(30);
            selection = trim(selection);
            if (selection == "back")
            {
                continue;
            }

            int idx = -1;
            try
            {
                idx = std::stoi(selection) - 1;
            }
            catch (...)
            {
                idx = -1;
            }
            if (idx < 0 || static_cast<size_t>(idx) >= aiTokens.size())
            {
                ::displayOutput("Invalid selection.", rows, coutMutex);
                continue;
            }

            std::string selectedToken = aiTokens[idx];
            ::displayOutput("\nSelected: " + selectedToken, rows, coutMutex);

            displayPrompt("Enter your message to the token: ", rows, coutMutex);
            std::string message = readLineWithTimeout(60);
            message = trim(message);
            if (message.empty() || message == "back")
            {
                continue;
            }

            // Prepare request for the AI oracle route
            json request = {
                {"tokenID", selectedToken},
                {"address", wallet.getCurrentAddress()},
                {"message", message}};

            ::displayOutput("\nSending to AI Oracle...", rows, coutMutex);

            // Invoke the registered handlers.
            json response;
            try
            {
                response = handleInteractWithAIToken(const_cast<Blockchain &>(chain), request, 1);
            }
            catch (const std::exception &e)
            {
                ::displayOutput(std::string("RPC error: ") + e.what(), rows, coutMutex);
                continue;
            }

            if (response.contains("result") && response["result"].contains("requestID"))
            {
                std::string requestID = response["result"]["requestID"].get<std::string>();
                ::displayOutput("Request ID: " + requestID, rows, coutMutex);
                ::displayOutput("Waiting for AI response...", rows, coutMutex);

                // Poll up to ~10s
                for (int i = 0; i < 10; ++i)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));

                    json checkReq = {{"requestID", requestID}};
                    json aiResponse;
                    try
                    {
                        aiResponse = handleGetAIResponse(const_cast<Blockchain &>(chain), checkReq, 2);
                    }
                    catch (const std::exception &e)
                    {
                        ::displayOutput(std::string("RPC error while checking: ") + e.what(), rows, coutMutex);
                        break;
                    }

                    if (aiResponse.contains("result"))
                    {
                        const auto &res = aiResponse["result"];
                        if (res.contains("status") && res["status"].is_string() && res["status"] != "pending")
                        {
                            ::displayOutput("\n🤖 Token Response:", rows, coutMutex);
                            if (res.contains("content") && res["content"].is_string())
                            {
                                ::displayOutput(res["content"].get<std::string>(), rows, coutMutex);
                            }
                            else
                            {
                                ::displayOutput("[no content field in response]", rows, coutMutex);
                            }
                            break;
                        }
                    }
                }
            }
            else
            {
                ::displayOutput("AI oracle did not return a requestID.", rows, coutMutex);
            }

            ::displayOutput("\nPress Enter to continue...", rows, coutMutex);
            signalAwareIgnoreLine();
        }

        else if (choice == "13f") {
            menuTokenAiTools(wallet, rows, coutMutex);
        }
        else if (choice == "14") {
            // Show current address + QR, then list the other addresses below
            try {
                auto allAddrs = wallet.getAllAddresses();
                if (allAddrs.empty()) {
                    displayOutput("[CLI] No addresses in wallet!", rows, coutMutex);
                } else {
                    size_t currentIdx = wallet.getCurrentIndex();
                    std::string currentAddr = allAddrs[currentIdx];

                    // Clear screen for a focused view
                    std::cout << "\033[2J\033[H";

                    // Header and current address in green
                    std::cout << colorText("Current Address:\n", 95, true);
                    std::cout << colorText(currentAddr, 32, true) << "\n\n";

                    // QR code for current address
                    printQRCode(currentAddr);

                    // List the other addresses beneath
                    std::cout << "\nOther Addresses (" << allAddrs.size() - 1 << "):\n";
                    for (size_t i = 0; i < allAddrs.size(); ++i) {
                        if (i == currentIdx) continue;
                        std::cout << "  [" << i << "] " << allAddrs[i] << "\n";
                    }

                    // Wait for Enter to return
                    std::cout << "\nPress Enter to return to menu...";
                    signalAwareIgnoreLine();

                    // Clear screen again before redrawing menu
                    std::cout << "\033[2J\033[H";
                }
            } catch (const std::exception& e) {
                Logger::log("[CLI] Failed to list addresses: " + std::string(e.what()));
                displayOutput("[CLI] Failed to list addresses: " + std::string(e.what()), rows, coutMutex);
            } 
        }
        else if (choice == "15") {
            // Send token
            displayPrompt("Enter Token ID to send (e.g., 'bid'): ", rows, coutMutex);
            std::string tokenID;
            signalAwareGetline(tokenID);
            if (tokenID.empty() || !std::all_of(tokenID.begin(), tokenID.end(), ::isalnum)) {
                displayOutput("[CLI] Error: Invalid Token ID. Must be alphanumeric and non-empty.", rows, coutMutex);
                continue;
            }
        
            displayPrompt("Enter quantity to send (positive integer): ", rows, coutMutex);
            std::string quantityStr;
            signalAwareGetline(quantityStr);
            uint64_t quantity = 0;
            try {
                quantity = std::stoull(quantityStr);
                if (quantity == 0) {
                    displayOutput("[CLI] Error: Quantity must be greater than 0.", rows, coutMutex);
                    continue;
                }
            } catch (const std::out_of_range&) {
                displayOutput("[CLI] Error: Quantity is too large for processing.", rows, coutMutex);
                continue;
            } catch (const std::invalid_argument&) {
                displayOutput("[CLI] Error: Invalid quantity format. Use a positive integer.", rows, coutMutex);
                continue;
            }
        
            displayPrompt("Enter recipient address (Base58 format): ", rows, coutMutex);
            std::string recipient;
            signalAwareGetline(recipient);
            if (recipient.empty()) {
                displayOutput("[CLI] Error: Recipient address cannot be empty.", rows, coutMutex);
                continue;
            }
            try {
                std::vector<unsigned char> decoded = base58Decode(recipient);
                if (decoded.size() != 25 || decoded[0] != tru_network::MAINNET_P2PKH_VERSION) {
                    displayOutput("[CLI] Error: Invalid recipient address. Must be a valid TRU mainnet P2PKH address.", rows, coutMutex);
                    continue;
                }
            } catch (...) {
                displayOutput("[CLI] Error: Recipient address failed Base58 decoding.", rows, coutMutex);
                continue;
            }
        
            std::string senderAddress = wallet.getCurrentAddress();
            displayOutput("Using sender address: " + senderAddress, rows, coutMutex);
            try {
                std::vector<unsigned char> decoded = base58Decode(senderAddress);
                if (decoded.size() != 25 || decoded[0] != tru_network::MAINNET_P2PKH_VERSION) {
                    displayOutput("[CLI] Error: Invalid sender address from wallet.", rows, coutMutex);
                    continue;
                }
            } catch (...) {
                displayOutput("[CLI] Error: Sender address failed Base58 decoding.", rows, coutMutex);
                continue;
            }
        
            try {
                Logger::log("[CLI] Sending token: tokenID=" + tokenID + ", quantity=" + std::to_string(quantity) + 
                            ", recipient=" + recipient + ", sender=" + senderAddress);
        
                // Find token UTXO to ensure the sender owns the token
                auto [utxoTxid,controllingVout, vout] = wallet.findTokenUTXO(tokenID, senderAddress);
                if (utxoTxid.empty()) {
                    displayOutput("[CLI] Error: No UTXO found for tokenID=" + tokenID, rows, coutMutex);
                    continue;
                }
        
                // Send the token and get the transfer transaction ID
                std::string txid = wallet.sendToken(tokenID, quantity, recipient, senderAddress);
                Logger::log("[CLI] Token transfer transaction created: txid=" + txid);
        
                // Fetch token type and metadata using the transfer txid
                std::string tokenType = "Unknown";
                std::unordered_map<std::string, std::string> metadata;
                LevelDBStorage* storage = chain.getStorage();
                if (!storage) {
                    Logger::log("[CLI] Error: Storage pointer is null");
                    displayOutput("[CLI] Warning: Could not fetch token metadata - storage unavailable", rows, coutMutex);
                } else {
                    std::string metaKey = "tokenMetadata:" + txid;
                    std::string metaValue;
                    Logger::log("[CLI] Querying metadata key: " + metaKey);
                    if (storage->get(metaKey, metaValue)) {
                        try {
                            nlohmann::json metaJson = nlohmann::json::parse(metaValue);
                            tokenType = metaJson.value("type", "Unknown");
                            if (metaJson.contains("meta") && metaJson["meta"].is_object()) {
                                for (const auto& [key, value] : metaJson["meta"].items()) {
                                    if (value.is_string()) {
                                        metadata[key] = value.get<std::string>();
                                    }
                                }
                            }
                            Logger::log("[CLI] Retrieved tokenType=" + tokenType + ", metadata size=" + std::to_string(metadata.size()));
                        } catch (const std::exception& e) {
                            Logger::log("[CLI] Warning: Failed to parse metadata for txid=" + txid + ": " + e.what());
                            displayOutput("[CLI] Warning: Could not parse token metadata - " + std::string(e.what()), rows, coutMutex);
                        }
                    } else {
                        Logger::log("[CLI] Warning: Metadata key not found: " + metaKey);
                        displayOutput("[CLI] Warning: No metadata found for transfer txid=" + txid, rows, coutMutex);
                    }
                }
        
                // Display the success message with the correct token type and metadata
                displaySuccessMessageTokenSend(txid, tokenID, quantity, recipient, senderAddress, tokenType, metadata, coutMutex);
            } catch (const std::invalid_argument& e) {
                displayOutput("[CLI] Error: Invalid input - " + std::string(e.what()), rows, coutMutex);
            } catch (const std::runtime_error& e) {
                displayOutput("[CLI] Error: Transaction failed - " + std::string(e.what()), rows, coutMutex);
            } catch (...) {
                displayOutput("[CLI] Error: Unexpected failure while sending token.", rows, coutMutex);
            }
        }
        else if (choice == "burntoken") {
            displayPrompt("Enter Token ID to permanently burn: ", rows, coutMutex);
            std::string tokenID;
            signalAwareGetline(tokenID);
            tokenID = trim(tokenID);
            if (tokenID.empty()) {
                displayOutput("[TOKEN-BURN-01] Burn cancelled: token ID is empty.", rows, coutMutex);
                continue;
            }

            const std::string senderAddress = wallet.getCurrentAddress();
            if (senderAddress.empty()) {
                displayOutput("[TOKEN-BURN-01] No current wallet address.", rows, coutMutex);
                continue;
            }

            std::ostringstream warning;
            warning
                << "=== TOKEN-BURN-01 // PERMANENT TOKEN RETIREMENT ===\n"
                << "Token: " << tokenID << "\n"
                << "From:  " << senderAddress << "\n"
                << "Sink:  " << tru_token_burn_v1::BURN_ADDRESS << "\n\n"
                << "This transfers one complete current token holding to the "
                   "canonical burn sink.\n"
                << "Issuance/history remains on-chain. The transfer cannot be "
                   "reversed by the wallet.\n"
                << "If this address owns multiple independent holdings of the same "
                   "token, repeat after each burn confirms.\n";
            displayOutput(warning.str(), rows, coutMutex);

            displayPrompt("Type BURN exactly to continue: ", rows, coutMutex);
            std::string confirmation;
            signalAwareGetline(confirmation);
            confirmation = trim(confirmation);
            if (confirmation != "BURN") {
                displayOutput("[TOKEN-BURN-01] Burn cancelled.", rows, coutMutex);
                continue;
            }

            try {
                const std::string txid =
                    wallet.burnToken(tokenID, senderAddress);
                std::ostringstream result;
                result
                    << "TOKEN BURN SUBMITTED\n"
                    << "TXID: " << txid << "\n"
                    << "Burn address: "
                    << tru_token_burn_v1::BURN_ADDRESS << "\n"
                    << "Wait for confirmation before attempting another holding.";
                displayOutput(result.str(), rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput(
                    "[TOKEN-BURN-01] Burn failed: " + std::string(e.what()),
                    rows, coutMutex);
            }
        }
        else if (choice == "16") {
            // Connect to a peer
            displayPrompt("Enter peer IP: ", rows, coutMutex);
            std::string ip;
            signalAwareGetline(ip);

            displayPrompt("Enter peer port: ", rows, coutMutex);
            std::string portStr;
            signalAwareGetline(portStr);
            int port;
            try {
                port = std::stoi(portStr);
            } catch (...) {
                displayOutput("[CLI] Invalid port number", rows, coutMutex);
                continue;
            }

            if (node.connectToPeer(ip, port)) {
                displayOutput("Connected to peer: " + ip + ":" + portStr, rows, coutMutex);
            } else {
                displayOutput("Failed to connect to peer: " + ip + ":" + portStr, rows, coutMutex);
            }
        }
        else if (choice == "17") {
            // Send message to a peer
            displayPrompt("Enter peer IP: ", rows, coutMutex);
            std::string ip;
            signalAwareGetline(ip);

            displayPrompt("Enter peer port: ", rows, coutMutex);
            std::string portStr;
            signalAwareGetline(portStr);
            int port;
            try {
                port = std::stoi(portStr);
            } catch (...) {
                displayOutput("[CLI] Invalid port number", rows, coutMutex);
                continue;
            }

            displayPrompt("Enter message: ", rows, coutMutex);
            std::string message;
            signalAwareGetline(message);

            node.sendMessageToPeer(ip, port, message);
            displayOutput("Message sent to peer: " + ip + ":" + portStr, rows, coutMutex);
        }
        else if (choice == "18")
        {
            beginProgressiveResult(rows, coutMutex);
            std::string outputBuffer;
            int currentRow = truResultFirstRow();

            try
            {
                // 1) show sender & pubkeyhash
                const std::string senderAddr = wallet.getCurrentAddress();
                const std::string pubkeyhash = getCurrentPubkeyhash(wallet);
                displayOutputProgressive(outputBuffer,
                                         "Your Address: " + senderAddr, currentRow, rows, coutMutex, 32, true);
                displayOutputProgressive(outputBuffer,
                                         "Current Pubkeyhash: " + pubkeyhash, currentRow, rows, coutMutex, 32, true);

                // 2) prompt contract type (1–11)
                displayOutputProgressive(outputBuffer,
                                         "Choose contract type:\n"
                                         "  1) Time Lock\n"
                                         "  2) OP_RETURN\n"
                                         "  3) Hash Lock\n"
                                         "  4) Custom Script\n"
                                         "  5) Oracle‑Locked\n"
                                         "  6) Stateful Key/Value\n"
                                         "  7) Token Issuer (Mining Tokens)\n"
                                         "  8) Voting Contract (Voting)\n"
                                         "  9) NOVO/BSTY Bridge (Bridge)\n"
                                         " 10) Multisig / Escrow (2-of-3)\n"
                                         " 11) HTLC / Atomic Swap",
                                         currentRow, rows, coutMutex, 33, true);

                displayPrompt(
                    "Contract type [1-11/name/back]: ",
                    rows, coutMutex);
                std::string contractTypeChoice;
                uint32_t displayLockTime = 0;
                std::string preimageHashForDisplay = "";
                signalAwareGetline(contractTypeChoice);
                contractTypeChoice = trim(contractTypeChoice);
                if (contractTypeChoice.empty() || toLower(contractTypeChoice) == "back")
                    throw std::runtime_error("User cancelled");

                // 3) map to a canonical type string
                std::string contractType;
                if (contractTypeChoice == "1" || toLower(contractTypeChoice) == "time lock")
                    contractType = "TIME LOCK";
                else if (contractTypeChoice == "2" || toLower(contractTypeChoice) == "op_return")
                    contractType = "OP_RETURN";
                else if (contractTypeChoice == "3" || toLower(contractTypeChoice) == "hash lock")
                    contractType = "HASH LOCK";
                else if (contractTypeChoice == "4" || toLower(contractTypeChoice) == "custom script")
                    contractType = "CUSTOM SCRIPT";
                else if (contractTypeChoice == "5" || toLower(contractTypeChoice) == "oracle-locked" || toLower(contractTypeChoice) == "oracle lock")
                    contractType = "ORACLE LOCK";
                else if (contractTypeChoice == "6" || toLower(contractTypeChoice) == "stateful" || toLower(contractTypeChoice).find("stateful") != std::string::npos)
                    contractType = "STATEFUL CONTRACT";
                else if (contractTypeChoice == "7" || toLower(contractTypeChoice) == "token issuer")
                    contractType = "TOKEN ISSUER";
                else if (contractTypeChoice == "8" || toLower(contractTypeChoice) == "voting")
                    contractType = "VOTING";
                else if (contractTypeChoice == "9" || toLower(contractTypeChoice) == "novo/bsty bridge")
                    contractType = "BRIDGE";
                else if (contractTypeChoice == "10" ||
                         toLower(contractTypeChoice) == "multisig" ||
                         toLower(contractTypeChoice) == "multisig escrow" ||
                         toLower(contractTypeChoice) == "escrow")
                    contractType = "MULTISIG ESCROW";
                else if (contractTypeChoice == "11" ||
                         toLower(contractTypeChoice) == "htlc" ||
                         toLower(contractTypeChoice) == "atomic swap" ||
                         toLower(contractTypeChoice) == "htlc / atomic swap")
                    contractType = "HTLC ATOMIC SWAP";
                else
                {
                    displayOutputProgressive(outputBuffer,
                                             "[CLI] Invalid choice. Use 1-11 or name.", currentRow, rows, coutMutex, 31, true);
                    throw std::runtime_error("Invalid contract type");
                }
                displayOutputProgressive(outputBuffer,
                                         "Contract Type: " + contractType, currentRow, rows, coutMutex, 32, true);

                std::string multisigAction;
                if (contractType == "MULTISIG ESCROW") {
                    multisigAction = toLower(trim(getValidatedInput(
                        "Multisig action [create/sign/redeem]: ",
                        [](const std::string& s) {
                            const std::string v = toLower(trim(s));
                            return v == "create" || v == "sign" || v == "redeem";
                        },
                        "[CLI] Enter create, sign, or redeem.",
                        outputBuffer, currentRow, rows, coutMutex)));
                    displayOutputProgressive(
                        outputBuffer,
                        "Multisig action: " + multisigAction,
                        currentRow, rows, coutMutex, 32, true);
                }

                std::string htlcAction;
                if (contractType == "HTLC ATOMIC SWAP") {
                    htlcAction = toLower(trim(getValidatedInput(
                        "HTLC action [create/claim/refund]: ",
                        [](const std::string& s) {
                            const std::string v = toLower(trim(s));
                            return v == "create" || v == "claim" || v == "refund";
                        },
                        "[CLI] Enter create, claim, or refund.",
                        outputBuffer, currentRow, rows, coutMutex)));
                    displayOutputProgressive(
                        outputBuffer,
                        "HTLC action: " + htlcAction,
                        currentRow, rows, coutMutex, 32, true);
                }

                // 4) collect parameters
                std::string scriptText, contractName, lockReason;
                std::string statefulInitKey;
                std::vector<unsigned char> statefulInitValue;
                uint64_t contractAmount = 0; // Amount to lock in the contract

                // Prompt for amount to lock (except for OP_RETURN which always has 0 value)
                if (contractType != "OP_RETURN" &&
                    (contractType != "MULTISIG ESCROW" || multisigAction == "create") &&
                    (contractType != "HTLC ATOMIC SWAP" || htlcAction == "create"))
                {
                    std::string amountStr = getValidatedInput(
                        "Enter amount to lock [TRU]: ",
                        [](const std::string &s)
                        {
                            std::uint64_t atoms = 0;
                            std::string reason;
                            return parseTRUAmountExact(s, atoms, reason) && atoms > 0;
                        },
                        "[CLI] Invalid TRU amount. Use up to 8 decimal places and a value greater than 0.",
                        outputBuffer, currentRow, rows, coutMutex);
                    std::string amountReason;
                    if (!parseTRUAmountExact(amountStr, contractAmount, amountReason) ||
                        contractAmount == 0) {
                        throw std::runtime_error(
                            "Invalid TRU contract amount: " + amountReason);
                    }
                    displayOutputProgressive(
                        outputBuffer,
                        "Amount to lock: " + formatTRUAmountExact(contractAmount),
                        currentRow, rows, coutMutex, 32, true);
                }

                if (contractType == "HTLC ATOMIC SWAP")
                {
                    auto getHtlcFundingTxid = [&]() {
                        return toLower(trim(getValidatedInput(
                            "HTLC funding TXID [64 hex]: ",
                            [](const std::string& s) {
                                return s.size() == 64U && isValidHex(s);
                            },
                            "[CLI] Funding TXID must be exactly 64 hex characters.",
                            outputBuffer, currentRow, rows, coutMutex)));
                    };

                    auto getHtlcRecipient = [&]() {
                        std::string raw = trim(getValidatedInput(
                            "Recipient TRU address [address/me]: ",
                            [&](const std::string& s) {
                                const std::string v = trim(s);
                                return toLower(v) == "me" || isValidAddress(v);
                            },
                            "[CLI] Enter a valid TRU mainnet P2PKH address or 'me'.",
                            outputBuffer, currentRow, rows, coutMutex));
                        if (toLower(raw) == "me") return senderAddr;
                        return raw;
                    };

                    if (htlcAction == "claim") {
                        const std::string fundingTxid = getHtlcFundingTxid();
                        const std::string recipient = getHtlcRecipient();
                        const std::string preimageHex =
                            toLower(trim(getValidatedInput(
                                "Secret preimage HEX: ",
                                [](const std::string& s) {
                                    return !s.empty() &&
                                           s.size() <= 510U &&
                                           (s.size() % 2U) == 0U &&
                                           isValidHex(s);
                                },
                                "[CLI] Enter 1..255 binary preimage bytes as even-length hex.",
                                outputBuffer, currentRow, rows, coutMutex)));

                        const auto result = wallet.claimHtlcAtomicSwapV1(
                            fundingTxid, 1U, recipient, preimageHex);

                        std::ostringstream report;
                        report << "HTLC / ATOMIC SWAP V1 CLAIMED\n"
                               << "Family: htlc_atomic_swap_v1\n"
                               << "Branch: CLAIM\n"
                               << "Funding Outpoint: " << result.contractTxid
                               << ":" << result.contractVout << "\n"
                               << "Claim TXID: " << result.txid << "\n"
                               << "Recipient: " << result.recipient << "\n"
                               << "Release Amount: "
                               << formatTRUAmountExact(result.releaseAmountAtoms) << "\n"
                               << "Fee: " << formatTRUAmountExact(result.feeAtoms) << "\n"
                               << "Secret HASH160: " << result.secretHash160Hex << "\n"
                               << "Signer Pubkey: " << result.signerPubkeyHex << "\n"
                               << "Sighash: " << result.sighashHex << "\n"
                               << "Status: MEMPOOL ACCEPTED\n"
                               << "Next: mine one block, then verify the HTLC outpoint is spent.";
                        displayOutput(report.str(), rows, coutMutex);
                        continue;
                    }

                    if (htlcAction == "refund") {
                        const std::string fundingTxid = getHtlcFundingTxid();
                        const std::string recipient = getHtlcRecipient();

                        const auto result = wallet.refundHtlcAtomicSwapV1(
                            fundingTxid, 1U, recipient);

                        std::ostringstream report;
                        report << "HTLC / ATOMIC SWAP V1 REFUNDED\n"
                               << "Family: htlc_atomic_swap_v1\n"
                               << "Branch: REFUND\n"
                               << "Funding Outpoint: " << result.contractTxid
                               << ":" << result.contractVout << "\n"
                               << "Refund TXID: " << result.txid << "\n"
                               << "Recipient: " << result.recipient << "\n"
                               << "Release Amount: "
                               << formatTRUAmountExact(result.releaseAmountAtoms) << "\n"
                               << "Fee: " << formatTRUAmountExact(result.feeAtoms) << "\n"
                               << "Refund Time: " << result.refundLockTime
                               << " (" << formatTimestamp(result.refundLockTime) << ")\n"
                               << "Signer Pubkey: " << result.signerPubkeyHex << "\n"
                               << "Sighash: " << result.sighashHex << "\n"
                               << "Status: MEMPOOL ACCEPTED\n"
                               << "Next: mine one block, then verify the HTLC outpoint is spent.";
                        displayOutput(report.str(), rows, coutMutex);
                        continue;
                    }

                    std::string myCompressedPubkey;
                    try {
                        const auto myPub = wallet.getPublicKeyForAddress(senderAddr);
                        if (myPub.size() == 33U &&
                            (myPub[0] == 0x02 || myPub[0] == 0x03)) {
                            myCompressedPubkey = bytesToHex(myPub);
                            displayOutputProgressive(
                                outputBuffer,
                                "Your compressed pubkey (use 'me'): " +
                                    myCompressedPubkey,
                                currentRow, rows, coutMutex, 36, true);
                        }
                    } catch (const std::exception& e) {
                        displayOutputProgressive(
                            outputBuffer,
                            "[HTLC-01C] Unable to derive current compressed pubkey: " +
                                std::string(e.what()),
                            currentRow, rows, coutMutex, 33, true);
                    }

                    auto normalizeHtlcPubkey = [&](const std::string& raw) {
                        std::string v = trim(raw);
                        if (toLower(v) == "me") {
                            if (myCompressedPubkey.empty()) {
                                throw std::runtime_error(
                                    "'me' is unavailable because the current wallet "
                                    "does not expose a canonical compressed pubkey");
                            }
                            return myCompressedPubkey;
                        }
                        std::transform(
                            v.begin(), v.end(), v.begin(),
                            [](unsigned char c) {
                                return static_cast<char>(std::tolower(c));
                            });
                        return v;
                    };

                    auto validHtlcPubkey = [&](const std::string& raw) {
                        try {
                            const std::string v = normalizeHtlcPubkey(raw);
                            return v.size() == 66U &&
                                   (v.rfind("02", 0) == 0 ||
                                    v.rfind("03", 0) == 0) &&
                                   isValidHex(v);
                        } catch (...) {
                            return false;
                        }
                    };

                    const std::string commitmentMode = toLower(trim(getValidatedInput(
                        "Secret commitment [generate/hash]: ",
                        [](const std::string& s) {
                            const std::string v = toLower(trim(s));
                            return v == "generate" || v == "hash";
                        },
                        "[CLI] Enter 'generate' for a secure 32-byte secret or 'hash' to supply an existing HASH160.",
                        outputBuffer, currentRow, rows, coutMutex)));

                    std::string generatedPreimageHex;
                    std::string secretHash160Hex;
                    if (commitmentMode == "generate") {
                        const auto secret = wallet.generateHtlcAtomicSwapSecretV1();
                        generatedPreimageHex = secret.preimageHex;
                        secretHash160Hex = secret.hash160Hex;
                        displayOutputProgressive(
                            outputBuffer,
                            "Generated secret HASH160: " + secretHash160Hex,
                            currentRow, rows, coutMutex, 36, true);
                        displayOutputProgressive(
                            outputBuffer,
                            "KEEP THE PREIMAGE SECRET AND SAFE — it will be shown once in the final receipt.",
                            currentRow, rows, coutMutex, 36, true);
                    } else {
                        secretHash160Hex = toLower(trim(getValidatedInput(
                            "Secret HASH160 commitment [40 hex]: ",
                            [](const std::string& s) {
                                return s.size() == 40U && isValidHex(s);
                            },
                            "[CLI] HASH160 commitment must be exactly 40 hex characters.",
                            outputBuffer, currentRow, rows, coutMutex)));
                    }

                    const std::string claimRaw = getValidatedInput(
                        "Claim pubkey [66 hex or me]: ",
                        validHtlcPubkey,
                        "[CLI] Enter a 33-byte compressed claim key.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const std::string claimPubkey = normalizeHtlcPubkey(claimRaw);

                    const std::string refundRaw = getValidatedInput(
                        "Refund pubkey [66 hex or me]: ",
                        validHtlcPubkey,
                        "[CLI] Enter a 33-byte compressed refund key.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const std::string refundPubkey = normalizeHtlcPubkey(refundRaw);

                    if (claimPubkey == refundPubkey) {
                        throw std::runtime_error(
                            "HTLC claim and refund keys must be different");
                    }

                    std::uint32_t currentMtp = 0U;
                    try {
                        std::string tipHash;
                        int tipHeight = -1;
                        chain.getBestTipSnapshot(tipHash, tipHeight);
                        if (tipHeight >= 0 &&
                            tipHeight < std::numeric_limits<int>::max() &&
                            !tipHash.empty()) {
                            currentMtp = chain.getMedianTimePast(tipHash, tipHeight + 1);
                            if (currentMtp > 0) {
                                displayOutputProgressive(
                                    outputBuffer,
                                    "Current chain MTP: " + std::to_string(currentMtp) +
                                        " (" + formatTimestamp(currentMtp) + ")",
                                    currentRow, rows, coutMutex, 36, true);
                            }
                        }
                    } catch (const std::exception& e) {
                        displayOutputProgressive(
                            outputBuffer,
                            "[HTLC-01C] Unable to display current MTP: " +
                                std::string(e.what()),
                            currentRow, rows, coutMutex, 33, true);
                    }

                    const std::string refundTimeStr = getValidatedInput(
                        "Refund time [Unix timestamp]: ",
                        [&](const std::string& raw) {
                            try {
                                size_t used = 0;
                                const unsigned long long v = std::stoull(raw, &used, 10);
                                return used == raw.size() &&
                                       v >= 500000000ULL &&
                                       v <= std::numeric_limits<std::uint32_t>::max() &&
                                       (currentMtp == 0U || v > currentMtp);
                            } catch (...) {
                                return false;
                            }
                        },
                        "[CLI] Enter a timestamp >=500000000 and later than current chain MTP.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const std::uint32_t refundLockTime =
                        static_cast<std::uint32_t>(std::stoull(refundTimeStr));

                    displayOutputProgressive(
                        outputBuffer,
                        "Refund activates at: " + std::to_string(refundLockTime) +
                            " (" + formatTimestamp(refundLockTime) + ")",
                        currentRow, rows, coutMutex, 36, true);
                    displayOutputProgressive(
                        outputBuffer,
                        "Claim remains valid after timeout until either branch spends the UTXO.",
                        currentRow, rows, coutMutex, 36, true);

                    const std::string confirm = getValidatedInput(
                        "Create this HTLC / Atomic Swap? (yes/no): ",
                        [](const std::string& s) {
                            const std::string v = toLower(trim(s));
                            return v == "yes" || v == "no";
                        },
                        "[CLI] Please enter 'yes' or 'no'.",
                        outputBuffer, currentRow, rows, coutMutex);
                    if (toLower(trim(confirm)) != "yes") {
                        displayOutput(
                            "HTLC / Atomic Swap creation cancelled.",
                            rows, coutMutex);
                        continue;
                    }

                    const auto result = wallet.createHtlcAtomicSwapV1(
                        secretHash160Hex,
                        claimPubkey,
                        refundPubkey,
                        refundLockTime,
                        contractAmount);

                    std::ostringstream report;
                    report << "HTLC / ATOMIC SWAP V1 CREATED\n"
                           << "Family: htlc_atomic_swap_v1\n"
                           << "Amount: "
                           << formatTRUAmountExact(result.amountAtoms) << "\n"
                           << "Funding TXID: " << result.txid << "\n"
                           << "Funding Vout: " << result.contractVout << "\n"
                           << "Contract Outpoint: " << result.txid << ":"
                           << result.contractVout << "\n"
                           << "Fee: "
                           << formatTRUAmountExact(result.feeAtoms) << "\n"
                           << "Secret HASH160: " << result.secretHash160Hex << "\n"
                           << "Claim Pubkey: " << result.claimPubkeyHex << "\n"
                           << "Refund Pubkey: " << result.refundPubkeyHex << "\n"
                           << "Refund Time: " << result.refundLockTime
                           << " (" << formatTimestamp(result.refundLockTime) << ")\n";
                    if (!generatedPreimageHex.empty()) {
                        report << "SECRET PREIMAGE HEX: " << generatedPreimageHex << "\n"
                               << "KEEP THIS SECRET — it is not stored in the HTLC output.\n";
                    }
                    report << "Status: MEMPOOL ACCEPTED\n"
                           << "Next: mine one block before claim/refund.\n"
                           << "Then return to option 11 and choose claim or refund.";
                    displayOutput(report.str(), rows, coutMutex);
                    continue;
                }

                if (contractType == "MULTISIG ESCROW")
                {
                    std::string myCompressedPubkey;
                    try {
                        const auto myPub =
                            wallet.getPublicKeyForAddress(senderAddr);
                        if (myPub.size() == 33U &&
                            (myPub[0] == 0x02 || myPub[0] == 0x03)) {
                            myCompressedPubkey = bytesToHex(myPub);
                            displayOutputProgressive(
                                outputBuffer,
                                "Your compressed pubkey (use 'me'): " +
                                    myCompressedPubkey,
                                currentRow, rows, coutMutex, 36, true);
                        } else {
                            displayOutputProgressive(
                                outputBuffer,
                                "Current wallet key is not a canonical compressed key; enter participant keys explicitly.",
                                currentRow, rows, coutMutex, 33, true);
                        }
                    } catch (const std::exception& e) {
                        displayOutputProgressive(
                            outputBuffer,
                            "[MS-01C] Unable to derive current compressed pubkey: " +
                                std::string(e.what()),
                            currentRow, rows, coutMutex, 33, true);
                    }

                    auto normalizeParticipant = [&](const std::string& raw) {
                        std::string v = trim(raw);
                        std::string lower = toLower(v);
                        if (lower == "me") {
                            if (myCompressedPubkey.empty()) {
                                throw std::runtime_error(
                                    "'me' is unavailable because the current wallet "
                                    "does not expose a canonical compressed pubkey");
                            }
                            return myCompressedPubkey;
                        }
                        std::transform(
                            v.begin(), v.end(), v.begin(),
                            [](unsigned char c) {
                                return static_cast<char>(std::tolower(c));
                            });
                        return v;
                    };

                    auto validParticipantInput =
                        [&](const std::string& raw) {
                            try {
                                const std::string v =
                                    normalizeParticipant(raw);
                                return v.size() == 66U &&
                                       (v.rfind("02", 0) == 0 ||
                                        v.rfind("03", 0) == 0) &&
                                       std::all_of(
                                           v.begin(), v.end(),
                                           [](unsigned char c) {
                                               return std::isxdigit(c) != 0;
                                           });
                            } catch (...) {
                                return false;
                            }
                        };

                    auto getFundingTxid = [&]() {
                        return toLower(trim(getValidatedInput(
                            "Escrow funding TXID [64 hex]: ",
                            [](const std::string& s) {
                                return s.size() == 64U && isValidHex(s);
                            },
                            "[CLI] Funding TXID must be exactly 64 hex characters.",
                            outputBuffer, currentRow, rows, coutMutex)));
                    };
                    auto getReleaseRecipient = [&]() {
                        return trim(getValidatedInput(
                            "Release recipient TRU address: ",
                            [](const std::string& s) { return isValidAddress(trim(s)); },
                            "[CLI] Enter a valid TRU mainnet P2PKH address.",
                            outputBuffer, currentRow, rows, coutMutex));
                    };

                    if (multisigAction == "sign") {
                        const std::string fundingTxid = getFundingTxid();
                        const std::string recipient = getReleaseRecipient();
                        const std::string signerRaw = getValidatedInput(
                            "Signer compressed pubkey [66 hex or me]: ",
                            validParticipantInput,
                            "[CLI] Enter a 33-byte compressed participant pubkey.",
                            outputBuffer, currentRow, rows, coutMutex);
                        const std::string signerPubkey =
                            normalizeParticipant(signerRaw);

                        const auto package = wallet.signMultisigEscrowV1(
                            fundingTxid, 1U, recipient, signerPubkey);

                        std::ostringstream report;
                        report << "MULTISIG / ESCROW V1 SIGNATURE PACKAGE\n"
                               << "Contract Outpoint: " << package.contractTxid
                               << ":" << package.contractVout << "\n"
                               << "Recipient: " << package.recipient << "\n"
                               << "Release Amount: "
                               << formatTRUAmountExact(package.releaseAmountAtoms) << "\n"
                               << "Fee: " << formatTRUAmountExact(package.feeAtoms) << "\n"
                               << "Sighash: " << package.sighashHex << "\n"
                               << "Signer Pubkey: " << package.signerPubkeyHex << "\n"
                               << "Signature: " << package.signatureHex << "\n"
                               << "Status: SIGNED LOCALLY — NOT BROADCAST\n"
                               << "Share the signer pubkey + signature with the finalizer.";
                        displayOutput(report.str(), rows, coutMutex);
                        continue;
                    }

                    if (multisigAction == "redeem") {
                        const std::string fundingTxid = getFundingTxid();
                        const std::string recipient = getReleaseRecipient();
                        std::array<std::string, 2> signerPubkeys;
                        std::array<std::string, 2> signatures;

                        for (std::size_t i = 0; i < 2U; ++i) {
                            const std::string rawPub = getValidatedInput(
                                "Signer " + std::to_string(i + 1) +
                                    " compressed pubkey [66 hex or me]: ",
                                validParticipantInput,
                                "[CLI] Enter a canonical participant pubkey.",
                                outputBuffer, currentRow, rows, coutMutex);
                            signerPubkeys[i] = normalizeParticipant(rawPub);
                            signatures[i] = toLower(trim(getValidatedInput(
                                "Signer " + std::to_string(i + 1) +
                                    " signature [DER+01 hex]: ",
                                [](const std::string& s) {
                                    return s.size() >= 18U && s.size() <= 146U &&
                                           (s.size() % 2U) == 0U &&
                                           isValidHex(s) &&
                                           toLower(s.substr(s.size() - 2U)) == "01";
                                },
                                "[CLI] Enter strict-DER signature hex with trailing SIGHASH_ALL 01.",
                                outputBuffer, currentRow, rows, coutMutex)));
                        }

                        const auto result = wallet.redeemMultisigEscrowV1(
                            fundingTxid, 1U, recipient,
                            signerPubkeys, signatures);

                        std::ostringstream report;
                        report << "MULTISIG / ESCROW V1 REDEEMED\n"
                               << "Contract Outpoint: " << result.contractTxid
                               << ":" << result.contractVout << "\n"
                               << "Redemption TXID: " << result.txid << "\n"
                               << "Recipient: " << result.recipient << "\n"
                               << "Released: "
                               << formatTRUAmountExact(result.releaseAmountAtoms) << "\n"
                               << "Fee: " << formatTRUAmountExact(result.feeAtoms) << "\n"
                               << "Signer 1: " << result.signerPubkeysHex[0] << "\n"
                               << "Signer 2: " << result.signerPubkeysHex[1] << "\n"
                               << "Status: MEMPOOL ACCEPTED\n"
                               << "Next: mine one block to confirm redemption.";
                        displayOutput(report.str(), rows, coutMutex);
                        continue;
                    }

                    std::array<std::string, 3> participantKeys;
                    for (std::size_t i = 0; i < participantKeys.size(); ++i) {
                        const std::string raw = getValidatedInput(
                            "Participant " + std::to_string(i + 1) +
                                " compressed pubkey [66 hex" +
                                (myCompressedPubkey.empty()
                                     ? std::string("")
                                     : std::string(" or me")) +
                                "]: ",
                            validParticipantInput,
                            "[CLI] Enter a 33-byte compressed SEC1 pubkey "
                            "(66 hex, prefix 02/03).",
                            outputBuffer, currentRow, rows, coutMutex);
                        participantKeys[i] = normalizeParticipant(raw);
                    }

                    {
                        auto keysForCheck = participantKeys;
                        std::sort(keysForCheck.begin(), keysForCheck.end());
                        if (keysForCheck[0] == keysForCheck[1] ||
                            keysForCheck[1] == keysForCheck[2]) {
                            throw std::runtime_error(
                                "Multisig / Escrow V1 requires three unique participant keys");
                        }
                    }

                    displayOutputProgressive(
                        outputBuffer,
                        "Threshold: 2 of 3 (keys are canonically sorted on-chain)",
                        currentRow, rows, coutMutex, 32, true);

                    const std::string confirm = getValidatedInput(
                        "Create this 2-of-3 escrow? (yes/no): ",
                        [](const std::string& s) {
                            const std::string lower = toLower(trim(s));
                            return lower == "yes" || lower == "no";
                        },
                        "[CLI] Please enter 'yes' or 'no'.",
                        outputBuffer, currentRow, rows, coutMutex);

                    if (toLower(trim(confirm)) != "yes") {
                        displayOutput(
                            "Multisig / Escrow creation cancelled.",
                            rows, coutMutex);
                        continue;
                    }

                    const auto result =
                        wallet.createMultisigEscrowV1(
                            participantKeys, contractAmount);

                    std::ostringstream report;
                    report << "MULTISIG / ESCROW V1 CREATED\n"
                           << "Threshold: 2 of 3\n"
                           << "Amount: "
                           << formatTRUAmountExact(result.amountAtoms) << "\n"
                           << "Funding TXID: " << result.txid << "\n"
                           << "Funding Vout: " << result.contractVout << "\n"
                           << "Contract Outpoint: " << result.txid << ":"
                           << result.contractVout << "\n"
                           << "Fee: "
                           << formatTRUAmountExact(result.feeAtoms) << "\n"
                           << "Participant 1: " << result.pubkeysHex[0] << "\n"
                           << "Participant 2: " << result.pubkeysHex[1] << "\n"
                           << "Participant 3: " << result.pubkeysHex[2] << "\n"
                           << "Status: MEMPOOL ACCEPTED\n"
                           << "Next: mine one block before redemption.\n"
                           << "Redemption UI/signature assembly arrives in MS-01D.";
                    displayOutput(report.str(), rows, coutMutex);
                    continue;
                }

                if (contractType == "TIME LOCK")
                {
                    // show the consensus maturity clock before the
                    // user chooses a timestamp. CLTV uses parent-chain MTP, not
                    // wall clock and not the candidate header timestamp.
                    try {
                        std::string tipHash;
                        int tipHeight = -1;
                        chain.getBestTipSnapshot(tipHash, tipHeight);
                        if (tipHeight >= 0 && tipHeight < std::numeric_limits<int>::max() &&
                            !tipHash.empty()) {
                            const uint32_t mtp =
                                chain.getMedianTimePast(tipHash, tipHeight + 1);
                            if (mtp > 0) {
                                displayOutputProgressive(
                                    outputBuffer,
                                    "Current chain MTP: " + std::to_string(mtp) +
                                        " (" + formatTimestamp(mtp) + ")",
                                    currentRow, rows, coutMutex, 36, true);
                            } else {
                                displayOutputProgressive(
                                    outputBuffer,
                                    "Current chain MTP: unavailable until the 11-block MTP window is active",
                                    currentRow, rows, coutMutex, 33, true);
                            }
                        }
                    } catch (const std::exception& e) {
                        displayOutputProgressive(
                            outputBuffer,
                            "[CLI] Unable to display current MTP: " + std::string(e.what()),
                            currentRow, rows, coutMutex, 33, true);
                    }

                    std::string lockTimeStr = getValidatedInput(
                        "Enter lock time (Unix ts >=500000000): ",
                        [](const std::string &s)
                        {
                            try {
                                size_t used = 0;
                                const unsigned long long v = std::stoull(s, &used, 10);
                                return used == s.size() &&
                                       v >= 500000000ULL &&
                                       v <= std::numeric_limits<uint32_t>::max();
                            } catch (...) {
                                return false;
                            }
                        },
                        "[CLI] Time Lock V1 requires an exact Unix timestamp >=500000000 and <=uint32 max.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const uint32_t lockTime = static_cast<uint32_t>(std::stoull(lockTimeStr));
                    displayLockTime = lockTime;
                    std::string pubHash = getValidatedInput(
                        "Enter pubkeyhash (40 hex chars): ",
                        [](const std::string &s)
                        { return s.size() == 40 && std::all_of(s.begin(), s.end(), ::isxdigit); },
                        "[CLI] Must be 40 hex chars.",
                        outputBuffer, currentRow, rows, coutMutex);
                    lockReason = getValidatedInput(
                        "Enter lock reason (opt, <=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    // Convert lockTime to little-endian hex
                    unsigned char timeBytes[4];
                    timeBytes[0] = (lockTime >> 0) & 0xFF;
                    timeBytes[1] = (lockTime >> 8) & 0xFF;
                    timeBytes[2] = (lockTime >> 16) & 0xFF;
                    timeBytes[3] = (lockTime >> 24) & 0xFF;
                    std::stringstream ss;
                    ss << std::hex << std::setfill('0');
                    for (int i = 0; i < 4; i++)
                    {
                        ss << std::setw(2) << static_cast<int>(timeBytes[i]);
                    }
                    scriptText = ss.str() + " OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 " + pubHash + " OP_EQUALVERIFY OP_CHECKSIG";
                }
                else if (contractType == "OP_RETURN")
                {
                    std::string data = getValidatedInput(
                        "Enter data (<=75 bytes): ",
                        [](const std::string &s)
                        { return s.size() <= 75; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    scriptText = "OP_RETURN " + asciiToHex(data);
                }
                else if (contractType == "HASH LOCK")
                {
                    std::string pre = getValidatedInput(
                        "Enter preimage (<=100 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 100; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);

                    unsigned char sha256sum[SHA256_DIGEST_LENGTH];
                    SHA256(reinterpret_cast<const unsigned char *>(pre.c_str()), pre.size(), sha256sum);
                    std::vector<unsigned char> h160(20);
                    RIPEMD160(sha256sum, SHA256_DIGEST_LENGTH, h160.data());

                    // Ensure hex is lowercase for regex matching
                    preimageHashForDisplay = bytesToHex(h160);
                    std::transform(preimageHashForDisplay.begin(), preimageHashForDisplay.end(),
                                   preimageHashForDisplay.begin(), ::tolower);

                    // Create the script text
                    scriptText = "OP_HASH160 " + preimageHashForDisplay + " OP_EQUAL";

                    // Add debug logging to verify the compiled script
                    auto tempScriptBytes = compileTextScript(scriptText);
                    std::string tempScriptHex = bytesToHex(tempScriptBytes);
                    std::transform(tempScriptHex.begin(), tempScriptHex.end(),
                                   tempScriptHex.begin(), ::tolower);
                    Logger::log("[CLI] Hash Lock compiled script: " + tempScriptHex);
                }
                else if (contractType == "CUSTOM SCRIPT")
                {
                    scriptText = getValidatedInput(
                        "Enter custom script: ",
                        [](const std::string &s)
                        { return !s.empty(); },
                        "[CLI] Cannot be empty.",
                        outputBuffer, currentRow, rows, coutMutex);
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                }
                else if (contractType == "ORACLE LOCK")
                {
                    std::string oracleKey = getValidatedInput(
                        "Oracle feed [chain:block_height | chain:total_supply | chain:block_reward]: ",
                        [](const std::string &s)
                        {
                            return s == "chain:block_height" ||
                                   s == "chain:total_supply" ||
                                   s == "chain:block_reward";
                        },
                        "[CLI] Unsupported feed. Patch 18 Oracle Feed V1 accepts only deterministic chain:* keys.",
                        outputBuffer, currentRow, rows, coutMutex);
                    std::string thStr = getValidatedInput(
                        "Threshold (uint64): ",
                        [](const std::string &s)
                        {
                            if (s.empty() || !std::all_of(s.begin(), s.end(), [](unsigned char c){ return c >= '0' && c <= '9'; }))
                                return false;
                            try { size_t used = 0; (void)std::stoull(s, &used, 10); return used == s.size(); }
                            catch (...) { return false; }
                        },
                        "[CLI] Invalid uint64 decimal.",
                        outputBuffer, currentRow, rows, coutMutex);
                    uint64_t threshold = std::stoull(thStr);

                    // Oracle threshold numeric encoding.
                    // Consensus numeric values are encoded as canonical 8-byte little-endian uint64.
                    std::vector<unsigned char> thresholdBytes(8);
                    for (size_t i = 0; i < thresholdBytes.size(); ++i)
                    {
                        thresholdBytes[i] = static_cast<unsigned char>((threshold >> (8 * i)) & 0xff);
                    }
                    const std::string thresholdLE = bytesToHex(thresholdBytes);

                    std::string cmpChoice = getValidatedInput(
                        "Compare: 1) >=   2) <= : ",
                        [](const std::string &s)
                        { return s == "1" || s == "2"; },
                        "[CLI] Must enter 1 or 2.",
                        outputBuffer, currentRow, rows, coutMutex);
                    bool ge = (cmpChoice == "1");
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    scriptText = asciiToHex(oracleKey) + " OP_DATAFEED " + thresholdLE + (ge ? " OP_GREATERTHANOREQUAL" : " OP_LESSTHANOREQUAL") + " OP_VERIFY OP_DUP OP_HASH160 " + pubkeyhash + " OP_EQUALVERIFY OP_CHECKSIG";
                }

                else if (contractType == "TOKEN ISSUER")
                {
                    // Token Issuer V1 creation uses the same proven
                    // f751 stable-root anchor as K/V and Voting. All authoritative
                    // initialization is carried by one canonical TRUSTATE envelope.
                    std::string tokenName = getValidatedInput(
                        "Enter token name (1-10 chars; A-Z a-z 0-9 _ -): ",
                        [](const std::string& s)
                        {
                            if (s.empty() || s.size() > 10) return false;
                            return std::all_of(
                                s.begin(), s.end(), [](unsigned char c) {
                                    return (c >= 'A' && c <= 'Z') ||
                                           (c >= 'a' && c <= 'z') ||
                                           (c >= '0' && c <= '9') ||
                                           c == '_' || c == '-';
                                });
                        },
                        "[CLI] Invalid canonical Token Issuer V1 token name.",
                        outputBuffer, currentRow, rows, coutMutex);

                    std::string rateStr = getValidatedInput(
                        "Enter exchange rate (token units per TRU atom): ",
                        [](const std::string& s)
                        {
                            try {
                                return std::stoull(s) > 0;
                            } catch (...) {
                                return false;
                            }
                        },
                        "[CLI] Invalid exchange rate; must be uint64 > 0.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const std::uint64_t exchangeRate =
                        static_cast<std::uint64_t>(std::stoull(rateStr));

                    std::string maxSupplyStr = getValidatedInput(
                        "Enter max supply in token atomic units (0 = uncapped): ",
                        [](const std::string& s)
                        {
                            try {
                                (void)std::stoull(s);
                                return true;
                            } catch (...) {
                                return false;
                            }
                        },
                        "[CLI] Invalid max supply.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const std::uint64_t maxSupply =
                        static_cast<std::uint64_t>(std::stoull(maxSupplyStr));

                    contractName = tokenName + "_Issuer";

                    // Canonical Token Issuer V1 state anchor.
                    scriptText = "OP_STORE OP_1";
                    const auto scriptBytes = compileTextScript(scriptText);
                    const std::string scriptHex = bytesToHex(scriptBytes);
                    if (scriptHex != "f751") {
                        throw std::runtime_error(
                            "Token Issuer V1 canonical anchor must compile exactly to f751");
                    }

                    tru_contract_state_init::StateInitEnvelope initEnvelope;
                    initEnvelope.targetVout = 1;

                    auto u64Bytes = [](std::uint64_t value) {
                        std::vector<unsigned char> out(8, 0);
                        for (std::size_t i = 0; i < 8; ++i) {
                            out[i] = static_cast<unsigned char>(
                                (value >> (8U * i)) & 0xffU);
                        }
                        return out;
                    };

                    initEnvelope.entries.emplace_back(
                        "token_name",
                        std::vector<unsigned char>(
                            tokenName.begin(), tokenName.end()));
                    initEnvelope.entries.emplace_back(
                        "exchange_rate", u64Bytes(exchangeRate));
                    initEnvelope.entries.emplace_back(
                        "max_supply", u64Bytes(maxSupply));
                    initEnvelope.entries.emplace_back(
                        "total_issued", u64Bytes(0));

                    std::sort(
                        initEnvelope.entries.begin(),
                        initEnvelope.entries.end(),
                        [](const auto& a, const auto& b) {
                            return a.first < b.first;
                        });

                    std::string tokenInitReason;
                    if (!tru_contract_call::IsCanonicalTokenIssuerV1InitEnvelope(
                            initEnvelope, tokenInitReason)) {
                        throw std::runtime_error(
                            "Token Issuer V1 TRUSTATE validation failed: " +
                            tokenInitReason);
                    }

                    std::vector<unsigned char> initScript;
                    if (!tru_contract_state_init::BuildOpReturnScript(
                            initEnvelope, initScript)) {
                        throw std::runtime_error(
                            "Unable to build canonical Token Issuer V1 TRUSTATE");
                    }

                    const std::string senderAddr = wallet.getCurrentAddress();
                    auto [utxoTxid, utxoVout] =
                        wallet.findOneSpendableUtxo(
                            senderAddr, chain.mempool.get());
                    if (utxoTxid.empty()) {
                        throw std::runtime_error(
                            "No spendable creator UTXO found for " + senderAddr);
                    }

                    UTXO utxo;
                    if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo)) {
                        throw std::runtime_error(
                            "Failed to fetch Token Issuer V1 creator UTXO");
                    }

                    constexpr std::uint64_t fee = 10000;
                    if (utxo.amount < contractAmount ||
                        utxo.amount - contractAmount < fee) {
                        throw std::runtime_error(fmt::format(
                            "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms",
                            utxo.amount, contractAmount + fee));
                    }

                    Transaction tx;
                    tx.version = 1;
                    tx.lockTime = 0;
                    tx.vin.emplace_back(utxoTxid, utxoVout);

                    {
                        const std::string meta =
                            "TRU_CONTRACT:" + contractName;
                        const std::vector<unsigned char> metaBytes(
                            meta.begin(), meta.end());
                        if (metaBytes.size() > 80) {
                            throw std::runtime_error(
                                "Token Issuer V1 metadata too long");
                        }
                        const std::string opHex =
                            "6a" +
                            fmt::format("{:02x}", metaBytes.size()) +
                            bytesToHex(metaBytes);
                        tx.vout.emplace_back(0, opHex);
                    }

                    // vout1 is the permanent-root initial live anchor.
                    tx.vout.emplace_back(contractAmount, scriptHex);
                    // vout2 initializes token_name/rate/max/issued.
                    tx.vout.emplace_back(0, bytesToHex(initScript));

                    const std::uint64_t changeAmount =
                        utxo.amount - contractAmount - fee;
                    if (changeAmount > 0) {
                        tx.vout.emplace_back(
                            changeAmount,
                            createP2PKHScriptHexFromAddress(senderAddr));
                    }

                    if (!wallet.signTransaction(tx)) {
                        throw std::runtime_error(
                            "Failed to sign Token Issuer V1 creation");
                    }
                    tx.computeTxId();

                    const auto status =
                        chain.mempool->addTransaction(tx);
                    if (status != MempoolAddStatus::SUCCESS) {
                        throw std::runtime_error(
                            "Mempool rejected Token Issuer V1 creation");
                    }

                    const std::string rawHex =
                        hexEncode(tx.serializeBinary());
                    const bool ok =
                        wallet.broadcastTxToExternalNode(
                            rawHex, "127.0.0.1",
                            tru_network::MAINNET_RPC_PORT);
                    const std::string broadcastStatus =
                        ok ? "Broadcast succeeded." : "Broadcast failed.";

                    const std::string contractAddress =
                        tx.txid + ":1";

                    Logger::log(
                        "[TOKEN ISSUER V1] Creation accepted root=" +
                        contractAddress +
                        " rate=" + std::to_string(exchangeRate) +
                        " maxSupply=" + std::to_string(maxSupply) +
                        " entries=" +
                        std::to_string(initEnvelope.entries.size()) +
                        " — mine one block before purchasing/minting");

                    displaySuccessMessageContract(
                        contractType,
                        tx.txid,
                        contractAddress,
                        scriptHex,
                        broadcastStatus,
                        senderAddr,
                        contractName,
                        /*lockReason*/ "",
                        contractAmount,
                        fee,
                        /*displayLockTime*/ 0,
                        /*preimageHashForDisplay*/ "",
                        coutMutex);

                    continue;
                }

                else if (contractType == "VOTING")
                {
                    // 1) Gather inputs
                    std::string proposal = getValidatedInput(
                        "Enter proposal/question to vote on: ",
                        [](const std::string &s)
                        { return !s.empty() && s.size() <= 200; },
                        "[CLI] Proposal must be 1-200 chars.",
                        outputBuffer, currentRow, rows, coutMutex);

                    std::string optionsStr = getValidatedInput(
                        "Number of options (2-10): ",
                        [](const std::string &s)
                        {
                            try
                            {
                                int n = std::stoi(s);
                                return n >= 2 && n <= 10;
                            }
                            catch (...)
                            {
                                return false;
                            }
                        },
                        "[CLI] Must be 2-10 options.",
                        outputBuffer, currentRow, rows, coutMutex);
                    int numOptions = std::stoi(optionsStr);

                    std::vector<std::string> options;
                    options.reserve(numOptions);
                    for (int i = 0; i < numOptions; i++)
                    {
                        std::string opt = getValidatedInput(
                            "Enter option " + std::to_string(i) + ": ",
                            [](const std::string &s)
                            { return !s.empty() && s.size() <= 50; },
                            "[CLI] Option must be 1-50 chars.",
                            outputBuffer, currentRow, rows, coutMutex);
                        options.push_back(opt);
                    }

                    std::string endTimeStr = getValidatedInput(
                        "Voting end time (Unix timestamp, 1..4294967295): ",
                        [](const std::string &s)
                        {
                            try
                            {
                                const auto value = std::stoull(s);
                                return value > 0 &&
                                       value <=
                                           std::numeric_limits<std::uint32_t>::max();
                            }
                            catch (...)
                            {
                                return false;
                            }
                        },
                        "[CLI] Invalid Voting V1 timestamp.",
                        outputBuffer, currentRow, rows, coutMutex);
                    const uint32_t endTime =
                        static_cast<uint32_t>(std::stoull(endTimeStr));

                    contractName = "Vote: " + proposal.substr(0, 20);

                    // CONFIRMATION:
                    displayOutput("=== CONTRACT SUMMARY ===", rows, coutMutex);
                    displayOutput("Proposal: " + proposal, rows, coutMutex);
                    displayOutput("Options: " + std::to_string(numOptions), rows, coutMutex);
                    for (size_t i = 0; i < options.size(); i++)
                    {
                        displayOutput("  " + std::to_string(i) + ": " + options[i], rows, coutMutex);
                    }
                    displayOutput("Amount: " + formatTRUAmountDetailed(contractAmount), rows, coutMutex);
                    displayOutput("Fee: " + formatTRUAmountDetailed(10000), rows, coutMutex);

                    std::string confirm = getValidatedInput(
                        "Create this voting contract? (yes/no): ",
                        [](const std::string &s)
                        {
                            std::string lower = s;
                            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                            return lower == "yes" || lower == "no";
                        },
                        "[CLI] Please enter 'yes' or 'no'",
                        outputBuffer, currentRow, rows, coutMutex);

                    if (confirm != "yes")
                    {
                        displayOutput("Contract creation cancelled.", rows, coutMutex);
                        continue; // This will return to main menu
                    }

                    // Cooldown to prevent rapid re-creation:
                    static std::chrono::steady_clock::time_point lastVotingContract;
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastVotingContract).count() < 10)
                    {
                        displayOutput("Please wait 10 seconds between contract creations.", rows, coutMutex);
                        continue;
                    }
                    lastVotingContract = now;

                    // Voting V1 uses the proven canonical f751
                    // state-anchor. Initialization lives ONLY in TRUSTATE and
                    // becomes authoritative after the creation transaction mines.
                    scriptText = "OP_STORE OP_1";

                    Logger::log("[VOTING V1] Contract configured with proposal: " + proposal);
                    Logger::log("[VOTING V1] Number of options: " + std::to_string(numOptions));
                    for (size_t i = 0; i < options.size(); i++)
                        Logger::log("[VOTING V1] Option " + std::to_string(i) + ": " + options[i]);
                    Logger::log("[VOTING V1] Voting ends at: " + std::to_string(endTime));

                    displayOutputProgressive(outputBuffer,
                                             "Voting V1 contract configured successfully!",
                                             currentRow, rows, coutMutex, 92, true);

                    // 3) Compile exact f751 call-only anchor.
                    auto scriptBytes = compileTextScript(scriptText);
                    std::string scriptHex = bytesToHex(scriptBytes);
                    if (scriptHex != "f751")
                        throw std::runtime_error("Voting V1 canonical anchor must compile exactly to f751");
                    Logger::log("[CLI] Voting V1 compiled scriptHex=" + scriptHex);

                    // Build the canonical sorted multi-entry TRUSTATE envelope.
                    tru_contract_state_init::StateInitEnvelope initEnvelope;
                    initEnvelope.targetVout = 1;

                    auto addInit = [&](const std::string& key,
                                       const std::vector<unsigned char>& value) {
                        initEnvelope.entries.emplace_back(key, value);
                    };
                    addInit("proposal",
                            std::vector<unsigned char>(proposal.begin(), proposal.end()));
                    addInit("numoptions",
                            std::vector<unsigned char>{
                                static_cast<unsigned char>(numOptions)});

                    std::vector<unsigned char> endTimeBytes(8, 0);
                    const std::uint64_t endTime64 = static_cast<std::uint64_t>(endTime);
                    for (std::size_t i = 0; i < 8; ++i)
                        endTimeBytes[i] =
                            static_cast<unsigned char>((endTime64 >> (8U * i)) & 0xffU);
                    addInit("endtime", endTimeBytes);

                    const std::vector<unsigned char> zero8(8, 0);
                    for (std::size_t i = 0; i < options.size(); ++i) {
                        addInit(
                            "option" + std::to_string(i),
                            std::vector<unsigned char>(
                                options[i].begin(), options[i].end()));
                        addInit("count" + std::to_string(i), zero8);
                    }
                    addInit("totalvotes", zero8);

                    std::sort(
                        initEnvelope.entries.begin(),
                        initEnvelope.entries.end(),
                        [](const auto& a, const auto& b) {
                            return a.first < b.first;
                        });

                    std::string votingInitReason;
                    if (!tru_contract_call::IsCanonicalVotingV1InitEnvelope(
                            initEnvelope, votingInitReason)) {
                        throw std::runtime_error(
                            "Voting V1 TRUSTATE validation failed: " +
                            votingInitReason);
                    }

                    std::vector<unsigned char> initScript;
                    if (!tru_contract_state_init::BuildOpReturnScript(
                            initEnvelope, initScript)) {
                        throw std::runtime_error(
                            "Unable to build canonical Voting V1 TRUSTATE");
                    }

                    // 4) Select the single creator/owner P2PKH funding UTXO.
                    const std::string senderAddr = wallet.getCurrentAddress();
                    auto [utxoTxid, utxoVout] =
                        wallet.findOneSpendableUtxo(
                            senderAddr, chain.mempool.get());
                    if (utxoTxid.empty())
                        throw std::runtime_error(
                            "No spendable UTXO found for " + senderAddr);

                    UTXO utxo;
                    if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo))
                        throw std::runtime_error(
                            "Failed to fetch UTXO " + utxoTxid + ":" +
                            std::to_string(utxoVout));
                    const uint64_t coinValue = utxo.amount;

                    // 5) Fees & amounts.
                    constexpr uint64_t fee = 10000;
                    if (coinValue < contractAmount + fee) {
                        throw std::runtime_error(fmt::format(
                            "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms (contract: {} TRU atoms, fee: {} TRU atoms)",
                            coinValue, contractAmount + fee,
                            contractAmount, fee));
                    }

                    // 6) Build creation transaction:
                    //   vout0 metadata
                    //   vout1 f751 Voting V1 state anchor
                    //   vout2 TRUSTATE -> targetVout 1
                    //   vout3 optional creator change
                    Transaction tx;
                    tx.version = 1;
                    tx.lockTime = 0;
                    tx.vin.emplace_back(utxoTxid, utxoVout);

                    {
                        std::string meta = "TRU_CONTRACT:" + contractName;
                        std::vector<unsigned char> metaBytes(
                            meta.begin(), meta.end());
                        if (metaBytes.size() > 80)
                            throw std::runtime_error("Metadata too long");
                        std::string opHex =
                            "6a" +
                            fmt::format("{:02x}", metaBytes.size()) +
                            bytesToHex(metaBytes);
                        tx.vout.emplace_back(0, opHex);
                    }

                    tx.vout.emplace_back(contractAmount, scriptHex);
                    tx.vout.emplace_back(0, bytesToHex(initScript));

                    const uint64_t changeAmount =
                        coinValue - contractAmount - fee;
                    if (changeAmount > 0) {
                        tx.vout.emplace_back(
                            changeAmount,
                            createP2PKHScriptHexFromAddress(senderAddr));
                    }

                    // 7) Sign creator funding input.
                    if (!wallet.signTransaction(tx))
                        throw std::runtime_error(
                            "Failed to sign Voting V1 creation transaction");
                    tx.computeTxId();

                    // 8) Relay/broadcast. No legacy ContractStorage writes:
                    // confirmed LevelDB root state is the only V1 truth.
                    const auto status = chain.mempool->addTransaction(tx);
                    if (status != MempoolAddStatus::SUCCESS)
                        throw std::runtime_error(
                            "Mempool rejected Voting V1 creation");

                    const std::string rawHex =
                        hexEncode(tx.serializeBinary());
                    const bool ok = wallet.broadcastTxToExternalNode(
                        rawHex, "127.0.0.1",
                        tru_network::MAINNET_RPC_PORT);
                    const std::string broadcastStatus =
                        ok ? "Broadcast succeeded." : "Broadcast failed.";

                    // 9) Stable root is creation vout 1.
                    const std::string contractAddress =
                        tx.txid + ":1";

                    Logger::log(
                        "[VOTING V1] Creation accepted root=" +
                        contractAddress +
                        " entries=" +
                        std::to_string(initEnvelope.entries.size()) +
                        " — mine one block before voting");

                    // 11) Done UI
                    displaySuccessMessageContract(
                        contractType,
                        tx.txid,
                        contractAddress,
                        scriptHex,
                        broadcastStatus,
                        senderAddr,
                        contractName,
                        /*lockReason*/ "",
                        contractAmount,
                        fee,
                        /*displayLockTime*/ 0,
                        /*preimageHashForDisplay*/ "",
                        coutMutex);

                    continue;
                }

                else if (contractTypeChoice == "9" || toLower(contractTypeChoice).find("bridge") != std::string::npos)
                {
                    std::string asset = getValidatedInput(
                        "Bridge asset (NOVO or BSTY): ",
                        [](const std::string &s)
                        {
                            auto t = toLower(trim(s));
                            return (t == "novo" || t == "bsty");
                        },
                        "[CLI] Must be NOVO or BSTY.",
                        outputBuffer, currentRow, rows, coutMutex);

                    // Exchange rate: how many TRU atoms are credited per 1 foreign atomic unit
                    // Use token-issuer conventions for foreign-chain to TRU transfers.
                    std::string rateStr = getValidatedInput(
                        "Enter exchange rate (TRU atoms credited per 1 foreign atomic unit): ",
                        [](const std::string &s)
                        { try { return std::stoull(s) > 0; } catch (...) { return false; } },
                        "[CLI] Invalid rate (>0).",
                        outputBuffer, currentRow, rows, coutMutex);
                    uint64_t rate = std::stoull(rateStr);

                    std::string minConfStr = getValidatedInput(
                        "Minimum confirmations required on foreign chain (e.g. 6): ",
                        [](const std::string &s)
                        { try { return std::stoul(s) >= 0; } catch (...) { return false; } },
                        "[CLI] Invalid number.",
                        outputBuffer, currentRow, rows, coutMutex);
                    uint32_t minConf = (uint32_t)std::stoul(minConfStr);

                    contractName = "BRIDGE_" + toUpper(asset);

                    // Helper: encode uint64 -> 8-byte LE
                    auto u64le = [](uint64_t v)
                    {
                        std::string out(8, '\0');
                        for (int i = 0; i < 8; ++i)
                            out[i] = (char)((v >> (i * 8)) & 0xFF);
                        return out;
                    };
                    // Helper: encode uint32 -> 4-byte LE
                    auto u32le = [](uint32_t v)
                    {
                        std::string out(4, '\0');
                        for (int i = 0; i < 4; ++i)
                            out[i] = (char)((v >> (i * 8)) & 0xFF);
                        return out;
                    };

                    // ===== Bridge Script =====
                    //
                    // We store:
                    //   - "asset"      -> "NOVO" or "BSTY"
                    //   - "rate_le"    -> 8B LE uint64 (TRU atoms credited per foreign atomic unit)
                    //   - "min_conf"   -> 4B LE uint32
                    //
                    // And include a small dispatcher to generate a deposit address on first call:
                    //   asset OP_LOAD "NOVO" OP_EQUAL OP_IF OP_NOVO_GENADDR OP_ELSE OP_BSTY_GENADDR OP_ENDIF
                    //
                    // Confirm, redeem, and verify opcodes handle state on subsequent calls.
                    //
                    std::string scriptText;
                    // metadata
                    scriptText += asciiToHex("asset") + " " + asciiToHex(toUpper(asset)) + " OP_STORE ";
                    scriptText += asciiToHex("rate_le") + " " + bytesToHex(std::vector<unsigned char>(u64le(rate).begin(), u64le(rate).end())) + " OP_STORE ";
                    scriptText += asciiToHex("min_conf") + " " + bytesToHex(std::vector<unsigned char>(u32le(minConf).begin(), u32le(minConf).end())) + " OP_STORE ";

                    // Idempotent address-generation gate.
                    // if asset == "NOVO" then OP_NOVO_GENADDR else OP_BSTY_GENADDR
                    scriptText += asciiToHex("asset") + " OP_LOAD ";
                    scriptText += asciiToHex("NOVO") + " OP_EQUAL OP_IF ";
                    scriptText += "OP_NOVO_GENADDR ";
                    scriptText += "OP_ELSE OP_BSTY_GENADDR OP_ENDIF ";

                    // Success
                    scriptText += "OP_1";

                    // ===== Compile script =====
                    auto scriptBytes = compileTextScript(scriptText);
                    std::string scriptHex = bytesToHex(scriptBytes);
                    Logger::log("[BRIDGE] Compiled scriptHex=" + scriptHex);

                    // ===== UTXO selection (reuse previously shown senderAddr) =====
                    const std::string senderAddr = wallet.getCurrentAddress();
                    auto [utxoTxid, utxoVout] = wallet.findOneSpendableUtxo(senderAddr, chain.mempool.get());
                    if (utxoTxid.empty())
                        throw std::runtime_error("No spendable UTXO found for " + senderAddr);

                    UTXO utxo;
                    if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo))
                        throw std::runtime_error("Failed to fetch UTXO " + utxoTxid + ":" + std::to_string(utxoVout));
                    uint64_t coinValue = utxo.amount;

                    // Use contractAmount from the earlier menu prompt.
                    uint64_t fee = 10000;
                    if (coinValue < contractAmount + fee)
                        throw std::runtime_error(fmt::format(
                            "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms (contract: {} TRU atoms, fee: {} TRU atoms)",
                            coinValue, contractAmount + fee, contractAmount, fee));

                    // ===== Build TX =====
                    Transaction tx;
                    tx.version = 1;
                    tx.lockTime = 0;
                    tx.vin.emplace_back(utxoTxid, utxoVout);

                    // OP_RETURN label
                    {
                        std::string meta = "TRU_CONTRACT:" + contractName;
                        std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
                        if (metaBytes.size() > 80)
                            throw std::runtime_error("Metadata too long");
                        std::string opHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + bytesToHex(metaBytes);
                        tx.vout.emplace_back(0, opHex);
                    }

                    // Contract output
                    tx.vout.emplace_back(contractAmount, scriptHex);

                    // Change
                    uint64_t changeAmount = coinValue - contractAmount - fee;
                    if (changeAmount > 0)
                    {
                        std::string changeScript = createP2PKHScriptHexFromAddress(senderAddr);
                        tx.vout.emplace_back(changeAmount, changeScript);
                    }

                    // Sign + mempool + broadcast
                    if (!wallet.signTransaction(tx))
                        throw std::runtime_error("Failed to sign transaction");
                    tx.computeTxId();
                    auto status = chain.mempool->addTransaction(tx);
                    if (status != MempoolAddStatus::SUCCESS)
                        throw std::runtime_error("Mempool rejected transaction");

                    std::string rawHex = hexEncode(tx.serializeBinary());
                    bool ok = wallet.broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);
                    std::string broadcastStatus = ok ? "Broadcast succeeded." : "Broadcast failed.";

                    // Compute contract address (vout #1)
                    std::string contractAddress = tx.txid + ":1";

                    // ===== Persist initial bridge state for explorer/CLI (mirrors OP_STORE data) =====
                    try
                    {
                        ContractStorage cstore(chain.getStorage());
                        cstore.storeContractData(contractAddress, "asset", toUpper(asset));
                        cstore.storeContractData(contractAddress, "rate_le", u64le(rate));
                        cstore.storeContractData(contractAddress, "min_conf", u32le(minConf));

                        // Initialize helpful counters/fields
                        cstore.storeContractData(contractAddress, "total_foreign_received", std::string(8, '\0')); // u64 0
                        cstore.storeContractData(contractAddress, "total_tru_credited", std::string(8, '\0'));     // u64 0
                        // deposit_addr/deposit_priv will be set later by the first OP_*_GENADDR call
                    }
                    catch (const std::exception &ex)
                    {
                        Logger::log(std::string("[BRIDGE] WARNING: Failed to persist initial state: ") + ex.what());
                    }

                    // ===== UI =====
                    displaySuccessMessageContract(
                        "BRIDGE",
                        tx.txid,
                        contractAddress,
                        scriptHex,
                        broadcastStatus,
                        senderAddr,
                        contractName,
                        /*lockReason*/ "",
                        contractAmount,
                        fee,
                        /*displayLockTime*/ 0,
                        /*preimageHashForDisplay*/ "",
                        coutMutex);

                    continue;
                }
                else
                { // STATEFUL CONTRACT
                    std::string kvKey = getValidatedInput(
                        "State key: ",
                        [](const std::string &s)
                        { return !s.empty(); },
                        "[CLI] Cannot be empty.",
                        outputBuffer, currentRow, rows, coutMutex);
                    std::string kvVal = getValidatedInput(
                        "Initial value: ",
                        [](const std::string &s)
                        { return !s.empty(); },
                        "[CLI] Cannot be empty.",
                        outputBuffer, currentRow, rows, coutMutex);
                    contractName = getValidatedInput(
                        "Enter contract name (<=50 chars): ",
                        [](const std::string &s)
                        { return s.size() <= 50; },
                        "[CLI] Too long.",
                        outputBuffer, currentRow, rows, coutMutex);
                    // creation state is NOT executable locking code.
                    // The anchor is call-only; the initial key/value is carried in
                    // the TRUSTATE envelope added to this creation transaction.
                    statefulInitKey = kvKey;
                    statefulInitValue.assign(kvVal.begin(), kvVal.end());
                    scriptText = "OP_STORE OP_1";
                }

                // 5) compile script
                auto scriptBytes = compileTextScript(scriptText);
                std::string scriptHex = bytesToHex(scriptBytes);
                Logger::log("[CLI] Compiled scriptHex=" + scriptHex);

                // 6) pick UTXO
                auto [utxoTxid, utxoVout] = wallet.findOneSpendableUtxo(senderAddr, chain.mempool.get());
                if (utxoTxid.empty())
                    throw std::runtime_error("No spendable UTXO found for " + senderAddr);
                UTXO utxo;
                if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo))
                    throw std::runtime_error("Failed to fetch UTXO " + utxoTxid + ":" + std::to_string(utxoVout));
                uint64_t coinValue = utxo.amount;

                // Validate sufficient funds
                uint64_t fee = 10000;
                uint64_t totalNeeded = contractAmount + fee;
                if (coinValue < totalNeeded)
                {
                    throw std::runtime_error(fmt::format(
                        "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms (contract: {} TRU atoms, fee: {} TRU atoms)",
                        coinValue, totalNeeded, contractAmount, fee));
                }

                // 7) build tx
                Transaction tx;
                tx.version = 1;
                tx.lockTime = 0;
                tx.vin.emplace_back(utxoTxid, utxoVout);

                // OP_RETURN metadata
                std::string meta = "TRU_CONTRACT:" + contractName + (lockReason.empty() ? "" : ":REASON:" + lockReason);
                std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
                if (metaBytes.size() > 80)
                    throw std::runtime_error("Metadata too long");
                std::string opHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + bytesToHex(metaBytes);
                tx.vout.emplace_back(0, opHex);

                // contract output - USE THE CONTRACT AMOUNT!
                tx.vout.emplace_back(contractAmount, scriptHex);

                // canonical one-time Stateful K/V initialization.
                // Keep the state anchor at vout 1 for stable contract-address
                // semantics; append the zero-value TRUSTATE envelope afterward.
                if (contractType == "STATEFUL CONTRACT")
                {
                    if (statefulInitKey.empty())
                        throw std::runtime_error("Stateful K/V init key missing");

                    tru_contract_state_init::StateInitEnvelope initEnvelope;
                    initEnvelope.targetVout = 1;
                    initEnvelope.entries.emplace_back(
                        statefulInitKey, statefulInitValue);

                    std::vector<unsigned char> initScript;
                    if (!tru_contract_state_init::BuildOpReturnScript(
                            initEnvelope, initScript)) {
                        throw std::runtime_error(
                            "Failed to build canonical TRUSTATE initialization envelope");
                    }
                    tx.vout.emplace_back(0, bytesToHex(initScript));
                }

                // change
                uint64_t changeAmount = coinValue - contractAmount - fee;
                if (changeAmount > 0)
                {
                    std::string changeScript = createP2PKHScriptHexFromAddress(senderAddr);
                    tx.vout.emplace_back(changeAmount, changeScript);
                }

                // 8) sign
                if (!wallet.signTransaction(tx))
                    throw std::runtime_error("Failed to sign transaction");

                // 9) mempool + broadcast
                auto status = chain.mempool->addTransaction(tx);
                if (status != MempoolAddStatus::SUCCESS)
                    throw std::runtime_error("Mempool rejected transaction");
                std::string rawHex = hexEncode(tx.serializeBinary());
                bool ok = wallet.broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);
                std::string broadcastStatus = ok
                                                  ? "Broadcast succeeded."
                                                  : "Broadcast failed.";

                // 10) compute contract identity. Hash Lock redemption is
                // outpoint-based, so never surface its P2SH-looking script as
                // a Base58 address.
                std::string contractAddress;
                if (contractType == "HASH LOCK" || contractType == "TIME LOCK") {
                    contractAddress = tx.txid + ":1";
                } else {
                    contractAddress =
                        extractAddressFromScriptPubKey(
                            scriptHex, tx.txid, 1, &chain);
                    if (contractAddress.empty())
                        contractAddress = tx.txid + ":1";
                }

                // 12) success display
                displaySuccessMessageContract(
			contractType,
			tx.txid,
			contractAddress,
			scriptHex,
			broadcastStatus,
			senderAddr,
			contractName,
			lockReason,
			contractAmount,
			fee,
			displayLockTime,
			preimageHashForDisplay,
			coutMutex
                );
            }
            catch (const std::exception &e)
            {
                displayOutputProgressive(outputBuffer,
                                         std::string("[CLI] ") + e.what(),
                                         currentRow, rows, coutMutex, 31, true);
                Logger::log(std::string("[CLI] Contract #18 failed: ") + e.what());
            }

        }
        else if (choice == "18a") {
            try {
                std::string pubkeyhash = getCurrentPubkeyhash(wallet);
                displayOutput("[CLI] Current Pubkeyhash: " + pubkeyhash, rows, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to get pubkeyhash: " + std::string(e.what()), rows, coutMutex);
            }
        }

        else if (choice == "18b")
        {
            // --------------------------------------------
            // Bridge: NOVO/BSTY  (9a/9b/9c)
            // --------------------------------------------
            beginProgressiveResult(rows, coutMutex);
            std::string outputBuffer;
            int currentRow = truResultFirstRow();

            try
            {
                const std::string senderAddr = wallet.getCurrentAddress();
                const std::string pubkeyhash = getCurrentPubkeyhash(wallet);

                displayOutputProgressive(outputBuffer,
                                         "Your Address: " + senderAddr, currentRow, rows, coutMutex, 32, true);
                displayOutputProgressive(outputBuffer,
                                         "Current Pubkeyhash: " + pubkeyhash, currentRow, rows, coutMutex, 32, true);

                // Submenu
                displayOutputProgressive(outputBuffer,
                                         "Bridge actions:\n"
                                         "  a) Generate deposit address (commitment -> address)\n"
                                         "  b) Confirm deposit (amount+proof)\n"
                                         "  c) Redeem (release secret)",
                                         currentRow, rows, coutMutex, 33, true);

                displayPrompt(
                    "Bridge action [a/b/c/back]: ",
                    rows, coutMutex);
                std::string sub;
                signalAwareGetline(sub);
                sub = trim(sub);
                if (sub.empty() || toLower(sub) == "back")
                    throw std::runtime_error("User cancelled");

                // Asset select (NOVO/BSTY)
                displayOutputProgressive(outputBuffer,
                                         "Choose asset:\n"
                                         "  1) NOVO (legacy P2PKH, base58)\n"
                                         "  2) BSTY (bech32 gb1..., P2WPKH)",
                                         currentRow, rows, coutMutex, 33, true);

                displayPrompt(
                    "Bridge asset [1=NOVO, 2=BSTY]: ",
                    rows, coutMutex);
                std::string assetChoice;
                signalAwareGetline(assetChoice);
                assetChoice = trim(assetChoice);
                if (assetChoice != "1" && assetChoice != "2")
                    throw std::runtime_error("Invalid asset choice");

                const bool isNOVO = (assetChoice == "1");
                const std::string assetName = isNOVO ? "NOVO" : "BSTY";

                // Build script text for 9a/9b/9c
                std::string scriptText;
                std::string labelName;          // For OP_RETURN label
                uint64_t contractAmount = 1000; // dust to ensure vout is standard and evaluated
                const uint64_t fee = 10000;

                auto u64le_bytes = [](uint64_t v)
                {
                    std::vector<unsigned char> b(8, 0);
                    for (int i = 0; i < 8; ++i)
                        b[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
                    return b;
                };

                // Collect inputs per sub-action
                if (toLower(sub) == "a")
                {
                    // 9a: Generate deposit address
                    labelName = "BRIDGE_" + assetName + "_ADDR";

                    // 32-byte commitment (hex or free text -> hashed)
                    std::string commitInput = getValidatedInput(
                        "Enter commitment (hex(64) or any string; we'll hash if not hex-64): ",
                        [](const std::string &s)
                        { return !s.empty(); },
                        "[CLI] commitment cannot be empty.",
                        outputBuffer, currentRow, rows, coutMutex);

                    std::vector<unsigned char> commitment;
                    bool hex64 = (commitInput.size() == 64) &&
                                 std::all_of(commitInput.begin(), commitInput.end(), ::isxdigit);

                    if (hex64)
                    {
                        commitment = hexDecode(commitInput);
                    }
                    else
                    {
                        // hash arbitrary text to 32 bytes
                        std::vector<unsigned char> msg(commitInput.begin(), commitInput.end());
                        std::vector<unsigned char> sha(SHA256_DIGEST_LENGTH);
                        SHA256(msg.data(), msg.size(), sha.data());
                        commitment = sha;
                    }
                    if (commitment.size() != 32)
                        throw std::runtime_error("Commitment must be 32 bytes after processing");

                    // Script: <32-bytes> OP_*_ADDR
                    std::string pushCommit = bytesToHex(commitment);
                    scriptText = pushCommit + " ";
                    scriptText += (isNOVO ? "OP_NOVO_ADDR" : "OP_BSTY_ADDR");
                }
                else if (toLower(sub) == "b")
                {
                    // 9b: Confirm deposit
                    labelName = "BRIDGE_" + assetName + "_CONFIRM";

                    std::string amtStr = getValidatedInput(
                        "Enter deposit amount on source chain (integer foreign atomic units): ",
                        [](const std::string &s)
                        { try{ std::stoull(s); return true; }catch(...){return false;} },
                        "[CLI] invalid amount",
                        outputBuffer, currentRow, rows, coutMutex);
                    uint64_t amountSrc = std::stoull(amtStr);
                    auto amountLE = u64le_bytes(amountSrc);

                    std::string proofHex = getValidatedInput(
                        "Enter proof bytes (hex) (txid/merkle/path/etc as you define): ",
                        [](const std::string &s)
                        { return !s.empty() && std::all_of(s.begin(), s.end(), ::isxdigit); },
                        "[CLI] proof must be non-empty hex",
                        outputBuffer, currentRow, rows, coutMutex);
                    auto proof = hexDecode(proofHex);

                    // Script: <amountLE(8)> <proof> OP_*_CONFIRM
                    scriptText = bytesToHex(amountLE) + " ";
                    scriptText += bytesToHex(proof) + " ";
                    scriptText += (isNOVO ? "OP_NOVO_CONFIRM" : "OP_BSTY_CONFIRM");
                }
                else if (toLower(sub) == "c")
                {
                    // 9c: Redeem
                    labelName = "BRIDGE_" + assetName + "_REDEEM";

                    std::string secretHex = getValidatedInput(
                        "Enter secret (hex): ",
                        [](const std::string &s)
                        { return !s.empty() && std::all_of(s.begin(), s.end(), ::isxdigit); },
                        "[CLI] secret must be hex",
                        outputBuffer, currentRow, rows, coutMutex);
                    auto secret = hexDecode(secretHex);

                    // Script: <secret> OP_*_REDEEM
                    scriptText = bytesToHex(secret) + " ";
                    scriptText += (isNOVO ? "OP_NOVO_REDEEM" : "OP_BSTY_REDEEM");
                }
                else
                {
                    throw std::runtime_error("Unknown bridge sub-action");
                }

                // Compile → hex
                auto scriptBytes = compileTextScript(scriptText);
                std::string scriptHex = bytesToHex(scriptBytes);
                Logger::log("[BRIDGE] Compiled scriptHex=" + scriptHex);

                // Pick UTXO and build/broadcast
                auto [utxoTxid, utxoVout] = wallet.findOneSpendableUtxo(senderAddr, chain.mempool.get());
                if (utxoTxid.empty())
                    throw std::runtime_error("No spendable UTXO found for " + senderAddr);

                UTXO utxo;
                if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo))
                    throw std::runtime_error("Failed to fetch UTXO " + utxoTxid + ":" + std::to_string(utxoVout));
                uint64_t coinValue = utxo.amount;

                if (coinValue < contractAmount + fee)
                    throw std::runtime_error(fmt::format("Insufficient funds. Need {} (script {}) + fee {}", contractAmount + fee, contractAmount, fee));

                Transaction tx;
                tx.version = 1;
                tx.lockTime = 0;
                tx.vin.emplace_back(utxoTxid, utxoVout);

                // OP_RETURN label (<=80 bytes)
                {
                    std::string meta = "TRU_CONTRACT:" + labelName;
                    std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
                    if (metaBytes.size() > 80)
                        throw std::runtime_error("Metadata too long");
                    std::string opHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + bytesToHex(metaBytes);
                    tx.vout.emplace_back(0, opHex);
                }

                // Contract call output (#1)
                tx.vout.emplace_back(contractAmount, scriptHex);

                // Change
                uint64_t changeAmount = coinValue - contractAmount - fee;
                if (changeAmount > 0)
                {
                    std::string changeScript = createP2PKHScriptHexFromAddress(senderAddr);
                    tx.vout.emplace_back(changeAmount, changeScript);
                }

                // Sign + mempool + broadcast
                if (!wallet.signTransaction(tx))
                    throw std::runtime_error("Failed to sign transaction");
                tx.computeTxId();

                auto status = chain.mempool->addTransaction(tx);
                if (status != MempoolAddStatus::SUCCESS)
                    throw std::runtime_error("Mempool rejected transaction");

                std::string rawHex = hexEncode(tx.serializeBinary());
                bool ok = wallet.broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);
                std::string broadcastStatus = ok ? "Broadcast succeeded." : "Broadcast failed.";

                // Contract address (vout#1)
                std::string contractAddress = tx.txid + ":1";

                // Pretty success
                displaySuccessMessageContract(
                    "BRIDGE " + assetName,
                    tx.txid,
                    contractAddress,
                    scriptHex,
                    broadcastStatus,
                    senderAddr,
                    labelName,
                    /*lockReason*/ "",
                    contractAmount,
                    fee,
                    /*displayLockTime*/ 0,
                    /*preimageHashForDisplay*/ "",
                    coutMutex);

                // Small hint for 9a
                if (toLower(sub) == "a")
                {
                    displayOutputProgressive(outputBuffer,
                                             "Tip: After this tx confirms, call 9b (Confirm) with the source-chain proof and amount.",
                                             currentRow, rows, coutMutex, 92, true);
                }
            }
            catch (const std::exception &e)
            {
                displayOutputProgressive(outputBuffer,
                                         std::string("[CLI] ") + e.what(),
                                         currentRow, rows, coutMutex, 31, true);
                Logger::log(std::string("[CLI] Bridge #9 failed: ") + e.what());
            }

        }
        else if (choice == "19") {
            listMempoolTransactions(chain, rows, coutMutex);
        }
        else if (choice == "20") {
            SmartContract::queryContractState(chain, rows, coutMutex);
        }

        else if (choice == "20a")
        {
            try
            {
                displayPagedContractVault(chain, rows, coutMutex);
            }
            catch (const std::exception &e)
            {
                displayOutput("Error getting contracts: " + std::string(e.what()), rows, coutMutex);
            }

            continue;
        }


        else if (choice == "20b")
        {
            try
            {
                displayOutput("=== AVAILABLE CONTRACTS ===", rows, coutMutex);

                auto result = chain.getContracts();

                // Extract the contracts array from the wrapper object
                nlohmann::json contracts;
                if (result.is_object() && result.contains("contracts"))
                {
                    contracts = result["contracts"];
                }
                else if (result.is_array())
                {
                    // Fallback in case it's already an array
                    contracts = result;
                }
                else
                {
                    displayOutput("ERROR: Unexpected format from getContracts()", rows, coutMutex);
                    continue;
                }

                // Now check if the actual contracts array is empty
                if (!contracts.is_array() || contracts.empty())
                {
                    displayOutput("No contracts deployed yet", rows, coutMutex);
                }
                else
                {
                    displayOutput("Found " + std::to_string(contracts.size()) + " contract(s):", rows, coutMutex);
                    displayOutput("", rows, coutMutex);

                    int contractNum = 1;
                    for (const auto &contract : contracts)
                    {
                        displayOutput("---", rows, coutMutex);
                        displayOutput("Contract #" + std::to_string(contractNum++), rows, coutMutex);

                        // Initialize variables for contract details
                        std::string contractAddr;
                        std::string contractName;
                        std::string contractType = "Unknown";
                        uint64_t amount = 0;
                        std::string scriptPubKey;
                        std::string creator = "N/A";
                        std::string txid;
                        uint32_t vout = 0;
                        std::string status = "Unknown";

                        // First check if the contract is a simple string (address only)
                        if (contract.is_string())
                        {
                            contractAddr = contract.get<std::string>();
                            displayOutput("  Address: " + contractAddr, rows, coutMutex);
                        }
                        // Otherwise it should be a JSON object
                        else if (contract.is_object())
                        {
                            // Try to extract all possible fields

                            // Get address (try multiple field names)
                            if (contract.contains("address"))
                            {
                                contractAddr = contract["address"].get<std::string>();
                            }
                            else if (contract.contains("contractAddress"))
                            {
                                contractAddr = contract["contractAddress"].get<std::string>();
                            }
                            else if (contract.contains("identifier"))
                            {
                                contractAddr = contract["identifier"].get<std::string>();
                            }
                            else if (contract.contains("txid") && contract.contains("vout"))
                            {
                                txid = contract["txid"].get<std::string>();
                                vout = contract["vout"].get<uint32_t>();
                                contractAddr = txid + ":" + std::to_string(vout);
                            }

                            // Get name
                            if (contract.contains("name"))
                            {
                                contractName = contract["name"].get<std::string>();
                            }

                            // Get type (try both "type" and "contractType")
                            if (contract.contains("type"))
                            {
                                contractType = contract["type"].get<std::string>();
                            }
                            else if (contract.contains("contractType"))
                            {
                                contractType = contract["contractType"].get<std::string>();
                            }

                            // Get creator
                            if (contract.contains("creator"))
                            {
                                creator = contract["creator"].get<std::string>();
                            }

                            // Get status
                            if (contract.contains("status"))
                            {
                                status = contract["status"].get<std::string>();
                            }
                            else if (contract.contains("isUnspent"))
                            {
                                bool unspent = contract["isUnspent"].get<bool>();
                                status = unspent ? "Active" : "Spent";
                            }

                            // Get amount
                            if (contract.contains("amount"))
                            {
                                if (contract["amount"].is_number())
                                {
                                    amount = contract["amount"].get<uint64_t>();
                                }
                                else if (contract["amount"].is_string())
                                {
                                    try
                                    {
                                        amount = std::stoull(contract["amount"].get<std::string>());
                                    }
                                    catch (...)
                                    {
                                        amount = 0;
                                    }
                                }
                            }

                            // Get script if available
                            if (contract.contains("scriptPubKey"))
                            {
                                scriptPubKey = contract["scriptPubKey"].get<std::string>();
                            }

                            // Get txid if not already set
                            if (txid.empty() && contract.contains("txid"))
                            {
                                txid = contract["txid"].get<std::string>();
                            }

                            // Display the basic info
                            if (!contractAddr.empty())
                            {
                                displayOutput("  Address: " + contractAddr, rows, coutMutex);
                            }
                            if (!contractName.empty())
                            {
                                displayOutput("  Name: " + contractName, rows, coutMutex);
                            }
                            if (contractType != "Unknown")
                            {
                                displayOutput("  Type: " + contractType, rows, coutMutex);
                            }
                            if (!creator.empty() && creator != "N/A")
                            {
                                displayOutput("  Creator: " + creator, rows, coutMutex);
                            }
                            if (!status.empty() && status != "Unknown")
                            {
                                displayOutput("  Status: " + status, rows, coutMutex);
                            }
                            if (!txid.empty())
                            {
                                displayOutput("  Transaction ID: " + txid, rows, coutMutex);
                                if (vout > 0)
                                {
                                    displayOutput("  Output Index: " + std::to_string(vout), rows, coutMutex);
                                }
                            }
                            if (amount > 0)
                            {
                                displayOutput(
                                    "  Locked Amount: " + formatTRUAmountDetailed(amount),
                                    rows, coutMutex);
                            }

                            // Display script (abbreviated if too long)
                            if (!scriptPubKey.empty())
                            {
                                if (scriptPubKey.length() <= 100)
                                {
                                    displayOutput("  Script: " + scriptPubKey, rows, coutMutex);
                                }
                                else
                                {
                                    displayOutput("  Script: " + scriptPubKey.substr(0, 50) + "...", rows, coutMutex);
                                }
                            }

                            // Check for type-specific details
                            if (contract.contains("details") && contract["details"].is_object())
                            {
                                auto details = contract["details"];

                                if (contractType == "TIME LOCK" && details.contains("lockTime"))
                                {
                                    uint32_t lockTime = details["lockTime"].get<uint32_t>();
                                    time_t lockTimeT = static_cast<time_t>(lockTime);
                                    char timeBuffer[100];
                                    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", localtime(&lockTimeT));
                                    displayOutput("  Lock Time: " + std::string(timeBuffer), rows, coutMutex);

                                    if (details.contains("unlockable"))
                                    {
                                        bool unlockable = details["unlockable"].get<bool>();
                                        displayOutput("  Unlockable: " + std::string(unlockable ? "Yes" : "Not yet"), rows, coutMutex);
                                    }
                                }
                                else if (contractType == "HASH LOCK" && details.contains("hash"))
                                {
                                    displayOutput("  Hash: " + details["hash"].get<std::string>(), rows, coutMutex);
                                }
                            }

                            // Check for TOKEN ISSUER details
                            if (contractType == "TOKEN ISSUER" && contract.contains("token") && contract["token"].is_object())
                            {
                                displayOutput("  === Token Details ===", rows, coutMutex);
                                auto token = contract["token"];

                                if (token.contains("name"))
                                {
                                    displayOutput("    Token Name: " + token["name"].get<std::string>(), rows, coutMutex);
                                }
                                if (token.contains("exchangeRate"))
                                {
                                    uint64_t rate = token["exchangeRate"].get<uint64_t>();
                                    displayOutput("    Exchange Rate: " + std::to_string(rate) + " token units per TRU atom", rows, coutMutex);
                                }
                                if (token.contains("tokensPerTRU"))
                                {
                                    std::string tokensPerTRU = token["tokensPerTRU"].get<std::string>();
                                    displayOutput("    Tokens per TRU: " + tokensPerTRU, rows, coutMutex);
                                }
                                if (token.contains("maxSupply"))
                                {
                                    uint64_t maxSupply = token["maxSupply"].get<uint64_t>();
                                    if (maxSupply > 0)
                                    {
                                        displayOutput("    Max Supply: " + std::to_string(maxSupply), rows, coutMutex);
                                    }
                                    else
                                    {
                                        displayOutput("    Max Supply: Unlimited", rows, coutMutex);
                                    }
                                }
                                if (token.contains("totalIssued"))
                                {
                                    uint64_t totalIssued = token["totalIssued"].get<uint64_t>();
                                    displayOutput("    Total Issued: " + std::to_string(totalIssued), rows, coutMutex);
                                }
                                if (token.contains("available"))
                                {
                                    uint64_t available = token["available"].get<uint64_t>();
                                    displayOutput("    Available: " + std::to_string(available), rows, coutMutex);
                                }

                                displayOutput("", rows, coutMutex);
                                displayOutput("  To mint tokens: Use option 26 with address: " + contractAddr, rows, coutMutex);
                            }

                            // Check for VOTING contract
                            if (contractType == "VOTING" || contract.contains("proposal"))
                            {
                                // Try to get proposal from contract storage if we have an address
                                if (!contractAddr.empty())
                                {
                                    try
                                    {
                                        ContractStorage storage(chain.getStorage());
                                        std::string proposal;
                                        if (storage.getContractData(contractAddr, "proposal", proposal) && !proposal.empty())
                                        {
                                            displayOutput("  === Voting Contract ===", rows, coutMutex);
                                            displayOutput("  Proposal: " + proposal, rows, coutMutex);
                                            displayOutput("  To vote: Use option 24 with address: " + contractAddr, rows, coutMutex);
                                            displayOutput("  To view results: Use option 25 with address: " + contractAddr, rows, coutMutex);
                                        }
                                    }
                                    catch (...)
                                    {
                                        // Storage check failed - not critical
                                    }
                                }
                            }
                        }
                        else
                        {
                            // Unknown format - try to display what we can
                            displayOutput("  Data type: " + std::string(contract.type_name()), rows, coutMutex);
                            try
                            {
                                std::string dump = contract.dump();
                                if (dump.length() > 200)
                                {
                                    dump = dump.substr(0, 200) + "...";
                                }
                                displayOutput("  Raw: " + dump, rows, coutMutex);
                            }
                            catch (...)
                            {
                                displayOutput("  Unable to display contract data", rows, coutMutex);
                            }
                        }
                    }
                }

                displayOutput("=== END OF CONTRACTS ===", rows, coutMutex);
            }
            catch (const std::exception &e)
            {
                displayOutput("Error getting contracts: " + std::string(e.what()), rows, coutMutex);
            }

            continue;
        }

        else if (choice == "20u")
        {
            try
            {
                displayOutput("=== STATEFUL K/V V1 OWNER UPDATE ===", rows, coutMutex);

                std::string root;
                displayPrompt("Stable contract root (txid:vout): ", rows, coutMutex);
                signalAwareGetline(root);
                root = trim(root);
                if (!tru_contract_state::IsCanonicalContractOutpoint(root)) {
                    throw std::runtime_error("Contract root must be canonical lowercase <64-hex-txid>:<vout>");
                }

                std::string logicalKey;
                displayPrompt("State key: ", rows, coutMutex);
                signalAwareGetline(logicalKey);
                logicalKey = trim(logicalKey);

                std::string valueText;
                displayPrompt("New value (empty is allowed): ", rows, coutMutex);
                signalAwareGetline(valueText);
                std::vector<unsigned char> newValue(valueText.begin(), valueText.end());

                std::vector<unsigned char> unlockScript;
                if (!tru_contract_call::BuildStatefulKvV1UnlockScript(
                        logicalKey, newValue, unlockScript)) {
                    throw std::runtime_error(
                        "Invalid K/V call arguments (key 1..128 bytes; value <=4096 bytes)");
                }

                LevelDBStorage *storage = chain.getStorage();
                if (!storage) {
                    throw std::runtime_error("Blockchain storage is unavailable");
                }

                const std::string liveKey =
                    tru_contract_state::BuildContractLiveKey(root);
                const std::string ownerKey =
                    tru_contract_state::BuildContractOwnerKey(root);
                if (liveKey.empty() || ownerKey.empty()) {
                    throw std::runtime_error("Unable to derive root registry keys");
                }

                std::string live;
                std::string ownerHash160;
                bool found = false;
                if (!storage->getRaw(liveKey, live, found) || !found ||
                    !tru_contract_state::IsCanonicalContractOutpoint(live)) {
                    throw std::runtime_error(
                        "No canonical confirmed live anchor exists for this root");
                }
                found = false;
                if (!storage->getRaw(ownerKey, ownerHash160, found) || !found) {
                    throw std::runtime_error(
                        "No confirmed owner binding exists for this root (legacy roots remain fail-closed)");
                }
                if (ownerHash160.size() != 40 ||
                    ownerHash160.find_first_not_of("0123456789abcdef") !=
                        std::string::npos) {
                    throw std::runtime_error(
                        "Confirmed owner binding is malformed; refusing state update");
                }

                const std::string senderAddr = wallet.getCurrentAddress();
                const std::string senderScript =
                    createP2PKHScriptHexFromAddress(senderAddr);
                std::string senderHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        senderScript, senderHash160) ||
                    senderHash160 != ownerHash160) {
                    throw std::runtime_error(
                        "Current wallet address is not the owner of this state root");
                }

                std::string liveTxid;
                std::uint32_t liveVout = 0;
                if (!tru_contract_state::ParseCanonicalContractOutpoint(
                        live, liveTxid, liveVout)) {
                    throw std::runtime_error("Stored live anchor is malformed");
                }

                UTXO anchorUtxo;
                if (!chain.utxoSet.getUTXO(liveTxid, liveVout, anchorUtxo)) {
                    throw std::runtime_error(
                        "Confirmed live contract anchor UTXO is missing");
                }
                std::vector<unsigned char> anchorLock;
                if (!tru_contract_call::DecodeScriptHexStrict(
                        anchorUtxo.scriptPubKey, anchorLock) ||
                    !tru_contract_call::IsCanonicalStatefulKvV1Script(anchorLock)) {
                    throw std::runtime_error(
                        "Live anchor is not canonical Stateful K/V V1");
                }

                auto [callerTxid, callerVout] =
                    wallet.findOneSpendableUtxo(senderAddr, chain.mempool.get());
                if (callerTxid.empty()) {
                    throw std::runtime_error(
                        "No mature owner P2PKH UTXO is available to pay the call fee");
                }
                if (callerTxid == liveTxid &&
                    static_cast<std::uint32_t>(callerVout) == liveVout) {
                    throw std::runtime_error(
                        "Caller funding input cannot duplicate the contract anchor");
                }

                UTXO callerUtxo;
                if (!chain.utxoSet.getUTXO(callerTxid, callerVout, callerUtxo)) {
                    throw std::runtime_error("Failed to fetch caller funding UTXO");
                }
                std::string callerHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        callerUtxo.scriptPubKey, callerHash160) ||
                    callerHash160 != ownerHash160) {
                    throw std::runtime_error(
                        "Caller funding UTXO is not controlled by the bound contract owner");
                }

                constexpr std::uint64_t fee = 10000;
                if (callerUtxo.amount < fee) {
                    throw std::runtime_error("Caller funding UTXO cannot cover the 10000-TRU-atom fee");
                }

                Transaction tx;
                tx.version = 1;
                tx.lockTime = 0;

                // vin[0] is NOT a signature input. Its scriptSig is canonical
                // push-only K/V calldata and is committed by the signed TRUCALL.
                tx.vin.emplace_back(liveTxid, liveVout);
                tx.vin[0].scriptSig = unlockScript;

                // vin[1] is the sole owner/caller P2PKH fee input.
                tx.vin.emplace_back(callerTxid, callerVout);

                // First V1 activation is non-payable: preserve the exact anchor
                // amount and locking script. New live anchor is predictably vout 0.
                tx.vout.emplace_back(anchorUtxo.amount, anchorUtxo.scriptPubKey);

                tru_contract_call_envelope::StateCallEnvelope callEnvelope;
                callEnvelope.targetInput = 0;
                callEnvelope.continuationVout = 0;
                if (!tru_contract_call::ComputeUnlockScriptSha256(
                        unlockScript, callEnvelope.unlockScriptSha256)) {
                    throw std::runtime_error("Unable to hash Stateful K/V calldata");
                }
                std::vector<unsigned char> callScript;
                if (!tru_contract_call_envelope::BuildOpReturnScript(
                        callEnvelope, callScript)) {
                    throw std::runtime_error("Unable to build canonical TRUCALL envelope");
                }
                tx.vout.emplace_back(0, bytesToHex(callScript));

                const std::uint64_t change = callerUtxo.amount - fee;
                if (change > 0) {
                    tx.vout.emplace_back(change, senderScript);
                }

                // Dedicated state-call signing path: sign vin[1] only. Calling
                // Wallet::signTransaction() here would overwrite/reject vin[0]
                // because vin[0] intentionally spends a contract, not P2PKH.
                const std::string privateKey =
                    wallet.getPrivateKeyForAddress(senderAddr);
                ECDSAKey keyObj = ECDSAKey::fromPrivateKey(privateKey);
                const std::vector<unsigned char> pubKey =
                    keyObj.getCompressedSec1();

                unsigned char pubHash[HASH160_LEN];
                if (wally_hash160(pubKey.data(), pubKey.size(),
                                  pubHash, HASH160_LEN) != WALLY_OK) {
                    throw std::runtime_error("Failed to hash owner public key");
                }
                const std::string pubHashHex = bytesToHex(
                    std::vector<unsigned char>(pubHash, pubHash + HASH160_LEN));
                if (pubHashHex != ownerHash160) {
                    throw std::runtime_error(
                        "Wallet private key does not match the durable owner binding");
                }

                const std::vector<unsigned char> callerScript =
                    hexDecode(callerUtxo.scriptPubKey);
                const std::vector<unsigned char> sigHash =
                    tx.getSigHash(1, callerScript);
                std::vector<unsigned char> signature =
                    keyObj.sign(std::string(sigHash.begin(), sigHash.end()));
                signature.push_back(0x01); // SIGHASH_ALL
                if (signature.empty() || signature.size() > 75 || pubKey.size() > 75) {
                    throw std::runtime_error("Unexpected state-call signature/public-key size");
                }

                tx.vin[1].scriptSig.clear();
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(signature.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(), signature.begin(), signature.end());
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(pubKey.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(), pubKey.begin(), pubKey.end());
                tx.vin[1].pubKey = pubKey;

                // getSigHash() operates on a temporary transaction; fail loudly
                // if that invariant ever changes and mutates contract calldata.
                if (tx.vin[0].scriptSig != unlockScript) {
                    throw std::runtime_error(
                        "Signing unexpectedly mutated vin[0] contract calldata");
                }

                tx.computeTxId();

                const auto status = chain.mempool->addTransaction(tx);
                if (status != MempoolAddStatus::SUCCESS) {
                    throw std::runtime_error("Mempool rejected owner-authorized state call");
                }

                const std::string rawHex = hexEncode(tx.serializeBinary());
                const bool broadcastOk = wallet.broadcastTxToExternalNode(
                    rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);

                const std::string newLive =
                    tru_contract_state::BuildCanonicalContractOutpoint(tx.txid, 0);

                TruTransactionReceipt receipt;
                receipt.type = "CONTRACT CALL / STATEFUL K/V V1";
                receipt.txid = tx.txid;
                receipt.fields = {
                    {"Family", "stateful_kv_v1"},
                    {"Stable Root", root},
                    {"Old Live", live},
                    {"New Live", newLive + " (pending confirmation)"},
                    {"Owner", ownerHash160},
                    {"State Key", logicalKey},
                    {"New Value", valueText},
                    {"Broadcast", broadcastOk ? "succeeded" : "failed"}
                };
                receipt.next = "Mine one block, then query/prove the stable root state.";
                displayTransactionReceipt(receipt, coutMutex);
            }
            catch (const std::exception &e)
            {
                displayOutput(
                    "[CLI] Stateful K/V update failed: " + std::string(e.what()),
                    rows, coutMutex);
                Logger::log(
                    "[CLI] Stateful K/V update failed: " + std::string(e.what()));
            }
            continue;
        }

        else if (choice == "21")
        {
            try
            {
                displayOutput("=== VOTING V1 — CAST BALLOT ===", rows, coutMutex);

                std::string root;
                displayPrompt("Stable voting root (txid:vout): ", rows, coutMutex);
                signalAwareGetline(root);
                root = trim(root);
                if (!tru_contract_state::IsCanonicalContractOutpoint(root)) {
                    throw std::runtime_error(
                        "Voting root must be canonical lowercase <64-hex-txid>:<vout>");
                }

                LevelDBStorage* storage = chain.getStorage();
                if (!storage) {
                    throw std::runtime_error("Blockchain storage is unavailable");
                }

                const std::string liveKey =
                    tru_contract_state::BuildContractLiveKey(root);
                std::string live;
                bool found = false;
                if (liveKey.empty() ||
                    !storage->getRaw(liveKey, live, found) || !found ||
                    !tru_contract_state::IsCanonicalContractOutpoint(live)) {
                    throw std::runtime_error(
                        "No canonical confirmed live anchor exists for this voting root");
                }

                tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
                std::string stateReason;
                if (!tru_contract_state_runtime::LoadConfirmedStateDomain(
                        *storage, live, snapshot, stateReason)) {
                    throw std::runtime_error(
                        "Unable to load confirmed Voting V1 state: " + stateReason);
                }
                if (snapshot.root != root || snapshot.family != "voting_v1") {
                    throw std::runtime_error(
                        "The supplied root is not an activated Voting V1 contract");
                }

                std::size_t numOptions = 0;
                std::uint64_t endTime = 0;
                if (!tru_contract_state_runtime::ValidateVotingV1State(
                        snapshot.state, numOptions, endTime, stateReason)) {
                    throw std::runtime_error(
                        "Confirmed Voting V1 state is malformed: " + stateReason);
                }

                const auto proposalIt = snapshot.state.find("proposal");
                const std::string proposal(
                    proposalIt->second.begin(), proposalIt->second.end());

                std::uint64_t totalVotes = 0;
                if (!tru_contract_state_runtime::ReadVotingU64(
                        snapshot.state, "totalvotes", totalVotes)) {
                    throw std::runtime_error("Confirmed totalvotes is malformed");
                }

                std::ostringstream ballot;
                ballot << "=== VOTING V1 — CONFIRMED BALLOT ===\n"
                       << "Stable Root: " << root << "\n"
                       << "Live Anchor: " << live << "\n"
                       << "Proposal: " << proposal << "\n"
                       << "Total Votes: " << totalVotes << "\n"
                       << "Voting Ends: " << endTime << " (Unix)\n"
                       << "\nOptions:\n";

                for (std::size_t i = 0; i < numOptions; ++i) {
                    const auto optionIt =
                        snapshot.state.find("option" + std::to_string(i));
                    std::uint64_t count = 0;
                    if (optionIt == snapshot.state.end() ||
                        !tru_contract_state_runtime::ReadVotingU64(
                            snapshot.state,
                            "count" + std::to_string(i),
                            count)) {
                        throw std::runtime_error(
                            "Confirmed Voting V1 option/count state is malformed");
                    }
                    const std::string option(
                        optionIt->second.begin(), optionIt->second.end());
                    ballot << "  " << i << ") " << option
                           << "  [" << count << " vote";
                    if (count != 1) ballot << "s";
                    ballot << "]\n";
                }
                appendResult(ballot.str(), rows, coutMutex, 96);

                const std::uint64_t now =
                    static_cast<std::uint64_t>(std::time(nullptr));
                if (now > endTime) {
                    throw std::runtime_error(
                        "Voting has ended according to local time; consensus also enforces block-time expiry");
                }

                // The signed P2PKH fee input is the V1 voter identity.
                const std::string voterAddr = wallet.getCurrentAddress();
                const std::string voterScript =
                    createP2PKHScriptHexFromAddress(voterAddr);
                std::string voterHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        voterScript, voterHash160)) {
                    throw std::runtime_error(
                        "Current wallet address is not canonical P2PKH");
                }

                const std::string voterKey =
                    "voted:" + voterHash160;
                if (snapshot.state.find(voterKey) != snapshot.state.end()) {
                    throw std::runtime_error(
                        "This wallet address has already voted in this Voting V1 root");
                }

                displayPrompt("Enter your vote choice (number): ", rows, coutMutex);
                std::string voteChoice;
                signalAwareGetline(voteChoice);
                voteChoice = trim(voteChoice);

                std::size_t choiceIndex = 0;
                try {
                    const unsigned long parsed = std::stoul(voteChoice);
                    if (parsed >= numOptions) throw std::out_of_range("choice");
                    choiceIndex = static_cast<std::size_t>(parsed);
                } catch (...) {
                    throw std::runtime_error(
                        "Invalid voting choice; expected 0-" +
                        std::to_string(numOptions - 1));
                }

                const std::string countKey =
                    "count" + std::to_string(choiceIndex);
                const auto selectedOptionIt =
                    snapshot.state.find("option" + std::to_string(choiceIndex));
                if (selectedOptionIt == snapshot.state.end()) {
                    throw std::runtime_error(
                        "Selected Voting V1 option text is missing");
                }
                const std::string selectedOption(
                    selectedOptionIt->second.begin(),
                    selectedOptionIt->second.end());

                std::uint64_t currentCount = 0;
                if (!tru_contract_state_runtime::ReadVotingU64(
                        snapshot.state, countKey, currentCount) ||
                    currentCount == std::numeric_limits<std::uint64_t>::max()) {
                    throw std::runtime_error(
                        "Voting count is malformed or at uint64 maximum");
                }
                const std::vector<unsigned char> nextCount =
                    tru_contract_state_runtime::EncodeVotingU64(
                        currentCount + 1U);

                std::vector<unsigned char> unlockScript;
                if (!tru_contract_call::BuildStatefulKvV1UnlockScript(
                        countKey, nextCount, unlockScript)) {
                    throw std::runtime_error(
                        "Unable to build canonical Voting V1 vote calldata");
                }

                std::string liveTxid;
                std::uint32_t liveVout = 0;
                if (!tru_contract_state::ParseCanonicalContractOutpoint(
                        live, liveTxid, liveVout)) {
                    throw std::runtime_error("Stored live anchor is malformed");
                }

                UTXO anchorUtxo;
                if (!chain.utxoSet.getUTXO(
                        liveTxid, liveVout, anchorUtxo)) {
                    throw std::runtime_error(
                        "Confirmed live voting anchor UTXO is missing");
                }
                std::vector<unsigned char> anchorLock;
                if (!tru_contract_call::DecodeScriptHexStrict(
                        anchorUtxo.scriptPubKey, anchorLock) ||
                    !tru_contract_call::IsCanonicalStatefulKvV1Script(anchorLock)) {
                    throw std::runtime_error(
                        "Voting V1 live anchor is not canonical f751");
                }

                auto [callerTxid, callerVout] =
                    wallet.findOneSpendableUtxo(
                        voterAddr, chain.mempool.get());
                if (callerTxid.empty()) {
                    throw std::runtime_error(
                        "No mature voter P2PKH UTXO is available to pay the vote fee");
                }
                if (callerTxid == liveTxid &&
                    static_cast<std::uint32_t>(callerVout) == liveVout) {
                    throw std::runtime_error(
                        "Voter funding input cannot duplicate the voting anchor");
                }

                UTXO callerUtxo;
                if (!chain.utxoSet.getUTXO(
                        callerTxid, callerVout, callerUtxo)) {
                    throw std::runtime_error(
                        "Failed to fetch voter funding UTXO");
                }
                std::string callerHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        callerUtxo.scriptPubKey, callerHash160) ||
                    callerHash160 != voterHash160) {
                    throw std::runtime_error(
                        "Selected funding UTXO does not belong to the current voter address");
                }

                constexpr std::uint64_t fee = 10000;
                if (callerUtxo.amount < fee) {
                    throw std::runtime_error(
                        "Voter funding UTXO cannot cover the 10000-TRU-atom fee");
                }

                Transaction tx;
                tx.version = 1;
                tx.lockTime = 0;

                // vin[0] is canonical vote calldata, not a signature.
                tx.vin.emplace_back(liveTxid, liveVout);
                tx.vin[0].scriptSig = unlockScript;

                // vin[1] is the signed voter/fee input.
                tx.vin.emplace_back(callerTxid, callerVout);

                // Voting V1 is non-payable: preserve the anchor exactly.
                tx.vout.emplace_back(
                    anchorUtxo.amount, anchorUtxo.scriptPubKey);

                tru_contract_call_envelope::StateCallEnvelope callEnvelope;
                callEnvelope.targetInput = 0;
                callEnvelope.continuationVout = 0;
                if (!tru_contract_call::ComputeUnlockScriptSha256(
                        unlockScript, callEnvelope.unlockScriptSha256)) {
                    throw std::runtime_error(
                        "Unable to hash Voting V1 calldata");
                }
                std::vector<unsigned char> callScript;
                if (!tru_contract_call_envelope::BuildOpReturnScript(
                        callEnvelope, callScript)) {
                    throw std::runtime_error(
                        "Unable to build canonical Voting V1 TRUCALL");
                }
                tx.vout.emplace_back(0, bytesToHex(callScript));

                const std::uint64_t change =
                    callerUtxo.amount - fee;
                if (change > 0) {
                    tx.vout.emplace_back(change, voterScript);
                }

                // Sign only vin[1]. SIGHASH_ALL commits the voter to the exact
                // vote calldata, continuation anchor, and TRUCALL.
                const std::string privateKey =
                    wallet.getPrivateKeyForAddress(voterAddr);
                ECDSAKey keyObj =
                    ECDSAKey::fromPrivateKey(privateKey);
                const std::vector<unsigned char> pubKey =
                    keyObj.getCompressedSec1();

                unsigned char pubHash[HASH160_LEN];
                if (wally_hash160(
                        pubKey.data(), pubKey.size(),
                        pubHash, HASH160_LEN) != WALLY_OK) {
                    throw std::runtime_error(
                        "Failed to hash voter public key");
                }
                const std::string pubHashHex =
                    bytesToHex(std::vector<unsigned char>(
                        pubHash, pubHash + HASH160_LEN));
                if (pubHashHex != voterHash160) {
                    throw std::runtime_error(
                        "Wallet private key does not match current voter address");
                }

                const std::vector<unsigned char> callerScript =
                    hexDecode(callerUtxo.scriptPubKey);
                const std::vector<unsigned char> sigHash =
                    tx.getSigHash(1, callerScript);
                std::vector<unsigned char> signature =
                    keyObj.sign(std::string(
                        sigHash.begin(), sigHash.end()));
                signature.push_back(0x01); // SIGHASH_ALL
                if (signature.empty() || signature.size() > 75 ||
                    pubKey.size() > 75) {
                    throw std::runtime_error(
                        "Unexpected Voting V1 signature/public-key size");
                }

                tx.vin[1].scriptSig.clear();
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(signature.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(),
                    signature.begin(), signature.end());
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(pubKey.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(),
                    pubKey.begin(), pubKey.end());
                tx.vin[1].pubKey = pubKey;

                if (tx.vin[0].scriptSig != unlockScript) {
                    throw std::runtime_error(
                        "Signing unexpectedly mutated Voting V1 calldata");
                }

                tx.computeTxId();

                const auto status =
                    chain.mempool->addTransaction(tx);
                if (status != MempoolAddStatus::SUCCESS) {
                    throw std::runtime_error(
                        "Mempool rejected Voting V1 call");
                }

                const std::string rawHex =
                    hexEncode(tx.serializeBinary());
                const bool broadcastOk =
                    wallet.broadcastTxToExternalNode(
                        rawHex, "127.0.0.1",
                        tru_network::MAINNET_RPC_PORT);

                const std::string newLive =
                    tru_contract_state::BuildCanonicalContractOutpoint(
                        tx.txid, 0);

                TruTransactionReceipt receipt;
                receipt.type = "CONTRACT CALL / VOTING V1";
                receipt.txid = tx.txid;
                receipt.fields = {
                    {"Family", "voting_v1"},
                    {"Stable Root", root},
                    {"Old Live", live},
                    {"New Live", newLive + " (pending confirmation)"},
                    {"Voter", voterHash160},
                    {"Choice", std::to_string(choiceIndex)},
                    {"Option", selectedOption},
                    {"Projected Option Count", std::to_string(currentCount + 1U)},
                    {"Projected Total Votes", std::to_string(totalVotes + 1U)},
                    {"Broadcast", broadcastOk ? "succeeded" : "failed"}
                };
                receipt.next = "Mine one block, then use Voting Results; this voter is permanently marked for this root.";
                displayTransactionReceipt(receipt, coutMutex);
            }
            catch (const std::exception& ex)
            {
                displayOutput(
                    "[CLI] Voting V1 call failed: " +
                    std::string(ex.what()),
                    rows, coutMutex);
                Logger::log(
                    "[CLI] Voting V1 call failed: " +
                    std::string(ex.what()));
            }
            continue;
        }

        else if (choice == "22")
        {
            // View voting results
            displayPrompt("Stable voting root (txid:vout): ", rows, coutMutex);
            std::string contractAddr;
            signalAwareGetline(contractAddr);
            contractAddr = trim(contractAddr);

            displayVotingResults(chain, contractAddr, rows, coutMutex);
        }

        else if (choice == "23")
        {
            // canonical Token Issuer V1 payable continuation.
            // Legacy wallet.mintTokens()/ContractStorage is intentionally not
            // authoritative for this path.
            try
            {
                displayOutput(
                    "=== TOKEN ISSUER V1 — BUY / MINT ===",
                    rows, coutMutex);

                std::string root;
                displayPrompt(
                    "Stable token issuer root (txid:vout): ",
                    rows, coutMutex);
                signalAwareGetline(root);
                root = trim(root);
                if (!tru_contract_state::IsCanonicalContractOutpoint(root)) {
                    throw std::runtime_error(
                        "Token Issuer V1 root must be canonical lowercase <64-hex-txid>:<vout>");
                }

                LevelDBStorage* storage = chain.getStorage();
                if (!storage) {
                    throw std::runtime_error(
                        "Blockchain storage is unavailable");
                }

                const std::string liveKey =
                    tru_contract_state::BuildContractLiveKey(root);
                std::string live;
                bool found = false;
                if (liveKey.empty() ||
                    !storage->getRaw(liveKey, live, found) || !found ||
                    !tru_contract_state::IsCanonicalContractOutpoint(live)) {
                    throw std::runtime_error(
                        "No canonical confirmed live anchor exists for this token issuer root");
                }

                tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
                std::string stateReason;
                if (!tru_contract_state_runtime::LoadConfirmedStateDomain(
                        *storage, live, snapshot, stateReason)) {
                    throw std::runtime_error(
                        "Unable to load confirmed Token Issuer V1 state: " +
                        stateReason);
                }
                if (snapshot.root != root ||
                    snapshot.family != "token_issuer_v1") {
                    throw std::runtime_error(
                        "Confirmed root is not Token Issuer V1");
                }

                std::uint64_t exchangeRate = 0;
                std::uint64_t maxSupply = 0;
                std::uint64_t oldTotal = 0;
                if (!tru_contract_state_runtime::ValidateTokenIssuerV1State(
                        snapshot.state, exchangeRate,
                        maxSupply, oldTotal, stateReason)) {
                    throw std::runtime_error(
                        "Confirmed Token Issuer V1 state is invalid: " +
                        stateReason);
                }

                const auto nameIt = snapshot.state.find("token_name");
                if (nameIt == snapshot.state.end()) {
                    throw std::runtime_error(
                        "Confirmed token_name is missing");
                }
                const std::string tokenName(
                    nameIt->second.begin(), nameIt->second.end());

                displayOutput(
                    "Token: " + tokenName +
                    "\nRate: " + std::to_string(exchangeRate) +
                    " token units per TRU atom\nTotal issued: " +
                    std::to_string(oldTotal) +
                    (maxSupply == 0
                         ? "\nMax supply: uncapped"
                         : "\nMax supply: " + std::to_string(maxSupply)),
                    rows, coutMutex);

                std::string amountStr;
                displayPrompt(
                    "TRU contribution [TRU]: ",
                    rows, coutMutex);
                signalAwareGetline(amountStr);

                std::uint64_t callValue = 0;
                std::string amountReason;
                if (!parseTRUAmountExact(amountStr, callValue, amountReason) ||
                    callValue == 0) {
                    throw std::runtime_error(
                        "Invalid Token Issuer V1 TRU contribution: " +
                        (amountReason.empty()
                             ? std::string("amount must be greater than 0")
                             : amountReason));
                }
                if (callValue >
                    std::numeric_limits<std::uint64_t>::max() /
                        exchangeRate) {
                    throw std::runtime_error(
                        "callValue * exchange_rate would overflow uint64");
                }
                const std::uint64_t minted =
                    callValue * exchangeRate;
                if (minted >
                    std::numeric_limits<std::uint64_t>::max() -
                        oldTotal) {
                    throw std::runtime_error(
                        "total_issued addition would overflow uint64");
                }
                const std::uint64_t newTotal =
                    oldTotal + minted;
                if (maxSupply != 0 && newTotal > maxSupply) {
                    throw std::runtime_error(
                        "Purchase would exceed Token Issuer V1 max supply");
                }

                const auto totalBytes =
                    tru_contract_state_runtime::EncodeTokenIssuerU64(
                        newTotal);
                std::vector<unsigned char> unlockScript;
                if (!tru_contract_call::BuildStatefulKvV1UnlockScript(
                        "total_issued", totalBytes, unlockScript)) {
                    throw std::runtime_error(
                        "Unable to build canonical Token Issuer V1 calldata");
                }

                std::string liveTxid;
                std::uint32_t liveVout = 0;
                if (!tru_contract_state::ParseCanonicalContractOutpoint(
                        live, liveTxid, liveVout)) {
                    throw std::runtime_error(
                        "Stored Token Issuer V1 live anchor is malformed");
                }

                UTXO anchorUtxo;
                if (!chain.utxoSet.getUTXO(
                        liveTxid, liveVout, anchorUtxo)) {
                    throw std::runtime_error(
                        "Confirmed Token Issuer V1 live anchor UTXO is missing");
                }
                std::vector<unsigned char> anchorLock;
                if (!tru_contract_call::DecodeScriptHexStrict(
                        anchorUtxo.scriptPubKey, anchorLock) ||
                    !tru_contract_call::IsCanonicalStatefulKvV1Script(
                        anchorLock)) {
                    throw std::runtime_error(
                        "Token Issuer V1 live anchor is not canonical f751");
                }
                if (anchorUtxo.amount >
                    std::numeric_limits<std::uint64_t>::max() -
                        callValue) {
                    throw std::runtime_error(
                        "Token Issuer V1 continuation amount overflow");
                }
                const std::uint64_t newAnchorAmount =
                    anchorUtxo.amount + callValue;

                const std::string buyerAddr =
                    wallet.getCurrentAddress();
                const std::string buyerScript =
                    createP2PKHScriptHexFromAddress(buyerAddr);
                std::string buyerHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        buyerScript, buyerHash160)) {
                    throw std::runtime_error(
                        "Current wallet address is not canonical P2PKH");
                }

                auto [callerTxid, callerVout] =
                    wallet.findOneSpendableUtxo(
                        buyerAddr, chain.mempool.get());
                if (callerTxid.empty()) {
                    throw std::runtime_error(
                        "No mature buyer P2PKH UTXO is available");
                }
                if (callerTxid == liveTxid &&
                    static_cast<std::uint32_t>(callerVout) == liveVout) {
                    throw std::runtime_error(
                        "Buyer funding input cannot duplicate the token anchor");
                }

                UTXO callerUtxo;
                if (!chain.utxoSet.getUTXO(
                        callerTxid, callerVout, callerUtxo)) {
                    throw std::runtime_error(
                        "Failed to fetch Token Issuer V1 buyer funding UTXO");
                }

                std::string callerHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        callerUtxo.scriptPubKey, callerHash160) ||
                    callerHash160 != buyerHash160) {
                    throw std::runtime_error(
                        "Selected funding UTXO does not belong to current buyer address");
                }

                constexpr std::uint64_t fee = 10000;
                if (callerUtxo.amount < callValue ||
                    callerUtxo.amount - callValue < fee) {
                    throw std::runtime_error(
                        "Buyer funding UTXO cannot cover call value plus 10000-TRU-atom fee");
                }

                Transaction tx;
                tx.version = 1;
                tx.lockTime = 0;

                // vin[0]: contract calldata, not a signature.
                tx.vin.emplace_back(liveTxid, liveVout);
                tx.vin[0].scriptSig = unlockScript;

                // vin[1]: signed buyer/funding identity.
                tx.vin.emplace_back(callerTxid, callerVout);

                // Economic call value is exactly the increase in the live anchor.
                tx.vout.emplace_back(
                    newAnchorAmount, anchorUtxo.scriptPubKey);

                tru_contract_call_envelope::StateCallEnvelope callEnvelope;
                callEnvelope.targetInput = 0;
                callEnvelope.continuationVout = 0;
                if (!tru_contract_call::ComputeUnlockScriptSha256(
                        unlockScript,
                        callEnvelope.unlockScriptSha256)) {
                    throw std::runtime_error(
                        "Unable to hash Token Issuer V1 calldata");
                }
                std::vector<unsigned char> callScript;
                if (!tru_contract_call_envelope::BuildOpReturnScript(
                        callEnvelope, callScript)) {
                    throw std::runtime_error(
                        "Unable to build canonical Token Issuer V1 TRUCALL");
                }
                tx.vout.emplace_back(0, bytesToHex(callScript));

                const std::uint64_t change =
                    callerUtxo.amount - callValue - fee;
                if (change > 0) {
                    tx.vout.emplace_back(change, buyerScript);
                }

                // Sign only vin[1]. SIGHASH_ALL commits the buyer to the exact
                // economic anchor delta, issuance calldata, and TRUCALL.
                const std::string privateKey =
                    wallet.getPrivateKeyForAddress(buyerAddr);
                ECDSAKey keyObj =
                    ECDSAKey::fromPrivateKey(privateKey);
                const std::vector<unsigned char> pubKey =
                    keyObj.getCompressedSec1();

                unsigned char pubHash[HASH160_LEN];
                if (wally_hash160(
                        pubKey.data(), pubKey.size(),
                        pubHash, HASH160_LEN) != WALLY_OK) {
                    throw std::runtime_error(
                        "Failed to hash Token Issuer V1 buyer public key");
                }
                const std::string pubHashHex =
                    bytesToHex(std::vector<unsigned char>(
                        pubHash, pubHash + HASH160_LEN));
                if (pubHashHex != buyerHash160) {
                    throw std::runtime_error(
                        "Wallet private key does not match current buyer address");
                }

                const std::vector<unsigned char> callerScript =
                    hexDecode(callerUtxo.scriptPubKey);
                const std::vector<unsigned char> sigHash =
                    tx.getSigHash(1, callerScript);
                std::vector<unsigned char> signature =
                    keyObj.sign(std::string(
                        sigHash.begin(), sigHash.end()));
                signature.push_back(0x01); // SIGHASH_ALL
                if (signature.empty() || signature.size() > 75 ||
                    pubKey.size() > 75) {
                    throw std::runtime_error(
                        "Unexpected Token Issuer V1 signature/public-key size");
                }

                tx.vin[1].scriptSig.clear();
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(signature.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(),
                    signature.begin(), signature.end());
                tx.vin[1].scriptSig.push_back(
                    static_cast<unsigned char>(pubKey.size()));
                tx.vin[1].scriptSig.insert(
                    tx.vin[1].scriptSig.end(),
                    pubKey.begin(), pubKey.end());
                tx.vin[1].pubKey = pubKey;

                if (tx.vin[0].scriptSig != unlockScript) {
                    throw std::runtime_error(
                        "Signing unexpectedly mutated Token Issuer V1 calldata");
                }

                tx.computeTxId();

                const auto status =
                    chain.mempool->addTransaction(tx);
                if (status != MempoolAddStatus::SUCCESS) {
                    throw std::runtime_error(
                        "Mempool rejected Token Issuer V1 call");
                }

                const std::string rawHex =
                    hexEncode(tx.serializeBinary());
                const bool broadcastOk =
                    wallet.broadcastTxToExternalNode(
                        rawHex, "127.0.0.1",
                        tru_network::MAINNET_RPC_PORT);

                const std::string newLive =
                    tru_contract_state::BuildCanonicalContractOutpoint(
                        tx.txid, 0);

                TruTransactionReceipt receipt;
                receipt.type = "CONTRACT CALL / TOKEN ISSUER V1";
                receipt.txid = tx.txid;
                receipt.fields = {
                    {"Family", "token_issuer_v1"},
                    {"Stable Root", root},
                    {"Old Live", live},
                    {"New Live", newLive + " (pending confirmation)"},
                    {"Buyer", buyerHash160},
                    {"Call Value", formatTRUAmountExact(callValue)},
                    {"Atomic Value", formatTRUAtomValue(callValue)},
                    {"Rate", std::to_string(exchangeRate) +
                        " token units per TRU atom"},
                    {"Minted", std::to_string(minted) + " " + tokenName},
                    {"Total Issued", std::to_string(newTotal)},
                    {"Broadcast", broadcastOk ? "succeeded" : "failed"}
                };
                receipt.next = "Mine one block before another purchase.";
                displayTransactionReceipt(receipt, coutMutex);
            }
            catch (const std::exception& e)
            {
                displayOutput(
                    "[CLI] Token Issuer V1 call failed: " +
                    std::string(e.what()),
                    rows, coutMutex);
                Logger::log(
                    "[CLI] Token Issuer V1 call failed: " +
                    std::string(e.what()));
            }
            continue;
        }

        else if (choice == "24")
        {
            displayPrompt("Enter token contract address: ", rows, coutMutex);
            std::string contractAddr;
            signalAwareGetline(contractAddr);

            auto info = getTokenContractInfo(chain, contractAddr);
            if (!info.isValid)
            {
                displayOutput("Invalid token contract or data not found", rows, coutMutex);
                continue;
            }

            displayOutput("=== TOKEN CONTRACT INFO ===", rows, coutMutex);
            displayOutput("Token Name: " + info.tokenName, rows, coutMutex);
            displayOutput("Exchange Rate: " + std::to_string(info.exchangeRate) + " token units per TRU atom", rows, coutMutex);

            if (info.maxSupply > 0)
            {
                displayOutput("Max Supply: " + std::to_string(info.maxSupply), rows, coutMutex);
                displayOutput("Total Issued: " + std::to_string(info.totalIssued), rows, coutMutex);
                displayOutput("Available: " + std::to_string(info.maxSupply - info.totalIssued), rows, coutMutex);
            }
            else
            {
                displayOutput("Max Supply: Unlimited", rows, coutMutex);
                displayOutput("Total Issued: " + std::to_string(info.totalIssued), rows, coutMutex);
            }

            // UI arithmetic mirrors checked V1 multiplication.
            displayOutput("\n=== EXCHANGE CALCULATOR ===", rows, coutMutex);
            std::vector<uint64_t> amounts = {1000, 10000, 100000, 1000000};
            for (uint64_t amt : amounts)
            {
                if (info.exchangeRate != 0 &&
                    amt > std::numeric_limits<uint64_t>::max() /
                        info.exchangeRate) {
                    displayOutput(
                        formatTRUAmountExact(amt) +
                        " = overflow (rejected by Token Issuer V1)",
                        rows, coutMutex);
                    continue;
                }
                const uint64_t tokens = amt * info.exchangeRate;
                displayOutput(
                    formatTRUAmountExact(amt) + " = " +
                    std::to_string(tokens) + " " + info.tokenName,
                    rows, coutMutex);
            }
        }
        else if (choice == "12a")
        {
            // displayOutput() clears the output region on each
            // call, so compose this multi-line result and render it once.
            std::ostringstream tokenBalanceReport;
            tokenBalanceReport
                << "=== TOKEN ISSUER V1 PERSISTENT BALANCES ===";

            std::string buyerHash160;
            try {
                buyerHash160 = getCurrentPubkeyhash(wallet);
            } catch (const std::exception& e) {
                displayOutput(
                    "Unable to derive current wallet hash160: " +
                    std::string(e.what()),
                    rows, coutMutex);
                continue;
            }

            // Blockchain::getContracts() returns a wrapper object
            // containing a "contracts" array. Iterate the actual array rather
            // than the wrapper values so canonical Token Issuer V1 roots are
            // discoverable by the persistent-balance UI.
            const auto contractsJson = chain.getContracts();
            nlohmann::json contracts = nlohmann::json::array();

            if (contractsJson.is_object() &&
                contractsJson.contains("contracts") &&
                contractsJson["contracts"].is_array()) {
                contracts = contractsJson["contracts"];
            } else if (contractsJson.is_array()) {
                // Compatibility fallback if getContracts() ever returns the
                // array directly.
                contracts = contractsJson;
            } else {
                Logger::log(
                    "[TokenIssuer12a] Unexpected getContracts() payload shape");
            }

            bool foundTokens = false;

            for (const auto& contractJson : contracts)
            {
                std::string contractRoot;
                if (contractJson.contains("address")) {
                    contractRoot =
                        contractJson["address"].get<std::string>();
                } else if (contractJson.contains("contractAddress")) {
                    contractRoot =
                        contractJson["contractAddress"].get<std::string>();
                } else {
                    continue;
                }

                const auto info =
                    getTokenContractInfo(chain, contractRoot);
                if (!info.isValid) continue;

                const uint64_t balance =
                    getTokenBalance(
                        chain, contractRoot, buyerHash160);
                if (balance == 0) continue;

                foundTokens = true;
                tokenBalanceReport
                    << "\n\nToken: " << info.tokenName
                    << " | Balance: " << balance
                    << "\n  Stable root: " << contractRoot
                    << "\n  Exchange Rate: " << info.exchangeRate
                    << " token units per TRU atom"
                    << "\n  Total Issued: " << info.totalIssued;
            }

            if (!foundTokens)
            {
                tokenBalanceReport
                    << "\n\nNo positive Token Issuer V1 balances found for current wallet."
                    << "\nUse option 26 to purchase/mint from a confirmed Token Issuer V1 root.";
            }

            displayOutput(tokenBalanceReport.str(), rows, coutMutex);
        }

        else if (choice == "timeredeem")
        {
            try
            {
                displayResult(
                    "=== TIME LOCK — REDEEM ===\n"
                    "Provide the confirmed Time Lock output.\n"
                    "The wallet verifies lock time, owner key, tx.lockTime and non-final sequence.",
                    rows, coutMutex, 96);

                std::string contractOutpoint;
                displayPrompt("Time Lock output (txid:vout): ", rows, coutMutex);
                signalAwareGetline(contractOutpoint);
                contractOutpoint = trim(contractOutpoint);

                ContractDetails details = wallet.getContractDetails(contractOutpoint);
                if (details.type != "Time Lock") {
                    throw std::runtime_error(
                        "The supplied output is not a canonical Time Lock");
                }

                const size_t colonPos = contractOutpoint.find(':');
                if (colonPos == std::string::npos) {
                    throw std::runtime_error("Malformed Time Lock output");
                }
                const std::string lockTxid = contractOutpoint.substr(0, colonPos);
                const uint32_t lockVout = static_cast<uint32_t>(
                    std::stoul(contractOutpoint.substr(colonPos + 1)));

                UTXO lockedUtxo;
                if (!chain.utxoSet.getUTXO(lockTxid, lockVout, lockedUtxo)) {
                    throw std::runtime_error(
                        "Time Lock output is already spent or unavailable");
                }

                uint32_t lockTime = 0;
                if (lockedUtxo.scriptPubKey.size() == 64 &&
                    lockedUtxo.scriptPubKey.substr(0, 2) == "04" &&
                    lockedUtxo.scriptPubKey.substr(10, 10) == "b17576a914" &&
                    lockedUtxo.scriptPubKey.substr(60, 4) == "88ac") {
                    const std::string h = lockedUtxo.scriptPubKey.substr(2, 8);
                    for (int i = 0; i < 4; ++i) {
                        const uint32_t b = static_cast<uint32_t>(
                            std::stoul(h.substr(static_cast<std::size_t>(i) * 2, 2), nullptr, 16));
                        lockTime |= (b << (8 * i));
                    }
                } else {
                    throw std::runtime_error("Malformed canonical Time Lock script");
                }

                const std::string redeemTxid = wallet.redeemTimeLock(contractOutpoint);

                TruTransactionReceipt receipt;
                receipt.type = "CONTRACT REDEEM / TIME LOCK";
                receipt.txid = redeemTxid;
                receipt.fields = {
                    {"Locked Output", contractOutpoint},
                    {"Locked Amount", tru_amount::format(lockedUtxo.amount)},
                    {"Lock Until", formatTimestamp(lockTime)},
                    {"Destination", wallet.getCurrentAddress()},
                    {"Broadcast", "mempool accepted"}
                };
                receipt.next =
                    "Mine one block, then confirm the Time Lock output is spent and the redeemed TRU is confirmed.";
                displayTransactionReceipt(receipt, coutMutex);
            }
            catch (const std::exception& e)
            {
                displayOutput(
                    "[CLI] Time Lock redemption failed: " + std::string(e.what()),
                    rows, coutMutex);
                Logger::log(
                    "[CLI] Time Lock redemption failed: " + std::string(e.what()));
            }
            continue;
        }

        else if (choice == "hashredeem")
        {
            try
            {
                displayResult(
                    "=== HASH LOCK — REDEEM ===\n"
                    "Provide the confirmed Hash Lock output and the original preimage.\n"
                    "The wallet verifies HASH160 before constructing a spend.",
                    rows, coutMutex, 96);

                std::string contractOutpoint;
                displayPrompt(
                    "Hash Lock output (txid:vout): ",
                    rows, coutMutex);
                signalAwareGetline(contractOutpoint);
                contractOutpoint = trim(contractOutpoint);

                ContractDetails details =
                    wallet.getContractDetails(contractOutpoint);
                if (details.type != "Hash Lock") {
                    throw std::runtime_error(
                        "The supplied output is not an active canonical Hash Lock");
                }

                const size_t colonPos = contractOutpoint.find(':');
                if (colonPos == std::string::npos) {
                    throw std::runtime_error("Malformed Hash Lock output");
                }
                const std::string lockTxid =
                    contractOutpoint.substr(0, colonPos);
                const uint32_t lockVout =
                    static_cast<uint32_t>(
                        std::stoul(contractOutpoint.substr(colonPos + 1)));

                UTXO lockedUtxo;
                if (!chain.utxoSet.getUTXO(
                        lockTxid, lockVout, lockedUtxo)) {
                    throw std::runtime_error(
                        "Hash Lock output is already spent or unavailable");
                }

                std::string expectedHash160;
                if (details.scriptHex.size() == 46 &&
                    details.scriptHex.rfind("a914", 0) == 0 &&
                    details.scriptHex.substr(44, 2) == "87") {
                    expectedHash160 = details.scriptHex.substr(4, 40);
                }

                std::string preimage;
                displayPrompt(
                    "Original preimage (<=100 chars): ",
                    rows, coutMutex);
                signalAwareGetline(preimage);
                if (preimage.size() > 100) {
                    throw std::runtime_error(
                        "Preimage exceeds the 100-byte Hash Lock limit");
                }

                const std::string redeemTxid =
                    wallet.redeemHashLock(
                        contractOutpoint, preimage);

                TruTransactionReceipt receipt;
                receipt.type = "CONTRACT REDEEM / HASH LOCK";
                receipt.txid = redeemTxid;
                receipt.fields = {
                    {"Locked Output", contractOutpoint},
                    {"Locked Amount", tru_amount::format(lockedUtxo.amount)},
                    {"Expected HASH160", expectedHash160},
                    {"Destination", wallet.getCurrentAddress()},
                    {"Broadcast", "mempool accepted"}
                };
                receipt.next =
                    "Mine one block, then confirm the locked output is spent and the redeemed TRU is confirmed.";
                displayTransactionReceipt(receipt, coutMutex);
            }
            catch (const std::exception& e)
            {
                displayOutput(
                    "[CLI] Hash Lock redemption failed: " +
                    std::string(e.what()),
                    rows, coutMutex);
                Logger::log(
                    "[CLI] Hash Lock redemption failed: " +
                    std::string(e.what()));
            }
            continue;
        }

        else if (choice == "createlock")
        {
            displayPrompt("Amount to lock [TRU]: ", rows, coutMutex);
            std::string amountText;
            signalAwareGetline(amountText);

            std::uint64_t atoms = 0;
            std::string amountReason;
            if (!parseTRUAmountExact(amountText, atoms, amountReason) || atoms == 0) {
                throw std::runtime_error(
                    "Invalid MagicLock TRU amount: " +
                    (amountReason.empty()
                         ? std::string("amount must be greater than 0")
                         : amountReason));
            }

            displayPrompt("Target prefix (e.g., '21e8'): ", rows, coutMutex);
            std::string prefix;
            signalAwareGetline(prefix);
            prefix = trim(prefix);

            std::string txid = wallet.createMagicLock(atoms, prefix);
            TruTransactionReceipt receipt;
            receipt.type = "MAGICLOCK CREATE";
            receipt.txid = txid;
            receipt.fields = {
                {"Amount", tru_amount::format(atoms)},
                {"Atomic Value", std::to_string(atoms) + " TRU atoms"},
                {"Target Prefix", prefix}
            };
            receipt.next = "Mine one block before attempting redemption.";
            displayTransactionReceipt(receipt, coutMutex);
        }
        else if (choice == "unlock")
        {
            displayPrompt("Lock transaction ID: ", rows, coutMutex);
            std::string txid;
            signalAwareExtract(txid);

            displayPrompt("Output index: ", rows, coutMutex);
            uint32_t vout;
            signalAwareExtract(vout);

            displayPrompt("Send to address: ", rows, coutMutex);
            std::string recipient;
            signalAwareExtract(recipient);

            displayResult("Mining MagicLock... this may take a while", rows, coutMutex, 93);
            std::string unlockTx = wallet.unlockMagicLock(txid, vout, recipient);

            TruTransactionReceipt receipt;
            receipt.type = "MAGICLOCK REDEEM";
            receipt.txid = unlockTx;
            receipt.fields = {
                {"Source", txid + ":" + std::to_string(vout)},
                {"Recipient", recipient}
            };
            receipt.next = "Mine one block, then verify the redeemed output.";
            displayTransactionReceipt(receipt, coutMutex);
        }
        else if (choice == "sync")
        {
            uint64_t localHeight = chain.getBestTipHeight();
            uint64_t highestPeer = node.getHighestPeerHeight();

            std::cout << "\nSync Status:" << std::endl;
            std::cout << "Local height: " << localHeight << std::endl;
            std::cout << "Network height: " << highestPeer << std::endl;

            if (localHeight >= highestPeer)
            {
                std::cout << "Status: ✓ Fully synchronized" << std::endl;
            }
            else
            {
                float progress = (highestPeer > 0) ? ((float)localHeight / highestPeer * 100.0f) : 0;
                std::cout << "Status: Syncing... " << std::fixed << std::setprecision(1)
                          << progress << "% complete" << std::endl;
                std::cout << "Blocks remaining: " << (highestPeer - localHeight) << std::endl;
            }
        }
        else if (choice == "M" || choice == "m") {
            // M/C restore the logo with an absolute
            // header repaint instead of a full-screen clear. If mining is
            // active, displayMinerStats() will immediately reclaim rows 9..15.
            if (g_cliContentFocus.load(std::memory_order_acquire)) {
                clearOutput(rows, coutMutex);
                paintHeader(coutMutex);
                continue;
            }

            g_compactMenu = !g_compactMenu;
            paintHeader(coutMutex);
            continue;
        }
        else if (choice == "C" || choice == "c") {
            // restore the original Matrix-rain clear.
            // clearOutput() also releases Output Focus before the animation.
            clearOutput(rows, coutMutex);
            printBanner3(coutMutex);

            // printBanner3() deliberately retains the original animation and
            // legacy final-banner behavior. Normalize once afterward so the
            // current TRU CORE header/menu owns the expected fixed rows.
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                fmt::print("[2J[1;1H");
            }
            paintHeader(coutMutex);
            continue;
        }
        else {
            // Unrecognized
            displayOutput("Invalid option. Please choose 1-36, sync, C, or M", rows, coutMutex);
        }
    }
    sizeMonitorRunning = false;
    spinnerRunning = false;
}

// -------------------------------------------------------------------
// 	                   MEMPOOL LIST ALL TX
// -------------------------------------------------------------------
void listMempoolTransactions(const Blockchain& chain, int rows, std::mutex& coutMutex) {
    try {
        auto memTxs = chain.mempool->getAllTransactions();
        std::ostringstream oss;
        oss << "[CLI] Mempool Transactions (" << memTxs.size() << "):\n";
        if (memTxs.empty()) {
            oss << "  No transactions in mempool.\n";
        } else {
            for (const auto& tx : memTxs) {
                oss << "  Txid: " << tx.txid << "\n";
                oss << "    Inputs: " << tx.vin.size() << ", Outputs: " << tx.vout.size() << "\n";
                for (size_t i = 0; i < tx.vout.size(); ++i) {
                    oss << "    Output #" << i << ": " << tx.vout[i].scriptPubKey << " (" << formatTRUAtomValue(tx.vout[i].amount) << ")\n";
                }
            }
        }
        displayOutput(oss.str(), rows, coutMutex);
    } catch (const std::exception& e) {
        displayOutput("[CLI] Failed to list mempool transactions: " + std::string(e.what()), rows, coutMutex);
    }
}



//====================================================================================
// Function to load peers from a file
//====================================================================================
static bool persistablePeerIp(const std::string& ip,
                              const std::string& externalIp = std::string()) {
    // MULTINODE-01D: loopback was not enough. Any IPv4 address assigned to a
    // local interface is this node and must never become reconnect authority.
    if (tru_network_identity::isLocalAddress(ip)) return false;
    if (!externalIp.empty() &&
        (ip == externalIp || tru_network_identity::sameIpv4(ip, externalIp))) {
        return false;
    }
    return true;
}

std::vector<std::pair<std::string, int>> loadPeers(
    const std::string& filename,
    int canonicalP2PPort,
    const std::string& externalIp) {
    std::vector<std::pair<std::string, int>> peers;
    std::ifstream file(filename);
    if (!file.is_open()) return peers;

    std::string line;
    bool verifiedEndpointFormat = false;
    while (std::getline(file, line)) {
        if (line == "# TRU_PEER_ENDPOINTS_V2") { verifiedEndpointFormat = true; continue; }
        const auto colonPos = line.rfind(':');
        if (colonPos == std::string::npos) continue;
        const std::string ip = line.substr(0, colonPos);
        int storedPort = 0;
        try {
            std::size_t used = 0;
            const auto portText = line.substr(colonPos + 1);
            storedPort = std::stoi(portText, &used);
            if (used != portText.size() || storedPort <= 0 || storedPort > 65535) continue;
        } catch (...) {
            Logger::log("[MULTINODE-01A] Ignoring malformed saved peer: " + line);
            continue;
        }

        // Old releases persisted inbound TCP source ports (ephemeral 5xxxx/6xxxx
        // values). Only a peer explicitly stored at this network's canonical P2P
        // service port is reconnectable authority.
        if ((!verifiedEndpointFormat && storedPort != canonicalP2PPort) ||
            !persistablePeerIp(ip, externalIp)) {
            Logger::log(
                "[MULTINODE-01A] Ignoring non-canonical saved peer: " + line);
            continue;
        }

        const std::pair<std::string, int> candidate{ip, storedPort};
        if (std::find(peers.begin(), peers.end(), candidate) == peers.end()) {
            peers.push_back(candidate);
        }
    }
    return peers;
}

void savePeers(const std::vector<PeerInfo>& peers,
               const std::string& filename,
               int canonicalP2PPort,
               const std::string& externalIp) {
    std::ofstream file(filename, std::ios::trunc);
    if (!file.is_open()) {
        Logger::log("[MULTINODE-01A] Unable to open peer file for save: " + filename);
        return;
    }

    file << "# TRU_PEER_ENDPOINTS_V2\n";
    std::vector<std::string> written;
    for (const auto& peer : peers) {
        if (!persistablePeerIp(peer.ip, externalIp)) continue;
        if (peer.port <= 0 || peer.port > 65535) continue;
        const auto endpoint = peer.ip + ":" + std::to_string(peer.port);
        if (std::find(written.begin(), written.end(), endpoint) != written.end()) continue;
        // Only VERSION-verified service endpoints enter this book; source ports
        // never do. Legacy files without the marker still get strict filtering.
        file << endpoint << "\n";
        written.push_back(endpoint);
    }
    Logger::log(
        "[MULTINODE-01A] Saved " + std::to_string(written.size()) +
        " verified service endpoint(s)");
}
//======================================================================================
//			Main Ini
//======================================================================================
int main(int argc, char *argv[]) {
    // Declare these outside the try block so they're accessible in catch blocks
    std::unique_ptr<P2PNode> node;
    std::unique_ptr<Blockchain> chain;
    std::thread minerCleanupThread;
    
    try {
        std::srand(static_cast<unsigned>(std::time(nullptr)));

        cxxopts::Options options("tru_advanced", "TRU Blockchain Advanced Wallet CLI");
        options.add_options()
            ("d,datadir", "Path to data dir", cxxopts::value<std::string>()->default_value("data/utxo"))
            ("logdir", "Directory for TRU application logs (default: sibling logs directory beside datadir)", cxxopts::value<std::string>()->default_value(""))
            ("loglevel", "Log level: ERROR, WARN, INFO, DEBUG, TRACE", cxxopts::value<std::string>()->default_value("INFO"))
            ("log-max-mib", "Rotate active log after this many MiB", cxxopts::value<std::uint64_t>()->default_value("32"))
            ("log-retain", "Number of rotated log files to retain (0-32)", cxxopts::value<std::size_t>()->default_value("4"))
            ("c,cli", "Run in CLI mode", cxxopts::value<bool>()->default_value("true"))
            ("gui", "Run in GUI mode", cxxopts::value<bool>()->default_value("false"))
            //("rpcbind", "RPC bind IP", cxxopts::value<std::string>()->default_value("0.0.0.0"))
            ("rpcbind", "RPC bind IP", cxxopts::value<std::string>()->default_value("127.0.0.1"))
            ("rpcport", "RPC port", cxxopts::value<int>()->default_value(std::to_string(tru_network::MAINNET_RPC_PORT)))
            ("conf", "Path to config", cxxopts::value<std::string>()->default_value("tru.conf"))
            ("explorer-port", "Port for block explorer server", cxxopts::value<int>()->default_value("8001"))
            ("enable-explorer", "Enable block explorer server", cxxopts::value<bool>()->default_value("false"))
            ("peers", "Comma-separated list of peers", cxxopts::value<std::string>()->default_value(""))
            ("no-seeds", "Start without connecting to seed nodes", cxxopts::value<bool>()->default_value("false"))
            ("no-p2p", "Run without P2P listener", cxxopts::value<bool>()->default_value("false"))
            ("bootstrap-encrypted-wallet", "Create a brand-new encrypted wallet artifact set and exit", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);
        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // GUI-DESKTOP-01: initialize Qt only for GUI launches. CLI/headless
        // execution never attempts to connect to a display server.
#ifdef BUILD_WITH_QT
        std::unique_ptr<QApplication> qtApp;
        if (result["gui"].as<bool>()) {
            QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
            qtApp = std::make_unique<QApplication>(argc, argv);
        }
#else
        if (result["gui"].as<bool>())
            throw std::runtime_error("GUI unavailable; rebuild with BUILD_WITH_QT=ON");
#endif

        const std::string dbPath = result["datadir"].as<std::string>();
        std::string logDir = result["logdir"].as<std::string>();
        const std::string logLevel = result["loglevel"].as<std::string>();
        const std::uint64_t logMaxMiB = result["log-max-mib"].as<std::uint64_t>();
        const std::size_t logRetain = result["log-retain"].as<std::size_t>();

        if (logMaxMiB == 0 || logMaxMiB > 4096) {
            throw std::runtime_error("--log-max-mib must be between 1 and 4096");
        }
        if (logRetain > 32) {
            throw std::runtime_error("--log-retain must be between 0 and 32");
        }

        namespace fs = std::filesystem;
        fs::path requestedLogDir;
        if (logDir.empty()) {
            fs::path dataPath(dbPath);
            fs::path base = dataPath.parent_path();
            if (base.empty()) base = fs::path(".");
            requestedLogDir = base / "logs";
        } else {
            requestedLogDir = fs::path(logDir);
        }
        logDir = fs::absolute(requestedLogDir).lexically_normal().string();

        const fs::path logPath = fs::path(logDir) / "Tru_debug.log";
        Logger::init(
            logPath.string(),
            logLevel,
            logMaxMiB * 1024ULL * 1024ULL,
            logRetain);
        initializeSignalWakePipe();
        Logger::log(
            "[main] Signal-safe CLI wake pipe initialized for "
            "SIGINT/SIGTERM/SIGWINCH");
        Logger::log("[main] Starting TRU Advanced Wallet...");
        Logger::log(
            "[LOGGING-01C] datadir=" + dbPath +
            "; logdir=" + logDir +
            "; level=" + logLevel +
            "; maxMiB=" + std::to_string(logMaxMiB) +
            "; retained=" + std::to_string(logRetain));

        // SEC-14G — encrypted-first wallet bootstrap runs before config,
        // blockchain construction, networking, RPC, or any chain mutation.
        if (result["bootstrap-encrypted-wallet"].as<bool>()) {
            if (!::isatty(STDIN_FILENO)) {
                throw std::runtime_error(
                    "[SEC-14G] encrypted wallet bootstrap requires an interactive terminal");
            }

            auto readHiddenBootstrapPassphrase = [](const char* prompt) {
                struct termios oldTermios {};
                if (::tcgetattr(STDIN_FILENO, &oldTermios) != 0) {
                    throw std::runtime_error(
                        "[SEC-14G] unable to read terminal settings");
                }
                struct termios hiddenTermios = oldTermios;
                hiddenTermios.c_lflag &= static_cast<tcflag_t>(~ECHO);
                if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenTermios) != 0) {
                    throw std::runtime_error(
                        "[SEC-14G] unable to disable terminal echo");
                }

                std::string value;
                std::cout << prompt << std::flush;
                const bool ok = static_cast<bool>(std::getline(std::cin, value));
                const int restoreRc =
                    ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTermios);
                std::cout << std::endl;

                if (restoreRc != 0) {
                    std::fill(value.begin(), value.end(), '\0');
                    value.clear();
                    throw std::runtime_error(
                        "[SEC-14G] unable to restore terminal echo");
                }
                if (!ok || value.empty()) {
                    std::fill(value.begin(), value.end(), '\0');
                    value.clear();
                    throw std::runtime_error(
                        "[SEC-14G] bootstrap cancelled or empty passphrase");
                }
                return value;
            };

            std::string first =
                readHiddenBootstrapPassphrase("New wallet passphrase: ");
            std::string second =
                readHiddenBootstrapPassphrase("Confirm wallet passphrase: ");

            if (first != second) {
                std::fill(first.begin(), first.end(), '\0');
                std::fill(second.begin(), second.end(), '\0');
                first.clear();
                second.clear();
                throw std::runtime_error(
                    "[SEC-14G] wallet passphrase confirmation mismatch");
            }

            std::string newAddress;
            std::string bootstrapError;
            const bool bootstrapped = bootstrapEncryptedWalletV1(
                "tru.dat", first, newAddress, &bootstrapError);

            std::fill(first.begin(), first.end(), '\0');
            std::fill(second.begin(), second.end(), '\0');
            first.clear();
            second.clear();
            first.shrink_to_fit();
            second.shrink_to_fit();

            if (!bootstrapped) {
                throw std::runtime_error(
                    "[SEC-14G] encrypted-first wallet bootstrap failed" +
                    (bootstrapError.empty()
                        ? std::string()
                        : std::string(": ") + bootstrapError));
            }

            Logger::log(
                "[SEC-14G] encrypted-first wallet bootstrap completed; "
                "private material was not printed");
            std::cout
                << "SEC-14G ENCRYPTED-FIRST WALLET BOOTSTRAP: PASS\n"
                << "Wallet address: " << newAddress << "\n"
                << "Artifacts: wallet_seed.dat.enc, tru.dat.enc, tru.dat.public\n"
                << "Plaintext wallet artifacts: ABSENT\n"
                << "Private material printed: NO\n";
            Logger::shutdown();
            return 0;
        }

        bool cliMode = result["cli"].as<bool>();
        bool guiMode = result["gui"].as<bool>();
        // Resolve the selected config once; bootstrap helpers use this same file.
        std::string cfgFile = std::filesystem::absolute(
            result["conf"].as<std::string>()).lexically_normal().string();

        std::string rpcBind = result["rpcbind"].as<std::string>();
        int rpcPort = result["rpcport"].as<int>();

        int p2pPort = tru_network::MAINNET_P2P_PORT;
        bool listenP2P = true;
        int rpcMaxConnections = 32;
        bool rpcAllowRemote = false;

        int explorerPort = result["explorer-port"].as<int>();
        bool enableExplorer = result["enable-explorer"].as<bool>();
        std::string peersArg = result["peers"].as<std::string>();
        bool noSeeds = result["no-seeds"].as<bool>();
        bool noP2P = result["no-p2p"].as<bool>();

        const int maxConnectionRetries = 10;
        const std::chrono::seconds retryDelay(10);

        Logger::log("[main] Loading config file: " + cfgFile);
        auto cfg = readConfigFile(cfgFile);
        Logger::log("[main] Config file loaded successfully");

        const auto &networkCfg = cfg["network"];

        // rpcbind
        {
            auto it = networkCfg.find("rpcbind");
            if (it != networkCfg.end() && !it->second.empty())
            {
                rpcBind = it->second;
                Logger::log("[main] Config rpcbind = " + rpcBind);
            }
        }

        // rpcport
        {
            auto it = networkCfg.find("rpcport");
            if (it != networkCfg.end() && !it->second.empty())
            {
                try
                {
                    int value = std::stoi(it->second);

                    if (value > 0 && value <= 65535)
                    {
                        rpcPort = value;
                        Logger::log("[main] Config rpcport = " +
                                    std::to_string(rpcPort));
                    }
                    else
                    {
                        Logger::log(
                            "[main] WARNING: Invalid rpcport in config; "
                            "keeping default " +
                            std::to_string(rpcPort));
                    }
                }
                catch (const std::exception &e)
                {
                    Logger::log(
                        "[main] WARNING: Invalid rpcport in config (" +
                        it->second + "); keeping default " +
                        std::to_string(rpcPort));
                }
            }
        }

        // p2pPort
        {
            auto it = networkCfg.find("p2pPort");
            if (it != networkCfg.end() && !it->second.empty())
            {
                try
                {
                    int value = std::stoi(it->second);

                    if (value > 0 && value <= 65535)
                    {
                        p2pPort = value;
                        Logger::log("[main] Config p2pPort = " +
                                    std::to_string(p2pPort));
                    }
                    else
                    {
                        Logger::log(
                            "[main] WARNING: Invalid p2pPort in config; "
                            "keeping default " +
                            std::to_string(p2pPort));
                    }
                }
                catch (const std::exception &e)
                {
                    Logger::log(
                        "[main] WARNING: Invalid p2pPort in config (" +
                        it->second + "); keeping default " +
                        std::to_string(p2pPort));
                }
            }
        }

        // listen
        {
            auto it = networkCfg.find("listen");
            if (it != networkCfg.end() && !it->second.empty())
            {
                if (it->second == "1" ||
                    it->second == "true" ||
                    it->second == "TRUE")
                {

                    listenP2P = true;
                }
                else if (it->second == "0" ||
                         it->second == "false" ||
                         it->second == "FALSE")
                {

                    listenP2P = false;
                }
                else
                {
                    Logger::log(
                        "[main] WARNING: Invalid listen value in config (" +
                        it->second + "); keeping default listen=1");
                }

                Logger::log(
                    "[main] Config listen = " +
                    std::string(listenP2P ? "1" : "0"));
            }
        }

        // rpcMaxConnections
        {
            auto it = networkCfg.find("rpcMaxConnections");
            if (it != networkCfg.end() && !it->second.empty())
            {
                try
                {
                    int value = std::stoi(it->second);

                    if (value > 0 && value <= 256)
                    {
                        rpcMaxConnections = value;
                        Logger::log(
                            "[main] Config rpcMaxConnections = " +
                            std::to_string(rpcMaxConnections));
                    }
                    else
                    {
                        Logger::log(
                            "[main] WARNING: Invalid rpcMaxConnections; "
                            "keeping default " +
                            std::to_string(rpcMaxConnections));
                    }
                }
                catch (const std::exception &e)
                {
                    Logger::log(
                        "[main] WARNING: Invalid rpcMaxConnections (" +
                        it->second + "); keeping default " +
                        std::to_string(rpcMaxConnections));
                }
            }
        }

        // non-loopback privileged RPC requires explicit operator opt-in.
        {
            auto it = networkCfg.find("rpcAllowRemote");
            if (it != networkCfg.end() && !it->second.empty()) {
                std::string value = it->second;
                std::transform(value.begin(), value.end(), value.begin(),
                               [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (value == "1" || value == "true" || value == "yes" || value == "on") {
                    rpcAllowRemote = true;
                } else if (value == "0" || value == "false" || value == "no" || value == "off") {
                    rpcAllowRemote = false;
                } else {
                    throw std::runtime_error("Invalid [network] rpcAllowRemote value; expected 0/1/true/false");
                }
            }
        }

        std::vector<std::pair<std::string, int>> seedNodes;
        std::string externalIp;

        if (cfg["default"].find("peers") != cfg["default"].end()) {
            peersArg = cfg["default"]["peers"];
            Logger::log("[main] Found peers in [default]: " + peersArg);
        }

        if (cfg["network"].find("addnode") != cfg["network"].end()) {
            std::string addnodeStr = cfg["network"]["addnode"];
            Logger::log("[main] Found addnode in [network]: " + addnodeStr);
            std::stringstream ss(addnodeStr);
            std::string nodeAddr;
            while (std::getline(ss, nodeAddr, ',')) {
                size_t colonPos = nodeAddr.find(':');
                if (colonPos != std::string::npos) {
                    std::string ip = nodeAddr.substr(0, colonPos);
                    try {
                        int port = std::stoi(nodeAddr.substr(colonPos + 1));
                        seedNodes.emplace_back(ip, port);
                        Logger::log("[main] Parsed addnode: " + ip + ":" + std::to_string(port));
                    } catch (const std::exception& e) {
                        Logger::log("[main] Invalid addnode: " + nodeAddr + " - " + e.what());
                    }
                }
            }
        }

        if (cfg["network"].find("externalip") != cfg["network"].end()) {
            externalIp = cfg["network"]["externalip"];
            Logger::log("[main] External IP set to: " + externalIp);
        }
        // MULTINODE-01B: config-owned opt-in for the already-hardened 08B.4D.9
        // chainwork reorganization executor. Missing key preserves environment
        // behavior; explicit 0 disables; explicit 1 arms the exact existing magic.
        bool automaticReorgConfigured = false;
        bool automaticReorgEnabled = false;
        if (cfg["network"].find("automaticReorg") != cfg["network"].end()) {
            automaticReorgConfigured = true;
            std::string value = cfg["network"]["automaticReorg"];
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (value == "1" || value == "true" || value == "yes" || value == "on") {
                automaticReorgEnabled = true;
            } else if (value == "0" || value == "false" || value == "no" || value == "off") {
                automaticReorgEnabled = false;
            } else {
                throw std::runtime_error(
                    "Invalid [network] automaticReorg value; expected 0/1/true/false");
            }
            Logger::log(
                std::string("[MULTINODE-01B] Config automaticReorg=") +
                (automaticReorgEnabled ? "1" : "0"));
        }


        Logger::log("============================================================");
        Logger::log("[main] Effective network configuration:");
        Logger::log("[main]   rpcbind          = " + rpcBind);
        Logger::log("[main]   rpcport          = " + std::to_string(rpcPort));
        Logger::log("[main]   p2pPort          = " + std::to_string(p2pPort));
        Logger::log("[main]   listen           = " +
                    std::string(listenP2P ? "1" : "0"));
        Logger::log("[main]   rpcMaxConnections= " +
                    std::to_string(rpcMaxConnections));
        Logger::log("[main]   rpcAllowRemote    = " +
                    std::string(rpcAllowRemote ? "1" : "0"));
        Logger::log("============================================================");

        if (!directoryExists("data")) {
            Logger::log("[main] Creating data directory: data");
            mkdir("data", 0755);
        }
        if (!directoryExists(dbPath)) {
            Logger::log("[main] Creating data directory: " + dbPath);
            mkdir(dbPath.c_str(), 0755);
        }
        Logger::log("[main] Using data directory: " + dbPath);

        // authenticated privileged RPC boundary. Authentication is
        // mandatory. Loopback is the default; non-loopback binds require an
        // explicit rpcAllowRemote=1 acknowledgement. The token is never logged.
        if (!tru_rpc::isLoopbackBind(rpcBind) && !rpcAllowRemote) {
            throw std::runtime_error(
                "Patch 05: refusing non-loopback rpcbind without [network] rpcAllowRemote=1");
        }
        const std::string rpcAuthToken = tru_rpc::loadOrCreateServerToken(rpcPort);
#ifndef _WIN32
        ::setenv("TRU_RPC_TOKEN", rpcAuthToken.c_str(), 1);
#else
        _putenv_s("TRU_RPC_TOKEN", rpcAuthToken.c_str());
#endif
        Logger::log("[RPC-05] TRANSPORT_AUTH=REQUIRED");
        Logger::log("[RPC-05] RPC_TOKEN_PRINTED=NO");
        Logger::log("[RPC-05] COOKIE_PATH=" + tru_rpc::defaultCookiePath(rpcPort).string());
        Logger::log("[RPC-05] DIRECT_BROWSER_RPC=FORBIDDEN");

        if (automaticReorgConfigured) {
#ifdef _WIN32
            if (automaticReorgEnabled) {
                _putenv_s("TRU_ENABLE_08B4D9_AUTOMATIC_REORG",
                          "I_ACCEPT_PRODUCTION_CHAINWORK_REORGANIZATION");
            } else {
                _putenv_s("TRU_ENABLE_08B4D9_AUTOMATIC_REORG", "");
            }
#else
            if (automaticReorgEnabled) {
                ::setenv("TRU_ENABLE_08B4D9_AUTOMATIC_REORG",
                         "I_ACCEPT_PRODUCTION_CHAINWORK_REORGANIZATION", 1);
            } else {
                ::unsetenv("TRU_ENABLE_08B4D9_AUTOMATIC_REORG");
            }
#endif
        }

        // Initialize node and chain (previously these were declared here)
        node = std::make_unique<P2PNode>(cfgFile);
        chain = std::make_unique<Blockchain>(dbPath, std::string(tru_network::GENESIS_ADDRESS), *node, noSeeds);

        // install fail-stop plumbing before the node is exposed
        // to P2P. 9B may activate only freshly accepted strict-winning side tips.
        chain->setReorgFailStopShutdownCallback(
            [](const std::string& reason) {
                requestOrderlyShutdownFromBlockchain(reason);
            });
        Logger::log(
            std::string("[Patch08B.4D.9A] production automatic reorg gate=") +
            (chain->productionAutomaticReorgGateEnabled() ? "ARMED" : "OFF") +
            " activation=INCOMING_SIDE_ONLY");

        // reconcile a persisted strict-winning side tip before
        // node exposure, outbound seed/saved-peer connections, or P2P listener.
        std::string startupReorgReason;
        if (!chain->reconcileWinningSideTipAtStartup(startupReorgReason)) {
            Logger::log(
                "[Patch08B.4D.9C] FATAL startup reconciliation failed: " +
                startupReorgReason);
            throw std::runtime_error(
                "TRU_FATAL_9C_STARTUP_REORG_RECONCILIATION: " +
                startupReorgReason);
        }
        Logger::log(
            "[Patch08B.4D.9C] Startup reconciliation complete: " +
            startupReorgReason);

        node->setBlockchain(chain.get());

        if (!externalIp.empty()) {
            node->setExternalIp(externalIp);
        }

        // MULTINODE-01A: listen BEFORE outbound dials. Two nodes that start at
        // the same time must not both spend the entire startup window dialing a
        // socket that the other side has not opened yet.
        if (!noP2P && listenP2P) {
            try {
                Logger::log("[MULTINODE-01A] Starting P2P listener before outbound peers on port " +
                            std::to_string(p2pPort));
                node->startListening(p2pPort, chain.get());
            } catch (const std::runtime_error& e) {
                const std::string errorMsg = e.what();
                if (errorMsg.find("Address already in use") != std::string::npos) {
                    Logger::log(
                        "[main] ERROR: Failed to start P2P listener: Port " +
                        std::to_string(p2pPort) + " is already in use.");
                    std::cerr
                        << "Error: Port " << p2pPort
                        << " is already in use. Please ensure no other instance of "
                           "tru_advanced is running or free the port using:\n"
                        << "  sudo netstat -tulnp | grep " << p2pPort << "\n"
                        << "  sudo kill <pid>\n"
                        << std::endl;
                    Logger::shutdown();
                    return 1;
                }
                throw;
            }
        } else {
            Logger::log("[main] P2P listener disabled (--no-p2p or listen=0).");
        }

        Logger::log("[main] Total seed nodes: " + std::to_string(seedNodes.size()));
        for (const auto& seed : seedNodes) {
            Logger::log("[main] Seed: " + seed.first + ":" + std::to_string(seed.second));
        }

        if (!noSeeds && !seedNodes.empty()) {
            for (const auto& seed : seedNodes)
                node->rememberPeerForReconnect(seed.first, seed.second);
            bool connectedToSeed = false;
            for (int attempt = 1; attempt <= maxConnectionRetries && !connectedToSeed && g_running; ++attempt) {
                Logger::log("[main] Connection attempt " + std::to_string(attempt));
                for (const auto& seed : seedNodes) {
                    Logger::log("[main] Connecting to " + seed.first + ":" + std::to_string(seed.second));
                    auto future = std::async(std::launch::async, [&node, &seed]() {
                        return node->connectToPeer(seed.first, seed.second, 10);
                    });
                    if (future.wait_for(std::chrono::seconds(15)) == std::future_status::ready && future.get()) {
                        connectedToSeed = true;
                        Logger::log("[main] Connected to seed node: " + seed.first + ":" + std::to_string(seed.second));
                        break;
                    } else {
                        Logger::log("[main] Failed to connect to " + seed.first + ":" + std::to_string(seed.second));
                    }
                }
                if (!connectedToSeed && attempt < maxConnectionRetries) {
                    Logger::log("[main] Retrying after delay...");
                    std::this_thread::sleep_for(retryDelay);
                }
            }
            if (!connectedToSeed) {
                Logger::log("[main] WARNING: Failed to connect to any seed node after " + std::to_string(maxConnectionRetries) + " attempts");
            }
        }

        auto savedPeers = loadPeers(
            dbPath + "/peers.dat", p2pPort, externalIp);
        for (const auto& peer : savedPeers) {
            node->rememberPeerForReconnect(peer.first, peer.second);
            Logger::log("[main] Connecting to saved peer: " + peer.first + ":" + std::to_string(peer.second));
            node->connectToPeer(peer.first, peer.second, 10);
        }

        if (!peersArg.empty()) {
            std::stringstream ss(peersArg);
            std::string peer;
            while (std::getline(ss, peer, ',')) {
                size_t colonPos = peer.find(':');
                if (colonPos != std::string::npos) {
                    std::string ip = peer.substr(0, colonPos);
                    try {
                        int port = std::stoi(peer.substr(colonPos + 1));
                        node->rememberPeerForReconnect(ip, port);
                        Logger::log("[main] Connecting to CLI peer: " + ip + ":" + std::to_string(port));
                        node->connectToPeer(ip, port, 10);
                    } catch (const std::exception& e) {
                        Logger::log("[main] Invalid CLI peer: " + peer + " - " + e.what());
                    }
                }
            }
        }

std::string walletPath = "tru.dat";
        Wallet wallet(walletPath, chain.get());

        // SEC-14R.4 — authenticated core-wallet signing session.
        // Encrypted wallets start ENCRYPTED_LOCKED with public metadata only.
        // Authenticate locally before any worker/CLI path can reach signing.
        if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_LOCKED) {
#ifdef BUILD_WITH_QT
            if (qtApp) {
                bool accepted = false;
                QString entered = QInputDialog::getText(nullptr, "Unlock TRU wallet",
                    "Wallet passphrase (local authentication):", QLineEdit::Password, {}, &accepted);
                if (!accepted || entered.isEmpty()) throw std::runtime_error("Wallet unlock cancelled");
                std::string passphrase = entered.toStdString();
                entered.fill(QChar('\0')); entered.clear();
                std::string unlockError;
                const bool unlocked = wallet.unlockEncryptedWalletFromFiles(passphrase, &unlockError);
                std::fill(passphrase.begin(), passphrase.end(), '\0'); passphrase.clear();
                if (!unlocked || wallet.getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED)
                    throw std::runtime_error("Wallet unlock failed: " + unlockError);
            } else
#endif
            {
            if (!::isatty(STDIN_FILENO)) {
                throw std::runtime_error(
                    "[SEC-14R.4] encrypted wallet requires an interactive terminal for authenticated unlock");
            }

            struct termios oldTermios {};
            if (::tcgetattr(STDIN_FILENO, &oldTermios) != 0) {
                throw std::runtime_error(
                    "[SEC-14R.4] unable to read terminal settings for hidden wallet passphrase");
            }

            struct termios hiddenTermios = oldTermios;
            hiddenTermios.c_lflag &= static_cast<tcflag_t>(~ECHO);

            if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenTermios) != 0) {
                throw std::runtime_error(
                    "[SEC-14R.4] unable to disable terminal echo for wallet passphrase");
            }

            std::string walletPassphrase;
            std::string walletUnlockError;

            std::cout << "Wallet passphrase: " << std::flush;
            const bool inputOk =
                static_cast<bool>(std::getline(std::cin, walletPassphrase));

            const int restoreRc =
                ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTermios);
            std::cout << std::endl;

            if (restoreRc != 0) {
                std::fill(
                    walletPassphrase.begin(), walletPassphrase.end(), '\0');
                walletPassphrase.clear();
                throw std::runtime_error(
                    "[SEC-14R.4] unable to restore terminal echo after wallet passphrase entry");
            }

            if (!inputOk || walletPassphrase.empty()) {
                std::fill(
                    walletPassphrase.begin(), walletPassphrase.end(), '\0');
                walletPassphrase.clear();
                throw std::runtime_error(
                    "[SEC-14R.4] wallet unlock cancelled or empty passphrase");
            }

            const bool unlocked = wallet.unlockEncryptedWalletFromFiles(
                walletPassphrase, &walletUnlockError);

            std::fill(
                walletPassphrase.begin(), walletPassphrase.end(), '\0');
            walletPassphrase.clear();
            walletPassphrase.shrink_to_fit();

            if (!unlocked ||
                wallet.getWalletSecurityMode() !=
                    WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
                throw std::runtime_error(
                    "[SEC-14R.4] authenticated wallet unlock failed" +
                    (walletUnlockError.empty()
                        ? std::string()
                        : std::string(": ") + walletUnlockError));
            }

            Logger::log(
                "[SEC-14R.4] authenticated encrypted-wallet signing session active");
                    }
        }

        // TRU-SWAP-B — one-time deterministic role-key provisioning.
        // Enable only for the provisioning restart:
        //   export TRU_SWAP_PROVISION_ROLE_KEYS=1
        // This flag is non-secret. The wallet passphrase is entered locally
        // with terminal echo disabled and is never accepted via env/argv/RPC.
        const char* truSwapProvisionRaw =
            std::getenv("TRU_SWAP_PROVISION_ROLE_KEYS");
        if (truSwapProvisionRaw &&
            std::string(truSwapProvisionRaw) == "1") {
            if (wallet.getWalletSecurityMode() !=
                    WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
                throw std::runtime_error(
                    "[TRU-SWAP-B] role-key provisioning requires "
                    "ENCRYPTED_UNLOCKED wallet");
            }
            if (!::isatty(STDIN_FILENO)) {
                throw std::runtime_error(
                    "[TRU-SWAP-B] role-key provisioning requires an "
                    "interactive terminal");
            }

            struct termios swapOldTermios {};
            if (::tcgetattr(STDIN_FILENO, &swapOldTermios) != 0) {
                throw std::runtime_error(
                    "[TRU-SWAP-B] unable to read terminal settings");
            }
            struct termios swapHiddenTermios = swapOldTermios;
            swapHiddenTermios.c_lflag &=
                static_cast<tcflag_t>(~ECHO);
            if (::tcsetattr(
                    STDIN_FILENO, TCSAFLUSH, &swapHiddenTermios) != 0) {
                throw std::runtime_error(
                    "[TRU-SWAP-B] unable to disable terminal echo");
            }

            std::string swapProvisionPassphrase;
            std::cout
                << "TRU swap role-key provisioning passphrase: "
                << std::flush;
            const bool swapInputOk = static_cast<bool>(
                std::getline(std::cin, swapProvisionPassphrase));
            const int swapRestoreRc =
                ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &swapOldTermios);
            std::cout << std::endl;

            auto wipeSwapProvisionPassphrase = [&]() {
                std::fill(
                    swapProvisionPassphrase.begin(),
                    swapProvisionPassphrase.end(),
                    '\0');
                swapProvisionPassphrase.clear();
                swapProvisionPassphrase.shrink_to_fit();
            };

            if (swapRestoreRc != 0) {
                wipeSwapProvisionPassphrase();
                throw std::runtime_error(
                    "[TRU-SWAP-B] unable to restore terminal echo");
            }
            if (!swapInputOk || swapProvisionPassphrase.empty()) {
                wipeSwapProvisionPassphrase();
                throw std::runtime_error(
                    "[TRU-SWAP-B] role-key provisioning cancelled or empty passphrase");
            }

            TruSwapRoleKeysV1 swapRoles;
            std::string swapProvisionError;
            const bool swapProvisioned =
                wallet.provisionSwapRoleKeysV1(
                    swapProvisionPassphrase,
                    swapRoles,
                    &swapProvisionError);

            wipeSwapProvisionPassphrase();

            if (!swapProvisioned) {
                throw std::runtime_error(
                    "[TRU-SWAP-B] role-key provisioning failed" +
                    (swapProvisionError.empty()
                        ? std::string()
                        : std::string(": ") + swapProvisionError));
            }

            Logger::log(
                "[TRU-SWAP-B] deterministic encrypted swap role keys ready; "
                "private material was not printed");
            std::cout
                << "TRU-SWAP ROLE KEY PROVISIONING: PASS\n"
                << "TRU_CLAIM_ADDRESS=" << swapRoles.claimAddress << "\n"
                << "TRU_CLAIM_PUBKEY=" << swapRoles.claimPubkeyHex << "\n"
                << "TRU_REFUND_ADDRESS=" << swapRoles.refundAddress << "\n"
                << "TRU_REFUND_PUBKEY=" << swapRoles.refundPubkeyHex << "\n"
                << "PRIVATE_MATERIAL_PRINTED=NO\n";
        }

// SEC-14R.2: expression-level legacy wallet I/O is mode-guarded.
        if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::LEGACY_PLAINTEXT && !wallet.loadFromFile(walletPath)) {
            wallet.create_wallet(walletPath);
        }

        if (chain) {
            Logger::log("[main] Syncing wallet with blockchain...");
            wallet.updateLocalUTXOSetFromChain();

            // Log the balance to verify
            double balance = wallet.check_balance(false);
            Logger::log("[main] Wallet balance after sync: " + std::to_string(balance) + " TRU");
        }

        Logger::log("[main] Starting miner cleanup thread...");
        minerCleanupThread = startMinerCleanupThread(chain.get());
        Logger::log("[main] Miner cleanup thread started successfully");

        std::thread rpcThread([&]() {
            startRPCServer(*chain, wallet, *node, rpcPort, rpcBind, rpcMaxConnections, rpcAuthToken);
        });

        std::thread explorerThread;
        if (enableExplorer) {
            explorerThread = std::thread([&]() {
                chain->startExplorerServer(explorerPort, rpcPort);
            });
        }

        if (guiMode) {
            #ifdef BUILD_WITH_QT
            std::atomic<bool> syncRunning{true};
            std::thread syncThread([&chain, &node, &syncRunning]() {
                try {
                    chain->syncWithPeers(*node, syncRunning, nullptr);  // Pass nullptr for GUI mode
                } catch (const std::exception& e) {
                    Logger::log("[main] ERROR: Sync failed: " + std::string(e.what()));
                }
            });
            WalletGUI gui(wallet, nullptr, rpcPort, QByteArray::fromStdString(rpcAuthToken));
            QTimer guiSignalDispatch;
            QObject::connect(&guiSignalDispatch, &QTimer::timeout, &gui, [&gui]() {
                dispatchPendingSignalEvents();
                if (!g_running.load(std::memory_order_acquire)) gui.close();
            });
            guiSignalDispatch.start(250);
            gui.show();
            int guiResult = qtApp->exec();
            Logger::log("[main] GUI closed, initiating shutdown...");
            g_running = false;
            syncRunning = false;
            if (minerCleanupThread.joinable())
            {
                Logger::log("[main] Waiting for miner cleanup thread...");
                minerCleanupThread.join();
                Logger::log("[main] Miner cleanup thread joined");
            }
            // Patch 08B.4A.1a v2 / F1: stop and join external chain readers
            // before Blockchain::stop() takes the final exclusive chain lock.
            g_rpcServer.stop();
            if (enableExplorer) g_explorerServer.stop();
            node->stop();
            if (syncThread.joinable()) syncThread.join();
            if (rpcThread.joinable()) rpcThread.join();
            if (enableExplorer && explorerThread.joinable()) explorerThread.join();

            chain->stop();

            if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::LEGACY_PLAINTEXT) {
                wallet.saveToFile("tru.dat");
            } else {
                Logger::log("[SEC-14R.1] encrypted wallet persistence is authenticated; skipping legacy plaintext save");
            }
            Logger::log(
                "[main] GUI shutdown: Blockchain::stop() already performed "
                "the final blockchain save");
            savePeers(node->getKnownPeers(), dbPath + "/peers.dat", p2pPort, externalIp);
            Logger::log("[main] Shutdown completed.");
            Logger::shutdown();
            return guiResult;
            #else
            std::cerr << "GUI mode is unavailable; build with BUILD_WITH_QT=ON." << std::endl;
            Logger::shutdown();
            return 1;
            #endif
        } else if (cliMode) {
            std::atomic<bool> spinnerRunning(true);
            std::mutex coutMutex;
            std::thread spinnerThread;

            Logger::log("[main] Starting blockchain sync with peers...");
            std::atomic<bool> syncRunning{true};
            // background synchronization must never
            // paint over interactive CLI questions. syncWithPeers() treats a
            // null cout mutex as "log only / no terminal progress output".
            // Users can still request explicit sync status from the CLI.
            std::thread syncThread([&chain, &node, &syncRunning, &coutMutex]() {
                try {
                    updateCliSyncStatus(
                        "Starting blockchain synchronization...",
                        coutMutex);

                    chain->syncWithPeers(
                        *node,
                        syncRunning,
                        nullptr,
                        [&coutMutex](const std::string& status) {
                            updateCliSyncStatus(status, coutMutex);
                        });
                } catch (const std::exception& e) {
                    const std::string status =
                        "Synchronization error: " + std::string(e.what());
                    Logger::log(
                        "[main] ERROR: Background sync failed: " +
                        std::string(e.what()));
                    updateCliSyncStatus(status, coutMutex);
                }
            });

            spinnerThread = std::thread(runBlockchainSpinner, std::ref(spinnerRunning), std::ref(coutMutex));
            
            try {
                startCLI(*chain, *node, wallet, spinnerRunning, coutMutex);
            } catch (const CliShutdownInterrupt&) {
                Logger::log(
                    "[main] CLI input interrupted by shutdown signal; "
                    "entering graceful shutdown immediately");
            }

            Logger::log("[main] ========== SHUTDOWN SEQUENCE STARTED ==========");
            Logger::log("[main] CLI exited, initiating graceful shutdown...");
            // Step 0: Stop any active mining operations FIRST
            Logger::log("[main] >>> Phase 0: Stopping active mining operations...");

            // Stop any GPU mining that might be running by unregistering all miners
            try
            {
                if (chain)
                {
                    // Get list of active miners from the blockchain
                    auto activeMiners = chain->getActiveMiners();
                    if (!activeMiners.empty())
                    {
                        Logger::log("[main] Found " + std::to_string(activeMiners.size()) + " active miners, stopping...");

                        // Create a copy of the miner list since we'll be modifying the original
                        std::vector<std::string> minersCopy(activeMiners.begin(), activeMiners.end());

                        // Unregister all miners to stop mining
                        for (const auto &minerAddr : minersCopy)
                        {
                            try
                            {
                                chain->unregisterMiner(minerAddr);
                                Logger::log("[main] Unregistered miner: " + minerAddr);
                            }
                            catch (const std::exception &e)
                            {
                                Logger::log("[main] WARNING: Failed to unregister miner " + minerAddr + ": " + e.what());
                            }
                        }

                        // Give mining threads a moment to detect they've been unregistered
                        Logger::log("[main] Waiting for mining threads to detect shutdown...");
                        std::this_thread::sleep_for(std::chrono::seconds(1));

                        // Double-check that all miners are gone
                        activeMiners = chain->getActiveMiners();
                        if (!activeMiners.empty())
                        {
                            Logger::log("[main] WARNING: " + std::to_string(activeMiners.size()) + " miners still active after unregistration");

                            // Force unregister again
                            for (const auto &minerAddr : activeMiners)
                            {
                                try
                                {
                                    chain->unregisterMiner(minerAddr);
                                }
                                catch (...)
                                {
                                }
                            }
                        }
                    }
                    else
                    {
                        Logger::log("[main] No active miners found");
                    }

                    // Also clear the miner hash rates to prevent any lingering references
                    chain->minerHashRates.clear();
                    chain->minerLastActivity.clear();
                    chain->clearMinerBlockCounts();
                }
            }
            catch (const std::exception &e)
            {
                Logger::log("[main] WARNING: Error stopping miners: " + std::string(e.what()));
            }
            catch (...)
            {
                Logger::log("[main] WARNING: Unknown error stopping miners");
            }

            Logger::log("[main] Mining operations stopped");

            // Step 1: Set shutdown flags immediately and atomically
            g_running.store(false);
            syncRunning.store(false);
            g_shuttingDown.store(true);
            spinnerRunning.store(false);

            if (minerCleanupThread.joinable())
            {
                Logger::log("[main] Waiting for miner cleanup thread...");
                minerCleanupThread.join();
                Logger::log("[main] Miner cleanup thread joined");
            }

            Logger::log("[main] All shutdown flags set atomically");

            // Step 2: Stop all network services FIRST to prevent new incoming work
            Logger::log("[main] >>> Phase 1: Stopping network services...");
            
            std::atomic<int> servicesStoppedCount{0};
            const int totalServices = enableExplorer ? 3 : 2;
            
            // Stop P2P node first (most critical)
            auto stopP2P = std::async(std::launch::async, [&]() {
                try {
                    if (node) {
                        auto start = std::chrono::steady_clock::now();
                        node->stop();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start).count();
                        Logger::log("[main] P2P node stopped in " + std::to_string(duration) + "ms");
                    }
                    servicesStoppedCount.fetch_add(1);
                } catch (const std::exception& e) {
                    Logger::log("[main] ERROR stopping P2P node: " + std::string(e.what()));
                }
            });
            
            // Stop RPC server
            auto stopRPC = std::async(std::launch::async, [&]() {
                try {
                    auto start = std::chrono::steady_clock::now();
                    g_rpcServer.stop();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();
                    Logger::log("[main] RPC server stopped in " + std::to_string(duration) + "ms");
                    servicesStoppedCount.fetch_add(1);
                } catch (const std::exception& e) {
                    Logger::log("[main] ERROR stopping RPC server: " + std::string(e.what()));
                }
            });
            
            // Stop Explorer server if enabled
            std::future<void> stopExplorer;
            if (enableExplorer) {
                stopExplorer = std::async(std::launch::async, [&]() {
                    try {
                        auto start = std::chrono::steady_clock::now();
                        g_explorerServer.stop();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start).count();
                        Logger::log("[main] Explorer server stopped in " + std::to_string(duration) + "ms");
                        servicesStoppedCount.fetch_add(1);
                    } catch (const std::exception& e) {
                        Logger::log("[main] ERROR stopping Explorer server: " + std::string(e.what()));
                    }
                });
            }
            
            // Wait for all services to stop with timeout
            auto serviceStopStart = std::chrono::steady_clock::now();
            const auto serviceTimeout = std::chrono::seconds(10);
            
            while (servicesStoppedCount.load() < totalServices && 
                   (std::chrono::steady_clock::now() - serviceStopStart) < serviceTimeout) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            // Force completion of service stops
            if (stopP2P.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
                Logger::log("[main] WARNING: P2P stop timed out");
            }
            if (stopRPC.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
                Logger::log("[main] WARNING: RPC stop timed out");
            }
            if (enableExplorer && stopExplorer.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
                Logger::log("[main] WARNING: Explorer stop timed out");
            }
            
            shutdownAIOracle(); // hard lifetime barrier before LevelDB teardown
            
            Logger::log("[main] Network services shutdown phase completed");

            // Patch 08B.4A.1a v2 / F1: external RPC/explorer/sync readers
            // must be gone before Blockchain::stop() takes the final exclusive
            // chain lock for durable persistence.
            Logger::log("[main] >>> Phase 2: Deterministic external thread cleanup...");

            auto joinThreadDeterministically =
                [](std::thread& t, const std::string& name) -> bool {
                    if (!t.joinable()) {
                        Logger::log(
                            "[main] " + name +
                            " thread was not joinable");
                        return true;
                    }

                    try {
                        t.join();
                        Logger::log(
                            "[main] " + name +
                            " thread joined successfully");
                        return true;
                    } catch (const std::exception& e) {
                        Logger::log(
                            "[main] ERROR joining " + name +
                            " thread: " + std::string(e.what()));
                        return false;
                    }
                };

            int threadsJoined = 0;
            int totalThreads = 0;

            if (syncThread.joinable()) {
                totalThreads++;
                if (joinThreadDeterministically(syncThread, "sync")) threadsJoined++;
            }

            if (rpcThread.joinable()) {
                totalThreads++;
                if (joinThreadDeterministically(rpcThread, "rpc")) threadsJoined++;
            }

            if (enableExplorer && explorerThread.joinable()) {
                totalThreads++;
                if (joinThreadDeterministically(explorerThread, "explorer")) threadsJoined++;
            }

            if (spinnerThread.joinable()) {
                totalThreads++;
                if (joinThreadDeterministically(spinnerThread, "spinner")) threadsJoined++;
            }

            Logger::log(
                "[main] External thread cleanup completed: " +
                std::to_string(threadsJoined) + "/" +
                std::to_string(totalThreads) +
                " threads joined successfully");

            // Blockchain::stop() is now the internal-worker + durable-save
            // lifetime barrier, after all external chain readers have exited.
            Logger::log("[main] >>> Phase 3: Stopping blockchain processing...");
            if (chain) {
                try {
                    const auto start = std::chrono::steady_clock::now();
                    chain->stop();
                    const auto duration =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start).count();
                    Logger::log(
                        "[main] Blockchain stopped in " +
                        std::to_string(duration) + "ms");
                } catch (const std::exception& e) {
                    Logger::log(
                        "[main] ERROR stopping blockchain: " +
                        std::string(e.what()));
                }
            }

            Logger::log("[main] Blockchain processing shutdown phase completed");

            // synchronous shutdown saves with bounded retries.
            Logger::log("[main] >>> Phase 4: Saving application state...");
            
            auto saveWithRetry =
                [](std::function<void()> saveFunc,
                   const std::string& name,
                   int maxRetries = 2) -> bool {
                    for (int attempt = 1;
                         attempt <= maxRetries;
                         ++attempt) {
                        try {
                            saveFunc();
                            Logger::log(
                                "[main] " + name +
                                " saved successfully (attempt " +
                                std::to_string(attempt) + ")");
                            return true;
                        } catch (const std::exception& e) {
                            Logger::log(
                                "[main] ERROR saving " + name +
                                " (attempt " +
                                std::to_string(attempt) + "): " +
                                std::string(e.what()));
                        } catch (...) {
                            Logger::log(
                                "[main] ERROR saving " + name +
                                " (attempt " +
                                std::to_string(attempt) +
                                "): unknown exception");
                        }

                        if (attempt < maxRetries) {
                            Logger::log(
                                "[main] Retrying " + name +
                                " save...");
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(500));
                        }
                    }

                    Logger::log(
                        "[main] FAILED: " + name +
                        " could not be saved after " +
                        std::to_string(maxRetries) +
                        " attempts");
                    return false;
                };
            
            int saveSuccessCount = 0;
            int totalSaves = 0;
            
            // Save wallet
            totalSaves++;
            if (wallet.getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT || saveWithRetry([&]() { wallet.saveToFile("tru.dat"); }, "wallet", 3)) {
                saveSuccessCount++;
            }
            
            // Blockchain::stop() already performed the synchronous final
            // blockchain save. A second saveChainState() here would be a
            // misleading no-op because shutdownInitiated is already true.
            if (chain) {
                Logger::log(
                    "[main] Blockchain::stop() already performed the final "
                    "blockchain save; skipping redundant saveChainState()");
            }
            
            // Save peers
            if (node) {
                totalSaves++;
                if (saveWithRetry([&]() {
                    auto knownPeers = node->getKnownPeers();
                    savePeers(knownPeers, dbPath + "/peers.dat", p2pPort, externalIp);
                }, "peers", 2)) {
                    saveSuccessCount++;
                }
            }

            Logger::log("[main] State saving completed: " + std::to_string(saveSuccessCount) + 
                       "/" + std::to_string(totalSaves) + " saves successful");

            // Step 6: Final status and statistics
            Logger::log("[main] >>> Phase 5: Final status summary...");
            Logger::log("[main] ==========================================");
            Logger::log("[main] SHUTDOWN SUMMARY:");
            
            if (chain) {
                try {
                    Logger::log("[main] Final blockchain height: " + std::to_string(chain->getBestTipHeight()));
                    Logger::log("[main] Final best tip hash: " + chain->getBestTipHash());
                    Logger::log("[main] Total blocks in chain: " + std::to_string(chain->getChainSize()));
                } catch (const std::exception& e) {
                    Logger::log("[main] WARNING: Could not retrieve final blockchain stats: " + std::string(e.what()));
                }
            }
            
            auto totalShutdownTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - serviceStopStart).count();
            Logger::log("[main] Total shutdown time: " + std::to_string(totalShutdownTime) + " seconds");
            Logger::log("[main] Services stopped: " + std::to_string(servicesStoppedCount.load()) + "/" + std::to_string(totalServices));
            Logger::log("[main] Threads joined: " + std::to_string(threadsJoined) + "/" + std::to_string(totalThreads));
            Logger::log("[main] Data saves: " + std::to_string(saveSuccessCount) + "/" + std::to_string(totalSaves));
            Logger::log("[main] ==========================================");

            // Step 7: Smart pointer cleanup with timeout protection
            Logger::log("[main] >>> Phase 6: Resource cleanup...");
            
            auto cleanupWithTimeout = [](std::function<void()> cleanupFunc, const std::string& name, int timeoutSec = 5) {
                std::atomic<bool> completed{false};
                auto cleanupThread = std::async(std::launch::async, [&]() {
                    try {
                        cleanupFunc();
                        completed.store(true);
                    } catch (const std::exception& e) {
                        Logger::log("[main] ERROR during " + name + " cleanup: " + std::string(e.what()));
                        completed.store(true); // Mark as complete even with error
                    }
                });
                
                auto start = std::chrono::steady_clock::now();
                while (!completed.load() && 
                       (std::chrono::steady_clock::now() - start) < std::chrono::seconds(timeoutSec)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                
                if (completed.load()) {
                    Logger::log("[main] " + name + " cleanup completed");
                } else {
                    Logger::log("[main] WARNING: " + name + " cleanup timed out");
                }
            };
            
            // Reset smart pointers in reverse dependency order with timeout protection
            cleanupWithTimeout([&]() { chain.reset(); }, "blockchain", 8);
            cleanupWithTimeout([&]() { node.reset(); }, "P2P node", 5);
            
            Logger::log("[main] Resource cleanup phase completed");

            // Step 8: Final logger shutdown
            Logger::log("[main] >>> Phase 7: Final cleanup...");
            Logger::log("[main] ========== SHUTDOWN COMPLETED SUCCESSFULLY ==========");
// Small delay to ensure log is written
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

// Add raw console output to see where we're hanging
            std::cerr << "[DEBUG] About to call Logger::shutdown()..." << std::endl;
            Logger::shutdown();
            std::cerr << "[DEBUG] Logger::shutdown() completed" << std::endl;
            std::cerr << "[DEBUG] About to return from main()" << std::endl;

            return 0;
        } else {
            std::cerr << "No mode selected. Use --cli or --gui." << std::endl;
            Logger::log("[main] ERROR: No mode selected.");
            Logger::shutdown();
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        Logger::log("[main] FATAL: Unhandled std::exception: " + std::string(e.what()));
        
        // Enhanced emergency shutdown with aggressive timeouts
        Logger::log("[main] ========== EMERGENCY SHUTDOWN INITIATED ==========");
        
        try {
            // Set emergency flags
            g_running.store(false);
            g_shuttingDown.store(true);
            
            if (minerCleanupThread.joinable())
            {
                try
                {
                    Logger::log("[main] Emergency: waiting for miner cleanup thread...");
                    minerCleanupThread.join();
                    Logger::log("[main] Emergency: miner cleanup thread joined");
                }
                catch (...)
                {
                    Logger::log("[main] WARNING: Failed to join miner cleanup thread during emergency shutdown");
                }
            }
            auto emergencyStopWithTimeout = [](std::function<void()> stopFunc, const std::string& name, int timeoutMs = 1000) {
                std::atomic<bool> stopCompleted{false};
                auto stopFuture = std::async(std::launch::async, [&]() {
                    try {
                        stopFunc();
                        stopCompleted.store(true);
                    } catch (...) {
                        stopCompleted.store(true); // Mark complete even with error
                    }
                });
                
                auto start = std::chrono::steady_clock::now();
                while (!stopCompleted.load() && 
                       (std::chrono::steady_clock::now() - start) < std::chrono::milliseconds(timeoutMs)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                
                if (stopCompleted.load()) {
                    Logger::log("[main] Emergency stop of " + name + " completed");
                } else {
                    Logger::log("[main] WARNING: Emergency stop of " + name + " timed out");
                }
            };
            
            // Emergency stops with very short timeouts
            emergencyStopWithTimeout([&]() { g_rpcServer.stop(); }, "RPC server", 1500);
            shutdownAIOracle();
            emergencyStopWithTimeout([&]() { g_explorerServer.stop(); }, "Explorer server", 1500);
            
            if (chain) {
                emergencyStopWithTimeout([&]() { chain->stop(); }, "blockchain", 3000);
            }
            
            if (node) {
                emergencyStopWithTimeout([&]() { node->stop(); }, "P2P node", 2000);
            }
            
            // Force cleanup smart pointers
            emergencyStopWithTimeout([&]() { chain.reset(); }, "blockchain cleanup", 2000);
            emergencyStopWithTimeout([&]() { node.reset(); }, "node cleanup", 1000);
            
            Logger::log("[main] Emergency shutdown sequence completed");
            
        } catch (...) {
            std::cerr << "CRITICAL: Emergency shutdown failed" << std::endl;
        }
        
        Logger::shutdown();
        return 1;
        
    } catch (...) {
        std::cerr << "FATAL ERROR: Unknown exception" << std::endl;
        Logger::log("[main] FATAL: Unhandled unknown exception");
        
        // Ultra-minimal emergency cleanup
        try {
            Logger::log("[main] ========== CRITICAL EMERGENCY SHUTDOWN ==========");
            
            // Force stop everything with minimal timeout
            g_running.store(false);
            g_shuttingDown.store(true);
            
            if (minerCleanupThread.joinable())
            {
                try
                {
                    Logger::log("[main] Critical: waiting for miner cleanup thread...");
                    minerCleanupThread.join();
                    Logger::log("[main] Critical: miner cleanup thread joined");
                }
                catch (...)
                {
                    Logger::log("[main] WARNING: Failed to join miner cleanup thread during critical shutdown");
                }
            }
            auto criticalTimeout = std::chrono::milliseconds(500);
            auto start = std::chrono::steady_clock::now();
            
            // Try to stop critical services
            try { g_rpcServer.stop(); shutdownAIOracle(); } catch (...) {}
            try { g_explorerServer.stop(); } catch (...) {}
            
            // Force reset smart pointers if we have time
            if ((std::chrono::steady_clock::now() - start) < criticalTimeout) {
                try { if (chain) chain.reset(); } catch (...) {}
                try { if (node) node.reset(); } catch (...) {}
            }
            
            Logger::log("[main] Critical emergency shutdown completed");
            
        } catch (...) {
            std::cerr << "CRITICAL: All shutdown attempts failed" << std::endl;
        }
        
        try {
            Logger::shutdown();
        } catch (...) {
            // Last resort - just exit
        }
        
        return 2;
    }
}
