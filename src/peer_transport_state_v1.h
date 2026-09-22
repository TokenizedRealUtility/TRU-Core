#pragma once

// PEER-COMMS-01: local transport observations only; never consensus input.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace tru_peer_transport {
inline std::int64_t monoMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline std::int64_t unixSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
inline std::uint64_t nextSessionId() {
    static std::atomic<std::uint64_t> next{1};
    return next.fetch_add(1);
}
struct Observations {
    const std::uint64_t sessionId = nextSessionId();
    std::atomic<std::int64_t> receivedMono{monoMillis()};
    std::atomic<std::int64_t> receivedUnix{0};
    std::atomic<std::uint64_t> height{0};
    std::atomic<std::uint64_t> heightRevision{0};
    std::atomic<std::int64_t> heightUnix{0};
    std::atomic<std::int64_t> heightMono{0};
    std::atomic<unsigned> syncFailures{0};
    std::atomic<std::int64_t> syncRetryAt{0};

    void received(std::int64_t mono = monoMillis(), std::int64_t wall = unixSeconds()) {
        receivedMono.store(mono);
        receivedUnix.store(wall);
    }
    bool alive(std::int64_t now = monoMillis()) const {
        return now - receivedMono.load() < 90000;
    }
    void reportedHeight(std::uint64_t value) {
        height.store(value);
        heightUnix.store(unixSeconds());
        heightMono.store(monoMillis());
        heightRevision.fetch_add(1, std::memory_order_release);
    }
    bool freshHeight(std::int64_t now = monoMillis()) const {
        return heightRevision.load(std::memory_order_acquire) != 0 &&
               now - heightMono.load() < 30000;
    }
    void syncFailed(std::int64_t now = monoMillis()) {
        const unsigned n = std::min(syncFailures.load(), 5u);
        syncFailures.store(n + 1);
        syncRetryAt.store(now + std::min<std::int64_t>(30000, 5000LL << n));
    }
    void syncSucceeded() { syncFailures.store(0); syncRetryAt.store(0); }
    bool syncAllowed(std::int64_t now = monoMillis()) const { return now >= syncRetryAt.load(); }
};
} // namespace tru_peer_transport
