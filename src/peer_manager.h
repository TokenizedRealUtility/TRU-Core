// peer_manager.h

#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include "tru_limits.h"
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class PeerConnection;

struct PeerInfo {
    std::string ip;
    int port;
    bool isConnected;
    time_t lastActive;
};

class PeerManager {
public:
    PeerManager();
    ~PeerManager();

    // Known-peer address book.
    void addPeer(const std::string& ip, int port);
    void removePeer(const std::string& ip, int port);
    std::vector<PeerInfo> getPeers() const;
    void updatePeerActivity(const std::string& ip, int port);

    // connection admission/abuse controls.
    // Acquire before PeerConnection/thread creation and release exactly once.
    bool tryAcquireConnectionSlot(
        const std::string& ip,
        bool inbound,
        std::string& rejectionReason);
    void releaseConnectionSlot(const std::string& ip);

    // Snapshot policy queries retained for existing callers.
    bool canConnect(const std::string& ip) const;
    bool isBanned(const std::string& ip) const;

    // Add IP-scoped abuse score. Returns true if banned afterward.
    bool recordViolation(
        const std::string& ip,
        std::uint32_t points,
        const std::string& reason);

private:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct AbuseState {
        std::uint32_t score{0};
        TimePoint lastScoreEvent{};
        TimePoint bannedUntil{};
        TimePoint lastTouched{};
        std::deque<TimePoint> inboundAttempts;
    };

    AbuseState& ensureAbuseStateLocked(
        const std::string& ip,
        TimePoint now);
    void pruneStateLocked(TimePoint now);
    void expireStateLocked(AbuseState& state, TimePoint now);

    mutable std::mutex mtx;
    std::vector<PeerInfo> peers;
    std::unordered_map<std::string, std::size_t> activeConnections_;
    std::size_t totalActiveConnections_{0};
    std::unordered_map<std::string, AbuseState> abuse_;
};

#endif // PEER_MANAGER_H
