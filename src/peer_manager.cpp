#include "peer_manager.h"
#include "logging.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <stdexcept>

PeerManager::PeerManager() {}
PeerManager::~PeerManager() {}

void PeerManager::addPeer(const std::string& ip, int port) {
    // PEER-ENDPOINT-02: only syntactically valid endpoint ports enter the book.
    // Do not guess whether a port is "ephemeral" from its numeric range; NATs
    // may rewrite source ports from arbitrary ranges.
    if (ip.empty() || port <= 0 || port > 65535) {
        Logger::log(
            "[PEER-ENDPOINT-02] Rejecting invalid peer endpoint " +
            ip + ":" + std::to_string(port));
        return;
    }

    std::lock_guard<std::mutex> lock(mtx);

    // PEER-REDIAL-01: a valid VERSION handshake is the authority that clears
    // reconnect backoff. A mere TCP connect never reaches addPeer().
    auto& reconnectState = reconnect_[ip];
    reconnectState.consecutiveFailures = 0;
    reconnectState.nextAttempt = TimePoint{};

    // The rest of this PeerManager is deliberately IP-keyed: connection slots,
    // connected state, abuse state, and peers.dat persistence all operate per
    // observed IP. Keep the book consistent with that model by retaining one
    // reconnect/gossip endpoint per IP. A newly VERIFIED endpoint replaces the
    // old endpoint for that same IP; it does not create source-port clutter.
    auto it = std::find_if(peers.begin(), peers.end(), [&](const PeerInfo& p) {
        return p.ip == ip;
    });

    if (it == peers.end()) {
        peers.push_back(PeerInfo{
            ip,
            port,
            activeConnections_.find(ip) != activeConnections_.end(),
            time(nullptr)});
        Logger::log(
            "[PeerManager] Added verified peer endpoint: " +
            ip + ":" + std::to_string(port));
    } else {
        if (it->port != port) {
            Logger::log(
                "[PEER-ENDPOINT-02] Replacing peer endpoint for " + ip +
                " from :" + std::to_string(it->port) +
                " to :" + std::to_string(port));
            it->port = port;
        }
        it->isConnected =
            activeConnections_.find(ip) != activeConnections_.end();
        it->lastActive = time(nullptr);
    }
}

void PeerManager::removePeer(const std::string& ip, int port) {
    std::lock_guard<std::mutex> lock(mtx);
    peers.erase(
        std::remove_if(
            peers.begin(), peers.end(),
            [&](const PeerInfo& p) {
                return p.ip == ip && p.port == port;
            }),
        peers.end());

    const bool stillKnown = std::any_of(
        peers.begin(), peers.end(), [&](const PeerInfo& p) {
            return p.ip == ip;
        });
    if (!stillKnown) {
        reconnect_.erase(ip);
    }
}

std::vector<PeerInfo> PeerManager::getPeers() const {
    std::lock_guard<std::mutex> lock(mtx);
    return peers;
}

void PeerManager::updatePeerActivity(const std::string& ip, int port) {
    std::lock_guard<std::mutex> lock(mtx);
    for (auto& p : peers) {
        if (p.ip == ip && p.port == port) {
            p.lastActive = time(nullptr);
            break;
        }
    }
}

void PeerManager::expireStateLocked(AbuseState& state, TimePoint now) {
    while (!state.inboundAttempts.empty() &&
           now - state.inboundAttempts.front() >= std::chrono::minutes(1)) {
        state.inboundAttempts.pop_front();
    }

    if (state.bannedUntil != TimePoint{} && now >= state.bannedUntil) {
        state.bannedUntil = TimePoint{};
    }

    if (state.score != 0 &&
        state.lastScoreEvent != TimePoint{} &&
        now - state.lastScoreEvent >=
            std::chrono::seconds(tru_limits::P2P_SCORE_DECAY_SECONDS)) {
        state.score = 0;
        state.lastScoreEvent = TimePoint{};
    }
}

void PeerManager::pruneStateLocked(TimePoint now) {
    for (auto it = abuse_.begin(); it != abuse_.end();) {
        expireStateLocked(it->second, now);

        const bool active =
            activeConnections_.find(it->first) != activeConnections_.end();
        const bool banned =
            it->second.bannedUntil != TimePoint{} &&
            now < it->second.bannedUntil;
        const bool empty =
            it->second.score == 0 &&
            it->second.inboundAttempts.empty();

        if (!active && !banned && empty) {
            it = abuse_.erase(it);
        } else {
            ++it;
        }
    }

    while (abuse_.size() >= tru_limits::MAX_P2P_ABUSE_TABLE_ENTRIES) {
        auto victim = abuse_.end();

        // Prefer the oldest inactive, non-banned bookkeeping entry.
        for (auto it = abuse_.begin(); it != abuse_.end(); ++it) {
            const bool active =
                activeConnections_.find(it->first) != activeConnections_.end();
            const bool banned =
                it->second.bannedUntil != TimePoint{} &&
                now < it->second.bannedUntil;
            if (active || banned) {
                continue;
            }
            if (victim == abuse_.end() ||
                it->second.lastTouched < victim->second.lastTouched) {
                victim = it;
            }
        }

        // If every inactive entry is banned, evict the oldest inactive entry.
        // This preserves the hard memory ceiling under a very large botnet.
        if (victim == abuse_.end()) {
            for (auto it = abuse_.begin(); it != abuse_.end(); ++it) {
                const bool active =
                    activeConnections_.find(it->first) != activeConnections_.end();
                if (active) {
                    continue;
                }
                if (victim == abuse_.end() ||
                    it->second.lastTouched < victim->second.lastTouched) {
                    victim = it;
                }
            }
        }

        if (victim == abuse_.end()) {
            break; // every tracked entry currently has a live connection
        }
        abuse_.erase(victim);
    }
}

PeerManager::AbuseState& PeerManager::ensureAbuseStateLocked(
    const std::string& ip,
    TimePoint now) {

    auto it = abuse_.find(ip);
    if (it != abuse_.end()) {
        expireStateLocked(it->second, now);
        it->second.lastTouched = now;
        return it->second;
    }

    pruneStateLocked(now);
    if (abuse_.size() >= tru_limits::MAX_P2P_ABUSE_TABLE_ENTRIES) {
        throw std::runtime_error(
            "peer abuse table saturated with active entries");
    }

    AbuseState state;
    state.lastTouched = now;
    return abuse_.emplace(ip, std::move(state)).first->second;
}

bool PeerManager::tryAcquireConnectionSlot(
    const std::string& ip,
    bool inbound,
    std::string& rejectionReason) {

    std::lock_guard<std::mutex> lock(mtx);
    const TimePoint now = Clock::now();

    AbuseState* state = nullptr;
    try {
        state = &ensureAbuseStateLocked(ip, now);
    } catch (const std::exception&) {
        rejectionReason = "peer abuse table saturated";
        return false;
    }

    if (state->bannedUntil != TimePoint{} && now < state->bannedUntil) {
        const auto secondsLeft =
            std::chrono::duration_cast<std::chrono::seconds>(
                state->bannedUntil - now).count();
        rejectionReason =
            "temporarily banned for " + std::to_string(secondsLeft) + "s";
        return false;
    }

    if (inbound) {
        while (!state->inboundAttempts.empty() &&
               now - state->inboundAttempts.front() >=
                   std::chrono::minutes(1)) {
            state->inboundAttempts.pop_front();
        }

        if (state->inboundAttempts.size() >=
            tru_limits::MAX_P2P_INBOUND_CONNECTION_ATTEMPTS_PER_MINUTE) {
            rejectionReason = "inbound connection-attempt rate exceeded";
            return false;
        }

        state->inboundAttempts.push_back(now);
    }

    if (totalActiveConnections_ >= tru_limits::MAX_P2P_TOTAL_CONNECTIONS) {
        rejectionReason = "global active connection limit reached";
        return false;
    }

    const auto activeIt = activeConnections_.find(ip);
    const std::size_t active =
        activeIt == activeConnections_.end() ? 0 : activeIt->second;
    if (active >= tru_limits::MAX_P2P_CONNECTIONS_PER_IP) {
        rejectionReason = "per-IP active connection limit reached";
        return false;
    }

    activeConnections_[ip] = active + 1;
    ++totalActiveConnections_;
    state->lastTouched = now;
    rejectionReason.clear();

    for (auto& peer : peers) {
        if (peer.ip == ip) {
            peer.isConnected = true;
            peer.lastActive = time(nullptr);
        }
    }

    return true;
}

std::uint32_t PeerManager::scheduleReconnectFailureLocked(
    const std::string& ip,
    TimePoint now,
    std::uint32_t& jitterMillisOut) {

    auto& state = reconnect_[ip];
    if (state.consecutiveFailures < 1000) {
        ++state.consecutiveFailures;
    }

    const std::uint32_t failures = state.consecutiveFailures;
    std::uint32_t baseSeconds = 60;
    if (failures <= 1) baseSeconds = 5;
    else if (failures == 2) baseSeconds = 10;
    else if (failures == 3) baseSeconds = 20;
    else if (failures == 4) baseSeconds = 40;

    // Deterministic per-peer jitter avoids synchronized reconnect bursts
    // without introducing shared RNG state into networking threads.
    const std::size_t seed =
        std::hash<std::string>{}(ip + ":" + std::to_string(failures));
    jitterMillisOut = static_cast<std::uint32_t>(seed % 2000U);
    state.nextAttempt =
        now + std::chrono::seconds(baseSeconds) +
        std::chrono::milliseconds(jitterMillisOut);
    return baseSeconds;
}

void PeerManager::releaseConnectionSlot(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mtx);

    auto it = activeConnections_.find(ip);
    if (it == activeConnections_.end()) {
        return;
    }

    if (it->second <= 1) {
        activeConnections_.erase(it);
    } else {
        --it->second;
    }
    if (totalActiveConnections_ > 0) {
        --totalActiveConnections_;
    }

    const bool connected =
        activeConnections_.find(ip) != activeConnections_.end();
    bool knownPeer = false;
    for (auto& peer : peers) {
        if (peer.ip == ip) {
            knownPeer = true;
            peer.isConnected = connected;
            peer.lastActive = time(nullptr);
        }
    }

    if (!connected && knownPeer) {
        // A previously VERIFIED session disappeared. Treat that as the first
        // reconnect failure. Because addPeer() resets this counter after every
        // successful VERSION handshake, normal long-lived sessions always begin
        // recovery at ~5s, while repeated failures back off to a 60s ceiling.
        std::uint32_t jitterMillis = 0;
        const std::uint32_t baseSeconds =
            scheduleReconnectFailureLocked(ip, Clock::now(), jitterMillis);
        Logger::log(
            "[PEER-REDIAL-01] Verified peer disconnected " + ip +
            "; retryInMs=" +
            std::to_string(baseSeconds * 1000U + jitterMillis));
    }

    pruneStateLocked(Clock::now());
}

std::vector<PeerInfo> PeerManager::claimReconnectCandidates(
    std::size_t maxCandidates) {

    std::lock_guard<std::mutex> lock(mtx);
    std::vector<PeerInfo> result;
    if (maxCandidates == 0) {
        return result;
    }

    const TimePoint now = Clock::now();
    result.reserve(std::min(maxCandidates, peers.size()));

    for (const auto& peer : peers) {
        if (result.size() >= maxCandidates) {
            break;
        }
        if (peer.ip.empty() || peer.port <= 0 || peer.port > 65535) {
            continue;
        }
        if (activeConnections_.find(peer.ip) != activeConnections_.end()) {
            continue;
        }

        const auto abuseIt = abuse_.find(peer.ip);
        if (abuseIt != abuse_.end() &&
            abuseIt->second.bannedUntil != TimePoint{} &&
            now < abuseIt->second.bannedUntil) {
            continue;
        }

        auto& state = reconnect_[peer.ip];
        if (state.nextAttempt != TimePoint{} && now < state.nextAttempt) {
            continue;
        }

        // Attempt lease: longer than the 5s redial connect timeout. If TCP
        // succeeds but VERSION never validates, releaseConnectionSlot() will
        // schedule the next exponentially-backed-off attempt.
        state.nextAttempt = now + std::chrono::seconds(8);
        result.push_back(peer);
    }

    return result;
}

void PeerManager::noteReconnectFailure(const std::string& ip) {
    std::uint32_t failures = 0;
    std::uint32_t baseSeconds = 0;
    std::uint32_t jitterMillis = 0;

    {
        std::lock_guard<std::mutex> lock(mtx);
        const bool knownPeer = std::any_of(
            peers.begin(), peers.end(), [&](const PeerInfo& peer) {
                return peer.ip == ip;
            });
        if (!knownPeer) {
            return;
        }

        baseSeconds =
            scheduleReconnectFailureLocked(ip, Clock::now(), jitterMillis);
        failures = reconnect_[ip].consecutiveFailures;
    }

    Logger::log(
        "[PEER-REDIAL-01] Redial failed for " + ip +
        "; failures=" + std::to_string(failures) +
        "; retryInMs=" +
        std::to_string(baseSeconds * 1000U + jitterMillis));
}

bool PeerManager::canConnect(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mtx);
    const TimePoint now = Clock::now();

    const auto abuseIt = abuse_.find(ip);
    if (abuseIt != abuse_.end() &&
        abuseIt->second.bannedUntil != TimePoint{} &&
        now < abuseIt->second.bannedUntil) {
        return false;
    }

    if (totalActiveConnections_ >= tru_limits::MAX_P2P_TOTAL_CONNECTIONS) {
        return false;
    }

    const auto activeIt = activeConnections_.find(ip);
    const std::size_t active =
        activeIt == activeConnections_.end() ? 0 : activeIt->second;
    return active < tru_limits::MAX_P2P_CONNECTIONS_PER_IP;
}

bool PeerManager::isBanned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mtx);
    const auto it = abuse_.find(ip);
    return
        it != abuse_.end() &&
        it->second.bannedUntil != TimePoint{} &&
        Clock::now() < it->second.bannedUntil;
}

bool PeerManager::recordViolation(
    const std::string& ip,
    std::uint32_t points,
    const std::string& reason) {

    std::lock_guard<std::mutex> lock(mtx);
    const TimePoint now = Clock::now();

    AbuseState* state = nullptr;
    try {
        state = &ensureAbuseStateLocked(ip, now);
    } catch (const std::exception&) {
        Logger::log(
            "[PeerManager] Abuse table saturated while scoring " + ip);
        return true;
    }

    const std::uint64_t widened =
        static_cast<std::uint64_t>(state->score) + points;
    state->score = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(
            widened,
            std::numeric_limits<std::uint32_t>::max()));
    state->lastScoreEvent = now;
    state->lastTouched = now;

    bool banned = false;
    if (state->score >= tru_limits::P2P_BAN_SCORE_THRESHOLD) {
        state->bannedUntil =
            now + std::chrono::seconds(tru_limits::P2P_BAN_SECONDS);
        state->score = tru_limits::P2P_BAN_SCORE_THRESHOLD;
        state->inboundAttempts.clear();
        banned = true;
    }

    Logger::log(
        "[PeerManager] Peer violation ip=" + ip +
        " points=" + std::to_string(points) +
        " score=" + std::to_string(state->score) +
        " reason=" + reason +
        (banned ? " => TEMPORARILY BANNED" : ""));

    return banned;
}
