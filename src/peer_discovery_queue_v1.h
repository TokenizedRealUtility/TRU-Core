#pragma once

// PEER-COMMS-01 R2: readers enqueue discovery; maintenance performs socket I/O.
// No detached threads, unbounded work, or peer-book promotion from ADDR gossip.
#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace tru_peer_discovery {
class Queue {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    struct Endpoint { std::string ip; int port = 0; };
    static constexpr unsigned maxPerMessage = 2;
    static constexpr unsigned dialTimeoutSeconds = 1;
    static constexpr std::size_t maxPending = 32;
    static constexpr std::size_t maxPerMinute = 6;
    static constexpr std::size_t maxCooldownKeys = 512;

    bool enqueue(const std::string& ip, int port, TimePoint now = Clock::now()) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || pending_.size() >= maxPending) return false;
        pruneCooldown(now);
        const auto key = endpointKey({ip, port});
        if (pending_.count(key) || cooldown_.count(key)) return false;
        queue_.push_back({ip, port});
        pending_.insert(key);
        return true;
    }

    // Count attempts when dispatched, not when queued or successfully connected.
    // Keep the endpoint pending until complete(), including while a dial stalls.
    bool take(Endpoint& endpoint, TimePoint now = Clock::now()) {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!attempts_.empty() && now - attempts_.front() >= std::chrono::minutes(1))
            attempts_.pop_front();
        if (closed_ || queue_.empty() || attempts_.size() >= maxPerMinute) return false;
        endpoint = queue_.front();
        queue_.pop_front();
        attempts_.push_back(now);
        return true;
    }

    void complete(const Endpoint& endpoint, bool connected, TimePoint now = Clock::now()) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key = endpointKey(endpoint);
        pending_.erase(key);
        if (closed_) return;
        pruneCooldown(now);
        if (connected) cooldown_.erase(key);
        else if (cooldown_.size() < maxCooldownKeys)
            cooldown_[key] = now + std::chrono::seconds(900);
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        queue_.clear(); pending_.clear(); attempts_.clear(); cooldown_.clear();
    }

private:
    static std::string endpointKey(const Endpoint& endpoint) {
        return endpoint.ip + ":" + std::to_string(endpoint.port);
    }
    void pruneCooldown(TimePoint now) {
        for (auto it = cooldown_.begin(); it != cooldown_.end(); ) {
            if (now >= it->second) it = cooldown_.erase(it);
            else ++it;
        }
    }
    std::mutex mutex_;
    bool closed_ = false;
    std::deque<Endpoint> queue_;
    std::unordered_set<std::string> pending_;
    std::deque<TimePoint> attempts_;
    std::unordered_map<std::string, TimePoint> cooldown_;
};
} // namespace tru_peer_discovery
