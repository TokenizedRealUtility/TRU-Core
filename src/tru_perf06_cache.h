#pragma once
#include <mutex>
#include <string>
#include <unordered_map>

// Process-local optimization only. Eviction changes performance, never validity.
// Fixed entry and key/value byte limits bound retained memory under hostile input.
class TruCachePerf06 {
    std::mutex mutex_;
    std::unordered_map<std::string, std::string> entries_;
public:
    bool get(const std::string& key, std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        value = it->second;
        return true;
    }
    void put(const std::string& key, const std::string& value) {
        if (key.size() > 256 || value.size() > 32) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (entries_.find(key) != entries_.end()) return;
        if (entries_.size() >= 32768) entries_.erase(entries_.begin());
        entries_.emplace(key, value);
    }
};
