// sybil_protection.h

#ifndef SYBIL_PROTECTION_H
#define SYBIL_PROTECTION_H

#include <string>
#include <unordered_set>
#include <mutex>

class SybilProtection {
public:
    SybilProtection();

    // Check if IP is blacklisted
    bool isBlacklisted(const std::string &ip) const;

    // Add IP to blacklist
    void blacklistIP(const std::string &ip);

    // Remove IP from blacklist
    void removeFromBlacklist(const std::string &ip);

private:
    mutable std::mutex mtx;
    std::unordered_set<std::string> blacklist;
};

#endif // SYBIL_PROTECTION_H
