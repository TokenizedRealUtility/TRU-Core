#pragma once
// MARKET-02B-CORE-01: Strict domain-separated local CLI login challenge parser.
// This module does not expose any RPC, network handler or signing key.
#include <cstdint>
#include <ctime>
#include <regex>
#include <string>

namespace tru_market_login_v1 {
struct Challenge {
    std::string exact;
    std::string address;
    std::string nonce;
    std::int64_t expires = 0;
};

inline bool parse(const std::string& text, Challenge& out, std::string& reason,
                  const std::int64_t nowSeconds = static_cast<std::int64_t>(std::time(nullptr))) {
    reason.clear();
    if (text.size() > 512) { reason = "challenge exceeds 512 bytes"; return false; }
    // Exactly six LF-terminated lines. No CR, whitespace changes or other domains.
    static const std::regex pattern(
        R"(^TRU-MARKET-AUTH-V1\nnetwork:tru-mainnet\ndomain:market\.tokenizedrealutility\.com\naddress:(T[1-9A-HJ-NP-Za-km-z]{33})\nnonce:([0-9a-f]{48})\nexpires:([0-9]{10})\n$)",
        std::regex::ECMAScript);
    std::smatch parts;
    if (!std::regex_match(text, parts, pattern)) {
        reason = "not an exact TRU Marketplace mainnet login challenge";
        return false;
    }
    std::int64_t expiry = 0;
    try { expiry = std::stoll(parts[3].str()); }
    catch (...) { reason = "invalid challenge expiration"; return false; }
    if (expiry <= nowSeconds || expiry > nowSeconds + 600) {
        reason = "challenge expired or future expiration exceeds 10 minutes";
        return false;
    }
    out = {text, parts[1].str(), parts[2].str(), expiry};
    return true;
}
// One-line transport for the same V1 login message. Domain and network are
// fixed by this signer and are included in the reconstructed signed payload.
// Compact syntax: TRUM1:<owned-address>:<48-lowercase-hex-nonce>:<10-digit-epoch>
// This is not a new signature format, RPC endpoint, transaction or authority.
inline bool parseCompact(const std::string& code, Challenge& out, std::string& reason,
                         const std::int64_t nowSeconds = static_cast<std::int64_t>(std::time(nullptr))) {
    reason.clear();
    if (code.size() > 128) { reason = "compact login code is too long"; return false; }
    static const std::regex compactPattern(
        R"(^TRUM1:(T[1-9A-HJ-NP-Za-km-z]{33}):([0-9a-f]{48}):([0-9]{10})$)",
        std::regex::ECMAScript);
    std::smatch parts;
    if (!std::regex_match(code, parts, compactPattern)) {
        reason = "invalid one-line TRU Marketplace login code";
        return false;
    }
    const std::string exact = "TRU-MARKET-AUTH-V1\nnetwork:tru-mainnet\n"
                              "domain:market.tokenizedrealutility.com\naddress:" + parts[1].str() +
                              "\nnonce:" + parts[2].str() + "\nexpires:" + parts[3].str() + "\n";
    return parse(exact, out, reason, nowSeconds);
}

} // namespace tru_market_login_v1
