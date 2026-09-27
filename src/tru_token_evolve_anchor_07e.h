// TRU AI ANCHOR 07E -- local OP_RETURN protocol only; NOT consensus rules.
// The durable evolution-record format remains TRU_TOKEN_EVOLVE_V1.
#pragma once

#include <openssl/sha.h>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace tru_anchor_07e {
constexpr std::size_t kMaxRelayOpReturnScriptBytes = 257U;

inline std::string sha256Raw(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()),
           input.size(), digest);
    return std::string(reinterpret_cast<const char*>(digest), sizeof(digest));
}

inline unsigned char nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    throw std::invalid_argument("noncanonical hexadecimal anchor field");
}

inline std::string fromLowerHex64(const std::string& hex) {
    if (hex.size() != 64U) {
        throw std::invalid_argument("anchor hash must be 32-byte lowercase hex");
    }
    std::string raw;
    raw.reserve(32U);
    for (std::size_t i = 0; i < 64U; i += 2U) {
        raw.push_back(static_cast<char>((nibble(hex[i]) << 4U) | nibble(hex[i+1U])));
    }
    return raw;
}

inline std::string toLowerHex(const std::string& raw) {
    static constexpr char h[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(raw.size() * 2U);
    for (unsigned char c : raw) {
        hex.push_back(h[c >> 4U]);
        hex.push_back(h[c & 15U]);
    }
    return hex;
}

inline void push(std::string& script, const std::string& bytes) {
    const std::size_t n = bytes.size();
    if (n <= 75U) {
        script.push_back(static_cast<char>(n));
    } else if (n <= 255U) {
        script.push_back(static_cast<char>(0x4c));
        script.push_back(static_cast<char>(n));
    } else if (n <= 65535U) {
        script.push_back(static_cast<char>(0x4d));
        script.push_back(static_cast<char>(n & 255U));
        script.push_back(static_cast<char>((n >> 8U) & 255U));
    } else {
        throw std::invalid_argument("oversized anchor field");
    }
    script.append(bytes);
}

inline std::string script(const std::vector<std::string>& fields) {
    std::string raw(1, static_cast<char>(0x6a));
    for (const std::string& field : fields) push(raw, field);
    return toLowerHex(raw);
}

struct Fields {
    std::string tokenID;
    std::string tokenType;
    uint64_t epoch{0U};
    std::string provider;
    std::string trigger;
    std::string previousMetadataHash;
    std::string newMetadataHash;
    std::string signedRecordHash;
};

// Historical exact V1 encoding: never change this order or representation.
inline std::string legacyV1(const Fields& f) {
    return script({"TRU_EVOLVE_V1", f.tokenID, f.tokenType,
                   std::to_string(f.epoch), f.provider, f.trigger,
                   f.previousMetadataHash, f.newMetadataHash});
}

// V2 binary-hash encoding: binds full canonical signed record and full trigger.
// Each 32-byte binary digest is a separate canonical push, not 64 ASCII chars.
inline std::string compactV2(const Fields& f) {
    return script({"TRU_EVOLVE_V2", f.tokenID, f.tokenType,
                   std::to_string(f.epoch), f.provider,
                   sha256Raw(f.trigger),
                   fromLowerHex64(f.previousMetadataHash),
                   fromLowerHex64(f.newMetadataHash),
                   fromLowerHex64(f.signedRecordHash)});
}

inline bool selectCanonical(const Fields& f,
                            std::string& selected,
                            std::string& legacy) {
    selected.clear();
    legacy.clear();
    if (f.epoch == 0U || (f.tokenType != "SFT" && f.tokenType != "NCFT") ||
        f.provider.empty() ||
        (f.tokenID.size() != 8U && f.tokenID.size() != 16U)) return false;
    try {
        // Even when V1 overflows the policy, retain its deterministic script
        // for strict verification of an existing historical prepared tx.
        legacy = legacyV1(f);
        if (legacy.size() / 2U <= kMaxRelayOpReturnScriptBytes) {
            selected = legacy;
        } else {
            selected = compactV2(f);
        }
        if (selected.size() / 2U > kMaxRelayOpReturnScriptBytes) {
            selected.clear();
            return false;
        }
        return true;
    } catch (const std::exception&) {
        selected.clear();
        return false;
    }
}

struct RecoveryGate {
    bool expectedCompact{false};
    bool exactLegacySignedTx{false};
    bool legacyScriptOversized{false};
    bool oldTransactionUnobservable{false};
    bool noSubmittedAnchorOrReceipt{false};
    bool archiveSlotEmpty{false};
    bool fundingUtxoLive{false};
    bool fundingNotMempoolReserved{false};
};
inline bool canRecover(const RecoveryGate& g) {
    return g.expectedCompact && g.exactLegacySignedTx &&
           g.legacyScriptOversized && g.oldTransactionUnobservable &&
           g.noSubmittedAnchorOrReceipt && g.archiveSlotEmpty &&
           g.fundingUtxoLive && g.fundingNotMempoolReserved;
}
} // namespace tru_anchor_07e
