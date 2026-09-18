#pragma once

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include "contract_state_limits.h"  // shared state-key limits

// stable state-domain / lineage key primitives.
//
// IMPORTANT: this header defines canonical identities and durable key shapes only.
// It does NOT activate persistence, create a lineage registry, select continuation
// outputs, or change VM execution. Those consensus rules land in later 14D patches.
//
// Identity model:
//   current contract instance = "<txid>:<vout>" (the locking UTXO being spent)
//   stable state domain       = root creation outpoint, same canonical shape
//
// Durable LevelDB key families reserved by this patch:
//   contractlineage:<current-outpoint>          -> <root-state-domain>
//   contractlive:<root-state-domain>            -> <current-live-outpoint>
//   contractowner:<root-state-domain>           -> lowercase P2PKH hash160 hex
//   contractfamily:<root-state-domain>          -> immutable activated family id
//   contractstate:<root-state-domain>:<hex-key> -> state value
//
// Logical state keys are hex-encoded in DB keys so arbitrary VM key bytes cannot
// collide with ':' separators or with another key family.

namespace tru_contract_state {

inline bool IsAsciiHexDigit(char ch)
{
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

inline char ToLowerAsciiHex(char ch)
{
    return (ch >= 'A' && ch <= 'F')
        ? static_cast<char>(ch - 'A' + 'a')
        : ch;
}

inline bool IsHex64(std::string_view s)
{
    if (s.size() != 64) return false;
    for (const char ch : s) {
        if (!IsAsciiHexDigit(ch)) return false;
    }
    return true;
}

inline std::string LowerHex64(std::string_view s)
{
    if (!IsHex64(s)) return {};
    std::string out;
    out.reserve(64);
    for (const char ch : s) {
        out.push_back(ToLowerAsciiHex(ch));
    }
    return out;
}

inline std::string BuildCanonicalContractOutpoint(
    const std::string& txid,
    uint32_t vout)
{
    const std::string canonicalTxid = LowerHex64(txid);
    if (canonicalTxid.empty()) return {};
    return canonicalTxid + ":" + std::to_string(vout);
}

inline bool ParseCanonicalContractOutpoint(
    std::string_view outpoint,
    std::string& txidOut,
    uint32_t& voutOut)
{
    const size_t colon = outpoint.find(':');
    if (colon != 64 || outpoint.find(':', colon + 1) != std::string_view::npos) {
        return false;
    }

    const std::string canonicalTxid = LowerHex64(outpoint.substr(0, colon));
    if (canonicalTxid.empty()) return false;

    const std::string_view voutText = outpoint.substr(colon + 1);
    if (voutText.empty()) return false;
    if (voutText.size() > 1 && voutText.front() == '0') return false;

    uint64_t parsed = 0;
    for (const char ch : voutText) {
        if (ch < '0' || ch > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (parsed > (std::numeric_limits<uint32_t>::max() - digit) / 10ULL) {
            return false;
        }
        parsed = parsed * 10ULL + digit;
    }

    txidOut = canonicalTxid;
    voutOut = static_cast<uint32_t>(parsed);
    return true;
}

inline bool IsCanonicalContractOutpoint(std::string_view outpoint)
{
    std::string txid;
    uint32_t vout = 0;
    if (!ParseCanonicalContractOutpoint(outpoint, txid, vout)) return false;
    return outpoint == BuildCanonicalContractOutpoint(txid, vout);
}

inline std::string BuildContractLineageKey(std::string_view currentOutpoint)
{
    if (!IsCanonicalContractOutpoint(currentOutpoint)) return {};
    return "contractlineage:" + std::string(currentOutpoint);
}

inline std::string BuildContractLiveKey(std::string_view stateDomain)
{
    if (!IsCanonicalContractOutpoint(stateDomain)) return {};
    return "contractlive:" + std::string(stateDomain);
}

// durable owner binding for owner-authorized V1 calls.
// The value stored at this key is exactly 40 lowercase ASCII hex characters
// representing the creator funding input's standard P2PKH hash160.
inline std::string BuildContractOwnerKey(std::string_view stateDomain)
{
    if (!IsCanonicalContractOutpoint(stateDomain)) return {};
    return "contractowner:" + std::string(stateDomain);
}

// immutable activated contract-family registry. Existing
// Stateful K/V V1 roots intentionally have no family key; Voting V1 roots are
// born with exactly "voting_v1". Future families must add explicit values
// rather than inferring consensus semantics from mutable user state.
inline std::string BuildContractFamilyKey(std::string_view stateDomain)
{
    if (!IsCanonicalContractOutpoint(stateDomain)) return {};
    return "contractfamily:" + std::string(stateDomain);
}

inline std::string HexEncodeLogicalKey(std::string_view logicalKey)
{
    static constexpr char HEX[] = "0123456789abcdef";
    if (logicalKey.empty()) return {};

    std::string out;
    if (logicalKey.size() > (std::numeric_limits<size_t>::max() / 2U)) return {};
    out.reserve(logicalKey.size() * 2U);

    for (const unsigned char c : logicalKey) {
        out.push_back(HEX[(c >> 4) & 0x0F]);
        out.push_back(HEX[c & 0x0F]);
    }
    return out;
}

inline std::string BuildContractStatePrefix(std::string_view stateDomain)
{
    if (!IsCanonicalContractOutpoint(stateDomain)) return {};
    return "contractstate:" + std::string(stateDomain) + ":";
}

inline std::string BuildContractStateKey(
    std::string_view stateDomain,
    std::string_view logicalKey)
{
    if (!tru_contract_state_limits::IsLogicalKeyAllowed(logicalKey)) return {};
    const std::string prefix = BuildContractStatePrefix(stateDomain);
    const std::string encodedKey = HexEncodeLogicalKey(logicalKey);
    if (prefix.empty() || encodedKey.empty()) return {};
    return prefix + encodedKey;
}

} // namespace tru_contract_state

// Preserve Patch 14C behavior exactly for existing VM call sites.
// Canonical validation is required only when a value is promoted into the
// stable lineage/state-domain registry in later 14D patches.
inline std::string BuildContractIdentity(const std::string& txid, uint32_t vout)
{
    if (txid.empty()) return {};
    return txid + ":" + std::to_string(vout);
}
