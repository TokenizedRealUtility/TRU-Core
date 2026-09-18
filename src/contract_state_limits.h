#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// genesis contract-state resource policy.
//
// These are CONSENSUS limits pinned before persistent VM state is activated.
// The VM remains persistence-disabled until Patch 14D3.
//
// Logical keys are hex-encoded when promoted to durable LevelDB keys. State
// accounting therefore charges two durable key bytes for every logical key byte.
// Fixed family/domain prefix overhead is not counted toward the per-domain cap.

namespace tru_contract_state_limits {

inline constexpr std::size_t MAX_LOGICAL_KEY_BYTES = 128;
inline constexpr std::size_t MAX_VALUE_BYTES = 4ULL * 1024ULL;                 // 4 KiB
inline constexpr std::size_t MAX_KEYS_PER_DOMAIN = 4096;
inline constexpr std::size_t MAX_TOTAL_STATE_BYTES = 1ULL * 1024ULL * 1024ULL; // 1 MiB accounted

// Permanent storage is priced much more aggressively than transient stack work.
// With the existing 20M block gas ceiling, 100 gas/accounted byte bounds the
// dominant durable state growth component to roughly 200 KiB per full-gas block.
inline constexpr std::uint64_t STORE_GAS_BASE = 1000;
inline constexpr std::uint64_t STORE_GAS_PER_ACCOUNTED_BYTE = 100;

using StateMap = std::unordered_map<std::string, std::vector<unsigned char>>;

inline bool IsLogicalKeyAllowed(std::string_view key)
{
    return !key.empty() && key.size() <= MAX_LOGICAL_KEY_BYTES;
}

inline bool IsValueAllowed(const std::vector<unsigned char>& value)
{
    return value.size() <= MAX_VALUE_BYTES;
}

inline bool ComputeAccountedEntryBytes(
    std::string_view key,
    std::size_t valueBytes,
    std::size_t& bytesOut)
{
    if (!IsLogicalKeyAllowed(key) || valueBytes > MAX_VALUE_BYTES) return false;
    const std::size_t encodedKeyBytes = key.size() * 2U;
    if (valueBytes > MAX_TOTAL_STATE_BYTES - encodedKeyBytes) return false;
    bytesOut = encodedKeyBytes + valueBytes;
    return true;
}

inline bool MeasureStateBytes(const StateMap& state, std::size_t& bytesOut)
{
    if (state.size() > MAX_KEYS_PER_DOMAIN) return false;

    std::size_t total = 0;
    for (const auto& [key, value] : state) {
        std::size_t entryBytes = 0;
        if (!ComputeAccountedEntryBytes(key, value.size(), entryBytes)) return false;
        if (entryBytes > MAX_TOTAL_STATE_BYTES - total) return false;
        total += entryBytes;
    }

    bytesOut = total;
    return true;
}

inline bool CanApplyStateWrite(
    const StateMap& state,
    const std::string& key,
    const std::vector<unsigned char>& value,
    std::size_t* resultingBytesOut = nullptr)
{
    if (!IsLogicalKeyAllowed(key) || !IsValueAllowed(value)) return false;

    std::size_t currentBytes = 0;
    if (!MeasureStateBytes(state, currentBytes)) return false;

    const auto it = state.find(key);
    if (it == state.end()) {
        if (state.size() >= MAX_KEYS_PER_DOMAIN) return false;
    } else {
        std::size_t oldEntryBytes = 0;
        if (!ComputeAccountedEntryBytes(key, it->second.size(), oldEntryBytes) ||
            oldEntryBytes > currentBytes) {
            return false;
        }
        currentBytes -= oldEntryBytes;
    }

    std::size_t newEntryBytes = 0;
    if (!ComputeAccountedEntryBytes(key, value.size(), newEntryBytes)) return false;
    if (newEntryBytes > MAX_TOTAL_STATE_BYTES - currentBytes) return false;
    const std::size_t resultingBytes = currentBytes + newEntryBytes;

    if (resultingBytesOut) *resultingBytesOut = resultingBytes;
    return true;
}

inline bool ComputeStoreGas(
    std::size_t keyBytes,
    std::size_t valueBytes,
    std::uint64_t& gasOut)
{
    if (keyBytes == 0 || keyBytes > MAX_LOGICAL_KEY_BYTES ||
        valueBytes > MAX_VALUE_BYTES) {
        return false;
    }

    const std::size_t accountedBytes = keyBytes * 2U + valueBytes;
    if (accountedBytes >
        (std::numeric_limits<std::uint64_t>::max() - STORE_GAS_BASE) /
            STORE_GAS_PER_ACCOUNTED_BYTE) {
        return false;
    }

    gasOut = STORE_GAS_BASE +
        static_cast<std::uint64_t>(accountedBytes) *
            STORE_GAS_PER_ACCOUNTED_BYTE;
    return true;
}

} // namespace tru_contract_state_limits
