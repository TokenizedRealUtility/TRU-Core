#ifndef TRU_SWAP_PREPARED_FUNDING_GUARD_H
#define TRU_SWAP_PREPARED_FUNDING_GUARD_H

// TRU SWAP GROUP-01 — local prepared-funding reservation namespace.
// This is wallet/node policy state, not consensus state.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <nlohmann/json.hpp>

namespace tru_swap_prepared_funding {

inline constexpr const char* OP_PREFIX =
    "swapPreparedFundingV1:op:";
inline constexpr const char* INPUT_PREFIX =
    "swapPreparedFundingV1:input:";
inline constexpr const char* RECORD_VERSION =
    "TRU-SWAP-PREPARED-FUNDING-V1";
inline constexpr const char* INPUT_VERSION =
    "TRU-SWAP-PREPARED-INPUT-V1";

inline std::recursive_mutex& mutex()
{
    static std::recursive_mutex m;
    return m;
}

inline bool isLowerHex64(const std::string& value)
{
    if (value.size() != 64U) return false;
    return std::all_of(
        value.begin(), value.end(),
        [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

inline std::string opKey(const std::string& operationId)
{
    return std::string(OP_PREFIX) + operationId;
}

inline std::string inputKey(const std::string& txid, std::uint32_t vout)
{
    return std::string(INPUT_PREFIX) + txid + ":" + std::to_string(vout);
}

inline std::string sha256Hex(const std::vector<unsigned char>& bytes)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(bytes.data(), bytes.size(), digest);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : digest) {
        oss << std::setw(2) << static_cast<unsigned int>(c);
    }
    return oss.str();
}

inline bool parseInputMarker(
    const std::string& payload,
    std::string& operationIdOut,
    std::string& preparedTxidOut,
    std::string& rawTxSha256Out)
{
    operationIdOut.clear();
    preparedTxidOut.clear();
    rawTxSha256Out.clear();
    try {
        const auto j = nlohmann::json::parse(payload);
        if (j.value("version", std::string{}) != INPUT_VERSION) return false;
        operationIdOut = j.value("operationId", std::string{});
        preparedTxidOut = j.value("preparedTxid", std::string{});
        rawTxSha256Out = j.value("rawTxSha256", std::string{});
        return isLowerHex64(operationIdOut) &&
               isLowerHex64(preparedTxidOut) &&
               isLowerHex64(rawTxSha256Out);
    } catch (...) {
        return false;
    }
}

} // namespace tru_swap_prepared_funding

#endif // TRU_SWAP_PREPARED_FUNDING_GUARD_H
