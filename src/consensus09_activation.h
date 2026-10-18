#pragma once
#include <cstdint>
#include <limits>
#include <vector>
namespace tru09 {
// TRU Core 0.08.5 mainnet activation: block 50000 (inclusive).
// Network consensus constant; never override through tru.conf or an RPC.
inline constexpr uint32_t NEVER = std::numeric_limits<uint32_t>::max();
#ifdef TRU_CONSENSUS09_TEST_HEIGHT
#ifndef TRU_CONSENSUS09_TEST_BUILD
#error "A test activation height is forbidden in a production build"
#endif
inline constexpr uint32_t ACTIVATION_HEIGHT = TRU_CONSENSUS09_TEST_HEIGHT;
#else
inline constexpr uint32_t ACTIVATION_HEIGHT = 50000;
#endif
inline constexpr uint32_t WOTS_HEIGHT = ACTIVATION_HEIGHT;
inline constexpr uint32_t MARKET_HEIGHT = ACTIVATION_HEIGHT;
inline constexpr uint32_t OPSIZE_HEIGHT = ACTIVATION_HEIGHT;
inline constexpr uint32_t COMMITMENT_HEIGHT = ACTIVATION_HEIGHT;
inline bool active(uint32_t h, uint32_t at = ACTIVATION_HEIGHT) {
    return at != NEVER && h >= at;
}
inline constexpr uint64_t WOTS_GAS = 125000;
inline constexpr uint64_t WOTS_SIGOPS = 256;
inline constexpr uint64_t MARKET_GAS = 25000;
inline constexpr uint64_t MARKET_SIGOPS = 20;
// TRU arithmetic uses unsigned little endian values, not Bitcoin signed
// ScriptNum. Zero is empty; no redundant high zero bytes after activation.
inline std::vector<unsigned char> sizeValue(uint64_t n, uint32_t h) {
    if (!active(h, OPSIZE_HEIGHT)) return {static_cast<unsigned char>(n)};
    std::vector<unsigned char> out;
    while (n) { out.push_back(static_cast<unsigned char>(n)); n >>= 8; }
    return out;
}
}
