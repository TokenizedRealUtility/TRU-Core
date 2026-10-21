#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

// Node recovery policy, not block consensus or activation parameters.
namespace tru_fork_recovery {
inline constexpr int MAX_DISCONNECT_BLOCKS = 4096;
inline constexpr int MAX_CONNECT_BLOCKS = 4096;
inline constexpr std::size_t MAX_INDEXED_SIDE_BLOCKS = 8192;
inline constexpr std::size_t MAX_SIDE_BLOCKS_PER_SOURCE = MAX_CONNECT_BLOCKS;
inline constexpr std::size_t MAX_PENDING_RECORD_BYTES = 4ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t PARENT_CACHE_BYTES = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t PARENT_CACHE_ENTRIES = 8;
static_assert(MAX_INDEXED_SIDE_BLOCKS >= 2ULL * MAX_CONNECT_BLOCKS,
              "side index must hold a candidate plus displaced active suffix");
static_assert(MAX_SIDE_BLOCKS_PER_SOURCE >= MAX_CONNECT_BLOCKS,
              "one peer must be able to deliver a supported branch");
static_assert(MAX_PENDING_RECORD_BYTES >=
              256ULL * (MAX_DISCONNECT_BLOCKS + MAX_CONNECT_BLOCKS) + 65536,
              "durable intent must accommodate bounded branch identity arrays");

enum class Discovery { Found, BeyondWindow, LocalUnavailable, PeerUnavailable };
struct AncestorResult {
    Discovery state{Discovery::BeyondWindow};
    std::uint64_t height{0};
    std::size_t probes{0};
};
// Hash equality is only a discovery hint. The caller MUST fetch the full
// contiguous branch and use authoritative validation/work before activation.
// Local and peer callbacks return false when a hash cannot be obtained.
// The caller also rechecks its tip identity after discovery to reject races.
template<class LocalHash, class PeerHash>
AncestorResult findAncestor(std::uint64_t localTip, std::uint64_t peerTip,
                           std::uint64_t maxDisconnect,
                           LocalHash localHash, PeerHash peerHash) {
    AncestorResult result;
    const auto high = std::min(localTip, peerTip);
    const auto low = localTip > maxDisconnect ? localTip - maxDisconnect : 1;
    if (!high || low > high) return result;
    auto equalAt = [&](std::uint64_t h, bool& equal) {
        std::string local, peer;
        if (!localHash(h, local) || local.empty()) {
            result.state = Discovery::LocalUnavailable; return false;
        }
        ++result.probes;
        if (!peerHash(h, peer) || peer.empty()) {
            result.state = Discovery::PeerUnavailable; return false;
        }
        equal = local == peer; return true;
    };
    bool equal = false;
    if (!equalAt(high, equal)) return result;
    if (equal) { result.state=Discovery::Found;result.height=high;return result; }
    if (low == high) return result;
    if (!equalAt(low, equal)) return result;
    if (!equal) { result.state=Discovery::BeyondWindow;return result; }
    std::uint64_t lo=low, hi=high;
    while (hi-lo>1) {
        auto mid=lo+(hi-lo)/2;
        if (!equalAt(mid,equal)) return result;
        if (equal) lo=mid; else hi=mid;
    }
    result.state=Discovery::Found;result.height=lo;return result;
}
}
