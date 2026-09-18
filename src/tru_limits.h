#pragma once
#ifndef TRU_LIMITS_H
#define TRU_LIMITS_H

#include <cstddef>
#include <cstdint>

// one source of truth for TRU block/network size limits.
// Keep the hard consensus limit separate from the miner/template assembly
// budget so block-level metadata still has headroom before validation.
namespace tru_limits {
inline constexpr std::size_t MAX_BLOCK_BYTES = 64ULL * 1024ULL * 1024ULL;       // 64 MiB hard consensus cap
inline constexpr std::size_t BLOCK_ASSEMBLY_BYTES = 56ULL * 1024ULL * 1024ULL;  // 56 MiB tx-selection budget
inline constexpr std::size_t MAX_P2P_MESSAGE_BYTES = 80ULL * 1024ULL * 1024ULL; // 80 MiB absolute framed payload cap

// P2P framing/request ceilings (NODE POLICY).
// BLOCK needs the existing 80 MiB envelope because consensus blocks may be
// 64 MiB and protobuf framing/metadata need headroom. Other message classes
// are intentionally much smaller so an attacker cannot force 80 MiB protobuf
// allocations for a PING/INV/TX/control message.
inline constexpr std::size_t MAX_P2P_CONTROL_MESSAGE_BYTES = 64ULL * 1024ULL;   // 64 KiB
inline constexpr std::size_t MAX_P2P_TX_MESSAGE_BYTES = 12ULL * 1024ULL * 1024ULL; // legacy text TX wire form may expand beyond 4 MiB binary
inline constexpr std::size_t MAX_P2P_RECEIVE_BUFFER_BYTES =
    MAX_P2P_MESSAGE_BYTES + 64ULL * 1024ULL; // one max frame + recv overshoot

inline constexpr std::size_t MAX_P2P_ADDR_ITEMS = 256;
inline constexpr std::size_t MAX_P2P_INV_ITEMS = 128;
inline constexpr std::size_t MAX_P2P_GETDATA_ITEMS = 8;
inline constexpr std::size_t MAX_P2P_ADDRESS_STRING_BYTES = 128;
inline constexpr std::size_t MAX_P2P_INVENTORY_ITEM_BYTES = 66; // "b:"/"t:" + 64 hex chars

// peer abuse/rate-limit policy (NODE POLICY).
// Connection admission is per source IP and occurs before PeerConnection/thread
// creation. Runtime token buckets preserve enough burst capacity for one
// maximum-size block while bounding sustained peer traffic and request abuse.
inline constexpr std::size_t MAX_P2P_TOTAL_CONNECTIONS = 64;
inline constexpr std::size_t MAX_P2P_CONNECTIONS_PER_IP = 5;
inline constexpr std::size_t MAX_P2P_INBOUND_CONNECTION_ATTEMPTS_PER_MINUTE = 20;

// Runtime traffic budgets are backpressure, not abuse scoring. The byte
// bucket is intentionally large enough for two maximum P2P block frames and
// refills fast enough for high-throughput IBD without punishing an honest peer.
inline constexpr std::size_t P2P_INBOUND_BYTE_RATE_PER_SECOND =
    64ULL * 1024ULL * 1024ULL; // 64 MiB/s sustained per peer
inline constexpr std::size_t P2P_INBOUND_BYTE_BURST =
    160ULL * 1024ULL * 1024ULL; // two maximum 80 MiB framed blocks

inline constexpr std::size_t P2P_INBOUND_MESSAGE_RATE_PER_SECOND = 100;
inline constexpr std::size_t P2P_INBOUND_MESSAGE_BURST = 200;

// Keep sync batching and request admission derived from the same source of
// truth so a future batch-size change cannot silently self-rate-limit IBD.
inline constexpr std::size_t P2P_SYNC_BLOCK_REQUEST_BATCH = 100;
inline constexpr std::size_t P2P_INBOUND_REQUEST_RATE_PER_SECOND = 64;
inline constexpr std::size_t P2P_INBOUND_REQUEST_BURST =
    P2P_SYNC_BLOCK_REQUEST_BATCH + 28; // 128
static_assert(
    P2P_INBOUND_REQUEST_BURST >= P2P_SYNC_BLOCK_REQUEST_BATCH,
    "P2P request burst must cover one sync batch");

// locally-owned outstanding block-request bounds.
inline constexpr std::size_t MAX_P2P_INFLIGHT_BLOCK_REQUESTS_PER_PEER =
    P2P_SYNC_BLOCK_REQUEST_BATCH + 28; // 128
static_assert(
    MAX_P2P_INFLIGHT_BLOCK_REQUESTS_PER_PEER >= P2P_SYNC_BLOCK_REQUEST_BATCH,
    "in-flight block-request cap must cover one sync batch");

inline constexpr std::uint32_t P2P_PEER_REAP_INTERVAL_SECONDS = 5;

// untrusted-source side-fork quotas.
// Global side-pool bounds remain in blockchain.cpp. These source quotas ensure
// one peer IP (or the RPC/legacy-network bucket) cannot monopolize that pool.
inline constexpr std::size_t MAX_SIDE_BLOCKS_PER_UNTRUSTED_SOURCE = 64;
inline constexpr std::size_t MAX_SIDE_BYTES_PER_UNTRUSTED_SOURCE =
    64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t MAX_SIDE_CHILDREN_PER_PARENT_PER_UNTRUSTED_SOURCE = 2;
inline constexpr std::size_t MAX_SIDE_SOURCE_KEY_BYTES = 64;

inline constexpr std::uint32_t P2P_BAN_SCORE_THRESHOLD = 100;
inline constexpr std::uint32_t P2P_MALFORMED_FRAME_SCORE = 100;
inline constexpr std::uint32_t P2P_BAN_SECONDS = 10 * 60;
inline constexpr std::uint32_t P2P_SCORE_DECAY_SECONDS = 10 * 60;
inline constexpr std::size_t MAX_P2P_ABUSE_TABLE_ENTRIES = 4096;

// one source of truth for monetary and mempool policy
// bounds. MAX_MONEY mirrors the consensus value already enforced by
// validateBlock(); the mempool/queue limits are NODE POLICY, not consensus.
inline constexpr std::uint64_t MAX_MONEY = 21000000ULL * 100000000ULL;

// consensus execution/resource ceilings.
// These are deliberately shared by block validation and mempool validation so
// a locally-relayed transaction cannot become consensus-invalid when mined.
inline constexpr std::size_t MAX_CONSENSUS_TX_BYTES = 4ULL * 1024ULL * 1024ULL; // 4 MiB / tx
inline constexpr std::size_t MAX_TX_INPUTS = 1000;
inline constexpr std::size_t MAX_TX_OUTPUTS = 1000;
inline constexpr std::size_t MAX_BLOCK_INPUTS = 20000;
inline constexpr std::size_t MAX_BLOCK_OUTPUTS = 20000;
inline constexpr std::size_t MAX_SCRIPT_BYTES = 10000;
inline constexpr std::uint64_t MAX_SCRIPT_OPS = 1000;
inline constexpr std::uint64_t MAX_TX_SCRIPT_OPS = 20000;
inline constexpr std::uint64_t MAX_BLOCK_SCRIPT_OPS = 100000;
inline constexpr std::uint64_t MAX_TX_SIGOPS = 4000;
inline constexpr std::uint64_t MAX_BLOCK_SIGOPS = 20000;
inline constexpr std::uint64_t MAX_SCRIPT_GAS_PER_INPUT = 1000000;
inline constexpr std::uint64_t MAX_TX_SCRIPT_GAS = 4000000;
inline constexpr std::uint64_t MAX_BLOCK_SCRIPT_GAS = 20000000;
inline constexpr std::size_t MAX_STACK_ITEMS = 1000;
inline constexpr std::size_t MAX_STACK_ITEM_BYTES = 64ULL * 1024ULL;
inline constexpr std::size_t MAX_STACK_BYTES = 1ULL * 1024ULL * 1024ULL;

inline constexpr std::size_t MAX_MEMPOOL_TX_BYTES = MAX_CONSENSUS_TX_BYTES;
inline constexpr std::size_t MAX_MEMPOOL_BYTES = 64ULL * 1024ULL * 1024ULL;      // 64 MiB serialized
inline constexpr std::size_t MAX_MEMPOOL_TXS = 10000;
inline constexpr std::size_t MAX_TX_QUEUE_BYTES = 16ULL * 1024ULL * 1024ULL;     // pre-validation queue
inline constexpr std::size_t MAX_TX_QUEUE_TXS = 1024;

// NODE POLICY ONLY, not block consensus.
// One TRU atom per serialized byte blocks free/zero-fee mempool pinning.
// Every direct/queued/RPC/internal Mempool::addTransaction() call shares the
// same bounded script-validation concurrency gate.
inline constexpr std::uint64_t MIN_RELAY_FEE_SAT_PER_BYTE = 1;
inline constexpr std::size_t MAX_CONCURRENT_MEMPOOL_VALIDATIONS = 4;

// BUSY is retryable overload, not transaction invalidity. The bounded P2P
// queue retries BUSY entries at the back of the queue rather than dropping a
// valid transaction or blocking the queue worker indefinitely.
inline constexpr std::uint8_t MAX_MEMPOOL_BUSY_RETRIES = 20;
inline constexpr std::uint8_t MEMPOOL_BUSY_BACKOFF_BATCH = 8;
inline constexpr std::uint32_t MEMPOOL_BUSY_RETRY_MILLIS = 50;
}

#endif // TRU_LIMITS_H
