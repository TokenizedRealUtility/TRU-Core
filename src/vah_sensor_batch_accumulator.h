#pragma once
#ifndef VAH_SENSOR_BATCH_ACCUMULATOR_H
#define VAH_SENSOR_BATCH_ACCUMULATOR_H

#include "vah_sensor_batch.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class LevelDBStorage;

// VAH-04B: restart-safe local sensor-feed accumulator.
//
// This layer persists only already-valid VAH-04A SENSOR batches. One durable
// head exists per (token_id, writer_id) feed and sequences continue across token
// epoch changes. No RPC/P2P ingress, anchor emission, TOKEN_EVOLUTION mutation,
// wallet spending, or chain policy change is enabled here.
namespace VAHSensorBatchAccumulator {

constexpr std::size_t MAX_DURABLE_BATCH_BYTES = 131072U;
constexpr std::size_t MAX_DURABLE_HEAD_BYTES = 2048U;

struct StoredBatch {
    std::uint64_t feed_index{0U};
    // first sequence of the predecessor batch; zero for feed genesis.
    std::uint64_t previous_first_sequence{0U};
    VAHSensorBatch::Batch batch;
};

struct FeedHead {
    std::uint32_t format_version{1U};
    std::string token_id;
    std::string writer_id;
    std::string writer_pubkey_hex;
    std::uint64_t batch_count{0U};
    std::uint64_t latest_epoch{0U};
    std::uint64_t last_first_sequence{0U};
    std::uint64_t last_sequence{0U};
    std::uint64_t last_observed_at_ms{0U};
    std::string last_batch_hash;
};

struct LoadHeadResult {
    bool ok{false};
    bool has_head{false};
    FeedHead head;
    StoredBatch latest;
    std::vector<std::string> errors;
};

std::string accumulatedBatchKey(
    const std::string& tokenId,
    const std::string& writerId,
    std::uint64_t firstSequence,
    const std::string& batchHash
);

std::string feedHeadKey(
    const std::string& tokenId,
    const std::string& writerId
);

std::string serializeStoredBatch(const StoredBatch& stored);
bool parseStoredBatch(
    const std::string& encoded,
    StoredBatch& out,
    std::string* reason = nullptr
);

std::string serializeFeedHead(const FeedHead& head);
bool parseFeedHead(
    const std::string& encoded,
    FeedHead& out,
    std::string* reason = nullptr
);

// Append one locally supplied batch after full VAH-04A verification. New state
// is one synced LevelDB batch containing the append-only batch record plus the
// mutable strict-checksum feed head. Exact semantic replay is idempotent even
// after later batches have advanced the head. A competing current-head branch
// fails closed.
bool appendBatch(
    LevelDBStorage& storage,
    const VAHSensorBatch::Batch& batch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

// Restart/recovery reader. The strict head is checksum-verified and is bound to
// the exact latest stored batch. For non-genesis heads, the immediate predecessor
// is also exact-key loaded and continuity checked. No unbounded namespace scan
// is performed.
LoadHeadResult loadFeedHead(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex
);

// Exact-key historical reader used by later anchor phases and replay tests.
bool loadStoredBatch(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    std::uint64_t firstSequence,
    const std::string& batchHash,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    StoredBatch& out,
    std::string* reason = nullptr
);

} // namespace VAHSensorBatchAccumulator

#endif
