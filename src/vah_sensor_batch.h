#pragma once
#ifndef VAH_SENSOR_BATCH_H
#define VAH_SENSOR_BATCH_H

#include "vah_authorization.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class ECDSAKey;

// VAH-04A: canonical sensor-batch envelope + Merkle commitments.
//
// This layer batches bounded SENSOR events beneath one signed, authorization-
// checked envelope. It is pure/non-persistent: no LevelDB accumulator, RPC/P2P
// ingress, anchor emission, or TOKEN_EVOLUTION mutation exists in VAH-04A.
namespace VAHSensorBatch {

constexpr std::size_t MAX_EVENTS_PER_BATCH = 256U;
constexpr std::size_t MAX_FIELD_BYTES = 64U;
constexpr std::size_t HASH_HEX_BYTES = 64U;

struct Event {
    std::uint64_t sequence{0U};
    std::uint64_t observed_at_ms{0U};
    std::string field;
    // Hash of the canonical sensor payload kept outside the batch envelope.
    // Raw telemetry is intentionally not embedded here.
    std::string payload_hash;
};

struct Batch {
    std::uint32_t format_version{1U};
    std::string token_id;
    std::string token_type;
    std::uint64_t epoch{0U};

    // Chained feed identity. All-zero is permitted only as a structural genesis
    // predecessor; continuity against durable state is VAH-04B's job.
    std::string previous_batch_hash;

    std::string writer_pubkey_hex;
    std::string writer_id;
    std::string writer_class{"sensor"};

    // Canonical order is vector order, and structural validation requires the
    // event sequence numbers to be contiguous in that same order.
    std::vector<Event> events;

    std::string merkle_root;
    // SHA256 of the canonical unsigned batch envelope.
    std::string batch_hash;
    std::string signature_der_hex;
};

// Domain-separated leaf commitment. The leaf binds batch context, writer,
// event_count/sequence/timestamp/field, and payload_hash so a proof cannot be transplanted
// into another token/epoch/feed branch.
std::string eventLeafHashHex(const Batch& batch, const Event& event);

// Bitcoin-style duplicate-last Merkle tree with explicit leaf/node domains.
// Batch event_count is separately committed by batchDigest(), preventing odd-
// leaf duplication ambiguity.
std::string computeMerkleRootHex(const Batch& batch);

// Sibling hashes from leaf level upward. Returns false for malformed batch or
// index. Proof verification requires both index and event_count.
bool buildInclusionProof(
    const Batch& batch,
    std::size_t eventIndex,
    std::vector<std::string>& siblingHashes,
    std::string* reason = nullptr
);

bool verifyInclusionProof(
    const Batch& batchContext,
    const Event& event,
    std::size_t eventIndex,
    std::size_t eventCount,
    const std::vector<std::string>& siblingHashes,
    const std::string& expectedMerkleRoot,
    std::string* reason = nullptr
);

std::vector<unsigned char> batchDigest(const Batch& batch);
std::string batchDigestHex(const Batch& batch);

// Convenience signer for a local sensor producer. Identity is derived from the
// private key. The function computes merkle_root + batch_hash and signs the
// batch digest, but does not authorize or persist the batch.
bool signBatch(
    Batch& batch,
    const ECDSAKey& sensorKey,
    std::string* reason = nullptr
);

// Strict authorization + signature + Merkle admission. The complete signed
// authorization history is replayed at batch.epoch for every unique event field.
bool verifyBatch(
    const Batch& batch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

} // namespace VAHSensorBatch

#endif
