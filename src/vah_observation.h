#pragma once
#ifndef VAH_OBSERVATION_H
#define VAH_OBSERVATION_H

#include "vah_reconciliation.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class Blockchain;

namespace VAHObservation {

constexpr std::size_t MAX_ANCHOR_SCRIPT_BYTES = 65536U;
constexpr std::size_t MAX_OBSERVATION_BLOCKS = 2048U;
constexpr std::size_t MAX_OBSERVATION_TRANSACTIONS = 1000000U;

// TRU_EVOLVE_V1 does not commit the durable off-chain record hash.  A
// chain-derived V1 candidate therefore uses this explicit sentinel instead of
// importing an uncommitted record identity from a peer or local arrival order.
const std::string& v1UncommittedRecordHash();

struct AnchorV1 {
    std::string tokenID;
    std::string tokenType;
    uint64_t epoch{0};
    std::string provider;
    std::string trigger;
    std::string previousMetadataHash;
    std::string newMetadataHash;
};

// VAH-02D dormant strong-binding envelope. It is the V1 anchor plus the
// exact durable record hash. No production writer emits V2 in VAH-02D.
struct AnchorV2 {
    std::string tokenID;
    std::string tokenType;
    uint64_t epoch{0};
    std::string provider;
    std::string trigger;
    std::string previousMetadataHash;
    std::string newMetadataHash;
    std::string recordHash;
};

enum class AnchorParseStatus {
    NotEvolutionAnchor,
    Valid,
    Malformed
};

struct OutputSnapshot {
    uint64_t amount{0};
    std::string scriptPubKey;
};

struct TransactionSnapshot {
    std::string txid;
    std::vector<OutputSnapshot> outputs;
};

struct BlockSnapshot {
    std::string blockHash;
    std::string previousBlockHash;
    uint64_t height{0};
    std::vector<TransactionSnapshot> transactions;
};

struct ObservationRequest {
    std::string expectedTokenID;
    uint64_t expectedEpoch{0};
    std::string expectedPreviousMetadataHash;
    VAHReconciliation::CanonicalView view;
};

struct ObservationResult {
    bool ok{false};
    std::string error;
    std::vector<VAHReconciliation::Candidate> candidates;
    std::size_t malformedEvolutionAnchors{0};
    std::size_t ignoredOtherEvolutionAnchors{0};
};

// Parse the exact eight-push TRU_EVOLVE_V1 anchor emitted by the current
// anchor worker.  Only minimal direct/PUSHDATA1/PUSHDATA2 encodings are
// accepted.  Unrelated OP_RETURN scripts return NotEvolutionAnchor.
AnchorParseStatus parseEvolutionAnchorV1(
    const std::string& scriptHex,
    AnchorV1& out,
    std::string& reason);

// Canonical nine-push OP_RETURN codec for TRU_EVOLVE_V2. The final field is
// a non-zero lowercase 64-hex record hash, making durable record identity
// visible on chain. Encoding/decoding here does not activate any writer.
std::string encodeEvolutionAnchorV2(const AnchorV2& anchor);

AnchorParseStatus parseEvolutionAnchorV2(
    const std::string& scriptHex,
    AnchorV2& out,
    std::string& reason);

// Fixed-size, canonical binary transport for a fully located VAH candidate.
// Decoding is structural only: transport never proves active-chain inclusion.
std::string encodeCandidateTransportV1(
    const VAHReconciliation::Candidate& candidate);

bool decodeCandidateTransportV1(
    const std::string& encoded,
    VAHReconciliation::Candidate& candidate,
    std::string& reason);

// Pure observation core. The caller must supply an ascending, contiguous
// snapshot ending exactly at request.view. TRU_EVOLVE_V1 candidates retain
// the all-zero uncommitted record-hash sentinel; TRU_EVOLVE_V2 candidates
// carry the exact chain-committed record hash. It performs no storage mutation.
ObservationResult observeConfirmedActiveRange(
    const ObservationRequest& request,
    const std::vector<BlockSnapshot>& blocks);

// Production read-only adapter.  It snapshots the local active chain through
// Blockchain's existing public getters and rechecks the tip after observation.
// Peer claims are not inputs and no TOKEN_EVOLUTION state is written.
ObservationResult observeLocalActiveChain(
    const Blockchain& chain,
    const ObservationRequest& request,
    uint64_t firstHeight);

} // namespace VAHObservation

#endif
