#pragma once
#ifndef VAH_RECONCILIATION_H
#define VAH_RECONCILIATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace VAHReconciliation {

constexpr uint64_t MAX_CANDIDATES_PER_EPOCH = 256U;

struct Candidate {
    std::string tokenID;
    uint64_t epoch{0};
    std::string previousMetadataHash;
    std::string newMetadataHash;

    // Exact durable off-chain record identity.  This is required for
    // transport/persistence equality, but V1 anchors do not commit it.
    std::string recordHash;

    // Confirmed active-chain observation.
    std::string anchorTxid;
    std::string blockHash;
    uint64_t blockHeight{0};
    uint64_t txIndex{0};
};

struct CanonicalView {
    uint64_t finalizedHeight{0};
    std::string finalizedBlockHash;
};

struct ElectionResult {
    bool ok{false};
    bool hasWinner{false};
    std::string error;
    Candidate winner;
    std::vector<Candidate> rejected;
};

// A candidate is eligible only when it is a structurally canonical,
// confirmed active-chain claim at or below the caller's finalized prefix.
bool validateCandidate(
    const Candidate& candidate,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    std::string& reason);

// VAH-02D closure gate. A strongly bound candidate must pass the ordinary
// finalized active-chain candidate checks and carry a non-zero record hash.
// The all-zero record hash remains reserved for legacy TRU_EVOLVE_V1 anchors,
// which do not commit the durable record identity and therefore cannot close
// reconciliation for later external-writer activation.
bool validateStronglyBoundCandidate(
    const Candidate& candidate,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    std::string& reason);

// Verify that a locally observed strongly-bound candidate commits the exact
// expected durable off-chain record hash.
bool verifyCommittedRecordHash(
    const Candidate& candidate,
    const std::string& expectedRecordHash,
    std::string& reason);

// Deterministic election rule:
//
//   1. confirmed active-chain candidates only
//   2. same token / epoch / parent metadata hash
//   3. earliest active-chain block height wins
//   4. then lowest transaction index within that block
//   5. then lexicographically lowest anchor txid
//   6. then lexicographically lowest new metadata hash
//   7. then lexicographically lowest record hash
//
// Arrival order, wall clock time and peer identity are never inputs.
ElectionResult electCanonicalCandidate(
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    const std::vector<Candidate>& candidates);

// VAH-02D closed election. Candidates without a chain-committed record hash
// are rejected before applying the unchanged deterministic ordering rule.
ElectionResult electStronglyBoundCanonicalCandidate(
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    const std::vector<Candidate>& candidates);

bool sameCanonicalIdentity(const Candidate& a, const Candidate& b);

} // namespace VAHReconciliation

#endif
