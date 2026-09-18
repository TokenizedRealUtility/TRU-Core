#pragma once
#ifndef VAH_EXTERNAL_WRITER_STAGE_H
#define VAH_EXTERNAL_WRITER_STAGE_H

#include "vah_external_writer_gate.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class LevelDBStorage;

// VAH-03B: bounded local external-writer claim intake + durable staging.
//
// Only claims that already satisfy the VAH-03A cryptographic/historical/
// capability gate may be staged. The staging namespace is append-only at this
// phase and is deliberately separate from TOKEN_EVOLUTION and VAH_RECON.
// No RPC/P2P ingress, TRU_EVOLVE_V2 emission, chain mutation, or token-state
// materialization is activated here.
namespace VAHExternalWriterStage {

constexpr std::size_t MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH = 32U;
constexpr std::size_t MAX_STAGED_CLAIM_BYTES = 4096U;

struct LoadResult {
    bool ok{false};
    std::vector<VAHExternalWriter::Claim> claims;
    std::vector<std::string> errors;
};

// Deterministic, line-oriented durable representation. This envelope is not a
// signature preimage; VAH-03A signatures remain bound to claimDigest().
std::string serializePendingClaim(const VAHExternalWriter::Claim& claim);
bool parsePendingClaim(
    const std::string& encoded,
    VAHExternalWriter::Claim& out,
    std::string* reason = nullptr
);

// Canonical durable key used by VAH-03B. Exposed for later VAH-03 phases and
// adversarial tests; callers must not write this namespace except through the
// staging API once runtime ingress is activated.
std::string pendingClaimKey(
    const std::string& tokenId,
    std::uint64_t epoch,
    const std::string& recordHash
);

// Verify through VAH-03A and append one synced pending claim. Exact replay is
// idempotent. Existing corruption, key/envelope mismatch, or resource-bound
// exhaustion fails closed. This does not mutate TOKEN_EVOLUTION.
bool stageClaim(
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

// Restart/recovery reader. Every entry under the exact token/epoch prefix is
// checksum-verified, parsed canonically, key-bound to its record_hash, and
// re-verified through VAH-03A before being returned in deterministic order.
LoadResult loadPendingClaims(
    LevelDBStorage& storage,
    const std::string& tokenId,
    std::uint64_t epoch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex
);

} // namespace VAHExternalWriterStage

#endif
