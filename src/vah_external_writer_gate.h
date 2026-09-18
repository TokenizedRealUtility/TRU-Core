#pragma once
#ifndef VAH_EXTERNAL_WRITER_GATE_H
#define VAH_EXTERNAL_WRITER_GATE_H

#include "vah_authorization.h"

#include <cstdint>
#include <string>
#include <vector>

class ECDSAKey;

// VAH-03A: controlled external-writer activation gate.
//
// This layer validates a signed HUMAN / SENSOR / DEVICE claim against the
// complete signed historical authorization state and the VAH typed field
// catalog.  It does not persist the claim, emit TRU_EVOLVE_V2, accept P2P
// records, or mutate TOKEN_EVOLUTION.  Its record_hash is the exact digest
// intended to become the strong VAH-02D chain commitment in later phases.
namespace VAHExternalWriter {

constexpr std::size_t MAX_CHANGED_FIELDS = 16U;
constexpr std::size_t MAX_CHANGED_FIELD_BYTES = 64U;

struct Claim {
    std::uint32_t format_version{1U};
    std::string token_id;
    std::string token_type;
    std::uint64_t epoch{0U};
    std::string previous_metadata_hash;
    std::string new_metadata_hash;

    std::string writer_pubkey_hex;
    std::string writer_id;
    std::string writer_class;
    std::vector<std::string> changed_fields;

    // SHA256 of the canonical unsigned claim.  This exact non-zero hash is
    // suitable for the TRU_EVOLVE_V2 record_hash field introduced by VAH-02D.
    std::string record_hash;
    std::string signature_der_hex;
};

// Canonical digest of all claim semantics except record_hash/signature.
std::vector<unsigned char> claimDigest(const Claim& claim);
std::string claimDigestHex(const Claim& claim);

// Convenience signer for local/dev producers. The writer public key and
// writer_id are derived from the supplied private key; changed_fields must
// already be canonical sorted/unique.
bool signClaim(
    Claim& claim,
    const ECDSAKey& writerKey,
    std::string* reason = nullptr
);

// Strict admission gate. The trusted authorization root is supplied
// independently by the caller. The complete authorization history is verified
// and replayed at claim.epoch before the writer signature is accepted.
bool verifyClaim(
    const Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

} // namespace VAHExternalWriter

#endif
