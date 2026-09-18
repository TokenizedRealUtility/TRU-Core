#pragma once

#include "vah_capabilities.h"

#include <cstdint>
#include <string>
#include <vector>

class ECDSAKey;

// VAH-01D/E: signed writer authorization history.
//
// This layer defines and verifies cryptographic authorization records. It does
// NOT activate external writers and it does NOT decide the canonical next
// token-evolution epoch across nodes. VAH-02 remains the activation gate for
// externally-originated writer records.
namespace VAHAuthorization {

enum class Action {
    AUTHORIZE,
    ROTATE,
    REVOKE,
    UNKNOWN
};

struct AuthorizationRecord {
    std::uint32_t format_version = 1;
    std::string token_id;
    std::uint64_t sequence = 0;
    std::uint64_t effective_epoch = 0;
    Action action = Action::UNKNOWN;

    // Writer identity. writer_id is derived from writer_pubkey_hex and is never
    // trusted as an independently supplied identity.
    std::string writer_id;
    std::string writer_pubkey_hex;
    std::string writer_class;
    std::vector<std::string> capabilities;

    // ROTATE points at the active writer ID being replaced. Empty otherwise.
    std::string replaces_writer_id;

    // Authorization history hash chain. Sequence 1 uses 64 zero hex chars.
    std::string previous_record_hash;

    // The trusted authorization root is supplied independently by the caller.
    // This field is committed into the record but cannot make itself trusted.
    std::string authorization_root_pubkey_hex;

    // SHA256 of the canonical unsigned record and strict-DER low-S ECDSA
    // signature by the authorization root over that exact 32-byte digest.
    std::string record_hash;
    std::string signature_der_hex;
};

struct HistoryVerificationResult {
    bool ok = false;
    std::uint64_t verified_records = 0;
    std::vector<std::string> errors;
};

std::string actionToString(Action action);
Action actionFromString(const std::string& value);

// Canonical 33-byte compressed SEC1 writer identity:
// SHA256("TRU_VAH_WRITER_ID_V1" || LP(pubkey_bytes)), lowercase hex.
std::string deriveWriterId(const std::string& writerPubKeyHex);

// Compute the canonical authorization record digest. This excludes record_hash
// and signature_der_hex, but includes all authorization semantics and the root
// public key. Returns exactly 32 bytes.
std::vector<unsigned char> authorizationDigest(const AuthorizationRecord& record);
std::string authorizationDigestHex(const AuthorizationRecord& record);

// Sign with the supplied authorization-root private key. The record's root
// public key must exactly match that key's compressed SEC1 public key.
bool signAuthorizationRecord(
    AuthorizationRecord& record,
    const ECDSAKey& authorizationRootKey,
    std::string* reason = nullptr
);

// Verify one record against an independently trusted root public key and the
// structural token/writer/capability policy.
bool verifyAuthorizationRecord(
    const AuthorizationRecord& record,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

// Verify the complete chained history and action-state transitions.
HistoryVerificationResult verifyAuthorizationHistory(
    const std::vector<AuthorizationRecord>& records,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex
);

// Historical authorization query. The complete history is first verified.
// Only records effective at or before `epoch` are replayed. Every changed field
// must be both structurally compatible and covered by an active capability.
bool isWriterAuthorizedAtEpoch(
    const std::vector<AuthorizationRecord>& records,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::uint64_t epoch,
    const std::string& writerPubKeyHex,
    const std::string& writerType,
    const std::vector<std::string>& changedFields,
    std::string* reason = nullptr
);

// Deterministic storage/debug representation. This is NOT the signed preimage;
// signatures always use authorizationDigest().
std::string serializeAuthorizationRecord(const AuthorizationRecord& record);
bool parseAuthorizationRecord(
    const std::string& encoded,
    AuthorizationRecord& out,
    std::string* reason = nullptr
);

} // namespace VAHAuthorization
