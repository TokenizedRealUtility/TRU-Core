#pragma once
#ifndef VAH_EXTERNAL_WRITER_ANCHOR_H
#define VAH_EXTERNAL_WRITER_ANCHOR_H

#include "vah_external_writer_stage.h"
#include "vah_observation.h"

#include <cstdint>
#include <string>
#include <vector>

class Blockchain;
class LevelDBStorage;
class Transaction;

namespace VAHExternalWriterAnchor {

constexpr std::size_t MAX_ANCHOR_TRANSACTION_OUTPUTS = 64U;
constexpr const char* EXTERNAL_WRITER_PROVIDER = "external_writer";
constexpr const char* EXTERNAL_WRITER_TRIGGER = "authorized_claim";

// Canonical TRU_EVOLVE_V2 identity for one VAH-03A claim. The claim's
// non-zero record_hash is the strong VAH-02D commitment.
VAHObservation::AnchorV2 canonicalAnchorForClaim(
    const VAHExternalWriter::Claim& claim);

std::string canonicalAnchorScriptForClaim(
    const VAHExternalWriter::Claim& claim);

// Pure transaction-output gate used before production broadcast. Exactly one
// evolution anchor is permitted and it must be the zero-value canonical V2
// script for the supplied claim. Other ordinary outputs (e.g. change) are OK.
bool verifyPreparedAnchorOutputs(
    const std::vector<VAHObservation::OutputSnapshot>& outputs,
    const VAHExternalWriter::Claim& claim,
    std::string* reason = nullptr);

// Pure confirmed-chain closure used by the DEV matrix. The exact submitted
// txid must win VAH-02D's strong election for token/epoch/parent.
bool admitConfirmedCanonicalClaim(
    const VAHExternalWriter::Claim& claim,
    const std::string& expectedTxid,
    const VAHReconciliation::CanonicalView& view,
    const std::vector<VAHObservation::BlockSnapshot>& blocks,
    VAHReconciliation::Candidate& winnerOut,
    std::string* reason = nullptr);

// Production internal emission primitive. No RPC/P2P caller is enabled by
// VAH-03C. The claim must already exist byte-identically in VAH-03B staging,
// must still pass VAH-03A authorization, and the supplied transaction must be
// fully materialized/funded/signed with exactly one canonical V2 anchor.
bool submitPreparedAnchor(
    Blockchain& chain,
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const Transaction& preparedTx,
    std::string* reason = nullptr);

// Production confirmed-active-chain admission. This is read-only with respect
// to TOKEN_EVOLUTION and VAH pending state. The exact prepared txid must be the
// strongly-bound canonical winner at/below the caller-supplied finalized view.
bool confirmPreparedAnchor(
    const Blockchain& chain,
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const Transaction& preparedTx,
    const VAHReconciliation::CanonicalView& view,
    std::uint64_t firstHeight,
    VAHReconciliation::Candidate& winnerOut,
    std::string* reason = nullptr);

} // namespace VAHExternalWriterAnchor

#endif
