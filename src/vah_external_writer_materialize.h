#pragma once
#ifndef VAH_EXTERNAL_WRITER_MATERIALIZE_H
#define VAH_EXTERNAL_WRITER_MATERIALIZE_H

#include "vah_external_writer_anchor.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

class Blockchain;
class ContractStorage;
class LevelDBStorage;
class Transaction;

namespace VAHExternalWriterMaterialization {

constexpr const char* MATERIALIZATION_FORMAT = "TRU_VAH_EXTERNAL_MATERIALIZATION_V1";
constexpr const char* TOKEN_EVOLUTION_FORMAT = "TRU_TOKEN_EVOLVE_V1";
constexpr std::uint64_t EXTERNAL_RECORD_FORMAT_VERSION = 3U;

// Production closeout primitive. The exact 03B-staged claim is reverified,
// 03C independently re-confirms the supplied prepared transaction as the
// canonical strongly-bound active-chain winner, and only then may the exact
// caller-supplied metadata document cross into TOKEN_EVOLUTION.
//
// This function has no RPC/P2P caller in VAH-03D and never deletes the staged
// claim. The staged claim remains append-only audit evidence.
bool materializeConfirmedAnchor(
    const Blockchain& chain,
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const Transaction& preparedTx,
    const VAHReconciliation::CanonicalView& view,
    std::uint64_t firstHeight,
    const nlohmann::json& issuanceMetadata,
    const nlohmann::json& exactNewMetadata,
    std::string* reason = nullptr);

std::string materializationCheckpointKey(
    const std::string& tokenID,
    std::uint64_t epoch);

#ifdef TRU_VAH_03D_TEST_HOOKS
// DEV-only entry point: exercises the exact durable materialization core with
// a caller-supplied canonical winner. Production builds do not expose this.
bool materializeConfirmedWinnerForTest(
    LevelDBStorage& storage,
    ContractStorage& contractStorage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const VAHReconciliation::Candidate& winner,
    const VAHReconciliation::CanonicalView& view,
    const nlohmann::json& issuanceMetadata,
    const nlohmann::json& exactNewMetadata,
    std::string* reason = nullptr);
#endif

} // namespace VAHExternalWriterMaterialization

#endif
