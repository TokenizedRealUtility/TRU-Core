#include "vah_external_writer_materialize.h"

#include "blockchain.h"
#include "contract_storage.h"
#include "leveldb_storage.h"
#include "tx.h"

namespace VAHExternalWriterMaterialization {

// Internal production core defined in vah_external_writer_materialize.cpp.
bool materializeConfirmedWinnerProductionCore(
    LevelDBStorage& storage,
    ContractStorage& contractStorage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const VAHReconciliation::Candidate& winner,
    const VAHReconciliation::CanonicalView& view,
    const nlohmann::json& issuanceMetadata,
    const nlohmann::json& exactNewMetadata,
    std::string* reason);

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
    std::string* reason)
{
    if (reason) reason->clear();

    VAHReconciliation::Candidate winner;
    std::string confirmReason;
    if (!VAHExternalWriterAnchor::confirmPreparedAnchor(
            chain,
            storage,
            claim,
            authorizationHistory,
            trustedAuthorizationRootPubKeyHex,
            preparedTx,
            view,
            firstHeight,
            winner,
            &confirmReason))
    {
        if (reason) *reason = "VAH-03C confirmation failed: " + confirmReason;
        return false;
    }

    ContractStorage contractStorage(&storage);
    return materializeConfirmedWinnerProductionCore(
        storage,
        contractStorage,
        claim,
        authorizationHistory,
        trustedAuthorizationRootPubKeyHex,
        winner,
        view,
        issuanceMetadata,
        exactNewMetadata,
        reason);
}

} // namespace VAHExternalWriterMaterialization
