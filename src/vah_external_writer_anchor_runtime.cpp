#include "vah_external_writer_anchor.h"

#include "blockchain.h"
#include "leveldb_storage.h"
#include "tx.h"

#include <algorithm>
#include <cctype>

namespace {

void setReason(std::string* reason, const std::string& text) {
    if (reason) *reason = text;
}

bool isLowerHex64(const std::string& s) {
    return s.size() == 64U && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::vector<VAHObservation::OutputSnapshot> snapshotOutputs(const Transaction& tx) {
    std::vector<VAHObservation::OutputSnapshot> outputs;
    outputs.reserve(tx.vout.size());
    for (const auto& out : tx.vout) {
        VAHObservation::OutputSnapshot snap;
        snap.amount = out.amount;
        snap.scriptPubKey = out.scriptPubKey;
        outputs.push_back(std::move(snap));
    }
    return outputs;
}

bool exactClaimIsStaged(
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& history,
    const std::string& root,
    std::string* reason)
{
    const auto loaded = VAHExternalWriterStage::loadPendingClaims(
        storage, claim.token_id, claim.epoch, history, root);
    if (!loaded.ok) {
        setReason(reason, loaded.errors.empty() ?
            "pending claim reconstruction failed" : loaded.errors.front());
        return false;
    }

    const std::string expected = VAHExternalWriterStage::serializePendingClaim(claim);
    for (const auto& staged : loaded.claims) {
        if (staged.record_hash == claim.record_hash &&
            VAHExternalWriterStage::serializePendingClaim(staged) == expected)
        {
            return true;
        }
    }

    setReason(reason, "exact external-writer claim is not durably staged");
    return false;
}

bool validatePreparedTransaction(
    const Transaction& preparedTx,
    const VAHExternalWriter::Claim& claim,
    std::string& txid,
    std::string* reason)
{
    if (preparedTx.isCoinbase || preparedTx.vin.empty()) {
        setReason(reason, "prepared external-writer anchor must be a funded non-coinbase transaction");
        return false;
    }

    Transaction canonical = preparedTx;
    canonical.computeTxId();
    txid = canonical.txid;
    if (!isLowerHex64(txid) || preparedTx.txid != txid) {
        setReason(reason, "prepared anchor txid is missing or does not match canonical serialization");
        return false;
    }

    if (!VAHExternalWriterAnchor::verifyPreparedAnchorOutputs(
            snapshotOutputs(preparedTx), claim, reason))
    {
        return false;
    }

    return true;
}

} // namespace

namespace VAHExternalWriterAnchor {

bool submitPreparedAnchor(
    Blockchain& chain,
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const Transaction& preparedTx,
    std::string* reason)
{
    if (reason) reason->clear();

    std::string gateReason;
    if (!VAHExternalWriter::verifyClaim(
            claim, authorizationHistory, trustedAuthorizationRootPubKeyHex, &gateReason))
    {
        setReason(reason, "VAH-03A claim verification failed: " + gateReason);
        return false;
    }

    if (!exactClaimIsStaged(
            storage, claim, authorizationHistory,
            trustedAuthorizationRootPubKeyHex, reason))
    {
        return false;
    }

    std::string txid;
    if (!validatePreparedTransaction(preparedTx, claim, txid, reason)) {
        return false;
    }

    if (!chain.broadcastTransaction(preparedTx)) {
        setReason(reason, "prepared TRU_EVOLVE_V2 anchor was rejected by local mempool/broadcast path");
        return false;
    }

    return true;
}

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
    std::string* reason)
{
    winnerOut = VAHReconciliation::Candidate{};
    if (reason) reason->clear();

    std::string gateReason;
    if (!VAHExternalWriter::verifyClaim(
            claim, authorizationHistory, trustedAuthorizationRootPubKeyHex, &gateReason))
    {
        setReason(reason, "VAH-03A claim verification failed: " + gateReason);
        return false;
    }
    if (!exactClaimIsStaged(
            storage, claim, authorizationHistory,
            trustedAuthorizationRootPubKeyHex, reason))
    {
        return false;
    }

    std::string txid;
    if (!validatePreparedTransaction(preparedTx, claim, txid, reason)) {
        return false;
    }

    VAHObservation::ObservationRequest request;
    request.expectedTokenID = claim.token_id;
    request.expectedEpoch = claim.epoch;
    request.expectedPreviousMetadataHash = claim.previous_metadata_hash;
    request.view = view;

    const auto observed = VAHObservation::observeLocalActiveChain(
        chain, request, firstHeight);
    if (!observed.ok) {
        setReason(reason, "local confirmed active-chain observation failed: " + observed.error);
        return false;
    }

    const auto election = VAHReconciliation::electStronglyBoundCanonicalCandidate(
        claim.token_id,
        claim.epoch,
        claim.previous_metadata_hash,
        view,
        observed.candidates);
    if (!election.ok || !election.hasWinner) {
        setReason(reason, election.error.empty() ?
            "no strongly-bound canonical winner" : election.error);
        return false;
    }

    std::string bindingReason;
    if (!VAHReconciliation::verifyCommittedRecordHash(
            election.winner, claim.record_hash, bindingReason) ||
        election.winner.newMetadataHash != claim.new_metadata_hash ||
        election.winner.anchorTxid != txid)
    {
        setReason(reason, "exact submitted V2 anchor is not the canonical confirmed winner");
        return false;
    }

    winnerOut = election.winner;
    return true;
}

} // namespace VAHExternalWriterAnchor
