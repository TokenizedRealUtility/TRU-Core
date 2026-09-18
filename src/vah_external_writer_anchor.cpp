#include "vah_external_writer_anchor.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace {

void setReason(std::string* reason, const std::string& text) {
    if (reason) *reason = text;
}

bool isLowerHex(const std::string& s, std::size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool claimIdentityLooksCanonical(const VAHExternalWriter::Claim& claim) {
    return claim.format_version == 1U &&
        isLowerHex(claim.token_id, 16U) &&
        (claim.token_type == "SFT" || claim.token_type == "NCFT") &&
        claim.epoch > 0U &&
        isLowerHex(claim.previous_metadata_hash, 64U) &&
        isLowerHex(claim.new_metadata_hash, 64U) &&
        isLowerHex(claim.record_hash, 64U) &&
        claim.record_hash != std::string(64U, '0') &&
        claim.record_hash == VAHExternalWriter::claimDigestHex(claim);
}

} // namespace

namespace VAHExternalWriterAnchor {

VAHObservation::AnchorV2 canonicalAnchorForClaim(
    const VAHExternalWriter::Claim& claim)
{
    if (!claimIdentityLooksCanonical(claim)) {
        throw std::invalid_argument("external-writer claim identity is not canonical");
    }

    VAHObservation::AnchorV2 anchor;
    anchor.tokenID = claim.token_id;
    anchor.tokenType = claim.token_type;
    anchor.epoch = claim.epoch;
    anchor.provider = EXTERNAL_WRITER_PROVIDER;
    anchor.trigger = EXTERNAL_WRITER_TRIGGER;
    anchor.previousMetadataHash = claim.previous_metadata_hash;
    anchor.newMetadataHash = claim.new_metadata_hash;
    anchor.recordHash = claim.record_hash;
    return anchor;
}

std::string canonicalAnchorScriptForClaim(
    const VAHExternalWriter::Claim& claim)
{
    return VAHObservation::encodeEvolutionAnchorV2(
        canonicalAnchorForClaim(claim));
}

bool verifyPreparedAnchorOutputs(
    const std::vector<VAHObservation::OutputSnapshot>& outputs,
    const VAHExternalWriter::Claim& claim,
    std::string* reason)
{
    if (reason) reason->clear();
    if (outputs.empty() || outputs.size() > MAX_ANCHOR_TRANSACTION_OUTPUTS) {
        setReason(reason, "prepared anchor transaction output count is invalid");
        return false;
    }

    std::string expectedScript;
    try {
        expectedScript = canonicalAnchorScriptForClaim(claim);
    } catch (const std::exception& e) {
        setReason(reason, e.what());
        return false;
    }

    std::size_t exactMatches = 0U;
    for (const auto& output : outputs) {
        if (output.scriptPubKey == expectedScript) {
            if (output.amount != 0U) {
                setReason(reason, "TRU_EVOLVE_V2 anchor output must carry zero TRU");
                return false;
            }
            ++exactMatches;
            continue;
        }

        VAHObservation::AnchorV2 v2;
        VAHObservation::AnchorV1 v1;
        std::string parseReason;
        const auto v2Status = VAHObservation::parseEvolutionAnchorV2(
            output.scriptPubKey, v2, parseReason);
        if (v2Status != VAHObservation::AnchorParseStatus::NotEvolutionAnchor) {
            setReason(reason, "prepared transaction contains a second or mismatched TRU_EVOLVE_V2 anchor");
            return false;
        }

        parseReason.clear();
        const auto v1Status = VAHObservation::parseEvolutionAnchorV1(
            output.scriptPubKey, v1, parseReason);
        if (v1Status != VAHObservation::AnchorParseStatus::NotEvolutionAnchor) {
            setReason(reason, "prepared transaction mixes V1/V2 evolution anchors");
            return false;
        }
    }

    if (exactMatches != 1U) {
        setReason(reason, "prepared transaction does not contain exactly one canonical external-writer V2 anchor");
        return false;
    }

    return true;
}

bool admitConfirmedCanonicalClaim(
    const VAHExternalWriter::Claim& claim,
    const std::string& expectedTxid,
    const VAHReconciliation::CanonicalView& view,
    const std::vector<VAHObservation::BlockSnapshot>& blocks,
    VAHReconciliation::Candidate& winnerOut,
    std::string* reason)
{
    winnerOut = VAHReconciliation::Candidate{};
    if (reason) reason->clear();

    if (!claimIdentityLooksCanonical(claim) || !isLowerHex(expectedTxid, 64U)) {
        setReason(reason, "claim/txid identity is not canonical");
        return false;
    }

    VAHObservation::ObservationRequest request;
    request.expectedTokenID = claim.token_id;
    request.expectedEpoch = claim.epoch;
    request.expectedPreviousMetadataHash = claim.previous_metadata_hash;
    request.view = view;

    const auto observed = VAHObservation::observeConfirmedActiveRange(
        request, blocks);
    if (!observed.ok) {
        setReason(reason, "confirmed active-chain observation failed: " + observed.error);
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
            election.winner, claim.record_hash, bindingReason))
    {
        setReason(reason, "canonical winner does not commit staged claim record_hash");
        return false;
    }

    if (election.winner.newMetadataHash != claim.new_metadata_hash) {
        setReason(reason, "canonical winner new metadata hash differs from staged claim");
        return false;
    }
    if (election.winner.anchorTxid != expectedTxid) {
        setReason(reason, "exact submitted anchor txid is not the canonical winner");
        return false;
    }

    winnerOut = election.winner;
    return true;
}

} // namespace VAHExternalWriterAnchor
