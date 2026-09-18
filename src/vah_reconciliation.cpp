#include "vah_reconciliation.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <tuple>

namespace {

bool isLowerHex(const std::string& s, std::size_t n) {
    if (s.size() != n) return false;
    for (const unsigned char c : s) {
        if (!std::isdigit(c) && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}

auto orderKey(const VAHReconciliation::Candidate& c) {
    return std::tie(
        c.blockHeight,
        c.txIndex,
        c.anchorTxid,
        c.newMetadataHash,
        c.recordHash);
}

std::string dedupeKey(const VAHReconciliation::Candidate& c) {
    return c.anchorTxid + "|" + c.blockHash + "|" +
           std::to_string(c.blockHeight) + "|" + std::to_string(c.txIndex) +
           "|" + c.newMetadataHash + "|" + c.recordHash;
}

bool isAllZeroHash(const std::string& value) {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](char c) { return c == '0'; });
}

} // namespace

namespace VAHReconciliation {

bool validateCandidate(
    const Candidate& c,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    std::string& reason)
{
    reason.clear();

    if (!isLowerHex(expectedTokenID, 16U)) {
        reason = "expected token id is not canonical 16-hex";
        return false;
    }
    if (expectedEpoch == 0U) {
        reason = "expected epoch must be >= 1";
        return false;
    }
    if (!isLowerHex(expectedPreviousMetadataHash, 64U)) {
        reason = "expected parent metadata hash is invalid";
        return false;
    }
    if (view.finalizedHeight == 0U ||
        !isLowerHex(view.finalizedBlockHash, 64U))
    {
        reason = "canonical finalized view is invalid";
        return false;
    }

    if (c.tokenID != expectedTokenID) {
        reason = "token id mismatch";
        return false;
    }
    if (c.epoch != expectedEpoch) {
        reason = "epoch mismatch";
        return false;
    }
    if (c.previousMetadataHash != expectedPreviousMetadataHash) {
        reason = "parent metadata hash mismatch";
        return false;
    }
    if (!isLowerHex(c.newMetadataHash, 64U) ||
        !isLowerHex(c.recordHash, 64U) ||
        !isLowerHex(c.anchorTxid, 64U) ||
        !isLowerHex(c.blockHash, 64U))
    {
        reason = "candidate hash/txid fields are invalid";
        return false;
    }
    if (c.blockHeight == 0U || c.blockHeight > view.finalizedHeight) {
        reason = "candidate is outside finalized active-chain prefix";
        return false;
    }

    return true;
}

bool validateStronglyBoundCandidate(
    const Candidate& c,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    std::string& reason)
{
    if (!validateCandidate(
            c, expectedTokenID, expectedEpoch, expectedPreviousMetadataHash,
            view, reason))
    {
        return false;
    }
    if (isAllZeroHash(c.recordHash)) {
        reason = "candidate record hash is not chain-committed";
        return false;
    }
    reason.clear();
    return true;
}

bool verifyCommittedRecordHash(
    const Candidate& candidate,
    const std::string& expectedRecordHash,
    std::string& reason)
{
    if (!isLowerHex(expectedRecordHash, 64U) || isAllZeroHash(expectedRecordHash)) {
        reason = "expected record hash is not a canonical committed hash";
        return false;
    }
    if (!isLowerHex(candidate.recordHash, 64U) || isAllZeroHash(candidate.recordHash)) {
        reason = "candidate record hash is not chain-committed";
        return false;
    }
    if (candidate.recordHash != expectedRecordHash) {
        reason = "candidate committed record hash mismatch";
        return false;
    }
    reason.clear();
    return true;
}

bool sameCanonicalIdentity(const Candidate& a, const Candidate& b) {
    return
        a.tokenID == b.tokenID &&
        a.epoch == b.epoch &&
        a.previousMetadataHash == b.previousMetadataHash &&
        a.newMetadataHash == b.newMetadataHash &&
        a.recordHash == b.recordHash &&
        a.anchorTxid == b.anchorTxid &&
        a.blockHash == b.blockHash &&
        a.blockHeight == b.blockHeight &&
        a.txIndex == b.txIndex;
}

ElectionResult electCanonicalCandidate(
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    const std::vector<Candidate>& candidates)
{
    ElectionResult out;

    if (candidates.size() > MAX_CANDIDATES_PER_EPOCH) {
        out.error = "candidate set exceeds bounded reconciliation limit";
        return out;
    }

    // Validate the view even when the candidate set is empty.
    Candidate probe;
    probe.tokenID = expectedTokenID;
    probe.epoch = expectedEpoch;
    probe.previousMetadataHash = expectedPreviousMetadataHash;
    probe.newMetadataHash = std::string(64U, '0');
    probe.recordHash = std::string(64U, '0');
    probe.anchorTxid = std::string(64U, '0');
    probe.blockHash = std::string(64U, '0');
    probe.blockHeight = 1U;

    std::string reason;
    if (view.finalizedHeight == 0U ||
        !isLowerHex(view.finalizedBlockHash, 64U) ||
        !isLowerHex(expectedTokenID, 16U) ||
        expectedEpoch == 0U ||
        !isLowerHex(expectedPreviousMetadataHash, 64U))
    {
        out.error = "invalid reconciliation input/view";
        return out;
    }

    std::vector<Candidate> eligible;
    std::set<std::string> seen;

    for (const auto& c : candidates) {
        if (!validateCandidate(
                c,
                expectedTokenID,
                expectedEpoch,
                expectedPreviousMetadataHash,
                view,
                reason))
        {
            out.rejected.push_back(c);
            continue;
        }

        const std::string key = dedupeKey(c);
        if (!seen.insert(key).second) {
            continue; // exact duplicate observation is harmless
        }
        eligible.push_back(c);
    }

    if (eligible.empty()) {
        out.ok = true;
        out.hasWinner = false;
        return out;
    }

    std::sort(
        eligible.begin(),
        eligible.end(),
        [](const Candidate& a, const Candidate& b) {
            return orderKey(a) < orderKey(b);
        });

    out.ok = true;
    out.hasWinner = true;
    out.winner = eligible.front();

    for (std::size_t i = 1; i < eligible.size(); ++i) {
        out.rejected.push_back(eligible[i]);
    }

    return out;
}

ElectionResult electStronglyBoundCanonicalCandidate(
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const CanonicalView& view,
    const std::vector<Candidate>& candidates)
{
    ElectionResult out;
    if (candidates.size() > MAX_CANDIDATES_PER_EPOCH) {
        out.error = "candidate set exceeds bounded reconciliation limit";
        return out;
    }

    std::vector<Candidate> stronglyBound;
    stronglyBound.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        std::string reason;
        if (validateStronglyBoundCandidate(
                candidate, expectedTokenID, expectedEpoch,
                expectedPreviousMetadataHash, view, reason))
        {
            stronglyBound.push_back(candidate);
        } else {
            out.rejected.push_back(candidate);
        }
    }

    ElectionResult elected = electCanonicalCandidate(
        expectedTokenID, expectedEpoch, expectedPreviousMetadataHash,
        view, stronglyBound);
    if (!elected.ok) {
        elected.rejected.insert(
            elected.rejected.begin(), out.rejected.begin(), out.rejected.end());
        return elected;
    }

    out.ok = true;
    out.hasWinner = elected.hasWinner;
    out.error = elected.error;
    if (elected.hasWinner) out.winner = elected.winner;
    out.rejected.insert(out.rejected.end(), elected.rejected.begin(), elected.rejected.end());
    return out;
}

} // namespace VAHReconciliation
