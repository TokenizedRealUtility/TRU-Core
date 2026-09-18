#include "vah_reconciliation_store.h"

#include "leveldb_storage.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <vector>

namespace VAHDurableReconciliation {
namespace {

constexpr const char* MAGIC = "TRU_VAH_RECONCILIATION_V1";

// Serialize local commit decisions so two in-process callers cannot both
// observe an absent epoch and race conflicting first writes.
std::mutex g_reconciliationCommitMutex;

bool isLowerHex(const std::string& s, std::size_t n) {
    if (s.size() != n) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isdigit(c) || (c >= 'a' && c <= 'f');
    });
}

bool parseU64(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    if (s.size() > 1U && s.front() == '0') return false;
    uint64_t value = 0;
    for (unsigned char c : s) {
        if (!std::isdigit(c)) return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10U) return false;
        value = value * 10U + digit;
    }
    out = value;
    return true;
}

bool validTokenID(const std::string& s) { return isLowerHex(s, 16U); }
bool validHash(const std::string& s) { return isLowerHex(s, 64U); }

std::string serialize(const DurableResult& r) {
    std::ostringstream out;
    out << MAGIC << '\n'
        << "token_id=" << r.tokenID << '\n'
        << "epoch=" << r.epoch << '\n'
        << "previous_metadata_hash=" << r.previousMetadataHash << '\n'
        << "finalized_height=" << r.view.finalizedHeight << '\n'
        << "finalized_block_hash=" << r.view.finalizedBlockHash << '\n'
        << "winner_new_metadata_hash=" << r.winner.newMetadataHash << '\n'
        << "winner_record_hash=" << r.winner.recordHash << '\n'
        << "winner_anchor_txid=" << r.winner.anchorTxid << '\n'
        << "winner_block_hash=" << r.winner.blockHash << '\n'
        << "winner_block_height=" << r.winner.blockHeight << '\n'
        << "winner_tx_index=" << r.winner.txIndex << '\n';
    return out.str();
}

bool takeField(const std::vector<std::string>& lines, std::size_t index,
               const char* prefix, std::string& out) {
    if (index >= lines.size()) return false;
    const std::string p(prefix);
    if (lines[index].compare(0, p.size(), p) != 0) return false;
    out = lines[index].substr(p.size());
    return true;
}

bool parse(const std::string& encoded, DurableResult& out, std::string& reason) {
    std::vector<std::string> lines;
    std::istringstream in(encoded);
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    if (lines.size() != 12U || lines[0] != MAGIC) {
        reason = "non-canonical durable reconciliation envelope";
        return false;
    }

    DurableResult r;
    std::string epoch, finalizedHeight, winnerBlockHeight, winnerTxIndex;
    if (!takeField(lines, 1, "token_id=", r.tokenID) ||
        !takeField(lines, 2, "epoch=", epoch) ||
        !takeField(lines, 3, "previous_metadata_hash=", r.previousMetadataHash) ||
        !takeField(lines, 4, "finalized_height=", finalizedHeight) ||
        !takeField(lines, 5, "finalized_block_hash=", r.view.finalizedBlockHash) ||
        !takeField(lines, 6, "winner_new_metadata_hash=", r.winner.newMetadataHash) ||
        !takeField(lines, 7, "winner_record_hash=", r.winner.recordHash) ||
        !takeField(lines, 8, "winner_anchor_txid=", r.winner.anchorTxid) ||
        !takeField(lines, 9, "winner_block_hash=", r.winner.blockHash) ||
        !takeField(lines, 10, "winner_block_height=", winnerBlockHeight) ||
        !takeField(lines, 11, "winner_tx_index=", winnerTxIndex)) {
        reason = "durable reconciliation field layout mismatch";
        return false;
    }

    if (!parseU64(epoch, r.epoch) ||
        !parseU64(finalizedHeight, r.view.finalizedHeight) ||
        !parseU64(winnerBlockHeight, r.winner.blockHeight) ||
        !parseU64(winnerTxIndex, r.winner.txIndex)) {
        reason = "durable reconciliation integer is non-canonical";
        return false;
    }

    if (!validTokenID(r.tokenID) || !validHash(r.previousMetadataHash) ||
        !validHash(r.view.finalizedBlockHash) || !validHash(r.winner.newMetadataHash) ||
        !validHash(r.winner.recordHash) || !validHash(r.winner.anchorTxid) ||
        !validHash(r.winner.blockHash)) {
        reason = "durable reconciliation contains malformed identity";
        return false;
    }

    r.winner.tokenID = r.tokenID;
    r.winner.epoch = r.epoch;
    r.winner.previousMetadataHash = r.previousMetadataHash;

    std::string validationReason;
    if (!VAHReconciliation::validateCandidate(
            r.winner, r.tokenID, r.epoch, r.previousMetadataHash,
            r.view, validationReason)) {
        reason = "durable winner fails canonical validation: " + validationReason;
        return false;
    }

    if (serialize(r) != encoded) {
        reason = "durable reconciliation serialization is not canonical";
        return false;
    }

    out = std::move(r);
    reason.clear();
    return true;
}

} // namespace

std::string reconciliationKey(const std::string& tokenID, uint64_t epoch) {
    std::ostringstream key;
    key << "TOKEN:VAH_RECON:" << tokenID << ":epoch:"
        << std::setw(20) << std::setfill('0') << epoch;
    return key.str();
}

bool sameDurableIdentity(const DurableResult& a, const DurableResult& b) {
    return a.tokenID == b.tokenID &&
           a.epoch == b.epoch &&
           a.previousMetadataHash == b.previousMetadataHash &&
           a.view.finalizedHeight == b.view.finalizedHeight &&
           a.view.finalizedBlockHash == b.view.finalizedBlockHash &&
           VAHReconciliation::sameCanonicalIdentity(a.winner, b.winner);
}

bool persistCanonicalResult(
    LevelDBStorage& storage,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const VAHReconciliation::CanonicalView& view,
    const VAHReconciliation::ElectionResult& election,
    std::string& reason) {

    std::lock_guard<std::mutex> commitLock(g_reconciliationCommitMutex);

    if (!validTokenID(expectedTokenID) || !validHash(expectedPreviousMetadataHash) ||
        !validHash(view.finalizedBlockHash)) {
        reason = "invalid durable reconciliation request identity";
        return false;
    }
    if (!election.ok || !election.hasWinner) {
        reason = "cannot persist reconciliation without canonical winner";
        return false;
    }

    std::string validationReason;
    if (!VAHReconciliation::validateCandidate(
            election.winner, expectedTokenID, expectedEpoch,
            expectedPreviousMetadataHash, view, validationReason)) {
        reason = "winner fails persistence validation: " + validationReason;
        return false;
    }

    DurableResult desired;
    desired.tokenID = expectedTokenID;
    desired.epoch = expectedEpoch;
    desired.previousMetadataHash = expectedPreviousMetadataHash;
    desired.view = view;
    desired.winner = election.winner;

    const std::string key = reconciliationKey(expectedTokenID, expectedEpoch);
    if (storage.exists("contract:" + key)) {
        std::string existingEncoded;
        if (!storage.getContract(key, existingEncoded)) {
            reason = "existing durable reconciliation is unreadable/corrupt";
            return false;
        }
        DurableResult existing;
        if (!parse(existingEncoded, existing, reason)) return false;
        if (!sameDurableIdentity(existing, desired)) {
            reason = "conflicting durable reconciliation already exists";
            return false;
        }
        reason.clear();
        return true;
    }

    const std::string encoded = serialize(desired);
    if (!storage.putContract(key, encoded)) {
        reason = "durable reconciliation write failed";
        return false;
    }

    std::string readback;
    if (!storage.getContract(key, readback) || readback != encoded) {
        reason = "durable reconciliation readback mismatch";
        return false;
    }
    DurableResult verified;
    if (!parse(readback, verified, reason) || !sameDurableIdentity(verified, desired)) {
        if (reason.empty()) reason = "durable reconciliation verification mismatch";
        return false;
    }

    reason.clear();
    return true;
}

bool loadCanonicalResult(
    const LevelDBStorage& storage,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    DurableResult& out,
    std::string& reason) {

    if (!validTokenID(expectedTokenID) || !validHash(expectedPreviousMetadataHash)) {
        reason = "invalid durable reconciliation lookup identity";
        return false;
    }

    std::string encoded;
    if (!storage.getContract(reconciliationKey(expectedTokenID, expectedEpoch), encoded)) {
        reason = "durable reconciliation not found or checksum-invalid";
        return false;
    }

    DurableResult loaded;
    if (!parse(encoded, loaded, reason)) return false;
    if (loaded.tokenID != expectedTokenID || loaded.epoch != expectedEpoch ||
        loaded.previousMetadataHash != expectedPreviousMetadataHash) {
        reason = "durable reconciliation lookup identity mismatch";
        return false;
    }

    out = std::move(loaded);
    reason.clear();
    return true;
}

} // namespace VAHDurableReconciliation
