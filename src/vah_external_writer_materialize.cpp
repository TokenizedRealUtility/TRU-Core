#include "vah_external_writer_materialize.h"

#include "contract_storage.h"
#include "leveldb_storage.h"
#include "token_evolution.h"
#include "vah_capabilities.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

namespace {

using json = nlohmann::json;

constexpr std::size_t HASH_HEX = 64U;
constexpr std::size_t TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS = 256U;
constexpr std::size_t TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES = 65536U;
std::mutex g_materializationCommitMutex;

void setReason(std::string* reason, const std::string& text) {
    if (reason) *reason = text;
}

bool isLowerHex(const std::string& s, std::size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::string sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2U);
    for (unsigned char b : hash) {
        out.push_back(HEX[(b >> 4U) & 0x0fU]);
        out.push_back(HEX[b & 0x0fU]);
    }
    return out;
}

std::string epoch20(std::uint64_t epoch) {
    std::ostringstream oss;
    oss << std::setw(20) << std::setfill('0') << epoch;
    return oss.str();
}

std::string evolutionEpochKey(const std::string& token, std::uint64_t epoch) {
    return "epoch:" + token + ":" + std::to_string(epoch);
}

std::string latestKey(const std::string& token) {
    return "latest:" + token;
}

std::string anchorTxKey(const std::string& token, std::uint64_t epoch) {
    return "anchor_tx:" + token + ":" + std::to_string(epoch);
}

std::string anchorReceiptKey(const std::string& token, std::uint64_t epoch) {
    return "anchor_receipt:" + token + ":" + std::to_string(epoch);
}

std::string queueItem(const std::string& token, std::uint64_t epoch) {
    return token + ":" + std::to_string(epoch);
}

std::string fullEvolutionKey(const std::string& key) {
    return "contract:TOKEN:EVOLUTION:" + key;
}

std::string fullMaterializationKey(const std::string& key) {
    return "contract:TOKEN:VAH_MATERIALIZED:" + key;
}

bool strictReadCanonicalContract(
    const LevelDBStorage& storage,
    const std::string& fullKey,
    std::string& value,
    bool& found,
    std::string* reason)
{
    std::string raw;
    found = false;
    if (!storage.getRaw(fullKey, raw, found)) {
        setReason(reason, "raw LevelDB read failed for " + fullKey);
        return false;
    }
    if (!found) {
        value.clear();
        return true;
    }

    const auto delim = raw.find('|');
    if (delim == std::string::npos) {
        setReason(reason, "canonical checksum envelope missing for " + fullKey);
        return false;
    }

    const std::string storedChecksum = raw.substr(0U, delim);
    value = raw.substr(delim + 1U);
    if (storedChecksum != storage.computeDataChecksum(value)) {
        setReason(reason, "strict canonical checksum mismatch for " + fullKey);
        return false;
    }
    return true;
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

bool parseCanonicalQueue(
    const std::string& raw,
    json& queue,
    std::string* reason)
{
    if (raw.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES) {
        setReason(reason, "anchor_queue exceeds byte bound");
        return false;
    }
    try {
        queue = json::parse(raw);
    } catch (...) {
        setReason(reason, "anchor_queue JSON is invalid");
        return false;
    }
    if (!queue.is_array() || queue.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS) {
        setReason(reason, "anchor_queue is not a bounded array");
        return false;
    }
    std::set<std::string> seen;
    for (const auto& item : queue) {
        if (!item.is_string()) {
            setReason(reason, "anchor_queue contains non-string item");
            return false;
        }
        const std::string text = item.get<std::string>();
        const auto colon = text.rfind(':');
        if (colon == std::string::npos || colon == 0U || colon + 1U >= text.size()) {
            setReason(reason, "anchor_queue contains malformed item");
            return false;
        }
        const std::string token = text.substr(0U, colon);
        const std::string epochText = text.substr(colon + 1U);
        if (!(token.size() == 8U || token.size() == 16U) ||
            !std::all_of(token.begin(), token.end(), [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            }) || epochText.empty() || epochText[0] == '0' ||
            !std::all_of(epochText.begin(), epochText.end(), [](unsigned char c) {
                return c >= '0' && c <= '9';
            }))
        {
            setReason(reason, "anchor_queue contains malformed item");
            return false;
        }
        try {
            const auto epoch = std::stoull(epochText);
            if (epoch == 0U) throw std::runtime_error("zero epoch");
        } catch (...) {
            setReason(reason, "anchor_queue contains invalid epoch");
            return false;
        }
        if (!seen.insert(text).second) {
            setReason(reason, "anchor_queue contains duplicate item");
            return false;
        }
    }
    return true;
}

bool validateWinner(
    const VAHExternalWriter::Claim& claim,
    const VAHReconciliation::Candidate& winner,
    const VAHReconciliation::CanonicalView& view,
    std::string* reason)
{
    std::string why;
    if (!VAHReconciliation::validateStronglyBoundCandidate(
            winner,
            claim.token_id,
            claim.epoch,
            claim.previous_metadata_hash,
            view,
            why))
    {
        setReason(reason, "confirmed winner invalid: " + why);
        return false;
    }
    if (winner.newMetadataHash != claim.new_metadata_hash ||
        winner.recordHash != claim.record_hash)
    {
        setReason(reason, "confirmed winner does not bind exact staged claim");
        return false;
    }
    return true;
}

bool validateMetadataDelta(
    const VAHExternalWriter::Claim& claim,
    const json& parent,
    const json& next,
    std::string* reason)
{
    if (!parent.is_object() || !next.is_object()) {
        setReason(reason, "parent/new metadata must be JSON objects");
        return false;
    }

    if (next.value("evolution_epoch", "") != std::to_string(claim.epoch)) {
        setReason(reason, "new metadata evolution_epoch does not equal claim epoch");
        return false;
    }

    if (sha256Hex(next.dump()) != claim.new_metadata_hash) {
        setReason(reason, "exact metadata document does not match confirmed new_metadata_hash");
        return false;
    }

    const std::set<std::string> claimed(
        claim.changed_fields.begin(), claim.changed_fields.end());
    std::set<std::string> actual;

    for (auto it = parent.begin(); it != parent.end(); ++it) {
        if (!next.contains(it.key())) {
            setReason(reason, "external materialization may not delete metadata field: " + it.key());
            return false;
        }
        if (next.at(it.key()) != it.value()) actual.insert(it.key());
    }
    for (auto it = next.begin(); it != next.end(); ++it) {
        if (!parent.contains(it.key())) actual.insert(it.key());
    }

    if (actual.erase("evolution_epoch") != 1U) {
        setReason(reason, "external materialization must advance only the system evolution_epoch plus claimed fields");
        return false;
    }

    if (actual != claimed) {
        setReason(reason, "actual metadata delta differs from signed changed_fields");
        return false;
    }

    for (const auto& field : claim.changed_fields) {
        if (!next.contains(field) || !next.at(field).is_string() ||
            !VAHCapabilities::writerClassMayHoldFieldCapability(
                claim.token_type, claim.writer_class, field))
        {
            setReason(reason, "materialized field/value violates writer capability: " + field);
            return false;
        }
    }

    return true;
}

json buildEvolutionRecord(
    const VAHExternalWriter::Claim& claim,
    const VAHReconciliation::Candidate& winner,
    const json& metadata)
{
    json updates = json::object();
    for (const auto& field : claim.changed_fields) updates[field] = metadata.at(field);

    return json{
        {"format", VAHExternalWriterMaterialization::TOKEN_EVOLUTION_FORMAT},
        {"record_format_version", VAHExternalWriterMaterialization::EXTERNAL_RECORD_FORMAT_VERSION},
        {"status", "materialized"},
        {"tokenID", claim.token_id},
        {"type", claim.token_type},
        {"writer_type", claim.writer_class},
        {"provider", VAHExternalWriterAnchor::EXTERNAL_WRITER_PROVIDER},
        {"trigger", VAHExternalWriterAnchor::EXTERNAL_WRITER_TRIGGER},
        {"writer_id", claim.writer_id},
        {"writer_pubkey_hex", claim.writer_pubkey_hex},
        {"external_claim_hash", claim.record_hash},
        {"changed_fields", claim.changed_fields},
        {"epoch_before", claim.epoch - 1U},
        {"epoch_after", claim.epoch},
        {"previous_metadata_hash", claim.previous_metadata_hash},
        {"new_metadata_hash", claim.new_metadata_hash},
        {"updated_fields", updates},
        {"metadata", metadata},
        {"anchor_txid", winner.anchorTxid},
        {"anchor_block_hash", winner.blockHash},
        {"anchor_block_height", winner.blockHeight},
        {"anchor_tx_index", winner.txIndex}
    };
}

json buildReceipt(
    const VAHExternalWriter::Claim& claim,
    const VAHReconciliation::Candidate& winner)
{
    return json{
        {"format", "TRU_TOKEN_EVOLVE_ANCHOR_RECEIPT_V1"},
        {"status", "submitted"},
        {"tokenID", claim.token_id},
        {"epoch", claim.epoch},
        {"new_metadata_hash", claim.new_metadata_hash},
        {"record_hash", claim.record_hash},
        {"txid", winner.anchorTxid}
    };
}

json buildCheckpoint(
    const VAHExternalWriter::Claim& claim,
    const VAHReconciliation::Candidate& winner,
    const VAHReconciliation::CanonicalView& view,
    const std::string& evolutionRecordHash,
    const std::string& receiptHash)
{
    return json{
        {"format", VAHExternalWriterMaterialization::MATERIALIZATION_FORMAT},
        {"token_id", claim.token_id},
        {"epoch", claim.epoch},
        {"previous_metadata_hash", claim.previous_metadata_hash},
        {"new_metadata_hash", claim.new_metadata_hash},
        {"claim_record_hash", claim.record_hash},
        {"evolution_record_hash", evolutionRecordHash},
        {"anchor_txid", winner.anchorTxid},
        {"anchor_block_hash", winner.blockHash},
        {"anchor_block_height", winner.blockHeight},
        {"anchor_tx_index", winner.txIndex},
        {"finalized_height", view.finalizedHeight},
        {"finalized_block_hash", view.finalizedBlockHash},
        {"anchor_receipt_hash", receiptHash}
    };
}

bool verifyExactReplay(
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const VAHReconciliation::Candidate& winner,
    const json& exactNewMetadata,
    std::string* reason)
{
    const std::string epochKey = evolutionEpochKey(claim.token_id, claim.epoch);
    const std::string checkpointKey =
        VAHExternalWriterMaterialization::materializationCheckpointKey(
            claim.token_id, claim.epoch);

    std::string epochRaw;
    std::string latestRaw;
    std::string receiptRaw;
    std::string anchorTxRaw;
    std::string queueRaw;
    std::string checkpointRaw;
    bool foundEpoch = false;
    bool foundLatest = false;
    bool foundReceipt = false;
    bool foundAnchorTx = false;
    bool foundQueue = false;
    bool foundCheckpoint = false;

    if (!strictReadCanonicalContract(storage, fullEvolutionKey(epochKey), epochRaw, foundEpoch, reason) ||
        !strictReadCanonicalContract(storage, fullEvolutionKey(latestKey(claim.token_id)), latestRaw, foundLatest, reason) ||
        !strictReadCanonicalContract(storage, fullEvolutionKey(anchorReceiptKey(claim.token_id, claim.epoch)), receiptRaw, foundReceipt, reason) ||
        !strictReadCanonicalContract(storage, fullEvolutionKey(anchorTxKey(claim.token_id, claim.epoch)), anchorTxRaw, foundAnchorTx, reason) ||
        !strictReadCanonicalContract(storage, fullEvolutionKey("anchor_queue"), queueRaw, foundQueue, reason) ||
        !strictReadCanonicalContract(storage, fullMaterializationKey(checkpointKey), checkpointRaw, foundCheckpoint, reason))
    {
        return false;
    }

    if (!foundEpoch || !foundLatest || !foundReceipt || !foundAnchorTx ||
        !foundQueue || !foundCheckpoint ||
        anchorTxRaw != winner.anchorTxid)
    {
        setReason(reason, "incomplete/conflicting existing external materialization");
        return false;
    }

    json record;
    json latest;
    json receipt;
    json checkpoint;
    json queue;
    try {
        record = json::parse(epochRaw);
        latest = json::parse(latestRaw);
        receipt = json::parse(receiptRaw);
        checkpoint = json::parse(checkpointRaw);
    } catch (...) {
        setReason(reason, "existing materialization JSON is invalid");
        return false;
    }
    if (!parseCanonicalQueue(queueRaw, queue, reason)) return false;

    if (!record.is_object() ||
        record.value("format", "") != VAHExternalWriterMaterialization::TOKEN_EVOLUTION_FORMAT ||
        record.value("record_format_version", 0ULL) != VAHExternalWriterMaterialization::EXTERNAL_RECORD_FORMAT_VERSION ||
        record.value("status", "") != "materialized" ||
        record.value("tokenID", "") != claim.token_id ||
        record.value("type", "") != claim.token_type ||
        record.value("writer_type", "") != claim.writer_class ||
        record.value("writer_id", "") != claim.writer_id ||
        record.value("writer_pubkey_hex", "") != claim.writer_pubkey_hex ||
        record.value("external_claim_hash", "") != claim.record_hash ||
        record.value("previous_metadata_hash", "") != claim.previous_metadata_hash ||
        record.value("new_metadata_hash", "") != claim.new_metadata_hash ||
        record.value("anchor_txid", "") != winner.anchorTxid ||
        record.value("anchor_block_hash", "") != winner.blockHash ||
        record.value("anchor_block_height", 0ULL) != winner.blockHeight ||
        record.value("anchor_tx_index", std::numeric_limits<std::uint64_t>::max()) != winner.txIndex ||
        !record.contains("metadata") || record["metadata"] != exactNewMetadata)
    {
        setReason(reason, "existing TOKEN_EVOLUTION materialization identity differs");
        return false;
    }

    if (!latest.is_object() ||
        latest.value("format", "") != VAHExternalWriterMaterialization::TOKEN_EVOLUTION_FORMAT ||
        latest.value("tokenID", "") != claim.token_id ||
        latest.value("type", "") != claim.token_type ||
        latest.value("epoch_after", 0ULL) < claim.epoch ||
        (latest.value("epoch_after", 0ULL) == claim.epoch && latestRaw != epochRaw))
    {
        setReason(reason, "TOKEN_EVOLUTION latest pointer is behind/conflicting with materialized epoch");
        return false;
    }

    if (!receipt.is_object() ||
        receipt.value("format", "") != "TRU_TOKEN_EVOLVE_ANCHOR_RECEIPT_V1" ||
        receipt.value("status", "") != "submitted" ||
        receipt.value("tokenID", "") != claim.token_id ||
        receipt.value("epoch", 0ULL) != claim.epoch ||
        receipt.value("new_metadata_hash", "") != claim.new_metadata_hash ||
        receipt.value("record_hash", "") != claim.record_hash ||
        receipt.value("txid", "") != winner.anchorTxid)
    {
        setReason(reason, "existing anchor receipt differs from confirmed winner");
        return false;
    }

    if (!checkpoint.is_object() ||
        checkpoint.value("format", "") != VAHExternalWriterMaterialization::MATERIALIZATION_FORMAT ||
        checkpoint.value("token_id", "") != claim.token_id ||
        checkpoint.value("epoch", 0ULL) != claim.epoch ||
        checkpoint.value("previous_metadata_hash", "") != claim.previous_metadata_hash ||
        checkpoint.value("new_metadata_hash", "") != claim.new_metadata_hash ||
        checkpoint.value("claim_record_hash", "") != claim.record_hash ||
        checkpoint.value("evolution_record_hash", "") != sha256Hex(epochRaw) ||
        checkpoint.value("anchor_txid", "") != winner.anchorTxid ||
        checkpoint.value("anchor_block_hash", "") != winner.blockHash ||
        checkpoint.value("anchor_block_height", 0ULL) != winner.blockHeight ||
        checkpoint.value("anchor_tx_index", std::numeric_limits<std::uint64_t>::max()) != winner.txIndex ||
        checkpoint.value("finalized_height", 0ULL) < winner.blockHeight ||
        !isLowerHex(checkpoint.value("finalized_block_hash", ""), 64U) ||
        checkpoint.value("anchor_receipt_hash", "") != sha256Hex(receiptRaw))
    {
        setReason(reason, "strict materialization checkpoint differs from durable state");
        return false;
    }

    for (const auto& item : queue) {
        if (item.get<std::string>() == queueItem(claim.token_id, claim.epoch)) {
            setReason(reason, "materialized external epoch must not remain in anchor_queue");
            return false;
        }
    }

    setReason(reason, "ok-idempotent");
    return true;
}

bool materializeCore(
    LevelDBStorage& storage,
    ContractStorage& contractStorage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    const VAHReconciliation::Candidate& winner,
    const VAHReconciliation::CanonicalView& view,
    const json& issuanceMetadata,
    const json& exactNewMetadata,
    std::string* reason)
{
    if (reason) reason->clear();
    std::lock_guard<std::mutex> commitLock(g_materializationCommitMutex);

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
    if (!validateWinner(claim, winner, view, reason)) return false;

    const std::string epochKey = evolutionEpochKey(claim.token_id, claim.epoch);
    const std::string checkpointKey =
        VAHExternalWriterMaterialization::materializationCheckpointKey(
            claim.token_id, claim.epoch);
    const bool hasEpochRaw = storage.exists(fullEvolutionKey(epochKey));
    const bool hasCheckpointRaw = storage.exists(fullMaterializationKey(checkpointKey));
    if (hasEpochRaw || hasCheckpointRaw) {
        if (!(hasEpochRaw && hasCheckpointRaw)) {
            setReason(reason, "partial materialization exists; refusing repair-by-guess");
            return false;
        }
        return verifyExactReplay(
            storage, claim, winner, exactNewMetadata, reason);
    }

    TokenEvolutionEngine engine(&contractStorage);
    json parent;
    std::string latestRaw;
    const bool hasLatest = contractStorage.getContractData(
        "TOKEN_EVOLUTION", latestKey(claim.token_id), latestRaw);

    if (claim.epoch == 1U) {
        if (hasLatest) {
            setReason(reason, "epoch 1 external materialization conflicts with existing history");
            return false;
        }
        if (!issuanceMetadata.is_object()) {
            setReason(reason, "issuance metadata is required for epoch 1 materialization");
            return false;
        }
        json issuanceRoot = issuanceMetadata;
        issuanceRoot["evolution_epoch"] = "0";
        parent = engine.normalizeMetadata(
            claim.token_type,
            issuanceRoot,
            VAHExternalWriterAnchor::EXTERNAL_WRITER_PROVIDER);
    } else {
        if (!hasLatest) {
            setReason(reason, "external materialization has no persisted parent epoch");
            return false;
        }

        const json historyReport = engine.verifyHistory(claim.token_id, issuanceMetadata);
        if (!historyReport.value("ok", false) ||
            !historyReport.value("fully_anchored", false) ||
            historyReport.value("latest_epoch", 0ULL) != claim.epoch - 1U)
        {
            setReason(reason, "parent TOKEN_EVOLUTION history is not fully anchored and contiguous");
            return false;
        }

        try {
            const json latest = json::parse(latestRaw);
            if (!latest.is_object() ||
                latest.value("tokenID", "") != claim.token_id ||
                latest.value("type", "") != claim.token_type ||
                latest.value("epoch_after", 0ULL) != claim.epoch - 1U ||
                latest.value("new_metadata_hash", "") != claim.previous_metadata_hash ||
                !latest.contains("metadata") || !latest["metadata"].is_object())
            {
                setReason(reason, "persisted parent identity differs from external claim parent");
                return false;
            }
            parent = engine.normalizeMetadata(
                claim.token_type,
                latest["metadata"],
                VAHExternalWriterAnchor::EXTERNAL_WRITER_PROVIDER);
            if (parent != latest["metadata"]) {
                setReason(reason, "persisted parent is not canonical for cross-writer continuation");
                return false;
            }
        } catch (...) {
            setReason(reason, "persisted parent TOKEN_EVOLUTION record is invalid");
            return false;
        }
    }

    if (sha256Hex(parent.dump()) != claim.previous_metadata_hash) {
        setReason(reason, "canonical parent metadata hash differs from signed claim parent");
        return false;
    }
    if (!validateMetadataDelta(claim, parent, exactNewMetadata, reason)) return false;

    json queue = json::array();
    std::string queueRaw;
    const bool hadAnchorQueue = contractStorage.getContractData(
        "TOKEN_EVOLUTION", "anchor_queue", queueRaw);
    if (hadAnchorQueue) {
        if (!parseCanonicalQueue(queueRaw, queue, reason)) return false;
    } else {
        queueRaw = queue.dump();
    }

    const std::string thisQueueItem = queueItem(claim.token_id, claim.epoch);
    for (const auto& item : queue) {
        if (item.get<std::string>() == thisQueueItem) {
            setReason(reason, "fresh external epoch unexpectedly already exists in anchor_queue");
            return false;
        }
    }

    const json evolutionRecord = buildEvolutionRecord(
        claim, winner, exactNewMetadata);
    const std::string evolutionRaw = evolutionRecord.dump();
    const std::string receiptRaw = buildReceipt(claim, winner).dump();
    const std::string checkpointRaw = buildCheckpoint(
        claim,
        winner,
        view,
        sha256Hex(evolutionRaw),
        sha256Hex(receiptRaw)).dump();

    std::vector<ContractStorage::BatchWrite> writes = {
        {"TOKEN_EVOLUTION", epochKey, evolutionRaw},
        {"TOKEN_EVOLUTION", latestKey(claim.token_id), evolutionRaw},
        {"TOKEN_EVOLUTION", anchorTxKey(claim.token_id, claim.epoch), winner.anchorTxid},
        {"TOKEN_EVOLUTION", anchorReceiptKey(claim.token_id, claim.epoch), receiptRaw},
        {"TOKEN:VAH_MATERIALIZED", checkpointKey, checkpointRaw}
    };
    // TOKEN_EVOLUTION verification requires a global queue key once history
    // exists. Create [] atomically only when the queue is absent; never rewrite
    // an existing unrelated queue snapshot during external materialization.
    if (!hadAnchorQueue) {
        writes.push_back({"TOKEN_EVOLUTION", "anchor_queue", queueRaw});
    }

    if (!contractStorage.storeContractDataBatch(writes)) {
        setReason(reason, "atomic external materialization batch failed");
        return false;
    }

    std::string verifyEpoch;
    std::string verifyLatest;
    std::string verifyAnchor;
    std::string verifyReceipt;
    std::string verifyQueue;
    std::string verifyCheckpoint;
    if (!contractStorage.getContractData("TOKEN_EVOLUTION", epochKey, verifyEpoch) ||
        !contractStorage.getContractData("TOKEN_EVOLUTION", latestKey(claim.token_id), verifyLatest) ||
        !contractStorage.getContractData("TOKEN_EVOLUTION", anchorTxKey(claim.token_id, claim.epoch), verifyAnchor) ||
        !contractStorage.getContractData("TOKEN_EVOLUTION", anchorReceiptKey(claim.token_id, claim.epoch), verifyReceipt) ||
        !contractStorage.getContractData("TOKEN_EVOLUTION", "anchor_queue", verifyQueue) ||
        !contractStorage.getContractData("TOKEN:VAH_MATERIALIZED", checkpointKey, verifyCheckpoint) ||
        verifyEpoch != evolutionRaw || verifyLatest != evolutionRaw ||
        verifyAnchor != winner.anchorTxid || verifyReceipt != receiptRaw ||
        verifyCheckpoint != checkpointRaw)
    {
        setReason(reason, "external materialization readback verification failed");
        return false;
    }

    json verifyQueueJson;
    if (!parseCanonicalQueue(verifyQueue, verifyQueueJson, reason)) return false;
    for (const auto& item : verifyQueueJson) {
        if (item.get<std::string>() == thisQueueItem) {
            setReason(reason, "materialized external epoch appeared in anchor_queue during readback");
            return false;
        }
    }

    setReason(reason, "ok");
    return true;
}

} // namespace

namespace VAHExternalWriterMaterialization {

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
    std::string* reason)
{
    return materializeCore(
        storage, contractStorage, claim, authorizationHistory,
        trustedAuthorizationRootPubKeyHex, winner, view, issuanceMetadata,
        exactNewMetadata, reason);
}

std::string materializationCheckpointKey(
    const std::string& tokenID,
    std::uint64_t epoch)
{
    return tokenID + ":epoch:" + epoch20(epoch);
}

#ifdef TRU_VAH_03D_TEST_HOOKS
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
    std::string* reason)
{
    return materializeCore(
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
#endif

// Production wrapper is defined in vah_external_writer_materialize_runtime.cpp.

} // namespace VAHExternalWriterMaterialization
