#include "vah_external_writer_materialize.h"

#include "contract_storage.h"
#include "crypto_ecdsa.h"
#include "leveldb_storage.h"
#include "token_evolution.h"
#include "vah_authorization.h"
#include "vah_external_writer_stage.h"

#include <openssl/sha.h>

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

std::string hexLower(const std::vector<unsigned char>& bytes) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (unsigned char b : bytes) {
        out.push_back(HEX[(b >> 4U) & 0x0fU]);
        out.push_back(HEX[b & 0x0fU]);
    }
    return out;
}

std::string sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return hexLower(std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH));
}

std::string tempPath(const std::string& tag) {
    return "/tmp/truq-vah03d-" + tag + "-" + std::to_string(::getpid());
}

void rm(const std::string& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
}

VAHAuthorization::AuthorizationRecord authorizeSensor(
    const std::string& token,
    const ECDSAKey& sensor,
    const ECDSAKey& root,
    const std::string& rootPub)
{
    VAHAuthorization::AuthorizationRecord record;
    record.sequence = 1U;
    record.effective_epoch = 1U;
    record.action = VAHAuthorization::Action::AUTHORIZE;
    record.token_id = token;
    record.writer_pubkey_hex = hexLower(sensor.getCompressedSec1());
    record.writer_class = "sensor";
    record.capabilities = {"SENSOR_MEASUREMENT"};
    record.previous_record_hash = std::string(64U, '0');
    record.authorization_root_pubkey_hex = rootPub;
    std::string reason;
    assert(VAHAuthorization::signAuthorizationRecord(record, root, &reason));
    return record;
}

VAHExternalWriter::Claim makeClaim(
    const std::string& token,
    const ECDSAKey& sensor,
    std::uint64_t epoch,
    const json& parent,
    const json& next)
{
    VAHExternalWriter::Claim claim;
    claim.token_id = token;
    claim.token_type = "SFT";
    claim.epoch = epoch;
    claim.previous_metadata_hash = sha256Hex(parent.dump());
    claim.new_metadata_hash = sha256Hex(next.dump());
    claim.writer_class = "sensor";
    claim.changed_fields = {"sentiment_score"};
    std::string reason;
    assert(VAHExternalWriter::signClaim(claim, sensor, &reason));
    return claim;
}

VAHReconciliation::CanonicalView makeView() {
    VAHReconciliation::CanonicalView view;
    view.finalizedHeight = 150U;
    view.finalizedBlockHash = std::string(64U, 'f');
    return view;
}

VAHReconciliation::Candidate makeWinner(
    const VAHExternalWriter::Claim& claim,
    std::uint64_t height,
    std::uint64_t txIndex,
    char txNibble,
    char blockNibble)
{
    VAHReconciliation::Candidate winner;
    winner.tokenID = claim.token_id;
    winner.epoch = claim.epoch;
    winner.previousMetadataHash = claim.previous_metadata_hash;
    winner.newMetadataHash = claim.new_metadata_hash;
    winner.recordHash = claim.record_hash;
    winner.anchorTxid = std::string(64U, txNibble);
    winner.blockHash = std::string(64U, blockNibble);
    winner.blockHeight = height;
    winner.txIndex = txIndex;
    return winner;
}

json issuance() {
    return json{
        {"name", "VAH external-writer test token"},
        {"symbol", "VAHX"}
    };
}

json canonicalRoot(ContractStorage& contractStorage, const json& issue) {
    TokenEvolutionEngine engine(&contractStorage);
    json root = issue;
    root["evolution_epoch"] = "0";
    return engine.normalizeMetadata("SFT", root, "external_writer");
}

json nextMetadata(const json& parent, std::uint64_t epoch, const std::string& value) {
    json next = parent;
    next["sentiment_score"] = value;
    next["evolution_epoch"] = std::to_string(epoch);
    return next;
}

bool noFreshMaterializationKeys(
    LevelDBStorage& storage,
    const std::string& token,
    std::uint64_t epoch)
{
    return !storage.exists("contract:TOKEN:EVOLUTION:epoch:" + token + ":" + std::to_string(epoch)) &&
           !storage.exists("contract:TOKEN:EVOLUTION:latest:" + token) &&
           !storage.exists("contract:TOKEN:VAH_MATERIALIZED:" +
               VAHExternalWriterMaterialization::materializationCheckpointKey(token, epoch));
}

} // namespace

int main() {
    const std::string token = "2df1363f156c50b8";
    const ECDSAKey rootKey = ECDSAKey::generate();
    const ECDSAKey sensor = ECDSAKey::generate();
    const std::string rootPub = hexLower(rootKey.getCompressedSec1());
    const std::vector<VAHAuthorization::AuthorizationRecord> history = {
        authorizeSensor(token, sensor, rootKey, rootPub)
    };
    const auto view = makeView();
    const json issue = issuance();
    std::string reason;

    // End-to-end external materialization, exact replay, second epoch, and
    // real close/reopen restart verification.
    const std::string restartPath = tempPath("restart");
    rm(restartPath);
    VAHExternalWriter::Claim c1;
    VAHExternalWriter::Claim c2;
    VAHReconciliation::Candidate w1;
    VAHReconciliation::Candidate w2;
    json m1;
    json m2;
    {
        LevelDBStorage storage(restartPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        m1 = nextMetadata(root, 1U, "0.73");
        c1 = makeClaim(token, sensor, 1U, root, m1);
        w1 = makeWinner(c1, 120U, 2U, '1', 'a');
        assert(VAHExternalWriterStage::stageClaim(storage, c1, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c1, history, rootPub, w1, view, issue, m1, &reason));
        assert(reason == "ok");

        TokenEvolutionEngine engine(&cs);
        auto report = engine.verifyHistory(token, issue);
        assert(report.value("ok", false));
        assert(report.value("fully_anchored", false));
        assert(report.value("latest_epoch", 0ULL) == 1U);
        assert(report["epochs"][0].value("record_format_version", 0ULL) == 3U);
        assert(report["epochs"][0].value("writer_type", "") == "sensor");
        assert(report["epochs"][0].value("record_hash", "") == c1.record_hash);

        const auto pending1 = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 1U, history, rootPub);
        assert(pending1.ok && pending1.claims.size() == 1U); // append-only audit evidence

        const std::size_t keysBeforeReplay = storage.countKeys();
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c1, history, rootPub, w1, view, issue, m1, &reason));
        assert(reason == "ok-idempotent");
        assert(storage.countKeys() == keysBeforeReplay);

        m2 = nextMetadata(m1, 2U, "0.84");
        c2 = makeClaim(token, sensor, 2U, m1, m2);
        w2 = makeWinner(c2, 125U, 1U, '2', 'b');
        assert(VAHExternalWriterStage::stageClaim(storage, c2, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c2, history, rootPub, w2, view, issue, m2, &reason));
        report = engine.verifyHistory(token, issue);
        assert(report.value("ok", false));
        assert(report.value("fully_anchored", false));
        assert(report.value("latest_epoch", 0ULL) == 2U);
        assert(report["epochs"][1].value("writer_type", "") == "sensor");
        assert(engine.loadLatest(token).at("metadata") == m2);

        // The global anchor_queue is allowed to evolve for unrelated tokens
        // after this materialization. Historical replay must not freeze it.
        assert(cs.storeContractData(
            "TOKEN_EVOLUTION", "anchor_queue",
            json::array({"abcdef12:1"}).dump()));

        // Replaying an older already-materialized epoch after latest has advanced
        // must remain an idempotent no-op and must not roll latest backward.
        const auto keysAfterEpoch2 = storage.countKeys();
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c1, history, rootPub, w1, view, issue, m1, &reason));
        assert(reason == "ok-idempotent");
        assert(storage.countKeys() == keysAfterEpoch2);
        assert(engine.loadLatest(token).at("metadata") == m2);
    }
    {
        LevelDBStorage storage(restartPath);
        ContractStorage cs(&storage);
        TokenEvolutionEngine engine(&cs);
        const auto report = engine.verifyHistory(token, issue);
        assert(report.value("ok", false));
        assert(report.value("fully_anchored", false));
        assert(report.value("latest_epoch", 0ULL) == 2U);
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c2, history, rootPub, w2, view, issue, m2, &reason));
        assert(reason == "ok-idempotent");
        auto laterReplayView = view;
        laterReplayView.finalizedHeight = 190U;
        laterReplayView.finalizedBlockHash = std::string(64U, 'd');
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, c2, history, rootPub, w2, laterReplayView,
            issue, m2, &reason));
        assert(reason == "ok-idempotent");

        // Same token/epoch, different valid signed claim must never overwrite.
        json conflictMeta = m1;
        conflictMeta["sentiment_score"] = "0.99";
        conflictMeta["evolution_epoch"] = "2";
        auto conflict = makeClaim(token, sensor, 2U, m1, conflictMeta);
        auto conflictWinner = makeWinner(conflict, 126U, 0U, '3', 'c');
        assert(VAHExternalWriterStage::stageClaim(storage, conflict, history, rootPub, &reason));
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, conflict, history, rootPub, conflictWinner, view,
            issue, conflictMeta, &reason));
        assert(engine.loadLatest(token).at("metadata") == m2);
    }
    rm(restartPath);

    // Cross-node canonical convergence: signature bytes and the caller's
    // later finalized view are local proof context, not canonical token state.
    // Two nodes with the same claim semantics/metadata/winner must persist
    // byte-identical TOKEN_EVOLUTION epoch records.
    const std::string convergeAPath = tempPath("converge-a");
    const std::string convergeBPath = tempPath("converge-b");
    rm(convergeAPath);
    rm(convergeBPath);
    std::string convergeEpochA;
    std::string convergeEpochB;
    {
        LevelDBStorage storage(convergeAPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        const json next = nextMetadata(root, 1U, "0.52");
        auto claim = makeClaim(token, sensor, 1U, root, next);
        auto winner = makeWinner(claim, 120U, 3U, 'a', 'e');
        assert(VAHExternalWriterStage::stageClaim(storage, claim, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, winner, view, issue, next, &reason));
        assert(storage.getContract(
            "contract:TOKEN:EVOLUTION:epoch:" + token + ":1", convergeEpochA));
    }
    {
        LevelDBStorage storage(convergeBPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        const json next = nextMetadata(root, 1U, "0.52");
        auto claim = makeClaim(token, sensor, 1U, root, next); // fresh valid signature
        auto winner = makeWinner(claim, 120U, 3U, 'a', 'e');
        auto laterView = view;
        laterView.finalizedHeight = 175U;
        laterView.finalizedBlockHash = std::string(64U, 'e');
        assert(VAHExternalWriterStage::stageClaim(storage, claim, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, winner, laterView, issue, next, &reason));
        assert(storage.getContract(
            "contract:TOKEN:EVOLUTION:epoch:" + token + ":1", convergeEpochB));
    }
    assert(convergeEpochA == convergeEpochB);
    rm(convergeAPath);
    rm(convergeBPath);

    // A claim can cryptographically commit an opaque metadata hash while
    // omitting an unauthorized hidden change from changed_fields. 03D must
    // compare the actual document delta and reject it before any state write.
    const std::string hiddenPath = tempPath("hidden-delta");
    rm(hiddenPath);
    {
        LevelDBStorage storage(hiddenPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        json hidden = nextMetadata(root, 1U, "0.55");
        hidden["ai_version"] = "999.0"; // not claimed; sensor cannot mutate it
        auto claim = makeClaim(token, sensor, 1U, root, hidden);
        auto winner = makeWinner(claim, 120U, 0U, '4', 'd');
        assert(VAHExternalWriter::verifyClaim(claim, history, rootPub, &reason));
        assert(VAHExternalWriterStage::stageClaim(storage, claim, history, rootPub, &reason));
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, winner, view, issue, hidden, &reason));
        assert(reason == "actual metadata delta differs from signed changed_fields");
        assert(noFreshMaterializationKeys(storage, token, 1U));
    }
    rm(hiddenPath);

    // The exact document supplied at materialization must hash to the already
    // confirmed new_metadata_hash; no reconstruction or best-effort repair.
    const std::string mismatchPath = tempPath("metadata-mismatch");
    rm(mismatchPath);
    {
        LevelDBStorage storage(mismatchPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        const json good = nextMetadata(root, 1U, "0.41");
        auto claim = makeClaim(token, sensor, 1U, root, good);
        auto winner = makeWinner(claim, 120U, 0U, '5', 'e');
        assert(VAHExternalWriterStage::stageClaim(storage, claim, history, rootPub, &reason));
        json wrong = good;
        wrong["sentiment_score"] = "0.42";
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, winner, view, issue, wrong, &reason));
        assert(noFreshMaterializationKeys(storage, token, 1U));

        auto badWinner = winner;
        badWinner.anchorTxid[0] = '9';
        badWinner.recordHash[0] = badWinner.recordHash[0] == 'a' ? 'b' : 'a';
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, badWinner, view, issue, good, &reason));
        assert(noFreshMaterializationKeys(storage, token, 1U));
    }
    rm(mismatchPath);

    // Simultaneous conflicting local first writers are serialized at the
    // materialization commit boundary. Exactly one may create epoch 1.
    const std::string racePath = tempPath("race");
    rm(racePath);
    {
        LevelDBStorage storage(racePath);
        ContractStorage setupCs(&storage);
        const json root = canonicalRoot(setupCs, issue);
        const json metaA = nextMetadata(root, 1U, "0.31");
        const json metaB = nextMetadata(root, 1U, "0.32");
        const auto claimA = makeClaim(token, sensor, 1U, root, metaA);
        const auto claimB = makeClaim(token, sensor, 1U, root, metaB);
        const auto winnerA = makeWinner(claimA, 124U, 0U, 'b', 'e');
        const auto winnerB = makeWinner(claimB, 124U, 1U, 'c', 'e');
        assert(VAHExternalWriterStage::stageClaim(storage, claimA, history, rootPub, &reason));
        assert(VAHExternalWriterStage::stageClaim(storage, claimB, history, rootPub, &reason));

        bool okA = false;
        bool okB = false;
        std::thread t1([&] {
            ContractStorage cs(&storage);
            std::string localReason;
            okA = VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
                storage, cs, claimA, history, rootPub, winnerA, view,
                issue, metaA, &localReason);
        });
        std::thread t2([&] {
            ContractStorage cs(&storage);
            std::string localReason;
            okB = VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
                storage, cs, claimB, history, rootPub, winnerB, view,
                issue, metaB, &localReason);
        });
        t1.join();
        t2.join();
        assert(okA != okB);

        ContractStorage verifyCs(&storage);
        TokenEvolutionEngine engine(&verifyCs);
        const auto report = engine.verifyHistory(token, issue);
        assert(report.value("ok", false));
        assert(report.value("fully_anchored", false));
        assert(report.value("latest_epoch", 0ULL) == 1U);
    }
    rm(racePath);

    // Atomic write refusal must leave no epoch/latest/materialization checkpoint.
    const std::string batchFailPath = tempPath("batch-fail");
    rm(batchFailPath);
    {
        LevelDBStorage storage(batchFailPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        const json next = nextMetadata(root, 1U, "0.61");
        auto claim = makeClaim(token, sensor, 1U, root, next);
        auto winner = makeWinner(claim, 121U, 0U, '6', 'a');
        assert(VAHExternalWriterStage::stageClaim(storage, claim, history, rootPub, &reason));
        cs.setTokenEvolutionTestFault(ContractStorage::TestFault::BATCH_WRITE_FAIL);
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, claim, history, rootPub, winner, view, issue, next, &reason));
        assert(noFreshMaterializationKeys(storage, token, 1U));
    }
    rm(batchFailPath);

    // Ambiguous caller failure after the synced batch: restart must discover
    // the exact durable state and converge to idempotent success.
    const std::string ambiguousPath = tempPath("ambiguous");
    rm(ambiguousPath);
    VAHExternalWriter::Claim ambiguousClaim;
    VAHReconciliation::Candidate ambiguousWinner;
    json ambiguousMeta;
    {
        LevelDBStorage storage(ambiguousPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        ambiguousMeta = nextMetadata(root, 1U, "0.67");
        ambiguousClaim = makeClaim(token, sensor, 1U, root, ambiguousMeta);
        ambiguousWinner = makeWinner(ambiguousClaim, 121U, 1U, '7', 'b');
        assert(VAHExternalWriterStage::stageClaim(
            storage, ambiguousClaim, history, rootPub, &reason));
        cs.setTokenEvolutionTestFault(
            ContractStorage::TestFault::AFTER_BATCH_BEFORE_READBACK);
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, ambiguousClaim, history, rootPub, ambiguousWinner,
            view, issue, ambiguousMeta, &reason));
        assert(storage.exists("contract:TOKEN:EVOLUTION:epoch:" + token + ":1"));
        assert(storage.exists("contract:TOKEN:VAH_MATERIALIZED:" +
            VAHExternalWriterMaterialization::materializationCheckpointKey(token, 1U)));
    }
    {
        LevelDBStorage storage(ambiguousPath);
        ContractStorage cs(&storage);
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, ambiguousClaim, history, rootPub, ambiguousWinner,
            view, issue, ambiguousMeta, &reason));
        assert(reason == "ok-idempotent");
        TokenEvolutionEngine engine(&cs);
        const auto report = engine.verifyHistory(token, issue);
        assert(report.value("ok", false) && report.value("fully_anchored", false));
    }
    rm(ambiguousPath);

    // Strict checkpoint corruption: a generic single-SHA put cannot be
    // migrated into trusted materialization state, and failed read does not
    // rewrite the tampered raw bytes.
    const std::string markerCorruptPath = tempPath("marker-corrupt");
    rm(markerCorruptPath);
    std::string markerRawBefore;
    VAHExternalWriter::Claim markerClaim;
    VAHReconciliation::Candidate markerWinner;
    json markerMeta;
    {
        LevelDBStorage storage(markerCorruptPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        markerMeta = nextMetadata(root, 1U, "0.71");
        markerClaim = makeClaim(token, sensor, 1U, root, markerMeta);
        markerWinner = makeWinner(markerClaim, 122U, 0U, '8', 'c');
        assert(VAHExternalWriterStage::stageClaim(storage, markerClaim, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, markerClaim, history, rootPub, markerWinner, view,
            issue, markerMeta, &reason));
        const std::string checkpointKey =
            "contract:TOKEN:VAH_MATERIALIZED:" +
            VAHExternalWriterMaterialization::materializationCheckpointKey(token, 1U);
        std::string decoded;
        assert(storage.getContract(checkpointKey, decoded));
        auto parsed = json::parse(decoded);
        std::string mutatedHash = parsed["new_metadata_hash"].get<std::string>();
        mutatedHash[0] = mutatedHash[0] == 'a' ? 'b' : 'a';
        parsed["new_metadata_hash"] = mutatedHash;
        assert(storage.put(checkpointKey, parsed.dump()));
        bool found = false;
        assert(storage.getRaw(checkpointKey, markerRawBefore, found) && found);
    }
    {
        LevelDBStorage storage(markerCorruptPath);
        ContractStorage cs(&storage);
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, markerClaim, history, rootPub, markerWinner, view,
            issue, markerMeta, &reason));
        const std::string checkpointKey =
            "contract:TOKEN:VAH_MATERIALIZED:" +
            VAHExternalWriterMaterialization::materializationCheckpointKey(token, 1U);
        std::string rawAfter;
        bool found = false;
        assert(storage.getRaw(checkpointKey, rawAfter, found) && found);
        assert(rawAfter == markerRawBefore);
    }
    rm(markerCorruptPath);

    // TOKEN_EVOLUTION V3 replay itself is read through a strict raw canonical
    // checksum path, so generic legacy-checksum laundering cannot rewrite it.
    const std::string epochCorruptPath = tempPath("epoch-corrupt");
    rm(epochCorruptPath);
    std::string epochRawBefore;
    VAHExternalWriter::Claim epochClaim;
    VAHReconciliation::Candidate epochWinner;
    json epochMeta;
    {
        LevelDBStorage storage(epochCorruptPath);
        ContractStorage cs(&storage);
        const json root = canonicalRoot(cs, issue);
        epochMeta = nextMetadata(root, 1U, "0.79");
        epochClaim = makeClaim(token, sensor, 1U, root, epochMeta);
        epochWinner = makeWinner(epochClaim, 123U, 0U, '9', 'd');
        assert(VAHExternalWriterStage::stageClaim(storage, epochClaim, history, rootPub, &reason));
        assert(VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, epochClaim, history, rootPub, epochWinner, view,
            issue, epochMeta, &reason));
        const std::string epochKey = "contract:TOKEN:EVOLUTION:epoch:" + token + ":1";
        std::string decoded;
        assert(storage.getContract(epochKey, decoded));
        auto parsed = json::parse(decoded);
        std::string mutatedWriter = parsed["writer_id"].get<std::string>();
        mutatedWriter[0] = mutatedWriter[0] == 'a' ? 'b' : 'a';
        parsed["writer_id"] = mutatedWriter;
        assert(storage.put(epochKey, parsed.dump()));
        bool found = false;
        assert(storage.getRaw(epochKey, epochRawBefore, found) && found);
    }
    {
        LevelDBStorage storage(epochCorruptPath);
        ContractStorage cs(&storage);
        assert(!VAHExternalWriterMaterialization::materializeConfirmedWinnerForTest(
            storage, cs, epochClaim, history, rootPub, epochWinner, view,
            issue, epochMeta, &reason));
        const std::string epochKey = "contract:TOKEN:EVOLUTION:epoch:" + token + ":1";
        std::string rawAfter;
        bool found = false;
        assert(storage.getRaw(epochKey, rawAfter, found) && found);
        assert(rawAfter == epochRawBefore);
    }
    rm(epochCorruptPath);

    std::cout << "TRU_VAH_03D_CANONICAL_EXTERNAL_WRITER_MATERIALIZATION_MATRIX=PASS\n";
    return 0;
}
