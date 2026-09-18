#include "vah_reconciliation_store.h"
#include "leveldb_storage.h"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

using namespace VAHReconciliation;
using namespace VAHDurableReconciliation;

namespace {
std::string hx(char c, std::size_t n) { return std::string(n, c); }

Candidate candidate(const std::string& token, uint64_t epoch,
                    const std::string& parent, char newHash, char recordHash,
                    char txid, char blockHash, uint64_t height, uint64_t txIndex) {
    Candidate c;
    c.tokenID = token;
    c.epoch = epoch;
    c.previousMetadataHash = parent;
    c.newMetadataHash = hx(newHash, 64U);
    c.recordHash = hx(recordHash, 64U);
    c.anchorTxid = hx(txid, 64U);
    c.blockHash = hx(blockHash, 64U);
    c.blockHeight = height;
    c.txIndex = txIndex;
    return c;
}
}

int main() {
    const std::string token = "2df1363f156c50b8";
    const uint64_t epoch = 7U;
    const std::string parent = hx('a', 64U);
    const CanonicalView view{120U, hx('f', 64U)};

    const Candidate later = candidate(token, epoch, parent, 'c', 'd', '3', 'e', 118U, 4U);
    const Candidate winner = candidate(token, epoch, parent, 'b', 'c', '2', 'd', 117U, 2U);
    ElectionResult election = electCanonicalCandidate(token, epoch, parent, view, {later, winner});
    assert(election.ok && election.hasWinner);
    assert(sameCanonicalIdentity(election.winner, winner));

    const std::string dbPath = "/tmp/tru-vah02c-restart-" + std::to_string(static_cast<long long>(::getpid()));
    std::filesystem::remove_all(dbPath);
    std::string reason;
    DurableResult beforeRestart;

    // First durable write + readback.
    {
        LevelDBStorage storage(dbPath);
        assert(persistCanonicalResult(storage, token, epoch, parent, view, election, reason));
        assert(reason.empty());
        assert(loadCanonicalResult(storage, token, epoch, parent, beforeRestart, reason));
        assert(reason.empty());
        assert(sameCanonicalIdentity(beforeRestart.winner, winner));

        // Exact replay is idempotent and does not create another key/value.
        const std::size_t keyCount = storage.countKeys();
        assert(persistCanonicalResult(storage, token, epoch, parent, view, election, reason));
        assert(storage.countKeys() == keyCount);

        // A conflicting winner for the same token/epoch may not overwrite history.
        ElectionResult conflict;
        conflict.ok = true;
        conflict.hasWinner = true;
        conflict.winner = candidate(token, epoch, parent, '9', '8', '1', 'd', 116U, 1U);
        assert(!persistCanonicalResult(storage, token, epoch, parent, view, conflict, reason));
        assert(reason == "conflicting durable reconciliation already exists");

        DurableResult afterConflict;
        assert(loadCanonicalResult(storage, token, epoch, parent, afterConflict, reason));
        assert(sameDurableIdentity(beforeRestart, afterConflict));
    }

    // Real restart proof: destroy DB handle, reopen path, reconstruct identical state.
    {
        LevelDBStorage storage(dbPath);
        DurableResult afterRestart;
        assert(loadCanonicalResult(storage, token, epoch, parent, afterRestart, reason));
        assert(reason.empty());
        assert(sameDurableIdentity(beforeRestart, afterRestart));

        // Lookup is bound to the exact parent and epoch.
        DurableResult ignored;
        assert(!loadCanonicalResult(storage, token, epoch, hx('9', 64U), ignored, reason));
        assert(!loadCanonicalResult(storage, token, epoch + 1U, parent, ignored, reason));
    }

    // A generic single-SHA256 write into the new VAH reconciliation namespace
    // must never be accepted as a legacy contract checksum or upgraded on read.
    // First exercise the original obviously malformed corruption case.
    {
        LevelDBStorage storage(dbPath);
        const std::string rawKey = "contract:" + reconciliationKey(token, epoch);
        assert(storage.put(rawKey, "corrupt-payload-without-valid-contract-checksum"));
    }
    {
        LevelDBStorage storage(dbPath);
        DurableResult ignored;
        assert(!loadCanonicalResult(storage, token, epoch, parent, ignored, reason));
        assert(reason == "durable reconciliation not found or checksum-invalid");
    }

    // Recreate a clean canonical checkpoint, then alter one byte inside a hash
    // field while preserving a fully parseable reconciliation envelope. The
    // generic put() intentionally wraps it in the legacy single-SHA256 format.
    // The strict VAH prefix must reject it before parsing and must not rewrite it.
    std::filesystem::remove_all(dbPath);
    std::string rawTamperedBefore;
    {
        LevelDBStorage storage(dbPath);
        assert(persistCanonicalResult(storage, token, epoch, parent, view, election, reason));

        std::string parseableTamper;
        assert(storage.getContract(reconciliationKey(token, epoch), parseableTamper));
        const std::string fieldPrefix = "winner_new_metadata_hash=";
        const std::size_t field = parseableTamper.find(fieldPrefix);
        assert(field != std::string::npos);
        const std::size_t byte = field + fieldPrefix.size();
        assert(byte < parseableTamper.size() && parseableTamper[byte] == 'b');
        parseableTamper[byte] = 'e';

        const std::string rawKey = "contract:" + reconciliationKey(token, epoch);
        assert(storage.put(rawKey, parseableTamper));
        bool found = false;
        assert(storage.getRaw(rawKey, rawTamperedBefore, found));
        assert(found);
    }
    {
        LevelDBStorage storage(dbPath);
        DurableResult ignored;
        assert(!loadCanonicalResult(storage, token, epoch, parent, ignored, reason));
        assert(reason == "durable reconciliation not found or checksum-invalid");

        const std::string rawKey = "contract:" + reconciliationKey(token, epoch);
        std::string rawTamperedAfter;
        bool found = false;
        assert(storage.getRaw(rawKey, rawTamperedAfter, found));
        assert(found);
        assert(rawTamperedAfter == rawTamperedBefore);
    }

    std::filesystem::remove_all(dbPath);

    // Compatibility control: the legacy single-SHA256 migration remains enabled
    // for ordinary pre-existing contract namespaces outside TOKEN:VAH_RECON.
    {
        const std::string legacyPath = "/tmp/truq-vah02c-legacy-control-" +
            std::to_string(static_cast<long long>(::getpid()));
        std::filesystem::remove_all(legacyPath);
        LevelDBStorage storage(legacyPath);
        const std::string key = "contract:VAH02C_LEGACY_CONTROL:value";
        const std::string value = "legacy-compatible-value";
        assert(storage.put(key, value));
        std::string loaded;
        assert(storage.getContract(key, loaded));
        assert(loaded == value);
        std::filesystem::remove_all(legacyPath);
    }

    // Simultaneous conflicting first writers are serialized: exactly one wins.
    {
        const std::string racePath = "/tmp/truq-vah02c-race-" +
            std::to_string(static_cast<long long>(::getpid()));
        std::filesystem::remove_all(racePath);
        LevelDBStorage storage(racePath);

        ElectionResult a = election;
        ElectionResult b;
        b.ok = true;
        b.hasWinner = true;
        b.winner = candidate(token, epoch, parent, '8', '9', '1', 'd', 116U, 1U);

        bool okA = false;
        bool okB = false;
        std::string reasonA;
        std::string reasonB;
        std::thread ta([&] { okA = persistCanonicalResult(storage, token, epoch, parent, view, a, reasonA); });
        std::thread tb([&] { okB = persistCanonicalResult(storage, token, epoch, parent, view, b, reasonB); });
        ta.join();
        tb.join();
        assert(okA != okB);

        DurableResult raced;
        assert(loadCanonicalResult(storage, token, epoch, parent, raced, reason));
        if (okA) {
            assert(sameCanonicalIdentity(raced.winner, a.winner));
            assert(reasonB == "conflicting durable reconciliation already exists");
        } else {
            assert(sameCanonicalIdentity(raced.winner, b.winner));
            assert(reasonA == "conflicting durable reconciliation already exists");
        }
        std::filesystem::remove_all(racePath);
    }

    std::cout << "TRU_VAH_02C_DURABLE_RECONCILIATION_RESTART_MATRIX=PASS\n";
    return 0;
}
