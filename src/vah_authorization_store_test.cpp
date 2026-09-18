#include "vah_authorization_store.h"
#include "contract_storage.h"
#include "crypto_ecdsa.h"
#include "leveldb_storage.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

std::string hexLower(const std::vector<unsigned char>& data) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (unsigned char b : data) {
        out.push_back(HEX[(b >> 4) & 0x0f]);
        out.push_back(HEX[b & 0x0f]);
    }
    return out;
}

[[noreturn]] void fail(const std::string& message) {
    std::cerr << "FAIL: " << message << "\n";
    std::exit(1);
}

void require(bool condition, const std::string& message) {
    if (!condition) fail(message);
}

VAHAuthorization::AuthorizationRecord makeRecord(
    const std::string& tokenId,
    std::uint64_t sequence,
    std::uint64_t epoch,
    VAHAuthorization::Action action,
    const ECDSAKey& root,
    const ECDSAKey& writer,
    const std::string& writerClass,
    const std::vector<std::string>& capabilities,
    const std::string& previousHash,
    const std::string& replaces = {})
{
    VAHAuthorization::AuthorizationRecord r;
    r.token_id = tokenId;
    r.sequence = sequence;
    r.effective_epoch = epoch;
    r.action = action;
    r.writer_pubkey_hex = hexLower(writer.getCompressedSec1());
    r.writer_class = writerClass;
    r.capabilities = capabilities;
    r.replaces_writer_id = replaces;
    r.previous_record_hash = previousHash;
    r.authorization_root_pubkey_hex = hexLower(root.getCompressedSec1());
    std::string reason;
    require(VAHAuthorization::signAuthorizationRecord(r, root, &reason), "signAuthorizationRecord: " + reason);
    return r;
}

std::string newPath(const std::string& tag) {
    return "/tmp/tru-vah01f-" + tag + "-" + std::to_string(static_cast<unsigned long long>(::getpid()));
}

void clean(const std::string& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
}

} // namespace

int main() {
    using namespace VAHAuthorization;
    using namespace VAHAuthorizationStore;

    const std::string tokenId = "2df1363f156c50b8";
    const std::string zeroHash(64, '0');
    ECDSAKey root = ECDSAKey::generate();
    ECDSAKey fakeRoot = ECDSAKey::generate();
    ECDSAKey sensor1 = ECDSAKey::generate();
    ECDSAKey sensor2 = ECDSAKey::generate();
    const std::string rootHex = hexLower(root.getCompressedSec1());
    const std::string fakeRootHex = hexLower(fakeRoot.getCompressedSec1());

    // 1. Fresh append + durable load + exact retry idempotence.
    const std::string p1 = newPath("basic"); clean(p1);
    AuthorizationRecord a1;
    AuthorizationRecord a2;
    {
        LevelDBStorage db(p1);
        ContractStorage storage(&db);
        auto empty = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(empty.ok && empty.records.empty() && empty.latest_sequence == 0, "fresh history not empty/valid");

        a1 = makeRecord(tokenId, 1, 5, Action::AUTHORIZE, root, sensor1, "sensor",
                        {"SENSOR_MEASUREMENT"}, zeroHash);
        std::string reason;
        require(appendRecord(storage, a1, "NCFT", rootHex, &reason), "first durable append failed: " + reason);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.size() == 1 && loaded.latest_sequence == 1 &&
                loaded.latest_record_hash == a1.record_hash, "first durable load mismatch");

        require(appendRecord(storage, a1, "NCFT", rootHex, &reason), "exact retry was not idempotent: " + reason);
        require(reason == "already persisted", "exact retry did not report already persisted");

        auto conflict = a1;
        conflict.effective_epoch = 6; // makes serialized candidate differ at same sequence
        require(!appendRecord(storage, conflict, "NCFT", rootHex, &reason), "same-sequence conflict accepted");

        a2 = makeRecord(tokenId, 2, 10, Action::ROTATE, root, sensor2, "sensor",
                        {"SENSOR_MEASUREMENT"}, a1.record_hash, a1.writer_id);
        require(appendRecord(storage, a2, "NCFT", rootHex, &reason), "second durable append failed: " + reason);
    }

    // 2. Restart/reopen proves persistence and full history verification.
    {
        LevelDBStorage db(p1);
        ContractStorage storage(&db);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.size() == 2 && loaded.latest_sequence == 2 &&
                loaded.latest_record_hash == a2.record_hash, "restart persistence verification failed");
        std::string reason;
        require(VAHAuthorization::isWriterAuthorizedAtEpoch(loaded.records, "NCFT", rootHex, 10,
                a2.writer_pubkey_hex, "sensor", {"emotion_response"}, &reason),
                "restarted persisted history failed historical authorization: " + reason);
        auto wrongRoot = loadHistory(storage, tokenId, "NCFT", fakeRootHex);
        require(!wrongRoot.ok, "persisted history accepted under wrong independently trusted root");
    }
    clean(p1);

    // 3. BEFORE_BATCH => zero persistence.
    const std::string p2 = newPath("before"); clean(p2);
    {
        LevelDBStorage db(p2); ContractStorage storage(&db);
        auto rec = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                              {"SENSOR_MEASUREMENT"}, zeroHash);
        setTestFault(TestFault::BEFORE_BATCH);
        std::string reason;
        require(!appendRecord(storage, rec, "NCFT", rootHex, &reason), "BEFORE_BATCH unexpectedly succeeded");
        setTestFault(TestFault::NONE);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.empty(), "BEFORE_BATCH left persisted state");
    }
    clean(p2);

    // 4. Underlying atomic WriteBatch refusal => zero partial persistence.
    const std::string p3 = newPath("batchfail"); clean(p3);
    {
        LevelDBStorage db(p3); ContractStorage storage(&db);
        auto rec = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                              {"SENSOR_MEASUREMENT"}, zeroHash);
        storage.setTokenEvolutionTestFault(ContractStorage::TestFault::BATCH_WRITE_FAIL);
        std::string reason;
        require(!appendRecord(storage, rec, "NCFT", rootHex, &reason), "WriteBatch refusal unexpectedly succeeded");
        storage.setTokenEvolutionTestFault(ContractStorage::TestFault::NONE);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.empty(), "WriteBatch refusal left partial persisted state");
    }
    clean(p3);

    // 5. Ambiguous failure after durable batch => complete state survives restart and retry is idempotent.
    const std::string p4 = newPath("afterbatch"); clean(p4);
    AuthorizationRecord ambiguous;
    {
        LevelDBStorage db(p4); ContractStorage storage(&db);
        ambiguous = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                               {"SENSOR_MEASUREMENT"}, zeroHash);
        setTestFault(TestFault::AFTER_BATCH_BEFORE_READBACK);
        std::string reason;
        require(!appendRecord(storage, ambiguous, "NCFT", rootHex, &reason), "after-batch fault unexpectedly returned success");
        setTestFault(TestFault::NONE);
    }
    {
        LevelDBStorage db(p4); ContractStorage storage(&db);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.size() == 1 && loaded.latest_record_hash == ambiguous.record_hash,
                "after-batch durable state was partial/lost across restart");
        std::string reason;
        require(appendRecord(storage, ambiguous, "NCFT", rootHex, &reason) && reason == "already persisted",
                "after-batch exact retry not idempotent");
    }
    clean(p4);

    // 6. Readback mismatch cannot report false success; durable batch remains complete and restart-valid.
    const std::string p5 = newPath("readback"); clean(p5);
    AuthorizationRecord readback;
    {
        LevelDBStorage db(p5); ContractStorage storage(&db);
        readback = makeRecord(tokenId, 1, 2, Action::AUTHORIZE, root, sensor1, "sensor",
                              {"SENSOR_MEASUREMENT"}, zeroHash);
        setTestFault(TestFault::READBACK_MISMATCH);
        std::string reason;
        require(!appendRecord(storage, readback, "NCFT", rootHex, &reason), "readback mismatch falsely reported success");
        setTestFault(TestFault::NONE);
    }
    {
        LevelDBStorage db(p5); ContractStorage storage(&db);
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.size() == 1 && loaded.latest_record_hash == readback.record_hash,
                "readback-mismatch durable batch invalid after restart");
    }
    clean(p5);

    // 7. Sequence gap / wrong previous hash / wrong root / tamper all fail before persistence.
    const std::string p6 = newPath("policy"); clean(p6);
    {
        LevelDBStorage db(p6); ContractStorage storage(&db);
        std::string reason;
        auto gap = makeRecord(tokenId, 2, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                              {"SENSOR_MEASUREMENT"}, zeroHash);
        require(!appendRecord(storage, gap, "NCFT", rootHex, &reason), "sequence gap persisted");

        auto wrongPrev = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                                    {"SENSOR_MEASUREMENT"}, std::string(64, '1'));
        require(!appendRecord(storage, wrongPrev, "NCFT", rootHex, &reason), "wrong previous hash persisted");

        auto valid = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                                {"SENSOR_MEASUREMENT"}, zeroHash);
        require(!appendRecord(storage, valid, "NCFT", fakeRootHex, &reason), "record persisted under wrong trusted root");

        auto tamper = valid;
        tamper.capabilities = {"DEVICE_STATE"};
        require(!appendRecord(storage, tamper, "NCFT", rootHex, &reason), "post-signature tamper persisted");

        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(loaded.ok && loaded.records.empty(), "pre-persistence policy failures mutated storage");
    }
    clean(p6);

    // 8. Impossible/corrupt persistent states fail closed.
    const std::string p7 = newPath("corrupt"); clean(p7);
    {
        LevelDBStorage db(p7); ContractStorage storage(&db);
        std::string reason;
        auto rec = makeRecord(tokenId, 1, 1, Action::AUTHORIZE, root, sensor1, "sensor",
                              {"SENSOR_MEASUREMENT"}, zeroHash);
        require(appendRecord(storage, rec, "NCFT", rootHex, &reason), "corruption fixture append failed");
        // Orphan record beyond head is impossible after a correct atomic append.
        storage.storeContractData("TOKEN:VAH_AUTH", tokenId + ":auth:00000000000000000002", serializeAuthorizationRecord(rec));
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(!loaded.ok, "orphan authorization record beyond head accepted");
    }
    clean(p7);

    const std::string p8 = newPath("missing"); clean(p8);
    {
        LevelDBStorage db(p8); ContractStorage storage(&db);
        // Head claims sequence 1 but record is absent.
        storage.storeContractData("TOKEN:VAH_AUTH", tokenId + ":head",
                                  "TRU_VAH_AUTH_HEAD_V1|1|" + std::string(64, '1'));
        auto loaded = loadHistory(storage, tokenId, "NCFT", rootHex);
        require(!loaded.ok, "head with missing record accepted");
    }
    clean(p8);

    std::cout << "TRU_VAH_01F_PERSISTENCE_BOUNDARY_MATRIX=PASS\n";
    return 0;
}
