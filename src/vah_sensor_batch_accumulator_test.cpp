#include "vah_sensor_batch_accumulator.h"

#include "crypto_ecdsa.h"
#include "leveldb_storage.h"
#include "vah_authorization.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

namespace fs = std::filesystem;

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

VAHAuthorization::AuthorizationRecord authorizeSensor(
    const std::string& token,
    const ECDSAKey& sensor,
    const ECDSAKey& root,
    const std::string& rootPub)
{
    VAHAuthorization::AuthorizationRecord rec;
    rec.sequence = 1U;
    rec.effective_epoch = 1U;
    rec.action = VAHAuthorization::Action::AUTHORIZE;
    rec.token_id = token;
    rec.writer_pubkey_hex = hexLower(sensor.getCompressedSec1());
    rec.writer_class = "sensor";
    rec.capabilities = {"SENSOR_MEASUREMENT"};
    rec.previous_record_hash = std::string(64U, '0');
    rec.authorization_root_pubkey_hex = rootPub;
    std::string reason;
    assert(VAHAuthorization::signAuthorizationRecord(rec, root, &reason));
    return rec;
}

VAHSensorBatch::Batch makeBatch(
    const std::string& token,
    const ECDSAKey& sensor,
    std::uint64_t epoch,
    const std::string& previousHash,
    std::uint64_t firstSequence,
    std::uint64_t firstTimestamp,
    char payloadNibble,
    std::size_t eventCount = 3U)
{
    VAHSensorBatch::Batch batch;
    batch.token_id = token;
    batch.token_type = "SFT";
    batch.epoch = epoch;
    batch.previous_batch_hash = previousHash;
    for (std::size_t i = 0U; i < eventCount; ++i) {
        batch.events.push_back({
            firstSequence + static_cast<std::uint64_t>(i),
            firstTimestamp + static_cast<std::uint64_t>(i) * 1000U,
            "sentiment_score",
            std::string(63U, payloadNibble) + static_cast<char>('1' + (i % 8U))
        });
    }
    std::string reason;
    assert(VAHSensorBatch::signBatch(batch, sensor, &reason));
    return batch;
}

std::string tempPath(const std::string& tag) {
    return "/tmp/truq-vah04b-" + tag + "-" + std::to_string(::getpid());
}

void rm(const std::string& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
}

} // namespace

int main() {
    const std::string token = "2df1363f156c50b8";
    const ECDSAKey root = ECDSAKey::generate();
    const ECDSAKey sensor = ECDSAKey::generate();
    const ECDSAKey other = ECDSAKey::generate();
    const std::string rootPub = hexLower(root.getCompressedSec1());
    const std::vector<VAHAuthorization::AuthorizationRecord> history = {
        authorizeSensor(token, sensor, root, rootPub)
    };
    std::string reason;

    // Genesis -> continuation -> cross-epoch continuation -> old replay -> restart.
    const std::string restartPath = tempPath("restart");
    rm(restartPath);
    const auto b1 = makeBatch(token, sensor, 7U, std::string(64U, '0'), 1U, 1700000000000ULL, 'a');
    const auto b2 = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1700000004000ULL, 'b');
    const auto b3 = makeBatch(token, sensor, 8U, b2.batch_hash, 7U, 1700000008000ULL, 'c');
    {
        LevelDBStorage storage(restartPath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b2, history, rootPub, &reason));
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b3, history, rootPub, &reason));
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        assert(reason == "ok-idempotent");

        // A fresh valid signature over identical semantics is also semantic replay.
        auto resign = makeBatch(token, sensor, 7U, std::string(64U, '0'), 1U, 1700000000000ULL, 'a');
        assert(resign.batch_hash == b1.batch_hash);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, resign, history, rootPub, &reason));
        assert(reason == "ok-idempotent");

        const auto head = VAHSensorBatchAccumulator::loadFeedHead(
            storage, token, b1.writer_id, history, rootPub);
        assert(head.ok && head.has_head);
        assert(head.head.batch_count == 3U);
        assert(head.head.latest_epoch == 8U);
        assert(head.head.last_sequence == 9U);
        assert(head.head.last_batch_hash == b3.batch_hash);
    }
    {
        LevelDBStorage storage(restartPath);
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(
            storage, token, b1.writer_id, history, rootPub);
        assert(head.ok && head.has_head && head.head.batch_count == 3U);
        VAHSensorBatchAccumulator::StoredBatch old;
        assert(VAHSensorBatchAccumulator::loadStoredBatch(storage, token, b1.writer_id,
            1U, b1.batch_hash, history, rootPub, old, &reason));
        assert(old.feed_index == 1U && old.previous_first_sequence == 0U);
    }
    rm(restartPath);

    // Continuity failures must not advance the durable head.
    const std::string continuityPath = tempPath("continuity");
    rm(continuityPath);
    {
        LevelDBStorage storage(continuityPath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        auto wrongPrev = makeBatch(token, sensor, 7U, std::string(64U, 'e'), 4U, 1700000004000ULL, 'd');
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, wrongPrev, history, rootPub, &reason));
        auto gap = makeBatch(token, sensor, 7U, b1.batch_hash, 5U, 1700000004000ULL, 'e');
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, gap, history, rootPub, &reason));
        auto timeBack = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1699999999000ULL, 'f');
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, timeBack, history, rootPub, &reason));
        auto epochBack = makeBatch(token, sensor, 6U, b1.batch_hash, 4U, 1700000004000ULL, 'a');
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, epochBack, history, rootPub, &reason));
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, b1.writer_id, history, rootPub);
        assert(head.ok && head.has_head && head.head.batch_count == 1U);
    }
    rm(continuityPath);

    // Unauthorized batches fail before persistence.
    const std::string deniedPath = tempPath("denied");
    rm(deniedPath);
    {
        LevelDBStorage storage(deniedPath);
        const auto denied = makeBatch(token, other, 7U, std::string(64U, '0'), 1U, 1700000000000ULL, 'a');
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, denied, history, rootPub, &reason));
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, denied.writer_id, history, rootPub);
        assert(head.ok && !head.has_head);
    }
    rm(deniedPath);

    // Competing current-head branch: first committed branch wins.
    const std::string forkPath = tempPath("fork");
    rm(forkPath);
    {
        LevelDBStorage storage(forkPath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        const auto a = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1700000004000ULL, 'a');
        const auto b = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1700000004000ULL, 'b');
        assert(a.batch_hash != b.batch_hash);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, a, history, rootPub, &reason));
        assert(!VAHSensorBatchAccumulator::appendBatch(storage, b, history, rootPub, &reason));
    }
    rm(forkPath);

    // Concurrent competing first writers are serialized: exactly one branch advances.
    const std::string racePath = tempPath("race");
    rm(racePath);
    {
        LevelDBStorage storage(racePath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        const auto a = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1700000004000ULL, 'c');
        const auto b = makeBatch(token, sensor, 7U, b1.batch_hash, 4U, 1700000004000ULL, 'd');
        bool okA = false;
        bool okB = false;
        std::thread t1([&] { std::string r; okA = VAHSensorBatchAccumulator::appendBatch(storage, a, history, rootPub, &r); });
        std::thread t2([&] { std::string r; okB = VAHSensorBatchAccumulator::appendBatch(storage, b, history, rootPub, &r); });
        t1.join();
        t2.join();
        assert(okA != okB);
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, b1.writer_id, history, rootPub);
        assert(head.ok && head.has_head && head.head.batch_count == 2U && head.head.last_sequence == 6U);
    }
    rm(racePath);

    // Strict stored-batch checksum boundary: parseable one-byte tamper through
    // generic put() fails closed and is not laundered/upgraded on read.
    const std::string batchCorruptPath = tempPath("batch-corrupt");
    rm(batchCorruptPath);
    std::string batchRawBefore;
    {
        LevelDBStorage storage(batchCorruptPath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        const std::string key = VAHSensorBatchAccumulator::accumulatedBatchKey(token, b1.writer_id, 1U, b1.batch_hash);
        std::string encoded;
        assert(storage.getContract(key, encoded));
        const std::string needle = "event_0000_payload_hash=";
        const auto pos = encoded.find(needle);
        assert(pos != std::string::npos);
        const auto p = pos + needle.size();
        encoded[p] = encoded[p] == 'a' ? 'b' : 'a';
        VAHSensorBatchAccumulator::StoredBatch parsed;
        assert(VAHSensorBatchAccumulator::parseStoredBatch(encoded, parsed, &reason));
        assert(storage.put(key, encoded));
        bool found = false;
        assert(storage.getRaw(key, batchRawBefore, found) && found);
    }
    {
        LevelDBStorage storage(batchCorruptPath);
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, b1.writer_id, history, rootPub);
        assert(!head.ok);
        const std::string key = VAHSensorBatchAccumulator::accumulatedBatchKey(token, b1.writer_id, 1U, b1.batch_hash);
        std::string rawAfter;
        bool found = false;
        assert(storage.getRaw(key, rawAfter, found) && found);
        assert(rawAfter == batchRawBefore);
    }
    rm(batchCorruptPath);

    // Strict mutable head checksum boundary receives the same no-legacy policy.
    const std::string headCorruptPath = tempPath("head-corrupt");
    rm(headCorruptPath);
    std::string headRawBefore;
    {
        LevelDBStorage storage(headCorruptPath);
        assert(VAHSensorBatchAccumulator::appendBatch(storage, b1, history, rootPub, &reason));
        const std::string key = VAHSensorBatchAccumulator::feedHeadKey(token, b1.writer_id);
        std::string encoded;
        assert(storage.getContract(key, encoded));
        const std::string needle = "last_observed_at_ms=";
        const auto pos = encoded.find(needle);
        assert(pos != std::string::npos);
        const auto p = pos + needle.size();
        encoded[p] = encoded[p] == '1' ? '2' : '1';
        VAHSensorBatchAccumulator::FeedHead parsed;
        assert(VAHSensorBatchAccumulator::parseFeedHead(encoded, parsed, &reason));
        assert(storage.put(key, encoded));
        bool found = false;
        assert(storage.getRaw(key, headRawBefore, found) && found);
    }
    {
        LevelDBStorage storage(headCorruptPath);
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, b1.writer_id, history, rootPub);
        assert(!head.ok);
        const std::string key = VAHSensorBatchAccumulator::feedHeadKey(token, b1.writer_id);
        std::string rawAfter;
        bool found = false;
        assert(storage.getRaw(key, rawAfter, found) && found);
        assert(rawAfter == headRawBefore);
    }
    rm(headCorruptPath);

    // Valid checksum alone is insufficient for malformed durable state.
    const std::string malformedPath = tempPath("malformed");
    rm(malformedPath);
    {
        LevelDBStorage storage(malformedPath);
        assert(storage.putContract(VAHSensorBatchAccumulator::feedHeadKey(token, b1.writer_id),
            "TRU_VAH_SENSOR_FEED_HEAD_V1\nformat_version=1\n"));
        const auto head = VAHSensorBatchAccumulator::loadFeedHead(storage, token, b1.writer_id, history, rootPub);
        assert(!head.ok);
    }
    rm(malformedPath);

    // Byte/resource bound is checked before a durable envelope is accepted.
    VAHSensorBatchAccumulator::StoredBatch huge;
    huge.feed_index = 1U;
    huge.batch = b1;
    huge.batch.signature_der_hex.assign(VAHSensorBatchAccumulator::MAX_DURABLE_BATCH_BYTES, 'a');
    assert(VAHSensorBatchAccumulator::serializeStoredBatch(huge).size() >
        VAHSensorBatchAccumulator::MAX_DURABLE_BATCH_BYTES);
    VAHSensorBatchAccumulator::StoredBatch ignored;
    assert(!VAHSensorBatchAccumulator::parseStoredBatch(
        VAHSensorBatchAccumulator::serializeStoredBatch(huge), ignored, &reason));

    std::cout << "TRU_VAH_04B_LOCAL_BATCH_ACCUMULATOR_SEQUENCE_REPLAY_RESOURCE_MATRIX=PASS\n";
    return 0;
}
