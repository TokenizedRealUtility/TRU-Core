#include "vah_sensor_batch.h"

#include "crypto_ecdsa.h"
#include "vah_authorization.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

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

VAHSensorBatch::Batch baseBatch(const std::string& token) {
    VAHSensorBatch::Batch batch;
    batch.token_id = token;
    batch.token_type = "SFT";
    batch.epoch = 7U;
    batch.previous_batch_hash = std::string(64U, '0');
    batch.events = {
        {100U, 1700000000000ULL, "sentiment_score", std::string(64U, 'a')},
        {101U, 1700000001000ULL, "sentiment_score", std::string(64U, 'b')},
        {102U, 1700000002000ULL, "sentiment_score", std::string(64U, 'c')}
    };
    return batch;
}

} // namespace

int main() {
    const std::string token = "2df1363f156c50b8";
    const ECDSAKey root = ECDSAKey::generate();
    const ECDSAKey sensor = ECDSAKey::generate();
    const ECDSAKey other = ECDSAKey::generate();
    const std::string rootPub = hexLower(root.getCompressedSec1());
    std::vector<VAHAuthorization::AuthorizationRecord> history = {
        authorizeSensor(token, sensor, root, rootPub)
    };

    std::string reason;
    auto batch = baseBatch(token);
    assert(VAHSensorBatch::signBatch(batch, sensor, &reason));
    assert(VAHSensorBatch::verifyBatch(batch, history, rootPub, &reason));
    assert(batch.merkle_root.size() == 64U);
    assert(batch.batch_hash == VAHSensorBatch::batchDigestHex(batch));
    assert(batch.batch_hash != std::string(64U, '0'));

    // Determinism: identical semantics produce identical root/hash even though
    // a fresh ECDSA signature can differ.
    auto same = baseBatch(token);
    assert(VAHSensorBatch::signBatch(same, sensor, &reason));
    assert(same.merkle_root == batch.merkle_root);
    assert(same.batch_hash == batch.batch_hash);

    // Every leaf in an odd-width tree has a valid canonical proof.
    for (std::size_t i = 0; i < batch.events.size(); ++i) {
        std::vector<std::string> proof;
        assert(VAHSensorBatch::buildInclusionProof(batch, i, proof, &reason));
        assert(VAHSensorBatch::verifyInclusionProof(
            batch, batch.events[i], i, batch.events.size(), proof, batch.merkle_root, &reason));

        auto tamperedEvent = batch.events[i];
        tamperedEvent.payload_hash[0] = tamperedEvent.payload_hash[0] == 'a' ? 'd' : 'a';
        assert(!VAHSensorBatch::verifyInclusionProof(
            batch, tamperedEvent, i, batch.events.size(), proof, batch.merkle_root, &reason));
    }

    // Leaf/proof transplant into another feed branch fails because leaf hashes
    // commit token/epoch/previous_batch_hash/writer identity.
    std::vector<std::string> proof;
    assert(VAHSensorBatch::buildInclusionProof(batch, 1U, proof, &reason));
    auto otherBranch = batch;
    otherBranch.previous_batch_hash = std::string(64U, 'd');
    assert(!VAHSensorBatch::verifyInclusionProof(
        otherBranch, batch.events[1], 1U, batch.events.size(), proof, batch.merkle_root, &reason));

    // Reordering breaks canonical contiguous sequence order and therefore cannot
    // be resigned into an alternative root for the same event set.
    auto reordered = baseBatch(token);
    std::swap(reordered.events[0], reordered.events[1]);
    assert(!VAHSensorBatch::signBatch(reordered, sensor, &reason));

    // Gapped and duplicate sequence numbers are rejected.
    auto gap = baseBatch(token);
    gap.events[1].sequence = 103U;
    assert(!VAHSensorBatch::signBatch(gap, sensor, &reason));
    auto duplicate = baseBatch(token);
    duplicate.events[1].sequence = 100U;
    assert(!VAHSensorBatch::signBatch(duplicate, sensor, &reason));

    // Timestamp regression and zero payload hashes are rejected.
    auto timeBackwards = baseBatch(token);
    timeBackwards.events[1].observed_at_ms = timeBackwards.events[0].observed_at_ms - 1U;
    assert(!VAHSensorBatch::signBatch(timeBackwards, sensor, &reason));
    auto zeroPayload = baseBatch(token);
    zeroPayload.events[0].payload_hash = std::string(64U, '0');
    assert(!VAHSensorBatch::signBatch(zeroPayload, sensor, &reason));

    // Sensor batches cannot cross typed capability boundaries.
    auto deviceField = baseBatch(token);
    deviceField.events[0].field = "operating_state";
    assert(!VAHSensorBatch::signBatch(deviceField, sensor, &reason));

    // An unauthorized sensor may self-sign but cannot pass historical auth.
    auto unauthorized = baseBatch(token);
    assert(VAHSensorBatch::signBatch(unauthorized, other, &reason));
    assert(!VAHSensorBatch::verifyBatch(unauthorized, history, rootPub, &reason));

    // Post-sign tampering of a leaf, root, chained predecessor, or batch hash is
    // detected before/at signature verification.
    auto tamperedLeaf = batch;
    tamperedLeaf.events[2].payload_hash[0] = 'd';
    assert(!VAHSensorBatch::verifyBatch(tamperedLeaf, history, rootPub, &reason));
    auto tamperedRoot = batch;
    tamperedRoot.merkle_root[0] = tamperedRoot.merkle_root[0] == 'a' ? 'b' : 'a';
    assert(!VAHSensorBatch::verifyBatch(tamperedRoot, history, rootPub, &reason));
    auto tamperedPrevious = batch;
    tamperedPrevious.previous_batch_hash = std::string(64U, 'e');
    assert(!VAHSensorBatch::verifyBatch(tamperedPrevious, history, rootPub, &reason));
    auto tamperedHash = batch;
    tamperedHash.batch_hash[0] = tamperedHash.batch_hash[0] == 'a' ? 'b' : 'a';
    assert(!VAHSensorBatch::verifyBatch(tamperedHash, history, rootPub, &reason));

    // Hard batch bound: 256 accepted, 257 rejected.
    auto maxBatch = baseBatch(token);
    maxBatch.events.clear();
    for (std::uint64_t i = 0; i < VAHSensorBatch::MAX_EVENTS_PER_BATCH; ++i) {
        maxBatch.events.push_back({
            1000U + i,
            1700001000000ULL + i,
            "sentiment_score",
            std::string(63U, 'a') + "1"
        });
    }
    assert(VAHSensorBatch::signBatch(maxBatch, sensor, &reason));
    assert(VAHSensorBatch::verifyBatch(maxBatch, history, rootPub, &reason));
    maxBatch.events.push_back({
        1000U + VAHSensorBatch::MAX_EVENTS_PER_BATCH,
        1700001000000ULL + VAHSensorBatch::MAX_EVENTS_PER_BATCH,
        "sentiment_score",
        std::string(63U, 'b') + "2"
    });
    assert(!VAHSensorBatch::signBatch(maxBatch, sensor, &reason));

    // Proof shape is count-bound: a proof from a 3-leaf tree cannot be declared
    // as belonging to a different event_count.
    assert(VAHSensorBatch::buildInclusionProof(batch, 2U, proof, &reason));
    assert(!VAHSensorBatch::verifyInclusionProof(
        batch, batch.events[2], 2U, 4U, proof, batch.merkle_root, &reason));

    std::cout << "TRU_VAH_04A_CANONICAL_SENSOR_BATCH_MERKLE_MATRIX=PASS\n";
    return 0;
}
