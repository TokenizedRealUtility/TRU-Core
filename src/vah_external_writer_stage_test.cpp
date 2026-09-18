#include "vah_external_writer_stage.h"

#include "crypto_ecdsa.h"
#include "leveldb_storage.h"
#include "vah_authorization.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
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

std::string hex64(std::uint64_t value) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setw(64) << std::setfill('0') << value;
    return oss.str();
}

VAHAuthorization::AuthorizationRecord authorizeSensor(
    const std::string& token,
    const ECDSAKey& sensor,
    const ECDSAKey& root,
    const std::string& rootPub)
{
    VAHAuthorization::AuthorizationRecord record;
    record.sequence = 1U;
    record.effective_epoch = 2U;
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

VAHExternalWriter::Claim makeSensorClaim(
    const std::string& token,
    const ECDSAKey& sensor,
    std::uint64_t discriminator,
    std::uint64_t epoch = 7U)
{
    VAHExternalWriter::Claim claim;
    claim.token_id = token;
    claim.token_type = "SFT";
    claim.epoch = epoch;
    claim.previous_metadata_hash = std::string(64U, 'a');
    claim.new_metadata_hash = hex64(0x1000U + discriminator);
    claim.writer_class = "sensor";
    claim.changed_fields = {"sentiment_score"};
    std::string reason;
    assert(VAHExternalWriter::signClaim(claim, sensor, &reason));
    return claim;
}

std::string tempPath(const std::string& tag) {
    return "/tmp/truq-vah03b-" + tag + "-" + std::to_string(::getpid());
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
    const ECDSAKey unauthorized = ECDSAKey::generate();
    const std::string rootPub = hexLower(root.getCompressedSec1());
    const std::vector<VAHAuthorization::AuthorizationRecord> history = {
        authorizeSensor(token, sensor, root, rootPub)
    };
    std::string reason;

    // Basic append + exact replay + restart reconstruction.
    const std::string restartPath = tempPath("restart");
    rm(restartPath);
    const auto c1 = makeSensorClaim(token, sensor, 1U);
    const auto c2 = makeSensorClaim(token, sensor, 2U);
    {
        LevelDBStorage storage(restartPath);
        assert(VAHExternalWriterStage::stageClaim(storage, c1, history, rootPub, &reason));
        assert(VAHExternalWriterStage::stageClaim(storage, c1, history, rootPub, &reason));
        assert(reason == "ok-idempotent");
        assert(VAHExternalWriterStage::stageClaim(storage, c2, history, rootPub, &reason));
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(loaded.ok);
        assert(loaded.claims.size() == 2U);
        assert(loaded.claims[0].record_hash < loaded.claims[1].record_hash);
    }
    {
        LevelDBStorage storage(restartPath);
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(loaded.ok);
        assert(loaded.claims.size() == 2U);
        assert(VAHExternalWriterStage::stageClaim(storage, c1, history, rootPub, &reason));
        assert(reason == "ok-idempotent");
    }
    rm(restartPath);

    // Intake must not persist claims that fail VAH-03A.
    const std::string deniedPath = tempPath("denied");
    rm(deniedPath);
    {
        LevelDBStorage storage(deniedPath);
        auto denied = makeSensorClaim(token, unauthorized, 3U);
        assert(!VAHExternalWriterStage::stageClaim(storage, denied, history, rootPub, &reason));
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(loaded.ok && loaded.claims.empty());

        auto tampered = c1;
        tampered.new_metadata_hash[0] = 'e';
        assert(!VAHExternalWriterStage::stageClaim(storage, tampered, history, rootPub, &reason));
        const auto after = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(after.ok && after.claims.empty());
    }
    rm(deniedPath);

    // Strict TOKEN:VAH_PENDING checksum boundary: a parseable one-byte change
    // written through generic put() must fail before legacy upgrade-on-read,
    // and the failed read must not rewrite/launder the raw tampered bytes.
    const std::string corruptPath = tempPath("checksum");
    rm(corruptPath);
    std::string tamperedRawBefore;
    {
        LevelDBStorage storage(corruptPath);
        assert(VAHExternalWriterStage::stageClaim(storage, c1, history, rootPub, &reason));
        const std::string key = VAHExternalWriterStage::pendingClaimKey(
            c1.token_id, c1.epoch, c1.record_hash);
        std::string encoded;
        assert(storage.getContract(key, encoded));
        const std::string needle = "new_metadata_hash=";
        const auto pos = encoded.find(needle);
        assert(pos != std::string::npos);
        const auto bytePos = pos + needle.size();
        encoded[bytePos] = (encoded[bytePos] == 'e' ? 'd' : 'e');
        VAHExternalWriter::Claim stillParses;
        assert(VAHExternalWriterStage::parsePendingClaim(encoded, stillParses, &reason));
        assert(storage.put(key, encoded));
        bool found = false;
        assert(storage.getRaw(key, tamperedRawBefore, found) && found);
    }
    {
        LevelDBStorage storage(corruptPath);
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(!loaded.ok);
        assert(!loaded.errors.empty());
        assert(loaded.errors.front() == "pending claim not found or checksum-invalid");
        const std::string key = VAHExternalWriterStage::pendingClaimKey(
            c1.token_id, c1.epoch, c1.record_hash);
        std::string rawAfter;
        bool found = false;
        assert(storage.getRaw(key, rawAfter, found) && found);
        assert(rawAfter == tamperedRawBefore);
    }
    rm(corruptPath);

    // A valid contract checksum is not enough: malformed/key-mismatched staged
    // content still fails closed at the canonical envelope/content layer.
    const std::string malformedPath = tempPath("malformed");
    rm(malformedPath);
    {
        LevelDBStorage storage(malformedPath);
        const std::string key = VAHExternalWriterStage::pendingClaimKey(
            c1.token_id, c1.epoch, c1.record_hash);
        assert(storage.putContract(key, "TRU_VAH_PENDING_CLAIM_V1\nformat_version=1\n"));
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(!loaded.ok);
        assert(!loaded.errors.empty());
    }
    rm(malformedPath);

    // Resource bound: prefill exactly MAX canonical valid claims, prove one
    // more is rejected while exact replay remains accepted at the bound.
    const std::string boundPath = tempPath("bound");
    rm(boundPath);
    std::vector<VAHExternalWriter::Claim> boundClaims;
    boundClaims.reserve(VAHExternalWriterStage::MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH);
    {
        LevelDBStorage storage(boundPath);
        for (std::size_t i = 0U;
             i < VAHExternalWriterStage::MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH;
             ++i) {
            auto claim = makeSensorClaim(token, sensor, 100U + i);
            boundClaims.push_back(claim);
            assert(storage.putContract(
                VAHExternalWriterStage::pendingClaimKey(token, 7U, claim.record_hash),
                VAHExternalWriterStage::serializePendingClaim(claim)));
        }
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(loaded.ok);
        assert(loaded.claims.size() == VAHExternalWriterStage::MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH);

        auto overflow = makeSensorClaim(token, sensor, 999U);
        assert(!VAHExternalWriterStage::stageClaim(storage, overflow, history, rootPub, &reason));
        assert(reason == "pending claim resource bound reached");
        assert(VAHExternalWriterStage::stageClaim(
            storage, boundClaims.front(), history, rootPub, &reason));
        assert(reason == "ok-idempotent");
    }
    rm(boundPath);

    // Simultaneous local first writers cannot overrun the per-token/epoch cap.
    const std::string racePath = tempPath("race");
    rm(racePath);
    {
        LevelDBStorage storage(racePath);
        for (std::size_t i = 0U;
             i + 1U < VAHExternalWriterStage::MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH;
             ++i) {
            const auto claim = makeSensorClaim(token, sensor, 2000U + i);
            assert(storage.putContract(
                VAHExternalWriterStage::pendingClaimKey(token, 7U, claim.record_hash),
                VAHExternalWriterStage::serializePendingClaim(claim)));
        }

        const auto a = makeSensorClaim(token, sensor, 3001U);
        const auto b = makeSensorClaim(token, sensor, 3002U);
        bool okA = false;
        bool okB = false;
        std::thread t1([&] {
            std::string localReason;
            okA = VAHExternalWriterStage::stageClaim(storage, a, history, rootPub, &localReason);
        });
        std::thread t2([&] {
            std::string localReason;
            okB = VAHExternalWriterStage::stageClaim(storage, b, history, rootPub, &localReason);
        });
        t1.join();
        t2.join();
        assert(okA != okB);
        const auto loaded = VAHExternalWriterStage::loadPendingClaims(
            storage, token, 7U, history, rootPub);
        assert(loaded.ok);
        assert(loaded.claims.size() == VAHExternalWriterStage::MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH);
    }
    rm(racePath);

    std::cout << "TRU_VAH_03B_BOUNDED_LOCAL_CLAIM_INTAKE_DURABLE_STAGING_MATRIX=PASS\n";
    return 0;
}
