#include "vah_external_writer_gate.h"

#include "crypto_ecdsa.h"
#include "vah_authorization.h"

#include <cassert>
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

VAHAuthorization::AuthorizationRecord authorize(
    std::uint64_t sequence,
    std::uint64_t effectiveEpoch,
    const std::string& previousRecordHash,
    const std::string& token,
    const std::string& writerClass,
    const std::string& capability,
    const ECDSAKey& writer,
    const ECDSAKey& root,
    const std::string& rootPub)
{
    VAHAuthorization::AuthorizationRecord record;
    record.sequence = sequence;
    record.effective_epoch = effectiveEpoch;
    record.action = VAHAuthorization::Action::AUTHORIZE;
    record.token_id = token;
    record.writer_pubkey_hex = hexLower(writer.getCompressedSec1());
    record.writer_class = writerClass;
    record.capabilities = {capability};
    record.previous_record_hash = previousRecordHash;
    record.authorization_root_pubkey_hex = rootPub;
    std::string reason;
    assert(VAHAuthorization::signAuthorizationRecord(record, root, &reason));
    return record;
}

VAHExternalWriter::Claim baseClaim(
    const std::string& token,
    const std::string& writerClass,
    const std::vector<std::string>& fields)
{
    VAHExternalWriter::Claim claim;
    claim.token_id = token;
    claim.token_type = "SFT";
    claim.epoch = 7U;
    claim.previous_metadata_hash = std::string(64U, 'a');
    claim.new_metadata_hash = std::string(64U, 'b');
    claim.writer_class = writerClass;
    claim.changed_fields = fields;
    return claim;
}

} // namespace

int main() {
    const std::string token = "2df1363f156c50b8";
    const ECDSAKey root = ECDSAKey::generate();
    const ECDSAKey sensor = ECDSAKey::generate();
    const ECDSAKey human = ECDSAKey::generate();
    const ECDSAKey device = ECDSAKey::generate();
    const ECDSAKey unauthorized = ECDSAKey::generate();
    const std::string rootPub = hexLower(root.getCompressedSec1());

    std::vector<VAHAuthorization::AuthorizationRecord> history;
    history.push_back(authorize(
        1U, 2U, std::string(64U, '0'), token,
        "sensor", "SENSOR_MEASUREMENT", sensor, root, rootPub));
    history.push_back(authorize(
        2U, 2U, history.back().record_hash, token,
        "human", "HUMAN_ASSERTION", human, root, rootPub));
    history.push_back(authorize(
        3U, 2U, history.back().record_hash, token,
        "device", "DEVICE_STATE", device, root, rootPub));

    std::string reason;
    const auto verifiedHistory = VAHAuthorization::verifyAuthorizationHistory(history, "SFT", rootPub);
    assert(verifiedHistory.ok);

    // SENSOR / HUMAN / DEVICE each pass only their typed, historically granted field.
    auto sensorClaim = baseClaim(token, "sensor", {"sentiment_score"});
    assert(VAHExternalWriter::signClaim(sensorClaim, sensor, &reason));
    assert(VAHExternalWriter::verifyClaim(sensorClaim, history, rootPub, &reason));
    assert(sensorClaim.record_hash == VAHExternalWriter::claimDigestHex(sensorClaim));
    assert(sensorClaim.record_hash != std::string(64U, '0'));

    auto humanClaim = baseClaim(token, "human", {"privacy_level"});
    assert(VAHExternalWriter::signClaim(humanClaim, human, &reason));
    assert(VAHExternalWriter::verifyClaim(humanClaim, history, rootPub, &reason));

    auto deviceClaim = baseClaim(token, "device", {"operating_state"});
    assert(VAHExternalWriter::signClaim(deviceClaim, device, &reason));
    assert(VAHExternalWriter::verifyClaim(deviceClaim, history, rootPub, &reason));

    // A valid writer cannot cross typed capability boundaries.
    auto wrongField = baseClaim(token, "sensor", {"operating_state"});
    assert(!VAHExternalWriter::signClaim(wrongField, sensor, &reason));

    // AI/software remain outside the VAH-03 external-writer activation class set.
    auto aiClaim = baseClaim(token, "ai", {"description_ai"});
    assert(!VAHExternalWriter::signClaim(aiClaim, sensor, &reason));
    auto softwareClaim = baseClaim(token, "software", {"context_signal"});
    assert(!VAHExternalWriter::signClaim(softwareClaim, sensor, &reason));

    // An un-authorized key cannot pass even with a valid self-signature.
    auto unauthorizedClaim = baseClaim(token, "sensor", {"sentiment_score"});
    assert(VAHExternalWriter::signClaim(unauthorizedClaim, unauthorized, &reason));
    assert(!VAHExternalWriter::verifyClaim(unauthorizedClaim, history, rootPub, &reason));

    // Signature/digest binding: any post-sign mutation fails closed.
    auto tampered = sensorClaim;
    tampered.new_metadata_hash[0] = 'c';
    assert(!VAHExternalWriter::verifyClaim(tampered, history, rootPub, &reason));

    // Canonical field ordering prevents equivalent-but-differently-encoded claims.
    auto unordered = baseClaim(token, "sensor", {"sentiment_score", "bio_sensor_trigger"});
    assert(!VAHExternalWriter::signClaim(unordered, sensor, &reason));
    auto duplicated = baseClaim(token, "sensor", {"sentiment_score", "sentiment_score"});
    assert(!VAHExternalWriter::signClaim(duplicated, sensor, &reason));

    // Add a signed revoke effective at epoch 8; epoch 7 stays valid while epoch 8 fails.
    VAHAuthorization::AuthorizationRecord revoke;
    revoke.sequence = 4U;
    revoke.effective_epoch = 8U;
    revoke.action = VAHAuthorization::Action::REVOKE;
    revoke.token_id = token;
    revoke.writer_pubkey_hex = hexLower(sensor.getCompressedSec1());
    revoke.writer_class = "sensor";
    revoke.previous_record_hash = history.back().record_hash;
    revoke.authorization_root_pubkey_hex = rootPub;
    assert(VAHAuthorization::signAuthorizationRecord(revoke, root, &reason));
    history.push_back(revoke);
    assert(VAHExternalWriter::verifyClaim(sensorClaim, history, rootPub, &reason));

    auto afterRevoke = baseClaim(token, "sensor", {"sentiment_score"});
    afterRevoke.epoch = 8U;
    assert(VAHExternalWriter::signClaim(afterRevoke, sensor, &reason));
    assert(!VAHExternalWriter::verifyClaim(afterRevoke, history, rootPub, &reason));

    // Independently supplied authorization root is mandatory.
    const ECDSAKey wrongRoot = ECDSAKey::generate();
    assert(!VAHExternalWriter::verifyClaim(
        humanClaim, history, hexLower(wrongRoot.getCompressedSec1()), &reason));

    std::cout << "TRU_VAH_03A_CONTROLLED_EXTERNAL_WRITER_ACTIVATION_GATE_MATRIX=PASS\n";
    return 0;
}
