#include "vah_authorization.h"
#include "crypto_ecdsa.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

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

} // namespace

int main() {
    using namespace VAHAuthorization;

    const std::string tokenId = "2df1363f156c50b8";
    const std::string zeroHash(64, '0');

    ECDSAKey root = ECDSAKey::generate();
    ECDSAKey fakeRoot = ECDSAKey::generate();
    ECDSAKey sensor1 = ECDSAKey::generate();
    ECDSAKey sensor2 = ECDSAKey::generate();
    ECDSAKey human1 = ECDSAKey::generate();

    const std::string rootHex = hexLower(root.getCompressedSec1());
    const std::string fakeRootHex = hexLower(fakeRoot.getCompressedSec1());

    auto a1 = makeRecord(
        tokenId, 1, 5, Action::AUTHORIZE, root, sensor1, "sensor",
        {"SENSOR_MEASUREMENT"}, zeroHash);

    std::string reason;
    require(verifyAuthorizationRecord(a1, "NCFT", rootHex, &reason), "valid AUTHORIZE rejected: " + reason);

    std::vector<AuthorizationRecord> history{a1};
    auto hv = verifyAuthorizationHistory(history, "NCFT", rootHex);
    require(hv.ok && hv.verified_records == 1, "single-record history rejected");

    require(!isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 4, a1.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "writer active before effective epoch");

    require(isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 5, a1.writer_pubkey_hex, "sensor",
        {"emotion_response", "synaptic_pattern_id"}, &reason),
        "authorized sensor fields rejected: " + reason);

    require(!isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 5, a1.writer_pubkey_hex, "sensor",
        {"style_descriptor"}, &reason), "sensor incorrectly authorized for AI_CREATIVE field");

    require(!verifyAuthorizationRecord(a1, "NCFT", fakeRootHex, &reason),
            "independently trusted root mismatch accepted");

    auto tampered = a1;
    tampered.capabilities = {"DEVICE_STATE"};
    require(!verifyAuthorizationRecord(tampered, "NCFT", rootHex, &reason),
            "post-signature capability tamper accepted");

    auto malformedSig = a1;
    malformedSig.signature_der_hex = "00";
    require(!verifyAuthorizationRecord(malformedSig, "NCFT", rootHex, &reason),
            "malformed signature accepted");

    auto fake = makeRecord(
        tokenId, 1, 5, Action::AUTHORIZE, fakeRoot, sensor1, "sensor",
        {"SENSOR_MEASUREMENT"}, zeroHash);
    require(!verifyAuthorizationRecord(fake, "NCFT", rootHex, &reason),
            "self-declared fake authorization root accepted");

    auto rotate = makeRecord(
        tokenId, 2, 10, Action::ROTATE, root, sensor2, "sensor",
        {"SENSOR_MEASUREMENT"}, a1.record_hash, a1.writer_id);
    history.push_back(rotate);
    hv = verifyAuthorizationHistory(history, "NCFT", rootHex);
    require(hv.ok && hv.verified_records == 2, "valid ROTATE history rejected");

    require(isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 9, a1.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "old key not historically valid before rotation");
    require(!isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 10, a1.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "old key remained valid at rotation epoch");
    require(isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 10, rotate.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "new key not valid at rotation epoch");

    auto revoke = makeRecord(
        tokenId, 3, 20, Action::REVOKE, root, sensor2, "sensor",
        {}, rotate.record_hash);
    history.push_back(revoke);
    hv = verifyAuthorizationHistory(history, "NCFT", rootHex);
    require(hv.ok && hv.verified_records == 3, "valid REVOKE history rejected");

    require(isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 19, rotate.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "writer not historically valid before revocation");
    require(!isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 20, rotate.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "revoked writer remained valid at revocation epoch");
    require(isWriterAuthorizedAtEpoch(
        history, "NCFT", rootHex, 9, a1.writer_pubkey_hex, "sensor",
        {"emotion_response"}, &reason), "later revocation rewrote valid earlier history");

    std::string encoded = serializeAuthorizationRecord(a1);
    AuthorizationRecord parsed;
    require(parseAuthorizationRecord(encoded, parsed, &reason), "record parse failed: " + reason);
    require(serializeAuthorizationRecord(parsed) == encoded, "record serialization round-trip mismatch");
    require(verifyAuthorizationRecord(parsed, "NCFT", rootHex, &reason), "round-tripped record failed verification");

    auto badPrev = history;
    badPrev[1].previous_record_hash = zeroHash;
    hv = verifyAuthorizationHistory(badPrev, "NCFT", rootHex);
    require(!hv.ok, "broken history hash link accepted");

    auto badSeq = history;
    badSeq[1].sequence = 3;
    hv = verifyAuthorizationHistory(badSeq, "NCFT", rootHex);
    require(!hv.ok, "history sequence gap accepted");

    auto duplicateAuthorize = makeRecord(
        tokenId, 2, 6, Action::AUTHORIZE, root, sensor1, "sensor",
        {"SENSOR_MEASUREMENT"}, a1.record_hash);
    hv = verifyAuthorizationHistory({a1, duplicateAuthorize}, "NCFT", rootHex);
    require(!hv.ok, "duplicate active writer authorization accepted");

    auto badClassRotation = makeRecord(
        tokenId, 2, 10, Action::ROTATE, root, human1, "human",
        {"HUMAN_ASSERTION"}, a1.record_hash, a1.writer_id);
    hv = verifyAuthorizationHistory({a1, badClassRotation}, "NCFT", rootHex);
    require(!hv.ok, "ROTATE changed writer class");

    auto invalidPair = makeRecord(
        tokenId, 1, 1, Action::AUTHORIZE, root, human1, "human",
        {"SENSOR_MEASUREMENT"}, zeroHash);
    require(!verifyAuthorizationRecord(invalidPair, "NCFT", rootHex, &reason),
            "human writer accepted SENSOR_MEASUREMENT capability");

    std::cout << "TRU_VAH_01DE_SIGNED_AUTH_HISTORY_MATRIX=PASS\n";
    return 0;
}
