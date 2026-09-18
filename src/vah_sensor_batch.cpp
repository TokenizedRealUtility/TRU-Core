#include "vah_sensor_batch.h"

#include "crypto_ecdsa.h"
#include "vah_capabilities.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* BATCH_DOMAIN = "TRU_VAH_SENSOR_BATCH_V1";
constexpr const char* LEAF_DOMAIN = "TRU_VAH_SENSOR_EVENT_LEAF_V1";
constexpr const char* NODE_DOMAIN = "TRU_VAH_SENSOR_MERKLE_NODE_V1";
constexpr std::size_t MAX_SIGNATURE_BYTES = 80U;

void setReason(std::string* reason, const std::string& text) {
    if (reason) *reason = text;
}

bool isLowerHex(const std::string& s, std::size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool isZeroHash(const std::string& s) {
    return s.size() == VAHSensorBatch::HASH_HEX_BYTES &&
        std::all_of(s.begin(), s.end(), [](char c) { return c == '0'; });
}

bool isCanonicalField(const std::string& field) {
    if (field.empty() || field.size() > VAHSensorBatch::MAX_FIELD_BYTES) return false;
    return std::all_of(field.begin(), field.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    });
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

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

bool hexDecodeLower(const std::string& hex, std::vector<unsigned char>& out, std::size_t maxBytes) {
    if (hex.empty() || (hex.size() % 2U) != 0U || hex.size() / 2U > maxBytes) return false;
    out.clear();
    out.reserve(hex.size() / 2U);
    auto nibble = [](char c, unsigned char& v) -> bool {
        if (c >= '0' && c <= '9') { v = static_cast<unsigned char>(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { v = static_cast<unsigned char>(10 + c - 'a'); return true; }
        return false;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        unsigned char hi = 0U, lo = 0U;
        if (!nibble(hex[i], hi) || !nibble(hex[i + 1U], lo)) return false;
        out.push_back(static_cast<unsigned char>((hi << 4U) | lo));
    }
    return true;
}

void appendU32BE(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

void appendU64BE(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>((value >> static_cast<unsigned>(shift)) & 0xffU));
    }
}

void appendLP(std::vector<unsigned char>& out, const std::string& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("length-prefixed value too large");
    }
    appendU32BE(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<unsigned char> domainHash(
    const char* domain,
    const std::vector<unsigned char>& left,
    const std::vector<unsigned char>& right = {})
{
    std::vector<unsigned char> preimage;
    const std::string d(domain);
    preimage.insert(preimage.end(), d.begin(), d.end());
    appendU32BE(preimage, static_cast<std::uint32_t>(left.size()));
    preimage.insert(preimage.end(), left.begin(), left.end());
    appendU32BE(preimage, static_cast<std::uint32_t>(right.size()));
    preimage.insert(preimage.end(), right.begin(), right.end());
    return sha256(preimage);
}

std::vector<unsigned char> leafHash(const VAHSensorBatch::Batch& batch, const VAHSensorBatch::Event& event, std::size_t eventCount) {
    std::vector<unsigned char> p;
    const std::string domain(LEAF_DOMAIN);
    p.insert(p.end(), domain.begin(), domain.end());
    appendLP(p, batch.token_id);
    appendLP(p, batch.token_type);
    appendU64BE(p, batch.epoch);
    appendLP(p, batch.previous_batch_hash);
    appendLP(p, batch.writer_id);
    appendU32BE(p, static_cast<std::uint32_t>(eventCount));
    appendU64BE(p, event.sequence);
    appendU64BE(p, event.observed_at_ms);
    appendLP(p, event.field);
    appendLP(p, event.payload_hash);
    return sha256(p);
}

std::vector<unsigned char> nodeHash(
    const std::vector<unsigned char>& left,
    const std::vector<unsigned char>& right)
{
    return domainHash(NODE_DOMAIN, left, right);
}

bool eventStructureChecks(const VAHSensorBatch::Batch& batch, std::string* reason) {
    if (!isLowerHex(batch.token_id, 16U)) {
        setReason(reason, "token_id must be canonical 16-lower-hex"); return false;
    }
    if (batch.token_type != "SFT" && batch.token_type != "NCFT") {
        setReason(reason, "unsupported token_type"); return false;
    }
    if (batch.epoch == 0U) {
        setReason(reason, "epoch must be >= 1"); return false;
    }
    if (!isLowerHex(batch.previous_batch_hash, 64U)) {
        setReason(reason, "previous_batch_hash must be 64-lower-hex"); return false;
    }
    if (batch.writer_class != "sensor") {
        setReason(reason, "VAH-04 sensor batches require writer_class=sensor"); return false;
    }
    if (!isLowerHex(batch.writer_pubkey_hex, 66U) ||
        (batch.writer_pubkey_hex.rfind("02", 0) != 0U && batch.writer_pubkey_hex.rfind("03", 0) != 0U)) {
        setReason(reason, "writer_pubkey_hex must be canonical compressed secp256k1"); return false;
    }
    if (!isLowerHex(batch.writer_id, 64U)) {
        setReason(reason, "writer_id must be 64-lower-hex"); return false;
    }
    if (batch.writer_id != VAHAuthorization::deriveWriterId(batch.writer_pubkey_hex)) {
        setReason(reason, "writer_id does not match writer public key"); return false;
    }
    if (batch.events.empty() || batch.events.size() > VAHSensorBatch::MAX_EVENTS_PER_BATCH) {
        setReason(reason, "sensor batch event count out of bounds"); return false;
    }

    std::uint64_t expectedSequence = batch.events.front().sequence;
    if (expectedSequence == 0U) {
        setReason(reason, "sensor event sequence must start above zero"); return false;
    }
    std::uint64_t previousObservedAt = 0U;
    for (const auto& event : batch.events) {
        if (event.sequence != expectedSequence) {
            setReason(reason, "sensor event sequence must be contiguous and canonical"); return false;
        }
        if (expectedSequence == std::numeric_limits<std::uint64_t>::max() && &event != &batch.events.back()) {
            setReason(reason, "sensor event sequence overflow"); return false;
        }
        if (event.observed_at_ms == 0U || event.observed_at_ms < previousObservedAt) {
            setReason(reason, "sensor event timestamps must be non-zero and nondecreasing"); return false;
        }
        if (!isCanonicalField(event.field) ||
            !VAHCapabilities::isKnownFieldForToken(batch.token_type, event.field) ||
            !VAHCapabilities::writerClassMayHoldFieldCapability(batch.token_type, "sensor", event.field)) {
            setReason(reason, "sensor event field is not sensor-capable: " + event.field); return false;
        }
        if (!isLowerHex(event.payload_hash, 64U) || isZeroHash(event.payload_hash)) {
            setReason(reason, "sensor event payload_hash must be non-zero 64-lower-hex"); return false;
        }
        previousObservedAt = event.observed_at_ms;
        if (&event != &batch.events.back()) ++expectedSequence;
    }
    return true;
}

std::vector<std::string> uniqueFields(const VAHSensorBatch::Batch& batch) {
    std::set<std::string> fields;
    for (const auto& event : batch.events) fields.insert(event.field);
    return std::vector<std::string>(fields.begin(), fields.end());
}

bool envelopeStructureChecks(const VAHSensorBatch::Batch& batch, std::string* reason) {
    if (batch.format_version != 1U) {
        setReason(reason, "unsupported sensor batch format_version"); return false;
    }
    if (!eventStructureChecks(batch, reason)) return false;
    const std::string expectedRoot = VAHSensorBatch::computeMerkleRootHex(batch);
    if (!isLowerHex(batch.merkle_root, 64U) || isZeroHash(batch.merkle_root) || batch.merkle_root != expectedRoot) {
        setReason(reason, "sensor batch merkle_root mismatch"); return false;
    }
    return true;
}

} // namespace

namespace VAHSensorBatch {

std::string eventLeafHashHex(const Batch& batch, const Event& event) {
    return hexLower(leafHash(batch, event, batch.events.size()));
}

std::string computeMerkleRootHex(const Batch& batch) {
    if (batch.events.empty() || batch.events.size() > MAX_EVENTS_PER_BATCH) return {};
    std::vector<std::vector<unsigned char>> level;
    level.reserve(batch.events.size());
    for (const auto& event : batch.events) level.push_back(leafHash(batch, event, batch.events.size()));
    while (level.size() > 1U) {
        std::vector<std::vector<unsigned char>> next;
        next.reserve((level.size() + 1U) / 2U);
        for (std::size_t i = 0; i < level.size(); i += 2U) {
            const auto& left = level[i];
            const auto& right = (i + 1U < level.size()) ? level[i + 1U] : level[i];
            next.push_back(nodeHash(left, right));
        }
        level.swap(next);
    }
    return hexLower(level.front());
}

bool buildInclusionProof(
    const Batch& batch,
    std::size_t eventIndex,
    std::vector<std::string>& siblingHashes,
    std::string* reason)
{
    siblingHashes.clear();
    if (!eventStructureChecks(batch, reason) || eventIndex >= batch.events.size()) {
        if (eventIndex >= batch.events.size()) setReason(reason, "eventIndex out of range");
        return false;
    }
    std::vector<std::vector<unsigned char>> level;
    for (const auto& event : batch.events) level.push_back(leafHash(batch, event, batch.events.size()));
    std::size_t index = eventIndex;
    while (level.size() > 1U) {
        std::size_t sibling = (index % 2U == 0U) ? index + 1U : index - 1U;
        if (sibling >= level.size()) sibling = index;
        siblingHashes.push_back(hexLower(level[sibling]));

        std::vector<std::vector<unsigned char>> next;
        next.reserve((level.size() + 1U) / 2U);
        for (std::size_t i = 0; i < level.size(); i += 2U) {
            const auto& left = level[i];
            const auto& right = (i + 1U < level.size()) ? level[i + 1U] : level[i];
            next.push_back(nodeHash(left, right));
        }
        index /= 2U;
        level.swap(next);
    }
    setReason(reason, "ok");
    return true;
}

bool verifyInclusionProof(
    const Batch& batchContext,
    const Event& event,
    std::size_t eventIndex,
    std::size_t eventCount,
    const std::vector<std::string>& siblingHashes,
    const std::string& expectedMerkleRoot,
    std::string* reason)
{
    if (eventCount == 0U || eventCount > MAX_EVENTS_PER_BATCH || eventIndex >= eventCount ||
        !isLowerHex(expectedMerkleRoot, 64U) || isZeroHash(expectedMerkleRoot)) {
        setReason(reason, "invalid Merkle proof context"); return false;
    }
    if (!isLowerHex(batchContext.token_id, 16U) ||
        (batchContext.token_type != "SFT" && batchContext.token_type != "NCFT") ||
        batchContext.epoch == 0U || !isLowerHex(batchContext.previous_batch_hash, 64U) ||
        !isLowerHex(batchContext.writer_id, 64U) || batchContext.writer_class != "sensor" ||
        event.sequence == 0U || event.observed_at_ms == 0U || !isCanonicalField(event.field) ||
        !isLowerHex(event.payload_hash, 64U) || isZeroHash(event.payload_hash)) {
        setReason(reason, "invalid Merkle leaf context"); return false;
    }

    std::size_t expectedProofDepth = 0U;
    for (std::size_t n = eventCount; n > 1U; n = (n + 1U) / 2U) ++expectedProofDepth;
    if (siblingHashes.size() != expectedProofDepth) {
        setReason(reason, "Merkle proof depth mismatch"); return false;
    }

    std::vector<unsigned char> current = leafHash(batchContext, event, eventCount);
    std::size_t index = eventIndex;
    std::size_t width = eventCount;
    for (const auto& siblingHex : siblingHashes) {
        std::vector<unsigned char> sibling;
        if (!isLowerHex(siblingHex, 64U) || !hexDecodeLower(siblingHex, sibling, 32U)) {
            setReason(reason, "invalid Merkle sibling hash"); return false;
        }
        if (index % 2U == 0U) current = nodeHash(current, sibling);
        else current = nodeHash(sibling, current);
        index /= 2U;
        width = (width + 1U) / 2U;
        (void)width;
    }
    if (hexLower(current) != expectedMerkleRoot) {
        setReason(reason, "Merkle inclusion proof mismatch"); return false;
    }
    setReason(reason, "ok");
    return true;
}

std::vector<unsigned char> batchDigest(const Batch& batch) {
    std::vector<unsigned char> preimage;
    const std::string domain(BATCH_DOMAIN);
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BE(preimage, batch.format_version);
    appendLP(preimage, batch.token_id);
    appendLP(preimage, batch.token_type);
    appendU64BE(preimage, batch.epoch);
    appendLP(preimage, batch.previous_batch_hash);
    appendLP(preimage, batch.writer_pubkey_hex);
    appendLP(preimage, batch.writer_id);
    appendLP(preimage, batch.writer_class);
    appendU32BE(preimage, static_cast<std::uint32_t>(batch.events.size()));
    appendU64BE(preimage, batch.events.empty() ? 0U : batch.events.front().sequence);
    appendU64BE(preimage, batch.events.empty() ? 0U : batch.events.back().sequence);
    appendLP(preimage, batch.merkle_root);
    return sha256(preimage);
}

std::string batchDigestHex(const Batch& batch) {
    return hexLower(batchDigest(batch));
}

bool signBatch(Batch& batch, const ECDSAKey& sensorKey, std::string* reason) {
    try {
        batch.writer_class = "sensor";
        batch.writer_pubkey_hex = hexLower(sensorKey.getCompressedSec1());
        batch.writer_id = VAHAuthorization::deriveWriterId(batch.writer_pubkey_hex);
        if (!eventStructureChecks(batch, reason)) return false;
        batch.merkle_root = computeMerkleRootHex(batch);
        if (!isLowerHex(batch.merkle_root, 64U) || isZeroHash(batch.merkle_root)) {
            setReason(reason, "could not compute sensor batch Merkle root"); return false;
        }
        const auto digest = batchDigest(batch);
        batch.batch_hash = hexLower(digest);
        if (isZeroHash(batch.batch_hash)) {
            setReason(reason, "sensor batch hash cannot be zero"); return false;
        }
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        const auto sig = sensorKey.sign(message);
        if (!ECDSAKey::isStrictDERLowS(sig)) {
            setReason(reason, "sensor batch signer returned non-canonical signature"); return false;
        }
        batch.signature_der_hex = hexLower(sig);
        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("sensor batch sign failure: ") + e.what());
        return false;
    }
}

bool verifyBatch(
    const Batch& batch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    try {
        if (!envelopeStructureChecks(batch, reason)) return false;
        const auto digest = batchDigest(batch);
        const std::string expectedBatchHash = hexLower(digest);
        if (!isLowerHex(batch.batch_hash, 64U) || isZeroHash(batch.batch_hash) ||
            batch.batch_hash != expectedBatchHash) {
            setReason(reason, "sensor batch hash mismatch"); return false;
        }

        const auto fields = uniqueFields(batch);
        std::string authReason;
        if (!VAHAuthorization::isWriterAuthorizedAtEpoch(
                authorizationHistory,
                batch.token_type,
                trustedAuthorizationRootPubKeyHex,
                batch.epoch,
                batch.writer_pubkey_hex,
                "sensor",
                fields,
                &authReason)) {
            setReason(reason, "sensor batch authorization denied: " + authReason); return false;
        }

        std::vector<unsigned char> signature;
        std::vector<unsigned char> pubkey;
        if (!hexDecodeLower(batch.signature_der_hex, signature, MAX_SIGNATURE_BYTES) ||
            !ECDSAKey::isStrictDERLowS(signature) ||
            !hexDecodeLower(batch.writer_pubkey_hex, pubkey, 33U) || pubkey.size() != 33U) {
            setReason(reason, "sensor batch signature/public key encoding invalid"); return false;
        }
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        if (!ECDSAKey::verify(pubkey, message, signature)) {
            setReason(reason, "sensor batch signature invalid"); return false;
        }
        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("sensor batch verification failure: ") + e.what());
        return false;
    }
}

} // namespace VAHSensorBatch
