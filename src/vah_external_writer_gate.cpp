#include "vah_external_writer_gate.h"

#include "crypto_ecdsa.h"
#include "vah_capabilities.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace VAHExternalWriter {
namespace {

constexpr const char* CLAIM_DOMAIN = "TRU_VAH_EXTERNAL_WRITER_CLAIM_V1";
constexpr std::size_t TOKEN_ID_HEX = 16U;
constexpr std::size_t HASH_HEX = 64U;
constexpr std::size_t COMPRESSED_PUBKEY_HEX = 66U;
constexpr std::size_t MAX_SIGNATURE_BYTES = 72U;

void setReason(std::string* reason, const std::string& value) {
    if (reason != nullptr) *reason = value;
}

bool isLowerHex(const std::string& value, std::size_t exactSize) {
    if (value.size() != exactSize) return false;
    for (unsigned char c : value) {
        if (!std::isdigit(c) && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}

bool isZeroHash(const std::string& value) {
    return value == std::string(HASH_HEX, '0');
}

bool isCanonicalTokenType(const std::string& tokenType) {
    return tokenType == "SFT" || tokenType == "NCFT";
}

bool isExternalWriterClass(const std::string& writerClass) {
    const auto parsed = VAHCapabilities::writerClassFromString(writerClass);
    return (parsed == VAHCapabilities::WriterClass::HUMAN ||
            parsed == VAHCapabilities::WriterClass::SENSOR ||
            parsed == VAHCapabilities::WriterClass::DEVICE) &&
           VAHCapabilities::writerClassToString(parsed) == writerClass;
}

bool canonicalChangedFields(const std::vector<std::string>& fields) {
    if (fields.empty() || fields.size() > MAX_CHANGED_FIELDS) return false;
    for (const auto& field : fields) {
        if (field.empty() || field.size() > MAX_CHANGED_FIELD_BYTES) return false;
        for (unsigned char c : field) {
            const bool ok = std::islower(c) || std::isdigit(c) || c == '_';
            if (!ok) return false;
        }
    }
    return std::adjacent_find(fields.begin(), fields.end(),
        [](const std::string& a, const std::string& b) { return a >= b; }) == fields.end();
}

void appendU32BE(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

void appendU64BE(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
    }
}

void appendLP(std::vector<unsigned char>& out, const std::string& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("claim field too large");
    }
    appendU32BE(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& bytes) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(bytes.data(), bytes.size(), digest.data());
    return digest;
}

std::string hexEncodeLower(const std::vector<unsigned char>& bytes) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (unsigned char b : bytes) {
        out.push_back(HEX[(b >> 4U) & 0x0fU]);
        out.push_back(HEX[b & 0x0fU]);
    }
    return out;
}

bool hexDecodeVariableLower(
    const std::string& hex,
    std::vector<unsigned char>& out,
    std::size_t maxBytes)
{
    if (hex.empty() || (hex.size() & 1U) != 0U || hex.size() / 2U > maxBytes) return false;
    out.clear();
    out.reserve(hex.size() / 2U);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

bool hexDecodeFixedLower(
    const std::string& hex,
    std::vector<unsigned char>& out,
    std::size_t exactBytes)
{
    return hex.size() == exactBytes * 2U && hexDecodeVariableLower(hex, out, exactBytes) &&
           out.size() == exactBytes;
}

bool structuralClaimChecks(const Claim& claim, std::string* reason) {
    if (claim.format_version != 1U) {
        setReason(reason, "unsupported external writer claim version");
        return false;
    }
    if (!isLowerHex(claim.token_id, TOKEN_ID_HEX)) {
        setReason(reason, "token_id must be canonical lowercase 16-hex");
        return false;
    }
    if (!isCanonicalTokenType(claim.token_type)) {
        setReason(reason, "token_type must be SFT or NCFT");
        return false;
    }
    if (claim.epoch == 0U) {
        setReason(reason, "epoch must be non-zero");
        return false;
    }
    if (!isLowerHex(claim.previous_metadata_hash, HASH_HEX) ||
        !isLowerHex(claim.new_metadata_hash, HASH_HEX) ||
        isZeroHash(claim.previous_metadata_hash) ||
        isZeroHash(claim.new_metadata_hash) ||
        claim.previous_metadata_hash == claim.new_metadata_hash) {
        setReason(reason, "metadata hashes must be distinct non-zero lowercase 32-byte hex");
        return false;
    }
    if (!isExternalWriterClass(claim.writer_class)) {
        setReason(reason, "VAH-03A permits only canonical human/sensor/device writer classes");
        return false;
    }
    if (!isLowerHex(claim.writer_pubkey_hex, COMPRESSED_PUBKEY_HEX) ||
        (claim.writer_pubkey_hex.rfind("02", 0U) != 0U &&
         claim.writer_pubkey_hex.rfind("03", 0U) != 0U)) {
        setReason(reason, "writer public key must be canonical compressed SEC1 lowercase hex");
        return false;
    }
    if (VAHAuthorization::deriveWriterId(claim.writer_pubkey_hex) != claim.writer_id ||
        !isLowerHex(claim.writer_id, HASH_HEX)) {
        setReason(reason, "writer_id does not match writer public key");
        return false;
    }
    if (!canonicalChangedFields(claim.changed_fields)) {
        setReason(reason, "changed_fields must be bounded canonical sorted unique field names");
        return false;
    }
    for (const auto& field : claim.changed_fields) {
        if (!VAHCapabilities::isKnownFieldForToken(claim.token_type, field) ||
            !VAHCapabilities::writerClassMayHoldFieldCapability(
                claim.token_type, claim.writer_class, field)) {
            setReason(reason, "field incompatible with token/writer class: " + field);
            return false;
        }
    }
    return true;
}

} // namespace

std::vector<unsigned char> claimDigest(const Claim& claim) {
    std::vector<unsigned char> preimage;
    const std::string domain = CLAIM_DOMAIN;
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BE(preimage, claim.format_version);
    appendLP(preimage, claim.token_id);
    appendLP(preimage, claim.token_type);
    appendU64BE(preimage, claim.epoch);
    appendLP(preimage, claim.previous_metadata_hash);
    appendLP(preimage, claim.new_metadata_hash);
    appendLP(preimage, claim.writer_pubkey_hex);
    appendLP(preimage, claim.writer_id);
    appendLP(preimage, claim.writer_class);
    appendU32BE(preimage, static_cast<std::uint32_t>(claim.changed_fields.size()));
    for (const auto& field : claim.changed_fields) appendLP(preimage, field);
    return sha256(preimage);
}

std::string claimDigestHex(const Claim& claim) {
    return hexEncodeLower(claimDigest(claim));
}

bool signClaim(Claim& claim, const ECDSAKey& writerKey, std::string* reason) {
    try {
        claim.writer_pubkey_hex = hexEncodeLower(writerKey.getCompressedSec1());
        claim.writer_id = VAHAuthorization::deriveWriterId(claim.writer_pubkey_hex);
        if (!structuralClaimChecks(claim, reason)) return false;

        const auto digest = claimDigest(claim);
        claim.record_hash = hexEncodeLower(digest);
        if (isZeroHash(claim.record_hash)) {
            setReason(reason, "record_hash cannot be zero");
            return false;
        }
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        const auto signature = writerKey.sign(message);
        if (!ECDSAKey::isStrictDERLowS(signature)) {
            setReason(reason, "writer signer returned non-canonical signature");
            return false;
        }
        claim.signature_der_hex = hexEncodeLower(signature);
        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("external writer sign failure: ") + e.what());
        return false;
    }
}

bool verifyClaim(
    const Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    try {
        if (!structuralClaimChecks(claim, reason)) return false;

        const auto digest = claimDigest(claim);
        const std::string expectedHash = hexEncodeLower(digest);
        if (!isLowerHex(claim.record_hash, HASH_HEX) || isZeroHash(claim.record_hash) ||
            claim.record_hash != expectedHash) {
            setReason(reason, "external writer record_hash mismatch");
            return false;
        }

        std::string authReason;
        if (!VAHAuthorization::isWriterAuthorizedAtEpoch(
                authorizationHistory,
                claim.token_type,
                trustedAuthorizationRootPubKeyHex,
                claim.epoch,
                claim.writer_pubkey_hex,
                claim.writer_class,
                claim.changed_fields,
                &authReason)) {
            setReason(reason, "external writer authorization denied: " + authReason);
            return false;
        }

        std::vector<unsigned char> signature;
        if (!hexDecodeVariableLower(claim.signature_der_hex, signature, MAX_SIGNATURE_BYTES) ||
            !ECDSAKey::isStrictDERLowS(signature)) {
            setReason(reason, "writer signature must be strict-DER low-S lowercase hex");
            return false;
        }
        std::vector<unsigned char> pubkey;
        if (!hexDecodeFixedLower(claim.writer_pubkey_hex, pubkey, 33U)) {
            setReason(reason, "writer public key decode failed");
            return false;
        }
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        if (!ECDSAKey::verify(pubkey, message, signature)) {
            setReason(reason, "external writer signature invalid");
            return false;
        }

        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("external writer verification failure: ") + e.what());
        return false;
    }
}

} // namespace VAHExternalWriter
