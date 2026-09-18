#include "vah_external_writer_stage.h"

#include "leveldb_storage.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace VAHExternalWriterStage {
namespace {

constexpr const char* PENDING_DOMAIN = "TRU_VAH_PENDING_CLAIM_V1";
constexpr const char* PENDING_KEY_PREFIX = "contract:TOKEN:VAH_PENDING:";
constexpr std::size_t TOKEN_ID_HEX = 16U;
constexpr std::size_t HASH_HEX = 64U;

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

std::string epochKey(std::uint64_t epoch) {
    std::ostringstream oss;
    oss << std::setw(20) << std::setfill('0') << epoch;
    return oss.str();
}

std::string pendingEpochPrefix(const std::string& tokenId, std::uint64_t epoch) {
    return std::string(PENDING_KEY_PREFIX) + tokenId + ":epoch:" + epochKey(epoch) + ":";
}

std::string fieldIndex(std::size_t index) {
    std::ostringstream oss;
    oss << std::setw(4) << std::setfill('0') << index;
    return oss.str();
}

bool parseCanonicalU64(const std::string& text, std::uint64_t& out) {
    if (text.empty()) return false;
    if (text.size() > 1U && text.front() == '0') return false;
    std::uint64_t value = 0U;
    for (unsigned char c : text) {
        if (!std::isdigit(c)) return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) return false;
        value = value * 10U + digit;
    }
    if (std::to_string(value) != text) return false;
    out = value;
    return true;
}

bool parseCanonicalSize(const std::string& text, std::size_t& out) {
    std::uint64_t parsed = 0U;
    if (!parseCanonicalU64(text, parsed) || parsed > std::numeric_limits<std::size_t>::max()) {
        return false;
    }
    out = static_cast<std::size_t>(parsed);
    return true;
}

bool splitCanonicalLines(const std::string& encoded, std::vector<std::string>& lines) {
    lines.clear();
    if (encoded.empty() || encoded.size() > MAX_STAGED_CLAIM_BYTES || encoded.back() != '\n') {
        return false;
    }
    std::size_t start = 0U;
    while (start < encoded.size()) {
        const std::size_t end = encoded.find('\n', start);
        if (end == std::string::npos) return false;
        std::string line = encoded.substr(start, end - start);
        if (line.find('\r') != std::string::npos) return false;
        lines.push_back(std::move(line));
        start = end + 1U;
    }
    return !lines.empty();
}

bool takeValue(
    const std::vector<std::string>& lines,
    std::size_t& cursor,
    const std::string& key,
    std::string& out)
{
    if (cursor >= lines.size()) return false;
    const std::string prefix = key + "=";
    if (lines[cursor].rfind(prefix, 0U) != 0U) return false;
    out = lines[cursor].substr(prefix.size());
    ++cursor;
    return true;
}

std::mutex& stagingMutex() {
    static std::mutex m;
    return m;
}

LoadResult loadPendingClaimsUnlocked(
    LevelDBStorage& storage,
    const std::string& tokenId,
    std::uint64_t epoch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    LoadResult result;
    if (!isLowerHex(tokenId, TOKEN_ID_HEX) || epoch == 0U) {
        result.errors.push_back("pending claim token/epoch request is non-canonical");
        return result;
    }

    const std::string prefix = pendingEpochPrefix(tokenId, epoch);
    std::vector<std::string> suffixes;
    storage.iteratePrefix(prefix, [&](const std::string& suffix, const std::string&) {
        suffixes.push_back(suffix);
    });

    if (suffixes.size() > MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH) {
        result.errors.push_back("pending claim resource bound exceeded");
        return result;
    }

    std::sort(suffixes.begin(), suffixes.end());
    if (std::adjacent_find(suffixes.begin(), suffixes.end()) != suffixes.end()) {
        result.errors.push_back("duplicate pending claim key observed");
        return result;
    }

    result.claims.reserve(suffixes.size());
    for (const auto& suffix : suffixes) {
        const std::string claimPrefix = "claim:";
        if (suffix.rfind(claimPrefix, 0U) != 0U) {
            result.errors.push_back("unexpected key in pending claim namespace");
            return result;
        }
        const std::string keyHash = suffix.substr(claimPrefix.size());
        if (!isLowerHex(keyHash, HASH_HEX)) {
            result.errors.push_back("non-canonical pending claim record-hash key");
            return result;
        }

        const std::string fullKey = prefix + suffix;
        std::string encoded;
        if (!storage.getContract(fullKey, encoded)) {
            result.errors.push_back("pending claim not found or checksum-invalid");
            return result;
        }
        if (encoded.size() > MAX_STAGED_CLAIM_BYTES) {
            result.errors.push_back("pending claim durable envelope exceeds byte bound");
            return result;
        }

        VAHExternalWriter::Claim claim;
        std::string parseReason;
        if (!parsePendingClaim(encoded, claim, &parseReason)) {
            result.errors.push_back("non-canonical pending claim envelope: " + parseReason);
            return result;
        }
        if (claim.token_id != tokenId || claim.epoch != epoch || claim.record_hash != keyHash) {
            result.errors.push_back("pending claim key/envelope binding mismatch");
            return result;
        }

        std::string verifyReason;
        if (!VAHExternalWriter::verifyClaim(
                claim,
                authorizationHistory,
                trustedAuthorizationRootPubKeyHex,
                &verifyReason)) {
            result.errors.push_back("pending claim VAH-03A re-verification failed: " + verifyReason);
            return result;
        }

        result.claims.push_back(std::move(claim));
    }

    std::sort(result.claims.begin(), result.claims.end(),
        [](const VAHExternalWriter::Claim& a, const VAHExternalWriter::Claim& b) {
            return a.record_hash < b.record_hash;
        });
    result.ok = true;
    return result;
}

} // namespace

std::string serializePendingClaim(const VAHExternalWriter::Claim& claim) {
    std::ostringstream oss;
    oss << PENDING_DOMAIN << '\n';
    oss << "format_version=" << claim.format_version << '\n';
    oss << "token_id=" << claim.token_id << '\n';
    oss << "token_type=" << claim.token_type << '\n';
    oss << "epoch=" << claim.epoch << '\n';
    oss << "previous_metadata_hash=" << claim.previous_metadata_hash << '\n';
    oss << "new_metadata_hash=" << claim.new_metadata_hash << '\n';
    oss << "writer_pubkey_hex=" << claim.writer_pubkey_hex << '\n';
    oss << "writer_id=" << claim.writer_id << '\n';
    oss << "writer_class=" << claim.writer_class << '\n';
    oss << "changed_field_count=" << claim.changed_fields.size() << '\n';
    for (std::size_t i = 0U; i < claim.changed_fields.size(); ++i) {
        oss << "changed_field_" << fieldIndex(i) << '=' << claim.changed_fields[i] << '\n';
    }
    oss << "record_hash=" << claim.record_hash << '\n';
    oss << "signature_der_hex=" << claim.signature_der_hex << '\n';
    return oss.str();
}

bool parsePendingClaim(
    const std::string& encoded,
    VAHExternalWriter::Claim& out,
    std::string* reason)
{
    std::vector<std::string> lines;
    if (!splitCanonicalLines(encoded, lines) || lines.empty() || lines.front() != PENDING_DOMAIN) {
        setReason(reason, "invalid pending claim domain/line framing");
        return false;
    }

    VAHExternalWriter::Claim claim;
    std::size_t cursor = 1U;
    std::string value;

    if (!takeValue(lines, cursor, "format_version", value) || value != "1") {
        setReason(reason, "invalid pending claim format_version");
        return false;
    }
    claim.format_version = 1U;
    if (!takeValue(lines, cursor, "token_id", claim.token_id) ||
        !takeValue(lines, cursor, "token_type", claim.token_type) ||
        !takeValue(lines, cursor, "epoch", value)) {
        setReason(reason, "missing pending claim identity fields");
        return false;
    }
    if (!parseCanonicalU64(value, claim.epoch) || claim.epoch == 0U) {
        setReason(reason, "invalid canonical pending claim epoch");
        return false;
    }
    if (!takeValue(lines, cursor, "previous_metadata_hash", claim.previous_metadata_hash) ||
        !takeValue(lines, cursor, "new_metadata_hash", claim.new_metadata_hash) ||
        !takeValue(lines, cursor, "writer_pubkey_hex", claim.writer_pubkey_hex) ||
        !takeValue(lines, cursor, "writer_id", claim.writer_id) ||
        !takeValue(lines, cursor, "writer_class", claim.writer_class) ||
        !takeValue(lines, cursor, "changed_field_count", value)) {
        setReason(reason, "missing pending claim semantic fields");
        return false;
    }

    std::size_t fieldCount = 0U;
    if (!parseCanonicalSize(value, fieldCount) || fieldCount == 0U ||
        fieldCount > VAHExternalWriter::MAX_CHANGED_FIELDS) {
        setReason(reason, "invalid pending claim changed_field_count");
        return false;
    }
    claim.changed_fields.reserve(fieldCount);
    for (std::size_t i = 0U; i < fieldCount; ++i) {
        const std::string key = "changed_field_" + fieldIndex(i);
        std::string field;
        if (!takeValue(lines, cursor, key, field)) {
            setReason(reason, "missing or non-canonical pending claim changed field");
            return false;
        }
        claim.changed_fields.push_back(std::move(field));
    }

    if (!takeValue(lines, cursor, "record_hash", claim.record_hash) ||
        !takeValue(lines, cursor, "signature_der_hex", claim.signature_der_hex) ||
        cursor != lines.size()) {
        setReason(reason, "pending claim trailing/missing durable fields");
        return false;
    }

    if (serializePendingClaim(claim) != encoded) {
        setReason(reason, "pending claim envelope is not canonical round-trip form");
        return false;
    }

    out = std::move(claim);
    setReason(reason, "ok");
    return true;
}

std::string pendingClaimKey(
    const std::string& tokenId,
    std::uint64_t epoch,
    const std::string& recordHash)
{
    return pendingEpochPrefix(tokenId, epoch) + "claim:" + recordHash;
}

bool stageClaim(
    LevelDBStorage& storage,
    const VAHExternalWriter::Claim& claim,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock(stagingMutex());

    std::string verifyReason;
    if (!VAHExternalWriter::verifyClaim(
            claim,
            authorizationHistory,
            trustedAuthorizationRootPubKeyHex,
            &verifyReason)) {
        setReason(reason, "VAH-03A admission denied: " + verifyReason);
        return false;
    }

    const std::string encoded = serializePendingClaim(claim);
    if (encoded.empty() || encoded.size() > MAX_STAGED_CLAIM_BYTES) {
        setReason(reason, "pending claim durable envelope exceeds byte bound");
        return false;
    }

    VAHExternalWriter::Claim roundTrip;
    std::string parseReason;
    if (!parsePendingClaim(encoded, roundTrip, &parseReason) ||
        serializePendingClaim(roundTrip) != encoded) {
        setReason(reason, "pending claim self-serialization failed: " + parseReason);
        return false;
    }

    const std::string key = pendingClaimKey(claim.token_id, claim.epoch, claim.record_hash);
    std::string raw;
    bool found = false;
    if (!storage.getRaw(key, raw, found)) {
        setReason(reason, "pending claim durable existence read failed");
        return false;
    }
    if (found) {
        std::string existing;
        if (!storage.getContract(key, existing)) {
            setReason(reason, "existing pending claim is checksum-invalid");
            return false;
        }
        if (existing != encoded) {
            setReason(reason, "staged record_hash key contains different claim bytes");
            return false;
        }
        setReason(reason, "ok-idempotent");
        return true;
    }

    const LoadResult before = loadPendingClaimsUnlocked(
        storage,
        claim.token_id,
        claim.epoch,
        authorizationHistory,
        trustedAuthorizationRootPubKeyHex);
    if (!before.ok) {
        setReason(reason, before.errors.empty() ?
            "pending claim namespace validation failed" : before.errors.front());
        return false;
    }
    if (before.claims.size() >= MAX_PENDING_CLAIMS_PER_TOKEN_EPOCH) {
        setReason(reason, "pending claim resource bound reached");
        return false;
    }

    if (!storage.putContract(key, encoded)) {
        setReason(reason, "pending claim synced durable write failed");
        return false;
    }

    std::string readback;
    if (!storage.getContract(key, readback) || readback != encoded) {
        setReason(reason, "pending claim durable readback mismatch");
        return false;
    }

    setReason(reason, "ok");
    return true;
}

LoadResult loadPendingClaims(
    LevelDBStorage& storage,
    const std::string& tokenId,
    std::uint64_t epoch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    std::lock_guard<std::mutex> lock(stagingMutex());
    return loadPendingClaimsUnlocked(
        storage,
        tokenId,
        epoch,
        authorizationHistory,
        trustedAuthorizationRootPubKeyHex);
}

} // namespace VAHExternalWriterStage
