#include "vah_authorization.h"

#include "crypto_ecdsa.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

namespace VAHAuthorization {
namespace {

constexpr const char* AUTH_DOMAIN = "TRU_VAH_AUTH_V1";
constexpr const char* WRITER_ID_DOMAIN = "TRU_VAH_WRITER_ID_V1";
constexpr std::size_t COMPRESSED_PUBKEY_BYTES = 33;
constexpr std::size_t SHA256_BYTES = 32;
constexpr std::size_t MAX_RECORD_TEXT_BYTES = 64U * 1024U;
constexpr std::size_t MAX_CAPABILITIES = 32;
constexpr std::size_t MAX_SERIALIZED_FIELD = 4096;

const std::string ZERO_HASH(64, '0');

void setReason(std::string* reason, const std::string& value) {
    if (reason) *reason = value;
}

bool isLowerHex(const std::string& value, std::size_t exactChars) {
    if (value.size() != exactChars) return false;
    for (unsigned char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool isCanonicalTokenId(const std::string& value) {
    return isLowerHex(value, 16);
}

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

bool hexDecodeLower(
    const std::string& value,
    std::vector<unsigned char>& out,
    std::size_t exactBytes)
{
    out.clear();
    if (!isLowerHex(value, exactBytes * 2U)) return false;
    out.reserve(exactBytes);
    for (std::size_t i = 0; i < value.size(); i += 2U) {
        const int hi = hexNibble(value[i]);
        const int lo = hexNibble(value[i + 1U]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out.size() == exactBytes;
}

bool hexDecodeVariableLower(
    const std::string& value,
    std::vector<unsigned char>& out,
    std::size_t maxBytes)
{
    out.clear();
    if (value.empty() || (value.size() % 2U) != 0U || value.size() > maxBytes * 2U) return false;
    for (unsigned char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    out.reserve(value.size() / 2U);
    for (std::size_t i = 0; i < value.size(); i += 2U) {
        const int hi = hexNibble(value[i]);
        const int lo = hexNibble(value[i + 1U]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string hexEncodeLower(const std::vector<unsigned char>& data) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (unsigned char b : data) {
        out.push_back(HEX[(b >> 4) & 0x0f]);
        out.push_back(HEX[b & 0x0f]);
    }
    return out;
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(SHA256_BYTES);
    unsigned int outLen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("VAH sha256: EVP_MD_CTX_new failed");
    const bool ok =
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        (data.empty() || EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) &&
        EVP_DigestFinal_ex(ctx, digest.data(), &outLen) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || outLen != SHA256_BYTES) {
        throw std::runtime_error("VAH sha256: digest failure");
    }
    return digest;
}

void appendU32BE(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

void appendU64BE(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
    }
}

void appendLP(std::vector<unsigned char>& out, const std::string& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("VAH canonical field too large");
    }
    appendU32BE(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool isCanonicalCapabilities(const std::vector<std::string>& caps) {
    if (caps.size() > MAX_CAPABILITIES) return false;
    std::string previous;
    for (const auto& cap : caps) {
        const auto parsed = VAHCapabilities::capabilityFromString(cap);
        if (parsed == VAHCapabilities::Capability::UNKNOWN) return false;
        const std::string canonical = VAHCapabilities::capabilityToString(parsed);
        if (cap != canonical) return false;
        if (!previous.empty() && cap <= previous) return false;
        previous = cap;
    }
    return true;
}

bool capabilityAllowedForWriter(
    const std::string& tokenType,
    const std::string& writerType,
    const std::string& capability)
{
    const auto parsed = VAHCapabilities::capabilityFromString(capability);
    if (parsed == VAHCapabilities::Capability::UNKNOWN) return false;
    const auto fields = VAHCapabilities::fieldsForCapability(tokenType, parsed, false);
    for (const auto& field : fields) {
        if (VAHCapabilities::writerClassMayHoldFieldCapability(tokenType, writerType, field)) {
            return true;
        }
    }
    return false;
}

std::string capabilityForField(const std::string& field) {
    const auto* policy = VAHCapabilities::fieldPolicy(field);
    if (!policy) return {};
    return VAHCapabilities::capabilityToString(policy->capability);
}

struct ActiveWriter {
    std::string writer_id;
    std::string writer_pubkey_hex;
    std::string writer_class;
    std::set<std::string> capabilities;
};

bool applyRecord(
    const AuthorizationRecord& record,
    std::map<std::string, ActiveWriter>& active,
    std::string* reason)
{
    const auto writerIt = active.find(record.writer_id);

    if (record.action == Action::AUTHORIZE) {
        if (writerIt != active.end()) {
            setReason(reason, "AUTHORIZE targets an already-active writer");
            return false;
        }
        if (!record.replaces_writer_id.empty()) {
            setReason(reason, "AUTHORIZE must not set replaces_writer_id");
            return false;
        }
        ActiveWriter state;
        state.writer_id = record.writer_id;
        state.writer_pubkey_hex = record.writer_pubkey_hex;
        state.writer_class = record.writer_class;
        state.capabilities.insert(record.capabilities.begin(), record.capabilities.end());
        active.emplace(state.writer_id, std::move(state));
        return true;
    }

    if (record.action == Action::ROTATE) {
        if (record.replaces_writer_id.empty() || record.replaces_writer_id == record.writer_id) {
            setReason(reason, "ROTATE requires a distinct replaces_writer_id");
            return false;
        }
        if (writerIt != active.end()) {
            setReason(reason, "ROTATE new writer is already active");
            return false;
        }
        const auto oldIt = active.find(record.replaces_writer_id);
        if (oldIt == active.end()) {
            setReason(reason, "ROTATE replacement writer is not active");
            return false;
        }
        if (oldIt->second.writer_class != record.writer_class) {
            setReason(reason, "ROTATE cannot change writer class; use REVOKE + AUTHORIZE");
            return false;
        }
        active.erase(oldIt);
        ActiveWriter state;
        state.writer_id = record.writer_id;
        state.writer_pubkey_hex = record.writer_pubkey_hex;
        state.writer_class = record.writer_class;
        state.capabilities.insert(record.capabilities.begin(), record.capabilities.end());
        active.emplace(state.writer_id, std::move(state));
        return true;
    }

    if (record.action == Action::REVOKE) {
        if (writerIt == active.end()) {
            setReason(reason, "REVOKE targets a writer that is not active");
            return false;
        }
        if (!record.replaces_writer_id.empty()) {
            setReason(reason, "REVOKE must not set replaces_writer_id");
            return false;
        }
        if (!record.capabilities.empty()) {
            setReason(reason, "REVOKE must not carry capabilities");
            return false;
        }
        if (writerIt->second.writer_pubkey_hex != record.writer_pubkey_hex ||
            writerIt->second.writer_class != record.writer_class) {
            setReason(reason, "REVOKE writer identity/class mismatch");
            return false;
        }
        active.erase(writerIt);
        return true;
    }

    setReason(reason, "unknown authorization action");
    return false;
}

bool parseU64(const std::string& value, std::uint64_t& out) {
    if (value.empty()) return false;
    std::uint64_t result = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') return false;
        const unsigned digit = c - '0';
        if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) return false;
        result = result * 10U + digit;
    }
    out = result;
    return true;
}

std::vector<std::string> splitComma(const std::string& value) {
    std::vector<std::string> out;
    if (value.empty()) return out;
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t pos = value.find(',', start);
        const std::string item = value.substr(start, pos == std::string::npos ? std::string::npos : pos - start);
        if (item.empty()) return {};
        out.push_back(item);
        if (pos == std::string::npos) break;
        start = pos + 1U;
    }
    return out;
}

} // namespace

std::string actionToString(Action action) {
    switch (action) {
        case Action::AUTHORIZE: return "AUTHORIZE";
        case Action::ROTATE: return "ROTATE";
        case Action::REVOKE: return "REVOKE";
        case Action::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

Action actionFromString(const std::string& value) {
    if (value == "AUTHORIZE") return Action::AUTHORIZE;
    if (value == "ROTATE") return Action::ROTATE;
    if (value == "REVOKE") return Action::REVOKE;
    return Action::UNKNOWN;
}

std::string deriveWriterId(const std::string& writerPubKeyHex) {
    std::vector<unsigned char> pubkey;
    if (!hexDecodeLower(writerPubKeyHex, pubkey, COMPRESSED_PUBKEY_BYTES) ||
        (pubkey[0] != 0x02U && pubkey[0] != 0x03U)) {
        return {};
    }
    std::vector<unsigned char> preimage;
    const std::string domain = WRITER_ID_DOMAIN;
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BE(preimage, static_cast<std::uint32_t>(pubkey.size()));
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    return hexEncodeLower(sha256(preimage));
}

std::vector<unsigned char> authorizationDigest(const AuthorizationRecord& record) {
    std::vector<unsigned char> preimage;
    const std::string domain = AUTH_DOMAIN;
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BE(preimage, record.format_version);
    appendLP(preimage, record.token_id);
    appendU64BE(preimage, record.sequence);
    appendU64BE(preimage, record.effective_epoch);
    appendLP(preimage, actionToString(record.action));
    appendLP(preimage, record.writer_id);
    appendLP(preimage, record.writer_pubkey_hex);
    appendLP(preimage, record.writer_class);
    appendU32BE(preimage, static_cast<std::uint32_t>(record.capabilities.size()));
    for (const auto& capability : record.capabilities) appendLP(preimage, capability);
    appendLP(preimage, record.replaces_writer_id);
    appendLP(preimage, record.previous_record_hash);
    appendLP(preimage, record.authorization_root_pubkey_hex);
    return sha256(preimage);
}

std::string authorizationDigestHex(const AuthorizationRecord& record) {
    return hexEncodeLower(authorizationDigest(record));
}

bool signAuthorizationRecord(
    AuthorizationRecord& record,
    const ECDSAKey& authorizationRootKey,
    std::string* reason)
{
    try {
        const std::string rootHex = hexEncodeLower(authorizationRootKey.getCompressedSec1());
        if (record.authorization_root_pubkey_hex != rootHex) {
            setReason(reason, "authorization root public key does not match signing key");
            return false;
        }
        record.writer_id = deriveWriterId(record.writer_pubkey_hex);
        if (record.writer_id.empty()) {
            setReason(reason, "invalid compressed writer public key");
            return false;
        }
        const auto digest = authorizationDigest(record);
        record.record_hash = hexEncodeLower(digest);
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        const auto signature = authorizationRootKey.sign(message);
        if (!ECDSAKey::isStrictDERLowS(signature)) {
            setReason(reason, "signer returned non-canonical signature");
            return false;
        }
        record.signature_der_hex = hexEncodeLower(signature);
        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("sign failure: ") + e.what());
        return false;
    }
}

bool verifyAuthorizationRecord(
    const AuthorizationRecord& record,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    try {
        if (record.format_version != 1U) {
            setReason(reason, "unsupported authorization record version");
            return false;
        }
        if (!isCanonicalTokenId(record.token_id)) {
            setReason(reason, "token_id must be canonical lowercase 16-hex");
            return false;
        }
        if (record.sequence == 0U) {
            setReason(reason, "sequence must start at 1");
            return false;
        }
        if (record.action == Action::UNKNOWN) {
            setReason(reason, "unknown authorization action");
            return false;
        }
        if (!isLowerHex(record.writer_pubkey_hex, COMPRESSED_PUBKEY_BYTES * 2U) ||
            (record.writer_pubkey_hex.rfind("02", 0) != 0 && record.writer_pubkey_hex.rfind("03", 0) != 0)) {
            setReason(reason, "writer public key must be canonical compressed SEC1 lowercase hex");
            return false;
        }
        if (deriveWriterId(record.writer_pubkey_hex) != record.writer_id ||
            !isLowerHex(record.writer_id, 64)) {
            setReason(reason, "writer_id does not match writer public key");
            return false;
        }
        const auto writerClass = VAHCapabilities::writerClassFromString(record.writer_class);
        if (writerClass == VAHCapabilities::WriterClass::UNKNOWN ||
            VAHCapabilities::writerClassToString(writerClass) != record.writer_class) {
            setReason(reason, "writer_class is not canonical");
            return false;
        }
        if (!isCanonicalCapabilities(record.capabilities)) {
            setReason(reason, "capabilities must be canonical, sorted, unique, and known");
            return false;
        }
        if ((record.action == Action::AUTHORIZE || record.action == Action::ROTATE) &&
            record.capabilities.empty()) {
            setReason(reason, "AUTHORIZE/ROTATE require at least one capability");
            return false;
        }
        if (record.action == Action::REVOKE && !record.capabilities.empty()) {
            setReason(reason, "REVOKE cannot carry capabilities");
            return false;
        }
        for (const auto& capability : record.capabilities) {
            if (!capabilityAllowedForWriter(tokenType, record.writer_class, capability)) {
                setReason(reason, "capability is incompatible with token type / writer class: " + capability);
                return false;
            }
        }
        if (!isLowerHex(record.previous_record_hash, 64)) {
            setReason(reason, "previous_record_hash must be lowercase 32-byte hex");
            return false;
        }
        if (!isLowerHex(trustedAuthorizationRootPubKeyHex, COMPRESSED_PUBKEY_BYTES * 2U) ||
            (trustedAuthorizationRootPubKeyHex.rfind("02", 0) != 0 &&
             trustedAuthorizationRootPubKeyHex.rfind("03", 0) != 0)) {
            setReason(reason, "trusted root public key is not canonical compressed SEC1 hex");
            return false;
        }
        if (record.authorization_root_pubkey_hex != trustedAuthorizationRootPubKeyHex) {
            setReason(reason, "record root does not match independently trusted authorization root");
            return false;
        }
        const auto digest = authorizationDigest(record);
        if (record.record_hash != hexEncodeLower(digest)) {
            setReason(reason, "record_hash mismatch");
            return false;
        }
        std::vector<unsigned char> signature;
        if (!hexDecodeVariableLower(record.signature_der_hex, signature, 72U) ||
            !ECDSAKey::isStrictDERLowS(signature)) {
            setReason(reason, "signature must be strict-DER low-S lowercase hex");
            return false;
        }
        std::vector<unsigned char> rootPub;
        if (!hexDecodeLower(trustedAuthorizationRootPubKeyHex, rootPub, COMPRESSED_PUBKEY_BYTES)) {
            setReason(reason, "trusted root public key decode failed");
            return false;
        }
        const std::string message(reinterpret_cast<const char*>(digest.data()), digest.size());
        if (!ECDSAKey::verify(rootPub, message, signature)) {
            setReason(reason, "authorization root signature invalid");
            return false;
        }
        setReason(reason, "ok");
        return true;
    } catch (const std::exception& e) {
        setReason(reason, std::string("verification failure: ") + e.what());
        return false;
    }
}

HistoryVerificationResult verifyAuthorizationHistory(
    const std::vector<AuthorizationRecord>& records,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    HistoryVerificationResult result;
    if (records.empty()) {
        result.errors.push_back("authorization history is empty");
        return result;
    }

    std::map<std::string, ActiveWriter> active;
    std::string expectedPrevious = ZERO_HASH;
    std::uint64_t expectedSequence = 1U;
    std::uint64_t previousEffectiveEpoch = 0U;

    for (const auto& record : records) {
        std::string reason;
        if (record.sequence != expectedSequence) {
            result.errors.push_back("authorization sequence gap/reorder at expected sequence " + std::to_string(expectedSequence));
            return result;
        }
        if (record.previous_record_hash != expectedPrevious) {
            result.errors.push_back("authorization previous_record_hash mismatch at sequence " + std::to_string(record.sequence));
            return result;
        }
        if (record.sequence > 1U && record.effective_epoch < previousEffectiveEpoch) {
            result.errors.push_back("effective_epoch moved backwards at sequence " + std::to_string(record.sequence));
            return result;
        }
        if (!verifyAuthorizationRecord(record, tokenType, trustedAuthorizationRootPubKeyHex, &reason)) {
            result.errors.push_back("record " + std::to_string(record.sequence) + ": " + reason);
            return result;
        }
        if (!applyRecord(record, active, &reason)) {
            result.errors.push_back("record " + std::to_string(record.sequence) + " state transition: " + reason);
            return result;
        }
        expectedPrevious = record.record_hash;
        previousEffectiveEpoch = record.effective_epoch;
        ++expectedSequence;
        ++result.verified_records;
    }

    result.ok = true;
    return result;
}

bool isWriterAuthorizedAtEpoch(
    const std::vector<AuthorizationRecord>& records,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::uint64_t epoch,
    const std::string& writerPubKeyHex,
    const std::string& writerType,
    const std::vector<std::string>& changedFields,
    std::string* reason)
{
    const auto verified = verifyAuthorizationHistory(records, tokenType, trustedAuthorizationRootPubKeyHex);
    if (!verified.ok) {
        setReason(reason, verified.errors.empty() ? "authorization history invalid" : verified.errors.front());
        return false;
    }
    if (changedFields.empty()) {
        setReason(reason, "writer authorization query requires at least one changed field");
        return false;
    }
    const auto writerClass = VAHCapabilities::writerClassFromString(writerType);
    if (writerClass == VAHCapabilities::WriterClass::UNKNOWN ||
        VAHCapabilities::writerClassToString(writerClass) != writerType) {
        setReason(reason, "writer type is not canonical");
        return false;
    }
    const std::string writerId = deriveWriterId(writerPubKeyHex);
    if (writerId.empty()) {
        setReason(reason, "invalid writer public key");
        return false;
    }

    std::map<std::string, ActiveWriter> active;
    for (const auto& record : records) {
        if (record.effective_epoch > epoch) break;
        std::string localReason;
        if (!applyRecord(record, active, &localReason)) {
            setReason(reason, "historical state replay failed: " + localReason);
            return false;
        }
    }

    const auto it = active.find(writerId);
    if (it == active.end()) {
        setReason(reason, "writer is not active at requested epoch");
        return false;
    }
    if (it->second.writer_pubkey_hex != writerPubKeyHex || it->second.writer_class != writerType) {
        setReason(reason, "writer identity/class mismatch at requested epoch");
        return false;
    }

    std::set<std::string> seenFields;
    for (const auto& field : changedFields) {
        if (!seenFields.insert(field).second) {
            setReason(reason, "duplicate changed field");
            return false;
        }
        if (!VAHCapabilities::writerClassMayHoldFieldCapability(tokenType, writerType, field)) {
            setReason(reason, "field incompatible with token/writer class: " + field);
            return false;
        }
        const std::string needed = capabilityForField(field);
        if (needed.empty() || it->second.capabilities.count(needed) == 0U) {
            setReason(reason, "writer lacks capability for field: " + field);
            return false;
        }
    }

    setReason(reason, "ok");
    return true;
}

std::string serializeAuthorizationRecord(const AuthorizationRecord& record) {
    std::ostringstream out;
    out << "TRU_VAH_AUTH_RECORD_V1\n";
    out << "format_version=" << record.format_version << "\n";
    out << "token_id=" << record.token_id << "\n";
    out << "sequence=" << record.sequence << "\n";
    out << "effective_epoch=" << record.effective_epoch << "\n";
    out << "action=" << actionToString(record.action) << "\n";
    out << "writer_id=" << record.writer_id << "\n";
    out << "writer_pubkey_hex=" << record.writer_pubkey_hex << "\n";
    out << "writer_class=" << record.writer_class << "\n";
    out << "capabilities=";
    for (std::size_t i = 0; i < record.capabilities.size(); ++i) {
        if (i) out << ',';
        out << record.capabilities[i];
    }
    out << "\n";
    out << "replaces_writer_id=" << record.replaces_writer_id << "\n";
    out << "previous_record_hash=" << record.previous_record_hash << "\n";
    out << "authorization_root_pubkey_hex=" << record.authorization_root_pubkey_hex << "\n";
    out << "record_hash=" << record.record_hash << "\n";
    out << "signature_der_hex=" << record.signature_der_hex << "\n";
    return out.str();
}

bool parseAuthorizationRecord(
    const std::string& encoded,
    AuthorizationRecord& out,
    std::string* reason)
{
    if (encoded.empty() || encoded.size() > MAX_RECORD_TEXT_BYTES) {
        setReason(reason, "serialized authorization record size invalid");
        return false;
    }
    std::istringstream input(encoded);
    std::string line;
    if (!std::getline(input, line) || line != "TRU_VAH_AUTH_RECORD_V1") {
        setReason(reason, "authorization record header mismatch");
        return false;
    }
    std::map<std::string, std::string> fields;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        const std::size_t pos = line.find('=');
        if (pos == std::string::npos || pos == 0U) {
            setReason(reason, "malformed authorization record line");
            return false;
        }
        const std::string key = line.substr(0, pos);
        const std::string value = line.substr(pos + 1U);
        if (value.size() > MAX_SERIALIZED_FIELD || !fields.emplace(key, value).second) {
            setReason(reason, "duplicate/oversize authorization record field");
            return false;
        }
    }
    static const std::array<const char*, 14> REQUIRED{{
        "format_version", "token_id", "sequence", "effective_epoch", "action",
        "writer_id", "writer_pubkey_hex", "writer_class", "capabilities",
        "replaces_writer_id", "previous_record_hash", "authorization_root_pubkey_hex",
        "record_hash", "signature_der_hex"
    }};
    if (fields.size() != REQUIRED.size()) {
        setReason(reason, "unexpected or missing authorization record fields");
        return false;
    }
    for (const char* key : REQUIRED) {
        if (fields.find(key) == fields.end()) {
            setReason(reason, std::string("missing authorization record field: ") + key);
            return false;
        }
    }

    std::uint64_t format = 0, sequence = 0, epoch = 0;
    if (!parseU64(fields["format_version"], format) || format > std::numeric_limits<std::uint32_t>::max() ||
        !parseU64(fields["sequence"], sequence) ||
        !parseU64(fields["effective_epoch"], epoch)) {
        setReason(reason, "invalid numeric authorization record field");
        return false;
    }

    AuthorizationRecord parsed;
    parsed.format_version = static_cast<std::uint32_t>(format);
    parsed.token_id = fields["token_id"];
    parsed.sequence = sequence;
    parsed.effective_epoch = epoch;
    parsed.action = actionFromString(fields["action"]);
    parsed.writer_id = fields["writer_id"];
    parsed.writer_pubkey_hex = fields["writer_pubkey_hex"];
    parsed.writer_class = fields["writer_class"];
    parsed.capabilities = splitComma(fields["capabilities"]);
    if (!fields["capabilities"].empty() && parsed.capabilities.empty()) {
        setReason(reason, "invalid capabilities encoding");
        return false;
    }
    parsed.replaces_writer_id = fields["replaces_writer_id"];
    parsed.previous_record_hash = fields["previous_record_hash"];
    parsed.authorization_root_pubkey_hex = fields["authorization_root_pubkey_hex"];
    parsed.record_hash = fields["record_hash"];
    parsed.signature_der_hex = fields["signature_der_hex"];
    out = std::move(parsed);
    setReason(reason, "ok");
    return true;
}

} // namespace VAHAuthorization
