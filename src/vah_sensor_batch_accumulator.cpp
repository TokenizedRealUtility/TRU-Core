#include "vah_sensor_batch_accumulator.h"

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

namespace VAHSensorBatchAccumulator {
namespace {

constexpr const char* STORED_DOMAIN = "TRU_VAH_SENSOR_ACCUMULATED_BATCH_V1";
constexpr const char* HEAD_DOMAIN = "TRU_VAH_SENSOR_FEED_HEAD_V1";
constexpr const char* BATCH_PREFIX = "contract:TOKEN:VAH_SENSOR_BATCH:";
constexpr const char* HEAD_PREFIX = "contract:TOKEN:VAH_SENSOR_HEAD:";
constexpr std::size_t TOKEN_ID_HEX = 16U;
constexpr std::size_t WRITER_ID_HEX = 64U;
constexpr std::size_t HASH_HEX = 64U;
constexpr std::size_t PUBKEY_HEX = 66U;
constexpr std::size_t MAX_SIGNATURE_HEX = 160U;

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
    return value.size() == HASH_HEX &&
        std::all_of(value.begin(), value.end(), [](char c) { return c == '0'; });
}

bool isCanonicalField(const std::string& field) {
    if (field.empty() || field.size() > VAHSensorBatch::MAX_FIELD_BYTES) return false;
    return std::all_of(field.begin(), field.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    });
}

std::string u64Key(std::uint64_t value) {
    std::ostringstream oss;
    oss << std::setw(20) << std::setfill('0') << value;
    return oss.str();
}

std::string eventIndex(std::size_t value) {
    std::ostringstream oss;
    oss << std::setw(4) << std::setfill('0') << value;
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

bool parseCanonicalU32(const std::string& text, std::uint32_t& out) {
    std::uint64_t value = 0U;
    if (!parseCanonicalU64(text, value) || value > std::numeric_limits<std::uint32_t>::max()) return false;
    out = static_cast<std::uint32_t>(value);
    return true;
}

bool parseCanonicalSize(const std::string& text, std::size_t& out) {
    std::uint64_t value = 0U;
    if (!parseCanonicalU64(text, value) || value > std::numeric_limits<std::size_t>::max()) return false;
    out = static_cast<std::size_t>(value);
    return true;
}

bool splitLines(const std::string& encoded, std::size_t maxBytes, std::vector<std::string>& lines) {
    lines.clear();
    if (encoded.empty() || encoded.size() > maxBytes || encoded.back() != '\n') return false;
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

std::string wrapContract(LevelDBStorage& storage, const std::string& value) {
    return storage.computeDataChecksum(value) + "|" + value;
}

std::mutex& accumulatorMutex() {
    static std::mutex m;
    return m;
}

bool sameEvent(const VAHSensorBatch::Event& a, const VAHSensorBatch::Event& b) {
    return a.sequence == b.sequence &&
        a.observed_at_ms == b.observed_at_ms &&
        a.field == b.field &&
        a.payload_hash == b.payload_hash;
}

// Signature bytes are intentionally excluded. ECDSA signing can be randomized;
// batch_hash commits the canonical unsigned semantics and writer identity.
bool sameBatchIdentity(const VAHSensorBatch::Batch& a, const VAHSensorBatch::Batch& b) {
    if (a.format_version != b.format_version ||
        a.token_id != b.token_id || a.token_type != b.token_type || a.epoch != b.epoch ||
        a.previous_batch_hash != b.previous_batch_hash ||
        a.writer_pubkey_hex != b.writer_pubkey_hex || a.writer_id != b.writer_id ||
        a.writer_class != b.writer_class || a.merkle_root != b.merkle_root ||
        a.batch_hash != b.batch_hash || a.events.size() != b.events.size()) return false;
    for (std::size_t i = 0U; i < a.events.size(); ++i) {
        if (!sameEvent(a.events[i], b.events[i])) return false;
    }
    return true;
}

bool canonicalHeadStructure(const FeedHead& head, std::string* reason) {
    if (head.format_version != 1U) { setReason(reason, "unsupported sensor feed head version"); return false; }
    if (!isLowerHex(head.token_id, TOKEN_ID_HEX)) { setReason(reason, "sensor feed head token_id invalid"); return false; }
    if (!isLowerHex(head.writer_id, WRITER_ID_HEX)) { setReason(reason, "sensor feed head writer_id invalid"); return false; }
    if (!isLowerHex(head.writer_pubkey_hex, PUBKEY_HEX) ||
        (head.writer_pubkey_hex.rfind("02", 0U) != 0U && head.writer_pubkey_hex.rfind("03", 0U) != 0U)) {
        setReason(reason, "sensor feed head writer_pubkey invalid"); return false;
    }
    if (head.writer_id != VAHAuthorization::deriveWriterId(head.writer_pubkey_hex)) {
        setReason(reason, "sensor feed head writer identity mismatch"); return false;
    }
    if (head.batch_count == 0U || head.latest_epoch == 0U || head.last_first_sequence == 0U ||
        head.last_sequence < head.last_first_sequence || head.last_observed_at_ms == 0U ||
        !isLowerHex(head.last_batch_hash, HASH_HEX) || isZeroHash(head.last_batch_hash)) {
        setReason(reason, "sensor feed head counters/hash invalid"); return false;
    }
    return true;
}

bool loadStoredBatchUnlocked(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    std::uint64_t firstSequence,
    const std::string& batchHash,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    StoredBatch& out,
    std::string* reason)
{
    if (!isLowerHex(tokenId, TOKEN_ID_HEX) || !isLowerHex(writerId, WRITER_ID_HEX) ||
        firstSequence == 0U || !isLowerHex(batchHash, HASH_HEX) || isZeroHash(batchHash)) {
        setReason(reason, "non-canonical sensor stored-batch lookup"); return false;
    }
    const std::string key = accumulatedBatchKey(tokenId, writerId, firstSequence, batchHash);
    std::string raw;
    bool found = false;
    if (!storage.getRaw(key, raw, found)) { setReason(reason, "sensor batch raw lookup failed"); return false; }
    if (!found) { setReason(reason, "sensor accumulated batch not found"); return false; }

    std::string encoded;
    if (!storage.getContract(key, encoded)) { setReason(reason, "sensor accumulated batch checksum-invalid"); return false; }
    if (encoded.size() > MAX_DURABLE_BATCH_BYTES) { setReason(reason, "sensor durable batch byte bound exceeded"); return false; }

    StoredBatch parsed;
    std::string parseReason;
    if (!parseStoredBatch(encoded, parsed, &parseReason) || serializeStoredBatch(parsed) != encoded) {
        setReason(reason, "sensor accumulated batch envelope invalid: " + parseReason); return false;
    }
    if (parsed.batch.token_id != tokenId || parsed.batch.writer_id != writerId ||
        parsed.batch.events.empty() || parsed.batch.events.front().sequence != firstSequence ||
        parsed.batch.batch_hash != batchHash) {
        setReason(reason, "sensor accumulated batch key/envelope mismatch"); return false;
    }
    std::string verifyReason;
    if (!VAHSensorBatch::verifyBatch(parsed.batch, authorizationHistory,
            trustedAuthorizationRootPubKeyHex, &verifyReason)) {
        setReason(reason, "sensor accumulated batch VAH-04A verification failed: " + verifyReason); return false;
    }
    out = std::move(parsed);
    setReason(reason, "ok");
    return true;
}

LoadHeadResult loadFeedHeadUnlocked(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    LoadHeadResult result;
    if (!isLowerHex(tokenId, TOKEN_ID_HEX) || !isLowerHex(writerId, WRITER_ID_HEX)) {
        result.errors.push_back("sensor feed head lookup identity is non-canonical");
        return result;
    }

    const std::string key = feedHeadKey(tokenId, writerId);
    std::string raw;
    bool found = false;
    if (!storage.getRaw(key, raw, found)) {
        result.errors.push_back("sensor feed head raw lookup failed");
        return result;
    }
    if (!found) {
        result.ok = true;
        result.has_head = false;
        return result;
    }

    std::string encoded;
    if (!storage.getContract(key, encoded)) {
        result.errors.push_back("sensor feed head not found or checksum-invalid");
        return result;
    }
    if (encoded.size() > MAX_DURABLE_HEAD_BYTES) {
        result.errors.push_back("sensor feed head durable envelope exceeds byte bound");
        return result;
    }

    FeedHead head;
    std::string parseReason;
    if (!parseFeedHead(encoded, head, &parseReason) || serializeFeedHead(head) != encoded) {
        result.errors.push_back("non-canonical sensor feed head: " + parseReason);
        return result;
    }
    if (head.token_id != tokenId || head.writer_id != writerId) {
        result.errors.push_back("sensor feed head key/envelope binding mismatch");
        return result;
    }

    StoredBatch latest;
    std::string loadReason;
    if (!loadStoredBatchUnlocked(storage, tokenId, writerId, head.last_first_sequence,
            head.last_batch_hash, authorizationHistory, trustedAuthorizationRootPubKeyHex,
            latest, &loadReason)) {
        result.errors.push_back("sensor feed latest batch invalid: " + loadReason);
        return result;
    }
    if (latest.feed_index != head.batch_count || latest.batch.epoch != head.latest_epoch ||
        latest.batch.writer_pubkey_hex != head.writer_pubkey_hex || latest.batch.events.empty() ||
        latest.batch.events.back().sequence != head.last_sequence ||
        latest.batch.events.back().observed_at_ms != head.last_observed_at_ms) {
        result.errors.push_back("sensor feed head/latest batch binding mismatch");
        return result;
    }

    if (head.batch_count == 1U) {
        if (latest.previous_first_sequence != 0U || !isZeroHash(latest.batch.previous_batch_hash) ||
            latest.batch.events.front().sequence != 1U) {
            result.errors.push_back("sensor feed genesis continuity mismatch");
            return result;
        }
    } else {
        if (latest.previous_first_sequence == 0U || isZeroHash(latest.batch.previous_batch_hash)) {
            result.errors.push_back("sensor feed predecessor pointer missing");
            return result;
        }
        StoredBatch predecessor;
        if (!loadStoredBatchUnlocked(storage, tokenId, writerId, latest.previous_first_sequence,
                latest.batch.previous_batch_hash, authorizationHistory,
                trustedAuthorizationRootPubKeyHex, predecessor, &loadReason)) {
            result.errors.push_back("sensor feed immediate predecessor invalid: " + loadReason);
            return result;
        }
        if (predecessor.feed_index == std::numeric_limits<std::uint64_t>::max() ||
            predecessor.feed_index + 1U != latest.feed_index || predecessor.batch.events.empty() ||
            predecessor.batch.events.back().sequence == std::numeric_limits<std::uint64_t>::max() ||
            predecessor.batch.events.back().sequence + 1U != latest.batch.events.front().sequence ||
            predecessor.batch.events.back().observed_at_ms > latest.batch.events.front().observed_at_ms ||
            predecessor.batch.epoch > latest.batch.epoch) {
            result.errors.push_back("sensor feed immediate predecessor continuity mismatch");
            return result;
        }
    }

    result.ok = true;
    result.has_head = true;
    result.head = std::move(head);
    result.latest = std::move(latest);
    return result;
}

} // namespace

std::string accumulatedBatchKey(
    const std::string& tokenId,
    const std::string& writerId,
    std::uint64_t firstSequence,
    const std::string& batchHash)
{
    return std::string(BATCH_PREFIX) + tokenId + ":writer:" + writerId +
        ":first:" + u64Key(firstSequence) + ":batch:" + batchHash;
}

std::string feedHeadKey(const std::string& tokenId, const std::string& writerId) {
    return std::string(HEAD_PREFIX) + tokenId + ":writer:" + writerId;
}

std::string serializeStoredBatch(const StoredBatch& stored) {
    const auto& b = stored.batch;
    std::ostringstream oss;
    oss << STORED_DOMAIN << '\n';
    oss << "feed_index=" << stored.feed_index << '\n';
    oss << "previous_first_sequence=" << stored.previous_first_sequence << '\n';
    oss << "batch_format_version=" << b.format_version << '\n';
    oss << "token_id=" << b.token_id << '\n';
    oss << "token_type=" << b.token_type << '\n';
    oss << "epoch=" << b.epoch << '\n';
    oss << "previous_batch_hash=" << b.previous_batch_hash << '\n';
    oss << "writer_pubkey_hex=" << b.writer_pubkey_hex << '\n';
    oss << "writer_id=" << b.writer_id << '\n';
    oss << "writer_class=" << b.writer_class << '\n';
    oss << "event_count=" << b.events.size() << '\n';
    for (std::size_t i = 0U; i < b.events.size(); ++i) {
        const std::string idx = eventIndex(i);
        oss << "event_" << idx << "_sequence=" << b.events[i].sequence << '\n';
        oss << "event_" << idx << "_observed_at_ms=" << b.events[i].observed_at_ms << '\n';
        oss << "event_" << idx << "_field=" << b.events[i].field << '\n';
        oss << "event_" << idx << "_payload_hash=" << b.events[i].payload_hash << '\n';
    }
    oss << "merkle_root=" << b.merkle_root << '\n';
    oss << "batch_hash=" << b.batch_hash << '\n';
    oss << "signature_der_hex=" << b.signature_der_hex << '\n';
    return oss.str();
}

bool parseStoredBatch(const std::string& encoded, StoredBatch& out, std::string* reason) {
    std::vector<std::string> lines;
    if (!splitLines(encoded, MAX_DURABLE_BATCH_BYTES, lines) || lines.empty() || lines[0] != STORED_DOMAIN) {
        setReason(reason, "stored batch line/domain framing invalid"); return false;
    }
    std::size_t c = 1U;
    std::string v;
    StoredBatch parsed;
    if (!takeValue(lines, c, "feed_index", v) || !parseCanonicalU64(v, parsed.feed_index) || parsed.feed_index == 0U) {
        setReason(reason, "stored batch feed_index invalid"); return false;
    }
    if (!takeValue(lines, c, "previous_first_sequence", v) || !parseCanonicalU64(v, parsed.previous_first_sequence)) {
        setReason(reason, "stored batch previous_first_sequence invalid"); return false;
    }
    if (!takeValue(lines, c, "batch_format_version", v) || !parseCanonicalU32(v, parsed.batch.format_version) || parsed.batch.format_version != 1U) {
        setReason(reason, "stored batch format version invalid"); return false;
    }
    if (!takeValue(lines, c, "token_id", parsed.batch.token_id) || !isLowerHex(parsed.batch.token_id, TOKEN_ID_HEX)) {
        setReason(reason, "stored batch token_id invalid"); return false;
    }
    if (!takeValue(lines, c, "token_type", parsed.batch.token_type) ||
        (parsed.batch.token_type != "SFT" && parsed.batch.token_type != "NCFT")) {
        setReason(reason, "stored batch token_type invalid"); return false;
    }
    if (!takeValue(lines, c, "epoch", v) || !parseCanonicalU64(v, parsed.batch.epoch) || parsed.batch.epoch == 0U) {
        setReason(reason, "stored batch epoch invalid"); return false;
    }
    if (!takeValue(lines, c, "previous_batch_hash", parsed.batch.previous_batch_hash) ||
        !isLowerHex(parsed.batch.previous_batch_hash, HASH_HEX)) {
        setReason(reason, "stored batch previous hash invalid"); return false;
    }
    if (!takeValue(lines, c, "writer_pubkey_hex", parsed.batch.writer_pubkey_hex) ||
        !isLowerHex(parsed.batch.writer_pubkey_hex, PUBKEY_HEX) ||
        (parsed.batch.writer_pubkey_hex.rfind("02", 0U) != 0U && parsed.batch.writer_pubkey_hex.rfind("03", 0U) != 0U)) {
        setReason(reason, "stored batch writer pubkey invalid"); return false;
    }
    if (!takeValue(lines, c, "writer_id", parsed.batch.writer_id) || !isLowerHex(parsed.batch.writer_id, WRITER_ID_HEX) ||
        parsed.batch.writer_id != VAHAuthorization::deriveWriterId(parsed.batch.writer_pubkey_hex)) {
        setReason(reason, "stored batch writer identity invalid"); return false;
    }
    if (!takeValue(lines, c, "writer_class", parsed.batch.writer_class) || parsed.batch.writer_class != "sensor") {
        setReason(reason, "stored batch writer_class invalid"); return false;
    }
    std::size_t eventCount = 0U;
    if (!takeValue(lines, c, "event_count", v) || !parseCanonicalSize(v, eventCount) ||
        eventCount == 0U || eventCount > VAHSensorBatch::MAX_EVENTS_PER_BATCH) {
        setReason(reason, "stored batch event_count invalid"); return false;
    }
    parsed.batch.events.reserve(eventCount);
    for (std::size_t i = 0U; i < eventCount; ++i) {
        const std::string idx = eventIndex(i);
        VAHSensorBatch::Event e;
        if (!takeValue(lines, c, "event_" + idx + "_sequence", v) || !parseCanonicalU64(v, e.sequence) || e.sequence == 0U ||
            !takeValue(lines, c, "event_" + idx + "_observed_at_ms", v) || !parseCanonicalU64(v, e.observed_at_ms) || e.observed_at_ms == 0U ||
            !takeValue(lines, c, "event_" + idx + "_field", e.field) || !isCanonicalField(e.field) ||
            !takeValue(lines, c, "event_" + idx + "_payload_hash", e.payload_hash) || !isLowerHex(e.payload_hash, HASH_HEX) || isZeroHash(e.payload_hash)) {
            setReason(reason, "stored batch event encoding invalid"); return false;
        }
        parsed.batch.events.push_back(std::move(e));
    }
    if (!takeValue(lines, c, "merkle_root", parsed.batch.merkle_root) || !isLowerHex(parsed.batch.merkle_root, HASH_HEX) || isZeroHash(parsed.batch.merkle_root) ||
        !takeValue(lines, c, "batch_hash", parsed.batch.batch_hash) || !isLowerHex(parsed.batch.batch_hash, HASH_HEX) || isZeroHash(parsed.batch.batch_hash) ||
        !takeValue(lines, c, "signature_der_hex", parsed.batch.signature_der_hex) || parsed.batch.signature_der_hex.empty() ||
        parsed.batch.signature_der_hex.size() > MAX_SIGNATURE_HEX || (parsed.batch.signature_der_hex.size() % 2U) != 0U ||
        !std::all_of(parsed.batch.signature_der_hex.begin(), parsed.batch.signature_der_hex.end(), [](unsigned char ch) {
            return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
        }) || c != lines.size()) {
        setReason(reason, "stored batch trailer/signature invalid"); return false;
    }
    out = std::move(parsed);
    setReason(reason, "ok");
    return true;
}

std::string serializeFeedHead(const FeedHead& head) {
    std::ostringstream oss;
    oss << HEAD_DOMAIN << '\n';
    oss << "format_version=" << head.format_version << '\n';
    oss << "token_id=" << head.token_id << '\n';
    oss << "writer_id=" << head.writer_id << '\n';
    oss << "writer_pubkey_hex=" << head.writer_pubkey_hex << '\n';
    oss << "batch_count=" << head.batch_count << '\n';
    oss << "latest_epoch=" << head.latest_epoch << '\n';
    oss << "last_first_sequence=" << head.last_first_sequence << '\n';
    oss << "last_sequence=" << head.last_sequence << '\n';
    oss << "last_observed_at_ms=" << head.last_observed_at_ms << '\n';
    oss << "last_batch_hash=" << head.last_batch_hash << '\n';
    return oss.str();
}

bool parseFeedHead(const std::string& encoded, FeedHead& out, std::string* reason) {
    std::vector<std::string> lines;
    if (!splitLines(encoded, MAX_DURABLE_HEAD_BYTES, lines) || lines.empty() || lines[0] != HEAD_DOMAIN) {
        setReason(reason, "sensor feed head line/domain framing invalid"); return false;
    }
    std::size_t c = 1U;
    std::string v;
    FeedHead head;
    if (!takeValue(lines, c, "format_version", v) || !parseCanonicalU32(v, head.format_version) ||
        !takeValue(lines, c, "token_id", head.token_id) ||
        !takeValue(lines, c, "writer_id", head.writer_id) ||
        !takeValue(lines, c, "writer_pubkey_hex", head.writer_pubkey_hex) ||
        !takeValue(lines, c, "batch_count", v) || !parseCanonicalU64(v, head.batch_count) ||
        !takeValue(lines, c, "latest_epoch", v) || !parseCanonicalU64(v, head.latest_epoch) ||
        !takeValue(lines, c, "last_first_sequence", v) || !parseCanonicalU64(v, head.last_first_sequence) ||
        !takeValue(lines, c, "last_sequence", v) || !parseCanonicalU64(v, head.last_sequence) ||
        !takeValue(lines, c, "last_observed_at_ms", v) || !parseCanonicalU64(v, head.last_observed_at_ms) ||
        !takeValue(lines, c, "last_batch_hash", head.last_batch_hash) || c != lines.size() ||
        !canonicalHeadStructure(head, reason)) {
        if (reason != nullptr && reason->empty()) *reason = "sensor feed head field encoding invalid";
        return false;
    }
    out = std::move(head);
    setReason(reason, "ok");
    return true;
}

bool loadStoredBatch(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    std::uint64_t firstSequence,
    const std::string& batchHash,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    StoredBatch& out,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock(accumulatorMutex());
    return loadStoredBatchUnlocked(storage, tokenId, writerId, firstSequence, batchHash,
        authorizationHistory, trustedAuthorizationRootPubKeyHex, out, reason);
}

LoadHeadResult loadFeedHead(
    LevelDBStorage& storage,
    const std::string& tokenId,
    const std::string& writerId,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    std::lock_guard<std::mutex> lock(accumulatorMutex());
    return loadFeedHeadUnlocked(storage, tokenId, writerId,
        authorizationHistory, trustedAuthorizationRootPubKeyHex);
}

bool appendBatch(
    LevelDBStorage& storage,
    const VAHSensorBatch::Batch& batch,
    const std::vector<VAHAuthorization::AuthorizationRecord>& authorizationHistory,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    std::lock_guard<std::mutex> lock(accumulatorMutex());

    std::string verifyReason;
    if (!VAHSensorBatch::verifyBatch(batch, authorizationHistory,
            trustedAuthorizationRootPubKeyHex, &verifyReason)) {
        setReason(reason, "sensor batch VAH-04A admission failed: " + verifyReason); return false;
    }
    if (batch.events.empty()) { setReason(reason, "sensor batch has no events"); return false; }

    const std::uint64_t firstSequence = batch.events.front().sequence;
    const std::string batchKey = accumulatedBatchKey(batch.token_id, batch.writer_id,
        firstSequence, batch.batch_hash);

    std::string raw;
    bool batchExists = false;
    if (!storage.getRaw(batchKey, raw, batchExists)) {
        setReason(reason, "sensor batch raw existence check failed"); return false;
    }

    if (batchExists) {
        StoredBatch existing;
        if (!loadStoredBatchUnlocked(storage, batch.token_id, batch.writer_id, firstSequence,
                batch.batch_hash, authorizationHistory, trustedAuthorizationRootPubKeyHex,
                existing, &verifyReason)) {
            setReason(reason, "existing sensor batch is corrupt: " + verifyReason); return false;
        }
        if (!sameBatchIdentity(existing.batch, batch)) {
            setReason(reason, "existing sensor batch identity conflicts"); return false;
        }
        const auto current = loadFeedHeadUnlocked(storage, batch.token_id, batch.writer_id,
            authorizationHistory, trustedAuthorizationRootPubKeyHex);
        if (!current.ok || !current.has_head || current.head.batch_count < existing.feed_index) {
            setReason(reason, "sensor batch exists without a valid at-or-ahead feed head"); return false;
        }
        setReason(reason, "ok-idempotent");
        return true;
    }

    const auto current = loadFeedHeadUnlocked(storage, batch.token_id, batch.writer_id,
        authorizationHistory, trustedAuthorizationRootPubKeyHex);
    if (!current.ok) {
        setReason(reason, current.errors.empty() ? "sensor feed head invalid" : current.errors.front());
        return false;
    }

    StoredBatch stored;
    stored.batch = batch;
    FeedHead next;
    next.token_id = batch.token_id;
    next.writer_id = batch.writer_id;
    next.writer_pubkey_hex = batch.writer_pubkey_hex;
    next.latest_epoch = batch.epoch;
    next.last_first_sequence = firstSequence;
    next.last_sequence = batch.events.back().sequence;
    next.last_observed_at_ms = batch.events.back().observed_at_ms;
    next.last_batch_hash = batch.batch_hash;

    if (!current.has_head) {
        if (!isZeroHash(batch.previous_batch_hash)) {
            setReason(reason, "sensor feed genesis previous_batch_hash must be zero"); return false;
        }
        if (firstSequence != 1U) {
            setReason(reason, "sensor feed genesis sequence must begin at 1"); return false;
        }
        stored.feed_index = 1U;
        stored.previous_first_sequence = 0U;
        next.batch_count = 1U;
    } else {
        const FeedHead& head = current.head;
        if (head.batch_count == std::numeric_limits<std::uint64_t>::max()) {
            setReason(reason, "sensor feed batch_count overflow"); return false;
        }
        if (head.last_sequence == std::numeric_limits<std::uint64_t>::max()) {
            setReason(reason, "sensor feed event sequence exhausted"); return false;
        }
        if (batch.writer_pubkey_hex != head.writer_pubkey_hex || batch.epoch < head.latest_epoch) {
            setReason(reason, "sensor feed writer/epoch continuity mismatch"); return false;
        }
        if (batch.previous_batch_hash != head.last_batch_hash) {
            setReason(reason, "sensor feed previous_batch_hash does not match durable head"); return false;
        }
        if (firstSequence != head.last_sequence + 1U) {
            setReason(reason, "sensor feed first sequence does not continue durable head"); return false;
        }
        if (batch.events.front().observed_at_ms < head.last_observed_at_ms) {
            setReason(reason, "sensor feed timestamp regresses across batches"); return false;
        }
        stored.feed_index = head.batch_count + 1U;
        stored.previous_first_sequence = head.last_first_sequence;
        next.batch_count = stored.feed_index;
    }

    const std::string encodedBatch = serializeStoredBatch(stored);
    const std::string encodedHead = serializeFeedHead(next);
    if (encodedBatch.size() > MAX_DURABLE_BATCH_BYTES || encodedHead.size() > MAX_DURABLE_HEAD_BYTES) {
        setReason(reason, "sensor accumulator durable envelope exceeds byte bound"); return false;
    }

    leveldb::WriteBatch write;
    write.Put(batchKey, wrapContract(storage, encodedBatch));
    write.Put(feedHeadKey(batch.token_id, batch.writer_id), wrapContract(storage, encodedHead));
    if (!storage.putBatch(write, true)) {
        setReason(reason, "sensor accumulator synced batch/head write failed"); return false;
    }

    const auto readback = loadFeedHeadUnlocked(storage, batch.token_id, batch.writer_id,
        authorizationHistory, trustedAuthorizationRootPubKeyHex);
    if (!readback.ok || !readback.has_head || readback.head.batch_count != next.batch_count ||
        readback.head.last_batch_hash != batch.batch_hash ||
        !sameBatchIdentity(readback.latest.batch, batch)) {
        setReason(reason, "sensor accumulator immediate readback failed"); return false;
    }

    setReason(reason, "ok");
    return true;
}

} // namespace VAHSensorBatchAccumulator
