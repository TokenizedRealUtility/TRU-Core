#include "vah_authorization_store.h"

#include "contract_storage.h"

#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace VAHAuthorizationStore {
namespace {

constexpr const char* CONTRACT_ADDR = "TOKEN:VAH_AUTH";
constexpr const char* HEAD_MAGIC = "TRU_VAH_AUTH_HEAD_V1";
constexpr std::uint64_t MAX_AUTH_RECORDS = 4096;
const std::string ZERO_HASH(64, '0');

#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
TestFault g_testFault = TestFault::NONE;
#endif

void setReason(std::string* reason, const std::string& value) {
    if (reason) *reason = value;
}

bool isLowerHex(const std::string& value, std::size_t chars) {
    if (value.size() != chars) return false;
    for (unsigned char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool isCanonicalTokenId(const std::string& tokenId) {
    return isLowerHex(tokenId, 16);
}

std::string seqKey(std::uint64_t sequence) {
    std::ostringstream out;
    out << "auth:" << std::setw(20) << std::setfill('0') << sequence;
    return out.str();
}

std::string headKey(const std::string& tokenId) {
    return tokenId + ":head";
}

std::string recordKey(const std::string& tokenId, std::uint64_t sequence) {
    return tokenId + ":" + seqKey(sequence);
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

std::string encodeHead(std::uint64_t sequence, const std::string& hash) {
    return std::string(HEAD_MAGIC) + "|" + std::to_string(sequence) + "|" + hash;
}

bool decodeHead(const std::string& encoded, std::uint64_t& sequence, std::string& hash) {
    const std::size_t p1 = encoded.find('|');
    if (p1 == std::string::npos) return false;
    const std::size_t p2 = encoded.find('|', p1 + 1U);
    if (p2 == std::string::npos || encoded.find('|', p2 + 1U) != std::string::npos) return false;
    if (encoded.substr(0, p1) != HEAD_MAGIC) return false;
    if (!parseU64(encoded.substr(p1 + 1U, p2 - p1 - 1U), sequence)) return false;
    hash = encoded.substr(p2 + 1U);
    return sequence >= 1U && sequence <= MAX_AUTH_RECORDS && isLowerHex(hash, 64);
}

bool readExact(ContractStorage& storage, const std::string& key, std::string& value, std::string& error) {
    if (!storage.contractDataExists(CONTRACT_ADDR, key)) {
        error = "missing persisted key: " + key;
        return false;
    }
    if (!storage.getContractData(CONTRACT_ADDR, key, value)) {
        error = "failed reading persisted key: " + key;
        return false;
    }
    return true;
}

} // namespace

#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
void setTestFault(TestFault fault) {
    g_testFault = fault;
}
#endif

LoadResult loadHistory(
    ContractStorage& storage,
    const std::string& tokenId,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex)
{
    LoadResult result;
    if (!isCanonicalTokenId(tokenId)) {
        result.errors.push_back("token id is not canonical 16-char lowercase hex");
        return result;
    }

    const std::string hKey = headKey(tokenId);
    if (!storage.contractDataExists(CONTRACT_ADDR, hKey)) {
        // An empty history is valid at the storage layer. Authorization
        // verification still requires at least one record before a writer can
        // ever be considered active.
        result.ok = true;
        result.latest_record_hash = ZERO_HASH;
        return result;
    }

    std::string headText;
    if (!storage.getContractData(CONTRACT_ADDR, hKey, headText)) {
        result.errors.push_back("authorization head exists but cannot be read");
        return result;
    }

    std::uint64_t latest = 0;
    std::string latestHash;
    if (!decodeHead(headText, latest, latestHash)) {
        result.errors.push_back("authorization head is malformed");
        return result;
    }

    result.records.reserve(static_cast<std::size_t>(latest));
    for (std::uint64_t seq = 1; seq <= latest; ++seq) {
        const std::string key = recordKey(tokenId, seq);
        std::string encoded;
        std::string error;
        if (!readExact(storage, key, encoded, error)) {
            result.errors.push_back(error);
            return result;
        }
        VAHAuthorization::AuthorizationRecord record;
        std::string reason;
        if (!VAHAuthorization::parseAuthorizationRecord(encoded, record, &reason)) {
            result.errors.push_back("authorization record " + std::to_string(seq) + " parse failure: " + reason);
            return result;
        }
        if (record.token_id != tokenId || record.sequence != seq) {
            result.errors.push_back("authorization record identity/sequence mismatch at " + std::to_string(seq));
            return result;
        }
        result.records.push_back(std::move(record));
    }

    // A record beyond the committed head is an impossible state after a valid
    // atomic append and therefore fails closed rather than being silently
    // ignored.
    if (latest < MAX_AUTH_RECORDS && storage.contractDataExists(CONTRACT_ADDR, recordKey(tokenId, latest + 1U))) {
        result.errors.push_back("authorization record exists beyond committed head");
        return result;
    }

    const auto verified = VAHAuthorization::verifyAuthorizationHistory(
        result.records, tokenType, trustedAuthorizationRootPubKeyHex);
    if (!verified.ok) {
        result.errors = verified.errors;
        return result;
    }
    if (result.records.empty() || result.records.back().record_hash != latestHash) {
        result.errors.push_back("authorization head hash does not match final verified record");
        return result;
    }

    result.ok = true;
    result.latest_sequence = latest;
    result.latest_record_hash = latestHash;
    return result;
}

bool appendRecord(
    ContractStorage& storage,
    const VAHAuthorization::AuthorizationRecord& record,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason)
{
    if (!isCanonicalTokenId(record.token_id)) {
        setReason(reason, "record token id is not canonical");
        return false;
    }

    LoadResult current = loadHistory(storage, record.token_id, tokenType, trustedAuthorizationRootPubKeyHex);
    if (!current.ok) {
        setReason(reason, current.errors.empty() ? "persisted authorization history invalid" : current.errors.front());
        return false;
    }

    const std::string candidateEncoded = VAHAuthorization::serializeAuthorizationRecord(record);

    // Crash/retry idempotence. If the exact signed record is already durable at
    // its sequence, a retry succeeds without writing anything. A same-sequence
    // conflict is refused.
    if (record.sequence >= 1U && record.sequence <= current.latest_sequence) {
        const std::string key = recordKey(record.token_id, record.sequence);
        std::string durable;
        std::string error;
        if (!readExact(storage, key, durable, error)) {
            setReason(reason, error);
            return false;
        }
        if (durable == candidateEncoded) {
            setReason(reason, "already persisted");
            return true;
        }
        setReason(reason, "conflicting authorization record at already-persisted sequence");
        return false;
    }

    if (current.latest_sequence >= MAX_AUTH_RECORDS) {
        setReason(reason, "authorization history record bound reached");
        return false;
    }
    const std::uint64_t expectedSequence = current.latest_sequence + 1U;
    const std::string expectedPrevious = current.latest_sequence == 0U ? ZERO_HASH : current.latest_record_hash;
    if (record.sequence != expectedSequence) {
        setReason(reason, "authorization sequence is not the exact next sequence");
        return false;
    }
    if (record.previous_record_hash != expectedPrevious) {
        setReason(reason, "authorization previous_record_hash is not the committed head");
        return false;
    }

    std::vector<VAHAuthorization::AuthorizationRecord> candidateHistory = current.records;
    candidateHistory.push_back(record);
    const auto verified = VAHAuthorization::verifyAuthorizationHistory(
        candidateHistory, tokenType, trustedAuthorizationRootPubKeyHex);
    if (!verified.ok) {
        setReason(reason, verified.errors.empty() ? "candidate authorization history invalid" : verified.errors.front());
        return false;
    }

    const std::string rKey = recordKey(record.token_id, record.sequence);
    const std::string hKey = headKey(record.token_id);
    const std::string headText = encodeHead(record.sequence, record.record_hash);

#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
    if (g_testFault == TestFault::BEFORE_BATCH) {
        setReason(reason, "test fault before atomic batch");
        return false;
    }
#endif

    const std::vector<ContractStorage::BatchWrite> writes{
        {CONTRACT_ADDR, rKey, candidateEncoded},
        {CONTRACT_ADDR, hKey, headText}
    };
    if (!storage.storeContractDataBatch(writes)) {
        setReason(reason, "atomic authorization record/head batch refused");
        return false;
    }

#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
    if (g_testFault == TestFault::AFTER_BATCH_BEFORE_READBACK) {
        setReason(reason, "test fault after durable batch before readback");
        return false;
    }
#endif

    std::string readRecord;
    std::string readHead;
    if (!storage.getContractData(CONTRACT_ADDR, rKey, readRecord) ||
        !storage.getContractData(CONTRACT_ADDR, hKey, readHead)) {
        setReason(reason, "authorization atomic batch readback failed");
        return false;
    }
#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
    if (g_testFault == TestFault::READBACK_MISMATCH) readRecord += "#TRU_VAH_TEST_MISMATCH";
#endif
    if (readRecord != candidateEncoded || readHead != headText) {
        setReason(reason, "authorization atomic batch readback mismatch");
        return false;
    }

    setReason(reason, "ok");
    return true;
}

} // namespace VAHAuthorizationStore
