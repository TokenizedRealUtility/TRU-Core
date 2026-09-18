#pragma once

#include "vah_authorization.h"

#include <cstdint>
#include <string>
#include <vector>

class ContractStorage;

namespace VAHAuthorizationStore {

struct LoadResult {
    bool ok = false;
    std::uint64_t latest_sequence = 0;
    std::string latest_record_hash;
    std::vector<VAHAuthorization::AuthorizationRecord> records;
    std::vector<std::string> errors;
};

// Durable authorization-history reader. The trusted root is supplied by the
// caller; the store never derives trust from data inside the persisted record.
LoadResult loadHistory(
    ContractStorage& storage,
    const std::string& tokenId,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex
);

// Append one already-signed authorization record. The complete persisted
// history plus candidate record is verified before one synced atomic batch
// writes both the record and the head. Exact retries are idempotent.
bool appendRecord(
    ContractStorage& storage,
    const VAHAuthorization::AuthorizationRecord& record,
    const std::string& tokenType,
    const std::string& trustedAuthorizationRootPubKeyHex,
    std::string* reason = nullptr
);

#ifdef TRU_VAH_AUTH_STORE_TEST_FAULTS
enum class TestFault {
    NONE,
    BEFORE_BATCH,
    AFTER_BATCH_BEFORE_READBACK,
    READBACK_MISMATCH
};
void setTestFault(TestFault fault);
#endif

} // namespace VAHAuthorizationStore
