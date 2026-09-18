#pragma once
#ifndef VAH_RECONCILIATION_STORE_H
#define VAH_RECONCILIATION_STORE_H

#include "vah_reconciliation.h"

#include <cstdint>
#include <string>

class LevelDBStorage;

namespace VAHDurableReconciliation {

struct DurableResult {
    std::string tokenID;
    uint64_t epoch{0};
    std::string previousMetadataHash;
    VAHReconciliation::CanonicalView view;
    VAHReconciliation::Candidate winner;
};

// Stable append-only key for one reconciled token epoch.
std::string reconciliationKey(const std::string& tokenID, uint64_t epoch);

// Persist an elected winner durably. Existing identical state is idempotent;
// an existing conflicting value is never overwritten.
bool persistCanonicalResult(
    LevelDBStorage& storage,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    const VAHReconciliation::CanonicalView& view,
    const VAHReconciliation::ElectionResult& election,
    std::string& reason);

// Restart/recovery read. The checksum envelope is verified by LevelDBStorage,
// then every durable field is parsed and revalidated against its finalized view.
bool loadCanonicalResult(
    const LevelDBStorage& storage,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    const std::string& expectedPreviousMetadataHash,
    DurableResult& out,
    std::string& reason);

bool sameDurableIdentity(const DurableResult& a, const DurableResult& b);

} // namespace VAHDurableReconciliation

#endif
