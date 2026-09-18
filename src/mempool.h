#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <mutex>
#include <set>
#include <cstdint>
#include "tx.h"
#include "utxo.h"
#include "blockchain.h"

enum class MempoolAddStatus {
    SUCCESS,
    DUPLICATE,
    INVALID,
    BUSY
};

enum class MempoolValidationStatus {
    VALID,
    INVALID,
    BUSY
};

class Mempool {
public:
    MempoolAddStatus addTransaction(const Transaction& tx);
    bool removeTransaction(const std::string& txid);
    bool hasTransaction(const std::string& txid) const;
    bool getTransaction(const std::string& txid, Transaction& outTx) const;
    std::vector<Transaction> getAllTransactions() const;

    explicit Mempool(Blockchain& chain); 
    std::vector<unsigned char> buildInputSighash(const Transaction& tx, size_t inputIndex, const std::vector<unsigned char>& scriptPubKey) const;
    
    
    bool isAllowedSmartContractScript(const std::string& scriptPubKeyHex) const;

    // Public validation is tri-state so temporary overload can never be
    // silently collapsed into transaction invalidity.
    MempoolValidationStatus validateTransaction(
        const Transaction& tx,
        const Blockchain* blockchain) const;

    bool shouldRelayTransaction(const Transaction& tx) const;
    bool isUTXOSpentInMempool(const std::string& txid, uint32_t vout) const;
    void cleanAfterBlock(const Block& block);
    bool isMagicLockScript(const std::string& scriptHex) const;
    std::vector<std::string> scanForAIRequests() const;
    // OP_DATAFEED is no longer overloaded as an AI-request marker.

private:
    std::unordered_map<std::string, Transaction> pool_;
    Blockchain& chain_;

    //
    // One mutex owns the transaction map, spent-outpoint set, and all resource
    // accounting so callers cannot observe torn mempool state.
    mutable std::mutex mtx_;
    std::unordered_set<std::string> spentInMempool;
    std::unordered_map<std::string, std::size_t> txSerializedSizes_;
    std::unordered_map<std::string, std::uint64_t> txFees_;
    std::size_t poolBytes_{0};

    // Patch 12B exact fee-rate index.
    // compareRate() never uses floating point. Once integer quotients match,
    // remainders are each < MAX_MEMPOOL_TX_BYTES, so the cross products are
    // bounded by roughly 4 MiB * 4 MiB and fit safely in uint64_t.
    struct FeeEntry {
        std::uint64_t fee{0};
        std::size_t bytes{0};
        std::string txid;
    };

    struct FeeEntryLess {
        static int compareRate(const FeeEntry& a, const FeeEntry& b) noexcept {
            if (a.bytes == 0 || b.bytes == 0) {
                if (a.bytes == b.bytes) return 0;
                return a.bytes == 0 ? -1 : 1;
            }

            const std::uint64_t aBytes =
                static_cast<std::uint64_t>(a.bytes);
            const std::uint64_t bBytes =
                static_cast<std::uint64_t>(b.bytes);

            const std::uint64_t aq = a.fee / aBytes;
            const std::uint64_t bq = b.fee / bBytes;
            if (aq < bq) return -1;
            if (aq > bq) return 1;

            const std::uint64_t ar = a.fee % aBytes;
            const std::uint64_t br = b.fee % bBytes;
            const std::uint64_t lhs = ar * bBytes;
            const std::uint64_t rhs = br * aBytes;
            if (lhs < rhs) return -1;
            if (lhs > rhs) return 1;
            return 0;
        }

        bool operator()(const FeeEntry& a, const FeeEntry& b) const noexcept {
            const int cmp = compareRate(a, b);
            if (cmp != 0) return cmp < 0;
            return a.txid < b.txid;
        }
    };

    std::set<FeeEntry, FeeEntryLess> feeIndex_;

    // One fail-fast validation budget for ALL public validation/admission
    // paths. Saturation returns BUSY instead of being misclassified INVALID
    // or parking RPC/P2P worker threads on an unbounded wait.
    mutable std::mutex validationMutex_;
    mutable std::size_t activeValidations_{0};

    bool tryAcquireValidationSlot() const;
    void releaseValidationSlot() const;
    bool isTransactionValidUnchecked(
        const Transaction& tx,
        const Blockchain* blockchain) const;

    // Caller MUST hold mtx_. Centralizing removal keeps spent markers, byte
    // accounting, fee accounting and the fee-rate index synchronized.
    bool eraseTransactionLocked(const std::string& txid, const char* reason);
    void rebuildFeeIndexLocked();

};

#endif // MEMPOOL_H
