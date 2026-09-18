#pragma once
#include "leveldb_storage.h"
#include <string>
#include <tuple>
#include <vector>
#include "logging.h"

class ContractStorage {
public:
#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
    enum class TestFault {
        NONE,
        BEFORE_BATCH,
        BATCH_WRITE_FAIL,
        AFTER_BATCH_BEFORE_READBACK,
        READBACK_MISMATCH
    };

    void setTokenEvolutionTestFault(TestFault fault) {
        testFault_ = fault;
        testAfterBatch_ = false;
        testReadbackFaultConsumed_ = false;
    }
#endif
    // Changed to accept raw pointer instead of shared_ptr
    ContractStorage(LevelDBStorage* storage) : storage_(storage) {}
    
    // When you only have const storage (e.g., from Blockchain::getStorage())
    explicit ContractStorage(const LevelDBStorage* storage)
        : storage_(const_cast<LevelDBStorage*>(storage)) {}

    bool storeContractData(const std::string& contractAddr, const std::string& key, const std::string& value) {
        if (!storage_) return false;
        std::string cleanAddr = normalizeContractAddress(contractAddr);
        std::string fullKey = "contract:" + cleanAddr + ":" + key;
        return storage_->putContract(fullKey, value);
    }
    
    bool contractDataExists(const std::string& contractAddr, const std::string& key) const {
        if (!storage_) return false;
        std::string cleanAddr = normalizeContractAddressConst(contractAddr);
        const std::string fullKey = "contract:" + cleanAddr + ":" + key;
        return storage_->exists(fullKey);
    }

    bool getContractData(const std::string& contractAddr, const std::string& key, std::string& value) {
        if (!storage_) return false;
        std::string cleanAddr = normalizeContractAddress(contractAddr);
        std::string fullKey = "contract:" + cleanAddr + ":" + key;
        const bool ok = storage_->getContract(fullKey, value);
#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
        if (ok && testAfterBatch_ &&
            testFault_ == TestFault::READBACK_MISMATCH &&
            !testReadbackFaultConsumed_ &&
            cleanAddr == "TOKEN:EVOLUTION") {
            value += "#TRU_TEST_READBACK_MISMATCH";
            testReadbackFaultConsumed_ = true;
        }
#endif
        return ok;
    }

    // TOKEN-AI-02A: atomically persist related contract-state keys using one
    // synced LevelDB WriteBatch. Values retain the exact putContract()
    // checksum envelope so existing getContract() readers remain unchanged.
    using BatchWrite = std::tuple<std::string, std::string, std::string>;

    bool storeContractDataBatch(const std::vector<BatchWrite>& writes) {
        if (!storage_ || writes.empty()) return false;
#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
        if (testFault_ == TestFault::BEFORE_BATCH) return false;
#endif

        leveldb::WriteBatch batch;
        for (const auto& write : writes) {
            const std::string& contractAddr = std::get<0>(write);
            const std::string& key = std::get<1>(write);
            const std::string& value = std::get<2>(write);

            if (contractAddr.empty() || key.empty()) return false;

            const std::string cleanAddr = normalizeContractAddress(contractAddr);
            const std::string fullKey = "contract:" + cleanAddr + ":" + key;
            const std::string checksum = storage_->computeDataChecksum(value);
            batch.Put(fullKey, checksum + "|" + value);
        }

#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
        // Dedicated closeout target only. BATCH_WRITE_FAIL simulates the
        // storage layer refusing the atomic WriteBatch operation before it is
        // published. AFTER_BATCH_BEFORE_READBACK simulates an ambiguous caller
        // failure after the full synced batch is durable but before verification.
        if (testFault_ == TestFault::BATCH_WRITE_FAIL) return false;
#endif
        const bool ok = storage_->putBatch(batch, true);
#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
        if (ok) testAfterBatch_ = true;
        if (ok && testFault_ == TestFault::AFTER_BATCH_BEFORE_READBACK) return false;
#endif
        return ok;
    }
    
private:
    LevelDBStorage* storage_;
#ifdef TRU_TOKEN_EVOLUTION_TEST_FAULTS
    TestFault testFault_{TestFault::NONE};
    mutable bool testAfterBatch_{false};
    mutable bool testReadbackFaultConsumed_{false};
#endif  // Changed from shared_ptr to raw pointer
    
    std::string normalizeContractAddress(const std::string& addr) {
        return normalizeContractAddressConst(addr);
    }

    static std::string normalizeContractAddressConst(const std::string& addr) {
        std::string result = addr;
        if (result.find("contract_") == 0) {
            result = result.substr(9);
        }
        size_t underscorePos = result.rfind('_');
        if (underscorePos != std::string::npos && result.find(':') == std::string::npos) {
            result[underscorePos] = ':';
        }
        return result;
    }
};
