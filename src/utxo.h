#pragma once
#include <string>
#include <functional>
#include <mutex>
#include <set>
#include <map>
#include <shared_mutex>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include <leveldb/write_batch.h>
#include "leveldb_storage.h"
#include "tx.h"
#include "tokens.h"

// Forward declarations
class Blockchain;

// Simple UTXO structure
struct UTXO {
    std::string txid;
    uint32_t vout;
    uint64_t amount;
    std::string scriptPubKey;

    uint32_t createdAtHeight = 0;
    bool isCoinbase = false;
};

struct ApplyTransactionResult {
    bool success;
    leveldb::WriteBatch batch;
    std::unordered_set<std::string> utxosToDelete;
    std::vector<std::tuple<std::string, uint32_t, std::string, std::string>> utxosToAdd;
    //std::vector<std::tuple<std::string, std::string, uint64_t, std::string, std::string>> tokenUtxos;
    std::vector<std::tuple<std::string, std::string, uint64_t, ExtendedTokenData, std::string>> tokenUtxos;
    std::unordered_map<std::string, std::pair<uint64_t, std::string>> tokenOwnershipUpdates;
    std::unordered_map<std::string, nlohmann::json> tokenMetadata;
    std::unordered_map<std::string, uint64_t> inputTokenMap;
    std::unordered_map<std::string, uint64_t> outputTokenMap;
    uint64_t inputTruSum;
    uint64_t outputTruSum;
    std::vector<std::string> addresses;
    ApplyTransactionResult() : success(false), inputTruSum(0), outputTruSum(0) {}
};

class UTXOSet {
public:
    // Constructors
    explicit UTXOSet(const std::string &dbPath);
    UTXOSet(const std::string &dbPath, Blockchain* blockchainPtr = nullptr,
            bool loadRegistry = true);
    ~UTXOSet();

    // Key construction and retrieval
    std::string makeUTXOKey(const std::string &txid, uint32_t vout) const;
    std::string retrieveOriginalUTXO(const std::string &txid, uint32_t vout) const;

    // Iteration over all stored UTXOs
    void iterateAll(std::function<void(const std::string &, const std::string &)> callback) const;

    // Transaction methods
    ApplyTransactionResult applyTransaction(const Transaction &tx, int blockHeight, Blockchain* blockchainPtr, ScriptExecutionContext& ctx);
    bool rollbackTransaction(const Transaction &tx);

    // Query methods
    bool exists(const std::string &txid, uint32_t vout) const;
    bool getUTXO(const std::string &txid, uint32_t vout, UTXO &utxo) const;
    std::vector<UTXO> getAllUTXOs() const;

    std::string getAddressFromUTXO(const std::string& txid, uint32_t vout, const Blockchain* blockchainPtr) const;
    // Debug printing
    void printAllUTXOs() const;

    // Off-chain metadata functions
    std::string getOffChainMetadata(const std::string &tokenID) const;
    bool updateOffChainMetadata(const std::string &tokenID,
                               const std::string &newMetadataJson,
                               const std::string &cryptoSignature);

    // Convenience methods forwarding to LevelDBStorage
    void clear() { dbStorage.clear(); }
    void put(const std::string &key, const std::string &value) { dbStorage.put(key, value); }
    void loadTokenRegistry();

    bool writeBatch(leveldb::WriteBatch& batch) {
         return dbStorage.putBatch(batch);
    }
    UTXO findTokenUTXO(const std::string& tokenID, const std::string& owner) const;
   uint64_t calculateBalanceFromUTXOs(const std::string& address, const LevelDBStorage* storage) const;
   std::vector<UTXO> getUTXOsForAddress(const std::string& address) const;
private:
    LevelDBStorage dbStorage;    // LevelDB wrapper instance
    mutable std::shared_mutex mtx; // Shared mutex for thread safety
    std::unordered_set<std::string> seenTokens; // track existing tokenIDs
    Blockchain* blockchainPtr;
};
