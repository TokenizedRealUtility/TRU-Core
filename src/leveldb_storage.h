#pragma once
#include <cstdint>
#include <string>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "leveldb/cache.h"
#include <openssl/sha.h>
#include "logging.h" // Assuming a Logger class exists
#include <shared_mutex>

class LevelDBStorage {
public:
    explicit LevelDBStorage(const std::string &dbPath);
    ~LevelDBStorage();

    bool get(const std::string &key, std::string &value) const;
    // exact on-disk read for durable undo pre-images.
    // Returns true for Found/NotFound; `found` distinguishes absence
    // from a storage/IO failure.
    bool getRaw(const std::string &key, std::string &rawValue, bool &found) const;
    // create a consistent raw-key snapshot in another LevelDB.
    // Used only for isolated candidate-branch validation; values are copied
    // byte-for-byte so checksum wrappers and undo journals remain exact.
    bool copyRawSnapshotTo(
        LevelDBStorage& destination,
        bool skipBlockRecords = true,
        const std::unordered_set<std::string>* retainedUndoKeys = nullptr) const;
    bool put(const std::string &key, const std::string &value);
    bool del(const std::string &key);
    bool exists(const std::string &key) const;

    void iterateAll(std::function<void(const std::string &, const std::string &)> callback) const;
    void iteratePrefix(const std::string &prefix, std::function<void(const std::string &, const std::string &)> callback) const;

    void clear();
    void compact();
    size_t countKeys() const;

    bool repairDatabase();
    // live-state callers keep durable sync=true by default.
    // Disposable validation sandboxes may explicitly use sync=false.
    bool putBatch(leveldb::WriteBatch& batch, bool sync = true);
    const std::string& path() const noexcept { return dbPath; }
    // process-local, per-database-path
    // logical mutation generation. This is NOT durable consensus state.
    // Candidate-validation cache entries bind to this generation so any
    // successful same-path LevelDB mutation forces a cache miss/fail-closed
    // preflight instead of reusing a stale positive sandbox result.
    bool getMutationGeneration(uint64_t& generationOut) const;
    std::string computeDataChecksum(const std::string &data) const;
    bool putWithDataChecksum(const std::string &key, const std::string &value);
    bool getWithDataChecksum(const std::string &key, std::string &outValue) const;

    void verifyAllKeys() const; // Added for manual corruption verification

// In leveldb_storage.h, add these new methods to the public section:
    bool putContract(const std::string &key, const std::string &value);
    bool getContract(const std::string &key, std::string &outValue) const;

private:
    struct SharedDbEntry {
        leveldb::DB* db{nullptr};
        int refCount{0};
        leveldb::Cache* blockCache{nullptr};
    };

    leveldb::DB* db;
    const std::string dbPath;
    // the shared registry owns the custom LevelDB block cache so
    // repeated validation-sandbox open/close cycles cannot leak 100 MiB each.
    static std::unordered_map<std::string, SharedDbEntry> s_dbInstances;
    // shared ownership prevents erase from destroying a mutex
    // while an in-flight operation still holds/waits on it. The map itself is
    // protected by s_globalMtx.
    static std::unordered_map<std::string, std::shared_ptr<std::mutex>> s_dbMutexes;
    static std::shared_mutex s_globalMtx;
    // Slow DB::Open/close operations are serialized here, outside s_globalMtx,
    // so unrelated live DB operations are not frozen by sandbox lifecycle I/O.
    static std::mutex s_lifecycleMtx;
    // copy a lifetime-safe per-path mutex handle while holding
    // s_globalMtx. Callers then lock the shared mutex object without retaining
    // an unordered_map iterator/reference across rehash/erase.
    std::shared_ptr<std::mutex> getDbMutexHandle() const;
    std::string computeChecksum(const std::string &data) const; // Compute SHA-256 checksum
};
