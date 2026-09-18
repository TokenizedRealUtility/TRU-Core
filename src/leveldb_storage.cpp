#include "leveldb_storage.h"
#include "contract_storage.h"
#include <sys/stat.h>
#include <errno.h>
#include <iostream>
#include <stdexcept>
#include <memory>
#include <iomanip>
#include <sstream>
#include <limits>
#include "logging.h"
#include <mutex>

// Initialize static members
std::unordered_map<std::string, LevelDBStorage::SharedDbEntry> LevelDBStorage::s_dbInstances;
std::unordered_map<std::string, std::shared_ptr<std::mutex>> LevelDBStorage::s_dbMutexes;
std::shared_mutex LevelDBStorage::s_globalMtx;
std::mutex LevelDBStorage::s_lifecycleMtx;

// ============================================================================
// per-LevelDB-path logical mutation generation
//
// Cache invalidation metadata only. It is intentionally process-local:
// candidate validation cache entries are process-local and begin empty on
// restart. A different sandbox dbPath gets a different generation.
// ============================================================================
namespace {
struct Patch08B4D4MutationGenerationState {
    uint64_t value{0};
    bool disabled{false};
};

std::mutex g_patch08B4D4MutationGenerationMutex;
std::unordered_map<std::string, Patch08B4D4MutationGenerationState>
    g_patch08B4D4MutationGenerationByPath;
bool g_patch08B4D4MutationGenerationGloballyDisabled = false;

void patch08B4D4BumpMutationGeneration(const std::string& path) noexcept {
    try {
        std::lock_guard<std::mutex> lock(
            g_patch08B4D4MutationGenerationMutex);

        if (g_patch08B4D4MutationGenerationGloballyDisabled) return;

        auto& state = g_patch08B4D4MutationGenerationByPath[path];
        if (state.disabled) return;

        if (state.value == std::numeric_limits<uint64_t>::max()) {
            state.disabled = true;
            return;
        }

        ++state.value;
    } catch (...) {
        // Never turn an already-committed DB mutation into an apparent failure
        // because cache-invalidation bookkeeping could not allocate.
        try {
            std::lock_guard<std::mutex> lock(
                g_patch08B4D4MutationGenerationMutex);
            g_patch08B4D4MutationGenerationGloballyDisabled = true;
        } catch (...) {
        }
    }
}

void patch08B4D4DisableMutationGeneration(
    const std::string& path) noexcept {
    try {
        std::lock_guard<std::mutex> lock(
            g_patch08B4D4MutationGenerationMutex);
        if (g_patch08B4D4MutationGenerationGloballyDisabled) return;
        g_patch08B4D4MutationGenerationByPath[path].disabled = true;
    } catch (...) {
        try {
            std::lock_guard<std::mutex> lock(
                g_patch08B4D4MutationGenerationMutex);
            g_patch08B4D4MutationGenerationGloballyDisabled = true;
        } catch (...) {
        }
    }
}

bool patch08B4D4ReadMutationGeneration(
    const std::string& path,
    uint64_t& valueOut) noexcept {
    valueOut = 0;
    try {
        std::lock_guard<std::mutex> lock(
            g_patch08B4D4MutationGenerationMutex);

        if (g_patch08B4D4MutationGenerationGloballyDisabled) {
            return false;
        }

        const auto it = g_patch08B4D4MutationGenerationByPath.find(path);
        if (it == g_patch08B4D4MutationGenerationByPath.end()) {
            valueOut = 0;
            return true;
        }

        if (it->second.disabled) return false;
        valueOut = it->second.value;
        return true;
    } catch (...) {
        valueOut = 0;
        return false;
    }
}

void patch08B4D4EraseMutationGeneration(
    const std::string& path) noexcept {
    try {
        std::lock_guard<std::mutex> lock(
            g_patch08B4D4MutationGenerationMutex);
        g_patch08B4D4MutationGenerationByPath.erase(path);
    } catch (...) {
        // Hygiene only; cache/DB owner lifetime is ending.
    }
}
} // namespace


LevelDBStorage::LevelDBStorage(const std::string &dbPath)
    : db(nullptr), dbPath(dbPath) {
    Logger::log("[LevelDBStorage] Initializing database at path: " + dbPath);

    if (mkdir(dbPath.c_str(), 0777) == -1 && errno != EEXIST) {
        Logger::log("[LevelDBStorage] Failed to create directory: " + dbPath + ", errno: " + std::to_string(errno));
        throw std::runtime_error("[LevelDBStorage] Failed to create directory: " + dbPath);
    }

    // Fast path: reuse an already-open DB. No slow LevelDB operation occurs
    // while s_globalMtx is held.
    {
        std::unique_lock<std::shared_mutex> globalLock(s_globalMtx);
        auto it = s_dbInstances.find(dbPath);
        if (it != s_dbInstances.end()) {
            auto mutexIt = s_dbMutexes.find(dbPath);
            if (mutexIt == s_dbMutexes.end() || !mutexIt->second || !it->second.db) {
                Logger::log("[LevelDBStorage] FATAL: inconsistent DB/mutex registry for path: " + dbPath);
                throw std::runtime_error("[LevelDBStorage] inconsistent DB/mutex registry for path: " + dbPath);
            }
            db = it->second.db;
            ++it->second.refCount;
            Logger::log("[LevelDBStorage] Reusing existing instance for path: " + dbPath +
                        ", ref count: " + std::to_string(it->second.refCount));
            return;
        }
    }

    // serialize only slow open/close lifecycle work. The normal
    // DB registry lock remains available to unrelated live DB I/O while Open()
    // performs filesystem recovery/LOCK-file work.
    std::lock_guard<std::mutex> lifecycleLock(s_lifecycleMtx);

    // Another constructor may have won while we waited for lifecycleLock.
    {
        std::unique_lock<std::shared_mutex> globalLock(s_globalMtx);
        auto it = s_dbInstances.find(dbPath);
        if (it != s_dbInstances.end()) {
            auto mutexIt = s_dbMutexes.find(dbPath);
            if (mutexIt == s_dbMutexes.end() || !mutexIt->second || !it->second.db) {
                Logger::log("[LevelDBStorage] FATAL: inconsistent DB/mutex registry for path: " + dbPath);
                throw std::runtime_error("[LevelDBStorage] inconsistent DB/mutex registry for path: " + dbPath);
            }
            db = it->second.db;
            ++it->second.refCount;
            Logger::log("[LevelDBStorage] Reusing instance after lifecycle wait for path: " + dbPath +
                        ", ref count: " + std::to_string(it->second.refCount));
            return;
        }
    }

    leveldb::DB* newDb = nullptr;
    leveldb::Cache* newCache = leveldb::NewLRUCache(100ULL * 1048576ULL);
    leveldb::Options options;
    options.create_if_missing = true;
    options.compression = leveldb::kSnappyCompression;
    options.block_cache = newCache;

    // Intentionally outside s_globalMtx. s_lifecycleMtx prevents a same-process
    // competing open/close from racing the LevelDB LOCK file.
    const leveldb::Status status = leveldb::DB::Open(options, dbPath, &newDb);
    if (!status.ok()) {
        delete newCache;
        Logger::log("[LevelDBStorage] Failed to open database: " + status.ToString());
        throw std::runtime_error("[LevelDBStorage] Unable to open/create database: " + status.ToString());
    }

    {
        std::unique_lock<std::shared_mutex> globalLock(s_globalMtx);
        auto newMutex = std::make_shared<std::mutex>();
        const auto insertedDb = s_dbInstances.emplace(
            dbPath, SharedDbEntry{newDb, 1, newCache});
        const auto insertedMutex = s_dbMutexes.emplace(dbPath, std::move(newMutex));
        if (!insertedDb.second || !insertedMutex.second) {
            // With lifecycleLock held this should be impossible. Fail loudly and
            // clean the just-opened resources rather than corrupting refcounts.
            if (insertedDb.second) s_dbInstances.erase(insertedDb.first);
            if (insertedMutex.second) s_dbMutexes.erase(insertedMutex.first);
            globalLock.unlock();
            delete newDb;
            delete newCache;
            Logger::log("[LevelDBStorage] FATAL: registry insertion race for path: " + dbPath);
            throw std::runtime_error("[LevelDBStorage] registry insertion race for path: " + dbPath);
        }
        db = newDb;
    }

    Logger::log("[LevelDBStorage] Created new database instance for path: " + dbPath +
                " with Snappy compression and 100MB cache");
}

LevelDBStorage::~LevelDBStorage() {
    leveldb::DB* dbToDelete = nullptr;
    leveldb::Cache* cacheToDelete = nullptr;
    int remaining = -1;

    // Coordinate reopen-vs-close without holding s_globalMtx across LevelDB's
    // potentially slow destructor/flush/background-thread join.
    std::lock_guard<std::mutex> lifecycleLock(s_lifecycleMtx);
    {
        std::unique_lock<std::shared_mutex> globalLock(s_globalMtx);
        auto it = s_dbInstances.find(dbPath);
        if (it == s_dbInstances.end()) return;

        remaining = --it->second.refCount;
        if (remaining < 0) {
            Logger::log("[LevelDBStorage] FATAL: negative DB refcount for path: " + dbPath);
            return;
        }

        if (remaining == 0) {
            dbToDelete = it->second.db;
            cacheToDelete = it->second.blockCache;
            s_dbInstances.erase(it);
            s_dbMutexes.erase(dbPath);
        }
    }

    if (remaining == 0) {
        patch08B4D4EraseMutationGeneration(dbPath);
        delete dbToDelete;
        delete cacheToDelete;
        Logger::log("[LevelDBStorage] Closed DB and released block cache for path: " + dbPath);
    } else if (remaining > 0) {
        Logger::log("[LevelDBStorage] Decreased ref count for path: " + dbPath +
                    ", remaining: " + std::to_string(remaining));
    }
}

std::shared_ptr<std::mutex> LevelDBStorage::getDbMutexHandle() const {
    std::shared_lock<std::shared_mutex> globalLock(s_globalMtx);
    auto it = s_dbMutexes.find(dbPath);
    if (it == s_dbMutexes.end() || !it->second) {
        Logger::log(
            "[LevelDBStorage] ERROR: mutex handle not found for dbPath: " +
            dbPath);
        return {};
    }
    return it->second;
}

bool LevelDBStorage::get(const std::string &key, std::string &value) const {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return false;
    std::lock_guard<std::mutex> lock(*dbMutex);
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (status.ok()) {
        size_t delimPos = value.find('|');
        if (delimPos == std::string::npos) {
            Logger::log("[LevelDBStorage] Get key " + key + " failed: no checksum found in value");
            return false;
        }
        std::string storedChecksum = value.substr(0, delimPos);
        std::string data = value.substr(delimPos + 1);
        std::string computedChecksum = computeDataChecksum(data);
        if (storedChecksum != computedChecksum) {
            std::string dataSnippet = data.substr(0, 20) + (data.size() > 20 ? "..." : "");
            Logger::log("[LevelDBStorage] Get key " + key + " failed: checksum mismatch, stored=" + storedChecksum + ", computed=" + computedChecksum + ", data snippet: " + dataSnippet);
            return false;
        }
        value = data;
        Logger::log("[LevelDBStorage] Get key " + key + " succeeded, value: " + value);
    } else if (!status.IsNotFound()) {
        Logger::log("[LevelDBStorage] Get key " + key + " failed: " + status.ToString());
    }
    return status.ok();
}

bool LevelDBStorage::getRaw(
    const std::string &key,
    std::string &rawValue,
    bool &found) const {

    found = false;
    rawValue.clear();

    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log(
            "[LevelDBStorage::getRaw] ERROR: mutex not found for dbPath: " +
            dbPath);
        return false;
    }

    std::lock_guard<std::mutex> lock(*dbMutex);
    const leveldb::Status status =
        db->Get(leveldb::ReadOptions(), key, &rawValue);

    if (status.ok()) {
        found = true;
        return true;
    }

    if (status.IsNotFound()) {
        rawValue.clear();
        return true;
    }

    Logger::log(
        "[LevelDBStorage::getRaw] ERROR reading key " + key +
        ": " + status.ToString());
    rawValue.clear();
    return false;
}

bool LevelDBStorage::copyRawSnapshotTo(
    LevelDBStorage& destination,
    bool skipBlockRecords,
    const std::unordered_set<std::string>* retainedUndoKeys) const {

    if (destination.dbPath == dbPath) {
        Logger::log(
            "[LevelDBStorage::copyRawSnapshotTo] ERROR: source and destination paths are identical");
        return false;
    }

    const auto sourceMutex = getDbMutexHandle();
    if (!sourceMutex) {
        Logger::log(
            "[LevelDBStorage::copyRawSnapshotTo] ERROR: source mutex missing for " +
            dbPath);
        return false;
    }

    const leveldb::Snapshot* snapshot = nullptr;
    {
        std::lock_guard<std::mutex> sourceLock(*sourceMutex);
        snapshot = db->GetSnapshot();
    }

    if (!snapshot) {
        Logger::log(
            "[LevelDBStorage::copyRawSnapshotTo] ERROR: LevelDB returned null snapshot");
        return false;
    }

    auto releaseSnapshot = [&]() {
        std::lock_guard<std::mutex> sourceLock(*sourceMutex);
        db->ReleaseSnapshot(snapshot);
    };

    bool ok = true;
    size_t copiedKeys = 0;
    size_t copiedBytes = 0;

    try {
        leveldb::ReadOptions readOptions;
        readOptions.snapshot = snapshot;
        readOptions.fill_cache = false;

        std::unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));
        leveldb::WriteBatch batch;
        size_t batchKeys = 0;
        size_t batchBytes = 0;
        static constexpr size_t SNAPSHOT_BATCH_KEYS = 1024;
        static constexpr size_t SNAPSHOT_BATCH_BYTES = 8ULL * 1024ULL * 1024ULL;

        auto flushBatch = [&]() -> bool {
            if (batchKeys == 0) return true;
            if (!destination.putBatch(batch, false)) return false;
            batch.Clear();
            batchKeys = 0;
            batchBytes = 0;
            return true;
        };

        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            const std::string key = it->key().ToString();
            if (skipBlockRecords && key.rfind("block:", 0) == 0) {
                continue;
            }
            // historical undo journals dominate sandbox copy
            // cost but only the active suffix being rewound is required. Keep
            // exactly that allow-list when one is supplied; candidate blocks
            // create their own temporary journals as they are applied.
            if (retainedUndoKeys &&
                key.rfind("undo:block:", 0) == 0 &&
                retainedUndoKeys->count(key) == 0) {
                continue;
            }

            const std::string value = it->value().ToString();
            if (copiedBytes > std::numeric_limits<size_t>::max() - key.size() - value.size()) {
                throw std::overflow_error("candidate snapshot byte counter overflow");
            }

            batch.Put(key, value);
            ++batchKeys;
            ++copiedKeys;
            batchBytes += key.size() + value.size();
            copiedBytes += key.size() + value.size();

            if (batchKeys >= SNAPSHOT_BATCH_KEYS ||
                batchBytes >= SNAPSHOT_BATCH_BYTES) {
                if (!flushBatch()) {
                    ok = false;
                    break;
                }
            }
        }

        if (ok && !it->status().ok()) {
            Logger::log(
                "[LevelDBStorage::copyRawSnapshotTo] ERROR: source snapshot iteration failed: " +
                it->status().ToString());
            ok = false;
        }

        if (ok && !flushBatch()) ok = false;
    } catch (const std::exception& e) {
        Logger::log(
            "[LevelDBStorage::copyRawSnapshotTo] ERROR: " + std::string(e.what()));
        ok = false;
    } catch (...) {
        Logger::log(
            "[LevelDBStorage::copyRawSnapshotTo] ERROR: unknown snapshot-copy failure");
        ok = false;
    }

    releaseSnapshot();

    if (ok) {
        Logger::log(
            "[Patch08B.3] Candidate validation snapshot copied keys=" +
            std::to_string(copiedKeys) +
            " rawBytes=" + std::to_string(copiedBytes) +
            (skipBlockRecords ? " (block: records omitted)" : "") +
            (retainedUndoKeys ? " (undo journals filtered to required active suffix)" : ""));
    }
    return ok;
}

bool LevelDBStorage::put(const std::string &key, const std::string &value) {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[LevelDBStorage] ERROR: missing mutex for put: " + dbPath);
        return false;
    }
    std::lock_guard<std::mutex> lock(*dbMutex);
    std::string checksum = computeChecksum(value);
    std::string toStore = checksum + "|" + value;
    Logger::log("[LevelDBStorage] Put key " + key + ", value: " + value + ", checksum: " + checksum);
    leveldb::WriteOptions options;
    options.sync = true;
    leveldb::Status status = db->Put(options, key, toStore);
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] Put key " + key + " failed: " + status.ToString());
        throw std::runtime_error("[LevelDBStorage] Failed to put key: " + key + ", error: " + status.ToString());
    }
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
    return true;
}

bool LevelDBStorage::del(const std::string &key) {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[LevelDBStorage] ERROR: missing mutex for del: " + dbPath);
        return false;
    }
    std::lock_guard<std::mutex> lock(*dbMutex);
    Logger::log("[LevelDBStorage] Deleting key: " + key);
    leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
    if (!status.ok() && !status.IsNotFound()) {
        Logger::log("[LevelDBStorage] Delete key " + key + " failed: " + status.ToString());
        throw std::runtime_error("[LevelDBStorage] Failed to delete key: " + key + ", error: " + status.ToString());
    }
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
    return true;
}

bool LevelDBStorage::exists(const std::string &key) const {
    std::string temp;
    return get(key, temp);
}

void LevelDBStorage::iterateAll(std::function<void(const std::string &, const std::string &)> callback) const {
    std::vector<std::pair<std::string, std::string>> entries;
    {
        auto dbMutex = getDbMutexHandle();
        if (!dbMutex) return;
        std::lock_guard<std::mutex> lock(*dbMutex);
        Logger::log("[LevelDBStorage] Starting iteration over database");
        leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string key = it->key().ToString();
            std::string value = it->value().ToString();
            entries.push_back({key, value});
        }
        if (!it->status().ok()) {
            Logger::log("[LevelDBStorage] Iteration error: " + it->status().ToString());
            delete it;
            throw std::runtime_error("[LevelDBStorage] Iteration error");
        }
        delete it;
    }
    for (const auto& entry : entries) {
        try {
            callback(entry.first, entry.second);
        } catch (const std::exception& e) {
            Logger::log("[LevelDBStorage] Callback error for key " + entry.first + ": " + e.what());
        }
    }
    Logger::log("[LevelDBStorage] Iteration and callback execution completed");
}

void LevelDBStorage::clear() {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[LevelDBStorage] ERROR: missing mutex for clear: " + dbPath);
        return;
    }
    std::lock_guard<std::mutex> lock(*dbMutex);
    leveldb::WriteBatch batch;
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        batch.Delete(it->key());
    }
    if (!it->status().ok()) {
        Logger::log("[LevelDBStorage] Iteration error during clear: " + it->status().ToString());
        const std::string error = it->status().ToString();
        delete it;
        throw std::runtime_error("[LevelDBStorage] Iteration error during clear(): " + error);
    }
    delete it;
    leveldb::Status status = db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] Clear failed: " + status.ToString());
        throw std::runtime_error("[LevelDBStorage] clear() failed: " + status.ToString());
    }
    Logger::log("[LevelDBStorage] Database cleared");
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
}

void LevelDBStorage::compact() {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[LevelDBStorage] ERROR: missing mutex for compact: " + dbPath);
        return;
    }
    std::lock_guard<std::mutex> lock(*dbMutex);
    db->CompactRange(nullptr, nullptr);
    Logger::log("[LevelDBStorage] Database compacted");
}

size_t LevelDBStorage::countKeys() const {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[LevelDBStorage] ERROR: missing mutex for countKeys: " + dbPath);
        return 0;
    }
    std::lock_guard<std::mutex> lock(*dbMutex);
    size_t count = 0;
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        ++count;
    }
    if (!it->status().ok()) {
        Logger::log("[LevelDBStorage] Iteration error in countKeys: " + it->status().ToString());
        delete it;
        throw std::runtime_error("[LevelDBStorage] Iteration error in countKeys(): " + it->status().ToString());
    }
    delete it;
    Logger::log("[LevelDBStorage] Counted " + std::to_string(count) + " keys");
    return count;
}

bool LevelDBStorage::repairDatabase() {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return false;
    // repair can rewrite logical state outside
    // ordinary mutation primitives; disable candidate-cache
    // generation for this path before repair proceeds.
    patch08B4D4DisableMutationGeneration(dbPath);
    std::lock_guard<std::mutex> lock(*dbMutex);
    Logger::log("[LevelDBStorage] Attempting to repair database at path: " + dbPath);
    leveldb::Status status = leveldb::RepairDB(dbPath, leveldb::Options());
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] Repair failed: " + status.ToString());
        return false;
    }
    Logger::log("[LevelDBStorage] Database repair completed successfully");
    return true;
}

std::string LevelDBStorage::computeChecksum(const std::string &data) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

void LevelDBStorage::iteratePrefix(const std::string &prefix, std::function<void(const std::string &, const std::string &)> callback) const {
    // snapshot matching entries while holding the lifetime-safe
    // per-DB mutex, then release it before invoking callbacks. This prevents
    // registry erase/rehash races without deadlocking callbacks that read DB state.
    std::vector<std::pair<std::string, std::string>> entries;
    {
        auto dbMutex = getDbMutexHandle();
        if (!dbMutex) return;
        std::lock_guard<std::mutex> lock(*dbMutex);

        leveldb::ReadOptions opts;
        opts.fill_cache = false;
        std::unique_ptr<leveldb::Iterator> it(db->NewIterator(opts));
        for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix); it->Next()) {
            auto slice = it->key();
            std::string fullKey(slice.data(), slice.size());
            std::string keySansPrefix = fullKey.substr(prefix.size());
            std::string raw = it->value().ToString();
            auto delim = raw.find('|');
            std::string actualValue = (delim == std::string::npos ? raw : raw.substr(delim + 1));
            entries.emplace_back(std::move(keySansPrefix), std::move(actualValue));
        }
        if (!it->status().ok()) {
            Logger::log("[LevelDBStorage] iteratePrefix error: " + it->status().ToString());
            return;
        }
    }

    for (const auto& entry : entries) {
        try {
            callback(entry.first, entry.second);
        } catch (const std::exception &e) {
            Logger::log("[LevelDBStorage] iteratePrefix callback threw: " + std::string(e.what()));
        }
    }
}

bool LevelDBStorage::getMutationGeneration(
    uint64_t& generationOut) const {

    generationOut = 0;
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log(
            "[Patch08B.4D.4] mutation-generation read failed: DB mutex missing path=" +
            dbPath);
        return false;
    }

    // Serialize generation observation with all same-path LevelDB writes.
    std::lock_guard<std::mutex> lock(*dbMutex);

    if (!patch08B4D4ReadMutationGeneration(dbPath, generationOut)) {
        Logger::log(
            "[Patch08B.4D.4] mutation-generation unavailable/disabled path=" +
            dbPath);
        generationOut = 0;
        return false;
    }

    return true;
}


bool LevelDBStorage::putBatch(leveldb::WriteBatch& batch, bool sync) {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return false;
    std::lock_guard<std::mutex> lock(*dbMutex);
    leveldb::WriteOptions options;
    options.sync = sync;
    leveldb::Status status = db->Write(options, &batch);
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] Batch write failed: " + status.ToString());
        return false;
    }
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
    return true;
}

std::string LevelDBStorage::computeDataChecksum(const std::string &data) const {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash1);
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hash2[i]);
    }
    return oss.str();
}

bool LevelDBStorage::putWithDataChecksum(const std::string &key, const std::string &value) {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return false;
    std::lock_guard<std::mutex> lock(*dbMutex);
    std::string checksum = computeDataChecksum(value);
    std::string toStore = checksum + "|" + value;
    Logger::log("[LevelDBStorage] PutWithDataChecksum key=" + key + ", checksum=" + checksum + ", value=" + value);
    leveldb::WriteOptions opts;
    opts.sync = true;
    auto status = db->Put(opts, key, toStore);
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] PutWithDataChecksum failed: " + status.ToString());
        return false;
    }
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
    return true;
}

bool LevelDBStorage::getWithDataChecksum(const std::string &key, std::string &outValue) const {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) {
        Logger::log("[getWithDataChecksum] ERROR: Mutex not found for dbPath: " + dbPath);
        return false;
    }

    std::lock_guard<std::mutex> lock(*dbMutex);

    // Perform the database read operation
    std::string payload;
    leveldb::ReadOptions opts;
    auto status = db->Get(opts, key, &payload);
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] GetWithDataChecksum key " + key + " failed: " + status.ToString());
        return false;
    }

    // Parse the payload to extract stored checksum and data
    auto delim = payload.find('|');
    if (delim == std::string::npos) {
        Logger::log("[LevelDBStorage] GetWithDataChecksum malformed payload for key " + key);
        return false;
    }
    std::string storedCS = payload.substr(0, delim);
    std::string data = payload.substr(delim + 1);

    // Compute the checksum of the retrieved data and verify it
    std::string computed = computeDataChecksum(data);
    if (storedCS != computed) {
        std::string dataSnippet = data.substr(0, 20) + (data.size() > 20 ? "..." : "");
        Logger::log("[LevelDBStorage] GetWithDataChecksum checksum mismatch for key " + key +
                    ", stored=" + storedCS + ", computed=" + computed + ", data snippet: " + dataSnippet);
        return false;
    }

    // Assign the verified data to the output parameter
    outValue = data;
    return true;
}


void LevelDBStorage::verifyAllKeys() const {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return;
    std::lock_guard<std::mutex> lock(*dbMutex);
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        std::string value = it->value().ToString();
        size_t delimPos = value.find('|');
        if (delimPos == std::string::npos) {
            Logger::log("[LevelDBStorage] Verification failed for key " + key + ": no checksum found");
            continue;
        }
        std::string storedChecksum = value.substr(0, delimPos);
        std::string data = value.substr(delimPos + 1);
        std::string computedChecksum = computeDataChecksum(data);
        if (storedChecksum != computedChecksum) {
            std::string dataSnippet = data.substr(0, 20) + (data.size() > 20 ? "..." : "");
            Logger::log("[LevelDBStorage] Verification failed for key " + key + ": checksum mismatch, stored=" + storedChecksum + ", computed=" + computedChecksum + ", data snippet: " + dataSnippet);
        }
    }
    if (!it->status().ok()) {
        Logger::log("[LevelDBStorage] Iteration error during verification: " + it->status().ToString());
    }
    delete it;
}

bool LevelDBStorage::putContract(const std::string &key, const std::string &value) {
    auto dbMutex = getDbMutexHandle();
    if (!dbMutex) return false;
    std::lock_guard<std::mutex> lock(*dbMutex);
    
    // Always use double SHA256 for contracts
    std::string checksum = computeDataChecksum(value);
    std::string toStore = checksum + "|" + value;
    
    // Ensure key starts with "contract:"
    std::string fullKey = key;
    if (key.substr(0, 9) != "contract:") {
        fullKey = "contract:" + key;
    }
    
    Logger::log("[LevelDBStorage] PutContract key=" + fullKey + ", checksum=" + checksum);
    
    leveldb::WriteOptions options;
    options.sync = true;
    leveldb::Status status = db->Put(options, fullKey, toStore);
    
    if (!status.ok()) {
        Logger::log("[LevelDBStorage] PutContract failed: " + status.ToString());
        return false;
    }
    // successful logical DB mutation.
    patch08B4D4BumpMutationGeneration(dbPath);
    return true;
}

bool LevelDBStorage::getContract(const std::string &key, std::string &outValue) const {
    bool migrateOldChecksum = false;
    std::string data;

    {
        auto dbMutex = getDbMutexHandle();
        if (!dbMutex) {
            Logger::log("[getContract] ERROR: Mutex not found for dbPath: " + dbPath);
            return false;
        }
        std::lock_guard<std::mutex> lock(*dbMutex);

        std::string fullKey = key;
        if (key.substr(0, 9) != "contract:") {
            fullKey = "contract:" + key;
        }

        std::string payload;
        leveldb::ReadOptions opts;
        auto status = db->Get(opts, fullKey, &payload);
        if (!status.ok()) {
            Logger::log("[LevelDBStorage] GetContract key " + fullKey + " failed: " + status.ToString());
            return false;
        }

        auto delim = payload.find('|');
        if (delim == std::string::npos) {
            Logger::log("[LevelDBStorage] GetContract malformed payload for key " + fullKey);
            return false;
        }

        std::string storedCS = payload.substr(0, delim);
        data = payload.substr(delim + 1);
        std::string computed = computeDataChecksum(data);

        // VAH-02C.1 / VAH-03B / VAH-03D / VAH-04B: new VAH integrity namespaces have no legitimate
        // legacy single-SHA256 contract records. A canonical double-SHA256
        // mismatch is corruption and must never be accepted or upgraded-on-read.
        const bool strictVahReconciliationChecksum =
            fullKey.rfind("contract:TOKEN:VAH_RECON:", 0) == 0;
        const bool strictVahPendingChecksum =
            fullKey.rfind("contract:TOKEN:VAH_PENDING:", 0) == 0;
        const bool strictVahMaterializedChecksum =
            fullKey.rfind("contract:TOKEN:VAH_MATERIALIZED:", 0) == 0;
        const bool strictVahSensorBatchChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_BATCH:", 0) == 0;
        const bool strictVahSensorHeadChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_HEAD:", 0) == 0;
        const bool strictVahSensorAnchorPreparedChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_ANCHOR_PREPARED:", 0) == 0;
        const bool strictVahSensorAnchorWatchChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_ANCHOR_WATCH:", 0) == 0;
        const bool strictVahAuthorizationChecksum =
            fullKey.rfind("contract:TOKEN:VAH_AUTH:", 0) == 0;
        const bool strictVahSensorConfirmedChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_CONFIRMED:", 0) == 0;
        const bool strictVahSensorRecoveryChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_RECOVERY:", 0) == 0;
        const bool strictVahSensorCheckpointChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_CHECKPOINT:", 0) == 0;
        const bool strictVahSensorEventChecksum =
            fullKey.rfind("contract:TOKEN:VAH_SENSOR_EVENT:", 0) == 0;

        if (storedCS != computed) {
            if (strictVahReconciliationChecksum) {
                Logger::log(
                    "[LevelDBStorage] GetContract strict VAH reconciliation checksum mismatch for key " +
                    fullKey);
                return false;
            }
            if (strictVahPendingChecksum) {
                Logger::log(
                    "[LevelDBStorage] GetContract strict VAH pending checksum mismatch for key " +
                    fullKey);
                return false;
            }
            if (strictVahMaterializedChecksum) {
                Logger::log(
                    "[LevelDBStorage] GetContract strict VAH materialized checksum mismatch for key " +
                    fullKey);
                return false;
            }
            if (strictVahSensorBatchChecksum) {
                Logger::log(
                    "[LevelDBStorage] GetContract strict VAH sensor batch checksum mismatch for key " +
                    fullKey);
                return false;
            }
            if (strictVahSensorHeadChecksum) {
                Logger::log(
                    "[LevelDBStorage] GetContract strict VAH sensor head checksum mismatch for key " +
                    fullKey);
                return false;
            }
            if (strictVahSensorAnchorPreparedChecksum) {
                Logger::log("[LevelDBStorage] GetContract strict VAH sensor anchor prepared checksum mismatch for key " + fullKey);
                return false;
            }
            if (strictVahSensorAnchorWatchChecksum) {
                Logger::log("[LevelDBStorage] GetContract strict VAH sensor anchor watch checksum mismatch for key " + fullKey);
                return false;
            }
            if (strictVahAuthorizationChecksum) {
                Logger::log("[LevelDBStorage] GetContract strict VAH authorization checksum mismatch for key " + fullKey);
                return false;
            }
            if (strictVahSensorConfirmedChecksum) { Logger::log("[LevelDBStorage] GetContract strict VAH sensor confirmed checksum mismatch for key " + fullKey); return false; }
            if (strictVahSensorRecoveryChecksum) { Logger::log("[LevelDBStorage] GetContract strict VAH sensor recovery checksum mismatch for key " + fullKey); return false; }
            if (strictVahSensorCheckpointChecksum) { Logger::log("[LevelDBStorage] GetContract strict VAH sensor checkpoint checksum mismatch for key " + fullKey); return false; }
            if (strictVahSensorEventChecksum) { Logger::log("[LevelDBStorage] GetContract strict VAH sensor event checksum mismatch for key " + fullKey); return false; }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                oss << std::setw(2) << static_cast<int>(hash[i]);
            }
            if (storedCS != oss.str()) {
                Logger::log("[LevelDBStorage] GetContract checksum mismatch for key " + fullKey);
                return false;
            }

            Logger::log("[LevelDBStorage] GetContract detected old checksum format, accepting for key " + fullKey);
            migrateOldChecksum = true;
        }

        outValue = data;
    }

    // migrate only after releasing the per-DB mutex; putContract()
    // acquires the same mutex and the previous inline migration self-deadlocked.
    if (migrateOldChecksum) {
        if (!const_cast<LevelDBStorage*>(this)->putContract(key, data)) {
            Logger::log("[LevelDBStorage] WARNING: failed to migrate old contract checksum for key " + key);
        }
    }

    return true;
}

