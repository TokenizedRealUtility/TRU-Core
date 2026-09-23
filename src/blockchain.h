#pragma once
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <string>
#include "tx_relay_queue_v1.h"
#include <chrono>
#include <unordered_map>
#include <unordered_set>  // queued-tx deduplication
#include <shared_mutex>  
#include <vector>
#include <cstdint>
#include <memory>
#include <queue>
#include "globals.h"   // FIX: shared COINBASE_MATURITY (single source of truth)
#include "utxo.h"
#include "block.h"
#include "leveldb_storage.h"
#include "mempool.h"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <map>
#include "tokens.h"
#include "message.pb.h"
#include "p2p.h"
#include <atomic>
#include <optional>
#include <condition_variable>
#include <future>
#include <functional>  // fail-stop shutdown bridge
#include <boost/multiprecision/cpp_int.hpp>  // 256-bit chainwork

class P2PNode;
class Transaction;
class Mempool;
class Wallet;
struct AddressStats {
    double balance;
    int    txCount;
    std::vector<std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData>> tokenUtxos;
};

struct TokenData {
    std::string tokenID;
    TokenType type;
    uint64_t amount;
    uint32_t version;
    std::set<std::string> owners;
    TokenMeta meta;
    std::string metaHash;
    std::string offChainMetadata;
    std::string metadataSignature;
};

struct OrdinalData {
    uint64_t inscriptionIndex;
    uint64_t satNumber;
    uint64_t timestamp;
    size_t   sizeBytes;
};

inline void to_json(nlohmann::json& j, const TokenData& d) {
    j["tokenID"] = d.tokenID;
    j["type"] = tokenTypeToString(d.type);
    j["amount"] = d.amount;
    j["version"] = d.version;
    j["owners"] = d.owners;
    j["meta"] = d.meta;
    j["metaHash"] = d.metaHash;
    j["offChainMetadata"] = d.offChainMetadata;
    j["metadataSignature"] = d.metadataSignature;
}

using ChainWork256 = boost::multiprecision::uint256_t;

struct BlockIndexEntry {
    Block block;
    ChainWork256 chainWork;
    std::string parentHash;
    int height;
    bool isDirty;
    BlockIndexEntry() : chainWork(0), parentHash(""), height(0), isDirty(false) {}
    explicit BlockIndexEntry(const Block& b) : block(b), chainWork(0), parentHash(b.header.prevHash), height(b.height), isDirty(true) {}
};


// TRU REORG-TX-01:
// Atomic read-side classification of a known transaction relative to the
// CURRENT active chain. Historical interpretation belongs to durable consumers.
struct KnownTransactionStatus {
    bool found{false};
    std::string location{"NOT_FOUND"}; // ACTIVE | MEMPOOL | SIDECHAIN | NOT_FOUND
    Transaction transaction;
    int blockHeight{-1};
    std::string blockHash;
    uint64_t blockTime{0};
    int tipHeight{-1};
    bool conflicted{false};
    std::string conflictingTxid;
};

class Blockchain {
public:
    //explicit Blockchain(const std::string& utxoDBPath, P2PNode& p2pNode);
    Blockchain(const std::string& utxoDB, P2PNode& p2pNode);
    Blockchain(const std::string& utxoDBPath, const std::string& genesisAddress, P2PNode& p2pNode);
    Blockchain(const std::string& utxoDBPath, const std::string& genesisAddress, P2PNode& p2pNode, bool noSeeds);
    ~Blockchain();

    Block mineBlockCPU(P2PNode* p2pNode, const std::string& minerAddress);
    bool mineBlock(Block& block, uint64_t& foundNonce, std::vector<unsigned char>& finalHash, uint64_t maxNonce = UINT64_MAX);
    std::string mineBlockGPUChain(P2PNode* p2pNode, const std::string& minerAddress);
    bool addTransaction(const Transaction& tx);  // bounded ingress queue

    void removeMempoolTransaction(const std::string& txid);
    std::vector<Transaction> getMempoolTransactions() const;
    //double calculate_balance(const std::string& address) const;
    uint64_t calculate_balance(const std::string& address) const;
    bool isChainValid() const;
    int getChainSize() const;
    Block getBlock(const std::string& blockHash) const;
    std::string getBlockHashByHeight(int height) const;
    std::optional<Block> getBlockByHeight(uint64_t height) const;
    //Block getBlockByHeight(int height) const;
    std::string getLatestCoinbaseTxid() const;

    int getBestTipHeight() const;
    std::string getBestTipHash() const;
    void getBestTipSnapshot(std::string& hashOut, int& heightOut) const;
    uint32_t getDifficulty() const;
    uint64_t getBlockReward() const;

    bool loadChainState();
    // optional marker is published atomically with active-tip
    // metadata. Normal callers use nullptr.
    void saveChainState(const std::string* reorgTipPublishMarkerPayload = nullptr);
    void reloadBlocks();
    void saveAllBlocks();
    void saveAllBlocksSync();
    void initGenesisBlock(const std::string& genesisAddress);

    bool broadcastBlockToStandaloneNode(const Block& blk);

    bool compare256LE(const unsigned char hashVal[32], const unsigned char targetVal[32]) const;
    bool hexToBytes32LE(const std::string& hexStr, unsigned char out32[32]) const;
    std::string doubleSha256(const std::string& data) const;
    std::string computeMerkleRoot(const std::vector<Transaction>& transactions) const;

    bool isZKProof;
    UTXOSet utxoSet;
    std::unique_ptr<Mempool> mempool;

    bool mineBlockMultiThreaded(Block& block, uint64_t maxNonce);
    std::vector<unsigned char> buildHeaderBytes(const BlockHeader& hdr);
    uint64_t bitsToTarget(uint32_t bits) const;

    Mempool& getMempool();
    const Mempool& getMempool() const;

    size_t getTotalTransactions() const;
    
    std::unordered_set<std::string> getActiveAddresses() const;
    size_t getIssuedTokens() const;
    bool findTransaction(const std::string& txid, Transaction& tx) const;
    // TRU REORG-TX-01: current chain-location snapshot; no mutation.
    bool getKnownTransactionStatus(
        const std::string& txid,
        KnownTransactionStatus& status) const;
    void startExplorerServer(int port, int rpcPort);
    std::unordered_map<std::string, std::vector<unsigned char>> getContractState(const std::string& address) const;
    
    bool isSmartContractScript(const std::string& script) const;
    std::vector<unsigned char> getState(const std::string& address, const std::string& keyHex) const;

    std::unordered_map<std::string, std::unordered_map<std::string, std::vector<unsigned char>>> contractStates;

    void registerMiner(const std::string& minerAddress);
    void unregisterMiner(const std::string& minerAddress);
    std::unordered_map<std::string, double> minerHashRates;
    std::unordered_set<std::string> getActiveMiners() const;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> minerLastActivity;
    void updateMinerActivity(const std::string& minerAddress, uint64_t hashesTried, double timeTaken);
    std::string extractAddressFromCoinbase(const Transaction& coinbase) const;
    std::unordered_map<std::string, uint64_t> minerBlockCount;
    // EXPLORER-LOCK-02: synchronized access to the derived block counter.
    uint64_t getMinerBlockCount(const std::string& minerAddress) const;
    void clearMinerBlockCounts();
    friend class BlockExplorer;
    bool findBlockContainingTx(const std::string& txid, std::string& blockHash) const;

    nlohmann::json contractCache;          
    std::mutex contractCacheMutex;         
    bool contractCacheValid = false;
    void storeTokenMetadata(const std::string& txid, const ExtendedTokenData& tokenData);
    //void storeTokenMetadata(const std::string& txid, const std::unordered_map<std::string, std::string>& metadata);

    nlohmann::json getContracts() const;
    uint64_t getTotalIssuedTrus() const;
    double getNetworkHashrate(int numBlocks = 10) const;
    std::map<uint32_t, double> hashrateHistory;
    std::map<int, uint32_t> difficultyHistory;

    LevelDBStorage* getStorage() { return &dbStorage; }

    const LevelDBStorage* getStorage() const { return &dbStorage; }

    bool verifyBlockDifficulty(const Block& blk) const;
    std::shared_mutex utxoCacheMutex;
    std::unordered_map<std::string, UTXO> utxoCache; // Adjust type as needed
    int cacheHeight;
    void registerWallet(Wallet* w) { walletPtr = w; }
    Wallet* getWallet() const { return walletPtr; }

    int getHeightByHash(const std::string& hash) const;

    std::vector<std::string> getTransactionsForAddress(const std::string& address) const;

    std::vector<TokenData> getAllTokens() const;
    ExtendedTokenData fetchTokenMetadata(const std::string& key) const;
    bool isValidAddress(const std::string& addr) const;

   uint32_t getCurrentBlockTime() const;
   uint64_t calculateSubsidy(int height) const;
   OrdinalData getOrdinalData(const std::string& txid);
   uint64_t getBlockchainSize() const;
   uint64_t getBlockSize(const std::string& blockHash) const;
   void syncWithPeers(
       P2PNode& node,
       std::atomic<bool>& running,
       std::mutex* coutMutex,
       const std::function<void(const std::string&)>& statusCallback = {});
   bool validateBlock(const Block& block);
   // Local mining assembly only; does not connect, accept, or persist a block.
   bool checkMiningTemplate(const Block& block);

   std::string blockHash;
   bool validateTokenOutput(const ExtendedTokenData& tokenData, const std::string& owner) const;
   std::string calculateExpectedBits(const std::string& parentHash, int candidateHeight) const;
   std::vector<unsigned char> computeSighash(const Transaction& tx, size_t inputIndex, const std::vector<unsigned char>& scriptPubKey) const;
   void stop();
   Block getBlock(const std::string& hash);
   void rebuildChainState(); // Rebuild the chain state
   void validateChain();     // Validate the entire chain
   bool validateSocialPost(const std::string& opReturnData, const Transaction& tx, int blockHeight);

    std::unordered_map<std::string, std::string> didToAddressMap;
    void storeDIDMapping(const std::string& did, const std::string& address);
    // DID-01: atomic, immutable registration for signed public-web DID claims.
    // Returns false only on durable storage failure. `conflict` is true when the
    // DID already exists for a different address; same-address replay is idempotent.
    bool registerDIDMappingImmutable(
        const std::string& did,
        const std::string& address,
        bool& created,
        bool& conflict,
        std::string& existingAddress);
    std::string resolveDIDToAddress(const std::string& did);
    void incrementTxCount(const std::string& address, leveldb::WriteBatch* batch = nullptr);
    void storeTxForAddress(const std::string& address, const std::string& txid, leveldb::WriteBatch* batch = nullptr);
    std::string extractAddressFromTxInput(const TxIn& vin) const;
    int getTxBlockHeight(const std::string& txid) const;
    bool broadcastTransaction(const Transaction& tx);
    void queueAcceptedTransactionRelay(const std::string& txid) noexcept;
    void saveChainStateForShutdown();
    void saveHeightMappings();
    std::vector<TRUScriptInfo> getTRUScriptsFromIndex(int page, int limit);
    int getTotalTRUScriptCount();
    std::optional<TRUScriptInfo> getTRUScriptById(const std::string& txid);
    void interruptibleSleep(std::chrono::seconds duration, const std::atomic<bool>& running);
    void broadcastHeight(P2PNode& node, uint64_t height);
    int getConnectedPeerCount() const ;

#ifdef TRU_08B3T_TEST_HOOKS
    // local 08B.3T test hooks are compile-time excluded by default.
    // Even development builds still require the runtime environment gates.
    bool debug08B3TTestHooksEnabled() const;
    bool debug08B3TMutationEnabled() const;
    std::string debug08B3TStatus() const;
    bool debug08B3TProbeTipUndoJournal(std::string& report);
    bool debug08B3TValidateCandidate(const std::string& candidateTipHash,
                                     int repeatCount,
                                     bool productionLikeLockBehavior,
                                     std::string& report);
    bool debug08B3TDisconnectReapplyTip(std::string& report);

    // development-only inspection of the production reorg
    // planning/preflight machinery. No command can activate a reorganization.
    std::string debug08B4AStatus() const;
    // DEV-only controlled side-pressure fixture.
    bool debug08B4D2TRunFixture(const std::string& mode,
                               std::string& report);
    // DEV-only bounded positive-cache FIFO fixture.
    // Process-local cache only; no durable state and no consensus mutation.
    bool debug08B4D4TPositiveCacheFifo(std::string& report);
    // DEV-only immutable negative-cache FIFO fixture.
    // Process-local cache only; no durable state and no consensus mutation.
    bool debug08B4D5TNegativeCacheFifo(std::string& report);
    bool debug08B4APreflightCandidate(const std::string& candidateTipHash,
                                      std::string& report);
    bool debug08B4APrepareCandidateForRestartTest(
        const std::string& candidateTipHash,
        std::string& report);
    // development-only MANUAL executor. It can run only
    // against an authenticated PREPARED 08B.4A plan and never activates
    // automatic network fork promotion.
    bool debug08B4BExecutePreparedCandidate(
        const std::string& candidateTipHash,
        std::string& report,
        bool& shutdownRequired);
#endif
    bool getTransaction(const std::string& txid, Transaction& tx) const;
    bool validateBlockBasic(const Block& block);
    bool isChainBetter(const std::vector<Block>& newChain, uint64_t newChainWork) const;
    bool submitBlock(const Block& block);
    bool submitBlockFromNetwork(const Block& block, const std::string& sourceKey);

    // production activation plumbing only. The gate is
    // OFF unless the exact environment magic is present, and 9A does not
    // connect this gate to side-branch prepare/execute.
    bool productionAutomaticReorgGateEnabled() const;
    void setReorgFailStopShutdownCallback(
        std::function<void(const std::string&)> callback);

    // startup-only reconciliation. Main calls this after the
    // 9A fail-stop bridge is installed and before any peer connection/listener.
    // Gate-OFF is a no-op. Gate-ARMED scans only the bounded persisted side set.
    bool reconcileWinningSideTipAtStartup(std::string& reasonOut);
    double calculateHashrateForRange(int startHeight, int endHeight) const;
    bool isMinerRegistered(const std::string& minerAddress) const;
    void processSpecialTransactionTypes(const Transaction& tx, const Block& blk, leveldb::WriteBatch& batch, std::unordered_map<std::string, nlohmann::json>& metadata);
    bool extractTokenMetadataFromTransaction(const Transaction& tx, nlohmann::json& metadata);
    void cleanupInactiveMiners();
    int getActiveMinersCount() const;
    void batchUpdateMinerActivity(const std::vector<std::tuple<std::string, uint64_t, double>>& updates);
    bool hasBlock(const std::string& blockHash) const {std::shared_lock<std::shared_mutex> lock(mtx); return blockIndex.count(blockHash) > 0;}
    void invalidateCachedBalance(const std::string& address);
    void invalidateAddressCache(const std::string& address);
    void invalidateUTXOCache();
    //static bool looksLikeTokenIssuerScript(const std::string& scriptHex);
    uint32_t getMedianTimePast(const std::string& parentHash, int candidateHeight) const;
private:
    // Patch 08B.3 internal constructor for an isolated validation sandbox.
    // It opens the supplied copied state database but does not load/init a
    // chain, start worker threads, contact peers, or persist on destruction.
    Blockchain(const std::string& utxoDBPath,
               const std::string& genesisAddress,
               P2PNode& p2pNode,
               bool noSeeds,
               bool validationOnly);

    // submitBlock() is the sole PUBLIC block
    // acceptance entry point. Confirmed-state mutators stay private.
    bool connectTipBlock(
        const Block& block,
        const std::string* reorgTipPublishMarkerPayload = nullptr,
        const std::string* promotedSideBlockHash = nullptr,
        bool recoveryPublishOnly = false);

    // TRU CORE-SAVE-01: caller MUST already own the unique chain mutex.
    // Publishes active-tip metadata/dirty blocks without dropping and racing to
    // reacquire mtx. Returns true only after the synchronous durable batch commits.
    bool saveChainStateWithLockHeld(
        const std::string* reorgTipPublishMarkerPayload = nullptr);

    // bounded side-chain/fork scaffolding.
    // Alternate branches may be indexed, but MUST NOT mutate active
    // UTXO/contract/wallet state. Reorg stays fail-closed.
    bool validateBlockForIndex(const Block& block, const std::string& serializedBlock) const;
    bool submitBlockInternal(const Block& block, const std::string& sourceKey);
    bool indexSideChainBlock(const Block& block, const std::string& sourceKey);

    // caller MUST already own miningSubmitMutex.
    // If a fully validated incoming SIDE block is capacity-blocked, perform at
    // most one deterministic lower-work SIDE-leaf replacement. No active-state
    // mutation, no automatic reorg activation, and no undo:block:* pruning.
    bool tryWorkAwareSideReplacementWithSubmissionLockHeld(
        const Block& block,
        const std::string& serialized,
        const std::string& sourceKey,
        bool& handledOut);

    // caller MUST already own miningSubmitMutex.
    // Removes only objectively stale SIDE leaves whose active fork depth now
    // exceeds MAX_SIDE_FORK_DEPTH. No work-based eviction and no U4 pruning.
    // active-chain U4 retention core.
    bool pruneActiveUndoJournalsWithSubmissionLockHeld(
        std::string& reasonOut);

    bool pruneRuntimeStaleSideBlocksWithSubmissionLockHeld(
        size_t maxPrunes,
        size_t& prunedOut,
        std::string& reasonOut);

    void reloadSideChainIndexLocked();
    std::string findForkPointHashLocked(const std::string& tipHash) const;

    // reconstruct the fork-point state inside an isolated
    // validation-only LevelDB sandbox, then run normal full block semantics.
    // The standalone wrapper owns miningSubmitMutex. 08B.4 MUST use the
    // explicit lock-held form when its caller already owns miningSubmitMutex.
    bool validateCandidateBranchStateful(const std::string& candidateTipHash);
    bool validateCandidateBranchStatefulWithSubmissionLockHeld(
        const std::string& candidateTipHash);
    bool validateCandidateBranchStatefulImpl(
        const std::string& candidateTipHash,
        bool submissionLockAlreadyHeld);

    // optional reorgMarkerPayload plumbing remains available
    // for atomic state-batch markers, but 08B.4B.1 v2 deliberately publishes
    // CONNECT progress with tip metadata instead. Candidate side ownership is
    // still removed atomically in this state batch via promotedSideBlockHash.
    bool applyBlock(const Block& blk,
                    int height,
                    const std::string* reorgMarkerPayload = nullptr,
                    const std::string* promotedSideBlockHash = nullptr);
    // Patch 08B.1 v4 writes durable LevelDB pre-image journals during applyBlock().
    // Patch 08B.2 enables only an authenticated SINGLE active-tip disconnect.
    // LIVE CHAIN ONLY: validation sandboxes use authenticated manual U4 rewind
    // and must never call rollbackBlock*. 08B.4 must call the lock-held form
    // only for real active-chain mutation while it owns submission ordering.
    bool rollbackBlock(const Block& blk);
    bool rollbackBlockWithSubmissionLockHeld(
        const Block& blk,
        const std::string* reorgMarkerPayload = nullptr,
        const std::string* demoteSideSourceKey = nullptr,
        const std::vector<std::string>* recoveryAllowedSideChildren = nullptr);

    // durable reorganization planning/preflight.
    // PREPARED remains an authenticated, non-mutating durable intent record.
    // Patch 08B.4B.1 v2 adds only a MANUAL/GATED executor that consumes this
    // exact plan; automatic network fork promotion remains disabled.
    //
    // 4B MUST NOT trust stored chainwork as a decision input: reconstruct the
    // live index, recompute both branch works, compare them to the marker as
    // witnesses, and require originalTipHash to match the live transition base.
    //
    // 4A conservatively rejects any disconnect suffix with existing indexed
    // side children. 4B may relax that only after an atomic old-branch demotion
    // policy and side-pool capacity reservation are implemented.
    struct ReorgPlan {
        std::string originalTipHash;
        int originalTipHeight{0};
        ChainWork256 originalChainWork{0};
        std::string candidateTipHash;
        int candidateTipHeight{0};
        ChainWork256 candidateChainWork{0};
        std::string forkHash;
        int forkHeight{0};
        std::vector<std::string> disconnectHashes; // active tip -> fork child
        std::vector<int> disconnectHeights;        // same order as disconnectHashes
        std::vector<std::string> connectHashes;    // fork child -> candidate tip
        std::vector<int> connectHeights;           // same order as connectHashes
        size_t disconnectBytes{0};
        size_t connectBytes{0};

        // 4A policy contracts. These are persisted/fingerprinted so 4B cannot
        // silently reinterpret a PREPARED record under different semantics.
        std::string oldBranchPolicy;
        std::string mempoolPolicy;
    };

    bool buildReorgPlanLocked(const std::string& candidateTipHash,
                              ReorgPlan& planOut,
                              std::string& reasonOut) const;
    bool reorgPlansEquivalent(const ReorgPlan& a, const ReorgPlan& b) const;
    std::string computeReorgPlanSha256(const ReorgPlan& plan) const;
    bool readPreparedReorgMarker(ReorgPlan& planOut,
                                 bool& foundOut,
                                 std::string& reasonOut) const;
    bool persistPreparedReorgMarker(const ReorgPlan& plan,
                                    std::string& reasonOut);
    bool clearPreparedReorgMarker(std::string& reasonOut);
    bool verifyReorgDurabilityPreflight(const ReorgPlan& plan,
                                        std::string& reasonOut);
    // bounded in-memory POSITIVE
    // candidate-validation cache. Correctness never relies on candidateTipHash
    // alone. The witness commits the exact reorg plan, state-affecting block
    // payload fingerprints, full contract-state snapshot, authenticated durable
    // execution-source bytes, AND the live LevelDB per-path mutation generation.
    // 4D.5 owns negative-result caching.
    bool buildCandidateValidationCacheWitness(
        const ReorgPlan& plan,
        std::string& witnessOut,
        std::string& reasonOut) const;
    bool candidateValidationCacheContains(
        const std::string& witness,
        const std::string& candidateTipHash,
        const std::string& planSha256) const;
    void storeCandidateValidationCachePositive(
        const std::string& witness,
        const std::string& candidateTipHash,
        const std::string& planSha256);

    // bounded in-memory IMMUTABLE-REJECT cache.
    // This cache is deliberately NOT used for 4A/08B.3 stateful candidate
    // failures. Only explicitly classified byte/content-intrinsic
    // validateBlockForIndex() failures may be stored.
    bool immutableNegativeCandidateCacheContains(
        const std::string& fingerprint,
        std::string& reasonCodeOut) const;
    void storeImmutableNegativeCandidateCache(
        const std::string& fingerprint,
        const std::string& reasonCode) const;

    // per-authoritative-side-source budget for the
    // expensive 08B.3 candidate sandbox. This is node-local DoS policy only;
    // it does not change block validity, fork work, or durable chain state.
    bool consumeCandidateValidationBudgetForSource(
        const std::string& sourceKey,
        std::string& reasonOut);

    bool preflightReorgCandidateWithSubmissionLockHeld(
        const std::string& candidateTipHash,
        ReorgPlan& planOut,
        std::string& reasonOut);
    bool prepareReorgTransactionWithSubmissionLockHeld(
        const std::string& candidateTipHash,
        ReorgPlan& planOut,
        std::string& reasonOut);

    // controlled/manual executor core. Crash recovery of an
    // interrupted execution marker is intentionally deferred to 08B.4C.
    std::string buildReorgExecutionMarkerPayload(
        const ReorgPlan& plan,
        const std::string& phase,
        size_t disconnectDone,
        size_t connectDone,
        const std::string& stateTipHash,
        int stateTipHeight) const;
    bool verifyDurableActiveTipMetadata(
        const std::string& expectedHash,
        int expectedHeight,
        uint32_t expectedBits,
        std::string& reasonOut) const;
    bool verifyDurableReorgMarkerPayload(
        const std::string& expectedPayload,
        std::string& reasonOut) const;
    bool executePreparedReorgWithSubmissionLockHeld(
        const std::string& candidateTipHash,
        std::string& reasonOut,
        bool& mutationStartedOut);

    // authenticated restart classification only.
    // This structure is a witness parsed from the checksum-authenticated E2
    // execution marker. 08B.4C.1 never mutates chain state from this record.
    struct ReorgExecutionRecoveryState {
        ReorgPlan plan;
        std::string phase;
        size_t disconnectDone{0};
        size_t connectDone{0};
        std::string durableTipHash;
        int durableTipHeight{0};
        std::string markerSemantics;
        std::string exactPayload;
    };

    bool readReorgExecutionRecoveryState(
        ReorgExecutionRecoveryState& stateOut,
        bool& foundOut,
        std::string& reasonOut) const;
    bool classifyReorgExecutionRecoveryState(
        const ReorgExecutionRecoveryState& state,
        std::string& nextActionOut,
        std::string& reasonOut) const;

    // [Patch08B.4C.2] Finish-forward recovery core. This is invoked only from
    // startup after explicit runtime opt-in and while the caller owns
    // miningSubmitMutex. Automatic/network reorganization remains disabled.
    bool recoverInterruptedReorgWithSubmissionLockHeld(
        std::string& reasonOut,
        bool& mutationStartedOut);

    // TRU CORE RECOVERY CR-01A v1: recover an ordinary direct-tip block whose
    // Phase-5 state/U4/block witness committed before active-tip publication.
    void recoverDirectConnectPendingAtStartup();

    // TRU CORE RECOVERY CR-01B v1: explicitly armed one-time repair for the
    // already-proven pre-CR-01A height-355 orphan Phase-5 contamination.
    void recoverCR01BLegacyHeight355AtStartup();
    void recoverPreparedReorgMarkerAtStartup();
    bool handleChainReorganization(const std::vector<Block>& newChain);

    // normal-context bridge for a future 9B partial-mutation
    // fail-stop. This helper never performs reorganization itself. Future live
    // activation must require reorgFailStopShutdownReady() before mutation.
    bool reorgFailStopShutdownReady() const;
    void requestReorgFailStopShutdown(const std::string& reason);

    // called only after a side block has been fully accepted
    // and persisted while submitBlockInternal() still owns miningSubmitMutex.
    // Gate-OFF and non-winning candidates are no-ops. 9C will own startup scan.
    bool maybeActivateIncomingWinningSideTipWithSubmissionLockHeld(
        const std::string& candidateTipHash,
        std::string& reasonOut);

    // bounded pre-validation transaction queue.
    std::queue<Transaction> txQueue_;
    std::queue<std::size_t> txQueueSizes_;
    std::queue<std::uint8_t> txQueueRetries_;
    std::unordered_set<std::string> txQueueTxids_;
    std::size_t txQueueBytes_{0};
    std::mutex queueMutex_;
    std::condition_variable queueCond_;
    std::thread processorThread_;
    tru_tx_relay::Queue acceptedTxRelay_;
    std::thread acceptedTxRelayThread_;
    void processAcceptedTransactionRelay();
    //bool running_ = true;                      // Flag to control processor thread

    void processQueue();
    void invalidateCachesForAcceptedMempoolTransaction(const Transaction& tx);
    std::vector<Block> chain;
    std::unordered_map<std::string, BlockIndexEntry> blockIndex;

    //
    // O(1) resource accounting for SIDE blocks only.
    size_t sideBlockCount_{0};
    size_t sidePoolBytes_{0};
    std::unordered_map<std::string, size_t> sideChildCount_;

    // bounded resource ownership for untrusted
    // network sources. Keys are "peer:<IPv4>", "rpc", "explorer",
    // "p2p-legacy", or "local".
    //
    // IMPORTANT FOR 08B: any future side-block promotion/pruning/removal path
    // must decrement sideBlockCountBySource_, sidePoolBytesBySource_,
    // sideChildCountBySource_, and sideBlockSource_ in lockstep.
    std::unordered_map<std::string, size_t> sideBlockCountBySource_;
    std::unordered_map<std::string, size_t> sidePoolBytesBySource_;
    std::unordered_map<std::string, std::unordered_map<std::string, size_t>>
        sideChildCountBySource_;
    std::unordered_map<std::string, std::string> sideBlockSource_;
    // In-memory only; restart resets to height 2 without correctness risk.
    int undoActivePruneCursorHeight_{2};

    // if a manually-gated execution fails after the first
    // durable mutation, block ALL live confirmed-state mutation and prevent
    // shutdown from republishing chain state before 08B.4C recovery.
    std::atomic<bool> reorgExecutionHalted_{false};

    // installed by main before network activity. The callback
    // only requests the program's existing orderly shutdown path; it does not
    // own or mutate blockchain state.
    mutable std::mutex reorgFailStopShutdownCallbackMutex_;
    std::function<void(const std::string&)> reorgFailStopShutdownCallback_;

    std::string bestTipHash;
    //int bestTipHeight;
    uint32_t difficulty;
    uint64_t blockReward;
    mutable std::shared_mutex mtx;
    // EXPLORER-LOCK-02: display/telemetry-only maps never participate in
    // consensus state and must not extend chain-lock hold times.
    mutable std::shared_mutex derivedStatsMutex_;

    std::unordered_map<std::string, AddressStats> addressCache;
    mutable std::shared_mutex addressCacheMutex;
    // EXPLORER-LOCK-01: guarded by addressCacheMutex; derived cache only.
    // Every write/erase/swap advances this revision. No chain/DB serialization.
    uint64_t addressCacheRevision{0};
    std::string chainName;
    std::string ticker;
    std::string version;
    std::string networkType;
    uint64_t maxSupply;
    uint32_t halvingInterval;
    uint32_t targetBlockTime;
    P2PNode& node;
    uint16_t p2pPort;
    uint16_t rpcPort;
    std::string genesisAddress;
    LevelDBStorage dbStorage;

    //int getHeightByHash(const std::string& hash) const;

    std::unordered_set<std::string> activeMiners;
    std::condition_variable processBlocksCv;
    std::thread blockProcessor;           // Add this
    void processBlocks();
    Wallet* walletPtr = nullptr;
    std::chrono::steady_clock::time_point startTime;
    bool noSeeds_;
    bool validationOnly_{false}; // Patch 08B.3 isolated candidate sandbox mode
    // memory-only positive validation cache.
    // No durable state, no negative entries, deterministic FIFO eviction.
    struct CandidateValidationCacheEntry {
        std::string witnessSha256;
        std::string candidateTipHash;
        std::string planSha256;
        size_t accountedBytes{0};
    };
    mutable std::mutex candidateValidationCacheMutex_;
    std::vector<CandidateValidationCacheEntry> candidateValidationCache_;
    size_t candidateValidationCacheBytes_{0};


    // process-local immutable negative cache.
    // No state/time-dependent failure is eligible.
    struct ImmutableNegativeCandidateCacheEntry {
        std::string fingerprintSha256;
        std::string reasonCode;
        size_t accountedBytes{0};
    };
    mutable std::mutex immutableNegativeCandidateCacheMutex_;
    mutable std::vector<ImmutableNegativeCandidateCacheEntry>
        immutableNegativeCandidateCache_;
    mutable size_t immutableNegativeCandidateCacheBytes_{0};


    // bounded process-local token buckets keyed by the
    // authoritative sideBlockSource_ owner of the candidate TIP. Entries are
    // never persisted and therefore reset on process restart.
    struct CandidateValidationBudgetEntry {
        size_t tokens{0};
        std::chrono::steady_clock::time_point lastRefill{};
        std::chrono::steady_clock::time_point lastSeen{};
    };
    std::mutex candidateValidationBudgetMutex_;
    std::unordered_map<std::string, CandidateValidationBudgetEntry>
        candidateValidationBudgetBySource_;

    // one aggregate untrusted-source token bucket shares
    // the 4D.6 mutex so per-source + global admission is committed atomically.
    // Memory only; process restart deliberately resets this node-policy state.
    size_t globalCandidateValidationBudgetTokens_{0};
    std::chrono::steady_clock::time_point
        globalCandidateValidationBudgetLastRefill_{};
    bool globalCandidateValidationBudgetInitialized_{false};

    std::unordered_map<int, std::string> heightToHash;
    void rebuildHeightToHashIfNeeded();
    std::mutex applyBlockMutex;
    // token/application serialization is per-chain instance so an
    // isolated validation sandbox cannot stall the live chain on a process-global mutex.
    std::mutex tokenCreationMutex_;
    void debugTxCountChecksum(LevelDBStorage* storage, const std::string& addr);
    std::atomic<bool> running_{true};           // Replace: bool running_ = true;
    std::atomic<bool> stopProcessing{false};    // New atomic version
    std::atomic<bool> shutdownInitiated{false}; // New for shutdown management
    std::atomic<int> bestTipHeight{0};
    std::mutex blockchainMutex;
    std::mutex miningMutex;
    mutable std::shared_mutex minerMutex;     // Separate mutex for miner data
    mutable std::mutex miningSubmitMutex;     // For block submission ordering
    std::atomic<int> pendingSubmissions{0};   // Track pending submissions
};

#endif // BLOCKCHAIN_H
