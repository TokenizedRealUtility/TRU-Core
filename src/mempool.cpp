#include "mempool.h"
#include "tru_limits.h"  // shared money/mempool limits
#include "tokens.h"    
#include "tx.h"
#include "logging.h"  
#include <sstream>
#include <vector>
#include <mutex>
#include "utxo.h"            
#include "utils.h"
#include "address_helpers.h"
#include "script_interpreter.h"
#include "script_context_builder.h"  // shared execution context
#include "contract_call_policy.h"     // Patch 14D2/14D3B: state-anchor call policy
#include "contract_state_runtime.h"    // confirmed state snapshot + scratch execution
#include "tru_swap_prepared_funding_guard.h"  // TRU SWAP GROUP-01 input reservation
#include "opcodes.h"  // explicit OP_RETURN consensus parity
#include "utils.h"
#include <algorithm>  // TRU Security Patch 12A bounded gas min
#include <ctime>      // TRU Security Patch 12A mempool block-time context
#include <limits>
#include <unordered_map>  // TOKEN-BURN-01 token-control relay conservation
// For thread-safe initialization
//std::once_flag patternsOnceFlag;



bool Mempool::isUTXOSpentInMempool(const std::string& txid, uint32_t vout) const {
    std::lock_guard<std::mutex> lock(mtx_);
    const std::string key = makeUTXOKey(txid, vout);
    return spentInMempool.find(key) != spentInMempool.end();
}

//=========================================================================
//			HELPERS for the AI ORACLE
//=========================================================================
std::vector<std::string> Mempool::scanForAIRequests() const {
    // OP_DATAFEED is a deterministic consensus opcode, not an AI
    // request marker. The AI service's persisted ContractStorage/RPC queue is
    // authoritative for off-chain inference work. Keep this API for caller
    // compatibility but deliberately return no script-derived requests.
    return {};
}

//------------------------------------------------------------------------------
//      IS STANDARD SCRIPT
//------------------------------------------------------------------------------
bool isStandardScript(const std::string& scriptHex) {
    // P2PKH: "76a914<20-byte-hash>88ac"
    if (scriptHex.size() == 50 && scriptHex.substr(0, 6) == "76a914" && scriptHex.substr(46) == "88ac") {
        return true;
    }
    // OP_RETURN (token scripts)
    if (startsWithOpReturnHex(scriptHex)) {
        return true;
    }
    return false;
}

//======================================================================
//                      MagicLock Debug
//======================================================================
bool Mempool::isMagicLockScript(const std::string& scriptHex) const {
    tru_contract_call::CanonicalMagicLockV1Info info;
    const bool canonical =
        tru_contract_call::ParseCanonicalMagicLockV1ScriptHex(scriptHex, info);
    if (canonical) {
        Logger::log(
            "[isMagicLockScript][SC22] canonical MagicLock V1 target=" +
            info.targetPrefix);
    }
    return canonical;
}


//------------------------------------------------------------------------------
//      SC-22 COMPILED SCRIPT / RELAY POLICY
//------------------------------------------------------------------------------
//
// allowed_scripts.json is now a human-readable policy manifest only. Relay
// policy is compiled and deterministic so changing the process working
// directory or editing a JSON regex cannot widen what a node accepts.
//
// Named V1 families are byte-exact. Generic Custom Script remains available,
// but only when the bytecode parses under the consensus resource analyzer and
// does not execute a reserved/disabled family opcode.
//
// Policy-only exclusions below do NOT change consensus. Historical confirmed
// scripts remain governed by consensus spend rules; SC-22 only controls relay
// and new-output admission.
static bool isRelaySafeCustomScriptV1(
    const std::vector<unsigned char>& script,
    std::string& reasonOut)
{
    reasonOut.clear();

    const auto scan =
        tru_contract_call::ScanStatefulContractScript(script);
    if (!scan.valid) {
        reasonOut = "malformed PUSHDATA";
        return false;
    }
    if (scan.usesStateDomain) {
        reasonOut =
            "state opcodes require a canonical registered V1 state anchor";
        return false;
    }
    if (scan.usesBridgeOpcode) {
        reasonOut =
            "legacy NOVO/BSTY bridge opcodes are disabled pending redesign";
        return false;
    }
    if (scan.usesExternalData) {
        reasonOut =
            "OP_EXTERNALDATA is reserved and not relay-standard";
        return false;
    }
    if (scan.usesDataFeed) {
        reasonOut =
            "OP_DATAFEED is relay-standard only inside canonical Oracle V1";
        return false;
    }
    if (scan.usesDelegateCheck) {
        reasonOut =
            "OP_DELEGATECHECK is not activated for relay";
        return false;
    }
    if (scan.usesUpgradeNop) {
        reasonOut =
            "reserved upgrade NOPs are consensus-valid but non-standard";
        return false;
    }
    if (scan.usesMultisigOpcode) {
        reasonOut =
            "CHECKMULTISIG/CHECKMULTISIGVERIFY is relay-standard only inside canonical Multisig / Escrow V1";
        return false;
    }

    ScriptResourceMetrics metrics;
    if (!AnalyzeScriptResources(script, metrics)) {
        reasonOut = "unsupported/malformed/over-budget script";
        return false;
    }

    return true;
}

bool Mempool::isAllowedSmartContractScript(const std::string& scriptHex) const {
    std::vector<unsigned char> script;
    if (!tru_contract_call::DecodeScriptHexStrict(scriptHex, script) ||
        script.empty() ||
        script.size() > tru_limits::MAX_SCRIPT_BYTES) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] malformed/oversized script");
        return false;
    }

    // Standard P2PKH is handled by the ordinary payment path, not the smart
    // contract policy API.
    if (script.size() == 25 &&
        script[0] == static_cast<unsigned char>(OP_DUP) &&
        script[1] == static_cast<unsigned char>(OP_HASH160) &&
        script[2] == 0x14 &&
        script[23] == static_cast<unsigned char>(OP_EQUALVERIFY) &&
        script[24] == static_cast<unsigned char>(OP_CHECKSIG)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] P2PKH is standard payment, not contract");
        return false;
    }

    // OP_RETURN has its own output-policy path (zero-value enforcement at RPC,
    // extended-token parsing, and 256-byte generic payload cap in mempool).
    // Keep direct RPC contract creation parity without using a regex.
    if (script.front() == static_cast<unsigned char>(OP_RETURN)) {
        const bool allowed = script.size() <= 257U;
        Logger::log(
            std::string("[isAllowedSmartContractScript][SC22] OP_RETURN ") +
            (allowed ? "accepted by dedicated policy" : "too large"));
        return allowed;
    }

    tru_contract_call::CanonicalTimeLockV1Info timeInfo;
    if (tru_contract_call::ParseCanonicalTimeLockV1Script(script, timeInfo)) {
        static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD =
            500000000U;
        if (timeInfo.lockTime < TRU_CLTV_TIMESTAMP_THRESHOLD) {
            Logger::log(
                "[isAllowedSmartContractScript][SC22] rejected height-domain Time Lock");
            return false;
        }
        Logger::log(
            "[isAllowedSmartContractScript][SC22] canonical time_lock_v1");
        return true;
    }

    std::string hash160;
    if (tru_contract_call::ParseCanonicalHashLockV1ScriptHex(
            scriptHex, hash160)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] canonical hash_lock_v1");
        return true;
    }

    tru_contract_call::CanonicalHtlcAtomicSwapV1Info htlcInfo;
    if (tru_contract_call::ParseCanonicalHtlcAtomicSwapV1Script(
            script, htlcInfo)) {
        Logger::log(
            "[isAllowedSmartContractScript][HTLC-01B] canonical htlc_atomic_swap_v1");
        return true;
    }

    tru_contract_call::CanonicalOracleLockV1Info oracleInfo;
    if (tru_contract_call::ParseCanonicalOracleLockV1Script(
            script, oracleInfo)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] canonical oracle_lock_v1");
        return true;
    }

    if (tru_contract_call::IsCanonicalStatefulKvV1Script(script)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] canonical f751 state anchor");
        return true;
    }

    tru_contract_call::CanonicalMultisig2of3V1Info multisigInfo;
    if (tru_contract_call::ParseCanonicalMultisig2of3V1Script(
            script, multisigInfo)) {
        Logger::log(
            "[isAllowedSmartContractScript][MS-01B] canonical multisig_escrow_2of3_v1");
        return true;
    }

    tru_contract_call::CanonicalMagicLockV1Info magicInfo;
    if (tru_contract_call::ParseCanonicalMagicLockV1Script(
            script, magicInfo)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] canonical MagicLock V1");
        return true;
    }

    std::string customReason;
    if (isRelaySafeCustomScriptV1(script, customReason)) {
        Logger::log(
            "[isAllowedSmartContractScript][SC22] structurally valid custom script");
        return true;
    }

    Logger::log(
        "[isAllowedSmartContractScript][SC22] rejected: " + customReason +
        " script=" + scriptHex);
    return false;
}

//------------------------------------------------------------------------------
//      RELAY TX
//------------------------------------------------------------------------------
bool Mempool::shouldRelayTransaction(const Transaction& tx) const {
    for (const auto& output : tx.vout) {
        // TxOut::scriptPubKey is already canonical hex text throughout TRU.
        // The legacy implementation hex-encoded those ASCII characters a
        // second time (for example f751 -> 66373531), which would make this
        // helper disagree with actual mempool admission if it were used.
        const std::string& scriptHex = output.scriptPubKey;
        if (!isStandardScript(scriptHex) &&
            !isAllowedSmartContractScript(scriptHex)) {
            Logger::log(
                "[shouldRelayTransaction][SC22] Rejected script: " + scriptHex);
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------------------
// Helper: doubleSha256 - single, then second SHA256
//------------------------------------------------------------------------------
static std::string doubleSha256(const std::string &data) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    // 1) first sha
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash1);
    // 2) second sha
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // hex-encode
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << static_cast<int>(hash2[i]);
    }
    return oss.str();
}

Mempool::Mempool(Blockchain& chain) : chain_(chain) {
    // Initialization if needed
}

/**
 * Quick check if a script is an extended token script, i.e. starts with "6a" (OP_RETURN).
 */

static bool isExtendedTokenScript(const std::string &scriptHex) {
    if (scriptHex.size() < 2 || scriptHex.substr(0, 2) != "6a") return false;
    std::vector<unsigned char> raw = hexDecode(scriptHex.substr(2));
    // Check if it could be a token script: at least 37 bytes and valid TokenType
    return raw.size() >= 37 && (raw[0] >= static_cast<unsigned char>(TokenType::FT) &&
                                raw[0] <= static_cast<unsigned char>(TokenType::NCFT));
}
//-------------------------------------------------------------
//          ADD TX
//-------------------------------------------------------------
MempoolAddStatus Mempool::addTransaction(const Transaction &tx) {
    // TRU SWAP GROUP-01: serialize all mempool admission against durable
    // prepared-funding reservation creation/release. This is local node policy,
    // not consensus, and protects prepared wallet inputs from every admission
    // path (RPC, wallet, and peer relay).
    std::lock_guard<std::recursive_mutex> swapPreparedFundingGuard(
        tru_swap_prepared_funding::mutex());

    Logger::log("[Mempool] Adding transaction: " + tx.txid);

    std::vector<unsigned char> serializedBytes;
    std::size_t serializedSize = 0;
    try {
        serializedBytes = tx.serializeBinary();
        serializedSize = serializedBytes.size();
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Rejecting TX: serialization failed => " + tx.txid +
            ": " + e.what());
        return MempoolAddStatus::INVALID;
    } catch (...) {
        Logger::log(
            "[Mempool] Rejecting TX: unknown serialization failure => " + tx.txid);
        return MempoolAddStatus::INVALID;
    }

    if (serializedSize == 0 ||
        serializedSize > tru_limits::MAX_MEMPOOL_TX_BYTES) {
        Logger::log(
            "[Mempool] Rejecting TX: serialized size " +
            std::to_string(serializedSize) +
            " exceeds per-TX mempool policy");
        return MempoolAddStatus::INVALID;
    }

    // TRU SWAP GROUP-01 authoritative local reservation gate.
    // A reserved input may enter the mempool ONLY as the exact persisted raw
    // transaction. TRU's txid excludes scriptSig, so txid equality alone is
    // deliberately insufficient; rawTxSha256 binds the complete signed bytes.
    if (LevelDBStorage* preparedStorage = chain_.getStorage()) {
        const std::string rawTxSha256 =
            tru_swap_prepared_funding::sha256Hex(serializedBytes);
        for (const auto& vin : tx.vin) {
            if (vin.txid.size() != 64U || vin.vout < 0) continue;
            std::string markerPayload;
            if (!preparedStorage->getWithDataChecksum(
                    tru_swap_prepared_funding::inputKey(
                        vin.txid, static_cast<std::uint32_t>(vin.vout)),
                    markerPayload)) {
                continue;
            }

            std::string operationId;
            std::string preparedTxid;
            std::string preparedRawSha256;
            if (!tru_swap_prepared_funding::parseInputMarker(
                    markerPayload,
                    operationId,
                    preparedTxid,
                    preparedRawSha256)) {
                Logger::log(
                    "[TRU-SWAP-GROUP-01] Rejecting TX: corrupt prepared-input marker");
                return MempoolAddStatus::INVALID;
            }
            if (preparedTxid != tx.txid ||
                preparedRawSha256 != rawTxSha256) {
                Logger::log(
                    "[TRU-SWAP-GROUP-01] Rejecting conflicting spend of reserved input " +
                    vin.txid + ":" + std::to_string(vin.vout));
                return MempoolAddStatus::INVALID;
            }
        }
    }

    // Cheap duplicate/conflict preflight. Capacity is NOT rejected here:
    // a strictly higher-fee-rate newcomer may be able to evict lower-rate,
    // non-conflicting entries after validation.
    {
        std::lock_guard<std::mutex> preflightLock(mtx_);

        if (pool_.find(tx.txid) != pool_.end()) {
            Logger::log(
                "[Mempool] TX " + tx.txid +
                " already known (duplicate). Not added.");
            return MempoolAddStatus::DUPLICATE;
        }

        for (const auto& vin : tx.vin) {
            if (vin.vout < 0) continue;
            const std::string inKey =
                makeUTXOKey(vin.txid, static_cast<uint32_t>(vin.vout));
            if (spentInMempool.find(inKey) != spentInMempool.end()) {
                Logger::log(
                    "[Mempool] Rejecting conflicting TX under first-seen preflight; UTXO=" +
                    inKey);
                return MempoolAddStatus::INVALID;
            }
        }
    }

    // reserve one shared validation-work slot BEFORE fee
    // computation. This budgets both input/UTXO fee work and script execution.
    if (!tryAcquireValidationSlot()) {
        Logger::log(
            "[Mempool] Validation budget BUSY before admission work => " +
            tx.txid);
        return MempoolAddStatus::BUSY;
    }

    struct ValidationSlotGuard {
        const Mempool* self;
        ~ValidationSlotGuard() {
            self->releaseValidationSlot();
        }
    } validationSlot{this};

    // Enforce the fee floor before signature/script execution.
    std::uint64_t fee = 0;
    try {
        fee = tx.computeFee(chain_);
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Rejecting TX: fee computation failed => " +
            tx.txid + ": " + e.what());
        return MempoolAddStatus::INVALID;
    } catch (...) {
        Logger::log(
            "[Mempool] Rejecting TX: fee computation failed => " + tx.txid);
        return MempoolAddStatus::INVALID;
    }

    if (serializedSize >
        static_cast<std::size_t>(
            tru_limits::MAX_MONEY /
            tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE)) {
        Logger::log(
            "[Mempool] Rejecting TX: minimum-fee arithmetic overflow");
        return MempoolAddStatus::INVALID;
    }

    const std::uint64_t minimumFee =
        static_cast<std::uint64_t>(serializedSize) *
        tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE;

    if (fee < minimumFee) {
        Logger::log(
            "[Mempool] Rejecting TX below minimum relay fee: fee=" +
            std::to_string(fee) +
            " minimum=" + std::to_string(minimumFee) +
            " bytes=" + std::to_string(serializedSize) +
            " txid=" + tx.txid);
        return MempoolAddStatus::INVALID;
    }

    bool transactionValid = false;
    try {
        // Slot already held above; avoid a second acquisition.
        transactionValid = isTransactionValidUnchecked(tx, &chain_);
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Rejecting TX: validation threw => " + tx.txid +
            ": " + e.what());
        return MempoolAddStatus::INVALID;
    } catch (...) {
        Logger::log(
            "[Mempool] Rejecting TX: validation threw unknown exception => " +
            tx.txid);
        return MempoolAddStatus::INVALID;
    }

    if (!transactionValid) {
        Logger::log("[Mempool] Transaction invalid: " + tx.txid);
        return MempoolAddStatus::INVALID;
    }

    std::lock_guard<std::mutex> lock(mtx_);

    // TOCTOU-safe commit recheck after validation.
    if (pool_.find(tx.txid) != pool_.end()) {
        Logger::log(
            "[Mempool] TX " + tx.txid +
            " became known during validation (duplicate). Not added.");
        return MempoolAddStatus::DUPLICATE;
    }

    // Confirmed state may have advanced while validation waited/ran.
    for (const auto& vin : tx.vin) {
        UTXO utxo;
        if (vin.vout < 0 ||
            !chain_.utxoSet.getUTXO(
                vin.txid, static_cast<uint32_t>(vin.vout), utxo)) {
            Logger::log(
                "[Mempool] Input UTXO already spent/missing in blockchain: " +
                vin.txid + ":" + std::to_string(vin.vout));
            return MempoolAddStatus::INVALID;
        }
    }

    // FIRST-SEEN remains authoritative. Patch 12B fee eviction is NOT RBF.
    for (const auto& vin : tx.vin) {
        const std::string inKey =
            makeUTXOKey(vin.txid, static_cast<uint32_t>(vin.vout));
        if (spentInMempool.find(inKey) != spentInMempool.end()) {
            Logger::log(
                "[Mempool] Rejecting conflicting TX under first-seen policy; UTXO=" +
                inKey);
            return MempoolAddStatus::INVALID;
        }
    }

    // Prevent duplicate token issuance (FT or NFT) within the bounded mempool.
    // Token parsing is attacker-controlled input; any parser exception is an
    // INVALID transaction, never an exception escaping the mempool boundary.
    try {
        if (!pool_.empty()) {
            for (const auto& pair : pool_) {
            const Transaction& existingTx = pair.second;
            for (const auto& existingOut : existingTx.vout) {
                if (!isExtendedTokenScript(existingOut.scriptPubKey)) continue;

                ExtendedTokenData existingData;
                std::string existingOwner;
                if (!parseExtendedTokenScript(
                        existingOut.scriptPubKey,
                        existingTx.txid,
                        existingData,
                        existingOwner,
                        &chain_)) {
                    continue;
                }

                if (existingData.type != TokenType::FT &&
                    existingData.type != TokenType::NFT) {
                    continue;
                }

                for (const auto& newOut : tx.vout) {
                    if (!isExtendedTokenScript(newOut.scriptPubKey)) continue;

                    ExtendedTokenData newData;
                    std::string newOwner;
                    if (!parseExtendedTokenScript(
                            newOut.scriptPubKey,
                            tx.txid,
                            newData,
                            newOwner,
                            &chain_)) {
                        Logger::log(
                            "[Mempool] parseExtendedTokenScript failed for new TX output");
                        return MempoolAddStatus::INVALID;
                    }

                    if ((newData.type == TokenType::FT ||
                         newData.type == TokenType::NFT) &&
                        newData.tokenID == existingData.tokenID) {
                        Logger::log(
                            "[Mempool] Duplicate token issuance => tokenID=" +
                            newData.tokenID);
                        return MempoolAddStatus::INVALID;
                    }
                }
            }
            }
        }
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Rejecting TX: token-conflict parsing threw => " +
            tx.txid + ": " + e.what());
        return MempoolAddStatus::INVALID;
    } catch (...) {
        Logger::log(
            "[Mempool] Rejecting TX: token-conflict parsing threw unknown exception => " +
            tx.txid);
        return MempoolAddStatus::INVALID;
    }

    // IMPORTANT: no LevelDB writes for unconfirmed metadata. tx.tokenMetadata
    // remains in the in-memory Transaction object; applyBlock() owns confirmed
    // tokenMetadata persistence atomically with the block state transition.

    // Fee-rate-aware capacity policy.
    // Validate the accounting invariant before planning. A stale/desynchronized
    // index must not cause silent eviction of otherwise-valid pool entries.
    if (feeIndex_.size() != pool_.size() ||
        txFees_.size() != pool_.size() ||
        txSerializedSizes_.size() != pool_.size()) {
        Logger::log(
            "[Mempool] ERROR: fee/index accounting mismatch before eviction; "
            "rebuilding index and rejecting newcomer");
        rebuildFeeIndexLocked();
        return MempoolAddStatus::INVALID;
    }

    // Build the COMPLETE eviction plan first. If the newcomer cannot fit using
    // only strictly-lower-rate entries, reject without mutating the pool.
    const FeeEntry incoming{fee, serializedSize, tx.txid};
    std::vector<std::string> evictionPlan;

    std::size_t projectedCount = pool_.size();
    std::size_t projectedBytes = poolBytes_;

    auto needsCapacity = [&]() {
        if (serializedSize > tru_limits::MAX_MEMPOOL_BYTES) return true;
        if (projectedCount >= tru_limits::MAX_MEMPOOL_TXS) return true;
        return projectedBytes >
               tru_limits::MAX_MEMPOOL_BYTES - serializedSize;
    };

    auto feeIt = feeIndex_.begin();
    while (needsCapacity()) {
        if (feeIt == feeIndex_.end()) {
            Logger::log(
                "[Mempool] Rejecting TX: no sufficient lower-fee eviction set");
            return MempoolAddStatus::INVALID;
        }

        // Equal-rate arrivals do not churn first-seen pool contents.
        if (FeeEntryLess::compareRate(*feeIt, incoming) >= 0) {
            Logger::log(
                "[Mempool] Rejecting TX: pool full and newcomer fee-rate "
                "is not strictly higher than eviction floor");
            return MempoolAddStatus::INVALID;
        }

        if (projectedCount == 0 || projectedBytes < feeIt->bytes) {
            Logger::log(
                "[Mempool] ERROR: fee-index accounting mismatch; "
                "refusing partial eviction");
            return MempoolAddStatus::INVALID;
        }

        evictionPlan.push_back(feeIt->txid);
        --projectedCount;
        projectedBytes -= feeIt->bytes;
        ++feeIt;
    }

    // Reserve the incoming fee-index key BEFORE any eviction. If this fails,
    // nothing has been removed and the pool remains unchanged.
    const auto incomingIndexInsert = feeIndex_.insert(incoming);
    if (!incomingIndexInsert.second) {
        Logger::log(
            "[Mempool] ERROR: incoming fee-index key already exists; "
            "rebuilding index and rejecting without eviction => " + tx.txid);
        rebuildFeeIndexLocked();
        return MempoolAddStatus::INVALID;
    }

    for (const auto& evictTxid : evictionPlan) {
        if (!eraseTransactionLocked(
                evictTxid, "lower-feerate-capacity-eviction")) {
            Logger::log(
                "[Mempool] ERROR: planned eviction failed => " + evictTxid);
            feeIndex_.erase(incoming);
            rebuildFeeIndexLocked();
            return MempoolAddStatus::INVALID;
        }
    }

    // Commit all mempool resource + fee accounting under one mutex.
    pool_[tx.txid] = tx;
    txSerializedSizes_[tx.txid] = serializedSize;
    txFees_[tx.txid] = fee;

    for (const auto& vin : tx.vin) {
        spentInMempool.insert(
            makeUTXOKey(vin.txid, static_cast<uint32_t>(vin.vout)));
    }

    poolBytes_ += serializedSize;

    Logger::log(
        "[Mempool] Added TX => " + tx.txid +
        " fee=" + std::to_string(fee) +
        " bytes=" + std::to_string(serializedSize) +
        " poolTxs=" + std::to_string(pool_.size()) +
        " poolBytes=" + std::to_string(poolBytes_));
    // TX-RELAY-01: every newly admitted transaction, regardless of its type or
    // submission path, gets one bounded relay notification. This only queues a
    // txid while admission locks are held; the worker performs all socket I/O.
    chain_.queueAcceptedTransactionRelay(tx.txid);
    return MempoolAddStatus::SUCCESS;
}
//-------------------------------------------------------------
//		RM TX
//-------------------------------------------------------------
bool Mempool::eraseTransactionLocked(
    const std::string& txid,
    const char* reason) {

    auto it = pool_.find(txid);
    if (it == pool_.end()) return false;

    auto sizeForFee = txSerializedSizes_.find(txid);
    auto feeForIndex = txFees_.find(txid);
    if (sizeForFee != txSerializedSizes_.end() &&
        feeForIndex != txFees_.end()) {
        const std::size_t erased =
            feeIndex_.erase(
                FeeEntry{feeForIndex->second, sizeForFee->second, txid});
        if (erased != 1) {
            Logger::log(
                "[Mempool] WARNING: fee-index entry missing during erase => " +
                txid);
        }
    } else {
        Logger::log(
            "[Mempool] WARNING: fee accounting missing during erase => " +
            txid);
    }

    for (const auto& vin : it->second.vin) {
        if (vin.vout >= 0) {
            spentInMempool.erase(
                makeUTXOKey(vin.txid, static_cast<uint32_t>(vin.vout)));
        }
    }

    bool recalcBytes = false;
    auto sizeIt = txSerializedSizes_.find(txid);
    if (sizeIt != txSerializedSizes_.end()) {
        if (poolBytes_ >= sizeIt->second) {
            poolBytes_ -= sizeIt->second;
        } else {
            recalcBytes = true;
        }
        txSerializedSizes_.erase(sizeIt);
    } else {
        Logger::log(
            "[Mempool] WARNING: missing serialized-size accounting for TX => " +
            txid);
        recalcBytes = true;
    }

    if (recalcBytes) {
        poolBytes_ = 0;
        for (const auto& kv : txSerializedSizes_) {
            if (kv.second > tru_limits::MAX_MEMPOOL_BYTES ||
                poolBytes_ > tru_limits::MAX_MEMPOOL_BYTES - kv.second) {
                poolBytes_ = tru_limits::MAX_MEMPOOL_BYTES;
                break;
            }
            poolBytes_ += kv.second;
        }
    }

    txFees_.erase(txid);
    pool_.erase(it);
    Logger::log(
        std::string("[Mempool] Removed TX => ") + txid +
        " reason=" + (reason ? reason : "unspecified") +
        " poolTxs=" + std::to_string(pool_.size()) +
        " poolBytes=" + std::to_string(poolBytes_));
    return true;
}

void Mempool::rebuildFeeIndexLocked() {
    feeIndex_.clear();

    for (const auto& kv : pool_) {
        const auto sizeIt = txSerializedSizes_.find(kv.first);
        const auto feeIt = txFees_.find(kv.first);

        if (sizeIt == txSerializedSizes_.end() ||
            feeIt == txFees_.end() ||
            sizeIt->second == 0) {
            Logger::log(
                "[Mempool] WARNING: unable to rebuild fee index for TX => " +
                kv.first);
            continue;
        }

        feeIndex_.insert(
            FeeEntry{feeIt->second, sizeIt->second, kv.first});
    }
}

bool Mempool::removeTransaction(const std::string &txid) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (eraseTransactionLocked(txid, "explicit")) {
        return true;
    }

    // do NOT perform the old O(spent-set * pool * inputs) repair scan
    // for every not-found txid (applyBlock calls this for coinbase, too).
    // All marker/accounting mutations now happen atomically under mtx_.
    Logger::log("[Mempool] removeTransaction => TX not found => " + txid);
    return false;
}

//-------------------------------------------------------------
//
//-------------------------------------------------------------
bool Mempool::hasTransaction(const std::string &txid) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return (pool_.find(txid) != pool_.end());
}

//-------------------------------------------------------------
//
//-------------------------------------------------------------
bool Mempool::getTransaction(const std::string &txid, Transaction &outTx) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = pool_.find(txid);
    if (it == pool_.end()) {
        Logger::log("[Mempool] getTransaction => TX not found => " + txid);
        return false;
    }
    outTx = it->second;
    return true;
}
//-------------------------------------------------------------
//
//-------------------------------------------------------------
std::vector<Transaction> Mempool::getAllTransactions() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Transaction> result;
    result.reserve(pool_.size());
    for (const auto &pair : pool_) {
        result.push_back(pair.second);
    }
    Logger::log("[Mempool] getAllTransactions => returning " + std::to_string(result.size()) + " TX(s).");
    return result;
}

// Helper function to identify standard payment scripts
bool isStandardPaymentScript(const std::string& scriptPubKeyHex) {
    // P2PKH: 76a914<20-byte-hash>88ac, length 50 hex chars (25 bytes)
    if (scriptPubKeyHex.size() == 50 && 
        scriptPubKeyHex.substr(0, 6) == "76a914" && 
        scriptPubKeyHex.substr(46) == "88ac") {
        return true;
    }
    // P2SH: a914<20-byte-hash>87, length 46 hex chars (23 bytes)
    if (scriptPubKeyHex.size() == 46 && 
        scriptPubKeyHex.substr(0, 4) == "a914" && 
        scriptPubKeyHex.substr(44) == "87") {
        return true;
    }
    // Add other standard types (e.g., P2WPKH, P2WSH) if supported
    return false;
}
//___________________________________________________________
//            IS VALID TRANSACTION
//___________________________________________________________
bool Mempool::tryAcquireValidationSlot() const {
    std::lock_guard<std::mutex> lock(validationMutex_);
    if (activeValidations_ >=
        tru_limits::MAX_CONCURRENT_MEMPOOL_VALIDATIONS) {
        return false;
    }
    ++activeValidations_;
    return true;
}

void Mempool::releaseValidationSlot() const {
    std::lock_guard<std::mutex> lock(validationMutex_);
    if (activeValidations_ > 0) {
        --activeValidations_;
    }
}

MempoolValidationStatus Mempool::validateTransaction(
    const Transaction& tx,
    const Blockchain* blockchain) const {

    if (!tryAcquireValidationSlot()) {
        Logger::log(
            "[Mempool] Validation budget BUSY => " + tx.txid);
        return MempoolValidationStatus::BUSY;
    }

    struct ValidationSlotGuard {
        const Mempool* self;
        ~ValidationSlotGuard() {
            self->releaseValidationSlot();
        }
    } validationSlot{this};

    return isTransactionValidUnchecked(tx, blockchain)
        ? MempoolValidationStatus::VALID
        : MempoolValidationStatus::INVALID;
}

bool Mempool::isTransactionValidUnchecked(
    const Transaction& tx,
    const Blockchain* blockchain) const {

    // Public validator contract: malformed attacker input returns false; it must
    // not throw through wallet/RPC callers that use this method directly.
    try {
    if (!blockchain) {
        Logger::log("[Mempool] Blockchain pointer is null for TX => " + tx.txid);
        return false;
    }
    if (tx.vin.empty() || tx.vout.empty()) {
        Logger::log("[Mempool] Transaction has no inputs or outputs => " + tx.txid);
        return false;
    }
    if (tx.vin.size() > tru_limits::MAX_TX_INPUTS || tx.vout.size() > tru_limits::MAX_TX_OUTPUTS) {
        Logger::log("[Mempool] Transaction exceeds input/output limits => " + tx.txid);
        return false;
    }
    if (tx.isCoinbase) {
        Logger::log("[Mempool] Rejected coinbase TX => " + tx.txid);
        return false;
    }

    // Never trust a caller-supplied txid. Recompute from canonical content.
    if (tx.txid.size() != 64 || !isValidHex(tx.txid)) {
        Logger::log("[Mempool] Rejected malformed txid => " + tx.txid);
        return false;
    }
    try {
        Transaction canonical = tx;
        canonical.computeTxId();
        if (canonical.txid != tx.txid) {
            Logger::log(
                "[Mempool] Rejected txid/content mismatch: claimed=" + tx.txid +
                " computed=" + canonical.txid);
            return false;
        }
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Rejected TX: txid recomputation failed => " +
            tx.txid + ": " + e.what());
        return false;
    }

    // Metadata is carried by this transaction only. Arbitrary alternate keys
    // would make an unconfirmed transaction claim metadata for another txid.
    for (const auto& kv : tx.tokenMetadata) {
        if (kv.first != tx.txid) {
            Logger::log(
                "[Mempool] Rejected token metadata key not bound to txid => key=" +
                kv.first + " txid=" + tx.txid);
            return false;
        }
    }

    // relay parity for first stateful creation family.
    const auto stateCreation =
        tru_contract_call::ValidateStatefulCreationShape(tx);
    if (!stateCreation.valid) {
        Logger::log(
            "[Mempool] invalid stateful creation shape => TX=" + tx.txid +
            ": " + stateCreation.reason);
        return false;
    }
    if (stateCreation.hasCreation) {
        const char* family =
            stateCreation.family ==
                    tru_contract_call::StatefulCreationFamily::VotingV1
                ? "Voting V1"
                : stateCreation.family ==
                          tru_contract_call::StatefulCreationFamily::TokenIssuerV1
                      ? "Token Issuer V1"
                      : "Stateful K/V V1";
        Logger::log(
            std::string("[Mempool] ") + family +
            " creation accepted for target vout=" +
            std::to_string(stateCreation.targetVout) +
            " initBytes=" +
            std::to_string(stateCreation.accountedStateBytes));
    }

    uint64_t totalInput = 0;
    uint64_t txScriptOps = 0;
    uint64_t txSigOps = 0;
    uint64_t txGasUsed = 0;
    std::unordered_set<std::string> seenInputs;
    bool sawStatefulCallInput = false;

    // TOKEN-BURN-01 / TOKEN-CONTROL-POLICY-01:
    // Confirmed token-control outputs are ordinary P2PKH UTXOs at consensus
    // level today. Wallets already avoid spending them as plain TRU. Extend
    // that protection to mempool/relay: if a transaction consumes a CURRENT
    // token-control outpoint, it must recreate the exact raw token amount for
    // that tokenID in canonical token outputs. A burn remains valid because it
    // conserves the amount and changes only the owner to the canonical sink.
    //
    // POLICY ONLY: block validation is intentionally unchanged so this patch
    // cannot fork old nodes. A future activated consensus patch is required if
    // network-wide enforcement against custom block producers is desired.
    std::unordered_map<std::string, uint64_t> tokenControlInputAmounts;
    std::unordered_map<std::string, uint64_t> tokenControlOutputAmounts;

    // snapshot relay execution context once
    // per transaction from ONE active-tip view. OP_BLOCKTIME/stateful runtime
    // keeps the admission wall clock, while CLTV receives candidate-parent MTP
    // so relay and block consensus use the same maturity clock.
    std::string admissionTipHash;
    int admissionTipHeight = -1;
    chain_.getBestTipSnapshot(admissionTipHash, admissionTipHeight);
    if (admissionTipHeight < 0 || admissionTipHash.empty()) {
        Logger::log("[Mempool] Cannot build script context without an active tip");
        return false;
    }
    if (admissionTipHeight == std::numeric_limits<int>::max()) {
        Logger::log("[Mempool] Next execution height exceeds int range");
        return false;
    }
    const int admissionCandidateHeight = admissionTipHeight + 1;
    const uint64_t admissionExecHeight64 =
        static_cast<uint64_t>(admissionCandidateHeight);
    if (admissionExecHeight64 > std::numeric_limits<uint32_t>::max()) {
        Logger::log("[Mempool] Next execution height exceeds uint32_t");
        return false;
    }
    const uint32_t admissionExecHeight =
        static_cast<uint32_t>(admissionExecHeight64);
    const uint32_t admissionTime =
        static_cast<uint32_t>(std::time(nullptr));

    uint32_t admissionMedianTimePast = 0;
    try {
        admissionMedianTimePast = chain_.getMedianTimePast(
            admissionTipHash, admissionCandidateHeight);
    } catch (const std::exception& e) {
        Logger::log(
            std::string("[Mempool] Cannot derive candidate-parent MTP: ") +
            e.what());
        return false;
    }

    for (std::size_t i = 0; i < tx.vin.size(); ++i) {
        const TxIn& input = tx.vin[i];

        if (input.txid.size() != 64 || !isValidHex(input.txid) ||
            input.vout < 0) {
            Logger::log(
                "[Mempool] Rejected malformed input outpoint at #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }

        const uint32_t voutIndex = static_cast<uint32_t>(input.vout);
        const std::string outpoint = makeUTXOKey(input.txid, voutIndex);
        if (!seenInputs.insert(outpoint).second) {
            Logger::log(
                "[Mempool] Rejected duplicate input in one transaction => " +
                outpoint + " TX=" + tx.txid);
            return false;
        }

        if (input.scriptSig.size() > tru_limits::MAX_SCRIPT_BYTES) {
            Logger::log(
                "[Mempool] scriptSig exceeds size limit at input #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }

        UTXO utxo;
        if (!chain_.utxoSet.getUTXO(input.txid, voutIndex, utxo)) {
            Logger::log(
                "[Mempool] Missing UTXO => " + outpoint +
                " for TX => " + tx.txid);
            return false;
        }

        // TOKEN-CONTROL-POLICY-01: discover confirmed token-control inputs
        // from the CURRENT derived token index. This does not mutate state.
        if (const LevelDBStorage* tokenStorage = blockchain->getStorage()) {
            std::string tokenRecord;
            const std::string tokenKey = "tokenUTXO:" + outpoint;
            if (tokenStorage->getWithDataChecksum(tokenKey, tokenRecord)) {
                try {
                    const auto tokenJson = nlohmann::json::parse(tokenRecord);
                    const std::string tokenID =
                        tokenJson.value("tokenID", "");
                    if (tokenID.empty()) {
                        Logger::log(
                            "[TOKEN-CONTROL-POLICY-01] malformed current token record => " +
                            tokenKey);
                        return false;
                    }
                    const uint64_t amount =
                        tokenJson.at("amount").is_string()
                            ? std::stoull(
                                  tokenJson.at("amount").get<std::string>())
                            : tokenJson.at("amount").get<uint64_t>();
                    if (amount == 0) {
                        Logger::log(
                            "[TOKEN-CONTROL-POLICY-01] zero current token amount => " +
                            tokenKey);
                        return false;
                    }
                    uint64_t& sum = tokenControlInputAmounts[tokenID];
                    if (sum > std::numeric_limits<uint64_t>::max() - amount) {
                        Logger::log(
                            "[TOKEN-CONTROL-POLICY-01] token input amount overflow => TX=" +
                            tx.txid);
                        return false;
                    }
                    sum += amount;
                } catch (const std::exception& e) {
                    Logger::log(
                        "[TOKEN-CONTROL-POLICY-01] invalid current token record " +
                        tokenKey + ": " + e.what());
                    return false;
                }
            }
        }

        // the sole funding input of a new Stateful K/V
        // root is the durable owner identity. Require standard P2PKH now so
        // relay and confirmed application cannot disagree about ownership.
        if (stateCreation.hasCreation && i == 0) {
            std::string creatorHash160;
            if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                    utxo.scriptPubKey, creatorHash160)) {
                Logger::log(
                    "[Mempool] stateful V1 creator must fund from standard P2PKH => TX=" +
                    tx.txid);
                return false;
            }
        }

        if (utxo.amount > tru_limits::MAX_MONEY ||
            totalInput > tru_limits::MAX_MONEY - utxo.amount) {
            Logger::log(
                "[Mempool] Input value/sum exceeds MAX_MONEY => TX=" + tx.txid);
            return false;
        }
        totalInput += utxo.amount;

        if (utxo.isCoinbase) {
            const uint32_t maturesAt =
                utxo.createdAtHeight + static_cast<uint32_t>(COINBASE_MATURITY);
            if (admissionExecHeight <= utxo.createdAtHeight ||
                (admissionExecHeight - utxo.createdAtHeight) <
                    static_cast<uint32_t>(COINBASE_MATURITY)) {
                Logger::log(
                    "[Mempool] Rejected immature coinbase spend => " +
                    outpoint + " (created at height " +
                    std::to_string(utxo.createdAtHeight) +
                    ", tip " + std::to_string(admissionTipHeight) +
                    ", spendable at block " + std::to_string(maturesAt) +
                    ") for TX => " + tx.txid);
                return false;
            }
        }

        std::vector<unsigned char> scriptPubKey;
        try {
            scriptPubKey = hexDecode(utxo.scriptPubKey);
        } catch (const std::exception& e) {
            Logger::log(
                "[Mempool] Invalid UTXO scriptPubKey encoding => TX=" +
                tx.txid + ": " + e.what());
            return false;
        }

        if (scriptPubKey.empty() ||
            scriptPubKey.size() > tru_limits::MAX_SCRIPT_BYTES) {
            Logger::log("[Mempool] scriptPubKey is empty/oversized => TX=" + tx.txid);
            return false;
        }

        // mempool parity for leading OP_RETURN.
        // Patch 13A makes a confirmed UTXO whose locking script begins with
        // OP_RETURN consensus-unspendable in validateBlock(). Admission must
        // enforce the identical rule so an invalid spend cannot enter the
        // mempool or be selected into a doomed candidate block.
        if (scriptPubKey.front() == static_cast<unsigned char>(OP_RETURN)) {
            Logger::log(
                "[Mempool] Rejected spend of unspendable OP_RETURN UTXO => " +
                outpoint + " TX=" + tx.txid);
            return false;
        }

        ScriptResourceMetrics unlockMetrics, lockMetrics;
        if (!AnalyzeScriptResources(input.scriptSig, unlockMetrics) ||
            !AnalyzeScriptResources(scriptPubKey, lockMetrics)) {
            Logger::log("[Mempool] malformed/over-budget script => TX=" + tx.txid);
            return false;
        }
        // first mutable state activation.
        // Only the exact owner-bound Stateful K/V V1 anchor is executable.
        // State is loaded from the confirmed LevelDB root and copied into a
        // disposable scratch map; mempool admission never writes persistence.
        const auto statefulScan =
            tru_contract_call::ScanStatefulContractScript(scriptPubKey);
        if (!statefulScan.valid) {
            Logger::log("[Mempool] malformed stateful-script scan => TX=" + tx.txid);
            return false;
        }
        if (statefulScan.usesStateDomain) {
            const auto callShape =
                tru_contract_call::ValidateStatefulCallShape(
                    tx, i, utxo.scriptPubKey, utxo.amount);
            if (!callShape.valid) {
                Logger::log(
                    "[Mempool] invalid state-anchor call shape => TX=" + tx.txid +
                    ": " + callShape.reason);
                return false;
            }

            const std::string current =
                tru_contract_state::BuildCanonicalContractOutpoint(
                    input.txid, voutIndex);
            tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
            std::string stateReason;
            LevelDBStorage* confirmedStorage = chain_.getStorage();
            if (current.empty() || !confirmedStorage ||
                !tru_contract_state_runtime::LoadConfirmedStateDomain(
                    *confirmedStorage, current, snapshot, stateReason)) {
                Logger::log(
                    "[Mempool] confirmed state-domain load failed => TX=" +
                    tx.txid + ": " + stateReason);
                return false;
            }

            const TxIn& callerVin = tx.vin[callShape.callerInputIndex];
            if (callerVin.txid.size() != 64 ||
                !isValidHex(callerVin.txid) ||
                callerVin.vout < 0) {
                Logger::log("[Mempool] malformed stateful caller outpoint => TX=" + tx.txid);
                return false;
            }

            UTXO callerUtxo;
            const uint32_t callerVout =
                static_cast<uint32_t>(callerVin.vout);
            if (!chain_.utxoSet.getUTXO(callerVin.txid, callerVout, callerUtxo)) {
                Logger::log("[Mempool] missing caller funding UTXO for stateful call => TX=" + tx.txid);
                return false;
            }
            std::string callerHash160;
            if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                    callerUtxo.scriptPubKey, callerHash160)) {
                Logger::log("[Mempool] stateful V1 caller input must be standard P2PKH => TX=" + tx.txid);
                return false;
            }
            const std::string callerAddress =
                extractAddressFromScriptPubKey(
                    callerUtxo.scriptPubKey,
                    callerVin.txid, callerVout, &chain_);
            if (callerAddress.empty()) {
                Logger::log("[Mempool] unable to derive stateful caller address => TX=" + tx.txid);
                return false;
            }

            if (txGasUsed >= tru_limits::MAX_TX_SCRIPT_GAS) {
                Logger::log("[Mempool] transaction gas budget exhausted => TX=" + tx.txid);
                return false;
            }
            const uint64_t inputGasLimit = std::min(
                tru_limits::MAX_SCRIPT_GAS_PER_INPUT,
                tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed);
            if (inputGasLimit == 0) return false;

            uint64_t stateCallGasUsed = 0;
            std::string stateCallLabel;
            if (snapshot.family.empty()) {
                if (callerHash160 != snapshot.ownerHash160) {
                    Logger::log(
                        "[Mempool] rejected unauthorized Stateful K/V caller => TX=" +
                        tx.txid);
                    return false;
                }

                tru_contract_state_runtime::KvCallExecutionResult execResult;
                if (!tru_contract_state_runtime::ExecuteStatefulKvV1Call(
                        tx, callShape, scriptPubKey, snapshot, callerAddress,
                        admissionTime, admissionExecHeight, inputGasLimit,
                        &chain_, execResult, stateReason)) {
                    Logger::log(
                        "[Mempool] Stateful K/V V1 scratch execution failed => TX=" +
                        tx.txid + ": " + stateReason);
                    return false;
                }
                stateCallGasUsed = execResult.gasUsed;
                stateCallLabel = "Stateful K/V V1";
            } else if (snapshot.family == "voting_v1") {
                tru_contract_state_runtime::VotingCallExecutionResult execResult;
                if (!tru_contract_state_runtime::ExecuteVotingV1Call(
                        tx, callShape, scriptPubKey, snapshot,
                        callerHash160, callerAddress,
                        admissionTime, admissionExecHeight, inputGasLimit,
                        &chain_, execResult, stateReason)) {
                    Logger::log(
                        "[Mempool] Voting V1 scratch execution failed => TX=" +
                        tx.txid + ": " + stateReason);
                    return false;
                }
                stateCallGasUsed = execResult.gasUsed;
                stateCallLabel = "Voting V1";
            } else if (snapshot.family == "token_issuer_v1") {
                tru_contract_state_runtime::TokenIssuerCallExecutionResult execResult;
                if (!tru_contract_state_runtime::ExecuteTokenIssuerV1Call(
                        tx, callShape, scriptPubKey, snapshot,
                        callerHash160, callerAddress,
                        admissionTime, admissionExecHeight, inputGasLimit,
                        &chain_, execResult, stateReason)) {
                    Logger::log(
                        "[Mempool] Token Issuer V1 scratch execution failed => TX=" +
                        tx.txid + ": " + stateReason);
                    return false;
                }
                stateCallGasUsed = execResult.gasUsed;
                stateCallLabel = "Token Issuer V1";
            } else {
                Logger::log(
                    "[Mempool] unsupported stateful contract family => TX=" + tx.txid);
                return false;
            }

            if (unlockMetrics.opCount > UINT64_MAX - lockMetrics.opCount ||
                unlockMetrics.sigOpCost > UINT64_MAX - lockMetrics.sigOpCost) {
                return false;
            }
            const uint64_t addOps = unlockMetrics.opCount + lockMetrics.opCount;
            const uint64_t addSigOps = unlockMetrics.sigOpCost + lockMetrics.sigOpCost;
            if (addOps > tru_limits::MAX_TX_SCRIPT_OPS - txScriptOps ||
                addSigOps > tru_limits::MAX_TX_SIGOPS - txSigOps ||
                stateCallGasUsed > tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed) {
                Logger::log("[Mempool] stateful V1 resource budget exceeded => TX=" + tx.txid);
                return false;
            }
            txScriptOps += addOps;
            txSigOps += addSigOps;
            txGasUsed += stateCallGasUsed;
            sawStatefulCallInput = true;

            Logger::log(
                "[Mempool] " + stateCallLabel +
                " call accepted in scratch: root=" +
                snapshot.root + " current=" + current +
                " continuationVout=" +
                std::to_string(callShape.continuationVout) +
                " key=" + callShape.logicalKey +
                " callerHash160=" + callerHash160);
            continue;
        }
        if (unlockMetrics.opCount > UINT64_MAX - lockMetrics.opCount ||
            unlockMetrics.sigOpCost > UINT64_MAX - lockMetrics.sigOpCost) {
            return false;
        }
        const uint64_t addOps = unlockMetrics.opCount + lockMetrics.opCount;
        const uint64_t addSigOps = unlockMetrics.sigOpCost + lockMetrics.sigOpCost;
        if (addOps > tru_limits::MAX_TX_SCRIPT_OPS - txScriptOps ||
            addSigOps > tru_limits::MAX_TX_SIGOPS - txSigOps) {
            Logger::log("[Mempool] transaction script/sigop budget exceeded => TX=" + tx.txid);
            return false;
        }
        txScriptOps += addOps;
        txSigOps += addSigOps;

        std::vector<unsigned char> sighash =
            buildInputSighash(tx, i, scriptPubKey);
        if (sighash.empty()) {
            Logger::log(
                "[Mempool] Failed to build sighash for input #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }

        if (txGasUsed >= tru_limits::MAX_TX_SCRIPT_GAS) {
            Logger::log("[Mempool] transaction gas budget exhausted => TX=" + tx.txid);
            return false;
        }
        const uint64_t inputGasLimit = std::min(
            tru_limits::MAX_SCRIPT_GAS_PER_INPUT,
            tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed);
        if (inputGasLimit == 0) return false;

        // TRU Smart Contract Patch 14B/14B1 — relay context uses the same
        // base fields as consensus. Height/time are one transaction-level
        // admission snapshot; the future mined block header remains authoritative.
        const std::string inputSender =
            extractAddressFromScriptPubKey(
                utxo.scriptPubKey, input.txid, voutIndex, &chain_);
        const std::string contractIdentity =
            BuildContractIdentity(input.txid, voutIndex);
        if (contractIdentity.empty()) {
            Logger::log("[Mempool] Cannot derive contract identity => TX=" + tx.txid);
            return false;
        }

        ScriptExecutionContextSpec ctxSpec;
        ctxSpec.gasLimit = inputGasLimit;
        ctxSpec.tx = &tx;
        ctxSpec.blockTime = admissionTime;
        ctxSpec.medianTimePast = admissionMedianTimePast;
        ctxSpec.inputIndex = i;
        ctxSpec.scriptPubKey = &scriptPubKey;
        ctxSpec.sighash = sighash;
        ctxSpec.chainCtx = &chain_;
        ctxSpec.execHeight = admissionExecHeight;
        ctxSpec.sender = inputSender;
        ctxSpec.contractAddress = contractIdentity;
        // State remains unavailable in mempool until Patch 14D defines a
        // read-only persistent-state snapshot/overlay for relay execution.
        ScriptExecutionContext ctx = BuildScriptExecutionContext(ctxSpec);

        const std::string binarySighash(sighash.begin(), sighash.end());
        ctx.signatureCheckFunc = [binarySighash](
            const std::vector<unsigned char>& pubkey,
            const std::vector<unsigned char>& signature,
            const std::string&) {
            if (signature.empty()) {
                Logger::log("[Mempool] Signature too short");
                return false;
            }
            if (signature.back() != 0x01) {
                Logger::log(
                    "[Mempool] Invalid sighash type: " +
                    std::to_string(signature.back()));
                return false;
            }
            const std::vector<unsigned char> derSig(
                signature.begin(), signature.end() - 1);
            if (!ECDSAKey::verifyCanonicalTransactionSignature(
                    pubkey, binarySighash, derSig)) {
                Logger::log(
                    "[Mempool] ECDSA signature is invalid/non-canonical");
                return false;
            }
            return true;
        };

        std::vector<std::vector<unsigned char>> stack;
        if (!EvaluateScript(input.scriptSig, stack, ctx) ||
            !EvaluateScript(scriptPubKey, stack, ctx)) {
            Logger::log(
                "[Mempool] scriptSig+scriptPubKey execution failed => input #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }
        if (stack.empty() || stack.back().empty() || stack.back()[0] == 0) {
            Logger::log(
                "[Mempool] Script evaluation resulted in false => input #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }
        if (ctx.gasUsed > inputGasLimit ||
            ctx.gasUsed > tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed) {
            Logger::log("[Mempool] script gas accounting breach => TX=" + tx.txid);
            return false;
        }
        txGasUsed += ctx.gasUsed;
    }

    if (stateCreation.hasCallCandidate != sawStatefulCallInput) {
        Logger::log(
            "[Mempool] stateful call envelope/input parity failure => TX=" +
            tx.txid);
        return false;
    }

    uint64_t totalOutput = 0;
    for (const auto& out : tx.vout) {
        if (out.amount > tru_limits::MAX_MONEY ||
            totalOutput > tru_limits::MAX_MONEY - out.amount) {
            Logger::log(
                "[Mempool] Output value/sum exceeds MAX_MONEY => TX=" + tx.txid);
            return false;
        }
        totalOutput += out.amount;
    }

    if (totalInput < totalOutput) {
        Logger::log(
            "[Mempool] Transaction spends more than available: " + tx.txid +
            " (inputs=" + std::to_string(totalInput) +
            ", outputs=" + std::to_string(totalOutput) + ")");
        return false;
    }

    for (std::size_t i = 0; i < tx.vout.size(); ++i) {
        const TxOut& out = tx.vout[i];

        // Shape/byte limits apply before any special-script fast path.
        if (out.scriptPubKey.empty() ||
            (out.scriptPubKey.size() & 1U) != 0 ||
            out.scriptPubKey.size() / 2 > tru_limits::MAX_SCRIPT_BYTES ||
            !isValidHex(out.scriptPubKey)) {
            Logger::log(
                "[Mempool] scriptPubKey is malformed/oversized for output #" +
                std::to_string(i) + " => TX=" + tx.txid);
            return false;
        }

        if (isMagicLockScript(out.scriptPubKey)) {
            Logger::log(
                "[Mempool] Detected MagicLock script in output #" +
                std::to_string(i));
            continue;
        }

        if (isExtendedTokenScript(out.scriptPubKey)) {
            ExtendedTokenData td;
            std::string owner;
            if (parseExtendedTokenScript(
                    out.scriptPubKey, tx.txid, td, owner, blockchain)) {
                if (!isValidAddress(owner)) {
                    Logger::log(
                        "[Mempool] Invalid token owner address => " + owner +
                        " for TX => " + tx.txid);
                    return false;
                }
                if (td.tokenID.empty()) {
                    Logger::log(
                        "[Mempool] ExtendedTokenData tokenID is empty => TX=" +
                        tx.txid);
                    return false;
                }

                // Count canonical token outputs for the relay-only
                // token-control conservation check below.
                {
                    uint64_t& sum = tokenControlOutputAmounts[td.tokenID];
                    if (sum > std::numeric_limits<uint64_t>::max() - td.amount) {
                        Logger::log(
                            "[TOKEN-CONTROL-POLICY-01] token output amount overflow => TX=" +
                            tx.txid);
                        return false;
                    }
                    sum += td.amount;
                }

                switch (td.type) {
                    case TokenType::FT:
                    case TokenType::SFT:
                        if (td.amount == 0) {
                            Logger::log(
                                "[Mempool] Token amount cannot be zero => TX=" +
                                tx.txid);
                            return false;
                        }
                        break;
                    case TokenType::NFT:
                        if (td.amount != 1) {
                            Logger::log(
                                "[Mempool] NFT amount must be 1 => TX=" + tx.txid);
                            return false;
                        }
                        break;
                    case TokenType::NCFT:
                        break;
                    default:
                        Logger::log(
                            "[Mempool] Unknown token type => TX=" + tx.txid);
                        return false;
                }
            } else {
                std::vector<unsigned char> raw;
                try {
                    raw = hexDecode(out.scriptPubKey.substr(2));
                } catch (const std::exception&) {
                    Logger::log(
                        "[Mempool] Invalid OP_RETURN/token hex => TX=" + tx.txid);
                    return false;
                }
                if (raw.size() > 256) {
                    Logger::log(
                        "[Mempool] OP_RETURN data exceeds 256 bytes => TX=" +
                        tx.txid);
                    return false;
                }
            }
        } else if (!isStandardPaymentScript(out.scriptPubKey) &&
                   !isAllowedSmartContractScript(out.scriptPubKey)) {
            Logger::log(
                "[Mempool] Rejected non-standard output script => TX=" + tx.txid);
            return false;
        }
    }

    // TOKEN-CONTROL-POLICY-01: spending a confirmed token-control UTXO as
    // ordinary TRU is no longer relayed/mined by upgraded default nodes.
    // Exact conservation still permits normal transfer, split transfer and the
    // TOKEN-BURN-01 sink transfer. This is deliberately NOT block consensus.
    for (const auto& [tokenID, inputAmount] : tokenControlInputAmounts) {
        const auto outIt = tokenControlOutputAmounts.find(tokenID);
        const uint64_t outputAmount =
            outIt == tokenControlOutputAmounts.end() ? 0ULL : outIt->second;
        if (outputAmount != inputAmount) {
            Logger::log(
                "[TOKEN-CONTROL-POLICY-01] Rejecting token-control spend without exact token conservation: tokenID=" +
                tokenID + " input=" + std::to_string(inputAmount) +
                " output=" + std::to_string(outputAmount) +
                " TX=" + tx.txid);
            return false;
        }
    }

    Logger::log("[Mempool] Transaction is valid => " + tx.txid);
    return true;
    } catch (const std::exception& e) {
        Logger::log(
            "[Mempool] Validation exception => TX=" + tx.txid +
            ": " + e.what());
        return false;
    } catch (...) {
        Logger::log(
            "[Mempool] Unknown validation exception => TX=" + tx.txid);
        return false;
    }
}
//---------------------------------------------------
//		SIG HASH BUILD INPUT
//---------------------------------------------------
std::vector<unsigned char> Mempool::buildInputSighash(
    const Transaction &tx,
    size_t inputIndex,
    const std::vector<unsigned char> &scriptPubKey
) const {
    // one sighash implementation only.
    return tx.getSigHash(inputIndex, scriptPubKey);
}

void Mempool::cleanAfterBlock(const Block& block) {
    std::lock_guard<std::mutex> lock(mtx_);

    // Build the confirmed spend set once, then clean the bounded pool without
    // repeatedly scanning every block input for every mempool input.
    std::unordered_set<std::string> blockSpends;
    std::unordered_set<std::string> includedTxids;

    for (const auto& blockTx : block.transactions) {
        includedTxids.insert(blockTx.txid);
        if (blockTx.isCoinbase) continue;

        for (const auto& vin : blockTx.vin) {
            if (vin.vout < 0) continue;
            blockSpends.insert(
                makeUTXOKey(vin.txid, static_cast<uint32_t>(vin.vout)));
        }
    }

    std::vector<std::string> toRemove;
    toRemove.reserve(pool_.size());

    for (const auto& poolEntry : pool_) {
        if (includedTxids.count(poolEntry.first)) {
            toRemove.push_back(poolEntry.first);
            continue;
        }

        bool conflicts = false;
        for (const auto& vin : poolEntry.second.vin) {
            if (vin.vout < 0 ||
                blockSpends.count(
                    makeUTXOKey(
                        vin.txid, static_cast<uint32_t>(vin.vout)))) {
                conflicts = true;
                break;
            }
        }

        if (conflicts) toRemove.push_back(poolEntry.first);
    }

    for (const auto& txid : toRemove) {
        eraseTransactionLocked(txid, "confirmed-or-conflicted");
    }
}
