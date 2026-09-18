#include "utxo.h"
#include "tx.h"
#include "tokens.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include "opcodes.h"
#include "script_interpreter.h"
#include "utils.h"
#include "logging.h"
#include "address_helpers.h"
#include "blockchain.h"
#include "wallet.h"
#include <vector>
#include "tru_network_params.h"

static std::string extractAddressFromScriptTail(const std::string& scriptHex);
static bool looksLikeMagicLockScript(const std::string& scriptHex);

// Collect UTXOs owned by an address.
std::vector<UTXO> UTXOSet::getUTXOsForAddress(const std::string& address) const {
    std::vector<UTXO> result;

    // Iterate over all UTXO keys
    dbStorage.iteratePrefix("utxo:", [&](const std::string& keySansPrefix, const std::string& /*value*/) {
        // keySansPrefix should be "<txid>:<vout>"
        std::string key = keySansPrefix;

        // Defensive: if for any reason the prefix is still present, strip it
        if (key.rfind("utxo:", 0) == 0) {
            key = key.substr(5);
        }

        const size_t colonPos = key.find(':');
        if (colonPos == std::string::npos) {
            return; // malformed key
        }

        const std::string txid = key.substr(0, colonPos);
        uint32_t vout = 0;
        try {
            vout = static_cast<uint32_t>(std::stoul(key.substr(colonPos + 1)));
        } catch (...) {
            return; // bad vout
        }

        UTXO utxo;
        if (!getUTXO(txid, vout, utxo)) {
            return; // couldn't load UTXO entry
        }

        // Prefer canonical address derivation (uses chain context)
        std::string utxoAddress;
        if (blockchainPtr) {
            utxoAddress = getAddressFromUTXO(txid, vout, blockchainPtr);
        }

        // Fallbacks if needed
        if (utxoAddress.empty()) {
            // Reserved fallback: direct script address decoding (not implemented here).
            // utxoAddress = extractAddressFromScriptPubKey(utxo.scriptPubKey, txid, vout, blockchainPtr);
            // Reserved fallback: script-tail address decoding (not implemented here).
            // utxoAddress = extractAddressFromScriptTail(utxo.scriptPubKey);
        }

        if (utxoAddress == address) {
            // We already know txid/vout; ensure they’re set on the object
            utxo.txid = txid;
            utxo.vout = vout;
            result.push_back(std::move(utxo));
        }
    });

    return result;
}

//===================================================================
//			MagicLock Checker
//===================================================================
static std::string extractAddressFromScriptTail(const std::string& scriptHex) {
    size_t pos = scriptHex.find("76a914");
    if (pos == std::string::npos || pos + 6 + 40 + 4 > scriptHex.size()) {
        return "";
    }
    const std::string pkhHex = scriptHex.substr(pos + 6, 40);
    try {
        std::vector<uint8_t> pkh = hexDecode(pkhHex);

        // Build Base58Check for TRU mainnet P2PKH
        std::vector<uint8_t> payload;
        payload.reserve(1 + pkh.size() + 4);
        payload.push_back(tru_network::MAINNET_P2PKH_VERSION);
        payload.insert(payload.end(), pkh.begin(), pkh.end());

        unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
        SHA256(payload.data(), payload.size(), h1);
        SHA256(h1, SHA256_DIGEST_LENGTH, h2);

        payload.insert(payload.end(), h2, h2 + 4);
        return base58Encode(payload);
    } catch (...) {
        return "";
    }
}

//===================================================================
//			Magic Script Checker
//===================================================================
static bool looksLikeMagicLockScript(const std::string& scriptHex) {
    if (scriptHex.find("76a914") == std::string::npos) return false; // must have P2PKH tail
    // canonical: 7c aa ... 7f ... 88, legacy: 7c 76 aa ... 7f 88 or 6e 75 aa ... 7f 88
    return scriptHex.find("7caa")   != std::string::npos ||
           scriptHex.find("7c76aa") != std::string::npos ||
           scriptHex.find("6e75aa") != std::string::npos;
}

// --------------------------------------------------------------------
// A helper for decoding a hex string => raw bytes
// --------------------------------------------------------------------
static std::vector<unsigned char> parseHex(const std::string &hex)
{
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("[parseHex] hex string length is odd => " + hex);
    }
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        unsigned int byteVal = 0;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byteVal;
        out.push_back(static_cast<unsigned char>(byteVal));
    }
    return out;
}

// --------------------------------------------------------------------
// Convenience function to call VerifyScripts after decoding hex strings
// Updated to use non-const ScriptExecutionContext& to match VerifyScripts
// --------------------------------------------------------------------
bool VerifyScriptsHex(const std::string &scriptSigHex,
                      const std::string &scriptPubKeyHex,
                      ScriptExecutionContext &ctx)
{
    std::vector<unsigned char> sigBytes = parseHex(scriptSigHex);
    std::vector<unsigned char> pubBytes = parseHex(scriptPubKeyHex);
    return VerifyScripts(sigBytes, pubBytes, ctx);
}

//------------------------------------------------------------------------------
//                 Splits a string by spaces
//------------------------------------------------------------------------------
static std::vector<std::string> splitBySpace(const std::string &in)
{
    std::istringstream iss(in);
    std::vector<std::string> tokens;
    std::string t;
    while (iss >> t) {
        tokens.push_back(t);
    }
    return tokens;
}

//------------------------------------------------------
// Forward declare these script_interpreter.cpp
//------------------------------------------------------
extern bool VerifyScripts(const std::vector<unsigned char> &scriptSig,
                          const std::vector<unsigned char> &scriptPubKey,
                          ScriptExecutionContext &ctx);

extern std::vector<unsigned char> compileTextScript(const std::string &scriptText);

//------------------------------------------------------
//      SMART CONTRACT STATE MODIFY
//------------------------------------------------------
bool containsStateModifyingOpcode(const std::vector<unsigned char>& script) {
    for (size_t pc = 0; pc < script.size(); ) {
        unsigned char op = script[pc++];
        if (op == OP_STORE) { // 0xf7
            return true;
        }
        // Skip data pushes
        if (op > 0x00 && op <= 0x4B) {
            pc += op;
        } else if (op == OP_PUSHDATA1 && pc < script.size()) {
            pc += script[pc] + 1;
        } else if (op == OP_PUSHDATA2 && pc + 1 < script.size()) {
            pc += (script[pc] | (script[pc + 1] << 8)) + 2;
        } else if (op == OP_PUSHDATA4 && pc + 3 < script.size()) {
            pc += (script[pc] | (script[pc + 1] << 8) | (script[pc + 2] << 16) | (script[pc + 3] << 24)) + 4;
        }
    }
    return false;
}

//======================================================
//  BALANCE CACHE FOR THREAD-SAFE BALANCE MANAGEMENT
//======================================================
class BalanceCache {
private:
    std::unordered_map<std::string, double> cache;
    mutable std::shared_mutex mutex;

public:
    // Store balance in cache
    void setBalance(const std::string& addr, double balance) {
        std::unique_lock<std::shared_mutex> lock(mutex);
        cache[addr] = balance;
    }

    // Retrieve balance from cache, returns -1 if not found
    double getBalance(const std::string& addr) const {
        std::shared_lock<std::shared_mutex> lock(mutex);
        auto it = cache.find(addr);
        return it != cache.end() ? it->second : -1;
    }

    // Clear cache for a specific address
    void invalidate(const std::string& addr) {
        std::unique_lock<std::shared_mutex> lock(mutex);
        cache.erase(addr);
    }
};

// Global balance cache instance (singleton or managed externally)
static BalanceCache balanceCache;

//======================================================
//  SAFE BALANCE CALCULATION
//======================================================
double calculateBalanceSafely(const std::string& addr, Blockchain* blockchainPtr) {
    try {
        // Perform balance calculation without holding storage locks
        // This avoids deadlocks by deferring to blockchain's UTXO summation
        double balance = blockchainPtr->calculate_balance(addr);
        Logger::log("[calculateBalanceSafely] Calculated balance for " + addr + ": " + std::to_string(balance));
        balanceCache.setBalance(addr, balance); // Update cache
        return balance;
    } catch (const std::exception& e) {
        Logger::log("[calculateBalanceSafely] ERROR calculating balance for " + addr + ": " + e.what());
        return 0.0; // Fallback to zero to prevent transaction failure
    }
}

//======================================================
//  APPLY TRANSACTION TO UTXO SET
//======================================================
ApplyTransactionResult UTXOSet::applyTransaction(
    const Transaction& tx,
    int blockHeight,
    Blockchain* blockchainPtr,
    ScriptExecutionContext& ctx
) {
    ApplyTransactionResult result;
    result.success = false;
    Logger::log("[applyTransaction] Processing transaction with txid: " + tx.txid);

    try {
        LevelDBStorage* storage = blockchainPtr->getStorage();
        if (!storage) {
            throw std::runtime_error("Blockchain or storage not available");
        }

        auto buildValue = [&](uint64_t amount, const std::string &scriptHex, bool coinbase)
        {
            std::ostringstream oss;
            oss << "height=" << blockHeight << "|" << amount << "|" << scriptHex;
            if (coinbase)
                oss << "|cb=1";
            return oss.str();
        };

        std::unordered_set<std::string> involvedAddresses;

        // Process inputs (non-coinbase)
        uint64_t inputSum = 0;
        if (!tx.isCoinbase)
        {
            for (const auto &vin : tx.vin)
            {
                std::string utxoKey = "utxo:" + vin.txid + ":" + std::to_string(vin.vout);
                std::string utxoVal;

                // Prefer the checksummed read for integrity
                if (!storage->getWithDataChecksum(utxoKey, utxoVal))
                {
                    throw std::runtime_error("Spent UTXO not found: " + utxoKey);
                }

                // Parse "height=<H>|<amount>|<scriptHex>[|cb=1]"
                size_t firstDelim = utxoVal.find('|');
                size_t secondDelim = utxoVal.find('|', firstDelim + 1);
                if (firstDelim == std::string::npos || secondDelim == std::string::npos)
                {
                    throw std::runtime_error("Malformed UTXO data for " + utxoKey + " value=" + utxoVal);
                }

                uint64_t spentAmount = std::stoull(utxoVal.substr(firstDelim + 1, secondDelim - firstDelim - 1));
                inputSum += spentAmount;

                // Indexing convenience only (may be empty for custom scripts)
                std::string addr = getAddressFromUTXO(vin.txid, vin.vout, blockchainPtr);
                if (!addr.empty())
                {
                    involvedAddresses.insert(addr);
                }

                // ALWAYS delete the UTXO once it is spent
                result.utxosToDelete.insert(utxoKey);
                Logger::log("[applyTransaction] Scheduled UTXO deletion: " + utxoKey);
            }
        }
        else
        {
            Logger::log("[applyTransaction] Coinbase transaction, skipping inputs");
        }
        // Process outputs
        uint64_t outputSum = 0;
        std::vector<std::pair<size_t, ExtendedTokenData>> tokenOutputs;
        
        for (size_t idx = 0; idx < tx.vout.size(); ++idx) {
            const auto& out = tx.vout[idx];
            outputSum += out.amount;
            Logger::log("[applyTransaction] Processing output #" + std::to_string(idx));

            // Check for OP_RETURN output
            if (out.scriptPubKey.substr(0, 2) == "6a" && out.amount == 0) {
                // First try to parse as TRUScript
                nlohmann::json truScriptData;
                if (parseTRUScriptFromOPReturn(out.scriptPubKey, tx.txid, truScriptData, blockchainPtr)) {
                    // Handle TRUScript
                    if (truScriptData["type"] == "TRUSCRIPT") {
                        // New TRUScript inscription - handled by extractTokenMetadata in Block
                        Logger::log("[applyTransaction] Found TRUScript inscription in tx " + tx.txid);
                    } else if (truScriptData["type"] == "TRUSCRIPT_TRANSFER") {
                        // TRUScript transfer
                        std::string inscriptionTxid = truScriptData.value("inscription", "");
                        std::string to = truScriptData.value("to", "");
                        
                        Logger::log("[applyTransaction] Processing TRUScript transfer for " + 
                                  inscriptionTxid + " to " + to);
                        
                        if (!inscriptionTxid.empty() && storage) {
                            // Update the inscription's current owner
                            std::string metaKey = "tokenMetadata:" + inscriptionTxid;
                            std::string metaValue;
                            
                            if (storage->getWithDataChecksum(metaKey, metaValue)) {
                                nlohmann::json inscriptionMeta = nlohmann::json::parse(metaValue);
                                inscriptionMeta["owner"] = to;
                                inscriptionMeta["currentTxid"] = tx.txid;
                                inscriptionMeta["lastTransfer"] = tx.txid;
                                
                                std::string updatedMeta = inscriptionMeta.dump();
                                result.batch.Put(metaKey, storage->computeDataChecksum(updatedMeta) + "|" + updatedMeta);
                                
                                Logger::log("[applyTransaction] Updated TRUScript owner for " + 
                                          inscriptionTxid);
                            } else {
                                // Metadata not found locally - this happens when receiving blocks from network
                                // Create minimal metadata from transfer data
                                Logger::log("[applyTransaction] TRUScript metadata not found locally for " +
                                            inscriptionTxid + ", creating from transfer");

                                nlohmann::json inscriptionMeta;
                                inscriptionMeta["type"] = "TRUSCRIPT";
                                inscriptionMeta["creationTxid"] = inscriptionTxid;
                                inscriptionMeta["currentTxid"] = tx.txid;
                                inscriptionMeta["owner"] = to;
                                inscriptionMeta["lastTransfer"] = tx.txid;

                                // Copy additional data from transfer if available
                                if (truScriptData.contains("data"))
                                {
                                    inscriptionMeta["data"] = truScriptData["data"];
                                }
                                if (truScriptData.contains("inscriptionIndex"))
                                {
                                    inscriptionMeta["inscriptionIndex"] = truScriptData["inscriptionIndex"];
                                }
                                if (truScriptData.contains("satNumber"))
                                {
                                    inscriptionMeta["satNumber"] = truScriptData["satNumber"];
                                }
                                if (truScriptData.contains("creationTimestamp"))
                                {
                                    inscriptionMeta["timestamp"] = truScriptData["creationTimestamp"];
                                }

                                std::string updatedMeta = inscriptionMeta.dump();
                                result.batch.Put(metaKey, storage->computeDataChecksum(updatedMeta) + "|" + updatedMeta);

                                Logger::log("[applyTransaction] Created TRUScript metadata for " +
                                            inscriptionTxid);
                            }
                        }
                    }
                    // Skip to next output - this was a TRUScript
                    continue;
                }
                
                // Not a TRUScript, try parsing as extended token
                ExtendedTokenData tokenData;
                std::string ownerAddress;
                
                if (parseExtendedTokenScript(out.scriptPubKey, tx.txid, tokenData, ownerAddress, blockchainPtr)) {
                    Logger::log("[applyTransaction] Found token output: tokenID=" + tokenData.tokenID + 
                               ", owner=" + ownerAddress + ", amount=" + std::to_string(tokenData.amount));
                    
                    // Store token data for later processing
                    tokenOutputs.push_back({idx, tokenData});
                    
                    // The owner address should be tracked
                    if (!ownerAddress.empty()) {
                        involvedAddresses.insert(ownerAddress);
                    }
                    
                    // Create the tokenUTXO entry
                    uint32_t controllingVout = idx + 1; // Controlling output is typically next
                    
                    // Verify controlling output exists and matches owner
                    if (controllingVout < tx.vout.size()) {
                        std::string controllingAddr = extractAddressFromScriptPubKey(
                            tx.vout[controllingVout].scriptPubKey, tx.txid, controllingVout, blockchainPtr);
                        
                        if (controllingAddr == ownerAddress) {
                            // Create tokenUTXO entry
                            std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":" + std::to_string(controllingVout);
                            nlohmann::json tokenUtxoData = {
                                {"tokenID", tokenData.tokenID},
                                {"amount", std::to_string(tokenData.amount)},
                                {"owner", ownerAddress},
                                {"type", tokenTypeToString(tokenData.type)},
                                {"controllingVout", controllingVout}
                            };
                            
                            std::string tokenUtxoValue = tokenUtxoData.dump();
                            result.batch.Put(tokenUtxoKey, storage->computeDataChecksum(tokenUtxoValue) + "|" + tokenUtxoValue);
                            Logger::log("[applyTransaction] Created tokenUTXO entry at " + tokenUtxoKey);
                            
                            // Create ownership index
                            std::string indexKey = "tokenOwnerUTXO:" + tokenData.tokenID + ":" + 
                                                  ownerAddress + ":" + tx.txid + ":" + std::to_string(controllingVout);
                            std::string indexValue = "1";
                            result.batch.Put(indexKey, storage->computeDataChecksum(indexValue) + "|" + indexValue);
                            Logger::log("[applyTransaction] Created token ownership index: " + indexKey);
                            
                            // Update token ownership balance
                            std::string ownershipKey = "tokenOwnership:" + ownerAddress + ":" + tokenData.tokenID;
                            std::string existingOwnership;
                            nlohmann::json ownershipData;
                            
                            if (storage->getWithDataChecksum(ownershipKey, existingOwnership)) {
                                try {
                                    ownershipData = nlohmann::json::parse(existingOwnership);
                                    uint64_t currentAmount = ownershipData["amount"].is_string() ? 
                                        std::stoull(ownershipData["amount"].get<std::string>()) : 
                                        ownershipData["amount"].get<uint64_t>();
                                    ownershipData["amount"] = std::to_string(currentAmount + tokenData.amount);
                                } catch (...) {
                                    ownershipData = {{"amount", std::to_string(tokenData.amount)}, {"txid", tx.txid}};
                                }
                            } else {
                                ownershipData = {{"amount", std::to_string(tokenData.amount)}, {"txid", tx.txid}};
                            }
                            
                            std::string ownershipValue = ownershipData.dump();
                            result.batch.Put(ownershipKey, storage->computeDataChecksum(ownershipValue) + "|" + ownershipValue);
                            Logger::log("[applyTransaction] Updated token ownership for " + ownerAddress);
                        }
                    }
                }
                
                // Skip to next output - this was an OP_RETURN
                continue;
            }

            // Process regular UTXO
            std::string addr = extractAddressFromScriptPubKey(out.scriptPubKey, tx.txid, static_cast<uint32_t>(idx), blockchainPtr);
            //if (addr.empty() || out.amount == 0) {
            //    Logger::log("[applyTransaction] Skipping dust/non-P2PKH output");
            //    continue;
            //}

            if (addr.empty())
            {
                addr = extractAddressFromScriptTail(out.scriptPubKey);
            }

            if (out.amount == 0)
            {
                Logger::log("[applyTransaction] Skipping zero-amount output");
                continue;
            }

            if (addr.empty())
            {
                // canonical addressless contract UTXOs.
                //
                // Hash Lock V1 intentionally has no embedded P2PKH address:
                //     OP_HASH160 <20-byte HASH160> OP_EQUAL
                //     a9 14 <40 hex chars> 87
                //
                // Prior code preserved addressless MagicLock outputs but silently
                // discarded canonical Hash Lock outputs from the confirmed UTXO set.
                // That made a mined Hash Lock visible in contract history while
                // impossible to redeem because getUTXO(txid:vout) returned NotFound.
                const bool canonicalHashLock =
                    out.scriptPubKey.size() == 46 &&
                    out.scriptPubKey.compare(0, 4, "a914") == 0 &&
                    out.scriptPubKey.compare(44, 2, "87") == 0 &&
                    std::all_of(
                        out.scriptPubKey.begin(),
                        out.scriptPubKey.end(),
                        [](unsigned char c) { return std::isxdigit(c) != 0; });

                const bool addresslessSupportedContract =
                    looksLikeMagicLockScript(out.scriptPubKey) || canonicalHashLock;

                if (addresslessSupportedContract)
                {
                    std::string utxoVal =
                        buildValue(out.amount, out.scriptPubKey, tx.isCoinbase);
                    result.utxosToAdd.emplace_back(
                        tx.txid,
                        static_cast<uint32_t>(idx),
                        /*addr*/ "",
                        utxoVal);
                    Logger::log(
                        std::string("[applyTransaction] Scheduled addressless contract UTXO addition type=") +
                        (canonicalHashLock ? "HASH_LOCK" : "MAGIC_LOCK") +
                        " outpoint=" + tx.txid + ":" + std::to_string(idx));
                    // Addressless contracts are deliberately not indexed under
                    // address:<addr>:utxo. They remain canonical utxo:<txid>:<vout>
                    // records and are spent through their dedicated contract path.
                    continue;
                }

                Logger::log(
                    "[applyTransaction] Skipping unsupported addressless non-P2PKH output");
                continue;
            }

            involvedAddresses.insert(addr);
            std::string utxoVal = buildValue(out.amount, out.scriptPubKey,tx.isCoinbase);
            result.utxosToAdd.emplace_back(tx.txid, static_cast<uint32_t>(idx), addr, utxoVal);
            Logger::log("[applyTransaction] Scheduled UTXO addition: " + tx.txid + ":" + std::to_string(idx));
        }

        // Validate input sum >= output sum for non-coinbase transactions
        if (!tx.isCoinbase && inputSum < outputSum) {
            throw std::runtime_error("Insufficient input funds: inputSum=" + std::to_string(inputSum) + ", outputSum=" + std::to_string(outputSum));
        }

        // Store transaction IDs for each involved address
        for (const auto& addr : involvedAddresses) {
            std::string txKey = "address:" + addr + ":tx:" + tx.txid;
            result.batch.Put(txKey, "1");
            Logger::log("[applyTransaction] Scheduled transaction storage for address: " + addr + ", txid: " + tx.txid);
        }

        result.success = true;
        Logger::log("[applyTransaction] Transaction " + tx.txid + " processed successfully");
    } catch (const std::exception& ex) {
        Logger::log("[applyTransaction] EXCEPTION: " + std::string(ex.what()));
        result.success = false;
    }

    return result;
}
//============================================================================
//
//============================================================================
uint64_t UTXOSet::calculateBalanceFromUTXOs(const std::string& address, const LevelDBStorage* storage) const {
    uint64_t balance = 0;
    std::string prefix = "utxo:";
    storage->iteratePrefix(prefix, [&](const std::string& key, const std::string& utxoVal) {
        size_t firstDelim = utxoVal.find('|');
        size_t secondDelim = utxoVal.find('|', firstDelim + 1);
        if (firstDelim != std::string::npos && secondDelim != std::string::npos) {
            uint64_t amount = std::stoull(utxoVal.substr(firstDelim + 1, secondDelim - firstDelim - 1));
            std::string scriptPubKey = utxoVal.substr(secondDelim + 1);

            // drop the persisted coinbase flag before address
            // extraction.
            //
            // UTXO records are written (see storeUTXO, ~line 272) as:
            //     height=<H>|<amount>|<scriptHex>
            //     height=<H>|<amount>|<scriptHex>|cb=1     (coinbase)
            //
            // Taking everything after the second delimiter therefore handed
            // "76a914...88ac|cb=1" to extractAddressFromScriptPubKey() for
            // every mining reward. This is the same defect getAllUTXOs()
            // already carries a FIX(patch23b) for; this function was missed.
            //
            // Deliberately NOT rewritten as "take field [2] of a '|' split":
            // token UTXOs legitimately store an owner suffix inside the script
            // field (updateTokenMetadata builds
            // buildExtendedTokenScript(token) + "|" + owner), so a blanket
            // field-2 rule would truncate every token script at the owner
            // boundary. Strip only the coinbase flag, which is never a valid
            // owner string and never appears on a token output.
            {
                static const std::string kCoinbaseSuffix = "|cb=1";
                if (scriptPubKey.size() >= kCoinbaseSuffix.size() &&
                    scriptPubKey.compare(scriptPubKey.size() - kCoinbaseSuffix.size(),
                                         kCoinbaseSuffix.size(),
                                         kCoinbaseSuffix) == 0) {
                    scriptPubKey.erase(scriptPubKey.size() - kCoinbaseSuffix.size());
                }
            }

            // Extract txid from beginning of key to first colon
            // Note: key already has "utxo:" prefix removed by iteratePrefix
            size_t colonPos = key.find(':');
            if (colonPos == std::string::npos) {
                Logger::log("[calculateBalanceFromUTXOs] Invalid key format (no colon): " + key);
                return;
            }
            std::string txid = key.substr(0, colonPos);
            // Extract vout after the colon
            uint32_t vout = std::stoi(key.substr(colonPos + 1));
            std::string addr = extractAddressFromScriptPubKey(scriptPubKey, txid, vout, blockchainPtr);

            if (addr.empty()) {
                addr = extractAddressFromScriptTail(scriptPubKey);
            }

            // this function used to fail silently. A UTXO whose
            // address could not be resolved was simply never counted, with no
            // trace anywhere, which is exactly why the explorer/CLI balance
            // gap was so hard to localise. Say something.
            if (addr.empty()) {
                Logger::log("[calculateBalanceFromUTXOs] could not extract address for "
                            + txid + ":" + std::to_string(vout)
                            + " amount=" + std::to_string(amount)
                            + " script=" + scriptPubKey);
                return;
            }

            if (addr == address) {
                balance += amount;
            }
        }
    });
    return balance;
}
/*
uint64_t UTXOSet::calculateBalanceFromUTXOs(const std::string& address, const LevelDBStorage* storage) const {
    uint64_t balance = 0;
    std::string prefix = "utxo:";
    storage->iteratePrefix(prefix, [&](const std::string& key, const std::string& utxoVal) {
        size_t firstDelim = utxoVal.find('|');
        size_t secondDelim = utxoVal.find('|', firstDelim + 1);
        if (firstDelim != std::string::npos && secondDelim != std::string::npos) {
            uint64_t amount = std::stoull(utxoVal.substr(firstDelim + 1, secondDelim - firstDelim - 1));
            std::string scriptPubKey = utxoVal.substr(secondDelim + 1);
            // Fixed: Extract txid from beginning of key to first colon
            size_t colonPos = key.find(':');
            if (colonPos == std::string::npos) {
                Logger::log("[calculateBalanceFromUTXOs] Invalid key format (no colon): " + key);
                return;
            }
            std::string txid = key.substr(0, colonPos);
            // Extract vout after the colon
            uint32_t vout = std::stoi(key.substr(colonPos + 1));
            std::string addr = extractAddressFromScriptPubKey(scriptPubKey, txid, vout, blockchainPtr);
            if (addr == address) {
                balance += amount;
            }
        }
    });
    return balance;
}
*/
//============================================================================
//			FIND UTXO
//============================================================================
UTXO UTXOSet::findTokenUTXO(const std::string& tokenID, const std::string& owner) const {
    std::string prefix = "tokenOwnerUTXO:" + tokenID + ":" + owner + ":";
    std::string foundKey;
    Logger::log("[findTokenUTXO] Looking for tokenID=" + tokenID + " owner=" + owner);

    dbStorage.iteratePrefix(prefix, [&](const std::string& key, const std::string& value) {
        if (!foundKey.empty()) return; // Take the first match
        foundKey = key;
    });

    if (foundKey.empty()) {
        throw std::runtime_error("[findTokenUTXO] No UTXO found for tokenID=" + tokenID + " and owner=" + owner);
    }

    // Extract txid and vout from foundKey (format: tokenOwnerUTXO:tokenID:owner:txid:vout)
    size_t colonPos = prefix.length();
    size_t nextColon = foundKey.find(':', colonPos);
    if (nextColon == std::string::npos) {
        throw std::runtime_error("[findTokenUTXO] Invalid index key format: " + foundKey);
    }
    std::string txid = foundKey.substr(colonPos, nextColon - colonPos);
    std::string voutStr = foundKey.substr(nextColon + 1);
    uint32_t vout = std::stoi(voutStr);

    UTXO utxo;
    if (!getUTXO(txid, vout, utxo)) {
        throw std::runtime_error("[findTokenUTXO] UTXO not found for " + txid + ":" + std::to_string(vout));
    }
    Logger::log("[findTokenUTXO] Found UTXO: " + txid + ":" + std::to_string(vout));
    return utxo;
}
//-----------------------------------------------------------------------------
// Unimplemented cryptographic verification; this stub requires replacement before production use.
// (using OpenSSL, libsodium, etc.).
//------------------------------------------------------------------------------
static bool verifyMetadataSignature(const std::string &newMetadataJson,
                                    const std::string &cryptoSignature)
{
    // Demonstration stub: verification unconditionally succeeds.
    return true;
}

//==================================================================================
//			TRUScripts UTXO
//==================================================================================
std::vector<UTXO> UTXOSet::getAllUTXOs() const {
    std::shared_lock lock(mtx);
    Logger::log("[getAllUTXOs] ⏳ Starting enumeration of all live UTXOs");

    std::vector<UTXO> all;
    all.reserve(1024);

    dbStorage.iteratePrefix("utxo:", [&](const std::string &key, const std::string &raw) {
        // first, log *everything* coming out of LevelDB
        Logger::log("[getAllUTXOs] 🔸 Raw entry: key=" + key + "  value=\"" + raw + "\"");

        // now split on '|'  
        std::vector<std::string> parts;
        size_t start = 0, pos;
        while ((pos = raw.find('|', start)) != std::string::npos) {
            parts.push_back(raw.substr(start, pos - start));
            start = pos + 1;
        }
        parts.push_back(raw.substr(start));

        // fields after parts[2] are persisted metadata
        // such as cb=1. They must not cause a valid UTXO to be discarded.
        if (parts.size() < 3) {
            Logger::log("[getAllUTXOs] ⚠️  Unexpected format (need at least 3 parts): got " 
                        + std::to_string(parts.size()) + " — skipping");
            return;
        }

        // parts[0] == "height=NNN", parts[1] == amount, parts[2] == scriptHex
        auto &amountStr = parts[1];
        auto &scriptHex = parts[2];

        uint64_t amount = 0;
        try {
            amount = std::stoull(amountStr);
        } catch (const std::exception &e) {
            Logger::log("[getAllUTXOs] ⚠️  Bad amount \"" + amountStr + "\": " + e.what());
            return;
        }

        // parse out txid and vout from the key
        // key is already without "utxo:" prefix due to iteratePrefix
        auto colon = key.rfind(':');
        if (colon == std::string::npos) {
            Logger::log("[getAllUTXOs] ⚠️  Bad key format: " + key);
            return;
        }

        UTXO u;
        u.txid = key.substr(0, colon);
        u.vout = static_cast<uint32_t>(std::stoul(key.substr(colon + 1)));
        u.amount = amount;
        u.scriptPubKey = scriptHex;

        Logger::log("[getAllUTXOs] ➕ Parsed UTXO: " 
            + u.txid + ":" + std::to_string(u.vout)
            + ", amount=" + std::to_string(u.amount)
        );
        all.push_back(std::move(u));
    });

    Logger::log("[getAllUTXOs] 🔢 Total UTXOs returned: " + std::to_string(all.size()));
    std::sort(all.begin(), all.end(), [](auto const &A, auto const &B){
        if (A.txid != B.txid) return A.txid < B.txid;
        return A.vout < B.vout;
    });
    return all;
}
//------------------------------------------------------------------------------
//                     UTXOSet Implementation
//------------------------------------------------------------------------------
void UTXOSet::loadTokenRegistry() {
    std::unique_lock<std::shared_mutex> lock(mtx);
    seenTokens.clear();

    dbStorage.iterateAll([&](const std::string &key, const std::string &value) {
        static const std::string registryPrefix = "tokenRegistry:";
        if (key.compare(0, registryPrefix.size(), registryPrefix) == 0) {
            std::string tokenID = key.substr(registryPrefix.size());
            seenTokens.insert(tokenID);
        }
    });

    std::cout << "[UTXOSet] Token Registry loaded successfully. "
              << seenTokens.size() << " tokens registered." << std::endl;
}

UTXOSet::UTXOSet(const std::string &dbPath, Blockchain* blockchainPtr, bool loadRegistry)
    : dbStorage(dbPath), blockchainPtr(blockchainPtr) {
    // validation sandboxes query the copied LevelDB directly and
    // never consult seenTokens. Avoid a full-database registry scan/materialize
    // on every sandbox construction.
    if (loadRegistry) loadTokenRegistry();
}

UTXOSet::~UTXOSet() {
    // Do nothing here because dbStorage will be closed when the process ends.
}

std::string UTXOSet::makeUTXOKey(const std::string &txid, uint32_t vout) const {
    return txid + ":" + std::to_string(vout);
}

std::string UTXOSet::retrieveOriginalUTXO(const std::string &txid,
                                          uint32_t vout) const
{
    std::string bareKey = makeUTXOKey(txid, vout);
    std::string key     = "utxo:" + bareKey;

    std::string original;
    if (!dbStorage.getWithDataChecksum(key, original)) {
        throw std::runtime_error("[UTXOSet] Failed to retrieve original UTXO: " + key);
    }
    return original;
}

void UTXOSet::iterateAll(std::function<void(const std::string &, const std::string &)> callback) const {
    std::shared_lock<std::shared_mutex> lock(mtx);
    dbStorage.iterateAll(callback);
}

bool UTXOSet::rollbackTransaction(const Transaction &tx)
{
    std::unique_lock<std::shared_mutex> lock(mtx);

    // 1) remove any UTXOs this tx created
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        std::string bareKey = makeUTXOKey(tx.txid, i);
        std::string key     = "utxo:" + bareKey;
        if (!dbStorage.del(key)) {
            throw std::runtime_error("[UTXOSet] Failed to remove UTXO: " + key);
        }
    }

    // 2) restore the originals for each input (unless coinbase)
    if (!tx.isCoinbase) {
        for (const auto &vin : tx.vin) {
            std::string bareKey = makeUTXOKey(vin.txid, vin.vout);
            std::string key     = "utxo:" + bareKey;
            std::string originalUTXO = retrieveOriginalUTXO(vin.txid, vin.vout);
            if (!dbStorage.putWithDataChecksum(key, originalUTXO)) {
                throw std::runtime_error("[UTXOSet] Failed to restore UTXO: " + key);
            }
        }
    }

    return true;
}

bool UTXOSet::exists(const std::string &txid, uint32_t vout) const {
    std::shared_lock<std::shared_mutex> lock(mtx);
    // TOKEN-AI-02E V4 / UTXO-R1: UTXOs are stored under the canonical
    // "utxo:<txid>:<vout>" namespace and checksum-wrapped. Existence must
    // query that same canonical key and validate the stored checksum.
    const std::string key = "utxo:" + makeUTXOKey(txid, vout);
    std::string utxoData;
    return dbStorage.getWithDataChecksum(key, utxoData);
}

bool UTXOSet::getUTXO(const std::string &txid,
                      uint32_t vout,
                      UTXO &utxo) const
{
    Logger::log("[getUTXO] Retrieving UTXO for txid: " + txid +
                ", vout: " + std::to_string(vout));

    const std::string bareKey = makeUTXOKey(txid, vout);
    const std::string key     = "utxo:" + bareKey;

    std::string raw;
    {
        std::shared_lock<std::shared_mutex> lock(mtx);
        if (!dbStorage.getWithDataChecksum(key, raw)) {
            Logger::log("[getUTXO] UTXO not found for key: " + key);
            return false;
        }
    }

    // Split "height=<H>|<amount>|<scriptHex>[|cb=1]"
    std::vector<std::string> parts;
    {
        std::string token;
        std::istringstream iss(raw);
        while (std::getline(iss, token, '|')) parts.push_back(token);
    }

    // Allow 3 (legacy) or 4 (with cb=1) parts  // NEW
    if (parts.size() < 3 || parts.size() > 4) {
        Logger::log("[getUTXO] ERROR: Expected 3 or 4 parts, got " + std::to_string(parts.size())
                    + " for value: " + raw);
        return false;
    }

    const std::string& partHeight    = parts[0]; // "height=<H>"
    const std::string& partAmount    = parts[1];
    const std::string& partScriptHex = parts[2];

    // Parse amount
    uint64_t atoms = 0;
    try {
        if (partAmount.empty()) {
            Logger::log("[getUTXO] ERROR: Amount is empty");
            return false;
        }
        atoms = std::stoull(partAmount);
    } catch (const std::exception &ex) {
        Logger::log("[getUTXO] ERROR: Failed to parse amount '" + partAmount + "': " + ex.what());
        return false;
    }

    // Parse height=N from "height=<H>"                    // NEW
    uint32_t createdAtHeight = 0;
    {
        auto eq = partHeight.find('=');
        if (eq == std::string::npos) {
            Logger::log("[getUTXO] WARN: Missing '=' in height part: " + partHeight);
        } else {
            try {
                createdAtHeight = static_cast<uint32_t>(std::stoul(partHeight.substr(eq + 1)));
            } catch (const std::exception& ex) {
                Logger::log("[getUTXO] ERROR: Failed to parse height from '" + partHeight + "': " + ex.what());
                return false;
            }
        }
    }

    // Optional coinbase flag: 4th part equals "cb=1"      // NEW
    bool isCoinbase = false;
    if (parts.size() >= 4) {
        isCoinbase = (parts[3] == "cb=1");
    }

    // Fill the struct
    utxo.txid          = txid;
    utxo.vout          = vout;
    utxo.amount        = atoms;
    utxo.scriptPubKey  = partScriptHex;
    utxo.createdAtHeight = createdAtHeight;              // NEW
    utxo.isCoinbase      = isCoinbase;                   // NEW

    Logger::log("[getUTXO] OK – amount=" + std::to_string(atoms) +
                ", height=" + std::to_string(createdAtHeight) +
                (isCoinbase ? ", cb=1" : "") +
                ", scriptPubKey=" + partScriptHex);
    return true;
}

std::string UTXOSet::getAddressFromUTXO(const std::string& txid, uint32_t vout, const Blockchain* blockchainPtr) const {
    UTXO utxo;
    if (!getUTXO(txid, vout, utxo)) {
        Logger::log("[getAddressFromUTXO] UTXO not found for txid: " + txid + ", vout: " + std::to_string(vout));
        return "";
    }
    std::string address = extractAddressFromScriptPubKey(utxo.scriptPubKey, txid, vout, blockchainPtr);
    if (address.empty()) {
        Logger::log("[getAddressFromUTXO] Failed to extract address for txid: " + txid + ", vout: " + std::to_string(vout));
    } else {
        Logger::log("[getAddressFromUTXO] Extracted address: " + address + " for txid: " + txid + ", vout: " + std::to_string(vout));
    }
    return address;
}

void UTXOSet::printAllUTXOs() const {
    std::shared_lock<std::shared_mutex> lock(mtx);
    std::cout << "[UTXOSet] Listing All UTXOs and Tokens:\n";

    auto callback = [&](const std::string& key, const std::string& value) {
        // Extract txid from key (which already has "utxo:" prefix removed)
        size_t colonPos = key.find(':');
        if (colonPos == std::string::npos) {
            std::cout << "  " << key << " -> Invalid key format: missing colon\n";
            return;
        }
        std::string txid = key.substr(0, colonPos);
        
        size_t firstDelim = value.find('|');
        if (firstDelim == std::string::npos) {
            std::cout << "  " << key << " -> Invalid format: missing first delimiter\n";
            return;
        }

        size_t secondDelim = value.find('|', firstDelim + 1);
        if (secondDelim == std::string::npos) {
            std::cout << "  " << key << " -> Invalid format: missing second delimiter\n";
            return;
        }

        std::string heightStr = value.substr(0, firstDelim);
        std::string amountStr = value.substr(firstDelim + 1, secondDelim - firstDelim - 1);
        std::string script = value.substr(secondDelim + 1);

        uint64_t amount = 0;
        try {
            amount = std::stoull(amountStr);
        } catch (const std::exception& e) {
            std::cout << "  " << key << " -> Invalid amount format: " << amountStr << "\n";
            return;
        }

        std::cout << "  " << key << " -> Height: " << heightStr << ", Amount: " << amount 
                  << " TRU atoms, Script: " << script << "\n";

        ExtendedTokenData token;
        std::string owner;
        Logger::log("[printAllUTXOs] Calling parseExtendedTokenScript with txid: " + txid + " (length=" + std::to_string(txid.length()) + ")");
        if (parseExtendedTokenScript(script, txid, token, owner, blockchainPtr)) {
            std::string typeStr = tokenTypeToString(token.type);
            double adjustedAmount = static_cast<double>(token.amount) / 100.0;

            std::cout << "    [Token] ID: " << token.tokenID << ", Type: " << typeStr
                      << ", Amount: " << adjustedAmount << " " << token.tokenID
                      << ", Owner: " << owner << "\n";

            if (!token.meta.data.is_null() && !token.meta.data.empty()) {
                std::cout << "    [Metadata]\n";
                for (const auto& item : token.meta.data.items()) {
                    std::string value = item.value().is_string() ? item.value().get<std::string>() : item.value().dump();
                    std::cout << "      " << item.key() << ": " << value << "\n";
                }
            }
        } else {
            std::cout << "    [No Token Data]\n";
        }
    };

    dbStorage.iterateAll(callback);
}
std::string UTXOSet::getOffChainMetadata(const std::string &tokenID) const {
    std::shared_lock<std::shared_mutex> lock(mtx);
    std::string result;
    auto callback = [&](const std::string &key, const std::string &value) {
        // Check if this is a UTXO entry
        if (key.substr(0, 5) != "utxo:") return;
        
        // Extract txid from key format "utxo:<txid>:<vout>"
        std::string utxoKey = key.substr(5); // Remove "utxo:" prefix
        size_t colonPos = utxoKey.find(':');
        if (colonPos == std::string::npos) return;
        std::string txid = utxoKey.substr(0, colonPos);
        
        size_t firstDelim = value.find('|');
        size_t secondDelim = value.find('|', firstDelim + 1);
        if (firstDelim == std::string::npos || secondDelim == std::string::npos) return;
        std::string script = value.substr(secondDelim + 1);

        ExtendedTokenData token;
        std::string dummyOwner;
        if (parseExtendedTokenScript(script, txid, token, dummyOwner, blockchainPtr)) {
            if (token.tokenID == tokenID) {
                result = token.offChainMetadata;
            }
        }
    };
    dbStorage.iterateAll(callback);
    return result;
}

bool UTXOSet::updateOffChainMetadata(const std::string &tokenID,
                                     const std::string &newMetadataJson,
                                     const std::string &cryptoSignature)
{
    std::unique_lock<std::shared_mutex> lock(mtx);
    // Verify the signature using our stub (replace with real verification later)
    if (!verifyMetadataSignature(newMetadataJson, cryptoSignature)) {
        std::cerr << "[UTXOSet] Off-chain metadata signature check failed.\n";
        return false;
    }

    bool updatedAtLeastOne = false;

    // Iterate over all UTXOs to update any with the matching tokenID.
    auto callback = [&](const std::string &key, const std::string &value) {
        // Check if this is a UTXO entry
        if (key.substr(0, 5) != "utxo:") return;
        
        // Extract txid from key format "utxo:<txid>:<vout>"
        std::string utxoKey = key.substr(5); // Remove "utxo:" prefix
        size_t colonPos = utxoKey.find(':');
        if (colonPos == std::string::npos) return;
        std::string txid = utxoKey.substr(0, colonPos);
        
        size_t firstDelim = value.find('|');
        size_t secondDelim = value.find('|', firstDelim + 1);
        if (firstDelim == std::string::npos || secondDelim == std::string::npos) return;
        
        double amount = std::stod(value.substr(firstDelim + 1, secondDelim - firstDelim - 1));
        std::string script = value.substr(secondDelim + 1);

        ExtendedTokenData token;
        std::string dummyOwner;
        if (parseExtendedTokenScript(script, txid, token, dummyOwner, blockchainPtr)) {
            if (token.tokenID == tokenID) {
                // Update off-chain metadata and its signature.
                token.offChainMetadata = newMetadataJson;
                token.metadataSignature = cryptoSignature;

                // Extract the owner (assumed to be appended after the last '|')
                std::string owner = extractTokenOwner(script);
                // Rebuild the token script (do not include the owner in the builder)
                std::string newScript = buildExtendedTokenScript(token) + "|" + owner;

                // Build the new stored value: "height=X|amount|newScript"
                // We need to preserve the height part
                std::string heightPart = value.substr(0, firstDelim);
                std::ostringstream oss;
                oss << heightPart << "|" << static_cast<uint64_t>(amount) << "|" << newScript;
                std::string newValue = oss.str();

                if (!dbStorage.put(key, newValue)) {
                    throw std::runtime_error("[UTXOSet] Failed to update UTXO: " + key);
                }
                updatedAtLeastOne = true;
            }
        }
    };

    dbStorage.iterateAll(callback);
    return updatedAtLeastOne;
}
