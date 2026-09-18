#include "rpc_server.h"
#include "rpc_utils.h"  // authenticated RPC transport
#include "blockchain.h"
#include "tru_limits.h"  // shared block/template limits
#include "block.h"
#include "tx.h"
#include "tokens.h"
#include "token_burn_v1.h"  // TOKEN-BURN-01 non-consensus retirement sink
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include "address_helpers.h"
#include "crypto_ecdsa.h"
#include "utils.h"
#include "logging.h"
#include "wallet.h"
#include "tru_swap_v1_state.h"  // TRU-SWAP-A automation foundation
#include <cstdlib>  // TRU_SWAP_RPC_TOKEN
#include "hdwallet.h"
#include <openssl/rand.h>
#include "script_interpreter.h"
#include "contract_call_policy.h"  // stateful creation activation gate
#include "p2p.h"
#include "smart_contract.h"
#include "mempool.h"
#include "wallet.h"
#include <optional>
#include <algorithm>
#include <cctype>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <future>
#include <sstream>  // WEB-MINER-01 canonical browser coinbase tag
#include <limits>
#include <unordered_map>
#include <unordered_set>   // template double-spend guard
#include <chrono>
#include "ai_provider_interface.h"
#include "ai_oracle_service.h"
#include "token_evolution.h"  // TOKEN-AI-02D live provenance verifier
#include "tru_network_params.h"
#include "tru_amount.h"

using json = nlohmann::json;
httplib::Server g_rpcServer;

static std::shared_ptr<ConfigurableAIOracle> g_aiOracle;
static std::unique_ptr<ContractStorage> g_aiContractStorage;
static std::thread g_aiOracleThread;

//========================
// Build JSON-RPC error
//========================
static json makeError(int code, const std::string &msg) {
    return json{{"jsonrpc","2.0"},{"error",{{"code",code},{"message",msg}}}};
}

//========================
// Build JSON-RPC result
//========================
static json makeResult(int id, const json &res) {
    return json{{"jsonrpc","2.0"},{"id",id},{"result",res}};
}

// TOKEN-AI-01B2 — one RPC token-ID namespace rule.
// Canonical V2 IDs are 16 hex / 64 bits. Existing development-chain
// 8-hex IDs remain accepted for lookup/transfer compatibility only.
static std::string normalizeTokenIDForLookupV2(const std::string& input) {
    if (input.empty()) return {};

    if ((input.size() == 16U || input.size() == 8U) && isHex(input)) {
        std::string out = input;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    return bytesToHex(std::vector<unsigned char>(
        hash, hash + SHA256_DIGEST_LENGTH)).substr(0, 16);
}

// exact human-TRU JSON amount boundary.
static bool parseJsonTRUAmount(const json& value, uint64_t& atomsOut, std::string& reason) {
    std::string text;
    if (value.is_string()) {
        text = value.get<std::string>();
    } else if (value.is_number()) {
        text = value.dump();
    } else {
        reason = "amount must be a decimal string or JSON number";
        return false;
    }
    return tru_amount::parse(text, atomsOut, reason);
}

static bool readRpcUtxoAtoms(const json& utxo, uint64_t& atomsOut, std::string& reason) {
    if (utxo.contains("amount_atoms")) {
        if (!utxo["amount_atoms"].is_number_unsigned()) {
            reason = "amount_atoms must be an unsigned integer";
            return false;
        }
        atomsOut = utxo["amount_atoms"].get<uint64_t>();
        if (atomsOut > tru_limits::MAX_MONEY) {
            reason = "amount_atoms exceeds MAX_MONEY";
            return false;
        }
        return true;
    }
    if (!utxo.contains("amount")) {
        reason = "UTXO requires amount_atoms or legacy amount";
        return false;
    }
    if (!parseJsonTRUAmount(utxo["amount"], atomsOut, reason)) return false;
    if (atomsOut > tru_limits::MAX_MONEY) {
        reason = "UTXO amount exceeds MAX_MONEY";
        return false;
    }
    return true;
}

// RPC / VM parity gate.
// Browser and external RPC callers submit already-compiled script hex, bypassing
// compileTextScript(). Run the same consensus preflight here before any contract
// transaction is constructed so unsupported/malformed bytecode cannot be funded.
static bool validateContractScriptHexForVM(const std::string& scriptHex, std::string& error) {
    if (scriptHex.empty() || (scriptHex.size() % 2) != 0) {
        error = "script must be non-empty even-length hex";
        return false;
    }

    std::vector<unsigned char> scriptBytes;
    try {
        scriptBytes = hexDecode(scriptHex);
    } catch (const std::exception& e) {
        error = std::string("invalid script hex: ") + e.what();
        return false;
    }

    if (scriptBytes.empty()) {
        error = "decoded script is empty";
        return false;
    }

    ScriptResourceMetrics metrics;
    if (!AnalyzeScriptResources(scriptBytes, metrics)) {
        error = "script rejected by TRU VM preflight";
        return false;
    }

    // browser/RPC parity with the native
    // compiler. Stateful locking scripts must not be funded while Patch 14D2
    // keeps every stateful spend deliberately fail-closed.
    const auto statefulScan =
        tru_contract_call::ScanStatefulContractScript(scriptBytes);
    if (!statefulScan.valid) {
        error = "stateful-script scan failed";
        return false;
    }
    if (statefulScan.usesStateDomain) {
        error = "stateful contracts are not yet activated; funding disabled until Patch 14D3";
        return false;
    }

    return true;
}

// creation-time OP_RETURN value policy.
// Official contract creation derives data-carrier semantics from the script
// bytes, never from a client-supplied type string. Leading OP_RETURN outputs
// are unspendable under Patch 13A, so the official creation APIs require zero
// value to prevent accidental irreversible burns.
static bool isLeadingOpReturnScriptHex(const std::string& scriptHex) {
    return scriptHex.size() >= 2 &&
           scriptHex[0] == '6' &&
           (scriptHex[1] == 'a' || scriptHex[1] == 'A');
}

std::vector<std::string> splitString(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

static std::string extractP2PKHAddressCorrect(const std::string &scriptHex) {
    // Decode the hex into raw bytes
    std::vector<uint8_t> script = hexDecode(scriptHex);
    if (script.size() != 25 ||
        script[0]  != 0x76 ||  // OP_DUP
        script[1]  != 0xa9 ||  // OP_HASH160
        script[2]  != 0x14 ||  // push 20 bytes
        script[23] != 0x88 ||  // OP_EQUALVERIFY
        script[24] != 0xac)    // OP_CHECKSIG
    {
        throw std::runtime_error("Not a P2PKH scriptPubKey");
    }

    // Extract the 20-byte pubkey hash
    std::vector<uint8_t> pubKeyHash(script.begin() + 3, script.begin() + 23);

    // Build version + payload (1 byte version + 20 byte hash)
    std::vector<uint8_t> payload;
    payload.reserve(25);
    payload.push_back(tru_network::MAINNET_P2PKH_VERSION);  // TRU mainnet P2PKH
    payload.insert(payload.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Compute checksum = first 4 bytes of double-SHA256
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    
    // First SHA256
    SHA256(payload.data(), payload.size(), hash1);
    // Second SHA256  
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // Append first 4 bytes of final hash as checksum
    payload.insert(payload.end(), hash2, hash2 + 4);

    // Base58 encode the full 25-byte result
    return base58Encode(payload);
}

// removed unused duplicate extractP2PKHAddressFromHexCorrect().
// RPC script-to-address conversion remains extractP2PKHAddressCorrect().
struct TokenMetadataSpec {
    std::unordered_set<std::string> required;
    std::unordered_set<std::string> optional;
    std::unordered_map<std::string, std::string> defaults;
    std::unordered_map<std::string, std::string> hardcoded;
};

static const std::unordered_map<std::string, TokenMetadataSpec> TOKEN_METADATA_SPECS = {
    {"FT", {
        .required = {"name", "symbol", "decimals"},
        .optional = {"description", "image"},
        .defaults = {
            {"name", "Unnamed Token"},
            {"symbol", "TOK"},
            {"description", ""},
            {"image", ""},
            {"decimals", "8"}
        },
        .hardcoded = {}
    }},
    {"NFT", {
        .required = {"name"},
        .optional = {"description", "image", "creator", "external_link"},
        .defaults = {
            {"name", "Unnamed NFT"},
            {"description", ""},
            {"image", ""},
            {"creator", ""}, // Will be set to issuer address if empty
            {"external_link", ""}
        },
        .hardcoded = {
            {"decimals", "0"}
        }
    }},
    {"SFT", {
        .required = {"name", "symbol", "decimals"},
        .optional = {"description", "image", "ai_version", "learning_mode", "growth_algorithm"},
        .defaults = {
            {"name", "Unnamed SFT"},
            {"symbol", "SFT"},
            {"description", ""},
            {"image", ""},
            {"decimals", "0"},
            {"ai_version", "1.2"},
            {"learning_mode", "on-chain usage patterns"},
            {"growth_algorithm", "neural-adaptive"}
        },
        .hardcoded = {}
    }},
    {"NCFT", {
        .required = {"name"},
        .optional = {"description", "image", "ai_engine", "style_descriptor", "dynamic_morph"},
        .defaults = {
            {"name", "Unnamed NCFT"},
            {"description", ""},
            {"image", ""},
            {"ai_engine", "StableDiffusion-v2"},
            {"style_descriptor", "Van Gogh meets fractal geometry"},
            {"dynamic_morph", "transfer-based evolution"}
        },
        .hardcoded = {
            {"decimals", "0"}
        }
    }}
};

static json validateAndProcessMetadata(const std::string& tokenType, const json& inputMeta, const std::string& issuerAddress) {
    auto specIt = TOKEN_METADATA_SPECS.find(tokenType);
    if (specIt == TOKEN_METADATA_SPECS.end()) {
        throw std::invalid_argument("Unknown token type: " + tokenType);
    }
    
    const TokenMetadataSpec& spec = specIt->second;
    json processedMeta;
    
    // Check required fields
    for (const auto& field : spec.required) {
        if (!inputMeta.contains(field) || inputMeta[field].get<std::string>().empty()) {
            // Use default if available
            auto defaultIt = spec.defaults.find(field);
            if (defaultIt != spec.defaults.end()) {
                processedMeta[field] = defaultIt->second;
            } else {
                throw std::invalid_argument("Missing required field: " + field);
            }
        } else {
            processedMeta[field] = inputMeta[field];
        }
    }
    
    // Process optional fields
    for (const auto& field : spec.optional) {
        if (inputMeta.contains(field) && !inputMeta[field].get<std::string>().empty()) {
            processedMeta[field] = inputMeta[field];
        } else {
            // Use default if available
            auto defaultIt = spec.defaults.find(field);
            if (defaultIt != spec.defaults.end()) {
                processedMeta[field] = defaultIt->second;
            }
        }
    }
    
    // Apply hardcoded values
    for (const auto& [field, value] : spec.hardcoded) {
        processedMeta[field] = value;
    }
    
    // Special handling for certain fields
    if (tokenType == "NFT" && processedMeta["creator"].get<std::string>().empty()) {
        processedMeta["creator"] = issuerAddress;
    }
    
    // Validate decimals if present
    if (processedMeta.contains("decimals")) {
        try {
            int decimals = std::stoi(processedMeta["decimals"].get<std::string>());
            if (decimals < 0 || decimals > 18) {
                throw std::invalid_argument("Decimals must be between 0 and 18");
            }
        } catch (const std::exception& e) {
            throw std::invalid_argument("Invalid decimals value");
        }
    }
    
    return processedMeta;
}

static nlohmann::json ensureMetadataCompatibility(const nlohmann::json& webMeta, const std::string& txid, const std::string& scriptPubKey) {
    nlohmann::json compatMeta = webMeta;
    
    // Extract token data from the OP_RETURN script to ensure consistency
    ExtendedTokenData tokenData;
    std::string ownerAddress;
    
    if (parseExtendedTokenScript(scriptPubKey, txid, tokenData, ownerAddress, nullptr)) {
        // Ensure all fields match what the core expects
        compatMeta["tokenID"] = tokenData.tokenID;
        compatMeta["type"] = tokenTypeToString(tokenData.type);
        compatMeta["amount"] = std::to_string(tokenData.amount);
        compatMeta["owner"] = ownerAddress;
        compatMeta["version"] = "1";
        
        // Ensure meta field exists and has all required fields
        if (!compatMeta.contains("meta") || !compatMeta["meta"].is_object()) {
            compatMeta["meta"] = nlohmann::json::object();
        }
        
        // Ensure all meta fields are strings
        auto& meta = compatMeta["meta"];
        for (auto& [key, value] : meta.items()) {
            if (!value.is_string()) {
                meta[key] = value.dump();
            }
        }
        
        // Add missing required fields with defaults
        if (!meta.contains("decimals")) {
            meta["decimals"] = (tokenData.type == TokenType::NFT) ? "0" : "8";
        }
        if (!meta.contains("name") || meta["name"].get<std::string>().empty()) {
            meta["name"] = "Token_" + tokenData.tokenID;
        }
        if (!meta.contains("symbol")) {
            meta["symbol"] = tokenTypeToString(tokenData.type);
        }
        if (!meta.contains("description")) {
            meta["description"] = "";
        }
        
        // TOKEN-AI-01C: use the single canonical native metadata hasher.
        // generateMetaHash excludes the derived metaHash field itself and
        // rejects non-string metadata values after the compatibility pass above.
        compatMeta["metaHash"] = generateMetaHash(meta);
        
        compatMeta["metadataSignature"] = "";
        compatMeta["offChainMetadata"] = "";
    }
    
    return compatMeta;
}
//========================
// Async RPC Processor for handling high-load scenarios
//========================
class AsyncRPCProcessor {
private:
    struct RPCTask {
        std::string method;
        json params;
        int id;
        std::promise<json> promise;
    };
    
    std::queue<RPCTask> taskQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    std::thread processorThread;
    std::atomic<bool> running{true};
    
    // Rate limiting for miner activity
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastActivityReport;
    std::mutex rateLimitMutex;
    
public:
    AsyncRPCProcessor() : processorThread(&AsyncRPCProcessor::processLoop, this) {}
    
    ~AsyncRPCProcessor() {
        running = false;
        queueCV.notify_all();
        if (processorThread.joinable()) {
            processorThread.join();
        }
    }
    
    std::future<json> enqueueTask(const std::string& method, const json& params, int id) {
        std::unique_lock<std::mutex> lock(queueMutex);
        RPCTask task{method, params, id};
        auto future = task.promise.get_future();
        taskQueue.push(std::move(task));
        queueCV.notify_one();
        return future;
    }
    
    bool shouldRateLimit(const std::string& minerAddress) {
        std::lock_guard<std::mutex> lock(rateLimitMutex);
        auto now = std::chrono::steady_clock::now();
        auto it = lastActivityReport.find(minerAddress);
        
        if (it != lastActivityReport.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second);
            if (elapsed.count() < 1000) { // Limit to once per second per miner
                return true;
            }
        }
        
        lastActivityReport[minerAddress] = now;
        return false;
    }
    
private:
    void processLoop() {
        while (running) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this] { return !taskQueue.empty() || !running; });
            
            if (!running) break;
            
            if (!taskQueue.empty()) {
                RPCTask task = std::move(taskQueue.front());
                taskQueue.pop();
                lock.unlock();
                
                // Process task without holding queue lock
                json result;
                try {
                    // Process based on method
                    // ... (actual processing here)
                    result = json{{"processed", true}};
                } catch (const std::exception& e) {
                    result = makeError(-32000, e.what());
                }
                
                task.promise.set_value(result);
            }
        }
    }
};

static AsyncRPCProcessor g_rpcProcessor;

static bool ensureTokenMetadataIndexed(Blockchain &chain, const Transaction &tx, const nlohmann::json &metadata) {
    Logger::log("[ensureTokenMetadataIndexed] Processing token metadata for " + tx.txid);

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        const auto &out = tx.vout[i];
        Logger::log("[ensureTokenMetadataIndexed] vout[" + std::to_string(i) + "]: " +
                    "amount=" + std::to_string(out.amount) +
                    ", script=" + out.scriptPubKey.substr(0, 10) + "...");
    }

    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Storage not available");
        return false;
    }
    
    // Find the OP_RETURN output
    uint32_t tokenVout = UINT32_MAX;
    
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& out = tx.vout[i];
        if (out.scriptPubKey.substr(0, 2) == "6a" && out.amount == 0) {
            tokenVout = i;
            break;
        }
    }
    
    if (tokenVout == UINT32_MAX) {
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Could not find token OP_RETURN output");
        return false;
    }
    
    // Extract token information from metadata
    std::string tokenID = metadata.value("tokenID", "");
    std::string owner = metadata.value("owner", "");
    std::string amountStr = metadata.value("amount", "0");
    std::string type = metadata.value("type", "FT");
    
    if (tokenID.empty() || owner.empty()) {
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Missing tokenID or owner");
        return false;
    }
    
    // Check for duplicate issuance before proceeding
    std::string issuanceKey = "tokenIssuance:" + tokenID;
    std::string existingIssuance;
    if (storage->getWithDataChecksum(issuanceKey, existingIssuance)) {
        if (existingIssuance == tx.txid) {
            Logger::log("[ensureTokenMetadataIndexed] WARNING: Token " + tokenID + " already indexed in this tx: " + tx.txid);
            return true;  // Already indexed, no error
        }
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Token " + tokenID + " already issued in tx: " + existingIssuance);
        return false;
    }
    
    // Find the controlling output by matching the P2PKH script for the owner
    std::string ownerScript = createP2PKHScriptHexFromAddress(owner);
    if (ownerScript.empty()) {
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Failed to create owner script");
        return false;
    }
    
    uint32_t controllingVout = UINT32_MAX;
    int controllingCount = 0;
    
    for (size_t j = 0; j < tx.vout.size(); ++j) {
        const auto& out = tx.vout[j];
        if (j != tokenVout && out.scriptPubKey == ownerScript && out.amount > 0) {
            controllingVout = j;
            controllingCount++;
        }
    }
    
    if (controllingCount != 1) {
        Logger::log("[ensureTokenMetadataIndexed] ERROR: Found " + std::to_string(controllingCount) + 
                    " controlling outputs for owner (expected exactly 1)");
        return false;
    }
    
    try {
        // Store the complete metadata
        std::string metaKey = "tokenMetadata:" + tx.txid;
        nlohmann::json enrichedMeta = metadata;
        enrichedMeta["controllingVout"] = controllingVout;
        enrichedMeta["tokenVout"] = tokenVout;
        
        if (!storage->putWithDataChecksum(metaKey, enrichedMeta.dump())) {
            Logger::log("[ensureTokenMetadataIndexed] ERROR: Failed to store metadata");
            return false;
        }
        
        // Store token UTXO data at the controlling output (changed from tokenVout)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":" + std::to_string(controllingVout);
        nlohmann::json tokenUtxoData = {
            {"tokenID", tokenID},
            {"amount", amountStr},
            {"owner", owner},
            {"type", type},
            {"tokenVout", tokenVout}
        };
        
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoData.dump())) {
            Logger::log("[ensureTokenMetadataIndexed] ERROR: Failed to store token UTXO data");
            return false;
        }
        
        // Store ownership index pointing to controlling output
        std::string ownershipKey = "tokenOwnerUTXO:" + tokenID + ":" + owner + ":" + 
                                   tx.txid + ":" + std::to_string(controllingVout);
        if (!storage->putWithDataChecksum(ownershipKey, "1")) {
            Logger::log("[ensureTokenMetadataIndexed] ERROR: Failed to store ownership index");
            return false;
        }
        
        // Store issuance mapping
        if (!storage->putWithDataChecksum(issuanceKey, tx.txid)) {
            Logger::log("[ensureTokenMetadataIndexed] ERROR: Failed to store issuance mapping");
            return false;
        }
        
        Logger::log("[ensureTokenMetadataIndexed] Successfully indexed token: " + tokenID + 
                   " with controlling vout=" + std::to_string(controllingVout));
        
        return true;
        
    } catch (const std::exception& e) {
        Logger::log("[ensureTokenMetadataIndexed] Exception: " + std::string(e.what()));
        return false;
    }
}

static bool cleanupSpentTokenUTXOs(Blockchain &chain, const Transaction &tx) {
    Logger::log("[cleanupSpentTokenUTXOs] Processing transaction: " + tx.txid);
    
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        Logger::log("[cleanupSpentTokenUTXOs] ERROR: Storage not available");
        return false;
    }
    
    // For each input in the transaction, check if it's spending a token UTXO
    for (const auto& input : tx.vin) {
        std::string spentTxid = input.txid;
        uint32_t spentVout = input.vout;
        
        Logger::log("[cleanupSpentTokenUTXOs] Checking input: " + spentTxid + ":" + std::to_string(spentVout));
        
        // Check if this input is spending a token UTXO
        std::string tokenUtxoKey = "tokenUTXO:" + spentTxid + ":" + std::to_string(spentVout);
        std::string tokenUtxoValue;
        
        if (storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[cleanupSpentTokenUTXOs] Found spent token UTXO: " + tokenUtxoKey);
            
            try {
                // Parse the token UTXO data to get ownership info
                json tokenData = json::parse(tokenUtxoValue);
                std::string tokenID = tokenData["tokenID"].get<std::string>();
                std::string owner = tokenData["owner"].get<std::string>();
                
                // Remove the token UTXO entry
                storage->del(tokenUtxoKey);
                Logger::log("[cleanupSpentTokenUTXOs] Removed tokenUTXO: " + tokenUtxoKey);
                
                // Find and remove the corresponding ownership index
                uint32_t controllingVout = spentVout;
                
                // For tokens, the controlling vout is typically the next vout after the OP_RETURN
                Transaction originalTx;
                if (chain.findTransaction(spentTxid, originalTx)) {
                    std::string ownerScript = createP2PKHScriptHexFromAddress(owner);
                    
                    for (size_t i = 0; i < originalTx.vout.size(); ++i) {
                        if (i != spentVout && 
                            originalTx.vout[i].scriptPubKey == ownerScript && 
                            originalTx.vout[i].amount > 0) {
                            controllingVout = i;
                            break;
                        }
                    }
                }
                
                // Remove the ownership index
                std::string ownershipKey = "tokenOwnerUTXO:" + tokenID + ":" + owner + ":" + 
                                          spentTxid + ":" + std::to_string(controllingVout);
                
                if (storage->exists(ownershipKey)) {
                    storage->del(ownershipKey);
                    Logger::log("[cleanupSpentTokenUTXOs] Removed ownership index: " + ownershipKey);
                }
                
            } catch (const std::exception& e) {
                Logger::log("[cleanupSpentTokenUTXOs] Error parsing token UTXO data: " + std::string(e.what()));
                storage->del(tokenUtxoKey);
            }
        }
        
        // Also check if we're spending a controlling UTXO directly
        UTXO utxo;
        if (chain.utxoSet.getUTXO(spentTxid, spentVout, utxo)) {
            try {
                std::string utxoAddress = extractP2PKHAddressCorrect(utxo.scriptPubKey);
                
                // Check if there's a token UTXO at vout-1 or vout+1
                std::vector<uint32_t> candidateVouts = {
                    spentVout > 0 ? spentVout - 1 : 0,
                    spentVout + 1
                };
                
                for (uint32_t candidateVout : candidateVouts) {
                    std::string candidateTokenUtxoKey = "tokenUTXO:" + spentTxid + ":" + std::to_string(candidateVout);
                    std::string candidateTokenUtxoValue;
                    
                    if (storage->getWithDataChecksum(candidateTokenUtxoKey, candidateTokenUtxoValue)) {
                        try {
                            json tokenData = json::parse(candidateTokenUtxoValue);
                            std::string tokenOwner = tokenData["owner"].get<std::string>();
                            
                            if (tokenOwner == utxoAddress) {
                                std::string tokenID = tokenData["tokenID"].get<std::string>();
                                
                                storage->del(candidateTokenUtxoKey);
                                Logger::log("[cleanupSpentTokenUTXOs] Removed token UTXO via controlling spend: " + candidateTokenUtxoKey);
                                
                                std::string ownershipKey = "tokenOwnerUTXO:" + tokenID + ":" + tokenOwner + ":" + 
                                                          spentTxid + ":" + std::to_string(spentVout);
                                storage->del(ownershipKey);
                                Logger::log("[cleanupSpentTokenUTXOs] Removed ownership index via controlling spend: " + ownershipKey);
                                
                                break;
                            }
                        } catch (const std::exception& e) {
                            Logger::log("[cleanupSpentTokenUTXOs] Error parsing candidate token UTXO: " + std::string(e.what()));
                        }
                    }
                }
            } catch (const std::exception& e) {
                Logger::log("[cleanupSpentTokenUTXOs] Error extracting address from UTXO: " + std::string(e.what()));
            }
        }
    }
    
    return true;
}

static std::string getOriginalTokenFormat(Blockchain &chain, const std::string &tokenID) {
    Logger::log("[getOriginalTokenFormat] Checking format for token: " + tokenID);
    
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        return "binary"; // Default fallback
    }
    
    // Find the original issuance transaction
    std::string issuanceKey = "tokenIssuance:" + tokenID;
    std::string issuanceTxid;
    
    if (!storage->getWithDataChecksum(issuanceKey, issuanceTxid)) {
        Logger::log("[getOriginalTokenFormat] No issuance record found, defaulting to binary");
        return "binary";
    }
    
    // Get the original transaction
    Transaction originalTx;
    if (!chain.findTransaction(issuanceTxid, originalTx)) {
        Logger::log("[getOriginalTokenFormat] Original transaction not found, defaulting to binary");
        return "binary";
    }
    
    // Check the OP_RETURN format in the original transaction
    for (const auto& output : originalTx.vout) {
        if (output.scriptPubKey.substr(0, 2) == "6a" && output.amount == 0) {
            // Try to parse as JSON first
            try {
                std::string dataHex = output.scriptPubKey.substr(2); // Remove "6a"
                
                // Parse length
                if (dataHex.length() >= 2) {
                    size_t dataStart = 2;
                    uint8_t firstByte = std::stoi(dataHex.substr(0, 2), nullptr, 16);
                    
                    if (firstByte <= 75) {
                        // Direct push
                        size_t dataLen = firstByte * 2; // Convert to hex length
                        if (dataStart + dataLen <= dataHex.length()) {
                            std::string hexData = dataHex.substr(dataStart, dataLen);
                            
                            // Convert hex to string
                            std::string jsonStr;
                            for (size_t i = 0; i < hexData.length(); i += 2) {
                                std::string byteStr = hexData.substr(i, 2);
                                char byte = (char)std::stoi(byteStr, nullptr, 16);
                                jsonStr += byte;
                            }
                            
                            // Try to parse as JSON
                            json testJson = json::parse(jsonStr);
                            if (testJson.contains("type") && testJson.contains("tokenID")) {
                                Logger::log("[getOriginalTokenFormat] Original token uses JSON format");
                                return "json";
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                Logger::log("[getOriginalTokenFormat] JSON parsing failed: " + std::string(e.what()));
            }
            
            // If JSON parsing failed, assume binary
            Logger::log("[getOriginalTokenFormat] Original token uses binary format");
            return "binary";
        }
    }
    
    Logger::log("[getOriginalTokenFormat] No OP_RETURN found, defaulting to binary");
    return "binary";
}

static bool processTokenTransferIndexing(Blockchain &chain, const Transaction &tx) {
    Logger::log("[processTokenTransferIndexing] Processing transfer indexing for: " + tx.txid);
    
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        Logger::log("[processTokenTransferIndexing] ERROR: Storage not available");
        return false;
    }
    
    // Check if this transaction has token operations (look for OP_RETURN outputs)
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& output = tx.vout[i];
        
        // Skip non-OP_RETURN outputs
        if (output.scriptPubKey.substr(0, 2) != "6a" || output.amount != 0) {
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Found OP_RETURN at vout " + std::to_string(i));
        
        // Parse token data
        ExtendedTokenData tokenData;
        std::string ownerAddress;
        
        if (!parseExtendedTokenScript(output.scriptPubKey, tx.txid, tokenData, ownerAddress, nullptr)) {
            Logger::log("[processTokenTransferIndexing] Failed to parse token data");
            continue;
        }
        
        // Validate we have the required data
        if (tokenData.tokenID.empty() || ownerAddress.empty()) {
            Logger::log("[processTokenTransferIndexing] Missing required token data, skipping");
            continue;
        }
        
        // Find the controlling output
        uint32_t controllingVout = UINT32_MAX;
        std::string expectedOwnerScript = createP2PKHScriptHexFromAddress(ownerAddress);
        
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (j != i && tx.vout[j].scriptPubKey == expectedOwnerScript && tx.vout[j].amount > 0) {
                controllingVout = j;
                break;
            }
        }
        
        if (controllingVout == UINT32_MAX) {
            Logger::log("[processTokenTransferIndexing] ERROR: No controlling output found");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Found controlling output at vout " + std::to_string(controllingVout));
        
        // CRITICAL FIX: Store token UTXO at CONTROLLING output, not OP_RETURN
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":" + std::to_string(controllingVout);
        json tokenUtxoData = {
            {"tokenID", tokenData.tokenID},
            {"amount", std::to_string(tokenData.amount)},
            {"owner", ownerAddress},
            {"type", tokenTypeToString(tokenData.type)},
            {"controllingVout", controllingVout},
            {"tokenVout", i}  // Store where the actual token data is
        };
        
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoData.dump())) {
            Logger::log("[processTokenTransferIndexing] ERROR: Failed to store token UTXO data");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Stored token UTXO at controlling output: " + tokenUtxoKey);
        
        // Create ownership index (points to the controlling output)
        std::string ownershipKey = "tokenOwnerUTXO:" + tokenData.tokenID + ":" + ownerAddress + ":" + 
                                  tx.txid + ":" + std::to_string(controllingVout);
        
        if (!storage->putWithDataChecksum(ownershipKey, "1")) {
            Logger::log("[processTokenTransferIndexing] ERROR: Failed to store ownership index");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Stored ownership index: " + ownershipKey);
        
        // Also check if we have metadata attached to the transaction
        if (tx.tokenMetadata.find(tx.txid) != tx.tokenMetadata.end()) {
            std::string metaKey = "tokenMetadata:" + tx.txid;
            storage->putWithDataChecksum(metaKey, tx.tokenMetadata.at(tx.txid).dump());
            Logger::log("[processTokenTransferIndexing] Stored attached metadata");
        }
        
        Logger::log("[processTokenTransferIndexing] Successfully indexed token transfer: " + tx.txid);
    }
    
    return true;
}
/*
static bool processTokenTransferIndexing(Blockchain &chain, const Transaction &tx) {
    Logger::log("[processTokenTransferIndexing] Processing transfer indexing for: " + tx.txid);
    
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        Logger::log("[processTokenTransferIndexing] ERROR: Storage not available");
        return false;
    }
    
    // Check if this transaction has token operations (look for OP_RETURN outputs)
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& output = tx.vout[i];
        
        // Skip non-OP_RETURN outputs
        if (output.scriptPubKey.substr(0, 2) != "6a" || output.amount != 0) {
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Found OP_RETURN at vout " + std::to_string(i));
        
        // First, try to parse using your existing function (handles both formats)
        ExtendedTokenData tokenData;
        std::string ownerAddress;
        
        // Use your existing parseExtendedTokenScript function - but don't pass blockchain
        // to avoid metadata corruption
        if (parseExtendedTokenScript(output.scriptPubKey, tx.txid, tokenData, ownerAddress, nullptr)) {
            Logger::log("[processTokenTransferIndexing] Successfully parsed token data");
            Logger::log("[processTokenTransferIndexing] - TokenID: " + tokenData.tokenID);
            Logger::log("[processTokenTransferIndexing] - Type: " + tokenTypeToString(tokenData.type));
            Logger::log("[processTokenTransferIndexing] - Amount: " + std::to_string(tokenData.amount));
            Logger::log("[processTokenTransferIndexing] - Owner: " + ownerAddress);
            
        } else {
            Logger::log("[processTokenTransferIndexing] Failed to parse with parseExtendedTokenScript, trying manual parsing");
            
            // Manual parsing as fallback
            try {
                std::string dataHex = output.scriptPubKey.substr(2); // Remove "6a"
                
                // Try JSON format first
                try {
                    if (dataHex.length() >= 2) {
                        size_t dataStart = 2;
                        uint8_t firstByte = std::stoi(dataHex.substr(0, 2), nullptr, 16);
                        
                        if (firstByte <= 75) {
                            size_t dataLen = firstByte * 2;
                            if (dataStart + dataLen <= dataHex.length()) {
                                std::string hexData = dataHex.substr(dataStart, dataLen);
                                
                                // Convert hex to string
                                std::string jsonStr;
                                for (size_t j = 0; j < hexData.length(); j += 2) {
                                    std::string byteStr = hexData.substr(j, 2);
                                    char byte = (char)std::stoi(byteStr, nullptr, 16);
                                    jsonStr += byte;
                                }
                                
                                // Parse JSON
                                json tokenJson = json::parse(jsonStr);
                                if (tokenJson.contains("type") && tokenJson.contains("tokenID") && 
                                    tokenJson.contains("owner")) {
                                    
                                    tokenData.tokenID = tokenJson["tokenID"].get<std::string>();
                                    tokenData.type = stringToTokenType(tokenJson["type"].get<std::string>());
                                    tokenData.amount = std::stoull(tokenJson["amount"].get<std::string>());
                                    ownerAddress = tokenJson["owner"].get<std::string>();
                                    
                                    Logger::log("[processTokenTransferIndexing] Successfully parsed JSON format");
                                    Logger::log("[processTokenTransferIndexing] - TokenID: " + tokenData.tokenID);
                                    Logger::log("[processTokenTransferIndexing] - Owner: " + ownerAddress);
                                }
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::log("[processTokenTransferIndexing] JSON parsing failed: " + std::string(e.what()));
                    continue; // Skip this output
                }
            } catch (const std::exception& e) {
                Logger::log("[processTokenTransferIndexing] Manual parsing failed: " + std::string(e.what()));
                continue; // Skip this output
            }
        }
        
        // Validate we have the required data
        if (tokenData.tokenID.empty() || ownerAddress.empty()) {
            Logger::log("[processTokenTransferIndexing] Missing required token data, skipping");
            continue;
        }
        
        // Find the controlling output (should be the next output after OP_RETURN)
        uint32_t controllingVout = UINT32_MAX;
        
        // Look for P2PKH output to the owner
        std::string expectedOwnerScript = createP2PKHScriptHexFromAddress(ownerAddress);
        
        for (size_t j = 0; j < tx.vout.size(); ++j) {
            if (j != i && // Not the OP_RETURN output
                tx.vout[j].scriptPubKey == expectedOwnerScript && 
                tx.vout[j].amount > 0) {
                controllingVout = j;
                break;
            }
        }
        
        if (controllingVout == UINT32_MAX) {
            Logger::log("[processTokenTransferIndexing] ERROR: No controlling output found for token transfer");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Found controlling output at vout " + std::to_string(controllingVout));
        
        // Create token UTXO entry (points to the OP_RETURN output)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":" + std::to_string(i);
        json tokenUtxoData = {
            {"tokenID", tokenData.tokenID},
            {"amount", std::to_string(tokenData.amount)},
            {"owner", ownerAddress},
            {"type", tokenTypeToString(tokenData.type)},
            {"controllingVout", controllingVout}
        };
        
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoData.dump())) {
            Logger::log("[processTokenTransferIndexing] ERROR: Failed to store token UTXO data");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Stored token UTXO: " + tokenUtxoKey);
        
        // Create ownership index (points to the controlling output)
        std::string ownershipKey = "tokenOwnerUTXO:" + tokenData.tokenID + ":" + ownerAddress + ":" + 
                                  tx.txid + ":" + std::to_string(controllingVout);
        
        if (!storage->putWithDataChecksum(ownershipKey, "1")) {
            Logger::log("[processTokenTransferIndexing] ERROR: Failed to store ownership index");
            continue;
        }
        
        Logger::log("[processTokenTransferIndexing] Stored ownership index: " + ownershipKey);
        Logger::log("[processTokenTransferIndexing] Successfully indexed token transfer: " + tx.txid);
    }
    
    return true;
}//==============================================
*/
//==============================================
//          Handle Get Address TX
//==============================================

static json handleGetAddressTransactions(Blockchain &chain, const json &params, int id) {
    // WEB_WALLET_PATCH_2: enriched TRU/TRUScript address history.
    if (!params.contains("address") || !params["address"].is_string())
        return makeError(-32602, "Missing address parameter");

    const std::string address = params["address"].get<std::string>();
    int count = params.value("count", 100);
    if (count <= 0) count = 100;
    if (count > 500) count = 500;

    json rows = json::array();
    const int tip = chain.getBestTipHeight();

    for (int height = tip;
         height >= 0 && static_cast<int>(rows.size()) < count;
         --height) {

        auto blockOpt = chain.getBlockByHeight(height);
        if (!blockOpt.has_value()) continue;
        const Block& block = blockOpt.value();

        for (auto txIt = block.transactions.rbegin();
             txIt != block.transactions.rend() &&
             static_cast<int>(rows.size()) < count;
             ++txIt) {

            const Transaction& tx = *txIt;

            uint64_t totalInputs = 0;
            uint64_t myInputs = 0;
            uint64_t totalOutputs = 0;
            uint64_t myOutputs = 0;
            uint64_t sentToOthers = 0;

            std::string firstInputAddress;
            std::string firstOtherOutputAddress;

            for (const auto& vin : tx.vin) {
                if (vin.isCoinbase()) continue;

                Transaction prev;
                if (!chain.findTransaction(vin.txid, prev) ||
                    vin.vout >= prev.vout.size())
                    continue;

                const TxOut& prevOut = prev.vout[vin.vout];
                totalInputs += prevOut.amount;

                std::string inAddr;
                try {
                    inAddr = extractP2PKHAddressCorrect(prevOut.scriptPubKey);
                } catch (...) {
                    inAddr.clear();
                }

                if (firstInputAddress.empty() && !inAddr.empty())
                    firstInputAddress = inAddr;
                if (inAddr == address)
                    myInputs += prevOut.amount;
            }

            bool hasMyOutput = false;
            bool isScriptTransfer = false;
            std::string scriptFrom;
            std::string scriptTo;

            for (const auto& out : tx.vout) {
                totalOutputs += out.amount;

                std::string outAddr;
                try {
                    outAddr = extractP2PKHAddressCorrect(out.scriptPubKey);
                } catch (...) {
                    outAddr.clear();
                }

                if (outAddr == address) {
                    myOutputs += out.amount;
                    hasMyOutput = true;
                } else if (!outAddr.empty()) {
                    if (myInputs > 0)
                        sentToOthers += out.amount;
                    if (firstOtherOutputAddress.empty())
                        firstOtherOutputAddress = outAddr;
                }

                if (out.amount == 0 &&
                    out.scriptPubKey.rfind("6a", 0) == 0) {
                    try {
                        // WEB_WALLET_PATCH_2A:
                        // decodeOpReturn() is not visible in rpc_server.cpp.
                        // Decode standard OP_RETURN push data locally.
                        const std::string& scriptHex = out.scriptPubKey;
                        size_t pos = 2; // skip OP_RETURN (6a)
                        if (pos + 2 > scriptHex.size())
                            throw std::runtime_error("Malformed OP_RETURN");

                        const unsigned int pushOp =
                            static_cast<unsigned int>(
                                std::stoul(scriptHex.substr(pos, 2), nullptr, 16));
                        pos += 2;

                        size_t dataLen = 0;
                        if (pushOp <= 75) {
                            dataLen = pushOp;
                        } else if (pushOp == 0x4c) {
                            if (pos + 2 > scriptHex.size())
                                throw std::runtime_error("Malformed OP_PUSHDATA1");
                            dataLen = std::stoul(
                                scriptHex.substr(pos, 2), nullptr, 16);
                            pos += 2;
                        } else if (pushOp == 0x4d) {
                            if (pos + 4 > scriptHex.size())
                                throw std::runtime_error("Malformed OP_PUSHDATA2");
                            const size_t lo = std::stoul(
                                scriptHex.substr(pos, 2), nullptr, 16);
                            const size_t hi = std::stoul(
                                scriptHex.substr(pos + 2, 2), nullptr, 16);
                            dataLen = lo | (hi << 8);
                            pos += 4;
                        } else {
                            throw std::runtime_error(
                                "Unsupported OP_RETURN push opcode");
                        }

                        if (dataLen == 0 ||
                            pos + dataLen * 2 > scriptHex.size())
                            throw std::runtime_error(
                                "Malformed OP_RETURN payload");

                        const std::string dataHex =
                            scriptHex.substr(pos, dataLen * 2);
                        const std::vector<uint8_t> dataBytes =
                            hexDecode(dataHex);
                        const std::string decoded(
                            dataBytes.begin(), dataBytes.end());

                        const json marker = json::parse(decoded);
                        if (marker.value("type", "") ==
                            "TRUSCRIPT_TRANSFER") {
                            isScriptTransfer = true;
                            scriptFrom = marker.value("from", "");
                            scriptTo = marker.value("to", "");
                        }
                    } catch (...) {
                    }
                }
            }

            const bool involves =
                myInputs > 0 || hasMyOutput ||
                (isScriptTransfer &&
                 (scriptFrom == address || scriptTo == address));

            if (!involves)
                continue;

            std::string type;
            std::string counterparty;
            std::string asset = "TRU";
            double amount = 0.0;

            if (isScriptTransfer &&
                (scriptFrom == address || scriptTo == address)) {
                type = scriptFrom == address ? "Sent" : "Received";
                counterparty =
                    scriptFrom == address ? scriptTo : scriptFrom;
                asset = "TRUScript";
            } else if (tx.isCoinbase && hasMyOutput) {
                type = "Received";
                counterparty = "Mining Reward";
                amount = static_cast<double>(myOutputs) / 100000000.0;
            } else if (myInputs > 0) {
                type = "Sent";
                counterparty =
                    firstOtherOutputAddress.empty()
                        ? "Unknown"
                        : firstOtherOutputAddress;
                amount =
                    static_cast<double>(sentToOthers) / 100000000.0;
            } else {
                type = "Received";
                counterparty =
                    firstInputAddress.empty()
                        ? "Unknown"
                        : firstInputAddress;
                amount =
                    static_cast<double>(myOutputs) / 100000000.0;
            }

            uint64_t feeSat = 0;
            if (!tx.isCoinbase && totalInputs >= totalOutputs)
                feeSat = totalInputs - totalOutputs;

            rows.push_back({
                {"txid", tx.txid},
                {"type", type},
                {"address", counterparty},
                {"amount", amount},
                {"asset", asset},
                {"isTRUScript", asset == "TRUScript"},
                {"fee", static_cast<double>(feeSat) / 100000000.0},
                {"timestamp", block.header.timestamp},
                {"blockHeight", height},
                {"confirmations", tip >= height ? tip - height + 1 : 0}
            });
        }
    }

    return makeResult(id, rows);
}

//==============================================
//     Handle Send Token Web
//==============================================

static json handleCreateSendTokenTransaction(Blockchain &chain, const json &params, int id) {
    // WEB_WALLET_PATCH_2: mirror the proven native token transfer layout.
    if (!params.contains("tokenID") || !params.contains("amount") ||
        !params.contains("recipient") || !params.contains("senderAddress") ||
        !params.contains("feeUtxo") || !params.contains("fee")) {
        return makeError(-32602, "Missing required parameters");
    }

    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        const uint64_t amount = params["amount"].get<uint64_t>();
        const std::string recipient = params["recipient"].get<std::string>();
        const std::string sender = params["senderAddress"].get<std::string>();
        const json feeJson = params["feeUtxo"];
        const uint64_t fee = params["fee"].get<uint64_t>();

        std::string err;
        if (!validateBase58Address(recipient, err))
            return makeError(-32602, "Invalid recipient: " + err);
        if (!validateBase58Address(sender, err))
            return makeError(-32602, "Invalid sender: " + err);
        if (amount == 0)
            return makeError(-32602, "Token amount must be greater than zero");

        tokenID = normalizeTokenIDForLookupV2(tokenID);
        if (tokenID.empty())
            return makeError(-32602, "Invalid tokenID");

        LevelDBStorage* storage = chain.getStorage();
        if (!storage)
            return makeError(-32000, "Storage unavailable");

        const std::string prefix =
            "tokenOwnerUTXO:" + tokenID + ":" + sender + ":";

        std::string tokenTxid;
        uint32_t tokenVout = UINT32_MAX;
        uint64_t tokenAmount = 0;
        std::string tokenType;
        bool found = false;

        storage->iteratePrefix(
            prefix,
            [&](const std::string& suffix, const std::string&) {
                if (found) return;

                try {
                    const size_t colon = suffix.rfind(':');
                    if (colon == std::string::npos) return;

                    const std::string thisTxid = suffix.substr(0, colon);
                    const uint32_t thisVout =
                        static_cast<uint32_t>(
                            std::stoul(suffix.substr(colon + 1)));

                    UTXO control;
                    if (!chain.utxoSet.getUTXO(thisTxid, thisVout, control))
                        return;

                    if (chain.mempool &&
                        chain.mempool->isUTXOSpentInMempool(
                            thisTxid, thisVout))
                        return;

                    std::string rawToken;
                    if (!storage->getWithDataChecksum(
                            "tokenUTXO:" + thisTxid + ":" +
                                std::to_string(thisVout),
                            rawToken))
                        return;

                    const json t = json::parse(rawToken);
                    if (t.value("tokenID", "") != tokenID ||
                        t.value("owner", "") != sender)
                        return;

                    const uint64_t thisAmount =
                        t["amount"].is_string()
                            ? std::stoull(t["amount"].get<std::string>())
                            : t["amount"].get<uint64_t>();

                    if (thisAmount < amount)
                        return;

                    tokenTxid = thisTxid;
                    tokenVout = thisVout;
                    tokenAmount = thisAmount;
                    tokenType = t.value("type", "FT");
                    found = true;
                } catch (const std::exception& e) {
                    Logger::log(
                        "[handleCreateSendTokenTransaction][WEB2] candidate: " +
                        std::string(e.what()));
                }
            });

        if (!found)
            return makeError(
                -32000, "No current token UTXO with sufficient balance");

        const TokenType type = stringToTokenType(tokenType);
        if (type == TokenType::NONE)
            return makeError(-32000, "Unknown token type");
        if (type == TokenType::NFT && amount != tokenAmount)
            return makeError(-32000, "NFT cannot be partially transferred");

        std::string metaValue;
        bool haveMeta =
            storage->getWithDataChecksum(
                "tokenMetadata:" + tokenTxid, metaValue);
        if (!haveMeta) {
            std::string issuanceTxid;
            if (storage->getWithDataChecksum(
                    "tokenIssuance:" + tokenID, issuanceTxid)) {
                haveMeta = storage->getWithDataChecksum(
                    "tokenMetadata:" + issuanceTxid, metaValue);
            }
        }
        if (!haveMeta)
            return makeError(-32000, "Token metadata not found");

        const json fullMeta = json::parse(metaValue);
        TokenMeta tokenMeta;
        if (fullMeta.contains("meta") && fullMeta["meta"].is_object())
            from_json(fullMeta["meta"], tokenMeta);

        if (!feeJson.contains("txid") || !feeJson.contains("vout"))
            return makeError(-32602, "Invalid feeUtxo");

        const std::string feeTxid = feeJson["txid"].get<std::string>();
        const uint32_t feeVout = feeJson["vout"].get<uint32_t>();

        if (feeTxid == tokenTxid && feeVout == tokenVout)
            return makeError(
                -32000, "Token control cannot also be the fee input");

        UTXO feeUtxo;
        if (!chain.utxoSet.getUTXO(feeTxid, feeVout, feeUtxo))
            return makeError(-32000, "Fee UTXO no longer exists");

        if (chain.mempool &&
            chain.mempool->isUTXOSpentInMempool(feeTxid, feeVout))
            return makeError(-32000, "Fee UTXO already spent in mempool");

        const std::string feeScript = feeUtxo.scriptPubKey;
        const bool feeIsP2PKH =
            feeScript.size() == 50 &&
            feeScript.rfind("76a914", 0) == 0 &&
            feeScript.compare(feeScript.size() - 4, 4, "88ac") == 0;
        if (!feeIsP2PKH)
            return makeError(-32000, "Fee UTXO is not standard P2PKH");

        std::string feeOwner;
        try { feeOwner = extractP2PKHAddressCorrect(feeScript); }
        catch (...) { feeOwner.clear(); }
        if (feeOwner != sender)
            return makeError(-32000, "Fee UTXO does not belong to sender");

        if (storage->exists(
                "tokenUTXO:" + feeTxid + ":" + std::to_string(feeVout)))
            return makeError(-32000, "Fee UTXO controls a token");

        if (feeUtxo.isCoinbase) {
            const int tip = chain.getBestTipHeight();
            const uint32_t candidate =
                tip >= 0 ? static_cast<uint32_t>(tip + 1) : 0;
            if (tip < 0 ||
                candidate <= feeUtxo.createdAtHeight ||
                candidate - feeUtxo.createdAtHeight <
                    static_cast<uint32_t>(COINBASE_MATURITY))
                return makeError(-32000, "Fee UTXO is an immature coinbase");
        }

        const uint64_t remainder = tokenAmount - amount;
        const bool fungible =
            type == TokenType::FT ||
            type == TokenType::SFT ||
            type == TokenType::NCFT;

        // The consumed token-control TRU atom funds the recipient control.
        // A fungible remainder needs one additional control TRU atom.
        const uint64_t extraControl =
            (remainder > 0 && fungible) ? 1ULL : 0ULL;

        if (feeUtxo.amount < fee + extraControl)
            return makeError(-32000, "Fee UTXO too small");

        Transaction tx(false);
        tx.set_sender(sender);
        tx.vin.emplace_back(tokenTxid, tokenVout);
        tx.vin.emplace_back(feeTxid, feeVout);

        ExtendedTokenData newData;
        newData.tokenID = tokenID;
        newData.type = type;
        newData.amount = amount;
        newData.version = 1;
        newData.meta = tokenMeta;

        tx.vout.emplace_back(
            0, createExtendedTokenScriptPubKeyHex(newData, recipient));
        tx.vout.emplace_back(
            1, createP2PKHScriptHexFromAddress(recipient));

        if (remainder > 0 && fungible) {
            ExtendedTokenData rem = newData;
            rem.amount = remainder;
            tx.vout.emplace_back(
                0, createExtendedTokenScriptPubKeyHex(rem, sender));
            tx.vout.emplace_back(
                1, createP2PKHScriptHexFromAddress(sender));
        }

        const uint64_t coinChange =
            feeUtxo.amount - fee - extraControl;
        if (coinChange > 0) {
            tx.vout.emplace_back(
                coinChange, createP2PKHScriptHexFromAddress(sender));
        }

        // WEB_WALLET_PATCH_2B:
        // Mirror native Wallet::transferExtendedToken:
        // compute stable TXID, attach final metadata, THEN browser signs.
        tx.computeTxId();

        json transferMeta = fullMeta;
        transferMeta["tokenID"] = tokenID;
        transferMeta["type"] = tokenTypeToString(type);
        transferMeta["currentTxid"] = tx.txid;

        // Split amounts/owners live in each token OP_RETURN.
        // Transaction-level metadata follows the remainder when one exists,
        // matching the existing native transfer convention.
        if (remainder > 0 && fungible) {
            transferMeta["owner"] = sender;
            transferMeta["amount"] = std::to_string(remainder);
        } else {
            transferMeta["owner"] = recipient;
            transferMeta["amount"] = std::to_string(amount);
        }

        tx.tokenMetadata[tx.txid] = transferMeta;

        Logger::log(
            "[handleCreateSendTokenTransaction][WEB2B] metadata attached BEFORE signing: " +
            tx.txid);

        return makeResult(id, json{
            {"success", true},
            {"unsignedTxHex", bytesToHex(tx.serializeBinary())},
            {"tokenID", tokenID},
            {"selectedTokenTxid", tokenTxid},
            {"selectedTokenVout", tokenVout},
            {"selectedTokenAmount", tokenAmount},
            {"transferAmount", amount},
            {"remainder", remainder},
            {"metadataAttachedBeforeSigning", true}
        });
    } catch (const std::exception& e) {
        Logger::log(
            "[handleCreateSendTokenTransaction][WEB2] " +
            std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//================================================================
// TOKEN-BURN-01 — build a browser-signed burn transaction
//================================================================
// This is deliberately a transaction BUILDER only. It does not sign or
// broadcast. The transaction is an ordinary token transfer to the canonical
// sink and therefore requires no consensus, block-format or activation change.
static json handleCreateBurnTokenTransaction(
    Blockchain& chain,
    const json& params,
    int id)
{
    if (!params.contains("tokenID") ||
        !params.contains("senderAddress") ||
        !params.contains("feeUtxo") ||
        !params.contains("fee")) {
        return makeError(
            -32602,
            "Missing required parameters: tokenID, senderAddress, feeUtxo, fee");
    }

    try {
        std::string tokenID = normalizeTokenIDForLookupV2(
            params["tokenID"].get<std::string>());
        const std::string sender =
            params["senderAddress"].get<std::string>();

        if (tokenID.empty())
            return makeError(-32602, "Invalid tokenID");

        std::string err;
        if (!validateBase58Address(sender, err))
            return makeError(-32602, "Invalid sender: " + err);

        LevelDBStorage* storage = chain.getStorage();
        if (!storage)
            return makeError(-32000, "Storage unavailable");

        // Choose the largest CURRENT confirmed holding. Delegating that exact
        // amount to the normal transfer builder guarantees the selected token
        // control is consumed in full; a different equal-sized candidate is
        // equivalent. Multiple independent holdings are intentionally burned
        // one confirmation at a time so no new transaction format is needed.
        const std::string prefix =
            "tokenOwnerUTXO:" + tokenID + ":" + sender + ":";

        uint64_t largest = 0;
        uint64_t total = 0;
        size_t liveHoldings = 0;

        storage->iteratePrefix(
            prefix,
            [&](const std::string& suffix, const std::string&) {
                try {
                    const size_t colon = suffix.rfind(':');
                    if (colon == std::string::npos) return;
                    const std::string txid = suffix.substr(0, colon);
                    const uint32_t vout = static_cast<uint32_t>(
                        std::stoul(suffix.substr(colon + 1)));

                    UTXO control;
                    if (!chain.utxoSet.getUTXO(txid, vout, control)) return;
                    if (chain.mempool &&
                        chain.mempool->isUTXOSpentInMempool(txid, vout))
                        return;

                    std::string raw;
                    if (!storage->getWithDataChecksum(
                            "tokenUTXO:" + txid + ":" +
                                std::to_string(vout),
                            raw))
                        return;

                    const json t = json::parse(raw);
                    if (t.value("tokenID", "") != tokenID ||
                        t.value("owner", "") != sender)
                        return;

                    const uint64_t amount = t.at("amount").is_string()
                        ? std::stoull(t.at("amount").get<std::string>())
                        : t.at("amount").get<uint64_t>();
                    if (amount == 0) return;
                    if (total > std::numeric_limits<uint64_t>::max() - amount)
                        throw std::overflow_error(
                            "Token holding total exceeds uint64_t");

                    total += amount;
                    largest = std::max(largest, amount);
                    ++liveHoldings;
                } catch (const std::exception& e) {
                    Logger::log(
                        "[TOKEN-BURN-01] burn candidate skipped: " +
                        std::string(e.what()));
                }
            });

        if (largest == 0 || liveHoldings == 0)
            return makeError(
                -32000,
                "No current confirmed token holding is available to burn");

        json delegated = params;
        delegated["tokenID"] = tokenID;
        delegated["amount"] = largest;
        delegated["recipient"] = tru_token_burn_v1::BURN_ADDRESS;

        json built = handleCreateSendTokenTransaction(chain, delegated, id);
        if (!built.contains("result") || !built["result"].is_object())
            return built;

        auto& result = built["result"];
        result["burn"] = true;
        result["burnVersion"] = tru_token_burn_v1::VERSION;
        result["burnAddress"] = tru_token_burn_v1::BURN_ADDRESS;
        result["burnAmountRaw"] = largest;
        result["confirmedHoldingCount"] = liveHoldings;
        result["confirmedTotalRawBeforeBurn"] = total;
        result["confirmedRemainingRawAfterThisBurn"] = total - largest;
        result["burnsAllConfirmedHoldings"] = (total == largest);
        result["note"] =
            "Burn is an ordinary token transfer to the canonical retirement sink; issuance history remains on-chain.";
        return built;
    } catch (const std::exception& e) {
        Logger::log(
            "[TOKEN-BURN-01] create burn transaction failed: " +
            std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

/*
static json handleCreateSendTokenTransaction(Blockchain &chain, const json &params, int id) {
    if (!params.contains("tokenID") || !params.contains("amount") || 
        !params.contains("recipient") || !params.contains("senderAddress") ||
        !params.contains("feeUtxo") || !params.contains("fee")) {
        return makeError(-32602, "Missing required parameters");
    }
    
    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        uint64_t amount = params["amount"].get<uint64_t>();
        std::string recipient = params["recipient"].get<std::string>();
        std::string senderAddress = params["senderAddress"].get<std::string>();
        json feeUtxo = params["feeUtxo"];
        uint64_t fee = params["fee"].get<uint64_t>();
        std::string utxoTxid = feeUtxo["txid"].get<std::string>();
        uint32_t utxoVout = feeUtxo["vout"].get<uint32_t>();
        uint64_t utxoAmount = feeUtxo["amount"].get<uint64_t>();
        
        // Validate addresses
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            return makeError(-32602, "Invalid recipient: " + err);
        }
        if (!validateBase58Address(senderAddress, err)) {
            return makeError(-32602, "Invalid sender: " + err);
        }
        
        // TOKEN-AI-01B2: canonical lookup namespace is 16 hex; legacy
        // 8-hex development IDs remain readable for transfer compatibility.
        std::string truncatedTokenID = normalizeTokenIDForLookupV2(tokenID);
        if (truncatedTokenID.empty())
            return makeError(-32602, "Invalid tokenID");
        
        Logger::log("[handleCreateSendTokenTransaction] Looking for token: " + truncatedTokenID + 
                   " owned by: " + senderAddress);
        
        // Use the correct prefix: tokenOwnerUTXO:tokenID:address:
        LevelDBStorage* storage = chain.getStorage();
        std::string prefix = "tokenOwnerUTXO:" + truncatedTokenID + ":" + senderAddress + ":";
        
        std::string selectedTxid;
        uint32_t selectedControllingVout = 0;
        uint64_t selectedAmount = 0;
        TokenType selectedType = TokenType::NONE;
        bool found = false;
        
        // Track orphaned entries to clean up
        std::vector<std::string> orphanedEntries;
        
        storage->iteratePrefix(prefix, [&](const std::string& keySuffix, const std::string& value) {
            if (found) return;
            
            // keySuffix format: txid:vout
            size_t colonPos = keySuffix.find(':');
            if (colonPos == std::string::npos) {
                Logger::log("[handleCreateSendTokenTransaction] Invalid key format: " + prefix + keySuffix);
                return;
            }
            
            std::string thisTxid = keySuffix.substr(0, colonPos);
            uint32_t thisControllingVout = std::stoul(keySuffix.substr(colonPos + 1));
            
            // FIRST: Check if the controlling UTXO still exists (not spent)
            UTXO controllingUtxo;
            if (!chain.utxoSet.getUTXO(thisTxid, thisControllingVout, controllingUtxo)) {
                Logger::log("[handleCreateSendTokenTransaction] Controlling UTXO already spent: " + 
                           thisTxid + ":" + std::to_string(thisControllingVout) + ", skipping");
                
                // Mark for cleanup
                orphanedEntries.push_back(prefix + keySuffix);
                
                return; // Continue to next entry
            }
            
            // Token data is stored with the token vout (typically controllingVout - 1) as the key
            uint32_t tokenVout = thisControllingVout > 0 ? thisControllingVout - 1 : 0;
            std::string tokenUtxoKey = "tokenUTXO:" + thisTxid + ":" + std::to_string(tokenVout);
            std::string tokenUtxoValue;

            if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
                Logger::log("[handleCreateSendTokenTransaction] No token data at " + tokenUtxoKey);
                return;
            }
            
            try {
                json tokenJson = json::parse(tokenUtxoValue);
                
                // Verify this UTXO has the correct tokenID
                std::string utxoTokenID = tokenJson["tokenID"].get<std::string>();
                if (utxoTokenID != truncatedTokenID) {
                    Logger::log("[handleCreateSendTokenTransaction] TokenID mismatch: expected " + 
                               truncatedTokenID + ", got " + utxoTokenID);
                    return;
                }
                
                // Check owner
                std::string utxoOwner = tokenJson["owner"].get<std::string>();
                if (utxoOwner != senderAddress) {
                    Logger::log("[handleCreateSendTokenTransaction] Owner mismatch: expected " + 
                               senderAddress + ", got " + utxoOwner);
                    return;
                }
                
                // Get amount
                uint64_t utxoAmount = tokenJson["amount"].is_string() ? 
                    std::stoull(tokenJson["amount"].get<std::string>()) : 
                    tokenJson["amount"].get<uint64_t>();
                
                if (utxoAmount >= amount) {
                    // We already verified the controlling UTXO exists above
                    selectedTxid = thisTxid;
                    selectedControllingVout = thisControllingVout;
                    selectedAmount = utxoAmount;
                    selectedType = stringToTokenType(tokenJson["type"].get<std::string>());
                    found = true;
                    
                    Logger::log("[handleCreateSendTokenTransaction] Found suitable UTXO: " + 
                               thisTxid + ":" + std::to_string(thisControllingVout) + 
                               " with amount: " + std::to_string(utxoAmount));
                }
            } catch (const std::exception& e) {
                Logger::log("[handleCreateSendTokenTransaction] Error parsing token data: " + std::string(e.what()));
            }
        });
        
        // Clean up orphaned entries
        if (!orphanedEntries.empty()) {
            Logger::log("[handleCreateSendTokenTransaction] Cleaning up " + 
                       std::to_string(orphanedEntries.size()) + " orphaned ownership entries");
            for (const auto& orphanedKey : orphanedEntries) {
                storage->del(orphanedKey);
                
                // Also clean up the corresponding token UTXO data
                size_t lastColon = orphanedKey.rfind(':');
                size_t secondLastColon = orphanedKey.rfind(':', lastColon - 1);
                if (secondLastColon != std::string::npos && lastColon != std::string::npos) {
                    std::string txid = orphanedKey.substr(secondLastColon + 1, lastColon - secondLastColon - 1);
                    uint32_t controllingVout = std::stoul(orphanedKey.substr(lastColon + 1));
                    uint32_t tokenVout = controllingVout > 0 ? controllingVout - 1 : 0;
                    std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(tokenVout);
                    storage->del(tokenUtxoKey);
                }
            }
        }
        
        if (!found) {
            // Debug: Let's see what's in the storage
            Logger::log("[handleCreateSendTokenTransaction] No suitable token UTXO found. Debugging info:");
            Logger::log("[handleCreateSendTokenTransaction] Searched prefix: " + prefix);
            
            // Check if any tokenOwnerUTXO entries exist for this token
            std::string debugPrefix = "tokenOwnerUTXO:" + truncatedTokenID + ":";
            int count = 0;
            int validCount = 0;
            storage->iteratePrefix(debugPrefix, [&](const std::string& key, const std::string& value) {
                Logger::log("[handleCreateSendTokenTransaction] Found ownership entry: " + debugPrefix + key);
                count++;
                
                // Check if it's valid (controlling UTXO exists)
                size_t lastColon = key.rfind(':');
                size_t secondLastColon = key.rfind(':', lastColon - 1);
                if (secondLastColon != std::string::npos && lastColon != std::string::npos) {
                    std::string txid = key.substr(secondLastColon + 1, lastColon - secondLastColon - 1);
                    uint32_t vout = std::stoul(key.substr(lastColon + 1));
                    UTXO utxo;
                    if (chain.utxoSet.getUTXO(txid, vout, utxo)) {
                        validCount++;
                    }
                }
            });
            Logger::log("[handleCreateSendTokenTransaction] Total ownership entries for token: " + std::to_string(count) + 
                       ", valid entries: " + std::to_string(validCount));
            
            return makeError(-32000, "No suitable token UTXO found");
        }
        
        // Verify controlling output ownership
        Transaction oldTx;
        if (!chain.findTransaction(selectedTxid, oldTx)) {
            return makeError(-32000, "Failed to load token transaction");
        }
        
        if (selectedControllingVout >= oldTx.vout.size()) {
            return makeError(-32000, "Invalid controlling vout");
        }
        
        // Check NFT transfer restrictions
        if (selectedType == TokenType::NFT && amount != selectedAmount) {
            return makeError(-32000, "NFT cannot be partially transferred");
        }
        
        // Fetch original metadata from issuance
        std::string issuanceKey = "tokenIssuance:" + truncatedTokenID;
        std::string issuanceTxid;
        if (!storage->getWithDataChecksum(issuanceKey, issuanceTxid)) {
            Logger::log("[handleCreateSendTokenTransaction] Warning: Token issuance not found, using current metadata");
            issuanceTxid = selectedTxid; // Fall back to current tx
        }
        
        std::string metaKey = "tokenMetadata:" + issuanceTxid;
        std::string metaValue;
        if (!storage->getWithDataChecksum(metaKey, metaValue)) {
            return makeError(-32000, "Token metadata not found");
        }
        
        json fullMeta = json::parse(metaValue);
        json metaJson = fullMeta["meta"];
        
        TokenMeta tokenMeta;
        from_json(metaJson, tokenMeta);
        
        // Calculate costs
        const uint64_t dust = 546;
        bool hasRemainder = (amount < selectedAmount);
        uint64_t numControls = hasRemainder ? 2 : 1;
        uint64_t totalNeeded = fee + (dust * numControls);
        
        if (utxoAmount < totalNeeded) {
            return makeError(-32000, "Insufficient funds for fee and dust");
        }
        
        uint64_t changeAmount = utxoAmount - totalNeeded;
        
        // The token OP_RETURN is at vout-1 (vout 0 if controlling is at 1)
        uint32_t selectedTokenVout = selectedControllingVout > 0 ? selectedControllingVout - 1 : 0;
        
        // Build transaction
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        
        // Inputs: token OP_RETURN + controlling P2PKH + fee UTXO
        tx.vin.emplace_back(selectedTxid, selectedTokenVout);      // Token OP_RETURN
        tx.vin.emplace_back(selectedTxid, selectedControllingVout); // Controlling P2PKH
        tx.vin.emplace_back(utxoTxid, utxoVout);                   // Fee UTXO
        
        // Outputs:
        // 0: New token OP_RETURN for recipient
        ExtendedTokenData newData;
        newData.tokenID = truncatedTokenID;
        newData.type = selectedType;
        newData.amount = amount;
        newData.version = 1;
        newData.meta = tokenMeta;
        newData.offChainMetadata = "";
        newData.metadataSignature = "";
        std::string newTokenScript = createExtendedTokenScriptPubKeyHex(newData, recipient);
        tx.vout.emplace_back(0, newTokenScript);
        
        // 1: New controlling P2PKH for recipient
        std::string recipientScript = createP2PKHScriptHexFromAddress(recipient);
        tx.vout.emplace_back(dust, recipientScript);
        
        // If remainder:
        if (hasRemainder) {
            // 2: Remainder token OP_RETURN for sender
            ExtendedTokenData remData;
            remData.tokenID = truncatedTokenID;
            remData.type = selectedType;
            remData.amount = selectedAmount - amount;
            remData.version = 1;
            remData.meta = tokenMeta;
            remData.offChainMetadata = "";
            remData.metadataSignature = "";
            std::string remTokenScript = createExtendedTokenScriptPubKeyHex(remData, senderAddress);
            tx.vout.emplace_back(0, remTokenScript);
            
            // 3: Remainder controlling P2PKH for sender
            std::string senderScript = createP2PKHScriptHexFromAddress(senderAddress);
            tx.vout.emplace_back(dust, senderScript);
        }
        
        // Change output if any
        if (changeAmount >= dust) {
            std::string changeScript = createP2PKHScriptHexFromAddress(senderAddress);
            tx.vout.emplace_back(changeAmount, changeScript);
        }
        
        // Serialize unsigned
        tx.computeTxId();
        std::string unsignedHex = bytesToHex(tx.serializeBinary());
        
        json result = {
            {"unsignedTxHex", unsignedHex},
            {"success", true}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleCreateSendTokenTransaction] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
*/
//==============================================
// Get TRUScripts for an address
//==============================================
static json handleGetTRUScripts(Blockchain &chain, const json &params, int id) {
    if (!params.contains("ownerAddress")) {
        return makeError(-32602, "Missing ownerAddress parameter");
    }
    
    try {
        std::string ownerAddress = params["ownerAddress"].get<std::string>();
        json result = json::array();
        
        LevelDBStorage* storage = chain.getStorage();
        if (!storage) {
            return makeError(-32000, "Storage not available");
        }
        
        // Iterate through tokenMetadata looking for TRUScripts
        std::string prefix = "tokenMetadata:";
        storage->iteratePrefix(prefix, [&](const std::string& key, const std::string& value) {
            try {
                json metadata = json::parse(value);
                if (metadata.value("type", "") == "TRUSCRIPT" && 
                    metadata.value("owner", "") == ownerAddress) {
                    
                    std::string txid = key.substr(prefix.length());
                    
                    // Get the inscription data - try multiple sources
                    std::string inscriptionData;
                    
                    // First try to get from metadata itself
                    if (metadata.contains("data") && metadata["data"].is_string()) {
                        inscriptionData = metadata["data"].get<std::string>();
                    } else {
                        // Fall back to separate storage
                        std::string dataKey = "truscriptData:" + txid;
                        storage->getWithDataChecksum(dataKey, inscriptionData);
                    }
                    
                    // Ensure all fields are present with proper defaults
                    uint64_t inscriptionIndex = metadata.value("inscriptionIndex", 0);
                    uint64_t satNumber = metadata.value("satNumber", 0);
                    uint64_t timestamp = metadata.value("timestamp", 0);
                    uint64_t sizeBytes = inscriptionData.length();
                    int height = metadata.value("height", 0);
                    
                    // If sizeBytes is stored in metadata, use that instead
                    if (metadata.contains("sizeBytes")) {
                        sizeBytes = metadata.value("sizeBytes", sizeBytes);
                    }
                    
                    result.push_back({
                        {"txid", txid},
                        {"data", inscriptionData},
                        {"owner", ownerAddress},
                        {"timestamp", timestamp},
                        {"inscriptionIndex", inscriptionIndex},
                        {"satNumber", satNumber},
                        {"sizeBytes", sizeBytes},
                        {"height", height},
                        {"contentType", "text/plain"},
                        {"metadata", metadata}
                    });
                    
                    Logger::log("[handleGetTRUScripts] Found TRUScript: " + txid + 
                               " with data length: " + std::to_string(inscriptionData.length()));
                }
            } catch (const std::exception& e) {
                Logger::log("[handleGetTRUScripts] Error parsing metadata: " + std::string(e.what()));
            }
        });
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//==============================================
// Get specific TRUScript details
//==============================================
static json handleGetTRUScriptDetails(Blockchain &chain, const json &params, int id) {
    if (!params.contains("txid")) {
        return makeError(-32602, "Missing txid parameter");
    }
    
    try {
        std::string txid = params["txid"].get<std::string>();
        
        // Get metadata
        std::string metaKey = "tokenMetadata:" + txid;
        std::string metaValue;
        if (!chain.getStorage()->getWithDataChecksum(metaKey, metaValue)) {
            return makeError(-32000, "TRUScript not found");
        }
        
        json metadata = json::parse(metaValue);
        if (metadata.value("type", "") != "TRUSCRIPT") {
            return makeError(-32000, "Not a TRUScript");
        }
        
        // Get inscription data - try multiple sources
        std::string inscriptionData;
        
        // First try to get from metadata itself
        if (metadata.contains("data") && metadata["data"].is_string()) {
            inscriptionData = metadata["data"].get<std::string>();
        } else {
            // Fall back to separate storage
            std::string dataKey = "truscriptData:" + txid;
            chain.getStorage()->getWithDataChecksum(dataKey, inscriptionData);
        }
        
        // Get actual block height if transaction is confirmed
        int blockHeight = metadata.value("height", 0);
        Transaction tx;
        if (chain.findTransaction(txid, tx)) {
            // Try to find the actual block height
            // This would need a method to get tx block height
            // For now, use the stored value
        }
        
        json result = {
            {"txid", txid},
            {"data", inscriptionData},
            {"owner", metadata.value("owner", "")},
            {"timestamp", metadata.value("timestamp", 0)},
            {"inscriptionIndex", metadata.value("inscriptionIndex", 0)},
            {"satNumber", metadata.value("satNumber", 0)},
            {"sizeBytes", inscriptionData.length()},
            {"blockHeight", blockHeight},
            {"contentType", "text/plain"},
            {"metadata", metadata}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//==============================================
// Get raw transaction (verbose)
//==============================================
static json handleGetRawTransaction(Blockchain &chain, const json &params, int id) {
    if (!params.contains("txid")) {
        return makeError(-32602, "Missing txid parameter");
    }
    
    try {
        std::string txid = params["txid"].get<std::string>();
        bool verbose = params.value("verbose", false);
        
        // First check mempool
        auto mempoolTxs = chain.getMempoolTransactions();
        for (const auto& tx : mempoolTxs) {
            if (tx.txid == txid) {
                if (verbose) {
                    json result = {
                        {"txid", tx.txid},
                        {"version", tx.version},
                        {"locktime", tx.lockTime},
                        {"vin", json::array()},
                        {"vout", json::array()},
                        {"confirmations", 0},
                        {"time", std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count()},
                        {"hex", bytesToHex(tx.serializeBinary())}
                    };
                    
                    // Add inputs
                    for (const auto& input : tx.vin) {
                        result["vin"].push_back({
                            {"txid", input.txid},
                            {"vout", input.vout},
                            {"scriptSig", {{"hex", bytesToHex(input.scriptSig)}}},
                            {"sequence", input.sequence}
                        });
                    }
                    
                    // Add outputs
                    for (size_t i = 0; i < tx.vout.size(); i++) {
                        const auto& output = tx.vout[i];
                        result["vout"].push_back({
                            {"value", output.amount / 1e8},
                            {"n", i},
                            {"scriptPubKey", {
                                {"hex", output.scriptPubKey}
                            }}
                        });
                    }
                    
                    return makeResult(id, result);
                } else {
                    return makeResult(id, bytesToHex(tx.serializeBinary()));
                }
            }
        }
        
        // Then check blockchain
        Transaction tx;
        if (chain.findTransaction(txid, tx)) {
            if (verbose) {
                // Same as above but with blockchain data
                json result = {
                    {"txid", tx.txid},
                    {"version", tx.version},
                    {"locktime", tx.lockTime},
                    {"vin", json::array()},
                    {"vout", json::array()},
                    {"hex", bytesToHex(tx.serializeBinary())}
                };
                
                for (const auto& input : tx.vin) {
                    result["vin"].push_back({
                        {"txid", input.txid},
                        {"vout", input.vout},
                        {"scriptSig", {{"hex", bytesToHex(input.scriptSig)}}},
                        {"sequence", input.sequence}
                    });
                }
                
                for (size_t i = 0; i < tx.vout.size(); i++) {
                    const auto& output = tx.vout[i];
                    result["vout"].push_back({
                        {"value", output.amount / 1e8},
                        {"n", i},
                        {"scriptPubKey", {
                            {"hex", output.scriptPubKey}
                        }}
                    });
                }
                
                return makeResult(id, result);
            } else {
                return makeResult(id, bytesToHex(tx.serializeBinary()));
            }
        }
        
        return makeError(-32000, "Transaction not found");
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//==============================================
// Get transaction output
//==============================================
static json handleGetTxOut(Blockchain &chain, const json &params, int id) {
    if (!params.contains("txid") || !params.contains("n")) {
        return makeError(-32602, "Missing txid or n parameter");
    }
    
    try {
        std::string txid = params["txid"].get<std::string>();
        uint32_t vout = params["n"].get<uint32_t>();
        bool includeMempool = params.value("includeMempool", true);
        
        // Check UTXO set
        UTXO utxo;
        if (chain.utxoSet.getUTXO(txid, vout, utxo)) {
            json result = {
                {"bestblock", chain.getBestTipHash()},
                {"confirmations", 1}, // Simplified - would need to calculate actual confirmations
                {"value", utxo.amount / 1e8},
                {"scriptPubKey", {
                    {"hex", utxo.scriptPubKey}
                }},
                {"coinbase", false}
            };
            
            return makeResult(id, result);
        }
        
        // Not found (spent or doesn't exist)
        return makeResult(id, nullptr);
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Redeem canonical Hash Lock
//========================
static json handleRedeemHashLock(
    Blockchain &chain,
    Wallet &wallet,
    const json &params,
    int id)
{
    (void)chain;
    try {
        std::string contractAddress;
        if (params.contains("contractAddress") &&
            params["contractAddress"].is_string()) {
            contractAddress =
                params["contractAddress"].get<std::string>();
        } else if (params.contains("address") &&
                   params["address"].is_string()) {
            contractAddress =
                params["address"].get<std::string>();
        }

        if (contractAddress.empty() ||
            !params.contains("preimage") ||
            !params["preimage"].is_string()) {
            return makeError(
                -32602,
                "Missing required parameters: contractAddress/address, preimage");
        }

        const std::string preimage =
            params["preimage"].get<std::string>();
        if (preimage.size() > 100) {
            return makeError(
                -32602,
                "Hash Lock preimage exceeds the 100-byte contract limit");
        }

        const std::string txid =
            wallet.redeemHashLock(
                contractAddress, preimage);

        return makeResult(id, {
            {"success", true},
            {"status", "mempool_accepted"},
            {"type", "hash_lock_redeem"},
            {"contractAddress", contractAddress},
            {"txid", txid}
        });
    } catch (const std::exception& e) {
        Logger::log(
            "[handleRedeemHashLock] rejected: " +
            std::string(e.what()));
        return makeError(
            -32000,
            std::string("Hash Lock redemption failed: ") +
            e.what());
    }
}

//========================
// Redeem canonical Time Lock
//========================
static json handleRedeemTimeLock(
    Blockchain &chain,
    Wallet &wallet,
    const json &params,
    int id)
{
    (void)chain;
    try {
        std::string contractAddress;
        if (params.contains("contractAddress") && params["contractAddress"].is_string()) {
            contractAddress = params["contractAddress"].get<std::string>();
        } else if (params.contains("address") && params["address"].is_string()) {
            contractAddress = params["address"].get<std::string>();
        }
        if (contractAddress.empty()) {
            return makeError(-32602, "Missing required parameter: contractAddress/address");
        }

        const std::string txid = wallet.redeemTimeLock(contractAddress);
        return makeResult(id, {
            {"success", true},
            {"status", "mempool_accepted"},
            {"type", "time_lock_redeem"},
            {"contractAddress", contractAddress},
            {"txid", txid}
        });
    } catch (const std::exception& e) {
        Logger::log("[handleRedeemTimeLock] rejected: " + std::string(e.what()));
        return makeError(-32000, std::string("Time Lock redemption failed: ") + e.what());
    }
}

//========================
// Create Contract Transaction
//========================
static json handleCreateContractTransaction(Blockchain &chain, const json &params, int id) {
    try {
        // Validate required parameters
        if (!params.contains("type") || !params.contains("name") || 
            !params.contains("scriptHex") || !params.contains("senderAddress")) {
            return makeError(-32602, "Missing required parameters: type, name, scriptHex, senderAddress");
        }
        
        std::string contractType = params["type"].get<std::string>();
        std::string contractName = params["name"].get<std::string>();
        std::string scriptHex = params["scriptHex"].get<std::string>();
        std::string senderAddress = params["senderAddress"].get<std::string>();
        uint64_t contractAmount = params.value("amount", 0);
        std::string metadata = params.value("metadata", "");
        uint64_t fee = params.value("fee", 10000);
        
        // Also need UTXO info from client
        if (!params.contains("utxo") || !params["utxo"].contains("txid") || 
            !params["utxo"].contains("vout") || !params["utxo"].contains("amount")) {
            return makeError(-32602, "Missing UTXO information");
        }
        
        std::string utxoTxid = params["utxo"]["txid"].get<std::string>();
        uint32_t utxoVout = params["utxo"]["vout"].get<uint32_t>();
        uint64_t utxoAmount = 0;
        std::string utxoAmountReason;
        if (!readRpcUtxoAtoms(params["utxo"], utxoAmount, utxoAmountReason)) {
            return makeError(-32602, "Invalid UTXO amount: " + utxoAmountReason);
        }
        
        Logger::log("[handleCreateContractTransaction] Creating unsigned contract transaction");
        
        // Validate sender address
        std::string err;
        if (!validateBase58Address(senderAddress, err)) {
            return makeError(-32602, "Invalid sender address: " + err);
        }
        
        // browser/RPC creation must pass the
        // same VM preflight as compileTextScript before funds can be committed.
        std::string scriptPreflightError;
        if (!validateContractScriptHexForVM(scriptHex, scriptPreflightError)) {
            return makeError(-32602, "Invalid scriptHex: " + scriptPreflightError);
        }

        // determine OP_RETURN from bytecode,
        // not from the untrusted client-supplied contract type.
        const bool leadingOpReturn = isLeadingOpReturnScriptHex(scriptHex);
        const bool typeClaimsOpReturn =
            contractType == "op-return" || contractType == "OP_RETURN";
        const bool typeClaimsTimeLock =
            contractType == "time-lock" || contractType == "TIME LOCK" ||
            contractType == "TIME_LOCK";

        // the public RPC Time Lock family is timestamp-only.
        // Reject malformed or height-domain scripts at creation instead of
        // letting users create outputs that canonical CLTV will later reject.
        if (typeClaimsTimeLock) {
            if (scriptHex.size() != 64 ||
                scriptHex.substr(0, 2) != "04" ||
                scriptHex.substr(10, 10) != "b17576a914" ||
                scriptHex.substr(60, 4) != "88ac") {
                return makeError(
                    -32602,
                    "TIME LOCK requires canonical 04<LE-u32>b17576a914<hash160>88ac script");
            }
            uint32_t lockTime = 0;
            try {
                const std::string h = scriptHex.substr(2, 8);
                for (int i = 0; i < 4; ++i) {
                    const uint32_t b = static_cast<uint32_t>(
                        std::stoul(
                            h.substr(static_cast<std::size_t>(i) * 2, 2),
                            nullptr, 16));
                    lockTime |= (b << (8 * i));
                }
            } catch (...) {
                return makeError(-32602, "Invalid TIME LOCK timestamp encoding");
            }
            if (lockTime < 500000000U) {
                return makeError(
                    -32602,
                    "TRU Time Lock V1 is timestamp-only; lock time must be >= 500000000");
            }
        }

        if (leadingOpReturn && contractAmount != 0) {
            return makeError(
                -32602,
                "Leading OP_RETURN outputs are unspendable and must carry 0 TRU");
        }
        if (typeClaimsOpReturn && !leadingOpReturn) {
            return makeError(
                -32602,
                "Contract type OP_RETURN requires scriptHex beginning with OP_RETURN");
        }

        // Family/pattern allow-list remains a second, independent policy gate.
        if (!chain.mempool->isAllowedSmartContractScript(scriptHex)) {
            return makeError(-32602, "Script does not match any allowed smart contract pattern");
        }
        
        uint64_t totalNeeded = contractAmount + fee;
        if (utxoAmount < totalNeeded) {
            return makeError(-32000, fmt::format(
                "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms", 
                utxoAmount, totalNeeded));
        }
        
        // Build unsigned transaction
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        tx.vin.emplace_back(utxoTxid, utxoVout);
        
        // Output 0: OP_RETURN metadata
        std::string metaText = "TRU_CONTRACT:" + contractName;
        if (!metadata.empty()) {
            metaText += ":" + metadata;
        }
        
        std::vector<unsigned char> metaBytes(metaText.begin(), metaText.end());
        if (metaBytes.size() > 80) {
            return makeError(-32602, "Metadata too long (max 80 bytes)");
        }
        
        std::string opReturnHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + bytesToHex(metaBytes);
        tx.vout.emplace_back(0, opReturnHex);
        
        // Output 1 is always the requested
        // contract/data script. Leading OP_RETURN scripts are zero-value by
        // policy; non-OP_RETURN contracts retain the requested contractAmount.
        // This also fixes the old OP_RETURN path that skipped scriptHex entirely.
        tx.vout.emplace_back(leadingOpReturn ? 0 : contractAmount, scriptHex);
        
        // Output 2: Change output
        uint64_t changeAmount = utxoAmount - contractAmount - fee;
        if (changeAmount > 546) { // Dust threshold
            std::string changeScript = createP2PKHScriptHexFromAddress(senderAddress);
            tx.vout.emplace_back(changeAmount, changeScript);
        }
        
        // Don't sign - return unsigned transaction
        tx.computeTxId(); // This will be recomputed after signing
        
        // Compute contract address (will be at output 1)
        std::string contractAddress = tx.txid + ":1";
        
        Logger::log("[handleCreateContractTransaction] Created unsigned transaction");
        
        // Return unsigned transaction for client-side signing
        json result = {
            {"unsignedTxHex", hexEncode(tx.serializeBinary())},
            {"contractAddress", contractAddress},
            {"success", true}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleCreateContractTransaction] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Contract creation failed: ") + e.what());
    }
}
//========================
// mempool all
//========================
static json handleListMempoolTransactions(Blockchain &chain, const json &params, int id) {
    try {
        // Use direct access like your CLI
        auto memTxs = chain.mempool->getAllTransactions();
        
        json result = {
            {"count", memTxs.size()},
            {"transactions", json::array()}
        };
        
        if (memTxs.empty()) {
            result["message"] = "No transactions in mempool";
        } else {
            for (const auto& tx : memTxs) {
                json txInfo = {
                    {"txid", tx.txid},
                    {"inputs", tx.vin.size()},
                    {"outputs", tx.vout.size()},
                    {"vout_details", json::array()}
                };
                
                for (size_t i = 0; i < tx.vout.size(); ++i) {
                    txInfo["vout_details"].push_back({
                        {"index", i},
                        {"script", tx.vout[i].scriptPubKey},
                        {"amount", tx.vout[i].amount}
                    });
                }
                
                result["transactions"].push_back(txInfo);
            }
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, "Failed to list mempool: " + std::string(e.what()));
    }
}
//========================
// Get raw mempool (wrapper for compatibility)
//========================
static json handleGetRawMempool(Blockchain &chain, const json &params, int id) {
    try {
        bool verbose = false;
        if (params.contains("verbose") && params["verbose"].is_boolean()) {
            verbose = params["verbose"].get<bool>();
        }
        
        // Get mempool transactions directly from mempool
        std::vector<Transaction> mempoolTxs;
        if (chain.mempool) {
            mempoolTxs = chain.mempool->getAllTransactions();
        } else {
            // Fallback to getMempoolTransactions if direct access not available
            mempoolTxs = chain.getMempoolTransactions();
        }
        
        Logger::log("[handleGetRawMempool] Found " + std::to_string(mempoolTxs.size()) + " transactions in mempool");
        
        if (verbose) {
            // Return object format with transaction details
            json result = json::object();
            
            for (const auto& tx : mempoolTxs) {
                // isolate verbose failures per row.
                try {
                    const auto raw = tx.serializeBinary();
                    const uint64_t fee = tx.computeFee(chain);

                    json txInfo = {
                        {"size", raw.size()},
                        {"fee", fee},
                        {"feerate_sat_per_byte",
                         raw.empty() ? 0 :
                         fee / static_cast<uint64_t>(raw.size())},
                        {"time", std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count()},
                        {"height", chain.getBestTipHeight() + 1},
                        {"depends", json::array()},
                        {"hex", bytesToHex(raw)},
                        {"inputs", tx.vin.size()},
                        {"outputs", tx.vout.size()}
                    };

                    json outputs = json::array();
                    for (size_t i = 0; i < tx.vout.size(); ++i) {
                        outputs.push_back({
                            {"index", i},
                            {"amount", tx.vout[i].amount},
                            {"scriptPubKey", tx.vout[i].scriptPubKey}
                        });
                    }
                    txInfo["vout"] = outputs;
                    result[tx.txid] = txInfo;
                } catch (const std::exception& e) {
                    Logger::log(
                        "[handleGetRawMempool] Broken verbose entry " +
                        tx.txid + ": " + e.what());
                    result[tx.txid] = json{
                        {"error", std::string("entry unavailable: ") + e.what()}
                    };
                } catch (...) {
                    Logger::log(
                        "[handleGetRawMempool] Broken verbose entry " +
                        tx.txid + ": unknown exception");
                    result[tx.txid] = json{
                        {"error", "entry unavailable: unknown exception"}
                    };
                }
            }

            return makeResult(id, result);
        } else {
            // Return array of txids
            json txids = json::array();
            for (const auto& tx : mempoolTxs) {
                txids.push_back(tx.txid);
            }
            return makeResult(id, txids);
        }
        
    } catch (const std::exception& e) {
        Logger::log("[handleGetRawMempool] Error: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
//========================
// Enhanced Report miner activity
//========================
static json handleReportMinerActivityOptimized(Blockchain &chain, const json &params, int id) {
    if (!params.contains("minerAddress") || !params["minerAddress"].is_string()) {
        return makeError(-32602, "Missing or invalid minerAddress parameter");
    }
    
    std::string minerAddress = params["minerAddress"].get<std::string>();
    
    // Rate limit check first (without holding blockchain locks)
    if (g_rpcProcessor.shouldRateLimit(minerAddress)) {
        // Return success but don't actually process - miner stays alive
        return makeResult(id, json{
            {"success", true},
            {"message", "Rate limited - activity noted"},
            {"minerAddress", minerAddress}
        });
    }
    
    // Batch activity updates
    static std::mutex batchMutex;
    static std::unordered_map<std::string, std::pair<uint64_t, double>> batchedUpdates;
    static std::chrono::steady_clock::time_point lastFlush;
    
    {
        std::lock_guard<std::mutex> lock(batchMutex);
        
        uint64_t hashesTried = params["hashesTried"].get<uint64_t>();
        double timeTaken = params["timeTaken"].get<double>();
        
        if (batchedUpdates.count(minerAddress)) {
            batchedUpdates[minerAddress].first += hashesTried;
            batchedUpdates[minerAddress].second += timeTaken;
        } else {
            batchedUpdates[minerAddress] = {hashesTried, timeTaken};
        }
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastFlush);
        
        // Flush batch every 5 seconds or when we have many updates
        if (elapsed.count() > 5000 || batchedUpdates.size() > 50) {
            // Copy batch for processing
            auto updatesCopy = batchedUpdates;
            batchedUpdates.clear();
            lastFlush = now;
            
            // Process updates asynchronously
            std::thread([&chain, updatesCopy]() {
                for (const auto& [addr, data] : updatesCopy) {
                    chain.updateMinerActivity(addr, data.first, data.second);
                }
            }).detach();
        }
    }
    
    return makeResult(id, json{
        {"success", true},
        {"message", "Activity batched for processing"},
        {"minerAddress", minerAddress}
    });
}
//========================
// Enhanced Register miner
//========================
static json handleRegisterMiner(Blockchain &chain, const json &params, int id) {
    // Validate required parameters
    if (!params.contains("minerAddress") || !params["minerAddress"].is_string()) {
        return makeError(-32602, "Missing or invalid minerAddress parameter");
    }
    
    try {
        std::string minerAddress = params["minerAddress"].get<std::string>();
        
        // Validate minerAddress format
        if (minerAddress.empty()) {
            return makeError(-32602, "minerAddress cannot be empty");
        }
        if (minerAddress.length() < 26 || minerAddress.length() > 35) {
            return makeError(-32602, "Invalid minerAddress format (must be 26-35 characters)");
        }
        
        // Check if miner is already registered
        bool wasAlreadyRegistered = chain.isMinerRegistered(minerAddress);
        
        // Register the miner
        chain.registerMiner(minerAddress);
        
        // Initialize with zero hash rate to ensure proper tracking
        chain.updateMinerActivity(minerAddress, 0, 1.0);
        
        json result = {
            {"success", true},
            {"message", wasAlreadyRegistered ? "Miner re-registered successfully" : "Miner registered successfully"},
            {"minerAddress", minerAddress},
            {"wasAlreadyRegistered", wasAlreadyRegistered},
            {"registrationTime", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        
        Logger::log(std::string("[RPC] Miner ") + (wasAlreadyRegistered ? "re-registered" : "registered") + ": " + minerAddress);
        
        return makeResult(id, result);
        
    } catch (const nlohmann::json::exception& e) {
        return makeError(-32602, "JSON parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return makeError(-32000, "Internal error: " + std::string(e.what()));
    }
}

//========================
// Enhanced Unregister miner
//========================
static json handleUnregisterMiner(Blockchain &chain, const json &params, int id) {
    // Validate required parameters
    if (!params.contains("minerAddress") || !params["minerAddress"].is_string()) {
        return makeError(-32602, "Missing or invalid minerAddress parameter");
    }
    
    try {
        std::string minerAddress = params["minerAddress"].get<std::string>();
        
        // Validate minerAddress format
        if (minerAddress.empty()) {
            return makeError(-32602, "minerAddress cannot be empty");
        }
        if (minerAddress.length() < 26 || minerAddress.length() > 35) {
            return makeError(-32602, "Invalid minerAddress format (must be 26-35 characters)");
        }
        
        // Check if miner was actually registered
        bool wasRegistered = chain.isMinerRegistered(minerAddress);
        
        // Unregister the miner (this will also clean up hash rates and activity)
        chain.unregisterMiner(minerAddress);
        
        json result = {
            {"success", true},
            {"message", wasRegistered ? "Miner unregistered successfully" : "Miner was not registered"},
            {"minerAddress", minerAddress},
            {"wasRegistered", wasRegistered},
            {"unregistrationTime", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        
        Logger::log("[RPC] Miner unregistered: " + minerAddress + 
                   (wasRegistered ? " (was active)" : " (was not active)"));
        
        return makeResult(id, result);
        
    } catch (const nlohmann::json::exception& e) {
        return makeError(-32602, "JSON parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return makeError(-32000, "Internal error: " + std::string(e.what()));
    }
}

//========================
//  Get miner status
//========================
static json handleGetMinerStatus(Blockchain &chain, const json &params, int id) {
    // Validate required parameters
    if (!params.contains("minerAddress") || !params["minerAddress"].is_string()) {
        return makeError(-32602, "Missing or invalid minerAddress parameter");
    }
    
    try {
        std::string minerAddress = params["minerAddress"].get<std::string>();
        
        // Validate minerAddress format
        if (minerAddress.empty()) {
            return makeError(-32602, "minerAddress cannot be empty");
        }
        
        bool isRegistered = chain.isMinerRegistered(minerAddress);
        double currentHashRate = 0.0;
        int64_t lastActivityTimestamp = 0;
        bool isActive = false;
        uint64_t blocksMined = 0;
        
        if (isRegistered) {
            // Get current hash rate from public member
            if (chain.minerHashRates.count(minerAddress)) {
                currentHashRate = chain.minerHashRates.at(minerAddress);
            }
            
            // Get last activity and determine if active
            if (chain.minerLastActivity.count(minerAddress)) {
                auto lastActivity = chain.minerLastActivity.at(minerAddress);
                auto now = std::chrono::steady_clock::now();
                auto timeSinceActivity = now - lastActivity;
                isActive = timeSinceActivity < std::chrono::minutes(2);
                lastActivityTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                    lastActivity.time_since_epoch()).count();
            }
            
            // Get blocks mined count through the synchronized derived-stats accessor.
            blocksMined = chain.getMinerBlockCount(minerAddress);
            
            json result = {
                {"success", true},
                {"minerAddress", minerAddress},
                {"isRegistered", true},
                {"isActive", isActive},
                {"currentHashRate", currentHashRate},
                {"blocksMined", blocksMined},
                {"lastActivityTimestamp", lastActivityTimestamp}
            };
            
            return makeResult(id, result);
        } else {
            json result = {
                {"success", true},
                {"minerAddress", minerAddress},
                {"isRegistered", false},
                {"isActive", false},
                {"currentHashRate", 0.0},
                {"blocksMined", 0},
                {"lastActivityTimestamp", 0}
            };
            
            return makeResult(id, result);
        }
        
    } catch (const nlohmann::json::exception& e) {
        return makeError(-32602, "JSON parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return makeError(-32000, "Internal error: " + std::string(e.what()));
    }
}


//========================
// Get all miners
//========================
static json handleGetAllMiners(Blockchain &chain, const json &params, int id) {
    try {
        // Get all active miners from the blockchain
        auto activeMiners = chain.getActiveMiners();
        
        json minersArray = json::array();
        auto now = std::chrono::steady_clock::now();
        
        for (const auto& minerAddress : activeMiners) {
            // Get hash rate directly from public member
            double hashRate = 0.0;
            if (chain.minerHashRates.count(minerAddress)) {
                hashRate = chain.minerHashRates.at(minerAddress);
            }
            
            // Get last activity directly from public member
            bool isActive = false;
            int64_t lastActivityTimestamp = 0;
            if (chain.minerLastActivity.count(minerAddress)) {
                auto lastActivity = chain.minerLastActivity.at(minerAddress);
                auto timeSinceActivity = now - lastActivity;
                isActive = timeSinceActivity < std::chrono::minutes(2);
                lastActivityTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                    lastActivity.time_since_epoch()).count();
            }
            
            // Get blocks mined count through the synchronized derived-stats accessor.
            uint64_t blocksMined = chain.getMinerBlockCount(minerAddress);
            
            json minerInfo = {
                {"address", minerAddress},
                {"hashRate", hashRate},
                {"isActive", isActive},
                {"blocksMined", blocksMined},
                {"lastActivityTimestamp", lastActivityTimestamp},
                {"timeSinceLastActivity", std::chrono::duration_cast<std::chrono::seconds>(
                    now - (chain.minerLastActivity.count(minerAddress) ? 
                           chain.minerLastActivity.at(minerAddress) : now)).count()}
            };
            
            minersArray.push_back(minerInfo);
        }
        
        // Sort by hash rate descending, then by blocks mined
        std::sort(minersArray.begin(), minersArray.end(), [](const json& a, const json& b) {
            double hashRateA = a["hashRate"].get<double>();
            double hashRateB = b["hashRate"].get<double>();
            if (hashRateA != hashRateB) {
                return hashRateA > hashRateB;
            }
            return a["blocksMined"].get<uint64_t>() > b["blocksMined"].get<uint64_t>();
        });
        
        // Calculate summary statistics
        double totalHashRate = 0.0;
        int activeCount = 0;
        for (const auto& miner : minersArray) {
            if (miner["isActive"].get<bool>()) {
                totalHashRate += miner["hashRate"].get<double>();
                activeCount++;
            }
        }
        
        json result = {
            {"success", true},
            {"minerCount", minersArray.size()},
            {"activeMiners", activeCount},
            {"totalHashRate", totalHashRate},
            {"miners", minersArray},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, "Internal error: " + std::string(e.what()));
    }
}
//=======================================================================
//			SEND TRUSCRIPTS
//=======================================================================
// WEB_WALLET_PATCH_2
// Build a browser-owned TRUScript transfer. The browser signs it.
static json handleCreateTransferTRUScriptTransaction(
    Blockchain& chain, const json& params, int id) {

    if (!params.contains("inscriptionTxid") ||
        !params.contains("recipient") ||
        !params.contains("senderAddress") ||
        !params.contains("feeUtxo") ||
        !params.contains("fee")) {
        return makeError(-32602, "Missing TRUScript transfer parameters");
    }

    try {
        const std::string inscriptionTxid =
            params["inscriptionTxid"].get<std::string>();
        const std::string recipient =
            params["recipient"].get<std::string>();
        const std::string sender =
            params["senderAddress"].get<std::string>();
        const json feeJson = params["feeUtxo"];
        const uint64_t fee = params["fee"].get<uint64_t>();

        if (inscriptionTxid.size() != 64 ||
            !std::all_of(
                inscriptionTxid.begin(), inscriptionTxid.end(),
                [](unsigned char c) { return std::isxdigit(c) != 0; }))
            return makeError(-32602, "Invalid inscriptionTxid");

        std::string err;
        if (!validateBase58Address(recipient, err))
            return makeError(-32602, "Invalid recipient: " + err);
        if (!validateBase58Address(sender, err))
            return makeError(-32602, "Invalid sender: " + err);

        LevelDBStorage* storage = chain.getStorage();
        if (!storage)
            return makeError(-32000, "Storage unavailable");

        std::string metaText;
        if (!storage->getWithDataChecksum(
                "tokenMetadata:" + inscriptionTxid, metaText))
            return makeError(-32000, "TRUScript not found");

        const json meta = json::parse(metaText);
        if (meta.value("type", "") != "TRUSCRIPT")
            return makeError(-32000, "Not a TRUScript");
        if (meta.value("owner", "") != sender)
            return makeError(
                -32000, "Sender is not the current TRUScript owner");

        const std::string feeTxid =
            feeJson.at("txid").get<std::string>();
        const uint32_t feeVout =
            feeJson.at("vout").get<uint32_t>();

        UTXO feeUtxo;
        if (!chain.utxoSet.getUTXO(feeTxid, feeVout, feeUtxo))
            return makeError(-32000, "Fee UTXO no longer exists");

        if (chain.mempool &&
            chain.mempool->isUTXOSpentInMempool(feeTxid, feeVout))
            return makeError(-32000, "Fee UTXO already spent in mempool");

        const std::string script = feeUtxo.scriptPubKey;
        const bool p2pkh =
            script.size() == 50 &&
            script.rfind("76a914", 0) == 0 &&
            script.compare(script.size() - 4, 4, "88ac") == 0;
        if (!p2pkh)
            return makeError(-32000, "Fee UTXO is not standard P2PKH");

        std::string feeOwner;
        try { feeOwner = extractP2PKHAddressCorrect(script); }
        catch (...) { feeOwner.clear(); }
        if (feeOwner != sender)
            return makeError(-32000, "Fee UTXO does not belong to sender");

        if (storage->exists(
                "tokenUTXO:" + feeTxid + ":" + std::to_string(feeVout)))
            return makeError(-32000, "Fee UTXO controls a token");

        if (feeUtxo.isCoinbase) {
            const int tip = chain.getBestTipHeight();
            const uint32_t candidate =
                tip >= 0 ? static_cast<uint32_t>(tip + 1) : 0;
            if (tip < 0 ||
                candidate <= feeUtxo.createdAtHeight ||
                candidate - feeUtxo.createdAtHeight <
                    static_cast<uint32_t>(COINBASE_MATURITY))
                return makeError(-32000, "Fee UTXO is immature");
        }

        const uint64_t dust = 546;
        if (feeUtxo.amount < fee + dust)
            return makeError(-32000, "Fee UTXO too small");

        const json transferData = {
            {"type", "TRUSCRIPT_TRANSFER"},
            {"inscription", inscriptionTxid},
            {"from", sender},
            {"to", recipient},
            {"timestamp", static_cast<uint64_t>(std::time(nullptr))},
            {"data", meta.value("data", "")},
            {"inscriptionIndex", meta.value("inscriptionIndex", 0)},
            {"satNumber", meta.value("satNumber", 0)},
            {"creationTimestamp", meta.value("timestamp", 0)},
            {"sizeBytes", meta.value("sizeBytes", 0)}
        };

        const std::string transferJson = transferData.dump();

        std::string dataHex;
        static const char* HEX = "0123456789abcdef";
        dataHex.reserve(transferJson.size() * 2);
        for (unsigned char c : transferJson) {
            dataHex.push_back(HEX[(c >> 4) & 0xF]);
            dataHex.push_back(HEX[c & 0xF]);
        }

        auto byteHex = [](uint8_t b) {
            static const char* H = "0123456789abcdef";
            std::string s(2, '0');
            s[0] = H[(b >> 4) & 0xF];
            s[1] = H[b & 0xF];
            return s;
        };

        std::string push;
        const size_t dataLen = transferJson.size();
        if (dataLen <= 75) {
            push = byteHex(static_cast<uint8_t>(dataLen));
        } else if (dataLen <= 255) {
            push = "4c" + byteHex(static_cast<uint8_t>(dataLen));
        } else if (dataLen <= 65535) {
            push =
                "4d" +
                byteHex(static_cast<uint8_t>(dataLen & 0xFF)) +
                byteHex(static_cast<uint8_t>((dataLen >> 8) & 0xFF));
        } else {
            return makeError(-32000, "TRUScript transfer marker too large");
        }

        Transaction tx(false);
        tx.set_sender(sender);
        tx.vin.emplace_back(feeTxid, feeVout);
        tx.vout.emplace_back(0, "6a" + push + dataHex);
        tx.vout.emplace_back(
            dust, createP2PKHScriptHexFromAddress(recipient));

        const uint64_t change = feeUtxo.amount - fee - dust;
        if (change >= dust) {
            tx.vout.emplace_back(
                change, createP2PKHScriptHexFromAddress(sender));
        }

        tx.computeTxId();

        return makeResult(id, json{
            {"success", true},
            {"unsignedTxHex", bytesToHex(tx.serializeBinary())},
            {"inscriptionTxid", inscriptionTxid},
            {"from", sender},
            {"to", recipient}
        });
    } catch (const std::exception& e) {
        Logger::log(
            "[handleCreateTransferTRUScriptTransaction][WEB2] " +
            std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

static json handleTransferTRUScript(Blockchain& chain, Wallet& wallet, const json& params, int id) {
    Logger::log("[handleTransferTRUScript] Received params: " + params.dump());
    
    if (!params.contains("inscriptionTxid") || !params.contains("recipient")) {
        return makeError(-32602, "Missing inscriptionTxid or recipient");
    }
    
    try {
        std::string inscriptionTxid;
        std::string recipient;
        
        // Handle different ways the txid might be passed
        if (params["inscriptionTxid"].is_string()) {
            inscriptionTxid = params["inscriptionTxid"].get<std::string>();
        } else {
            return makeError(-32602, "inscriptionTxid must be a string");
        }
        
        if (params["recipient"].is_string()) {
            recipient = params["recipient"].get<std::string>();
        } else {
            return makeError(-32602, "recipient must be a string");
        }
        
        // Validate txid format (should be 64 hex characters)
        if (inscriptionTxid.length() != 64 || !std::all_of(inscriptionTxid.begin(), inscriptionTxid.end(), ::isxdigit)) {
            Logger::log("[handleTransferTRUScript] Invalid txid format: " + inscriptionTxid + " (length: " + std::to_string(inscriptionTxid.length()) + ")");
            return makeError(-32602, "Invalid inscriptionTxid format - must be 64 hex characters");
        }
        
        Logger::log("[handleTransferTRUScript] Processing transfer - txid: " + inscriptionTxid + ", recipient: " + recipient);
        
        std::string transferTxid = wallet.transferTRUScript(inscriptionTxid, recipient);
        
        return makeResult(id, json{{"transferTxid", transferTxid}});
    } catch (const std::exception& e) {
        Logger::log("[handleTransferTRUScript] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
//=======================================================================
// DID-01 — SIGNED NETWORK DID REGISTRATION
//=======================================================================
static std::string did01Sha256Hex(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    return bytesToHex(std::vector<unsigned char>(digest, digest + SHA256_DIGEST_LENGTH));
}

static std::string did01ExpectedDID(const std::string& address) {
    // Exact parity with web Utils.generateUserDID():
    // SHA256(address + salt) -> lowercase hex text -> SHA256(hex text) -> first 16 hex.
    const std::string h1 = did01Sha256Hex(address + "mySpecialRandomSalt42");
    const std::string h2 = did01Sha256Hex(h1);
    return "did:on_tru:" + h2.substr(0, 16);
}

static bool did01CanonicalDID(const std::string& did) {
    static const std::string prefix = "did:on_tru:";
    if (did.size() != prefix.size() + 16U || did.rfind(prefix, 0) != 0) return false;
    return isHex(did.substr(prefix.size()));
}

static std::string did01RegistrationMessage(
    const std::string& did,
    const std::string& address,
    const std::string& publicKeyHex) {
    // Domain/network separation makes the proof unusable for another protocol/network.
    return std::string("TRU-DID-REGISTER-V1\n") +
        "network=TRUMain\n" +
        "did=" + did + "\n" +
        "address=" + address + "\n" +
        "pubkey=" + publicKeyHex + "\n";
}

static json handleGetDIDMapping(Blockchain &chain, const json &params, int id) {
    if (!params.contains("did") || !params["did"].is_string()) {
        return makeError(-32602, "Missing DID");
    }
    const std::string did = params["did"].get<std::string>();
    if (!did01CanonicalDID(did)) {
        return makeError(-32602, "Invalid canonical TRU DID");
    }
    const std::string address = chain.resolveDIDToAddress(did);
    return makeResult(id, json{
        {"did", did},
        {"found", !address.empty()},
        {"address", address}
    });
}

static json handleRegisterDIDSigned(Blockchain &chain, const json &params, int id) {
    for (const char* field : {"did", "address", "publicKey", "signature"}) {
        if (!params.contains(field) || !params[field].is_string()) {
            return makeError(-32602, std::string("Missing or invalid ") + field);
        }
    }

    const std::string did = params["did"].get<std::string>();
    const std::string address = params["address"].get<std::string>();
    std::string publicKeyHex = params["publicKey"].get<std::string>();
    const std::string signatureHex = params["signature"].get<std::string>();

    if (!did01CanonicalDID(did)) {
        return makeError(-32602, "Invalid canonical TRU DID");
    }
    if (!chain.isValidAddress(address)) {
        return makeError(-32602, "Invalid TRU mainnet address");
    }

    std::transform(publicKeyHex.begin(), publicKeyHex.end(), publicKeyHex.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (publicKeyHex.size() != 66U ||
        (publicKeyHex.rfind("02", 0) != 0 && publicKeyHex.rfind("03", 0) != 0) ||
        !isHex(publicKeyHex)) {
        return makeError(-32602, "publicKey must be a compressed secp256k1 key");
    }
    if (signatureHex.empty() || signatureHex.size() > 144U ||
        (signatureHex.size() % 2U) != 0U || !isHex(signatureHex)) {
        return makeError(-32602, "signature must be strict DER hex");
    }

    const std::string expectedDid = did01ExpectedDID(address);
    if (did != expectedDid) {
        return makeError(-32602, "DID does not match deterministic address-derived TRU DID");
    }

    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> signature;
    try {
        publicKey = hexDecode(publicKeyHex);
        signature = hexDecode(signatureHex);
    } catch (const std::exception&) {
        return makeError(-32602, "Malformed public key or signature hex");
    }

    if (pubkeyToAddress(publicKey) != address) {
        return makeError(-32031, "Public key does not control claimed TRU address");
    }

    const std::string canonical = did01RegistrationMessage(did, address, publicKeyHex);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(), digest);
    const std::string digestBytes(
        reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH);

    if (!ECDSAKey::verifyCanonicalTransactionSignature(publicKey, digestBytes, signature)) {
        return makeError(-32032, "Invalid DID ownership signature");
    }

    bool created = false;
    bool conflict = false;
    std::string existingAddress;
    if (!chain.registerDIDMappingImmutable(
            did, address, created, conflict, existingAddress)) {
        return makeError(-32033, "DID registry durable write failed");
    }
    if (conflict) {
        Logger::log("[DID-01] immutable DID conflict refused for " + did);
        return makeError(-32034, "DID is already registered to a different address");
    }

    return makeResult(id, json{
        {"version", "TRU-DID-REGISTER-V1"},
        {"network", "TRUMain"},
        {"did", did},
        {"address", existingAddress},
        {"created", created},
        {"idempotent", !created},
        {"verifiedOwnership", true}
    });
}

// Legacy authenticated-Core method remains available for local compatibility,
// but is now immutable too. It is still forbidden from the public web gateway.
static json handleCreateDID(Blockchain &chain, const json &params, int id) {
    if (!params.contains("did") || !params["did"].is_string() ||
        !params.contains("address") || !params["address"].is_string()) {
        return makeError(-32602, "Missing DID or address");
    }
    const std::string did = params["did"].get<std::string>();
    const std::string address = params["address"].get<std::string>();
    bool created = false;
    bool conflict = false;
    std::string existingAddress;
    if (!chain.registerDIDMappingImmutable(
            did, address, created, conflict, existingAddress)) {
        return makeError(-32033, "DID registry durable write failed");
    }
    if (conflict) return makeError(-32034, "DID is already registered to a different address");
    return makeResult(id, created ? "DID mapping stored" : "DID mapping already exists");
}
//========================================================================
//			SOCIAL MEDIA POST
//========================================================================
static json handleCreateSocialPost(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("fromDID") || !params.contains("message") || !params.contains("tags") || !params.contains("privateKey")) {
        return makeError(-32602, "Missing required parameters");
    }

    std::string fromDID = params["fromDID"].get<std::string>();
    std::string message = params["message"].get<std::string>();
    std::vector<std::string> tags = params["tags"].get<std::vector<std::string>>();
    std::string privateKey = params["privateKey"].get<std::string>();

    if (fromDID.empty() || message.empty() || privateKey.empty()) {
        return makeError(-32602, "Parameters cannot be empty");
    }

    try {
        // Resolve DID to address
        std::string senderAddress = chain.resolveDIDToAddress(fromDID);
        if (senderAddress.empty()) {
            return makeError(-32000, "DID resolution failed");
        }

        // Create and add the social post transaction
        Transaction tx = wallet.createSocialPostTransaction(fromDID, message, tags, privateKey);
        if (!chain.addTransaction(tx)) {
            Logger::log("[handleCreateSocialPost] TX queue admission rejected: " + tx.txid);
            return makeError(-32000, "Transaction queue admission rejected");
        }
        return makeResult(id, json{{"txid", tx.txid}});
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}
//========================================================================
//			Get peer info
//========================================================================
json handleGetPeerInfo(P2PNode& node, const json& params, int id) {
    json response;
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    json peerArray = json::array();

    // Use getPeersList() to safely access the peers
    auto peers = node.getPeersList();
    for (const auto& peer : peers) {
        json peerInfo;
        peerInfo["ip"] = peer->getIp();
        peerInfo["port"] = peer->getPort();
        peerInfo["height"] = peer->getPeerHeight();
        peerArray.push_back(peerInfo);
    }
    response["result"] = peerArray;
    return response;
}
//========================================================================
//                      Display Tokens
//========================================================================
static json handleTokenMetadataDisplay(Blockchain& chain, const json& params, int id) {
    if (!params.contains("addresses") || !params["addresses"].is_array()) {
        return makeError(-32602, "Missing or invalid 'addresses' parameter");
    }

    std::vector<std::string> addresses = params["addresses"].get<std::vector<std::string>>();
    if (addresses.empty()) {
        return makeError(-32602, "No addresses provided");
    }

    json result = json::array();
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        return makeError(-32000, "Storage not available");
    }

    // Handle standard tokens (FT, NFT, SFT, NCFT)
    std::string prefix = "tokenOwnerUTXO:";
    try {
        storage->iteratePrefix(prefix, [&](const std::string& keySansPrefix, const std::string& /*value*/) {
            std::string fullKey = prefix + keySansPrefix;
            // Expected format: tokenOwnerUTXO:tokenID:address:txid:vout
            std::vector<std::string> parts;
            std::istringstream iss(fullKey);
            std::string part;
            while (std::getline(iss, part, ':')) {
                parts.push_back(part);
            }

            if (parts.size() != 5) {
                Logger::log("[handleTokenMetadataDisplay] Skipping invalid key: " + fullKey);
                return; // Skip malformed keys
            }

            std::string tokenID = parts[1];
            std::string owner = parts[2];
            std::string txid = parts[3];
            std::string voutStr = parts[4];

            // Check if the owner address is in the requested list
            if (std::find(addresses.begin(), addresses.end(), owner) == addresses.end()) {
                return; // Skip if not requested
            }

            uint32_t vout;
            try {
                vout = std::stoul(voutStr);
            } catch (const std::exception& e) {
                Logger::log("[handleTokenMetadataDisplay] Invalid vout in key " + fullKey + ": " + e.what());
                return;
            }

            // Fetch metadata
            std::string metaKey = "tokenMetadata:" + txid;
            std::string metaValue;
            if (!storage->getWithDataChecksum(metaKey, metaValue)) {
                Logger::log("[handleTokenMetadataDisplay] No metadata for " + metaKey);
                return;
            }

            try {
                json metaJson = json::parse(metaValue);
                result.push_back({
                    {"tokenID", tokenID},
                    {"type", metaJson.value("type", "Unknown")},
                    {"amount", metaJson.value("amount", "0")},
                    {"owner", owner},
                    {"txid", txid},
                    {"vout", vout},
                    {"meta", metaJson.value("meta", json::object())}
                });
            } catch (const std::exception& e) {
                Logger::log("[handleTokenMetadataDisplay] Error parsing metadata for " + metaKey + ": " + e.what());
            }
        });

        // Handle TRUScript inscriptions
        std::string metaPrefix = "tokenMetadata:";
        storage->iteratePrefix(metaPrefix, [&](const std::string& key, const std::string& metaValue) {
            try {
                json metaJson = json::parse(metaValue);
                if (metaJson.value("type", "") != "TRUSCRIPT") {
                    return; // Skip non-TRUScript entries
                }

                std::string owner = metaJson.value("owner", "");
                if (std::find(addresses.begin(), addresses.end(), owner) == addresses.end()) {
                    return; // Skip if owner not in requested addresses
                }

                std::string txid = key.substr(metaPrefix.length());
                result.push_back({
                    {"tokenID", "TRUSCRIPT:" + txid}, // Pseudo-tokenID for TRUScript
                    {"type", "TRUSCRIPT"},
                    {"amount", "1"}, // TRUScript has no amount, set to 1
                    {"owner", owner},
                    {"txid", txid},
                    {"vout", 0}, // TRUScript uses vout=0 for OP_RETURN
                    {"meta", metaJson}
                });
            } catch (const std::exception& e) {
                Logger::log("[handleTokenMetadataDisplay] Error parsing TRUScript metadata for " + key + ": " + e.what());
            }
        });
    } catch (const std::exception& e) {
        Logger::log("[handleTokenMetadataDisplay] Iteration failed: " + std::string(e.what()));
        return makeError(-32000, "Failed to iterate token data: " + std::string(e.what()));
    }

    return makeResult(id, result);
}
//================================================================
//		GET TOKEN UTXO
//================================================================
static json handleGetTokenUTXO(Blockchain& chain, const json& params, int id) {
    LevelDBStorage* storage = chain.getStorage();
    if (!storage) {
        return makeError(-32000, "Storage not available");
    }

    if (params.contains("txid") && params.contains("vout")) {
        // Handle specific UTXO request (for standalone mode token data fetch)
        std::string txid = params["txid"].get<std::string>();
        uint32_t vout = params["vout"].get<uint32_t>();
        
        std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(vout);
        std::string tokenUtxoValue;
        
        if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[handleGetTokenUTXO] No tokenUTXO data for specific " + tokenUtxoKey);
            return makeError(-32000, "No token data at this UTXO");
        }

        try {
            json j = json::parse(tokenUtxoValue);
            json result = json::array();
            result.push_back({
                {"txid", txid},
                {"tokenVout", vout},
                {"controllingVout", j.value("controllingVout", vout + 1)},
                {"amount", j["amount"]},
                {"owner", j["owner"]},
                {"type", j["type"]},
                {"tokenID", j["tokenID"]}
            });
            return makeResult(id, result);
        } catch (const std::exception& e) {
            Logger::log("[handleGetTokenUTXO] Error parsing specific tokenUTXO data for " + tokenUtxoKey + ": " + e.what());
            return makeError(-32000, "Failed to parse token data");
        }
    } else if (params.contains("tokenID") && params.contains("address")) {
        // Existing code for fetching all UTXOs for token/address
        std::string tokenID = params["tokenID"].get<std::string>();
        std::string address = params["address"].get<std::string>();

        if (tokenID.empty() || address.empty()) {
            return makeError(-32602, "tokenID and address must not be empty");
        }

        std::string truncatedTokenID = normalizeTokenIDForLookupV2(tokenID);
        if (truncatedTokenID.empty())
            return makeError(-32602, "Invalid tokenID");
        Logger::log("[handleGetTokenUTXO] Canonical/legacy token namespace ID: " +
                    truncatedTokenID + " from " + tokenID);

        std::string prefix = "tokenOwnerUTXO:" + truncatedTokenID + ":" + address + ":";
        json result = json::array();

        storage->iteratePrefix(prefix, [&](const std::string& keySansPrefix, const std::string& value) {
            std::string fullKey = prefix + keySansPrefix;
            std::vector<std::string> parts = splitString(fullKey.substr(prefix.length()), ':');
            
            if (parts.size() != 2) {
                Logger::log("[handleGetTokenUTXO] Malformed tokenOwnerUTXO key: " + fullKey);
                return;
            }
            
            std::string txid = parts[0];
            uint32_t controllingVout;
            
            try {
                controllingVout = std::stoul(parts[1]);
            } catch (const std::exception& e) {
                Logger::log("[handleGetTokenUTXO] Invalid vout in key " + fullKey + ": " + e.what());
                return;
            }
            
            uint32_t tokenVout = controllingVout - 1;
            std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(tokenVout);
            std::string tokenUtxoValue;
            
            if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
                Logger::log("[handleGetTokenUTXO] No tokenUTXO data for " + tokenUtxoKey);
                return;
            }

            try {
                json j = json::parse(tokenUtxoValue);
                if (!j.contains("tokenID") || j["tokenID"].get<std::string>() != truncatedTokenID) {
                    Logger::log("[handleGetTokenUTXO] TokenID mismatch in " + tokenUtxoKey);
                    return;
                }
                
                uint64_t amount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
                result.push_back({
                    {"txid", txid},
                    {"controllingVout", controllingVout},
                    {"tokenVout", tokenVout},
                    {"amount", amount},
                    {"owner", j["owner"].get<std::string>()},
                    {"type", j["type"].get<std::string>()}
                });
            } catch (const std::exception& e) {
                Logger::log("[handleGetTokenUTXO] Error parsing tokenUTXO data for " + tokenUtxoKey + ": " + e.what());
            }
        });

        if (result.empty()) {
            Logger::log("[handleGetTokenUTXO] No token UTXOs found for tokenID=" + truncatedTokenID + ", address=" + address);
            return makeError(-32000, "No token UTXOs found for the given token ID and address");
        }

        Logger::log("[handleGetTokenUTXO] Returning response: " + result.dump());
        return makeResult(id, result);
    } else {
        return makeError(-32602, "Missing required parameters (tokenID and address or txid and vout)");
    }
}



//================================================================
//              GET TOKEN META DATA
//================================================================
static json handleGetTokenMetadata(Blockchain& chain, const json& params, int id) {
    // Validate input parameters
    if (!params.contains("txid")) {
        return makeError(-32602, "Missing txid");
    }

    std::string txid = params["txid"].get<std::string>();
    if (txid.empty()) {
        return makeError(-32602, "txid must not be empty");
    }

    // Construct storage key and fetch metadata
    std::string metaKey = "tokenMetadata:" + txid;
    std::string metaValue;
    if (!chain.getStorage()->getWithDataChecksum(metaKey, metaValue)) {
        return makeError(-32000, "No metadata found for the given txid");
    }

    // Parse and return metadata
    try {
        json metaJson = json::parse(metaValue);
        if (!metaJson.is_object()) {
            return makeError(-32000, "Invalid metadata format");
        }
        return makeResult(id, metaJson);
    } catch (const std::exception& e) {
        Logger::log("[handleGetTokenMetadata] Error parsing metadata for txid " + txid + ": " + e.what());
        return makeError(-32000, std::string("Failed to parse metadata: ") + e.what());
    }
}

//========================
// Handle Issue Token Signed
//========================

static json handleIssueTokenSigned(Blockchain &chain, const json &params, int id) {
    if (!params.contains("signedTxHex")) {
        return makeError(-32602, "Missing signedTxHex parameter");
    }
    
    try {
        std::string txHex = params["signedTxHex"].get<std::string>();
        
        // Deserialize the signed transaction
        auto raw = hexDecode(txHex);
        Transaction tx = Transaction::deserializeBinary(raw);
        
        // Compute txid from the signed transaction (without metadata)
        tx.computeTxId();
        
        Logger::log("[handleIssueTokenSigned] Processing token issuance for txid: " + tx.txid);
        
        // Process and attach metadata for network propagation
        if (params.contains("metadata") && params.value("attachMetadata", false)) {
            std::string metadataStr = params["metadata"].get<std::string>();
            
            try {
                nlohmann::json metadata = json::parse(metadataStr);
                
                // Ensure all numeric values are strings
                if (metadata.contains("amount") && metadata["amount"].is_number()) {
                    metadata["amount"] = std::to_string(metadata["amount"].get<uint64_t>());
                }
                if (metadata.contains("meta") && metadata["meta"].is_object()) {
                    auto& meta = metadata["meta"];
                    if (meta.contains("decimals") && meta["decimals"].is_number()) {
                        meta["decimals"] = std::to_string(meta["decimals"].get<int>());
                    }
                }
                
                Logger::log("[handleIssueTokenSigned] Processed metadata: " + metadata.dump());
                
                // metadata may travel with the unconfirmed
                // transaction, but confirmed token state must not be persisted
                // from RPC/mempool context. applyBlock() owns all durable
                // tokenMetadata/tokenUTXO/tokenOwnerUTXO/tokenOwnership/
                // tokenIssuance indexing through mainBatch + U4.
                tx.tokenMetadata[tx.txid] = metadata;
                Logger::log(
                    "[Patch16A.0] issuetokensigned attached metadata tx=" +
                    tx.txid + " confirmed token indexing=DEFERRED_UNTIL_BLOCK");

            } catch (const json::exception& e) {
                Logger::log("[handleIssueTokenSigned] Invalid metadata JSON: " + std::string(e.what()));
                return makeError(-32602, "Invalid metadata JSON: " + std::string(e.what()));
            }
        }
        
        // never delete confirmed token indexes from RPC context.
        // Spending cleanup is performed by normal confirmed block application
        // and captured by the same mainBatch/U4 transition.

        // Add transaction to the bounded ingress queue. Never report/broadcast
        // success if queue admission failed.
        if (!chain.addTransaction(tx)) {
            Logger::log("[handleIssueTokenSigned] TX queue admission rejected: " + tx.txid);
            return makeError(-32000, "Transaction queue admission rejected");
        }
        
        // Broadcast to peers only after local queue admission succeeds.
        chain.broadcastTransaction(tx);
        
        Logger::log(
            "[handleIssueTokenSigned] Token transaction submitted; confirmed indexing deferred until block: " +
            tx.txid);
        
        json result = {
            {"txid", tx.txid},
            {"success", true}
        };
        
        if (!tx.tokenMetadata.empty()) {
            auto metadata = tx.tokenMetadata.begin()->second;
            result["tokenID"] = metadata.value("tokenID", "");
            result["indexed"] = false;
            result["indexing"] = "on-confirmation";
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleIssueTokenSigned] Exception: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to process signed token transaction: ") + e.what());
    }
}
/*
static json handleIssueTokenSigned(Blockchain &chain, const json &params, int id) {
    if (!params.contains("signedTxHex")) {
        return makeError(-32602, "Missing signedTxHex parameter");
    }
    
    try {
        std::string txHex = params["signedTxHex"].get<std::string>();
        
        // Deserialize the signed transaction
        auto raw = hexDecode(txHex);
        Transaction tx = Transaction::deserializeBinary(raw);
        
        // Compute txid from the signed transaction (without metadata)
        tx.computeTxId();
        
        Logger::log("[handleIssueTokenSigned] Processing token issuance for txid: " + tx.txid);
                
        // Process and attach metadata for network propagation
        if (params.contains("metadata") && params.value("attachMetadata", false)) {
            std::string metadataStr = params["metadata"].get<std::string>();
            
            try {
                nlohmann::json metadata = json::parse(metadataStr);
                
                // Ensure all numeric values are strings
                if (metadata.contains("amount") && metadata["amount"].is_number()) {
                    metadata["amount"] = std::to_string(metadata["amount"].get<uint64_t>());
                }
                if (metadata.contains("meta") && metadata["meta"].is_object()) {
                    auto& meta = metadata["meta"];
                    if (meta.contains("decimals") && meta["decimals"].is_number()) {
                        meta["decimals"] = std::to_string(meta["decimals"].get<int>());
                    }
                }
                
                Logger::log("[handleIssueTokenSigned] Processed metadata: " + metadata.dump());
                
                // Store metadata in database
                std::string metaKey = "tokenMetadata:" + tx.txid;
                chain.getStorage()->putWithDataChecksum(metaKey, metadata.dump());
                
                // Also store in temporary location for mempool
                std::string tempKey = "mempoolTokenMeta:" + tx.txid;
                chain.getStorage()->putWithDataChecksum(tempKey, metadata.dump());
                
                // Attach metadata to transaction for network propagation
                tx.tokenMetadata[tx.txid] = metadata;
                
                // Pre-index the token data
                ensureTokenMetadataIndexed(chain, tx, metadata);
                
            } catch (const json::exception& e) {
                Logger::log("[handleIssueTokenSigned] Invalid metadata JSON: " + std::string(e.what()));
                return makeError(-32602, "Invalid metadata JSON: " + std::string(e.what()));
            }
        }

        // ADD THIS:
        cleanupSpentTokenUTXOs(chain, tx);
        
        // Add transaction to the bounded ingress queue.
        if (!chain.addTransaction(tx)) {
            Logger::log("[handleIssueTokenSigned] TX queue admission rejected: " + tx.txid);
            return makeError(-32000, "Transaction queue admission rejected");
        }
        
        Logger::log("[handleIssueTokenSigned] Token transaction submitted: " + tx.txid);
        
        json result = {
            {"txid", tx.txid},
            {"success", true}
        };
        
        if (!tx.tokenMetadata.empty()) {
            auto metadata = tx.tokenMetadata.begin()->second;
            result["tokenID"] = metadata.value("tokenID", "");
            result["indexed"] = true;
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleIssueTokenSigned] Exception: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to process signed token transaction: ") + e.what());
    }
}
*/
//========================
// Handle Token Balance Verifyier
//========================
static json handleVerifyTokenBalance(Blockchain &chain, const json &params, int id) {
    if (!params.contains("address") || !params.contains("tokenID")) {
        return makeError(-32602, "Missing address or tokenID parameter");
    }
    
    try {
        std::string address = params["address"].get<std::string>();
        std::string tokenID = params["tokenID"].get<std::string>();
        
        // TOKEN-AI-01B2: canonical lookup namespace is 16 hex.
        std::string truncatedTokenID = normalizeTokenIDForLookupV2(tokenID);
        if (truncatedTokenID.empty())
            return makeError(-32602, "Invalid tokenID");
        
        Logger::log("[handleVerifyTokenBalance] Verifying balance for token: " + truncatedTokenID + ", address: " + address);
        
        LevelDBStorage* storage = chain.getStorage();
        if (!storage) {
            return makeError(-32000, "Storage not available");
        }
        
        std::string prefix = "tokenOwnerUTXO:" + truncatedTokenID + ":" + address + ":";
        uint64_t totalBalance = 0;
        int utxoCount = 0;
        int orphanedCount = 0;
        json utxos = json::array();
        
        storage->iteratePrefix(prefix, [&](const std::string& keySuffix, const std::string& value) {
            std::vector<std::string> parts = splitString(keySuffix, ':');
            if (parts.size() >= 2) {
                std::string txid = parts[0];
                uint32_t controllingVout = std::stoul(parts[1]);
                
                // Check if the controlling UTXO still exists
                UTXO utxo;
                if (chain.utxoSet.getUTXO(txid, controllingVout, utxo)) {
                    // Find the token UTXO data
                    uint32_t tokenVout = controllingVout > 0 ? controllingVout - 1 : 0;
                    std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(tokenVout);
                    std::string tokenUtxoValue;
                    
                    if (storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
                        try {
                            json tokenData = json::parse(tokenUtxoValue);
                            uint64_t amount = tokenData["amount"].is_string() ? 
                                std::stoull(tokenData["amount"].get<std::string>()) : 
                                tokenData["amount"].get<uint64_t>();
                            
                            totalBalance += amount;
                            utxoCount++;
                            
                            utxos.push_back({
                                {"txid", txid},
                                {"controllingVout", controllingVout},
                                {"tokenVout", tokenVout},
                                {"amount", amount}
                            });
                            
                        } catch (const std::exception& e) {
                            Logger::log("[handleVerifyTokenBalance] Error parsing token UTXO: " + std::string(e.what()));
                        }
                    }
                } else {
                    orphanedCount++;
                    Logger::log("[handleVerifyTokenBalance] Found orphaned ownership entry: " + prefix + keySuffix);
                }
            }
        });
        
        json result = {
            {"tokenID", truncatedTokenID},
            {"address", address},
            {"totalBalance", totalBalance},
            {"utxoCount", utxoCount},
            {"orphanedCount", orphanedCount},
            {"utxos", utxos}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Handle FIx Token Meta
//========================
static json handleFixTokenMetadata(Blockchain &chain, const json &params, int id) {
    if (!params.contains("txid") || !params.contains("metadata")) {
        return makeError(-32602, "Missing txid or metadata parameter");
    }
    
    try {
        std::string txid = params["txid"].get<std::string>();
        json metadata = params["metadata"];
        
        // Find the transaction to get the OP_RETURN script
        Transaction tx;
        if (!chain.findTransaction(txid, tx)) {
            return makeError(-32000, "Transaction not found");
        }
        
        // Find OP_RETURN
        std::string opReturnScript;
        for (const auto& out : tx.vout) {
            if (out.scriptPubKey.substr(0, 2) == "6a" && out.amount == 0) {
                opReturnScript = out.scriptPubKey;
                break;
            }
        }
        
        if (opReturnScript.empty()) {
            return makeError(-32000, "No OP_RETURN found in transaction");
        }
        
        // Ensure compatibility
        json compatMeta = ensureMetadataCompatibility(metadata, txid, opReturnScript);
        
        // Store the fixed metadata
        std::string metaKey = "tokenMetadata:" + txid;
        chain.getStorage()->putWithDataChecksum(metaKey, compatMeta.dump());
        
        Logger::log("[handleFixTokenMetadata] Fixed metadata for " + txid);
        
        return makeResult(id, json{
            {"success", true},
            {"message", "Metadata fixed"},
            {"metadata", compatMeta}
        });
        
    } catch (const std::exception& e) {
        return makeError(-32000, std::string("Failed to fix metadata: ") + e.what());
    }
}

//========================
//  Handle Verify Token Metadata
//========================
static json handleVerifyTokenMetadata(Blockchain &chain, const json &params, int id) {
    if (!params.contains("txid")) {
        return makeError(-32602, "Missing txid parameter");
    }
    
    std::string txid = params["txid"].get<std::string>();
    LevelDBStorage* storage = chain.getStorage();
    
    json result = {
        {"txid", txid},
        {"found", false},
        {"issues", json::array()}
    };
    
    // Check metadata storage
    std::string metaKey = "tokenMetadata:" + txid;
    std::string metaValue;
    if (storage->getWithDataChecksum(metaKey, metaValue)) {
        result["found"] = true;
        try {
            json metadata = json::parse(metaValue);
            result["metadata"] = metadata;
            
            // Verify token UTXO
            if (metadata.contains("tokenVout")) {
                uint32_t tokenVout = metadata["tokenVout"].get<uint32_t>();
                std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(tokenVout);
                std::string tokenUtxoValue;
                
                if (storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
                    result["tokenUTXO"] = json::parse(tokenUtxoValue);
                } else {
                    result["issues"].push_back("Token UTXO not found");
                }
            }
            
            // Verify ownership index
            if (metadata.contains("tokenID") && metadata.contains("owner") && 
                metadata.contains("controllingVout")) {
                std::string tokenID = metadata["tokenID"].get<std::string>();
                std::string owner = metadata["owner"].get<std::string>();
                uint32_t controllingVout = metadata["controllingVout"].get<uint32_t>();
                
                std::string ownershipKey = "tokenOwnerUTXO:" + tokenID + ":" + owner + ":" + 
                                          txid + ":" + std::to_string(controllingVout);
                
                if (storage->exists(ownershipKey)) {
                    result["ownershipIndexed"] = true;
                } else {
                    result["issues"].push_back("Ownership index missing");
                }
            }
            
        } catch (const std::exception& e) {
            result["issues"].push_back("Metadata parse error: " + std::string(e.what()));
        }
    } else {
        result["issues"].push_back("Metadata not found");
    }
    
    result["healthy"] = result["issues"].empty();
    
    return makeResult(id, result);
}

//========================
// Get Smart Contracts
//========================
static json handleGetContracts(Blockchain &chain, const json &params, int id) {
    (void)params;
    try {
        Logger::log("[handleGetContracts] Fetching authoritative contract view from Blockchain::getContracts");

        // SC-21B: Blockchain::getContracts() is the single classification and
        // status authority used by Contract Vault. Do not re-parse identifiers,
        // re-query observed UTXOs, or overwrite type/status fields in RPC.
        // Returning the same object guarantees CLI / explorer / RPC parity for
        // registry identity and structural contract details.
        nlohmann::json result = chain.getContracts();
        if (!result.is_object() ||
            !result.contains("contracts") ||
            !result["contracts"].is_array()) {
            throw std::runtime_error("Malformed contracts payload");
        }

        result["count"] = result["contracts"].size();
        Logger::log(
            "[handleGetContracts] Returning authoritative contract view count=" +
            std::to_string(result["contracts"].size()));
        return makeResult(id, result);

    } catch (const std::exception& e) {
        Logger::log("[handleGetContracts] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to get contracts: ") + e.what());
    }
}

// legacy createsmartcontract RPC removed.
// Contract creation is centralized in createcontracttransaction, which performs
// funded UTXO construction, VM preflight, OP_RETURN value policy, and family allow-list checks.

//=======================================================================
//         TRUScripts - short for TRU blockchain inscriptions
//=======================================================================
static json handleInscribeTRUScript(Blockchain &chain,
                                   Wallet &wallet,
                                   const json &params,
                                   int id) {
    if (!params.contains("data") || !params.contains("owner"))
        return makeError(-32602, "Missing data or owner params");

    std::string dataToInscribe = params["data"];
    std::string ownerAddress = params["owner"];

    try {
        // Delegate to wallet's inscribeTRUScript method which handles all the complexity
        std::string txid = wallet.inscribeTRUScript(dataToInscribe, ownerAddress);
        return makeResult(id, json{{"txid", txid}});
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Handle Inscribe TRUScript Signed
//========================
static uint64_t calculateCurrentSatNumber(Blockchain& chain) {
    uint64_t totalSats = 0;
    int currentHeight = chain.getBestTipHeight();
    
    for (int h = 0; h <= currentHeight; ++h) {
        uint64_t subsidy = chain.calculateSubsidy(h);
        totalSats += subsidy;
    }
    
    return totalSats;
}

static json handleInscribeTRUScriptSigned(Blockchain &chain, const json &params, int id) {
    if (!params.contains("signedTxHex")) {
        return makeError(-32602, "Missing signedTxHex parameter");
    }
    
    try {
        std::string txHex = params["signedTxHex"].get<std::string>();
        
        // Deserialize the signed transaction
        auto raw = hexDecode(txHex);
        Transaction tx = Transaction::deserializeBinary(raw);
        
        // Compute txid
        tx.computeTxId();
        
        Logger::log("[handleInscribeTRUScriptSigned] Processing TRUScript inscription for txid: " + tx.txid);
        
        // Store TRUScript data if provided
        if (params.contains("inscriptionData")) {
            std::string inscriptionData = params["inscriptionData"].get<std::string>();
            
            // Store the inscription data
            std::string dataKey = "truscriptData:" + tx.txid;
            chain.getStorage()->putWithDataChecksum(dataKey, inscriptionData);
            
            // Calculate inscription index by counting existing TRUScripts
            uint64_t inscriptionIndex = 0;
            std::string countKey = "truscriptCount";
            std::string countStr;
            if (chain.getStorage()->getWithDataChecksum(countKey, countStr)) {
                try {
                    inscriptionIndex = std::stoull(countStr) + 1;
                } catch (...) {
                    inscriptionIndex = 1;
                }
            } else {
                inscriptionIndex = 1;
            }
            
            // Update the count
            chain.getStorage()->putWithDataChecksum(countKey, std::to_string(inscriptionIndex));
            
            // Calculate TRU atom number (cumulative TRU atoms from genesis)
            uint64_t satNumber = calculateCurrentSatNumber(chain);
            
            // Calculate size in bytes
            uint64_t sizeBytes = inscriptionData.length();
            
            // Store metadata
            nlohmann::json metadata;
            metadata["type"] = "TRUSCRIPT";
            metadata["owner"] = params.value("owner", "");
            metadata["timestamp"] = std::time(nullptr);
            metadata["inscriptionIndex"] = inscriptionIndex;
            metadata["satNumber"] = satNumber;
            metadata["sizeBytes"] = sizeBytes;
            metadata["height"] = chain.getBestTipHeight() + 1;
            metadata["data"] = inscriptionData; // Store data in metadata too for easier retrieval
            metadata["creationTxid"] = tx.txid;
            metadata["currentTxid"] = tx.txid;
            
            std::string metaKey = "tokenMetadata:" + tx.txid;
            chain.getStorage()->putWithDataChecksum(metaKey, metadata.dump());
            
            Logger::log("[handleInscribeTRUScriptSigned] Stored TRUScript #" + std::to_string(inscriptionIndex) +
                       " with size=" + std::to_string(sizeBytes) + " bytes");
        }
        
        // Add transaction to the bounded ingress queue.
        if (!chain.addTransaction(tx)) {
            Logger::log("[handleInscribeTRUScriptSigned] TX queue admission rejected: " + tx.txid);
            return makeError(-32000, "Transaction queue admission rejected");
        }
        
        Logger::log("[handleInscribeTRUScriptSigned] TRUScript transaction submitted: " + tx.txid);
        
        json result;
        result["txid"] = tx.txid;
        result["success"] = true;
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleInscribeTRUScriptSigned] Exception: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to process signed TRUScript transaction: ") + e.what());
    }
}



//========================
// Send extended token
//========================
static json handleSendToken(Blockchain &chain, Wallet &wallet, const json &p, int id) {
    if(!p.contains("tokenID")||!p.contains("amount")||!p.contains("recipient")||!p.contains("senderAddress"))
        return makeError(-32602,"Missing params");
    std::string err;
    if(!validateBase58Address(p["recipient"],err)) return makeError(-32602,"Bad recipient: "+err);
    if(!validateBase58Address(p["senderAddress"],err)) return makeError(-32602,"Bad sender: "+err);
    try {
        auto tid = p["tokenID"].get<std::string>();
        uint64_t amt = p["amount"].get<uint64_t>();
        auto rec = p["recipient"].get<std::string>();
        auto snd = p["senderAddress"].get<std::string>();
        auto [utxoTx,controllingVout, utxoV] = wallet.findTokenUTXO(tid,snd);
        wallet.setCurrentAddress(snd);
        auto txid = wallet.transferExtendedToken(utxoTx,controllingVout,amt,rec);
        return makeResult(id,json{{"txid",txid}});
    } catch(const std::exception &e) {
        return makeError(-32000,e.what());
    }
}

//================================================================
// TOKEN-BURN-01 — canonical sink information
//================================================================
static json handleGetTokenBurnInfo(int id) {
    return makeResult(id, json{
        {"version", tru_token_burn_v1::VERSION},
        {"address", tru_token_burn_v1::BURN_ADDRESS},
        {"hash160", tru_token_burn_v1::BURN_HASH160_HEX},
        {"consensusChange", false},
        {"transactionType", "ordinary canonical token transfer"},
        {"historyDeleted", false},
        {"spendability",
            "No private key is known for the all-zero HASH160 sink; spending would require a cryptographic preimage break."}
    });
}

//================================================================
// TOKEN-BURN-01 — authenticated native-wallet burn
//================================================================
static json handleBurnToken(
    Blockchain&,
    Wallet& wallet,
    const json& params,
    int id)
{
    if (!params.contains("tokenID") ||
        !params.contains("senderAddress") ||
        !params.contains("confirm")) {
        return makeError(
            -32602,
            "Missing required parameters: tokenID, senderAddress, confirm");
    }

    const std::string confirmation = params["confirm"].get<std::string>();
    if (confirmation != "BURN")
        return makeError(
            -32602,
            "Permanent burn requires confirm=\"BURN\"");

    try {
        const std::string tokenID = params["tokenID"].get<std::string>();
        const std::string sender = params["senderAddress"].get<std::string>();
        std::string err;
        if (!validateBase58Address(sender, err))
            return makeError(-32602, "Invalid sender: " + err);

        const std::string txid = wallet.burnToken(tokenID, sender);
        return makeResult(id, json{
            {"success", true},
            {"txid", txid},
            {"tokenID", tokenID},
            {"from", sender},
            {"burnAddress", tru_token_burn_v1::BURN_ADDRESS},
            {"burnVersion", tru_token_burn_v1::VERSION},
            {"permanent", true},
            {"historyDeleted", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

//========================
// New HD address
//========================
static json handleGetNewAddress(Wallet& wallet, const json &/*params*/, int id) {
    try {
        if (wallet.getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_LOCKED) {
            return makeError(
                -32000,
                "getnewaddress requires an unlocked encrypted wallet");
        }
        if (wallet.getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
            return makeError(
                -32000,
                "getnewaddress is available only through the authenticated encrypted wallet");
        }

        std::string address;
        std::string publicKeyHex;
        std::uint32_t index = 0U;
        std::string error;
        if (!wallet.generateNewAddressEncrypted(
                address,
                publicKeyHex,
                index,
                &error)) {
            return makeError(
                -32000,
                error.empty()
                    ? "authenticated encrypted getnewaddress failed"
                    : error);
        }

        Logger::log(
            "[handleGetNewAddress] WALLET-ADDRESS-01 generated index=" +
            std::to_string(index) + " address=" + address);
        return makeResult(id, json{
            {"address", address},
            {"publicKey", publicKeyHex},
            {"index", index}
        });
    } catch (const std::exception& e) {
        Logger::log(
            "[handleGetNewAddress] WALLET-ADDRESS-01 error: " +
            std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
//========================
// Get block template
//========================
static json handleGetBlockTemplate(Blockchain &chain, const json &params = json::object()) {
    //
    // Hash + height must come from one chain snapshot so the template cannot
    // mix an old parent hash with a new height (or vice versa).
    std::string parentHash;
    int tipHeight = 0;
    chain.getBestTipSnapshot(parentHash, tipHeight);
    const int nextHeight = tipHeight + 1;
    uint64_t subsidy = chain.calculateSubsidy(nextHeight);
    json gbt = {
        {"version", 0x20000000},
        {"previousblockhash", parentHash},
        {"curtime", static_cast<uint64_t>(std::time(nullptr))},
        {"height", static_cast<uint64_t>(nextHeight)},
        {"transactions", json::array()},
        {"sizelimit", tru_limits::MAX_BLOCK_BYTES},
        {"assemblylimit", tru_limits::BLOCK_ASSEMBLY_BYTES}
    };
    // FIX(patch29) + TRU Security Patch 07:
    // Serve the SAME difficulty bits the validator enforces, derived from the
    // exact previousblockhash advertised above rather than active-chain height.
    gbt["bits"] = chain.calculateExpectedBits(parentHash, nextHeight);

    // size-aware template construction.  Previously the RPC put
    // the entire mempool into every template, so a busy mempool could create a
    // candidate larger than consensus allowed.  Size against the same textual
    // transaction representation Block::serialize() ultimately measures and
    // leave the shared 8 MiB metadata/header reserve.
    auto mempoolTxs = chain.getMempoolTransactions();
    uint64_t totalFees = 0;

    // getblocktemplate is a second line of defense.
    // Even if a malformed/stale entry somehow reaches the pool, fee arithmetic
    // must never wrap and poison every template.
    if (subsidy > tru_limits::MAX_MONEY) {
        throw std::runtime_error("getblocktemplate subsidy exceeds MAX_MONEY");
    }
    const uint64_t maxTemplateFees = tru_limits::MAX_MONEY - subsidy;

    size_t assembledBytes = 4096; // conservative header + coinbase + delimiters reserve
    size_t skippedForSize = 0;

    // test-validate every mempool transaction against the
    // prospective height BEFORE it goes into the template.
    //
    // Previously the whole mempool was copied in unconditionally. One
    // transaction that consensus would refuse was therefore re-included in
    // every template forever: the miner solved it, validateBlock() threw the
    // block away, the tip never moved, and block production stopped dead
    // until someone restarted the node and lost the mempool. A single bad
    // transaction should cost one transaction, not the whole chain.
    //
    // The checks below mirror validateBlock() Step 8 (missing/spent inputs,
    // coinbase maturity) plus an intra-template double-spend guard.
    size_t skippedInvalid = 0;
    std::unordered_set<std::string> templateSpends;

    // Bind to the real consensus constant so this can never drift from
    // validateBlock(). Wallet::findOneSpendableUtxo() already uses
    // COINBASE_MATURITY directly, so it is visible outside blockchain.cpp.
    // If your build does not expose it here, substitute 100, which is the
    // value handleListUnspent uses as kRpcCoinbaseMaturity.
    static constexpr int kTemplateCoinbaseMaturity =
        static_cast<int>(COINBASE_MATURITY);

    for (const auto& tx : mempoolTxs) {
        const size_t txCost = tx.serialize().size() + 32;
        if (txCost > tru_limits::BLOCK_ASSEMBLY_BYTES ||
            assembledBytes > tru_limits::BLOCK_ASSEMBLY_BYTES - txCost) {
            ++skippedForSize;
            continue;
        }

        bool includable = true;
        std::string rejectWhy;
        std::unordered_set<std::string> thisTxSpends;

        if (tx.isCoinbase) {
            // validateBlock() rejects any block whose non-first transaction is
            // a coinbase ("Multiple coinbase transactions detected"). A
            // coinbase should never reach the mempool, but if one ever does it
            // must not be allowed to wedge every subsequent template.
            includable = false;
            rejectWhy = "coinbase transaction found in mempool";
        } else {
            for (const auto& vin : tx.vin) {
                if (vin.txid.size() != 64 || !isValidHex(vin.txid) ||
                    vin.vout < 0) {
                    includable = false;
                    rejectWhy = "malformed input outpoint";
                    break;
                }

                const std::string outpoint =
                    vin.txid + ":" + std::to_string(vin.vout);

                // templateSpends catches a conflict with an earlier tx in this
                // template; thisTxSpends catches a transaction that lists the
                // same outpoint twice in its own vin.
                if (templateSpends.count(outpoint) ||
                    !thisTxSpends.insert(outpoint).second) {
                    includable = false;
                    rejectWhy = "duplicate or double-spent input: " + outpoint;
                    break;
                }

                UTXO u;
                if (!chain.utxoSet.getUTXO(vin.txid, vin.vout, u)) {
                    includable = false;
                    rejectWhy = "missing or already spent input: " + outpoint;
                    break;
                }

                if (u.isCoinbase) {
                    const int createdAt = static_cast<int>(u.createdAtHeight);
                    if (nextHeight <= createdAt ||
                        (nextHeight - createdAt) < kTemplateCoinbaseMaturity) {
                        includable = false;
                        rejectWhy = "immature coinbase input: " + outpoint +
                                    " (created at height " +
                                    std::to_string(createdAt) +
                                    ", needs " +
                                    std::to_string(kTemplateCoinbaseMaturity) +
                                    " confirmations)";
                        break;
                    }
                }
            }
        }

        if (!includable) {
            ++skippedInvalid;
            Logger::log("[getblocktemplate] Skipping unmineable mempool tx " +
                        tx.txid + ": " + rejectWhy);
            continue;
        }

        // Fee computation and serialisation can throw on a malformed
        // transaction. Isolate it per transaction: one bad entry must cost one
        // entry, never the whole getblocktemplate call, or the miner is left
        // with no work at all and mining stops for a different reason.
        uint64_t fee = 0;
        std::string txHex;
        try {
            fee = tx.computeFee(chain);
            txHex = bytesToHex(tx.serializeBinary());
        } catch (const std::exception& e) {
            ++skippedInvalid;
            Logger::log("[getblocktemplate] Skipping mempool tx " + tx.txid +
                        ": fee/serialisation failed: " + e.what());
            continue;
        } catch (...) {
            ++skippedInvalid;
            Logger::log("[getblocktemplate] Skipping mempool tx " + tx.txid +
                        ": unknown fee/serialisation failure");
            continue;
        }

        if (fee > maxTemplateFees ||
            totalFees > maxTemplateFees - fee) {
            ++skippedInvalid;
            Logger::log(
                "[getblocktemplate] Skipping mempool tx " + tx.txid +
                ": fee total would exceed MAX_MONEY");
            continue;
        }

        for (const auto& outpoint : thisTxSpends) {
            templateSpends.insert(outpoint);
        }

        totalFees += fee; // checked above
        gbt["transactions"].push_back({{"data", txHex}, {"fee", fee}});
        assembledBytes += txCost;
    }

    gbt["coinbasevalue"] = subsidy + totalFees; // overflow-safe by maxTemplateFees invariant
    gbt["estimatedblockbytes"] = assembledBytes;
    gbt["skippedforsize"] = skippedForSize;
    gbt["skippedinvalid"] = skippedInvalid;

    // WEB-MINER-01: browser mining must hash the exact candidate the node will
    // later validate.  Legacy wallet.js tried to manufacture a Bitcoin-style
    // block in JavaScript even though TRU submitblock accepts Block::serialize().
    // When browserMinerAddress is supplied, prepare the canonical candidate
    // here using the same transaction classes, merkle routine and header builder
    // as the native miner.  This is work preparation only; consensus and block
    // validation are unchanged.
    if (params.contains("browserMinerAddress")) {
        if (!params["browserMinerAddress"].is_string()) {
            throw std::runtime_error("browserMinerAddress must be a string");
        }
        const std::string minerAddr =
            params["browserMinerAddress"].get<std::string>();
        if (!chain.isValidAddress(minerAddr)) {
            throw std::runtime_error("invalid browser miner address");
        }

        int extraNonce = 0;
        if (params.contains("browserExtraNonce")) {
            const auto& rawExtraNonce = params["browserExtraNonce"];
            if (rawExtraNonce.is_number_unsigned()) {
                const uint64_t value = rawExtraNonce.get<uint64_t>();
                if (value > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
                    throw std::runtime_error("browserExtraNonce out of range");
                }
                extraNonce = static_cast<int>(value);
            } else if (rawExtraNonce.is_number_integer()) {
                const int64_t value = rawExtraNonce.get<int64_t>();
                if (value < 0 ||
                    value > static_cast<int64_t>(std::numeric_limits<int>::max())) {
                    throw std::runtime_error("browserExtraNonce out of range");
                }
                extraNonce = static_cast<int>(value);
            } else {
                throw std::runtime_error("browserExtraNonce must be an integer");
            }
        }

        const std::string bitsHex = gbt["bits"].get<std::string>();
        const uint32_t bitsVal =
            static_cast<uint32_t>(std::stoul(bitsHex, nullptr, 16));
        const uint32_t workTime =
            static_cast<uint32_t>(gbt["curtime"].get<uint64_t>());
        const int32_t workVersion =
            static_cast<int32_t>(gbt["version"].get<int64_t>());

        // Intentionally mirror my_miner.cpp's candidate construction.
        Block candidate(workVersion, parentHash, workTime, bitsVal);
        candidate.height = nextHeight;

        Transaction coinbase(true);
        std::ostringstream cb;
        cb << "TRU:" << nextHeight << "|WEB:" << extraNonce;
        const std::string cbText = cb.str();
        coinbase.vin.emplace_back(
            "COINBASE",
            0,
            std::vector<unsigned char>(cbText.begin(), cbText.end()),
            std::vector<unsigned char>());
        TxOut rewardOut;
        rewardOut.amount = gbt["coinbasevalue"].get<uint64_t>();
        rewardOut.scriptPubKey =
            createP2PKHScriptHexFromAddress(minerAddr);
        coinbase.vout.push_back(rewardOut);
        coinbase.computeTxId();
        candidate.transactions.push_back(coinbase);

        for (const auto& txItem : gbt["transactions"]) {
            if (!txItem.contains("data") || !txItem["data"].is_string()) {
                continue;
            }
            const std::vector<unsigned char> raw =
                hexDecode(txItem["data"].get<std::string>());
            Transaction memTx = Transaction::deserializeBinary(raw);
            memTx.computeTxId();
            candidate.transactions.push_back(std::move(memTx));
        }

        candidate.header.merkleRoot =
            computeMerkleRoot(candidate.transactions);
        candidate.header.nonce = 0;
        candidate.blockHash = candidate.computeHash();

        const std::vector<unsigned char> header80 =
            buildBlockHeader80(candidate.header);
        unsigned char targetLE[32];
        bitsToTargetArrayFree(bitsVal, targetLE);
        const std::vector<unsigned char> targetBytes(
            targetLE, targetLE + 32);

        gbt["browserWork"] = {
            {"version", "TRU-WEB-MINER-01"},
            {"minerAddress", minerAddr},
            {"extraNonce", extraNonce},
            {"height", candidate.height},
            {"previousblockhash", candidate.header.prevHash},
            {"merkleRoot", candidate.header.merkleRoot},
            {"timestamp", candidate.header.timestamp},
            {"bits", bitsHex},
            {"coinbasevalue", gbt["coinbasevalue"]},
            {"headerHex", bytesToHex(header80)},
            {"targetLEHex", bytesToHex(targetBytes)},
            {"candidate", candidate.serialize()}
        };
    }

    return gbt;
}
//========================
// Submit block
//========================
static json handleSubmitBlockOptimized(Blockchain &chain, P2PNode &node, const json &p, int id) {
    try {
        std::string submittedBlock;

        // WEB-MINER-01: browser miners receive a node-built canonical candidate
        // from getblocktemplate(browserMinerAddress=...).  They only search the
        // 32-bit nonce field.  Rehydrate that exact candidate here, install the
        // winning nonce and recompute the block hash server-side before feeding
        // it into the unchanged authoritative submit/validation path.
        if (p.contains("browserCandidate")) {
            if (!p["browserCandidate"].is_string() ||
                !p.contains("nonce") ||
                !(p["nonce"].is_number_unsigned() ||
                  p["nonce"].is_number_integer())) {
                return makeError(
                    -32602,
                    "browserCandidate requires a serialized candidate and nonce");
            }

            uint32_t browserNonce = 0;
            if (p["nonce"].is_number_unsigned()) {
                const uint64_t value = p["nonce"].get<uint64_t>();
                if (value > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
                    return makeError(-32602, "Browser mining nonce out of range");
                }
                browserNonce = static_cast<uint32_t>(value);
            } else {
                const int64_t value = p["nonce"].get<int64_t>();
                if (value < 0 ||
                    static_cast<uint64_t>(value) >
                        static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
                    return makeError(-32602, "Browser mining nonce out of range");
                }
                browserNonce = static_cast<uint32_t>(value);
            }

            Block prepared =
                Block::deserialize(p["browserCandidate"].get<std::string>());
            prepared.header.nonce = browserNonce;
            prepared.blockHash = prepared.computeHash();
            submittedBlock = prepared.serialize();

            Logger::log(
                "[WEB-MINER-01] Browser solution prepared height=" +
                std::to_string(prepared.height) +
                " nonce=" + std::to_string(prepared.header.nonce) +
                " hash=" + prepared.blockHash);
        } else if (p.contains("blockHex") && p["blockHex"].is_string()) {
            submittedBlock = p["blockHex"].get<std::string>();
        } else {
            return makeError(
                -32602,
                "Missing 'blockHex' or browserCandidate/nonce");
        }

        Block b = Block::deserialize(submittedBlock);
        if (b.blockHash.empty() || b.height <= 0) {
            return makeError(-32000, "Invalid block format");
        }

        if (chain.hasBlock(b.blockHash)) {
            return makeResult(id, json{
                {"status", "duplicate"},
                {"message", "Block already known"},
                {"hash", b.blockHash}
            });
        }

        // MULTINODE-01C: external miners submit through local RPC. Authoritative
        // acceptance remains the existing sole block pipeline; after acceptance,
        // relay the EXACT accepted block to connected peers. RPC no longer owns
        // minerBlockCount/miningReward bookkeeping, avoiding double accounting;
        // connectTipBlock() is the canonical active-chain accounting owner.
        const bool success = chain.submitBlockFromNetwork(b, "rpc");
        if (success) {
            try {
                node.broadcastBlock(b);
                Logger::log(
                    "[MULTINODE-01C] RPC-mined block relayed to peers hash=" +
                    b.blockHash + " height=" + std::to_string(b.height));
            } catch (const std::exception& e) {
                // Local block acceptance is already durable. Relay failure cannot
                // be reported as block rejection; normal sync can reconcile later.
                Logger::log(
                    "[MULTINODE-01C] WARNING: accepted RPC block relay failed: " +
                    std::string(e.what()));
            }
        }

        return makeResult(id, json{
            {"status", success ? "accepted" : "rejected"},
            {"message", success ? "Block accepted" : "Block rejected"},
            {"hash", b.blockHash}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Get block by height
//========================
static json handleGetBlockByHeight(Blockchain &chain, const json &p, int id) {
    // Validate parameters
    if (!p.contains("height") || !p["height"].is_number_integer()) {
        return makeError(-32602, "Missing or invalid 'height'");
    }

    // Extract the requested height
    int h = p["height"].get<int>();

    try {
        // Fetch block by height
        auto optionalB = chain.getBlockByHeight(h);
        if (!optionalB.has_value()) {
            return makeError(-32000, "Block not found");
        }
        Block b = optionalB.value();

        // Build response object
        json jb = {
            {"height",      h},
            {"hash",        b.blockHash},
            {"prevhash",    b.header.prevHash},
            {"merkleroot",  b.header.merkleRoot},
            {"timestamp",   b.header.timestamp},
            {"bits",        b.header.bits},
            {"nonce",       b.header.nonce}
        };

        // Collect transaction IDs
        json txs = json::array();
        for (const auto &tx : b.transactions) {
            txs.push_back(tx.txid);
        }
        jb["tx"] = txs;

        return makeResult(id, jb);

    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Get block by hash
//========================
static json handleGetBlock(Blockchain &chain, const json &p, int id) {
    if (!p.contains("hash") || !p["hash"].is_string()) {
        return makeError(-32602, "Missing or invalid 'hash'");
    }

    // Extract the requested block hash
    std::string hash = p["hash"].get<std::string>();

    try {
        // Fetch the block by its hash
        Block b = chain.getBlock(hash);

        // Use the block's own height field
        int height = b.height;

        // Build the JSON response
        json jb = {
            {"height",     height},
            {"hash",       b.blockHash},
            {"prevhash",   b.header.prevHash},
            {"merkleroot", b.header.merkleRoot},
            {"timestamp",  b.header.timestamp},
            {"bits",       b.header.bits},
            {"nonce",      b.header.nonce}
        };

        // Append all txids
        json txs = json::array();
        for (const auto &tx : b.transactions) {
            txs.push_back(tx.txid);
        }
        jb["tx"] = txs;

        return makeResult(id, jb);
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Get chain info
//========================
static json handleGetChainInfo(Blockchain &chain,int id) {
    json info = {
        {"bestHeight",chain.getBestTipHeight()},
        {"bestHash",chain.getBestTipHash()},
        {"chainSize",chain.getChainSize()},
        {"difficulty",chain.getDifficulty()},
        {"chainValid",chain.isChainValid()}
    };
    return makeResult(id,info);
}
/*
//========================
// 	Send raw tx Web
//========================
static json handleSendTransactionWeb(Blockchain &chain, const json &p, int id) {
    if (!p.contains("txHex") || !p["txHex"].is_string()) {
        return makeError(-32602, "Missing 'txHex'");
    }
    try {
        auto raw = hexDecode(p["txHex"].get<std::string>());
        Transaction tx = Transaction::deserializeBinary(raw);
        tx.computeTxId();

                // WEB_WALLET_PATCH_2:
        // applyBlock() is the only writer of confirmed token ownership.
        if (!chain.broadcastTransaction(tx)) {
            Logger::log(
                "[handleSendTransactionWeb][WEB2] rejected " + tx.txid);
            return makeError(
                -32000,
                "Transaction rejected by mempool; see Tru_debug.log");
        }

        return makeResult(id, json{
            {"txid", tx.txid},
            {"success", true},
            {"accepted", true}
        });\n    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Send raw tx
//========================
static json handleSendTransaction(Blockchain &chain, const json &p, int id) {
    if(!p.contains("txHex")||!p["txHex"].is_string())
        return makeError(-32602,"Missing 'txHex'");
    try {
        auto raw = hexDecode(p["txHex"].get<std::string>());
        Transaction tx = Transaction::deserializeBinary(raw);
        tx.computeTxId();

                // WEB_WALLET_PATCH_2:
        // Never report success unless the node actually accepts the transaction.
        if (!chain.broadcastTransaction(tx)) {
            Logger::log(
                "[handleSendTransaction][WEB2] rejected " + tx.txid);
            return makeError(
                -32000,
                "Transaction rejected by mempool; see Tru_debug.log");
        }

        return makeResult(id, json{
            {"txid", tx.txid},
            {"success", true},
            {"accepted", true}
        });\n    } catch(const std::exception &e) {
        return makeError(-32000,e.what());
    }
}
*/
//========================
// Send raw tx Web - FIXED VERSION
//========================
static json handleSendTransactionWeb(Blockchain &chain, const json &p, int id) {
    // WEB_WALLET_PATCH_2B: signed bytes are immutable.
    if (!p.contains("txHex") || !p["txHex"].is_string())
        return makeError(-32602, "Missing 'txHex'");

    try {
        Transaction tx =
            Transaction::deserializeBinary(
                hexDecode(p["txHex"].get<std::string>()));
        tx.computeTxId();

        Logger::log(
            "[handleSendTransactionWeb][WEB2B] immutable submit " + tx.txid);

        if (!chain.broadcastTransaction(tx)) {
            Logger::log(
                "[handleSendTransactionWeb][WEB2B] mempool rejected " + tx.txid);
            return makeError(
                -32000,
                "Transaction rejected by mempool; no token indexes changed");
        }

        return makeResult(id, json{
            {"txid", tx.txid},
            {"success", true},
            {"accepted", true}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Send raw tx - FIXED VERSION
//========================
static json handleSendTransaction(Blockchain &chain, const json &p, int id) {
    // WEB_WALLET_PATCH_2B: signed bytes are immutable.
    // NO cleanupSpentTokenUTXOs/processTokenTransferIndexing before acceptance.
    if (!p.contains("txHex") || !p["txHex"].is_string())
        return makeError(-32602, "Missing 'txHex'");

    try {
        Transaction tx =
            Transaction::deserializeBinary(
                hexDecode(p["txHex"].get<std::string>()));
        tx.computeTxId();

        Logger::log(
            "[handleSendTransaction][WEB2B] immutable submit " + tx.txid);

        if (!chain.broadcastTransaction(tx)) {
            Logger::log(
                "[handleSendTransaction][WEB2B] mempool rejected " + tx.txid);
            return makeError(
                -32000,
                "Transaction rejected by mempool; no token indexes changed");
        }

        return makeResult(id, json{
            {"txid", tx.txid},
            {"success", true},
            {"accepted", true}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Get mempool txs
//========================
static json handleGetMempoolTransactions(Blockchain &chain,int id) {
    json arr = json::array();
    for(auto &tx:chain.getMempoolTransactions()) arr.push_back(bytesToHex(tx.serializeBinary()));
    return makeResult(id,arr);
}

//========================
// List unspent
//========================
static json handleListUnspentWeb(Blockchain &chain, const json &p, int id) {
    // WEB_WALLET_PATCH_2: publish actual spendability.
    if (!p.contains("address") || !p["address"].is_string())
        return makeError(-32602, "Missing 'address'");

    const std::string addr = p["address"].get<std::string>();
    std::string err;
    if (!validateBase58Address(addr, err))
        return makeError(-32602, "Invalid address: " + err);

    LevelDBStorage* storage = chain.getStorage();
    if (!storage)
        return makeError(-32000, "Storage unavailable");

    const int tip = chain.getBestTipHeight();
    const uint32_t candidateHeight =
        tip >= 0 ? static_cast<uint32_t>(tip + 1) : 0;

    std::vector<std::string> indexed;
    getUTXOsForAddress(storage, addr, indexed, tip);

    std::set<std::string> spentInMempool;
    for (const auto& tx : chain.getMempoolTransactions()) {
        for (const auto& in : tx.vin)
            spentInMempool.insert(in.txid + ":" + std::to_string(in.vout));
    }

    json arr = json::array();

    for (const auto& idstr : indexed) {
        try {
            if (spentInMempool.count(idstr))
                continue;

            const size_t colon = idstr.find(':');
            if (colon == std::string::npos)
                continue;

            const std::string txid = idstr.substr(0, colon);
            const uint32_t vout =
                static_cast<uint32_t>(std::stoul(idstr.substr(colon + 1)));

            UTXO u;
            if (!chain.utxoSet.getUTXO(txid, vout, u))
                continue;
            if (u.amount == 0)
                continue;

            const std::string script = u.scriptPubKey;
            const bool standardP2PKH =
                script.size() == 50 &&
                script.rfind("76a914", 0) == 0 &&
                script.compare(script.size() - 4, 4, "88ac") == 0 &&
                std::all_of(script.begin(), script.end(),
                    [](unsigned char c) { return std::isxdigit(c) != 0; });

            std::string decodedAddress;
            if (standardP2PKH) {
                try { decodedAddress = extractP2PKHAddressCorrect(script); }
                catch (...) { decodedAddress.clear(); }
            }
            if (decodedAddress != addr)
                continue;

            const bool tokenControl =
                storage->exists(
                    "tokenUTXO:" + txid + ":" + std::to_string(vout));

            bool mature = true;
            uint32_t spendableAt = 0;
            if (u.isCoinbase) {
                spendableAt =
                    u.createdAtHeight +
                    static_cast<uint32_t>(COINBASE_MATURITY);
                mature =
                    tip >= 0 &&
                    candidateHeight > u.createdAtHeight &&
                    candidateHeight - u.createdAtHeight >=
                        static_cast<uint32_t>(COINBASE_MATURITY);
            }

            const bool spendable =
                standardP2PKH && mature && !tokenControl;

            arr.push_back({
                {"txid", txid},
                {"vout", vout},
                {"address", addr},
                {"scriptPubKey", script},
                {"amount", static_cast<double>(u.amount) / 100000000.0}, // legacy numeric TRU
                {"amount_tru", tru_amount::formatNumeric(u.amount)},
                {"amount_atoms", u.amount},
                {"confirmations",
                    tip >= static_cast<int>(u.createdAtHeight)
                        ? tip - static_cast<int>(u.createdAtHeight) + 1
                        : 0},
                {"spendable", spendable},
                {"isTokenControl", tokenControl},
                {"isCoinbase", u.isCoinbase},
                {"createdAtHeight", u.createdAtHeight},
                {"spendableAt",
                    u.isCoinbase ? json(spendableAt) : json(nullptr)}
            });
        } catch (const std::exception& e) {
            Logger::log(
                "[handleListUnspentWeb][WEB2] skipped " +
                idstr + ": " + e.what());
        }
    }

    Logger::log(
        "[handleListUnspentWeb][WEB2] returning " +
        std::to_string(arr.size()) + " entries for " + addr);
    return makeResult(id, arr);
}

static json handleListUnspent(Blockchain &chain, const json &p, int id) {
    // Validate input parameters
    if (!p.contains("address") || !p["address"].is_string()) 
        return makeError(-32602, "Missing 'address'");
    
    std::string addr = p["address"].get<std::string>();
    std::string err;
    if (!validateBase58Address(addr, err)) 
        return makeError(-32602, "Invalid address: " + err);
    
    // Get blockchain state
    int tip = chain.getBestTipHeight();
    auto storage = chain.getStorage();
    
    // Retrieve all UTXOs for the address
    std::vector<std::string> utxos;
    getUTXOsForAddress(storage, addr, utxos, tip);
    
    // Filter out UTXOs spent in the mempool
    auto mempoolTxs = chain.getMempoolTransactions();
    std::set<std::string> spentInMempool;
    for (const auto& tx : mempoolTxs) {
        for (const auto& in : tx.vin) {
            spentInMempool.insert(in.txid + ":" + std::to_string(in.vout));
        }
    }
    
    json arr = json::array();
    for (const auto &idstr : utxos) {
        // Skip if spent in mempool
        if (spentInMempool.count(idstr)) 
            continue;
        
        // Parse txid and vout
        auto ppos = idstr.find(':');
        auto txid = idstr.substr(0, ppos);
        int vout = std::stoi(idstr.substr(ppos + 1));
        std::string utxoKey = "utxo:" + txid + ":" + std::to_string(vout);
        
        // Fetch UTXO data
        std::string raw;
        if (!storage->get(utxoKey, raw)) {
            continue; // UTXO was spent
        }
        
        std::istringstream iss(raw);
        std::string h, s, scr;
        std::getline(iss, h, '|');
        std::getline(iss, s, '|');
        // stop at the script field delimiter so trailing
        // UTXO metadata (for example cb=1) is not appended to scriptPubKey.
        std::getline(iss, scr, '|');

        bool isCoinbase = false;
        std::string metadataField;
        while (std::getline(iss, metadataField, '|')) {
            if (metadataField == "cb=1") {
                isCoinbase = true;
            }
        }
        
        uint64_t amount = std::stoull(s);
        // Skip unspendable UTXOs (e.g., OP_RETURN)
        if (amount == 0) {
            continue;
        }
        
        int bh = std::stoi(h.substr(7));
        int conf = tip >= bh ? tip - bh + 1 : 0;
        double amt = amount / 1e8;

        // Wallet::rpcListUnspent() consumes this RPC but does
        // not currently inspect the JSON 'spendable' flag. Filter immature
        // coinbase UTXOs here so callers cannot accidentally select one.
        //
        // Current TRU consensus maturity is 100 confirmations.
        static constexpr int kRpcCoinbaseMaturity = 100;
        bool spendable =
            !isCoinbase || conf >= kRpcCoinbaseMaturity;

        if (!spendable) {
            continue;
        }
        
        // Check if this is a controlling UTXO for a token
        bool isTokenControllingUTXO = false;
        std::string tokenID;
        if (vout > 0) {
            std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(vout - 1);
            std::string tokenUtxoValue;
            if (storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
                try {
                    json j = json::parse(tokenUtxoValue);
                    if (j.contains("tokenID")) {
                        isTokenControllingUTXO = true;
                        tokenID = j["tokenID"].get<std::string>();
                    }
                } catch (const std::exception& e) {
                    Logger::log("[handleListUnspent] Error parsing tokenUTXO data for " + tokenUtxoKey + ": " + e.what());
                }
            }
        }
        
        // If it's a token controlling UTXO, verify current ownership
        if (isTokenControllingUTXO) {
            std::string ownershipKey = "tokenOwnerUTXO:" + tokenID + ":" + addr + ":" + txid + ":" + std::to_string(vout);
            if (!storage->exists(ownershipKey)) {
                continue; // Skip if the address no longer owns the token
            }
        }
        
        // Add the UTXO to the result
        arr.push_back({
            {"txid", txid},
            {"vout", vout},
            {"address", addr},
            {"scriptPubKey", scr},
            {"amount", amt},
            {"confirmations", conf},
            {"spendable", spendable}
        });
    }
    
    return makeResult(id, arr);
}
//========================
// Get block count
//========================
static json handleGetBlockCount(Blockchain &chain, int id) {
    try {
        int height = chain.getBestTipHeight();
        return makeResult(id, height);
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Get transaction
//========================
static json handleGetTransaction(Blockchain &chain, const json &params, int id) {
    // TRU REORG-TX-01 RPC:
    // Return explicit CURRENT chain location instead of overloading confirmation
    // counts or collapsing known non-active transactions into "not found".
    if (!params.contains("txid") || !params["txid"].is_string()) {
        return makeError(-32602, "Missing or invalid 'txid'");
    }

    const std::string txid = params["txid"].get<std::string>();

    try {
        KnownTransactionStatus s;
        if (!chain.getKnownTransactionStatus(txid, s)) {
            return makeResult(id, json{
                {"txid", txid},
                {"txState", "NOT_FOUND"},
                {"known", false},
                {"active", false},
                {"confirmations", 0},
                {"reorgSignal", false}
            });
        }

        if (s.location == "MEMPOOL") {
            return makeResult(id, json{
                {"txid", s.transaction.txid},
                {"hex", bytesToHex(s.transaction.serializeBinary())},
                {"txState", "MEMPOOL"},
                {"known", true},
                {"active", false},
                {"confirmations", 0},
                {"blockheight", nullptr},
                {"blockhash", nullptr},
                {"time", static_cast<uint64_t>(std::time(nullptr))},
                {"blocktime", 0},
                {"reorgSignal", false}
            });
        }

        if (s.location == "ACTIVE") {
            const int confirmations = s.tipHeight - s.blockHeight + 1;
            if (s.blockHeight < 1 ||
                s.tipHeight < s.blockHeight ||
                confirmations < 1 ||
                s.blockHash.empty()) {
                return makeError(
                    -32000,
                    "Active transaction produced inconsistent confirmation metadata");
            }

            return makeResult(id, json{
                {"txid", s.transaction.txid},
                {"hex", bytesToHex(s.transaction.serializeBinary())},
                {"txState", "CONFIRMED"},
                {"known", true},
                {"active", true},
                {"confirmations", confirmations},
                {"blockheight", s.blockHeight},
                {"blockhash", s.blockHash},
                {"time", s.blockTime},
                {"blocktime", s.blockTime},
                {"reorgSignal", false}
            });
        }

        if (s.location == "SIDECHAIN") {
            const std::string state =
                s.conflicted ? "CONFLICTED" : "SIDECHAIN";

            json result = {
                {"txid", s.transaction.txid},
                {"hex", bytesToHex(s.transaction.serializeBinary())},
                {"txState", state},
                {"known", true},
                {"active", false},
                {"confirmations", 0},
                {"sideBlockHeight", s.blockHeight},
                {"sideBlockHash", s.blockHash},
                {"sideBlockTime", s.blockTime},
                {"reorgSignal", true},
                {"conflicted", s.conflicted}
            };

            if (s.conflicted) {
                result["conflictingTxid"] = s.conflictingTxid;
            } else {
                result["conflictingTxid"] = nullptr;
            }

            return makeResult(id, result);
        }

        return makeError(-32000, "Unknown transaction chain-location state");
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//========================
// Decode raw transaction
//========================
static json handleDecodeRawTransaction(const json &params, int id) {
    if (!params.contains("txHex") || !params["txHex"].is_string()) {
        return makeError(-32602, "Missing or invalid 'txHex'");
    }
    
    try {
        std::string txHex = params["txHex"].get<std::string>();
        auto raw = hexDecode(txHex);
        Transaction tx = Transaction::deserializeBinary(raw);
        
        json result = {
            {"txid", tx.txid},
            {"version", tx.version},
            {"locktime", tx.lockTime},
            {"vin", json::array()},
            {"vout", json::array()}
        };
        
        // Add inputs
        for (const auto& input : tx.vin) {
            json in = {
                {"txid", input.txid},
                {"vout", input.vout},
                {"scriptSig", {
                    {"hex", bytesToHex(input.scriptSig)}
                }},
                {"sequence", input.sequence}
            };
            result["vin"].push_back(in);
        }
        
        // Add outputs
        for (size_t i = 0; i < tx.vout.size(); i++) {
            const auto& output = tx.vout[i];
            json out = {
                {"value", output.amount / 1e8},
                {"n", i},
                {"scriptPubKey", {
                    {"hex", output.scriptPubKey}
                }}
            };
            result["vout"].push_back(out);
        }
        
        return makeResult(id, result);
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//======================================================================
// TRU REORG-EXIT-01B — read-only exact exit transaction policy probe
//======================================================================
static json handleSwapTestExitMempoolAccept(
    Blockchain &chain, const json &params, int id) {

    // This RPC is intentionally narrower than a generic testmempoolaccept.
    // It proves whether the exact already-existing one-input HTLC exit bytes
    // are presently acceptable without inserting, evicting, relaying, signing,
    // or otherwise mutating chain/mempool/wallet state.
    if (!params.contains("txHex") || !params["txHex"].is_string() ||
        !params.contains("expectedTxid") || !params["expectedTxid"].is_string() ||
        !params.contains("fundingTxid") || !params["fundingTxid"].is_string() ||
        !params.contains("fundingVout") || !params["fundingVout"].is_number_unsigned()) {
        return makeError(
            -32602,
            "swaptestexitmempoolaccept requires txHex, expectedTxid, fundingTxid, fundingVout");
    }

    const std::string expectedTxid = params["expectedTxid"].get<std::string>();
    const std::string fundingTxid = params["fundingTxid"].get<std::string>();
    const std::uint64_t fundingVout64 = params["fundingVout"].get<std::uint64_t>();
    if (expectedTxid.size() != 64U || !isHex(expectedTxid) ||
        fundingTxid.size() != 64U || !isHex(fundingTxid) ||
        fundingVout64 > std::numeric_limits<std::uint32_t>::max()) {
        return makeError(-32602, "invalid exact-exit identity/outpoint parameters");
    }
    const std::uint32_t fundingVout = static_cast<std::uint32_t>(fundingVout64);

    auto hold = [&](const std::string& reason, const std::string& txid = std::string{}) {
        return makeResult(id, json{
            {"version", "TRU-REORG-EXIT-01B"},
            {"scope", "EXACT_HTLC_EXIT_RECOVERY"},
            {"allowed", false},
            {"readOnly", true},
            {"txid", txid},
            {"reason", reason},
            {"mempoolMutation", false},
            {"transactionBroadcast", false},
            {"walletMutation", false}
        });
    };

    try {
        const std::string txHex = params["txHex"].get<std::string>();
        if (txHex.empty() || (txHex.size() & 1U) != 0U ||
            txHex.size() > 2U * 1024U * 1024U) {
            return hold("RAW_HEX_SHAPE_INVALID");
        }

        Transaction tx = Transaction::deserializeBinary(hexDecode(txHex));
        tx.computeTxId();
        if (tx.txid != expectedTxid) {
            return hold("DECODED_TXID_IDENTITY_MISMATCH", tx.txid);
        }
        if (tx.isCoinbase || tx.vin.size() != 1U || tx.vout.size() != 1U) {
            return hold("EXIT_TRANSACTION_SHAPE_NOT_EXACT_ONE_IN_ONE_OUT", tx.txid);
        }
        if (tx.vin[0].txid != fundingTxid || tx.vin[0].vout < 0 ||
            static_cast<std::uint32_t>(tx.vin[0].vout) != fundingVout) {
            return hold("EXIT_TRANSACTION_FUNDING_OUTPOINT_MISMATCH", tx.txid);
        }
        if (!chain.mempool) {
            return hold("MEMPOOL_UNAVAILABLE", tx.txid);
        }

        std::vector<unsigned char> serialized;
        try {
            serialized = tx.serializeBinary();
        } catch (...) {
            return hold("SERIALIZATION_FAILED", tx.txid);
        }
        const std::size_t serializedSize = serialized.size();
        if (serializedSize == 0U ||
            serializedSize > tru_limits::MAX_MEMPOOL_TX_BYTES) {
            return hold("MEMPOOL_TX_SIZE_POLICY", tx.txid);
        }

        // Exact transaction must be absent. REORG-EXIT-01A treats MEMPOOL as
        // observe-only, not as rebroadcast eligibility.
        if (chain.mempool->hasTransaction(tx.txid)) {
            return hold("EXACT_TX_ALREADY_IN_MEMPOOL", tx.txid);
        }

        // FIRST-SEEN conflict proof against the current mempool snapshot.
        const auto pool = chain.getMempoolTransactions();
        std::size_t poolBytes = 0U;
        for (const auto& existing : pool) {
            for (const auto& in : existing.vin) {
                if (in.txid == fundingTxid && in.vout >= 0 &&
                    static_cast<std::uint32_t>(in.vout) == fundingVout) {
                    return hold("MEMPOOL_INPUT_CONFLICT", tx.txid);
                }
            }
            try {
                const std::size_t n = existing.serializeBinary().size();
                if (n > tru_limits::MAX_MEMPOOL_BYTES ||
                    poolBytes > tru_limits::MAX_MEMPOOL_BYTES - n) {
                    return hold("MEMPOOL_CAPACITY_ACCOUNTING_UNPROVABLE", tx.txid);
                }
                poolBytes += n;
            } catch (...) {
                return hold("MEMPOOL_CAPACITY_ACCOUNTING_UNPROVABLE", tx.txid);
            }
        }

        // Active-chain outpoint proof. If the winning chain already consumed
        // the HTLC outpoint, exact same-tx recovery is unsafe/impossible.
        UTXO fundingUtxo;
        if (!chain.utxoSet.getUTXO(fundingTxid, fundingVout, fundingUtxo)) {
            return hold("ACTIVE_CHAIN_FUNDING_OUTPOINT_SPENT_OR_MISSING", tx.txid);
        }

        std::uint64_t fee = 0;
        try {
            fee = tx.computeFee(chain);
        } catch (...) {
            return hold("FEE_COMPUTATION_FAILED", tx.txid);
        }
        if (serializedSize > static_cast<std::size_t>(
                tru_limits::MAX_MONEY /
                tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE)) {
            return hold("MINIMUM_FEE_ARITHMETIC_OVERFLOW", tx.txid);
        }
        const std::uint64_t minimumFee =
            static_cast<std::uint64_t>(serializedSize) *
            tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE;
        if (fee < minimumFee) {
            return hold("BELOW_MINIMUM_RELAY_FEE", tx.txid);
        }

        // Conservative capacity proof: if admission would require fee-rate
        // eviction, do NOT mutate the pool merely to discover eligibility.
        if (pool.size() >= tru_limits::MAX_MEMPOOL_TXS ||
            serializedSize > tru_limits::MAX_MEMPOOL_BYTES ||
            poolBytes > tru_limits::MAX_MEMPOOL_BYTES - serializedSize) {
            return hold("READ_ONLY_CAPACITY_PROOF_REQUIRES_NO_EVICTION", tx.txid);
        }

        const MempoolValidationStatus validation =
            chain.mempool->validateTransaction(tx, &chain);
        if (validation == MempoolValidationStatus::BUSY) {
            return hold("VALIDATION_BUDGET_BUSY", tx.txid);
        }
        if (validation != MempoolValidationStatus::VALID) {
            return hold("MEMPOOL_POLICY_INVALID", tx.txid);
        }

        return makeResult(id, json{
            {"version", "TRU-REORG-EXIT-01B"},
            {"scope", "EXACT_HTLC_EXIT_RECOVERY"},
            {"allowed", true},
            {"readOnly", true},
            {"txid", tx.txid},
            {"fundingTxid", fundingTxid},
            {"fundingVout", fundingVout},
            {"serializedBytes", serializedSize},
            {"feeAtoms", fee},
            {"minimumFeeAtoms", minimumFee},
            {"mempoolMutation", false},
            {"transactionBroadcast", false},
            {"walletMutation", false}
        });
    } catch (const std::exception& e) {
        return hold(std::string("EXACT_EXIT_POLICY_PROBE_ERROR: ") + e.what());
    } catch (...) {
        return hold("EXACT_EXIT_POLICY_PROBE_UNKNOWN_ERROR");
    }
}

//========================
// List transactions 
//========================
static json handleListTransactions(Blockchain &chain, const json &params, int id) {
    std::string address = "";
    int count = 100;
    
    if (params.contains("address") && params["address"].is_string()) {
        address = params["address"].get<std::string>();
    }
    if (params.contains("count") && params["count"].is_number()) {
        count = params["count"].get<int>();
    }
    
    try {
        json result = json::array();
        
        // This is a simplified implementation
        // In a real implementation, you would:
        // 1. Index transactions by address
        // 2. Return the most recent 'count' transactions for the address
        // 3. Include proper transaction details
        
        // For now, return an empty array to prevent errors
        return makeResult(id, result);
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Issue token 
//========================
static json handleIssueToken(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("type") || !params.contains("tokenID") || 
        !params.contains("address")) {  // Removed metadata check since web doesn't send it
        return makeError(-32602, "Missing required parameters");
    }
    
    try {
        std::string type = params["type"].get<std::string>();
        std::string tokenID = params["tokenID"].get<std::string>();

        // Legacy commented tokenID normalization (pre TOKEN-AI-01B2)
/*        std::string truncatedTokenID;
        if (tokenID.size() == 16 && isHex(tokenID))
        {
            truncatedTokenID = tokenID;
        }
        else
        {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char *>(tokenID.c_str()), tokenID.size(), hash);
            truncatedTokenID = bytesToHex(std::vector<unsigned char>(hash, hash + 4)); // legacy 32-bit path (commented out)
        }
*/
        std::string address = params["address"].get<std::string>();
        uint64_t supply = 0;
        
        if (params.contains("supply")) {
            supply = params["supply"].get<uint64_t>();
        }
        
        // Validate token type
        if (type != "FT" && type != "NFT" && type != "SFT" && type != "NCFT") {
            return makeError(-32602, "Invalid token type. Must be FT, NFT, SFT, or NCFT");
        }
        
        // Validate supply requirements
        if (type == "NFT" && supply != 0) {
            Logger::log("[handleIssueToken] Warning: NFT supply parameter ignored (always 1)");
            supply = 1;
        } else if ((type == "FT" || type == "SFT" || type == "NCFT") && supply == 0) {
            return makeError(-32602, type + " requires supply > 0");
        }
        
        // Validate address
        std::string err;
        if (!validateBase58Address(address, err)) {
            return makeError(-32602, "Invalid address: " + err);
        }
        
        // NEW: Construct metaJson from individual params sent by web client
        json metaJson = json::object();
        if (params.contains("name")) metaJson["name"] = params["name"];
        if (params.contains("symbol")) metaJson["symbol"] = params["symbol"];
        if (params.contains("decimals")) metaJson["decimals"] = params["decimals"];
        if (params.contains("description")) metaJson["description"] = params["description"];
        if (params.contains("image")) metaJson["image"] = params["image"];
        // Add any other optional/custom fields here if your web client sends more in the future
        
        // Validate and process metadata based on token type (adds defaults/hardcoded)
        json processedMeta = validateAndProcessMetadata(type, metaJson, address);
        
        // Set the wallet's current address
        wallet.setCurrentAddress(address);
        
        // Call the appropriate wallet method based on token type
        std::string txid;
        
        if (type == "FT") {
            // Extract standard fields from processedMeta
            std::string name = processedMeta["name"].get<std::string>();
            std::string symbol = processedMeta["symbol"].get<std::string>();
            std::string description = processedMeta.value("description", "");
            std::string image = processedMeta.value("image", "");
            int decimals = std::stoi(processedMeta["decimals"].get<std::string>());
            
            // Build additionalMeta from any non-standard fields
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : processedMeta.items()) {
                if (key != "name" && key != "symbol" && key != "description" && 
                    key != "image" && key != "decimals") {
                    additionalMeta[key] = value.get<std::string>();
                }
            }
            
            txid = wallet.issueExtendedFT(tokenID, supply, name, symbol, description, image, decimals, additionalMeta);
            
        } else if (type == "NFT") {
            // Similar extraction for NFT
            std::string name = processedMeta["name"].get<std::string>();
            std::string description = processedMeta.value("description", "");
            std::string image = processedMeta.value("image", "");
            std::string creator = processedMeta.value("creator", "");
            std::string external_link = processedMeta.value("external_link", "");
            
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : processedMeta.items()) {
                if (key != "name" && key != "description" && key != "image" && 
                    key != "creator" && key != "external_link") {
                    additionalMeta[key] = value.get<std::string>();
                }
            }
            
            txid = wallet.issueExtendedNFT(tokenID, name, description, image, creator, external_link, additionalMeta);
            
        } else if (type == "SFT") {
            // Extract for SFT (similar to FT + AI fields)
            std::string name = processedMeta["name"].get<std::string>();
            std::string symbol = processedMeta["symbol"].get<std::string>();
            std::string description = processedMeta.value("description", "");
            std::string image = processedMeta.value("image", "");
            int decimals = std::stoi(processedMeta["decimals"].get<std::string>());
            
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : processedMeta.items()) {
                if (key != "name" && key != "symbol" && key != "description" && 
                    key != "image" && key != "decimals") {
                    additionalMeta[key] = value.get<std::string>();
                }
            }
            
            txid = wallet.issueExtendedSFT(tokenID, supply, name, symbol, description, image, decimals, additionalMeta);
            
        } else if (type == "NCFT") {
            // Extract for NCFT
            std::string name = processedMeta["name"].get<std::string>();
            std::string description = processedMeta.value("description", "");
            std::string image = processedMeta.value("image", "");
            
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : processedMeta.items()) {
                if (key != "name" && key != "description" && key != "image") {
                    additionalMeta[key] = value.get<std::string>();
                }
            }
            
            txid = wallet.issueExtendedNCFT(tokenID, supply, name, description, image, additionalMeta);
        }
        
        Logger::log("[handleIssueToken] Token issued successfully - TXID: " + txid);
        Logger::log("[handleIssueToken] Token details - Type: " + type + ", ID: " + tokenID + 
                   ", Supply: " + std::to_string(supply) + ", Owner: " + address);
        
        // confirmed token metadata/index state is created only
        // when the transaction is accepted in a block through applyBlock() ->
        // transaction batch -> mainBatch -> authenticated U4 journal.
        //
        // Wallet issuance already attaches tokenMetadata to the transaction
        // before it enters the mempool, so no confirmed-style LevelDB write is
        // permitted from this RPC path.
        Logger::log(
            "[Patch16A.0] issuetoken admitted tx=" + txid +
            " confirmed token indexing=DEFERRED_UNTIL_BLOCK");

        // Return success with metadata summary
        json result;
        result["txid"] = txid;
        result["tokenType"] = type;
        result["tokenID"] = tokenID;
        result["metadata"] = processedMeta;
        result["indexed"] = false;
        result["indexing"] = "on-confirmation";
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleIssueToken] Failed to issue token: " + std::string(e.what()));
        return makeError(-32000, "Failed to issue token: " + std::string(e.what()));
    }
}
/*
static json handleIssueToken(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("type") || !params.contains("tokenID") || 
        !params.contains("address") || !params.contains("metadata")) {
        return makeError(-32602, "Missing required parameters");
    }
    
    try {
        std::string type = params["type"].get<std::string>();
        std::string tokenID = params["tokenID"].get<std::string>();
        std::string address = params["address"].get<std::string>();
        std::string metadata = params["metadata"].get<std::string>();
        uint64_t supply = 0;
        
        if (params.contains("supply")) {
            supply = params["supply"].get<uint64_t>();
        }
        
        // Validate token type
        if (type != "FT" && type != "NFT" && type != "SFT" && type != "NCFT") {
            return makeError(-32602, "Invalid token type. Must be FT, NFT, SFT, or NCFT");
        }
        
        // Validate supply requirements
        if (type == "NFT" && supply != 0) {
            Logger::log("[handleIssueToken] Warning: NFT supply parameter ignored (always 1)");
            supply = 1;
        } else if ((type == "FT" || type == "SFT" || type == "NCFT") && supply == 0) {
            return makeError(-32602, type + " requires supply > 0");
        }
        
        // Validate address
        std::string err;
        if (!validateBase58Address(address, err)) {
            return makeError(-32602, "Invalid address: " + err);
        }
        
        // Parse and validate metadata JSON
        json metaJson;
        try {
            metaJson = json::parse(metadata);
        } catch (const json::exception& e) {
            return makeError(-32602, "Invalid metadata JSON: " + std::string(e.what()));
        }
        
        // Validate and process metadata based on token type
        json processedMeta = validateAndProcessMetadata(type, metaJson, address);
        
        // Set the wallet's current address
        wallet.setCurrentAddress(address);
        
        // Call the appropriate wallet method based on token type
        std::string txid;
        
        if (type == "FT") {
            // Build additional metadata map
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : metaJson.items()) {
                // Skip standard fields
                if (key != "name" && key != "symbol" && key != "description" && 
                    key != "image" && key != "decimals") {
                    if (value.is_string()) {
                        additionalMeta[key] = value.get<std::string>();
                    }
                }
            }
            
            txid = wallet.issueExtendedFT(
                tokenID,
                supply,
                processedMeta["name"].get<std::string>(),
                processedMeta["symbol"].get<std::string>(),
                processedMeta["description"].get<std::string>(),
                processedMeta["image"].get<std::string>(),
                std::stoi(processedMeta["decimals"].get<std::string>()),
                additionalMeta
            );
            
        } else if (type == "NFT") {
            // Build additional metadata map
            std::unordered_map<std::string, std::string> additionalMeta;
            for (auto& [key, value] : metaJson.items()) {
                if (key != "name" && key != "description" && key != "image" && 
                    key != "creator" && key != "external_link") {
                    if (value.is_string()) {
                        additionalMeta[key] = value.get<std::string>();
                    }
                }
            }
            
            txid = wallet.issueExtendedNFT(
                tokenID,
                processedMeta["name"].get<std::string>(),
                processedMeta["description"].get<std::string>(),
                processedMeta["image"].get<std::string>(),
                processedMeta["creator"].get<std::string>(),
                processedMeta["external_link"].get<std::string>(),
                additionalMeta
            );
            
        } else if (type == "SFT") {
            // Build additional metadata map including AI fields
            std::unordered_map<std::string, std::string> additionalMeta;
            // Include AI metadata fields
            additionalMeta["ai_version"] = processedMeta["ai_version"].get<std::string>();
            additionalMeta["learning_mode"] = processedMeta["learning_mode"].get<std::string>();
            additionalMeta["growth_algorithm"] = processedMeta["growth_algorithm"].get<std::string>();
            
            // Add any other custom fields
            for (auto& [key, value] : metaJson.items()) {
                if (key != "name" && key != "symbol" && key != "description" && 
                    key != "image" && key != "decimals" && key != "ai_version" &&
                    key != "learning_mode" && key != "growth_algorithm") {
                    if (value.is_string()) {
                        additionalMeta[key] = value.get<std::string>();
                    }
                }
            }
            
            txid = wallet.issueExtendedSFT(
                tokenID,
                supply,
                processedMeta["name"].get<std::string>(),
                processedMeta["symbol"].get<std::string>(),
                processedMeta["description"].get<std::string>(),
                processedMeta["image"].get<std::string>(),
                std::stoi(processedMeta["decimals"].get<std::string>()),
                additionalMeta
            );
            
        } else if (type == "NCFT") {
            // Build additional metadata map including AI fields
            std::unordered_map<std::string, std::string> additionalMeta;
            // Include AI metadata fields
            additionalMeta["ai_engine"] = processedMeta["ai_engine"].get<std::string>();
            additionalMeta["style_descriptor"] = processedMeta["style_descriptor"].get<std::string>();
            additionalMeta["dynamic_morph"] = processedMeta["dynamic_morph"].get<std::string>();
            
            // Add any other custom fields
            for (auto& [key, value] : metaJson.items()) {
                if (key != "name" && key != "description" && key != "image" &&
                    key != "ai_engine" && key != "style_descriptor" && key != "dynamic_morph") {
                    if (value.is_string()) {
                        additionalMeta[key] = value.get<std::string>();
                    }
                }
            }
            
            txid = wallet.issueExtendedNCFT(
                tokenID,
                supply,
                processedMeta["name"].get<std::string>(),
                processedMeta["description"].get<std::string>(),
                processedMeta["image"].get<std::string>(),
                additionalMeta
            );
        }
        
        Logger::log("[handleIssueToken] Token issued successfully - TXID: " + txid);
        Logger::log("[handleIssueToken] Token details - Type: " + type + ", ID: " + tokenID + 
                   ", Supply: " + std::to_string(supply) + ", Owner: " + address);
        
        // Return success with metadata summary
        json result;
        result["txid"] = txid;
        result["tokenType"] = type;
        result["tokenID"] = tokenID;
        result["metadata"] = processedMeta;
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleIssueToken] Failed to issue token: " + std::string(e.what()));
        return makeError(-32000, "Failed to issue token: " + std::string(e.what()));
    }
}
*/
//========================
// SEND TOKENS
//========================
static json handleSendTokenWeb(Blockchain &chain, const json &params, int id) {
    if (!params.contains("tokenID") || !params.contains("amount") || 
        !params.contains("recipient") || !params.contains("senderAddress")) {
        return makeError(-32602, "Missing required parameters");
    }
    
    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        uint64_t amount = params["amount"].get<uint64_t>();
        std::string recipient = params["recipient"].get<std::string>();
        std::string senderAddress = params["senderAddress"].get<std::string>();
        
        // Validate addresses
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            return makeError(-32602, "Invalid recipient: " + err);
        }
        if (!validateBase58Address(senderAddress, err)) {
            return makeError(-32602, "Invalid sender: " + err);
        }
        
        // Find token UTXO for this address
        std::string utxoKey = "tokenOwnerUTXO:" + tokenID + ":" + senderAddress + ":";
        std::string foundKey;
        std::string foundValue;
        
        LevelDBStorage* storage = chain.getStorage();
        if (!storage) {
            return makeError(-32000, "Storage not available");
        }
        
        // Find the UTXO
        bool found = false;
        std::string txid;
        uint32_t controllingVout = 0;
        
        storage->iteratePrefix(utxoKey, [&](const std::string& keySuffix, const std::string& value) {
            if (!found) {
                // Parse txid:vout from the key
                std::vector<std::string> parts = splitString(keySuffix, ':');
                if (parts.size() >= 2) {
                    txid = parts[0];
                    controllingVout = std::stoul(parts[1]);
                    found = true;
                }
            }
        });
        
        if (!found) {
            return makeError(-32000, "No token UTXO found for this address");
        }
        
        // The token output is at vout-1
        uint32_t tokenVout = controllingVout > 0 ? controllingVout - 1 : 0;
        
        // Get token data
        std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(tokenVout);
        std::string tokenUtxoValue;
        if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            return makeError(-32000, "Token UTXO data not found");
        }
        
        json tokenData = json::parse(tokenUtxoValue);
        uint64_t currentAmount = tokenData["amount"].is_string() ? 
            std::stoull(tokenData["amount"].get<std::string>()) : 
            tokenData["amount"].get<uint64_t>();
        
        if (amount > currentAmount) {
            return makeError(-32000, "Insufficient token balance");
        }
        
        // Return the UTXO info for the client to build the transaction
        json result = {
            {"txid", txid},
            {"tokenVout", tokenVout},
            {"controllingVout", controllingVout},
            {"currentAmount", currentAmount},
            {"tokenID", tokenID}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}
//========================
// Create raw tx
//========================
static json handleCreateRawTransaction(Blockchain&, const json &p, int id) {
    if (!p.contains("inputs") || !p.contains("outputs")) {
        return makeError(-32602, "Missing inputs/outputs");
    }
    
    Transaction tx;
    tx.isCoinbase = false;
    
    try {
        // Add inputs
        for (auto &in : p["inputs"]) {
            tx.vin.emplace_back(in["txid"].get<std::string>(), in["vout"].get<uint32_t>());
        }
        
        // Add outputs
        for (auto it = p["outputs"].begin(); it != p["outputs"].end(); ++it) {
            const std::string& key = it.key();
            
            if (key == "data") {
                // Handle OP_RETURN data output
                // Value should be a hex string representing the full script
                if (!it.value().is_string()) {
                    throw std::runtime_error("Data output must be a hex string");
                }
                
                std::string dataHex = it.value().get<std::string>();
                
                // Validate hex string
                if (dataHex.length() % 2 != 0) {
                    throw std::runtime_error("Data hex string must have even length");
                }
                
                // Add OP_RETURN output with 0 value
                tx.vout.emplace_back(0, dataHex);
                
            } else {
                // Handle regular P2PKH output. Human TRU may be a decimal
                // string or JSON number; conversion to atoms is exact.
                uint64_t outputAtoms = 0;
                std::string amountReason;
                if (!parseJsonTRUAmount(it.value(), outputAtoms, amountReason) ||
                    outputAtoms > tru_limits::MAX_MONEY) {
                    if (amountReason.empty()) amountReason = "amount exceeds MAX_MONEY";
                    throw std::runtime_error("Bad output amount: " + amountReason);
                }
                
                // For regular outputs, 0 remains allowed (though it creates dust).
                std::string scriptHex = createP2PKHScriptHexFromAddress(key);
                tx.vout.emplace_back(outputAtoms, scriptHex);
            }
        }
        
        // Compute transaction ID
        tx.computeTxId();
        
        // Return the serialized transaction
        return makeResult(id, json(bytesToHex(tx.serializeBinary())));
        
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

//==============================================================================================
//				Web Wallet Sign Raw Key
//==============================================================================================
static json handleSignRawTransactionWithKeyWeb(Blockchain &chain, const json &p, int id) {
    if (!p.contains("txHex") || !p.contains("privKeys")) {
        return makeError(-32602, "Missing txHex/privKeys");
    }
    try {
        // Deserialize
        Transaction tx = Transaction::deserializeBinary(hexDecode(p["txHex"].get<std::string>()));

        // Sign each input
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            auto &in = tx.vin[i];
            UTXO utxo;
            if (!chain.utxoSet.getUTXO(in.txid, in.vout, utxo)) {
                throw std::runtime_error("Missing UTXO for input " + std::to_string(i));
            }
            std::string addr = extractP2PKHAddressCorrect(utxo.scriptPubKey);
            bool signedInput = false;
            for (const auto &pem : p["privKeys"]) {
                ECDSAKey key = ECDSAKey::fromPrivateKey(pem.get<std::string>());
                if (pubkeyToAddress(key.getCompressedSec1()) != addr) continue;

                auto sighash = tx.getSigHash(i, hexDecode(utxo.scriptPubKey));
                std::vector<uint8_t> sig = key.sign(std::string(sighash.begin(), sighash.end()));
                sig.push_back(0x01);  // SIGHASH_ALL

                // Build scriptSig = <sigLen><sig><pubkeyLen><pubkey>
                std::vector<uint8_t> ss;
                ss.push_back((uint8_t)sig.size());
                ss.insert(ss.end(), sig.begin(), sig.end());
                auto pub = key.getCompressedSec1();
                ss.push_back((uint8_t)pub.size());
                ss.insert(ss.end(), pub.begin(), pub.end());

                in.scriptSig = ss;
                signedInput = true;
                break;
            }
            if (!signedInput) {
                throw std::runtime_error("Cannot sign input " + std::to_string(i));
            }
        }

        // Serialize back out
        std::string hexTx = bytesToHex(tx.serializeBinary());
        // Return an object { hex, complete }
        return makeResult(id, json{{"hex", hexTx}, {"complete", true}});
    } catch (const std::exception &e) {
        return makeError(-32000, e.what());
    }
}

static json handleSignRawTransactionWithKey(Blockchain &chain, const json &p, int id) {
    if (!p.contains("txHex") || !p.contains("privKeys")) {
        return makeError(-32602, "Missing txHex/privKeys");
    }
    
    try {
        Transaction tx = Transaction::deserializeBinary(hexDecode(p["txHex"].get<std::string>()));
        
        Logger::log("[handleSignRawTransactionWithKey] Signing transaction with " + 
                   std::to_string(tx.vin.size()) + " inputs");
        
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            auto &in = tx.vin[i];
            UTXO utxo;
            if (!chain.utxoSet.getUTXO(in.txid, in.vout, utxo)) {
                Logger::log("[handleSignRawTransactionWithKey] Missing UTXO for input " + 
                           std::to_string(i));
                throw std::runtime_error("Missing UTXO for input " + std::to_string(i));
            }
            
            std::string utxoAddress = extractP2PKHAddressCorrect(utxo.scriptPubKey);
            Logger::log("[handleSignRawTransactionWithKey] Input " + std::to_string(i) + 
                       " requires signature from address: " + utxoAddress);
            
            bool signedInput = false;
            for (const auto &privJson : p["privKeys"]) {
                std::string privStr = privJson.get<std::string>();
                
                Logger::log("[handleSignRawTransactionWithKey] Trying private key (length: " + 
                           std::to_string(privStr.length()) + ")");
                
                ECDSAKey key;
                
                // Handle both PEM and hex format private keys
                if (privStr.find("-----BEGIN") != std::string::npos) {
                    // PEM format
                    key = ECDSAKey::fromPrivateKey(privStr);
                } else if (privStr.length() == 64 && 
                          privStr.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
                    // Hex format - convert to raw bytes
                    std::vector<uint8_t> rawKey = hexDecode(privStr);
                    if (rawKey.size() != 32) {
                        Logger::log("[handleSignRawTransactionWithKey] Invalid hex key size");
                        continue;
                    }
                    key = ECDSAKey::fromRawBytes(rawKey);
                } else {
                    Logger::log("[handleSignRawTransactionWithKey] Unknown key format");
                    continue;
                }
                
                // Get compressed public key
                std::vector<unsigned char> pubkey = key.getCompressedSec1();
                std::string derivedAddress = pubkeyToAddress(pubkey);
                
                Logger::log("[handleSignRawTransactionWithKey] Key derives to: " + derivedAddress);
                
                if (derivedAddress != utxoAddress) {
                    continue;
                }
                
                Logger::log("[handleSignRawTransactionWithKey] Address match! Signing...");
                
                // Get the sighash for this input
                std::vector<unsigned char> sighash = tx.getSigHash(i, hexDecode(utxo.scriptPubKey));
                Logger::log("[handleSignRawTransactionWithKey] Sighash: " + bytesToHex(sighash));
                
                // Sign the sighash
                std::string sighashStr(sighash.begin(), sighash.end());
                std::vector<unsigned char> signature = key.sign(sighashStr);
                
                // IMPORTANT: The signature from ECDSA is just the DER encoding
                // We need to append SIGHASH_ALL (0x01) for Bitcoin transactions
                signature.push_back(0x01);
                
                Logger::log("[handleSignRawTransactionWithKey] Signature with SIGHASH_ALL: " + 
                           bytesToHex(signature) + " (length: " + std::to_string(signature.size()) + ")");
                
                // Build scriptSig properly
                std::vector<uint8_t> scriptSig;
                
                // Push signature length (including SIGHASH byte)
                scriptSig.push_back(static_cast<uint8_t>(signature.size()));
                // Push signature bytes
                scriptSig.insert(scriptSig.end(), signature.begin(), signature.end());
                
                // Push pubkey length
                scriptSig.push_back(static_cast<uint8_t>(pubkey.size()));
                // Push pubkey bytes
                scriptSig.insert(scriptSig.end(), pubkey.begin(), pubkey.end());
                
                Logger::log("[handleSignRawTransactionWithKey] Complete scriptSig: " + 
                           bytesToHex(scriptSig));
                
                in.scriptSig = scriptSig;
                signedInput = true;
                break;
            }
            
            if (!signedInput) {
                throw std::runtime_error("Cannot sign input " + std::to_string(i));
            }
        }
        
        // Recompute txid after signing
        tx.computeTxId();
        
        std::string hexTx = bytesToHex(tx.serializeBinary());
        Logger::log("[handleSignRawTransactionWithKey] Signed transaction: " + tx.txid);
        
        return makeResult(id, json{{"hex", hexTx}, {"complete", true}});
        
    } catch (const std::exception &e) {
        Logger::log("[handleSignRawTransactionWithKey] Error: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
/*
static json handleSignRawTransactionWithKey(Blockchain &chain, const json &p, int id) {
    if (!p.contains("txHex") || !p.contains("privKeys")) {
        return makeError(-32602, "Missing txHex/privKeys");
    }
    try {
        Transaction tx = Transaction::deserializeBinary(hexDecode(p["txHex"].get<std::string>()));
        
        Logger::log("[handleSignRawTransactionWithKey] Signing transaction with " + 
                   std::to_string(tx.vin.size()) + " inputs");
        
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            auto &in = tx.vin[i];
            UTXO utxo;
            if (!chain.utxoSet.getUTXO(in.txid, in.vout, utxo)) {
                Logger::log("[handleSignRawTransactionWithKey] Missing UTXO for input " + 
                           std::to_string(i) + " (txid: " + in.txid + ", vout: " + std::to_string(in.vout) + ")");
                throw std::runtime_error("Missing UTXO for input " + std::to_string(i));
            }
            
            std::string utxoAddress = extractP2PKHAddressCorrect(utxo.scriptPubKey);
            Logger::log("[handleSignRawTransactionWithKey] Input " + std::to_string(i) + 
                       " requires signature from address: " + utxoAddress);
            
            bool signedInput = false;
            for (const auto &privJson : p["privKeys"]) {
                std::string privStr = privJson.get<std::string>();
                
                Logger::log("[handleSignRawTransactionWithKey] Trying private key (length: " + 
                           std::to_string(privStr.length()) + ", first 10 chars: " + 
                           privStr.substr(0, 10) + "...)");
                
                ECDSAKey k;
                // Check if the private key is in PEM format or hex
                if (privStr.find("-----BEGIN") != std::string::npos) {
                    k = ECDSAKey::fromPrivateKey(privStr); // PEM format
                } else {
                    // Assume hex format and decode to bytes
                    std::vector<uint8_t> raw = hexDecode(privStr);
                    if (raw.size() != 32) {
                        Logger::log("[handleSignRawTransactionWithKey] Invalid private key size: " + 
                                   std::to_string(raw.size()) + " bytes (expected 32)");
                        continue;
                    }
                    k = ECDSAKey::fromRawBytes(raw); // Hex format
                }
                
                // Get the address from this private key
                auto pubkey = k.getCompressedSec1();
                std::string derivedAddress = pubkeyToAddress(pubkey);
                
                Logger::log("[handleSignRawTransactionWithKey] Private key derives to address: " + 
                           derivedAddress + " (pubkey: " + hexEncode(pubkey).substr(0, 20) + "...)");
                
                if (derivedAddress != utxoAddress) {
                    Logger::log("[handleSignRawTransactionWithKey] Address mismatch - skipping this key");
                    continue;
                }
                
                Logger::log("[handleSignRawTransactionWithKey] Address match found! Signing input " + 
                           std::to_string(i));
                
                auto sighash = tx.getSigHash(i, hexDecode(utxo.scriptPubKey));
                std::vector<uint8_t> sig = k.sign(std::string(sighash.begin(), sighash.end()));
                sig.push_back(0x01); // SIGHASH_ALL
                
                std::vector<uint8_t> ss;
                ss.push_back(static_cast<uint8_t>(sig.size()));
                ss.insert(ss.end(), sig.begin(), sig.end());
                auto pub = k.getCompressedSec1();
                ss.push_back(static_cast<uint8_t>(pub.size()));
                ss.insert(ss.end(), pub.begin(), pub.end());
                in.scriptSig = ss;
                signedInput = true;
                
                Logger::log("[handleSignRawTransactionWithKey] Successfully signed input " + 
                           std::to_string(i));
                break;
            }
            if (!signedInput) {
                Logger::log("[handleSignRawTransactionWithKey] Failed to sign input " + 
                           std::to_string(i) + " - no matching private key found");
                throw std::runtime_error("Cannot sign input " + std::to_string(i));
            }
        }
        std::string hexTx = bytesToHex(tx.serializeBinary());
        Logger::log("[handleSignRawTransactionWithKey] Transaction signed successfully");
        return makeResult(id, json{{"hex", hexTx}, {"complete", true}});
    } catch (const std::exception &e) {
        Logger::log("[handleSignRawTransactionWithKey] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}
    */
//==================================================================================
// START MINING
//==================================================================================
static nlohmann::json handleStartMining(Blockchain &blockchain, const nlohmann::json &params) {
    Logger::log("[handleStartMining] Request: " + params.dump());
    if (!params.contains("type") || !params["type"].is_string() ||
        !params.contains("minerAddress") || !params["minerAddress"].is_string()) {
        Logger::log("[handleStartMining] Error: Missing or invalid parameters");
        return makeError(-32602, "Missing or invalid 'type' or 'minerAddress' parameters");
    }

    std::string typeStr = params["type"].get<std::string>();
    std::string minerAddr = params["minerAddress"].get<std::string>();
    bool quiet = params.value("quiet", false);

    try {
        nlohmann::json result;
        if (typeStr == "cpu") {
            Block b = blockchain.mineBlockCPU(nullptr, minerAddr);
            if (b.blockHash.empty()) {
                throw std::runtime_error("No solution found by CPU miner");
            }
            result["result"] = quiet ? "CPU mined block silently" : "CPU mined block => " + b.blockHash;
        } else if (typeStr == "gpu") {
            std::string resultStr = blockchain.mineBlockGPUChain(nullptr, minerAddr);
            result["result"] = quiet ? "GPU mined block silently" : resultStr;
        } else {
            throw std::invalid_argument("Unknown mining type. Must be 'cpu' or 'gpu'");
        }
        Logger::log("[handleStartMining] Success: " + result.dump());
        return result;
    } catch (const std::exception &e) {
        Logger::log("[handleStartMining] Error: " + std::string(e.what()));
        return makeError(-32000, "Failed to start mining: " + std::string(e.what()));
    }
}

//========================
//    Handle Debug Token
//========================
static json handleDebugTokenTx(Blockchain &chain, const json &params, int id) {
    std::string txid = params["txid"].get<std::string>();
    
    Transaction tx;
    if (!chain.findTransaction(txid, tx)) {
        return makeError(-32000, "Transaction not found");
    }
    
    json result;
    result["txid"] = txid;
    result["outputs"] = json::array();
    
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& out = tx.vout[i];
        json outInfo;
        outInfo["vout"] = i;
        outInfo["amount"] = out.amount;
        outInfo["scriptHex"] = out.scriptPubKey;
        outInfo["isOpReturn"] = (out.scriptPubKey.substr(0, 2) == "6a");
        result["outputs"].push_back(outInfo);
    }
    
    return makeResult(id, result);
}
//=================================
//          Handle Issue Token
//=================================
static json handleCreateTokenTransaction(Blockchain &chain, const json &params, int id) {
    try {
        // Validate required parameters
        if (!params.contains("type") || !params.contains("tokenID") || 
            !params.contains("name") || !params.contains("senderAddress")) {
            return makeError(-32602, "Missing required parameters: type, tokenID, name, senderAddress");
        }
        
        std::string tokenType = params["type"].get<std::string>();
        std::string tokenID = params["tokenID"].get<std::string>();
        std::string name = params["name"].get<std::string>();
        std::string symbol = params.value("symbol", "");
        std::string description = params.value("description", "");
        std::string imageUrl = params.value("imageUrl", "");
        int decimals = params.value("decimals", 8);
        uint64_t totalSupply = params.value("totalSupply", 1);
        std::string senderAddress = params["senderAddress"].get<std::string>();
        uint64_t fee = params.value("fee", 10000);
        
        // Get UTXO info from client
        if (!params.contains("utxo") || !params["utxo"].contains("txid") || 
            !params["utxo"].contains("vout") || !params["utxo"].contains("amount")) {
            return makeError(-32602, "Missing UTXO information");
        }
        
        std::string utxoTxid = params["utxo"]["txid"].get<std::string>();
        uint32_t utxoVout = params["utxo"]["vout"].get<uint32_t>();
        uint64_t utxoAmount = 0;
        std::string utxoAmountReason;
        if (!readRpcUtxoAtoms(params["utxo"], utxoAmount, utxoAmountReason)) {
            return makeError(-32602, "Invalid UTXO amount: " + utxoAmountReason);
        }
        
        Logger::log("[handleCreateTokenTransaction] Creating unsigned token transaction");
        Logger::log("[handleCreateTokenTransaction] Token: " + tokenID + " (" + tokenType + ")");
        Logger::log("[handleCreateTokenTransaction] Supply: " + std::to_string(totalSupply));
        
        // Validate sender address
        std::string err;
        if (!validateBase58Address(senderAddress, err)) {
            return makeError(-32602, "Invalid sender address: " + err);
        }
        
        // Validate token type
        if (tokenType != "FT" && tokenType != "NFT" && tokenType != "SFT" && tokenType != "NCFT") {
            return makeError(-32602, "Invalid token type. Must be FT, NFT, SFT, or NCFT");
        }
        
        // TOKEN-AI-01B2: new issuance/RPC namespace uses 16 hex.
        std::string truncatedTokenID = normalizeTokenIDForLookupV2(tokenID);
        if (truncatedTokenID.empty())
            return makeError(-32602, "Invalid tokenID");
        
        Logger::log("[handleCreateTokenTransaction] Truncated tokenID: " + truncatedTokenID);
        
        // Check for duplicate token issuance
        LevelDBStorage* storage = chain.getStorage();
        std::string issuanceKey = "tokenIssuance:" + truncatedTokenID;
        std::string existingIssuance;
        if (storage->getWithDataChecksum(issuanceKey, existingIssuance)) {
            return makeError(-32000, "Token already exists: " + truncatedTokenID);
        }
        
        // Validate amounts
        if (tokenType == "NFT") {
            totalSupply = 1; // NFTs always have supply of 1
        } else if (totalSupply == 0) {
            return makeError(-32602, tokenType + " requires supply > 0");
        }
        
        uint64_t totalNeeded = fee + 546; // fee + dust for controlling output
        if (utxoAmount < totalNeeded) {
            return makeError(-32000, fmt::format(
                "Insufficient funds. Have: {} TRU atoms, Need: {} TRU atoms", 
                utxoAmount, totalNeeded));
        }
        
        // Build token metadata
        json processedMeta = {
            {"name", name.empty() ? ("Token_" + truncatedTokenID) : name},
            {"symbol", symbol.empty() ? tokenType : symbol},
            {"decimals", std::to_string(decimals)},
            {"description", description},
            {"image", imageUrl.empty() ? "https://none.io" : imageUrl}
        };
        
        // Add type-specific defaults
        if (tokenType == "NFT") {
            processedMeta["decimals"] = "0";
            processedMeta["creator"] = senderAddress;
        } else if (tokenType == "SFT") {
            processedMeta["ai_version"] = "1.2";
            processedMeta["learning_mode"] = "on-chain usage patterns";
            processedMeta["growth_algorithm"] = "neural-adaptive";
        } else if (tokenType == "NCFT") {
            processedMeta["decimals"] = "0";
            processedMeta["ai_engine"] = "StableDiffusion-v2";
            processedMeta["style_descriptor"] = "Van Gogh meets fractal geometry";
            processedMeta["dynamic_morph"] = "transfer-based evolution";
        }
        
        // Add any additional metadata passed from client
        if (params.contains("metadata") && params["metadata"].is_object()) {
            for (auto& [key, value] : params["metadata"].items()) {
                if (value.is_string()) {
                    processedMeta[key] = value.get<std::string>();
                }
            }
        }
        
        // Create token metadata structure
        TokenMeta tokenMeta;
        from_json(processedMeta, tokenMeta);
        
        // Build ExtendedTokenData
        ExtendedTokenData tokenData;
        tokenData.tokenID = truncatedTokenID;
        tokenData.type = stringToTokenType(tokenType);
        tokenData.amount = totalSupply;
        tokenData.version = 1;
        tokenData.meta = tokenMeta;
        tokenData.offChainMetadata = "";
        tokenData.metadataSignature = "";
        
        // Build unsigned transaction
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        tx.isCoinbase = false;
        
        // Input: funding UTXO
        tx.vin.emplace_back(utxoTxid, utxoVout);
        
        // Output 0: OP_RETURN with token data
        std::string tokenScript = createExtendedTokenScriptPubKeyHex(tokenData, senderAddress);
        tx.vout.emplace_back(0, tokenScript);
        
        // Output 1: Controlling P2PKH output (546 TRU atoms)
        std::string controllingScript = createP2PKHScriptHexFromAddress(senderAddress);
        tx.vout.emplace_back(546, controllingScript);
        
        // Output 2: Change output (if any)
        uint64_t changeAmount = utxoAmount - fee - 546;
        if (changeAmount >= 546) { // Only create change if above dust threshold
            std::string changeScript = createP2PKHScriptHexFromAddress(senderAddress);
            tx.vout.emplace_back(changeAmount, changeScript);
        }
        
        // Don't sign - return unsigned transaction
        tx.computeTxId(); // This will be recomputed after signing
        
        // Prepare metadata for storage (will be stored after broadcast)
        json tokenMetadata = {
            {"type", tokenType},
            {"tokenID", truncatedTokenID},
            {"amount", std::to_string(totalSupply)},
            {"owner", senderAddress},
            {"version", "1"},
            {"meta", processedMeta},
            {"metadataSignature", ""},
            {"offChainMetadata", ""},
            {"tokenVout", 0},           // OP_RETURN is at vout 0
            {"controllingVout", 1}      // Controlling output is at vout 1
        };
        
        Logger::log("[handleCreateTokenTransaction] Created unsigned transaction");
        
        // Return unsigned transaction and metadata for client
        json result = {
            {"unsignedTxHex", hexEncode(tx.serializeBinary())},
            {"success", true},
            {"tokenID", truncatedTokenID},
            {"metadata", tokenMetadata},
            {"debug", {
                {"tokenType", tokenType},
                {"totalSupply", totalSupply},
                {"fee", fee},
                {"changeAmount", changeAmount}
            }}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleCreateTokenTransaction] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Token transaction creation failed: ") + e.what());
    }
}

//========================
// Handle Create MagicLock
//========================
static json handleCreateMagicLock(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("amount") || !params.contains("targetPrefix")) {
        return makeError(-32602, "Missing required parameters: amount, targetPrefix");
    }
    
    try {
        uint64_t amountAtoms = 0;
        std::string amountReason;
        if (!parseJsonTRUAmount(params["amount"], amountAtoms, amountReason) ||
            amountAtoms == 0 || amountAtoms > tru_limits::MAX_MONEY) {
            if (amountReason.empty()) {
                amountReason = amountAtoms > tru_limits::MAX_MONEY
                    ? "amount exceeds MAX_MONEY"
                    : "amount must be greater than 0";
            }
            return makeError(-32602, "Invalid TRU amount: " + amountReason);
        }
        std::string targetPrefix = params["targetPrefix"].get<std::string>();
        std::string address = params.value("address", "");
        
        // Optional secret data parameters
        std::string secretData = params.value("secretData", "");
        std::string dataType = params.value("dataType", "text");
        
        // Validate remaining parameters.
        if (targetPrefix.empty() || targetPrefix.length() % 2 != 0) {
            return makeError(-32602, "Target prefix must be non-empty hex string with even length");
        }
        
        if (!isHex(targetPrefix)) {
            return makeError(-32602, "Target prefix must be valid hex");
        }
        
        // If secret data is base64 encoded (from file upload), decode it
        if (!secretData.empty() && dataType != "text") {
            try {
                secretData = base64Decode(secretData);
            } catch (...) {
                // If decode fails, assume it's raw data
            }
        }
        
        // Set wallet address if provided
        if (!address.empty()) {
            try {
                wallet.addAddress(address);
                wallet.setCurrentAddress(address);
            } catch (const std::exception& e) {
                Logger::log("[handleCreateMagicLock] Note: " + std::string(e.what()));
                try {
                    wallet.setCurrentAddress(address);
                } catch (...) {
                    Logger::log("[handleCreateMagicLock] Using default wallet address");
                    address = wallet.getCurrentAddress();
                }
            }
        } else {
            address = wallet.getCurrentAddress();
        }
        
        Logger::log("[handleCreateMagicLock] Creating MagicLock: amount=" + std::to_string(amountAtoms) +
                   " TRU atoms, target=" + targetPrefix + ", address=" + address +
                   ", hasSecret=" + (!secretData.empty() ? "true" : "false"));
        
        std::string txid;
        
        // Handle secret data
        if (!secretData.empty()) {
            // Build transaction with secret in OP_RETURN
            std::string sender = wallet.getCurrentAddress();
            
            // Find UTXO
            auto [utxoTxid, utxoVout] = wallet.findOneSpendableUtxo(sender, chain.mempool.get());
            if (utxoTxid.empty()) {
                return makeError(-32000, "No UTXO available");
            }
            
            UTXO utxo;
            if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo)) {
                return makeError(-32000, "Failed to get UTXO details");
            }
            
            // Build transaction
            Transaction tx(false);
            tx.version = 1;
            tx.lockTime = 0;
            tx.vin.emplace_back(utxoTxid, utxoVout);
            
            // Output 0: MagicLock
            std::string pubKeyHash = wallet.getPubKeyHashForAddress(sender);
            std::string lockScript = wallet.createMagicLockScript(targetPrefix, pubKeyHash);
            tx.vout.emplace_back(amountAtoms, lockScript);
            
            // Create consistent encryption key using wallet's method
            // This ensures we can decrypt it later
            std::string encKey = wallet.deriveEncryptionKey(targetPrefix, pubKeyHash);
            
            // Simple XOR encryption for demonstration
            std::string encrypted;
            for (size_t i = 0; i < secretData.length(); i++) {
                unsigned char keyByte = encKey[i % 32];
                encrypted += (char)(secretData[i] ^ keyByte);
            }
            
            // Create metadata
            nlohmann::json metadata;
            metadata["type"] = "MAGIC_SECRET";
            metadata["dataType"] = dataType;
            metadata["encrypted"] = base64Encode(encrypted);
            metadata["hint"] = "Unlock with target: " + targetPrefix;
            metadata["timestamp"] = std::time(nullptr);
            
            std::string metaStr = metadata.dump();
            
            // Build OP_RETURN script
            std::vector<unsigned char> opReturnScript;
            opReturnScript.push_back(0x6a); // OP_RETURN
            
            if (metaStr.length() <= 75) {
                opReturnScript.push_back(static_cast<unsigned char>(metaStr.length()));
            } else if (metaStr.length() <= 220) {
                opReturnScript.push_back(0x4c); // OP_PUSHDATA1
                opReturnScript.push_back(static_cast<unsigned char>(metaStr.length()));
            } else {
                return makeError(-32602, "Secret data too large for OP_RETURN");
            }
            
            opReturnScript.insert(opReturnScript.end(), metaStr.begin(), metaStr.end());
            tx.vout.emplace_back(0, bytesToHex(opReturnScript));
            
            // Output 2: Change
            uint64_t fee = 10000;
            if (amountAtoms > std::numeric_limits<uint64_t>::max() - fee ||
                utxo.amount < amountAtoms + fee) {
                return makeError(-32000, "Insufficient funds for MagicLock amount + fee");
            }
            if (utxo.amount > amountAtoms + fee) {
                uint64_t changeAmount = utxo.amount - amountAtoms - fee;
                std::string changeScript = createP2PKHScriptHexFromAddress(sender);
                tx.vout.emplace_back(changeAmount, changeScript);
            }
            
            // Sign and get final txid
            tx.computeTxId();
            if (!wallet.signTransaction(tx)) {
                return makeError(-32000, "Failed to sign transaction");
            }
            
            tx.computeTxId();
            txid = tx.txid;
            
            // CRITICAL: Store the encryption key for later retrieval when unlocking
            // This allows the unlocker to decrypt the secret
            wallet.storeMagicLockSecret(txid, targetPrefix, dataType, encKey);
            Logger::log("[handleCreateMagicLock] Stored secret metadata for txid: " + txid);
            
            // Add to mempool
            MempoolAddStatus status = chain.mempool->addTransaction(tx);
            if (status == MempoolAddStatus::BUSY) {
                return makeError(
                    -32005, "Mempool validation busy; retry");
            }
            if (status != MempoolAddStatus::SUCCESS) {
                return makeError(-32000, "Failed to add to mempool");
            }
            
            // Broadcast
            chain.broadcastTransaction(tx);
            
        } else {
            // Standard MagicLock without secret
            txid = wallet.createMagicLock(amountAtoms, targetPrefix);
        }
        
        // Verify transaction is in mempool
        bool inMempool = chain.mempool->hasTransaction(txid);
        
        Logger::log("[handleCreateMagicLock] MagicLock created successfully: " + txid);
        
        json result = {
            {"txid", txid},
            {"amount", static_cast<double>(amountAtoms) / static_cast<double>(tru_amount::ATOMS_PER_TRU)},
            {"amount_tru", tru_amount::formatNumeric(amountAtoms)},
            {"amount_atoms", amountAtoms},
            {"targetPrefix", targetPrefix},
            {"address", address},
            {"hasSecret", !secretData.empty()},
            {"dataType", dataType},
            {"success", true},
            {"inMempool", inMempool}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleCreateMagicLock] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to create MagicLock: ") + e.what());
    }
}

// 30B3: removed obsolete commented duplicate MagicLock handler.

//========================
// Handle Unlock MagicLock
//========================
static json handleUnlockMagicLock(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("txid") || !params.contains("vout") || !params.contains("recipient")) {
        return makeError(-32602, "Missing required parameters: txid, vout, recipient");
    }
    
    try {
        std::string lockTxid = params["txid"].get<std::string>();
        uint32_t lockVout = params["vout"].get<uint32_t>();
        std::string recipient = params["recipient"].get<std::string>();
        
        // Validate recipient address
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            return makeError(-32602, "Invalid recipient address: " + err);
        }
        
        Logger::log("[handleUnlockMagicLock] Attempting to unlock: " + lockTxid + ":" + 
                   std::to_string(lockVout) + " to " + recipient);
        
        // Perform the unlock
        std::string unlockTxid = wallet.unlockMagicLock(lockTxid, lockVout, recipient);
        
        // Check if there's a secret to reveal
        std::string revealedSecret;
        std::string secretType = "none";
        
        // Get the original lock transaction to check for OP_RETURN
        Transaction lockTx;
        bool hasSecret = false;
        
        // Search in blockchain
        for (int height = 0; height <= chain.getBestTipHeight(); height++) {
            auto block = chain.getBlockByHeight(height);
            if (block) {
                for (const auto& tx : block->transactions) {
                    if (tx.txid == lockTxid) {
                        lockTx = tx;
                        break;
                    }
                }
            }
        }
        
        // Check mempool if not found in blockchain
        if (lockTx.txid.empty()) {
            for (const auto& tx : chain.getMempoolTransactions()) {
                if (tx.txid == lockTxid) {
                    lockTx = tx;
                    break;
                }
            }
        }
        
        // Look for OP_RETURN with secret
        if (!lockTx.txid.empty()) {
            for (const auto& out : lockTx.vout) {
                if (out.scriptPubKey.substr(0, 2) == "6a") { // OP_RETURN
                    // Extract data from OP_RETURN
                    std::string scriptHex = out.scriptPubKey;
                    size_t pos = 2;
                    
                    if (pos + 2 <= scriptHex.size()) {
                        size_t dataLen = std::stoul(scriptHex.substr(pos, 2), nullptr, 16);
                        pos += 2;
                        
                        if (dataLen == 0x4c && pos + 2 <= scriptHex.size()) {
                            // OP_PUSHDATA1
                            dataLen = std::stoul(scriptHex.substr(pos, 2), nullptr, 16);
                            pos += 2;
                        }
                        
                        if (dataLen > 0 && pos + dataLen * 2 <= scriptHex.size()) {
                            std::string dataHex = scriptHex.substr(pos, dataLen * 2);
                            std::vector<unsigned char> dataBytes = hexDecode(dataHex);
                            std::string opReturnData(dataBytes.begin(), dataBytes.end());
                            
                            try {
                                nlohmann::json metadata = nlohmann::json::parse(opReturnData);
                                if (metadata["type"] == "MAGIC_SECRET") {
                                    hasSecret = true;
                                    secretType = metadata["dataType"];
                                    
                                    // Retrieve the stored encryption key from LevelDB
                                    std::string encKey;
                                    LevelDBStorage* storage = chain.getStorage();
                                    if (storage) {
                                        std::string storageKey = "magicLockSecret:" + lockTxid;
                                        std::string secretMeta;
                                        
                                        if (storage->getWithDataChecksum(storageKey, secretMeta)) {
                                            try {
                                                nlohmann::json meta = nlohmann::json::parse(secretMeta);
                                                encKey = meta["encryptionKey"];
                                                Logger::log("[handleUnlockMagicLock] Retrieved encryption key from storage");
                                            } catch (const std::exception& e) {
                                                Logger::log("[handleUnlockMagicLock] Error parsing stored secret metadata: " + 
                                                          std::string(e.what()));
                                            }
                                        } else {
                                            Logger::log("[handleUnlockMagicLock] No stored encryption key found, deriving from script");
                                            
                                            // Fallback: derive the key the same way it was created
                                            UTXO lockedUtxo;
                                            chain.utxoSet.getUTXO(lockTxid, lockVout, lockedUtxo);
                                            std::string lockScript = lockedUtxo.scriptPubKey;
                                            
                                            // Extract target and pubKeyHash from lock script
                                            std::string target = extractTargetSmart(lockScript);
                                            
                                            // Extract pubKeyHash (20 bytes after 76a914 in the script)
                                            std::string pubKeyHash;
                                            size_t pkPos = lockScript.find("76a914");
                                            if (pkPos != std::string::npos && pkPos + 6 + 40 <= lockScript.size()) {
                                                pubKeyHash = lockScript.substr(pkPos + 6, 40);
                                            }
                                            
                                            // Use wallet's deriveEncryptionKey method
                                            encKey = wallet.deriveEncryptionKey(target, pubKeyHash);
                                        }
                                    } else {
                                        Logger::log("[handleUnlockMagicLock] Storage not available");
                                        //return makeResult(id, result);
                                    }
                                    
                                    if (!encKey.empty()) {
                                        // Decrypt using the correct key
                                        std::string encrypted = base64Decode(metadata["encrypted"]);
                                        
                                        // XOR decrypt with the same logic as encryption
                                        revealedSecret = "";
                                        for (size_t i = 0; i < encrypted.length(); i++) {
                                            unsigned char keyByte = encKey[i % 32];
                                            revealedSecret += (char)(encrypted[i] ^ keyByte);
                                        }
                                        
                                        Logger::log("[handleUnlockMagicLock] Secret revealed, type: " + secretType);
                                        Logger::log("[handleUnlockMagicLock] Decrypted text: " + revealedSecret);
                                    } else {
                                        Logger::log("[handleUnlockMagicLock] Failed to obtain encryption key");
                                    }
                                }
                            } catch (const std::exception& e) {
                                Logger::log("[handleUnlockMagicLock] No valid secret metadata: " + 
                                          std::string(e.what()));
                            }
                        }
                    }
                    break;
                }
            }
        }
        
        Logger::log("[handleUnlockMagicLock] MagicLock unlocked successfully: " + unlockTxid);
        
        json result = {
            {"unlockTxid", unlockTxid},
            {"lockedTxid", lockTxid},
            {"lockedVout", lockVout},
            {"recipient", recipient},
            {"success", true},
            {"hasSecret", hasSecret}
        };
        
        if (hasSecret && !revealedSecret.empty()) {
            result["secretRevealed"] = true;
            result["secretType"] = secretType;
            
            // For binary data types, encode as base64
            if (secretType == "image" || secretType == "pdf" || secretType == "file") {
                result["secretData"] = base64Encode(revealedSecret);
                result["encoding"] = "base64";
            } else {
                result["secretData"] = revealedSecret;
                result["encoding"] = "plain";
            }
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleUnlockMagicLock] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to unlock MagicLock: ") + e.what());
    }
}

/*
static json handleUnlockMagicLock(Blockchain &chain, Wallet &wallet, const json &params, int id) {
    if (!params.contains("txid") || !params.contains("vout") || !params.contains("recipient")) {
        return makeError(-32602, "Missing required parameters: txid, vout, recipient");
    }
    
    try {
        std::string lockTxid = params["txid"].get<std::string>();
        uint32_t lockVout = params["vout"].get<uint32_t>();
        std::string recipient = params["recipient"].get<std::string>();
        
        // Validate recipient address
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            return makeError(-32602, "Invalid recipient address: " + err);
        }
        
        Logger::log("[handleUnlockMagicLock] Attempting to unlock: " + lockTxid + ":" + 
                   std::to_string(lockVout) + " to " + recipient);
        
        // This will grind signatures until it finds one matching the target
        std::string unlockTxid = wallet.unlockMagicLock(lockTxid, lockVout, recipient);
        
        Logger::log("[handleUnlockMagicLock] MagicLock unlocked successfully: " + unlockTxid);
        
        json result = {
            {"unlockTxid", unlockTxid},
            {"lockedTxid", lockTxid},
            {"lockedVout", lockVout},
            {"recipient", recipient},
            {"success", true}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleUnlockMagicLock] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to unlock MagicLock: ") + e.what());
    }
}
*/
//========================
// Handle List MagicLocks
//========================
static json handleListMagicLocks(Blockchain &chain, const json &params, int id) {
    try {
        std::string filterAddress = params.value("address", "");

        auto isMagicLock = [](const std::string& s) -> bool {
            // Canonical:    7c aa ... 7f <push target> 88 ... 76a914...88ac
            // Legacy A:     <push target> 7c 76 aa ... 7f 88 ... 76a914...88ac
            // Legacy B:     <push target> 6e 75 aa ... 7f 88 ... 76a914...88ac
            if (s.find("76a914") == std::string::npos) return false;
            if (s.find("7f") == std::string::npos || s.find("88") == std::string::npos) return false;
            if (s.find("7caa") != std::string::npos) return true;  // canonical
            if (s.find("7c76aa") != std::string::npos) return true; // legacy A
            if (s.find("6e75aa") != std::string::npos) return true; // legacy B
            return false;
        };

        auto extractTarget = [](const std::string& scriptHex) -> std::string {
            // Reuse the same logic as in wallet (keep duplicated here to avoid cross-deps)
            auto readPush = [&](size_t off) -> std::pair<std::string,size_t> {
                if (off + 2 > scriptHex.size()) return {"", off};
                size_t len = std::stoul(scriptHex.substr(off,2), nullptr, 16);
                size_t need = 2 + len*2;
                if (off + need > scriptHex.size()) return {"", off};
                return { scriptHex.substr(off+2, len*2), off + need };
            };
            // Canonical first: find 7f, read the push *after* it
            size_t pos7f = scriptHex.find("7f");
            if (pos7f != std::string::npos) {
                auto [tgt, next] = readPush(pos7f + 2);
                if (!tgt.empty()) return tgt;
            }
            // Legacy: first push is likely <target>
            auto [tgt, next] = readPush(0);
            return tgt;
        };

        auto extractAddress = [&](const std::string& scriptHex) -> std::string {
            size_t pos = scriptHex.find("76a914");
            if (pos == std::string::npos || pos + 6 + 40 > scriptHex.size()) return "";
            std::string pkhHex = scriptHex.substr(pos + 6, 40);
            try {
                std::vector<uint8_t> pkh = hexDecode(pkhHex);
                std::vector<uint8_t> data = {tru_network::MAINNET_P2PKH_VERSION};
                data.insert(end(data), begin(pkh), end(pkh));
                unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
                SHA256(data.data(), data.size(), h1);
                SHA256(h1, SHA256_DIGEST_LENGTH, h2);
                data.insert(end(data), h2, h2 + 4);
                return base58Encode(data);
            } catch (...) { return ""; }
        };

        json arr = json::array();

        // --- Chain scan
        int tip = chain.getBestTipHeight();
        for (int height = 0; height <= tip; ++height) {
            auto b = chain.getBlockByHeight(height);
            if (!b) continue;
            for (const auto& tx : b->transactions) {
                for (size_t vout = 0; vout < tx.vout.size(); ++vout) {
                    const auto& out = tx.vout[vout];
                    const auto& sh = out.scriptPubKey;
                    if (!isMagicLock(sh)) continue;

                    std::string target = extractTarget(sh);
                    std::string addr   = extractAddress(sh);
                    if (!filterAddress.empty() && addr != filterAddress) continue;

                    UTXO u;
                    bool spent = !chain.utxoSet.getUTXO(tx.txid, vout, u);
                    arr.push_back({
                        {"txid", tx.txid},
                        {"vout", vout},
                        {"amount", out.amount / 1e8},
                        {"targetPrefix", target},
                        {"address", addr},
                        {"blockHeight", height},
                        {"spent", spent}
                    });
                }
            }
        }

        // --- Mempool scan
        for (const auto& tx : chain.getMempoolTransactions()) {
            for (size_t vout = 0; vout < tx.vout.size(); ++vout) {
                const auto& out = tx.vout[vout];
                const auto& sh = out.scriptPubKey;
                if (!isMagicLock(sh)) continue;

                std::string target = extractTarget(sh);
                std::string addr   = extractAddress(sh);
                if (!filterAddress.empty() && addr != filterAddress) continue;

                arr.push_back({
                    {"txid", tx.txid},
                    {"vout", vout},
                    {"amount", out.amount / 1e8},
                    {"targetPrefix", target},
                    {"address", addr},
                    {"blockHeight", -1},
                    {"spent", false}
                });
            }
        }

        return makeResult(id, json{{"magicLocks", arr},{"count", arr.size()}});
    } catch (const std::exception& e) {
        Logger::log(std::string("[handleListMagicLocks] Error: ") + e.what());
        return makeError(-32000, std::string("Failed to list MagicLocks: ") + e.what());
    }
}

/*
static json handleListMagicLocks(Blockchain &chain, const json &params, int id) {
    try {
        std::string filterAddress = "";
        if (params.contains("address")) {
            filterAddress = params["address"].get<std::string>();
        }
        
        json magicLocks = json::array();
        int tip = chain.getBestTipHeight();
        
        Logger::log("[handleListMagicLocks] Searching from height 0 to " + std::to_string(tip));
        
        // Search all blocks
        for (int height = 0; height <= tip; height++) {
            auto blockOpt = chain.getBlockByHeight(height);
            if (!blockOpt.has_value()) continue;
            
            Block block = blockOpt.value();
            for (const auto& tx : block.transactions) {
                for (size_t vout = 0; vout < tx.vout.size(); vout++) {
                    const auto& output = tx.vout[vout];
                    std::string scriptHex = output.scriptPubKey;
                    
                    // Updated pattern: Look for 7c76aa which is OP_SWAP OP_DUP OP_HASH256
                    if (scriptHex.find("6e75aa") != std::string::npos) {
                        Logger::log("[handleListMagicLocks] Found potential MagicLock: " + tx.txid + 
                                   " vout=" + std::to_string(vout));
                        Logger::log("[handleListMagicLocks] Script: " + scriptHex);
                        
                        try {
                            // Extract target (first part of script)
                            std::string target = "";
                            if (scriptHex.length() >= 4) {
                                size_t targetLen = std::stoul(scriptHex.substr(0, 2), nullptr, 16);
                                if (targetLen > 0 && targetLen * 2 + 2 <= scriptHex.length()) {
                                    target = scriptHex.substr(2, targetLen * 2);
                                }
                            }
                            
                            // Extract address from script (look for OP_DUP OP_HASH160 pattern)
                            std::string address = "";
                            size_t pos = scriptHex.find("76a914"); // OP_DUP OP_HASH160 OP_PUSHDATA(20)
                            if (pos != std::string::npos && pos + 50 <= scriptHex.length()) {
                                std::string pubKeyHashHex = scriptHex.substr(pos + 6, 40);
                                try {
                                    std::vector<uint8_t> pubKeyHash = hexDecode(pubKeyHashHex);
                                    if (pubKeyHash.size() == 20) {
                                        // Build address
                                        std::vector<uint8_t> addrData = {tru_network::MAINNET_P2PKH_VERSION}; // TRU mainnet P2PKH
                                        addrData.insert(addrData.end(), pubKeyHash.begin(), pubKeyHash.end());
                                        
                                        // Add checksum
                                        unsigned char hash1[SHA256_DIGEST_LENGTH];
                                        unsigned char hash2[SHA256_DIGEST_LENGTH];
                                        SHA256(addrData.data(), 21, hash1);
                                        SHA256(hash1, 32, hash2);
                                        addrData.insert(addrData.end(), hash2, hash2 + 4);
                                        
                                        address = base58Encode(addrData);
                                    }
                                } catch (...) {
                                    Logger::log("[handleListMagicLocks] Failed to decode address");
                                }
                            }
                            
                            // Apply address filter
                            if (!filterAddress.empty() && address != filterAddress) {
                                Logger::log("[handleListMagicLocks] Filtered out (address mismatch): " + address);
                                continue;
                            }
                            
                            // Check if UTXO is spent
                            UTXO utxo;
                            bool isSpent = !chain.utxoSet.getUTXO(tx.txid, vout, utxo);
                            
                            json lockInfo = {
                                {"txid", tx.txid},
                                {"vout", vout},
                                {"amount", output.amount / 1e8},
                                {"targetPrefix", target},
                                {"address", address},
                                {"blockHeight", height},
                                {"spent", isSpent}
                            };
                            
                            magicLocks.push_back(lockInfo);
                            
                            Logger::log("[handleListMagicLocks] Added MagicLock: " + tx.txid + 
                                       " target=" + target + " address=" + address + 
                                       " spent=" + (isSpent ? "true" : "false"));
                            
                        } catch (const std::exception& e) {
                            Logger::log("[handleListMagicLocks] Error parsing MagicLock: " + std::string(e.what()));
                        }
                    }
                }
            }
        }
        
        // Also check mempool
        auto mempoolTxs = chain.getMempoolTransactions();
        for (const auto& tx : mempoolTxs) {
            for (size_t vout = 0; vout < tx.vout.size(); vout++) {
                const auto& output = tx.vout[vout];
                std::string scriptHex = output.scriptPubKey;
                
                if (scriptHex.find("7c76aa") != std::string::npos) {
                    // Same parsing logic as above
                    std::string target = "";
                    if (scriptHex.length() >= 4) {
                        size_t targetLen = std::stoul(scriptHex.substr(0, 2), nullptr, 16);
                        if (targetLen > 0 && targetLen * 2 + 2 <= scriptHex.length()) {
                            target = scriptHex.substr(2, targetLen * 2);
                        }
                    }
                    
                    json lockInfo = {
                        {"txid", tx.txid},
                        {"vout", vout},
                        {"amount", output.amount / 1e8},
                        {"targetPrefix", target},
                        {"address", ""}, // Could parse if needed
                        {"blockHeight", -1},   // Unconfirmed
                        {"spent", false}
                    };
                    magicLocks.push_back(lockInfo);
                }
            }
        }
        
        Logger::log("[handleListMagicLocks] Found " + std::to_string(magicLocks.size()) + " total MagicLocks");
        
        json result = {
            {"magicLocks", magicLocks},
            {"count", magicLocks.size()}
        };
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleListMagicLocks] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to list MagicLocks: ") + e.what());
    }
}

*/

//========================
// Handle List Addresses
//========================
static json handleListAddresses(Wallet &wallet, const json &params, int id) {
    try {
        json result = {
            {"addresses", json::array()}
        };
        
        // Get addresses from wallet - use getAddresses() if it exists
        // Otherwise just return the current address
        try {
            auto addresses = wallet.getAddresses();
            for (const auto& addr : addresses) {
                result["addresses"].push_back(addr);
            }
        } catch (...) {
            // If getAddresses() doesn't exist, at least return current address
            result["addresses"].push_back(wallet.getCurrentAddress());
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleListAddresses] Error: " + std::string(e.what()));
        return makeError(-32000, std::string("Failed to list addresses: ") + e.what());
    }
}
//========================================================================
// TOKEN-AI-02D — Live token-evolution provenance / anchor verification
//========================================================================
static std::string tokenEvolutionTransactionStatus(
    Blockchain& chain,
    const std::string& txid,
    Transaction& out)
{
    for (const auto& tx : chain.getMempoolTransactions()) {
        if (tx.txid == txid) {
            out = tx;
            return "MEMPOOL";
        }
    }

    Transaction found;
    if (!chain.findTransaction(txid, found)) {
        return "MISSING";
    }

    // findTransaction() also checks mempool after confirmed blocks. Recheck the
    // mempool so a concurrent arrival cannot be mislabeled as confirmed.
    for (const auto& tx : chain.getMempoolTransactions()) {
        if (tx.txid == txid) {
            out = tx;
            return "MEMPOOL";
        }
    }

    out = std::move(found);
    return "CONFIRMED";
}

static bool loadTokenEvolutionIssuanceMetadata(
    LevelDBStorage& db,
    const std::string& tokenID,
    nlohmann::json& issuanceMetadata,
    std::string& issuanceTxid,
    std::string& tokenType,
    std::string& reason)
{
    issuanceMetadata = nlohmann::json::object();
    issuanceTxid.clear();
    tokenType.clear();
    reason.clear();

    if (!db.getWithDataChecksum("tokenIssuance:" + tokenID, issuanceTxid) ||
        issuanceTxid.size() != 64U ||
        !std::all_of(
            issuanceTxid.begin(), issuanceTxid.end(),
            [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            }))
    {
        reason = "missing or invalid tokenIssuance mapping";
        return false;
    }

    std::string raw;
    if (!db.getWithDataChecksum("tokenMetadata:" + issuanceTxid, raw)) {
        reason = "missing issuance tokenMetadata record";
        return false;
    }

    try {
        const nlohmann::json stored = nlohmann::json::parse(raw);
        if (!stored.is_object()) {
            reason = "issuance tokenMetadata is not an object";
            return false;
        }

        tokenType = stored.value("type", "");
        if (tokenType != "SFT" && tokenType != "NCFT") {
            reason = "token evolution is defined only for SFT/NCFT";
            return false;
        }

        if (stored.contains("meta") && stored["meta"].is_object()) {
            issuanceMetadata = stored["meta"];
        }

        // Match tru_evolve_token's issuance-root loader exactly.
        for (const char* key :
             {"name", "symbol", "description", "image", "imageUrl"})
        {
            if (stored.contains(key) && !issuanceMetadata.contains(key)) {
                issuanceMetadata[key] = stored[key];
            }
        }
    } catch (const std::exception& e) {
        reason = std::string("invalid issuance tokenMetadata: ") + e.what();
        return false;
    }

    return true;
}

static json handleVerifyTokenEvolution(
    Blockchain& chain,
    const json& params,
    int id)
{
    if (!params.contains("tokenID") || !params["tokenID"].is_string()) {
        return makeError(-32602, "Missing or invalid tokenID");
    }

    const bool requireConfirmed = params.value("require_confirmed", true);
    const std::string requested = params["tokenID"].get<std::string>();
    const std::string tokenID = normalizeTokenIDForLookupV2(requested);

    if ((tokenID.size() != 8U && tokenID.size() != 16U) || !isHex(tokenID)) {
        return makeError(-32602, "Invalid tokenID");
    }

    LevelDBStorage* db = chain.getStorage();
    if (!db) {
        return makeError(-32000, "Blockchain storage is unavailable");
    }

    nlohmann::json issuanceMetadata;
    std::string issuanceTxid;
    std::string tokenType;
    std::string loadReason;
    if (!loadTokenEvolutionIssuanceMetadata(
            *db, tokenID, issuanceMetadata, issuanceTxid, tokenType, loadReason))
    {
        return makeResult(id, json{
            {"format", "TRU_TOKEN_EVOLUTION_RUNTIME_VERIFY_V1"},
            {"tokenID", tokenID},
            {"runtime_ok", false},
            {"error", loadReason}
        });
    }

    ContractStorage contractStorage(db);
    TokenEvolutionEngine engine(&contractStorage);
    const nlohmann::json history =
        engine.verifyHistory(tokenID, issuanceMetadata);

    json result = {
        {"format", "TRU_TOKEN_EVOLUTION_RUNTIME_VERIFY_V1"},
        {"tokenID", tokenID},
        {"token_type", tokenType},
        {"issuance_txid", issuanceTxid},
        {"require_confirmed", requireConfirmed},
        {"history_ok", history.value("ok", false)},
        {"fully_anchored", history.value("fully_anchored", false)},
        {"history", history},
        {"anchors", json::array()},
        {"runtime_ok", false}
    };

    Transaction issuanceTx;
    const std::string issuanceStatus =
        tokenEvolutionTransactionStatus(chain, issuanceTxid, issuanceTx);
    result["issuance_status"] = issuanceStatus;

    bool allObservable = true;
    bool allPayloadsValid = true;
    bool allConfirmed = issuanceStatus == "CONFIRMED";
    uint64_t confirmedAnchors = 0;
    uint64_t mempoolAnchors = 0;
    uint64_t missingAnchors = 0;
    uint64_t validAnchorPayloads = 0;

    if (!history.value("ok", false) ||
        !history.contains("epochs") || !history["epochs"].is_array())
    {
        result["all_anchor_txs_observable"] = false;
        result["all_anchor_payloads_valid"] = false;
        result["all_anchor_txs_confirmed"] = false;
        return makeResult(id, result);
    }

    for (const auto& epochSummary : history["epochs"]) {
        json runtimeEpoch = {
            {"epoch", epochSummary.value("epoch", 0ULL)},
            {"anchor_status", epochSummary.value("anchor_status", "UNKNOWN")}
        };

        const std::string localStatus =
            epochSummary.value("anchor_status", "UNKNOWN");

        if (localStatus == "QUEUED_PENDING" ||
            localStatus == "PREPARED_PENDING")
        {
            runtimeEpoch["chain_status"] = "PENDING";
            runtimeEpoch["payload_valid"] = nullptr;
            result["anchors"].push_back(runtimeEpoch);
            allObservable = false;
            allConfirmed = false;
            continue;
        }

        if (localStatus != "RECEIPT_SUBMITTED" &&
            localStatus != "LEGACY_SUBMITTED")
        {
            runtimeEpoch["chain_status"] = "INVALID_LOCAL_STATE";
            runtimeEpoch["payload_valid"] = false;
            result["anchors"].push_back(runtimeEpoch);
            allObservable = false;
            allPayloadsValid = false;
            allConfirmed = false;
            continue;
        }

        const uint64_t epoch = epochSummary.value("epoch", 0ULL);
        const std::string anchorTxid =
            epochSummary.value("anchor_txid", "");
        runtimeEpoch["txid"] = anchorTxid;

        Transaction anchorTx;
        const std::string chainStatus =
            tokenEvolutionTransactionStatus(chain, anchorTxid, anchorTx);
        runtimeEpoch["chain_status"] = chainStatus;

        if (chainStatus == "CONFIRMED") {
            ++confirmedAnchors;
        } else if (chainStatus == "MEMPOOL") {
            ++mempoolAnchors;
            allConfirmed = false;
        } else {
            ++missingAnchors;
            allObservable = false;
            allConfirmed = false;
            runtimeEpoch["payload_valid"] = false;
            result["anchors"].push_back(runtimeEpoch);
            continue;
        }

        std::string epochRaw;
        const std::string epochKey =
            "epoch:" + tokenID + ":" + std::to_string(epoch);
        if (!contractStorage.getContractData(
                "TOKEN_EVOLUTION", epochKey, epochRaw))
        {
            runtimeEpoch["payload_valid"] = false;
            runtimeEpoch["payload_reason"] = "epoch record missing at runtime";
            allPayloadsValid = false;
            result["anchors"].push_back(runtimeEpoch);
            continue;
        }

        try {
            const nlohmann::json record = nlohmann::json::parse(epochRaw);
            std::string verifyReason;
            const bool valid = verifyTokenEvolutionAnchorTransaction(
                anchorTx, record, anchorTxid, verifyReason);

            runtimeEpoch["payload_valid"] = valid;
            runtimeEpoch["payload_reason"] = verifyReason;
            if (valid) {
                ++validAnchorPayloads;
            } else {
                allPayloadsValid = false;
            }
        } catch (const std::exception& e) {
            runtimeEpoch["payload_valid"] = false;
            runtimeEpoch["payload_reason"] =
                std::string("epoch parse/verification exception: ") + e.what();
            allPayloadsValid = false;
        }

        result["anchors"].push_back(runtimeEpoch);
    }

    result["confirmed_anchor_txs"] = confirmedAnchors;
    result["mempool_anchor_txs"] = mempoolAnchors;
    result["missing_anchor_txs"] = missingAnchors;
    result["valid_anchor_payloads"] = validAnchorPayloads;
    result["all_anchor_txs_observable"] = allObservable;
    result["all_anchor_payloads_valid"] = allPayloadsValid;
    result["all_anchor_txs_confirmed"] = allConfirmed;

    const bool issuanceAcceptable =
        requireConfirmed
            ? issuanceStatus == "CONFIRMED"
            : issuanceStatus != "MISSING";

    const bool anchorConfirmationAcceptable =
        requireConfirmed ? allConfirmed : allObservable;

    result["runtime_ok"] =
        history.value("ok", false) &&
        history.value("fully_anchored", false) &&
        issuanceAcceptable &&
        allObservable &&
        allPayloadsValid &&
        anchorConfirmationAcceptable;

    return makeResult(id, result);
}

//========================================================================
//                      Configure AI Provider
//========================================================================
static json handleConfigureAIProvider(Blockchain& chain, const json& params, int id) {
    Logger::log("[handleConfigureAIProvider] Received params: " + params.dump());
    
    if (!params.contains("address") || !params.contains("provider")) {
        return makeError(-32602, "Missing address or provider");
    }
    
    try {
        std::string userAddress = params["address"].get<std::string>();
        std::string provider = params["provider"].get<std::string>();
        
        // Build configuration based on provider type
        json config;
        
        if (provider == "openai") {
            if (!params.contains("api_key")) {
                return makeError(-32602, "OpenAI requires api_key");
            }
            config["api_key"] = params["api_key"];
            config["model"] = params.value("model", "gpt-4");
            
        } else if (provider == "ollama") {
            config["endpoint"] = params.value("endpoint", "http://127.0.0.1:11434/api/chat");
            config["model"] = params.value("model", "llama3");
            
        } else if (provider == "grok") {
            if (!params.contains("api_key")) {
                return makeError(-32602, "Grok requires api_key");
            }
            config["api_key"] = params["api_key"];
            config["model"] = params.value("model", "grok-beta");
            
        } else if (provider == "oobabooga") {
            config["endpoint"] = params.value("endpoint", "http://127.0.0.1:5000/v1/chat/completions");
            config["api_key"] = params.value("api_key", "");
            
        } else if (provider == "custom") {
            if (!params.contains("config")) {
                return makeError(-32602, "Custom provider requires config object");
            }
            config = params["config"];
        } else {
            return makeError(-32602, "Unknown provider: " + provider);
        }
        
        // Configure the provider
        std::string result = g_aiOracle->configureProvider(userAddress, provider, config);
        
        Logger::log("[handleConfigureAIProvider] Configuration successful: " + result);
        
        return makeResult(id, json{
            {"status", "success"},
            {"message", result},
            {"provider", provider},
            {"configured", true}
        });
        
    } catch (const std::exception& e) {
        Logger::log("[handleConfigureAIProvider] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Get Available AI Providers
//========================================================================
static json handleGetAIProviders(Blockchain& chain, const json& params, int id) {
    Logger::log("[handleGetAIProviders] Getting available providers");
    
    try {
        auto& registry = AIProviderRegistry::getInstance();
        auto providers = registry.getAvailableProviders();
        
        json result = json::object();
        
        for (const auto& name : providers) {
            auto provider = registry.getProvider(name);
            result[name] = {
                {"available", true},
                {"configured", provider->isConfigured()},
                {"endpoint", provider->getEndpoint()},
                {"default", (name == "oobabooga")}
            };
        }
        
        return makeResult(id, result);
        
    } catch (const std::exception& e) {
        Logger::log("[handleGetAIProviders] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Create AI Token
//========================================================================
static json handleCreateAIToken(Blockchain& chain, Wallet& wallet, const json& params, int id) {
    Logger::log("[handleCreateAIToken] Received params: " + params.dump());
    
    if (!params.contains("type") || !params.contains("tokenID") || 
        !params.contains("name") || !params.contains("address")) {
        return makeError(-32602, "Missing required parameters (type, tokenID, name, address)");
    }
    
    try {
        std::string tokenType = params["type"].get<std::string>();
        std::string tokenID = params["tokenID"].get<std::string>();
        std::string name = params["name"].get<std::string>();
        std::string userAddress = params["address"].get<std::string>();
        std::string provider = params.value("ai_provider", "oobabooga");
        
        // Validate token type
        if (tokenType != "SFT" && tokenType != "NCFT") {
            return makeError(-32602, "Token type must be SFT or NCFT");
        }
        
        // Store AI configuration for this token
        json tokenAIConfig = {
            {"provider", provider},
            {"created", std::time(nullptr)},
            {"owner", userAddress},
            {"consciousness_level", 0},
            {"evolution_state", "initial"}
        };
        
        LevelDBStorage* storage = chain.getStorage();
        if (storage) {
            std::string configKey = "ai_token:" + tokenID + ":config";
            storage->putWithDataChecksum(configKey, tokenAIConfig.dump());
        }
        
        // Prepare AI metadata
        std::unordered_map<std::string, std::string> aiMeta = {
            {"ai_provider", provider},
            {"ai_enabled", "true"},
            {"consciousness_version", "2.0"},
            {"oracle_address", "AI_ORACLE_ADDRESS"},
            {"neural_network", params.value("neural_network", "adaptive")},
            {"learning_rate", params.value("learning_rate", "0.05")}
        };
        
        std::string txid;
        
        if (tokenType == "SFT") {
            uint64_t supply = params.value("supply", 1000000);
            std::string symbol = params.value("symbol", "AI-SFT");
            std::string description = params.value("description", "AI-Enhanced Sentient Fungible Token");
            std::string image = params.value("image", "");
            uint32_t decimals = params.value("decimals", 8);
            
            txid = wallet.issueExtendedSFT(
                tokenID, supply, name, symbol,
                description, image, decimals, aiMeta
            );
            
        } else { // NCFT
            uint64_t quantity = params.value("quantity", 1);
            std::string description = params.value("description", "AI-Enhanced Neural Canvas Token");
            std::string image = params.value("image", "");
            
            txid = wallet.issueExtendedNCFT(
                tokenID, quantity, name,
                description, image, aiMeta
            );
        }
        
        Logger::log("[handleCreateAIToken] Created AI token with txid: " + txid);
        
        return makeResult(id, json{
            {"txid", txid},
            {"tokenID", tokenID},
            {"type", tokenType},
            {"ai_provider", provider},
            {"status", "created"},
            {"message", "AI-enabled " + tokenType + " token created successfully"}
        });
        
    } catch (const std::exception& e) {
        Logger::log("[handleCreateAIToken] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Interact with AI Token
//========================================================================
json handleInteractWithAIToken(Blockchain& chain, const json& params, int id) {
    Logger::log("[handleInteractWithAIToken] Received params: " + params.dump());
    
    if (!params.contains("tokenID") || !params.contains("address") || 
        !params.contains("message")) {
        return makeError(-32602, "Missing required parameters (tokenID, address, message)");
    }
    
    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        std::string userAddress = params["address"].get<std::string>();
        std::string message = params["message"].get<std::string>();
        
        // Generate unique request ID
        unsigned char hash[SHA256_DIGEST_LENGTH];
        std::string input = tokenID + userAddress + message + std::to_string(std::time(nullptr));
        SHA256((unsigned char*)input.c_str(), input.size(), hash);
        std::string requestID = bytesToHex(std::vector<uint8_t>(hash, hash + 8));
        
        // Prepare AI request
        json aiRequest = {
            {"tokenID", tokenID},
            {"sender", userAddress},
            {"prompt", message},
            {"timestamp", std::time(nullptr)},
            {"requestID", requestID}
        };
        
        LevelDBStorage* storage = chain.getStorage();
        if (storage) {
            storage->putContract("AI:ORACLE:request:" + requestID, aiRequest.dump());

            std::string cqueueData;
            storage->getContract("AI:ORACLE:ai_queue:pending", cqueueData);

            nlohmann::json cqueue = nlohmann::json::array();
            if (!cqueueData.empty())
            {
                try
                {
                    cqueue = nlohmann::json::parse(cqueueData);
                }
                catch (...)
                {
                    cqueue = nlohmann::json::array();
                } // recover from corrupt queue
            }
            // avoid duplicates
            if (std::find(cqueue.begin(), cqueue.end(), requestID) == cqueue.end())
            {
                cqueue.push_back(requestID);
            }
            storage->putContract("AI:ORACLE:ai_queue:pending", cqueue.dump());

            // Legacy keys (remove when all readers use contract namespace)
            {
                const std::string legacyReqKey = "ai_request:" + requestID;
                storage->putWithDataChecksum(legacyReqKey, aiRequest.dump());

                const std::string legacyQueueKey = "ai_queue:pending";
                std::string legacyQueueData;
                storage->getWithDataChecksum(legacyQueueKey, legacyQueueData);

                nlohmann::json legacyQueue = nlohmann::json::array();
                if (!legacyQueueData.empty())
                {
                    try
                    {
                        legacyQueue = nlohmann::json::parse(legacyQueueData);
                    }
                    catch (...)
                    {
                        legacyQueue = nlohmann::json::array();
                    }
                }
                if (std::find(legacyQueue.begin(), legacyQueue.end(), requestID) == legacyQueue.end())
                {
                    legacyQueue.push_back(requestID);
                }
                storage->putWithDataChecksum(legacyQueueKey, legacyQueue.dump());
            }
        }
        // Trigger async processing
        std::thread([requestID]() {
            if (g_aiOracle) {
                g_aiOracle->processAIRequest(requestID);
            }
        }).detach();
        
        Logger::log("[handleInteractWithAIToken] AI request submitted: " + requestID);
        
        return makeResult(id, json{
            {"requestID", requestID},
            {"tokenID", tokenID},
            {"status", "processing"},
            {"message", "AI interaction request submitted successfully"}
        });
        
    } catch (const std::exception& e) {
        Logger::log("[handleInteractWithAIToken] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Get AI Response
//========================================================================
json handleGetAIResponse(Blockchain& chain, const json& params, int id) {
    Logger::log(std::string("[handleGetAIResponse] Received params: ") + params.dump());

    if (!params.contains("requestID")) {
        return makeError(-32602, "Missing requestID");
    }

    try {
        const std::string requestID = params["requestID"].get<std::string>();
        LevelDBStorage* storage = chain.getStorage();
        if (!storage) {
            return makeError(-32000, "Storage not available");
        }

        // --- 1) Preferred: contract namespace (as written by Oracle) ---
        {
            std::string cdata;
            if (storage->getContract("AI:ORACLE:response:" + requestID, cdata)) {
                try {
                    nlohmann::json j = nlohmann::json::parse(cdata);
                    Logger::log("[handleGetAIResponse] Found contract response for: " + requestID);
                    return makeResult(id, j);
                } catch (const std::exception& e) {
                    return makeError(-32000, std::string("Corrupt contract response JSON: ") + e.what());
                }
            }
        }

        // --- 2) Legacy fallback (for older readers) ---
        {
            std::string legacy;
            if (storage->getWithDataChecksum("ai_response:" + requestID, legacy)) {
                try {
                    nlohmann::json j = nlohmann::json::parse(legacy);
                    Logger::log("[handleGetAIResponse] Found legacy response for: " + requestID);
                    return makeResult(id, j);
                } catch (const std::exception& e) {
                    return makeError(-32000, std::string("Corrupt legacy response JSON: ") + e.what());
                }
            }
        }

        // --- 3) Still pending? Verify request exists under either namespace ---
        {
            std::string req;
            bool exists =
                storage->getContract("AI:ORACLE:request:" + requestID, req) ||
                storage->getWithDataChecksum("ai_request:" + requestID, req);

            if (!exists) {
                return makeError(-32000, "Request ID not found");
            }
        }

        // Pending
        return makeResult(id, nlohmann::json{
            {"requestID", requestID},
            {"status", "pending"},
            {"message", "AI is still processing your request"}
        });

    } catch (const std::exception& e) {
        Logger::log(std::string("[handleGetAIResponse] Exception: ") + e.what());
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Get AI Token State
//========================================================================
static json handleGetAITokenState(Blockchain& chain, const json& params, int id) {
    Logger::log("[handleGetAITokenState] Received params: " + params.dump());
    
    if (!params.contains("tokenID")) {
        return makeError(-32602, "Missing tokenID");
    }
    
    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        
        LevelDBStorage* storage = chain.getStorage();
        if (!storage) {
            return makeError(-32000, "Storage not available");
        }
        
        json state;
        
        // Get AI configuration
        std::string configKey = "ai_token:" + tokenID + ":config";
        std::string configData;
        if (storage->getWithDataChecksum(configKey, configData)) {
            state["config"] = json::parse(configData);
        } else {
            return makeError(-32000, "Token not found or not AI-enabled");
        }
        
        // Get consciousness level
        std::string consciousnessKey = "ai_token:" + tokenID + ":consciousness";
        std::string consciousnessData;
        if (storage->getWithDataChecksum(consciousnessKey, consciousnessData)) {
            state["consciousness"] = json::parse(consciousnessData);
        }
        
        // Get evolution state
        std::string evolutionKey = "ai_token:" + tokenID + ":evolution";
        std::string evolutionData;
        if (storage->getWithDataChecksum(evolutionKey, evolutionData)) {
            state["evolution"] = json::parse(evolutionData);
        }
        
        // Get interaction history
        std::string historyKey = "ai_token:" + tokenID + ":history";
        std::string historyData;
        if (storage->getWithDataChecksum(historyKey, historyData)) {
            json history = json::parse(historyData);
            state["interaction_count"] = history.size();
            if (!history.empty()) {
                state["last_interaction"] = history.back();
            }
        }
        
        // Get last AI response
        std::string lastResponseKey = "ai_token:" + tokenID + ":last_response";
        std::string lastResponseData;
        if (storage->getWithDataChecksum(lastResponseKey, lastResponseData)) {
            state["last_ai_response"] = json::parse(lastResponseData);
        }
        
        state["tokenID"] = tokenID;
        state["ai_enabled"] = true;
        
        Logger::log("[handleGetAITokenState] Retrieved state for token: " + tokenID);
        
        return makeResult(id, state);
        
    } catch (const std::exception& e) {
        Logger::log("[handleGetAITokenState] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Train AI Token
//========================================================================
static json handleTrainAIToken(Blockchain& chain, const json& params, int id) {
    Logger::log("[handleTrainAIToken] Received params: " + params.dump());
    
    if (!params.contains("tokenID") || !params.contains("training_data")) {
        return makeError(-32602, "Missing tokenID or training_data");
    }
    
    try {
        std::string tokenID = params["tokenID"].get<std::string>();
        json trainingData = params["training_data"];
        std::string userAddress = params.value("address", "");
        
        // Store training request
        json trainingRequest = {
            {"tokenID", tokenID},
            {"training_data", trainingData},
            {"requester", userAddress},
            {"timestamp", std::time(nullptr)}
        };
        
        std::string requestID = generateRandomHex(16);
        
        LevelDBStorage* storage = chain.getStorage();
        if (storage) {
            std::string key = "ai_training:" + requestID;
            storage->putWithDataChecksum(key, trainingRequest.dump());
        }
        
        // Trigger training (async)
        std::thread([tokenID, trainingData]() {
            // Here you would send to AI provider for fine-tuning
            // This is simplified - actual implementation would vary by provider
            Logger::log("[handleTrainAIToken] Training initiated for token: " + tokenID);
        }).detach();
        
        return makeResult(id, json{
            {"requestID", requestID},
            {"tokenID", tokenID},
            {"status", "training_initiated"},
            {"message", "AI token training started"}
        });
        
    } catch (const std::exception& e) {
        Logger::log("[handleTrainAIToken] Exception: " + std::string(e.what()));
        return makeError(-32000, e.what());
    }
}

//========================================================================
//                      Initialize AI Oracle
//========================================================================
void initializeAIOracle(Blockchain& chain, Wallet* authenticatedSigningWallet) {
    Logger::log("[initializeAIOracle] Initializing AI Oracle system");
    try {
        if (g_aiOracleThread.joinable()) shutdownAIOracle();
        g_aiContractStorage=std::make_unique<ContractStorage>(chain.getStorage());
        g_aiOracle=std::make_shared<ConfigurableAIOracle>(
            &chain,
            g_aiContractStorage.get(),
            authenticatedSigningWallet);
        auto oracle=g_aiOracle;
        g_aiOracleThread=std::thread([oracle](){ oracle->startMonitoring(); });
        Logger::log("[initializeAIOracle] AI Oracle initialized with Oobabooga as default");
    } catch (const std::exception& e) { Logger::log("[initializeAIOracle] Failed to initialize: "+std::string(e.what())); }
}
void shutdownAIOracle() {
    Logger::log("[shutdownAIOracle] Stopping AI Oracle monitoring service");
    auto oracle=g_aiOracle; if (oracle) oracle->stopMonitoring();
    if (g_aiOracleThread.joinable()) { g_aiOracleThread.join(); Logger::log("[shutdownAIOracle] AI Oracle monitoring thread joined"); }
    g_aiOracle.reset(); g_aiContractStorage.reset();
    Logger::log("[shutdownAIOracle] AI Oracle shutdown complete");
}
//========================
// Start RPC Server
//========================
// Format TRU atoms as a fixed 8-decimal TRU string without snprintf/ostream
// precision surprises (integer math + manual zero-pad). See patch30 rationale.
static std::string truFromAtoms(uint64_t atoms) {
    return tru_amount::formatNumeric(atoms);
}

//========================
// getbalance  (aggregate TRU balance)
//========================
static json handleGetBalance(Blockchain &chain, Wallet &wallet, const json &p, int id) {
    try {
        std::string addr;

        if (p.contains("address") && p["address"].is_string()) {
            addr = p["address"].get<std::string>();
        } else {
            addr = wallet.getCurrentAddress();
        }

        if (addr.empty()) {
            return makeError(
                -32602,
                "No address supplied and wallet has no current address"
            );
        }

        // calculate_balance() returns spendable TRU atoms for the address,
        // excluding mempool-spent UTXOs and immature coinbase.
        uint64_t atoms = chain.calculate_balance(addr);

        json out = {
            {"address",   addr},
            {"confirmed", truFromAtoms(atoms)},
            {"atoms",     atoms}
        };

        return makeResult(id, out);

    } catch (const std::exception &e) {
        return makeError(
            -32000,
            std::string("getbalance failed: ") + e.what()
        );
    }
}

//========================
// getinfo  (aggregate, bitcoin-style)
//========================
static json handleGetInfo(Blockchain &chain, Wallet &wallet, P2PNode &node, int id) {
    try {
        int    height   = chain.getBestTipHeight();
        std::string tip = chain.getBestTipHash();
        uint32_t diff   = chain.getDifficulty();
        bool   valid    = chain.isChainValid();
        int    csize    = chain.getChainSize();

        // Connection count from the live peer list.
        size_t conns = 0;
        try { conns = node.getPeersList().size(); } catch (...) { conns = 0; }

        // Wallet snapshot (current address + its spendable balance).
        std::string addr = wallet.getCurrentAddress();
        uint64_t sats = 0;
        if (!addr.empty()) {
            try { sats = chain.calculate_balance(addr); } catch (...) { sats = 0; }
        }
        // Difficulty as a compact-bits hex string (manual, no snprintf).
        static const char* HEXD = "0123456789abcdef";
        std::string diffhex(8, '0');
        for (int i = 7; i >= 0; --i) { diffhex[i] = HEXD[diff & 0xF]; diff >>= 4; }
        uint32_t diffForOut = chain.getDifficulty();

        json out = {
            {"version",       std::string("TRU-node")},
            {"blocks",        height},
            {"bestblockhash", tip},
            {"chainsize",     csize},
            {"difficulty",    diffForOut},
            {"difficultyhex", std::string("0x") + diffhex},
            {"connections",   (uint64_t)conns},
            {"chainvalid",    valid},
            {"address",       addr},
            {"balance",       truFromAtoms(sats)},
            {"balance_atoms", sats},
            {"balance_sat",   sats}
        };
        return makeResult(id, out);
    } catch (const std::exception &e) {
        return makeError(-32000, std::string("getinfo failed: ") + e.what());
    }
}

//=======================================================================
// TRU-SWAP-A — AUTOMATION FOUNDATION
// Frozen HTLC V1 wallet operations + durable coordinator record RPC.
//=======================================================================
static bool truSwapConstantTimeEqual(const std::string& a, const std::string& b) {
    // use the transport helper's length-oblivious comparison so the
    // inner swap-token layer does not reintroduce an early length mismatch.
    return tru_rpc::constantTimeEqual(a, b);
}

static void requireTruSwapRpcAuth(const json& params) {
    const char* rawExpected = std::getenv("TRU_SWAP_RPC_TOKEN");
    if (!rawExpected) {
        throw std::runtime_error(
            "TRU-SWAP RPC disabled: TRU_SWAP_RPC_TOKEN is not configured");
    }
    const std::string expected(rawExpected);
    if (expected.size() < 32U) {
        throw std::runtime_error(
            "TRU-SWAP RPC disabled: TRU_SWAP_RPC_TOKEN must be at least 32 characters");
    }
    if (!params.contains("authToken") || !params.at("authToken").is_string()) {
        throw std::runtime_error("TRU-SWAP RPC authentication required");
    }
    const std::string supplied = params.at("authToken").get<std::string>();
    if (!truSwapConstantTimeEqual(supplied, expected)) {
        throw std::runtime_error("TRU-SWAP RPC authentication failed");
    }
}

static json handleHtlcGenerateSecret(Wallet& wallet, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        const auto secret = wallet.generateHtlcAtomicSwapSecretV1();
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"hashAlgorithm", "HASH160"},
            {"preimageHex", secret.preimageHex},
            {"secretHash160", secret.hash160Hex}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

//====================================================================================
// SWAP-FRESH-01B4D2 — authenticated signed funding preparation / NO BROADCAST
//====================================================================================
static json handleHtlcPrepareFunding(Wallet& wallet, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("operationId") ||
            !params.contains("secretHash160") ||
            !params.contains("claimPubkey") ||
            !params.contains("refundPubkey") ||
            !params.contains("refundTime") ||
            !params.contains("amountAtoms")) {
            return makeError(-32602,
                "htlcpreparefunding requires operationId, secretHash160, claimPubkey, refundPubkey, refundTime, amountAtoms");
        }
        const auto result = wallet.prepareHtlcAtomicSwapV1(
            params.at("secretHash160").get<std::string>(),
            params.at("claimPubkey").get<std::string>(),
            params.at("refundPubkey").get<std::string>(),
            params.at("refundTime").get<std::uint32_t>(),
            params.at("amountAtoms").get<std::uint64_t>(),
            params.at("operationId").get<std::string>());
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"status", "SIGNED_RESERVED_NOT_BROADCAST"},
            {"operationId", result.operationId},
            {"preparedTxid", result.txid},
            {"preparedVout", result.contractVout},
            {"rawTxHex", result.rawTxHex},
            {"scriptHex", result.scriptHex},
            {"amountAtoms", result.amountAtoms},
            {"feeAtoms", result.feeAtoms},
            {"secretHash160", result.secretHash160Hex},
            {"claimPubkey", result.claimPubkeyHex},
            {"refundPubkey", result.refundPubkeyHex},
            {"refundTime", result.refundLockTime},
            {"reservationActive", result.reservationActive},
            {"reservedInputCount", result.reservedInputCount},
            {"idempotentReuse", result.idempotentReuse},
            {"broadcast", false},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleHtlcPreparedStatus(
    Wallet& wallet, const json& params, int id)
{
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("operationId")) {
            return makeError(
                -32602, "htlcpreparedstatus requires operationId");
        }
        const auto result = wallet.getPreparedHtlcFundingStatusV1(
            params.at("operationId").get<std::string>());
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"operationId", result.operationId},
            {"found", result.found},
            {"state", result.state},
            {"preparedTxid", result.preparedTxid},
            {"preparedVout", result.contractVout},
            {"reservedInputCount", result.reservedInputCount},
            {"reservationActive", result.reservationActive},
            {"inMempool", result.inMempool},
            {"rawTxReturned", false},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleHtlcPreparedRelease(
    Wallet& wallet, const json& params, int id)
{
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("operationId") ||
            !params.contains("preparedTxid")) {
            return makeError(
                -32602,
                "htlcpreparedrelease requires operationId and preparedTxid");
        }
        const auto result = wallet.releasePreparedHtlcFundingV1(
            params.at("operationId").get<std::string>(),
            params.at("preparedTxid").get<std::string>());
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"operationId", result.operationId},
            {"state", result.state},
            {"preparedTxid", result.preparedTxid},
            {"reservationActive", result.reservationActive},
            {"inMempool", result.inMempool},
            {"released", true},
            {"rawTxReturned", false},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleHtlcBroadcastPrepared(
    Wallet& wallet, const json& params, int id)
{
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("operationId") ||
            !params.contains("preparedTxid")) {
            return makeError(
                -32602,
                "htlcbroadcastprepared requires operationId and preparedTxid; dryRun defaults true");
        }
        const bool dryRun = params.value("dryRun", true);
        const auto result = wallet.broadcastPreparedHtlcFundingV1(
            params.at("operationId").get<std::string>(),
            params.at("preparedTxid").get<std::string>(),
            dryRun);
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"operationId", result.operationId},
            {"preparedTxid", result.preparedTxid},
            {"preparedVout", result.contractVout},
            {"dryRun", result.dryRun},
            {"alreadyInMempool", result.alreadyInMempool},
            {"broadcast", result.broadcast},
            {"reservationActive", result.reservationActive},
            {"exactPersistedBytesOnly", true},
            {"rawTxReturned", false},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}


static json handleHtlcCreate(Wallet& wallet, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("secretHash160") ||
            !params.contains("claimPubkey") ||
            !params.contains("refundPubkey") ||
            !params.contains("refundTime") ||
            !params.contains("amountAtoms")) {
            return makeError(-32602,
                "htlccreate requires secretHash160, claimPubkey, refundPubkey, refundTime, amountAtoms");
        }
        const auto result = wallet.createHtlcAtomicSwapV1(
            params.at("secretHash160").get<std::string>(),
            params.at("claimPubkey").get<std::string>(),
            params.at("refundPubkey").get<std::string>(),
            params.at("refundTime").get<std::uint32_t>(),
            params.at("amountAtoms").get<std::uint64_t>());
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"status", "MEMPOOL_ACCEPTED"},
            {"fundingTxid", result.txid},
            {"fundingVout", result.contractVout},
            {"contractOutpoint", result.txid + ":" + std::to_string(result.contractVout)},
            {"scriptHex", result.scriptHex},
            {"amountAtoms", result.amountAtoms},
            {"feeAtoms", result.feeAtoms},
            {"secretHash160", result.secretHash160Hex},
            {"claimPubkey", result.claimPubkeyHex},
            {"refundPubkey", result.refundPubkeyHex},
            {"refundTime", result.refundLockTime}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleHtlcClaim(Wallet& wallet, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("fundingTxid") ||
            !params.contains("recipient") ||
            !params.contains("preimageHex")) {
            return makeError(-32602,
                "htlcclaim requires fundingTxid, recipient, preimageHex; vout defaults to 1");
        }
        const std::uint32_t vout = params.value("vout", 1U);
                const std::string allocationId =
            params.value("allocationId", std::string{});
        const auto result = wallet.claimHtlcAtomicSwapV1(
            params.at("fundingTxid").get<std::string>(),
            vout,
            params.at("recipient").get<std::string>(),
            params.at("preimageHex").get<std::string>(),
            allocationId);
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"branch", result.branch},
            {"status", "MEMPOOL_ACCEPTED"},
            {"fundingTxid", result.contractTxid},
            {"fundingVout", result.contractVout},
            {"claimTxid", result.txid},
            {"recipient", result.recipient},
            {"releaseAmountAtoms", result.releaseAmountAtoms},
            {"feeAtoms", result.feeAtoms},
            {"secretHash160", result.secretHash160Hex},
            {"refundTime", result.refundLockTime},
            {"signerPubkey", result.signerPubkeyHex},
            {"sighash", result.sighashHex}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleHtlcRefund(Wallet& wallet, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("fundingTxid") || !params.contains("recipient")) {
            return makeError(-32602,
                "htlcrefund requires fundingTxid, recipient; vout defaults to 1");
        }
        const std::uint32_t vout = params.value("vout", 1U);
                const std::string allocationId =
            params.value("allocationId", std::string{});
        const auto result = wallet.refundHtlcAtomicSwapV1(
            params.at("fundingTxid").get<std::string>(),
            vout,
            params.at("recipient").get<std::string>(),
            allocationId);
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"family", "htlc_atomic_swap_v1"},
            {"branch", result.branch},
            {"status", "MEMPOOL_ACCEPTED"},
            {"fundingTxid", result.contractTxid},
            {"fundingVout", result.contractVout},
            {"refundTxid", result.txid},
            {"recipient", result.recipient},
            {"releaseAmountAtoms", result.releaseAmountAtoms},
            {"feeAtoms", result.feeAtoms},
            {"secretHash160", result.secretHash160Hex},
            {"refundTime", result.refundLockTime},
            {"signerPubkey", result.signerPubkeyHex},
            {"sighash", result.sighashHex}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapRecordCreate(Blockchain& chain, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        bool created = false;
        const json record = tru_swap_v1::createRecord(chain.getStorage(), params, created);
        return makeResult(id, json{
            {"created", created},
            {"swapId", record.at("swapId")},
            {"record", record}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapRecordGet(Blockchain& chain, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("swapId") || !params.at("swapId").is_string())
            return makeError(-32602, "swaprecordget requires swapId");
        json record;
        if (!tru_swap_v1::loadRecord(
                chain.getStorage(), params.at("swapId").get<std::string>(), record))
            return makeError(-32004, "TRU-SWAP record not found");
        return makeResult(id, record);
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapRecordList(Blockchain& chain, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        const json records = tru_swap_v1::listRecords(chain.getStorage());
        return makeResult(id, json{{"count", records.size()}, {"records", records}});
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapRecordTransition(Blockchain& chain, const json& params, int id) {
    try {
        requireTruSwapRpcAuth(params);
        if (!params.contains("swapId") ||
            !params.contains("nextState") ||
            !params.at("swapId").is_string() ||
            !params.at("nextState").is_string())
            return makeError(-32602,
                "swaprecordtransition requires swapId and nextState");
        const json evidence =
            params.contains("evidence") ? params.at("evidence") : json::object();
        const json record = tru_swap_v1::transitionRecord(
            chain.getStorage(),
            params.at("swapId").get<std::string>(),
            params.at("nextState").get<std::string>(),
            evidence);
        return makeResult(id, record);
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

// TRU-SWAP-B — public-only view of deterministic encrypted wallet role keys.
// TRU-SWAP-FRESH-01A — SWAP-token-authenticated public-only fresh roles.
// allocationId is public metadata. No seed/private/passphrase material is
// returned by this RPC.
// TRU-SWAP-FRESH-01B1A — fixed-domain fresh-role signer self-proof.
//
// This RPC accepts only public allocationId + role metadata. It does not accept
// a caller-selected digest/message/sighash, does not return a signature, and
// does not expose seed/private/passphrase material.
static json handleSwapWalletFreshSelfProof(
    Wallet& wallet,
    const json& params,
    int id)
{
    try {
        requireTruSwapRpcAuth(params);

        if (!params.contains("allocationId") ||
            !params.at("allocationId").is_string()) {
            throw std::invalid_argument(
                "swapwalletfreshselfproof requires allocationId string");
        }
        if (!params.contains("role") ||
            !params.at("role").is_string()) {
            throw std::invalid_argument(
                "swapwalletfreshselfproof requires role string");
        }

        const std::string allocationId =
            params.at("allocationId").get<std::string>();
        const std::string roleName =
            params.at("role").get<std::string>();

        std::uint32_t role = 0U;
        if (roleName == "claim") {
            role = 0U;
        } else if (roleName == "refund") {
            role = 1U;
        } else {
            throw std::invalid_argument(
                "swapwalletfreshselfproof role must be claim or refund");
        }

        const TruFreshSwapRoleKeysV1 roles =
            wallet.deriveFreshSwapRoleKeysV1(allocationId);

        const std::string pubkeyHex =
            role == 0U ? roles.claimPubkeyHex : roles.refundPubkeyHex;
        const std::vector<unsigned char> pubkey =
            hexToBytes(pubkeyHex);

        if (pubkey.size() != 33U ||
            (pubkey[0] != 0x02U && pubkey[0] != 0x03U)) {
            throw std::runtime_error(
                "TRU-SWAP fresh self-proof derived invalid compressed pubkey");
        }

        const std::string proofPreimage =
            std::string("TRU-SWAP-FRESH-SELFPROOF-V1|") +
            roles.allocationId + "|" + roleName;

        unsigned char proofHash[SHA256_DIGEST_LENGTH];
        if (SHA256(
                reinterpret_cast<const unsigned char*>(proofPreimage.data()),
                proofPreimage.size(),
                proofHash) == nullptr) {
            throw std::runtime_error(
                "TRU-SWAP fresh self-proof SHA256 failed");
        }

        const std::vector<unsigned char> digest(
            proofHash, proofHash + SHA256_DIGEST_LENGTH);
        std::memset(proofHash, 0, sizeof(proofHash));

        std::vector<unsigned char> fullSignature =
            wallet.signFreshSwapRoleDigestV1(
                roles.allocationId, role, pubkey, digest);

        if (fullSignature.size() < 2U ||
            fullSignature.back() != 0x01U) {
            throw std::runtime_error(
                "TRU-SWAP fresh self-proof missing SIGHASH_ALL marker");
        }

        std::vector<unsigned char> derSignature(
            fullSignature.begin(), fullSignature.end() - 1);
        std::fill(fullSignature.begin(), fullSignature.end(), 0U);

        const std::string digestBinary(digest.begin(), digest.end());

        const bool verified =
            ECDSAKey::isStrictDERLowS(derSignature) &&
            ECDSAKey::verifyCanonicalTransactionSignature(
                pubkey, digestBinary, derSignature);

        std::fill(derSignature.begin(), derSignature.end(), 0U);

        if (!verified) {
            throw std::runtime_error(
                "TRU-SWAP fresh self-proof verification failed");
        }

        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"proofDomain", "TRU-SWAP-FRESH-SELFPROOF-V1"},
            {"derivationScheme", "TRU-SWAP-FRESH-HD-V1"},
            {"allocationId", roles.allocationId},
            {"role", roleName},
            {"pubkey", pubkeyHex},
            {"verified", true},
            {"signatureReturned", false},
            {"digestReturned", false},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapWalletFreshKeys(
    Wallet& wallet,
    const json& params,
    int id)
{
    try {
        requireTruSwapRpcAuth(params);

        if (!params.contains("allocationId") ||
            !params.at("allocationId").is_string()) {
            throw std::invalid_argument(
                "swapwalletfreshkeys requires allocationId string");
        }

        const TruFreshSwapRoleKeysV1 roles =
            wallet.deriveFreshSwapRoleKeysV1(
                params.at("allocationId").get<std::string>());

        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"derivationScheme", "TRU-SWAP-FRESH-HD-V1"},
            {"allocationId", roles.allocationId},
            {"claimAddress", roles.claimAddress},
            {"claimPubkey", roles.claimPubkeyHex},
            {"refundAddress", roles.refundAddress},
            {"refundPubkey", roles.refundPubkeyHex},
            {"privateMaterialReturned", false}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

static json handleSwapWalletRoleKeys(
    Wallet& wallet,
    const json& params,
    int id)
{
    try {
        requireTruSwapRpcAuth(params);
        const TruSwapRoleKeysV1 roles = wallet.getSwapRoleKeysV1();
        return makeResult(id, json{
            {"protocol", "TRU-SWAP-V1"},
            {"claimAddress", roles.claimAddress},
            {"claimPubkey", roles.claimPubkeyHex},
            {"claimIndex", roles.claimIndex},
            {"refundAddress", roles.refundAddress},
            {"refundPubkey", roles.refundPubkeyHex},
            {"refundIndex", roles.refundIndex}
        });
    } catch (const std::exception& e) {
        return makeError(-32000, e.what());
    }
}

namespace {
struct RpcRateBucket {
    double tokens{240.0};
    std::chrono::steady_clock::time_point updated{std::chrono::steady_clock::now()};
};

static std::mutex g_rpcRateMutex;
static std::unordered_map<std::string, RpcRateBucket> g_rpcRateBuckets;
static std::unordered_map<std::string, RpcRateBucket> g_rpcAuthFailBuckets;

static bool consumeRpcBucket(std::unordered_map<std::string, RpcRateBucket>& buckets,
                             const std::string& key,
                             double cost,
                             double capacity,
                             double refillPerSecond) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(g_rpcRateMutex);
    if (buckets.size() >= 1024U && buckets.find(key) == buckets.end()) {
        for (auto it = buckets.begin(); it != buckets.end();) {
            if (std::chrono::duration_cast<std::chrono::minutes>(now - it->second.updated).count() >= 15) {
                it = buckets.erase(it);
            } else {
                ++it;
            }
        }
        if (buckets.size() >= 1024U) return false;
    }
    auto it = buckets.find(key);
    if (it == buckets.end()) {
        it = buckets.emplace(key, RpcRateBucket{capacity, now}).first;
    }
    auto& b = it->second;
    const double elapsed = std::chrono::duration<double>(now - b.updated).count();
    if (elapsed > 0.0) b.tokens = std::min(capacity, b.tokens + elapsed * refillPerSecond);
    b.updated = now;
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
}

static double rpcMethodCost(const std::string& method) {
    static const std::unordered_set<std::string> expensive = {
        "submitblock", "sendrawtransaction", "sendrawtransactionWeb",
        "signrawtransactionwithkey", "signrawtransactionwithkeyWeb",
        "issuetoken", "issuetokensigned", "createcontracttransaction",
        "inscribeTRUScript", "inscribeTRUScriptSigned", "createsocialpost",
        "createAIToken", "interactWithAIToken", "trainAIToken"
    };
    if (expensive.count(method)) return 8.0;
    if (method == "getblocktemplate") return 2.0;
    return 1.0;
}

static bool requestHasBrowserOrigin(const httplib::Request& req) {
    return req.has_header("Origin") || req.has_header("Sec-Fetch-Site");
}

static bool authorizeRpcTransport(const httplib::Request& req,
                                  httplib::Response& res,
                                  const std::string& expectedToken) {
    if (requestHasBrowserOrigin(req)) {
        res.status = 403;
        res.set_content("{\"error\":\"direct browser access to privileged RPC is disabled\"}\n", "application/json");
        return false;
    }
    const std::string raw = req.get_header_value("Authorization");
    constexpr const char* prefix = "Bearer ";
    std::string supplied;
    if (raw.rfind(prefix, 0) == 0) supplied = raw.substr(7);
    if (!tru_rpc::constantTimeEqual(supplied, expectedToken)) {
        if (!consumeRpcBucket(g_rpcAuthFailBuckets, req.remote_addr, 1.0, 30.0, 0.5)) {
            res.status = 429;
            res.set_header("Retry-After", "2");
            res.set_content("{\"error\":\"RPC authentication rate limit exceeded\"}\n", "application/json");
            return false;
        }
        res.status = 401;
        res.set_header("WWW-Authenticate", "Bearer realm=\"TRU RPC\"");
        res.set_content("{\"error\":\"RPC authentication required\"}\n", "application/json");
        return false;
    }
    return true;
}
} // namespace

void startRPCServer(Blockchain &chain, Wallet &wallet, P2PNode &node, int port,
                    const std::string &bindIP, int maxConnections,
                    const std::string &rpcAuthToken) {
    if (rpcAuthToken.size() < 32U) {
        throw std::runtime_error("Patch 05 RPC authentication token is too short");
    }
    initializeAIOracle(chain, &wallet);
    const std::size_t workers = static_cast<std::size_t>(std::clamp(maxConnections, 1, 256));
    g_rpcServer.new_task_queue = [workers] {
        return new httplib::ThreadPool(workers, workers * 2U);
    };
    g_rpcServer.set_keep_alive_max_count(5);
    g_rpcServer.set_read_timeout(30, 0);
    g_rpcServer.set_write_timeout(30, 0);
    g_rpcServer.set_payload_max_length((tru_limits::MAX_BLOCK_BYTES * 2U) + (4U * 1024U * 1024U));

    // Privileged node RPC is intentionally NOT a browser API. No CORS headers.
    g_rpcServer.Options("/rpc", [](const auto&, auto& res) {
        res.status = 403;
        res.set_content("{\"error\":\"browser CORS access disabled\"}\n", "application/json");
    });

    g_rpcServer.Post("/rpc",[&chain, &wallet, &node, rpcAuthToken](auto &req,auto &res){
        if (!authorizeRpcTransport(req, res, rpcAuthToken)) return;
        const std::string contentType = req.get_header_value("Content-Type");
        if (contentType.rfind("application/json", 0) != 0) {
            res.status = 415;
            res.set_content("{\"error\":\"Content-Type application/json required\"}\n", "application/json");
            return;
        }
        json request; int id=0; try{request=json::parse(req.body); id=request.value("id",0);}catch(...){res.set_content(makeError(-32700,"Parse error").dump(2),"application/json");return;}
        std::string m=request.value("method",""); json params=request.value("params",json::object()); json response;

        // RPC-RATE-06: the privileged Core RPC listens on loopback, so native
        // miners, tru-cli and the public Explorer/Wallet gateway all arrive as
        // the same transport address (normally 127.0.0.1).  A single bucket for
        // that address allowed a busy native miner to consume the budget needed
        // by browser mining.  Keep the existing capacity/refill/cost policy, but
        // isolate independent RPC lanes.  Public browser traffic is still
        // protected by the existing per-client public-gateway limiter before it
        // reaches Core.
        std::string rpcRateKey = req.remote_addr + "|" + m;
        if (m == "getblocktemplate" &&
            params.contains("browserMinerAddress") &&
            params["browserMinerAddress"].is_string()) {
            const std::string browserMiner =
                params["browserMinerAddress"].get<std::string>();
            if (!browserMiner.empty() && browserMiner.size() <= 128U) {
                rpcRateKey += "|browser-miner|" + browserMiner;
            }
        } else if ((m == "reportmineractivity" ||
                    m == "registerminer" ||
                    m == "unregisterminer") &&
                   params.contains("minerAddress") &&
                   params["minerAddress"].is_string()) {
            const std::string minerAddress =
                params["minerAddress"].get<std::string>();
            if (!minerAddress.empty() && minerAddress.size() <= 128U) {
                rpcRateKey += "|miner|" + minerAddress;
            }
        } else if (m == "submitblock" &&
                   params.contains("browserCandidate")) {
            // Browser submissions are already constrained by the public gateway
            // and normal authoritative block validation.  Keep their Core RPC
            // budget separate from native submitblock traffic.
            rpcRateKey += "|browser-miner";
        }

        if (!consumeRpcBucket(g_rpcRateBuckets, rpcRateKey, rpcMethodCost(m), 240.0, 4.0)) {
            res.status = 429;
            res.set_header("Retry-After", "1");
            res.set_content("{\"error\":\"RPC request rate limit exceeded\"}\n", "application/json");
            return;
        }
        if      (m=="getpeerinfo")         response=handleGetPeerInfo(node, params, id);
        else if (m=="sendtoken")           response=handleSendToken(chain,wallet,params,id);
        else if (m=="burntoken")           response=handleBurnToken(chain,wallet,params,id);
        else if (m=="gettokenburninfo")    response=handleGetTokenBurnInfo(id);
        else if (m=="getnewaddress")       response=handleGetNewAddress(wallet,params,id);
        else if (m=="reportmineractivity") response=handleReportMinerActivityOptimized(chain,params,id);
        else if (m=="getblocktemplate") {
            try {
                response = makeResult(id, handleGetBlockTemplate(chain, params));
            } catch (const std::exception& e) {
                Logger::log(
                    "[getblocktemplate] ERROR: candidate ancestry/difficulty failure: " +
                    std::string(e.what()));
                response = makeError(
                    -32000,
                    std::string("getblocktemplate failed: ") + e.what());
            } catch (...) {
                Logger::log(
                    "[getblocktemplate] ERROR: unknown candidate ancestry/difficulty failure");
                response = makeError(
                    -32000,
                    "getblocktemplate failed: unknown ancestry/difficulty error");
            }
        }
        else if (m=="submitblock")         response=handleSubmitBlockOptimized(chain,node,params,id);
        else if (m=="getblockbyheight")    response=handleGetBlockByHeight(chain,params,id);
        else if (m=="getblock")            response=handleGetBlock(chain,params,id);
        else if (m=="getchaininfo")        response=handleGetChainInfo(chain,id);
        else if (m=="sendrawtransactionWeb")  response=handleSendTransactionWeb(chain,params,id);
        else if (m=="sendrawtransaction")  response=handleSendTransaction(chain,params,id);
        else if (m== "startmining")        response=handleStartMining(chain, params);
        else if (m=="getmempooltransactions") response=handleGetMempoolTransactions(chain,id);
        else if (m=="getrawmempool")       response=handleGetRawMempool(chain,params,id);
        else if (m=="listunspentWeb")         response=handleListUnspentWeb(chain,params,id);
        else if (m=="listunspent")         response=handleListUnspent(chain,params,id);
        else if (m=="createrawtransaction")      response=handleCreateRawTransaction(chain,params,id);
        else if (m=="signrawtransactionwithkeyWeb") response=handleSignRawTransactionWithKeyWeb(chain,params,id);
        else if (m=="signrawtransactionwithkey") response=handleSignRawTransactionWithKey(chain,params,id);
        else if (m=="gettokenutxo")        response=handleGetTokenUTXO(chain, params, id);
        else if (m=="gettokenmetadata")    response=handleGetTokenMetadata(chain, params, id);
        else if (m=="verifytokenevolution") response=handleVerifyTokenEvolution(chain, params, id);
        else if (m == "inscribeTRUScript") response = handleInscribeTRUScript(chain, wallet, params, id);
        else if (m=="inscribeTRUScriptSigned") response=handleInscribeTRUScriptSigned(chain,params,id);
        else if (m == "createsocialpost")  response = handleCreateSocialPost(chain, wallet, params, id);
        else if (m=="getDIDMapping")       response=handleGetDIDMapping(chain, params, id);
        else if (m=="registerDIDSigned")   response=handleRegisterDIDSigned(chain, params, id);
        else if (m=="createDID")           response=handleCreateDID(chain, params, id);
        else if (m == "tokenmetadisplay") response = handleTokenMetadataDisplay(chain, params, id);
        else if (m == "createTransferTRUScriptTransaction") response = handleCreateTransferTRUScriptTransaction(chain, params, id);
        else if (m == "transferTRUScript") response = handleTransferTRUScript(chain, wallet, params, id);
        else if (m=="getblockcount")       response=handleGetBlockCount(chain,id);
        else if (m=="gettransaction")      response=handleGetTransaction(chain,params,id);
        else if (m=="decoderawtransaction") response=handleDecodeRawTransaction(params,id);
        else if (m=="swaptestexitmempoolaccept") response=handleSwapTestExitMempoolAccept(chain,params,id);
        else if (m=="listtransactions")    response=handleListTransactions(chain,params,id);
        else if (m=="issuetoken")          response=handleIssueToken(chain,wallet,params,id);
        else if (m=="registerminer")       response=handleRegisterMiner(chain,params,id);
        else if (m=="unregisterminer")     response=handleUnregisterMiner(chain,params,id);
        else if (m=="getminerstatus")      response=handleGetMinerStatus(chain,params,id);
        else if (m=="getallminers")        response=handleGetAllMiners(chain,params,id);
        else if (m=="issuetokensigned")    response=handleIssueTokenSigned(chain,params,id);
        else if (m=="verifytokenmetadata") response=handleVerifyTokenMetadata(chain,params,id);
        else if (m=="createcontracttransaction") response=handleCreateContractTransaction(chain,params,id);
        else if (m=="redeemhashlock")      response=handleRedeemHashLock(chain,wallet,params,id);
        else if (m=="redeemtimelock")      response=handleRedeemTimeLock(chain,wallet,params,id);
        else if (m=="getcontracts")        response=handleGetContracts(chain,params,id);
        else if (m=="getrawtransaction")  response=handleGetRawTransaction(chain,params,id);
        else if (m=="gettxout")           response=handleGetTxOut(chain,params,id);
        else if (m == "getTRUScripts") response = handleGetTRUScripts(chain, params, id);
        else if (m == "getTRUScriptDetails") response = handleGetTRUScriptDetails(chain, params, id);
        else if (m=="sendtokenweb")       response=handleSendTokenWeb(chain,params,id);
        else if (m=="getaddresstransactions") response=handleGetAddressTransactions(chain,params,id);
        else if (m=="createsendtokentransaction") response=handleCreateSendTokenTransaction(chain,params,id);
        else if (m=="createburntokentransaction") response=handleCreateBurnTokenTransaction(chain,params,id);
        else if (m=="debugtokentx")       response=handleDebugTokenTx(chain,params,id);
        else if (m=="createtokentransaction") response=handleCreateTokenTransaction(chain,params,id);
        else if (m=="listmempooltransactions") response=handleListMempoolTransactions(chain,params,id);
        else if (m=="verifytokenbalance") response=handleVerifyTokenBalance(chain,params,id);
        else if (m=="createmagiclock")     response=handleCreateMagicLock(chain,wallet,params,id);
        else if (m=="unlockmagiclock")     response=handleUnlockMagicLock(chain,wallet,params,id);
        else if (m=="listmagiclocks")      response=handleListMagicLocks(chain,params,id);
        else if (m=="listaddresses")       response=handleListAddresses(wallet,params,id);
        else if (m=="getbalance")          response=handleGetBalance(chain,wallet,params,id);
        else if (m=="getinfo")             response=handleGetInfo(chain,wallet,node,id);
        else if (m=="configureAIProvider") response=handleConfigureAIProvider(chain, params, id);
        else if (m=="getAIProviders")      response=handleGetAIProviders(chain, params, id);
        else if (m=="createAIToken")       response=handleCreateAIToken(chain, wallet, params, id);
        else if (m=="interactWithAIToken") response=handleInteractWithAIToken(chain, params, id);
        else if (m=="getAIResponse")       response=handleGetAIResponse(chain, params, id);
        else if (m=="getAITokenState")     response=handleGetAITokenState(chain, params, id);
        else if (m=="trainAIToken")        response=handleTrainAIToken(chain, params, id);
        else if (m=="htlcgeneratesecret")    response=handleHtlcGenerateSecret(wallet,params,id);
       else if (m=="htlcpreparefunding")    response=handleHtlcPrepareFunding(wallet,params,id);
       else if (m=="htlcpreparedstatus")     response=handleHtlcPreparedStatus(wallet,params,id);
       else if (m=="htlcpreparedrelease")    response=handleHtlcPreparedRelease(wallet,params,id);
       else if (m=="htlcbroadcastprepared")  response=handleHtlcBroadcastPrepared(wallet,params,id);
       else if (m=="htlccreate")            response=handleHtlcCreate(wallet,params,id);
       else if (m=="htlcclaim")             response=handleHtlcClaim(wallet,params,id);
       else if (m=="htlcrefund")            response=handleHtlcRefund(wallet,params,id);
       else if (m=="swaprecordcreate")      response=handleSwapRecordCreate(chain,params,id);
       else if (m=="swaprecordget")         response=handleSwapRecordGet(chain,params,id);
       else if (m=="swaprecordlist")        response=handleSwapRecordList(chain,params,id);
       else if (m=="swaprecordtransition")  response=handleSwapRecordTransition(chain,params,id);
       else if (m=="swapwalletfreshkeys")    response=handleSwapWalletFreshKeys(wallet,params,id);
       else if (m=="swapwalletfreshselfproof") response=handleSwapWalletFreshSelfProof(wallet,params,id);
        else if (m=="swapwalletrolekeys")     response=handleSwapWalletRoleKeys(wallet,params,id);
        else response=makeError(-32601,"Method not found");
        res.set_content(response.dump(2),"application/json");
    });
    g_rpcServer.Get("/rpc",[](auto&,auto &res){res.status=405;res.set_header("Allow","POST");res.set_content("{\"error\":\"POST with RPC authentication required\"}\n","application/json");});
    Logger::log("[RPC] Patch 05 transport authentication REQUIRED");
    Logger::log("[RPC] Direct browser/CORS access DISABLED");
    Logger::log("[RPC] Worker threads="+std::to_string(workers)+", queued requests max="+std::to_string(workers*2U));
    Logger::log("[RPC] Listening on "+bindIP+":"+std::to_string(port));
    g_rpcServer.listen(bindIP.c_str(), port);
}
