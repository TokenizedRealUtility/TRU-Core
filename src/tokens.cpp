#include "tokens.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include "logging.h"
#include "address_helpers.h"
#include "leveldb_storage.h"
#include <regex>
#include <algorithm>
#include <cctype>
#include "blockchain.h"
#include "tru_network_params.h"

std::unordered_map<std::string, std::vector<std::pair<std::string, uint64_t>>> utxoCache;
std::shared_mutex utxoCacheMutex;
int cacheHeight = 0;



//==========================================================================================
//   			TRUScripts
//==========================================================================================
std::string buildTRUScript_OPRETURN(const std::string& text, 
                                   const std::string& owner,
                                   uint64_t inscriptionIndex,
                                   uint64_t satNumber,
                                   uint64_t timestamp) {
    // Create a JSON object with all metadata
    nlohmann::json metadata;
    metadata["type"] = "TRUSCRIPT";
    metadata["data"] = text;
    metadata["owner"] = owner;
    metadata["inscriptionIndex"] = inscriptionIndex;
    metadata["satNumber"] = satNumber;
    metadata["timestamp"] = timestamp;
    
    // Convert JSON to string
    std::string jsonStr = metadata.dump();
    
    // Convert to hex
    std::string dataHex;
    for (unsigned char c : jsonStr) {
        char buf[3];
        sprintf(buf, "%02x", c);
        dataHex += buf;
    }
    
    // Build OP_RETURN script
    // Format: OP_RETURN <length> <data>
    size_t dataLen = dataHex.length() / 2;
    std::string lenHex;
    
    if (dataLen <= 75) {
        // Direct push
        char buf[3];
        sprintf(buf, "%02x", (unsigned int)dataLen);
        lenHex = buf;
    } else if (dataLen <= 255) {
        // OP_PUSHDATA1
        lenHex = "4c";
        char buf[3];
        sprintf(buf, "%02x", (unsigned int)dataLen);
        lenHex += buf;
    } else {
        // OP_PUSHDATA2 (for larger data)
        lenHex = "4d";
        char buf[5];
        sprintf(buf, "%02x%02x", (unsigned int)(dataLen & 0xFF), (unsigned int)(dataLen >> 8));
        lenHex += buf;
    }
    
    return "6a" + lenHex + dataHex;
}

//========================================================================
//
//========================================================================
bool storeUTXO(LevelDBStorage* storage, const std::string& txid, uint32_t vout, const std::string& address, const std::string& value, leveldb::WriteBatch* batch) {
    if (!storage) {
        Logger::log("[storeUTXO] ERROR: storage pointer is null");
        return false;
    }

    const std::string key = "utxo:" + txid + ":" + std::to_string(vout);
    std::string checksum;
    try {
        checksum = storage->computeDataChecksum(value);
    } catch (const std::exception& e) {
        Logger::log(std::string("[storeUTXO] ERROR computing checksum: ") + e.what());
        return false;
    }
    const std::string toStore = checksum + "|" + value;

    try {
        if (batch) {
            batch->Put(key, toStore);
            // Store the index with a checksum for an empty value
            std::string idxKey = "address:" + address + ":utxo:" + txid + ":" + std::to_string(vout);
            std::string idxChecksum = storage->computeDataChecksum("");
            batch->Put(idxKey, idxChecksum + "|");
        } else {
            if (!storage->putWithDataChecksum(key, value)) {
                Logger::log("[storeUTXO] ERROR: putWithDataChecksum failed for key " + key);
                return false;
            }
            std::string idxKey = "address:" + address + ":utxo:" + txid + ":" + std::to_string(vout);
            if (!storage->putWithDataChecksum(idxKey, "")) {
                Logger::log("[storeUTXO] ERROR: putWithDataChecksum failed for address index " + idxKey);
                return false;
            }
        }
    } catch (const std::exception& e) {
        Logger::log(std::string("[storeUTXO] EXCEPTION: ") + e.what());
        return false;
    }

    invalidateUTXOCacheForAddress(address);
    return true;
}
//=================================================================================
//				GET UTXO FOR ADDRESS
//================================================================================
bool getUTXOsForAddress(LevelDBStorage* storage, const std::string& address, std::vector<std::string>& utxos, int currentBlockHeight) {
    utxos.clear();
    if (!storage) {
        Logger::log("[getUTXOsForAddress] ERROR: storage pointer is null");
        return false;
    }

    {
        std::shared_lock lock(utxoCacheMutex);
        auto it = utxoCache.find(address);
        if (it != utxoCache.end() && cacheHeight == currentBlockHeight) {
            for (auto& [id, amt] : it->second) {
                utxos.push_back(id + ":" + std::to_string(amt));
            }
            return true;
        }
    }

    std::vector<std::pair<std::string, uint64_t>> newCache;
    std::vector<std::string> results;
    const std::string prefix = "address:" + address + ":utxo:";

    try {
        storage->iteratePrefix(prefix, [&](const std::string& key, const std::string&) {
            std::string utxoId = key; // Fix: Use key directly as it is already <txid>:<vout>
            Logger::log("[getUTXOsForAddress] Processing UTXO index key: " + prefix + key + ", utxoId: " + utxoId);
            std::string raw;
            std::string fullKey = "utxo:" + utxoId;
            Logger::log("[getUTXOsForAddress] Attempting to retrieve UTXO key: " + fullKey);
            if (!storage->getWithDataChecksum(fullKey, raw)) {
                Logger::log("[getUTXOsForAddress] WARNING: missing UTXO data for " + fullKey);
                return;
            }
            auto p1 = raw.find('|');
            auto p2 = raw.find('|', p1 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos) {
                Logger::log("[getUTXOsForAddress] WARNING: malformed UTXO data for " + fullKey + ": " + raw);
                return;
            }
            // parse the amount defensively per-record. A single
            // malformed record must NOT throw out of the whole scan (which would
            // make the entire address enumerate nothing and show a 0 balance).
            uint64_t amt = 0;
            {
                const std::string amtStr = raw.substr(p1 + 1, p2 - p1 - 1);
                if (amtStr.empty() ||
                    amtStr.find_first_not_of("0123456789") != std::string::npos) {
                    Logger::log("[getUTXOsForAddress] WARNING: non-numeric amount in "
                                + fullKey + " (\"" + amtStr + "\"); skipping record");
                    return; // skip THIS record only, keep scanning the rest
                }
                try {
                    amt = std::stoull(amtStr);
                } catch (const std::exception& e) {
                    Logger::log("[getUTXOsForAddress] WARNING: bad amount in " + fullKey
                                + " (" + std::string(e.what()) + "); skipping record");
                    return; // skip THIS record only
                }
            }
            newCache.emplace_back(utxoId, amt);
            results.push_back(utxoId + ":" + std::to_string(amt));
        });
    } catch (const std::exception& e) {
        Logger::log(std::string("[getUTXOsForAddress] EXCEPTION: ") + e.what());
        return false;
    }

    {
        std::unique_lock lock(utxoCacheMutex);
        utxoCache[address] = newCache;
        cacheHeight = currentBlockHeight;
    }
    utxos.swap(results);
    return true;
}
//================================================================================
//================================================================================
bool storeTokenOwnership(LevelDBStorage* storage, const std::string& hashedTokenID, const std::string& ownerAddress, uint64_t amount, const std::string& txid, leveldb::WriteBatch* batch) {
    if (!storage) {
        Logger::log("[storeTokenOwnership] ERROR: storage pointer is null");
        return false;
    }
    if (hashedTokenID.size() != 64 || !std::all_of(hashedTokenID.begin(), hashedTokenID.end(), ::isxdigit)) {
        Logger::log("[storeTokenOwnership] ERROR: invalid hashedTokenID");
        return false;
    }
    if (ownerAddress.empty()) {
        Logger::log("[storeTokenOwnership] ERROR: ownerAddress is empty");
        return false;
    }
    if (amount == 0) {
        Logger::log("[storeTokenOwnership] ERROR: amount must be > 0");
        return false;
    }

    // TOKEN-AI-01B2: canonical ownership namespace is 64-bit / 16 hex.
    const std::string truncated = hashedTokenID.substr(0, 16);
    const std::string key = "tokenOwnership:" + ownerAddress + ":" + truncated;
    nlohmann::json j = {{"amount", amount}, {"txid", txid}};
    const std::string val = j.dump();

    try {
        if (batch) {
            batch->Put(key, val);
        } else {
            leveldb::WriteBatch b;
            b.Put(key, val);
            if (!storage->putBatch(b)) {
                Logger::log("[storeTokenOwnership] ERROR: batch write failed");
                return false;
            }
        }
    } catch (const std::exception& e) {
        Logger::log(std::string("[storeTokenOwnership] EXCEPTION: ") + e.what());
        return false;
    }

    return true;
}

std::optional<uint64_t> getTokenOwnership(const LevelDBStorage* storage, const std::string& tokenID, const std::string& address) {
    if (!storage) return std::nullopt;

    std::string truncated = tokenID;
    if (tokenID.size() == 64) truncated = tokenID.substr(0, 16);
    if (!((truncated.size() == 8 || truncated.size() == 16) &&
          std::all_of(truncated.begin(), truncated.end(), [](unsigned char c) {
              return std::isxdigit(c) != 0;
          }))) {
        Logger::log("[getTokenOwnership] Invalid tokenID namespace width");
        return std::nullopt;
    }
    const std::string key = "tokenOwnership:" + address + ":" + truncated;

    std::string raw;
    if (!storage->getWithDataChecksum(key, raw)) {
        Logger::log("[getTokenOwnership] No record for key: " + key);
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(raw);
        if (!j.contains("amount") || !j["amount"].is_number_unsigned()) {
            Logger::log("[getTokenOwnership] Malformed JSON for key: " + key);
            return std::nullopt;
        }
        return j["amount"].get<uint64_t>();
    } catch (const std::exception& e) {
        Logger::log(std::string("[getTokenOwnership] JSON parse error: ") + e.what());
        return std::nullopt;
    }
}

bool updateTokenOwnership(LevelDBStorage* storage, const std::string& hashedTokenID, const std::string& fromAddress, const std::string& toAddress, uint64_t quantity) {
    if (!storage) {
        Logger::log("[updateTokenOwnership] ERROR: storage pointer is null");
        return false;
    }
    if (hashedTokenID.size() != 64) {
        Logger::log("[updateTokenOwnership] ERROR: invalid hashedTokenID");
        return false;
    }

    // TOKEN-AI-01B2: canonical ownership namespace is 64-bit / 16 hex.
    const std::string tid = hashedTokenID.substr(0, 16);
    const std::string fromKey = "tokenOwnership:" + fromAddress + ":" + tid;
    const std::string toKey = "tokenOwnership:" + toAddress + ":" + tid;

    std::string rawFrom;
    if (!storage->getWithDataChecksum(fromKey, rawFrom)) {
        Logger::log("[updateTokenOwnership] No ownership found at: " + fromKey);
        return false;
    }
    nlohmann::json jf;
    try { jf = nlohmann::json::parse(rawFrom); }
    catch (...) {
        Logger::log("[updateTokenOwnership] JSON parse error for fromKey");
        return false;
    }
    uint64_t have = jf.value("amount", 0ULL);
    if (have < quantity) {
        Logger::log("[updateTokenOwnership] Insufficient balance: have=" + std::to_string(have) + ", need=" + std::to_string(quantity));
        return false;
    }

    // AUDIT-REMEDIATION-01 / Track 02:
    // A self-transfer must preserve the already-confirmed ownership amount.
    // Returning success here preserves historical transaction acceptance while
    // preventing two writes to the same LevelDB key from turning quantity into
    // an artificial balance increase.
    if (fromAddress == toAddress) {
        Logger::log("[updateTokenOwnership] Self-transfer: ownership unchanged");
        return true;
    }

    leveldb::WriteBatch batch;
    uint64_t rem = have - quantity;
    if (rem > 0) {
        jf["amount"] = rem;
        batch.Put(fromKey, jf.dump());
    } else {
        batch.Delete(fromKey);
    }

    uint64_t newTo = quantity;
    std::string rawTo;
    if (storage->getWithDataChecksum(toKey, rawTo)) {
        try {
            auto jt = nlohmann::json::parse(rawTo);
            newTo += jt.value("amount", 0ULL);
        } catch (...) {
            Logger::log("[updateTokenOwnership] JSON parse error for toKey");
        }
    }
    nlohmann::json jt = {{"amount", newTo}, {"txid", jf["txid"]}};
    batch.Put(toKey, jt.dump());

    if (!storage->putBatch(batch)) {
        Logger::log("[updateTokenOwnership] ERROR: batch write failed");
        return false;
    }
    return true;
}

static void sha256Twice(const unsigned char* data, size_t len, unsigned char out1[32], unsigned char out2[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, len);
    SHA256_Final(out1, &c);
    SHA256_Init(&c);
    SHA256_Update(&c, out1, 32);
    SHA256_Final(out2, &c);
}

std::string extractAddressFromScriptPubKey(const std::string& scriptHex, const std::string& txid, uint32_t vout, const Blockchain* chain) {
    // EXPLORER-MINERS-03: this helper is a hot path for explorer-derived data.
    // Do not synchronously flush two success/debug lines for every address parse.
    // Unknown/exceptional script logging below is retained. This is observational
    // only and changes no script, transaction, block, or consensus semantics.
    if (scriptHex.rfind("6a", 0) == 0) {
        ExtendedTokenData td;
        std::string owner;
        if (parseExtendedTokenScript(scriptHex, txid, td, owner, chain))
            return owner;
        return txid + ":" + std::to_string(vout);
    }

    if (scriptHex.size() == 50 && scriptHex.substr(0, 6) == "76a914" && scriptHex.substr(46) == "88ac") {
        auto hash160 = hexDecode(scriptHex.substr(6, 40));
        std::vector<unsigned char> vh{tru_network::MAINNET_P2PKH_VERSION};
        vh.insert(vh.end(), hash160.begin(), hash160.end());
        unsigned char h1[32], h2[32];
        sha256Twice(vh.data(), vh.size(), h1, h2);
        vh.insert(vh.end(), h2, h2 + 4);
        return base58Encode(vh);
    }

    if (scriptHex.find("b1") != std::string::npos && scriptHex.find("76a914") != std::string::npos) {
        auto pos = scriptHex.find("76a914") + 6;
        auto h = scriptHex.substr(pos, 40);
        return extractAddressFromScriptPubKey("76a914" + h + "88ac", txid, vout, chain);
    }

    static const std::regex scOp("(f7|f8|f9|fa|fb|fc|fd)", std::regex::icase);
    //static const std::regex scOp("{f7|f8|f9|fa|fb|fc|fd}", std::regex::icase);
    if (std::regex_search(scriptHex, scOp))
        return txid + ":" + std::to_string(vout);

    Logger::log("[extract] unknown script");
    return "";
}

bool startsWithOpReturnHex(const std::string &scriptPubKeyHex) {
    return (scriptPubKeyHex.size() >= 2 && scriptPubKeyHex.substr(0, 2) == "6a");
}

std::string asciiToHex(const std::string &input) {
    static const char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2);
    for (unsigned char c : input) {
        out.push_back(HEX[c >> 4]);
        out.push_back(HEX[c & 0xf]);
    }
    return out;
}

std::string tokenTypeToString(TokenType t) {
    switch (t) {
        case TokenType::FT: return "FT";
        case TokenType::NFT: return "NFT";
        case TokenType::SFT: return "SFT";
        case TokenType::NCFT: return "NCFT";
        default: return "NONE";
    }
}

TokenType stringToTokenType(const std::string &s) {
    if (s == "FT") return TokenType::FT;
    if (s == "NFT") return TokenType::NFT;
    if (s == "SFT") return TokenType::SFT;
    if (s == "NCFT") return TokenType::NCFT;
    return TokenType::NONE;
}

nlohmann::json extendedTokenDataToJson(const ExtendedTokenData &d) {
    nlohmann::json j;
    j["tokenID"] = d.tokenID;
    j["type"] = tokenTypeToString(d.type);
    j["amount"] = d.amount;
    j["version"] = d.version;
    j["meta"] = d.meta.data;
    j["offChainMetadata"] = d.offChainMetadata;
    j["metadataSignature"] = d.metadataSignature;
    return j;
}

std::string buildTokenIssueScript_OPRETURN(const ExtendedTokenData &data, const std::string &ownerAddress) {
    nlohmann::json j;
    j["token"] = extendedTokenDataToJson(data);
    j["owner"] = ownerAddress;
    std::string asciiData = j.dump();
    std::string prefixedData = "TOKENISSUE|" + asciiData;
    std::string hexData = asciiToHex(prefixedData);
    return "OP_RETURN " + hexData;
}

std::string buildExtendedTokenScript(const ExtendedTokenData& data) {
    std::ostringstream oss;
    oss << tokenTypeToString(data.type) << "|" << data.tokenID << "|" << data.amount;

    if (!data.meta.data.is_null() && data.meta.data.is_object()) {
        std::vector<std::string> keys;
        for (const auto& item : data.meta.data.items()) {
            keys.push_back(item.key());
        }
        std::sort(keys.begin(), keys.end());

        for (const auto& key : keys) {
            std::string value = data.meta.data[key].is_string() ? data.meta.data[key].get<std::string>() : data.meta.data[key].dump();
            oss << "|" << key << "=" << value;
        }
    }

    oss << "|offChainMetadata=" << data.offChainMetadata << "|metadataSignature=" << data.metadataSignature;
    return oss.str();
}

std::string extractTokenOwner(const std::string &script) {
    size_t pos = script.rfind('|');
    if (pos == std::string::npos || pos + 1 >= script.size()) {
        std::cerr << "[extractTokenOwner] Could not find owner in script: " << script << std::endl;
        return "";
    }
    return script.substr(pos + 1);
}

void invalidateUTXOCacheForAddress(const std::string& address) {
    std::unique_lock lock(utxoCacheMutex);
    utxoCache.erase(address);
    Logger::log("[invalidateUTXOCacheForAddress] Cache invalidated for address: " + address);
}

std::string createExtendedTokenScriptPubKeyHex(const ExtendedTokenData& data, const std::string& ownerAddress) {
    Logger::log("[createExtendedTokenScriptPubKeyHex] Building binary script => owner=" + ownerAddress);

    if (ownerAddress.empty() || data.tokenID.empty()) {
        throw std::invalid_argument("Owner address and token ID must not be empty");
    }

    std::vector<unsigned char> raw;
    raw.push_back(static_cast<unsigned char>(data.type));

    // TOKEN-AI-01B2: new canonical token IDs are 8 bytes / 16 hex.
    // Keep the 4-byte / 8-hex form readable/writable only for existing
    // development-chain tokens so the current chain does not need a reset.
    if (!((data.tokenID.size() == 16 || data.tokenID.size() == 8) &&
          std::all_of(data.tokenID.begin(), data.tokenID.end(), [](unsigned char c) {
              return std::isxdigit(c) != 0;
          }))) {
        throw std::invalid_argument(
            "Invalid token ID length: expected canonical 16 hex or legacy 8 hex");
    }
    std::vector<unsigned char> tokenIdBytes = hexDecode(data.tokenID);
    if (tokenIdBytes.size() != 8 && tokenIdBytes.size() != 4) {
        throw std::invalid_argument("Invalid token ID byte width");
    }
    raw.insert(raw.end(), tokenIdBytes.begin(), tokenIdBytes.end());

    uint64_t amount = data.amount;
    for (int i = 7; i >= 0; --i) {
        raw.push_back(static_cast<unsigned char>((amount >> (i * 8)) & 0xFF));
    }

    std::vector<unsigned char> ownerRaw = base58Decode(ownerAddress);
    if (ownerRaw.size() != 25) {
        throw std::invalid_argument("Invalid owner address");
    }
    std::vector<unsigned char> hash160(ownerRaw.begin() + 1, ownerRaw.begin() + 21);
    raw.insert(raw.end(), hash160.begin(), hash160.end());

    std::string metaHash = generateMetaHash(data.meta.data);
    std::vector<unsigned char> metaBytes = hexDecode(metaHash);
    if (metaBytes.size() != 32) {
        throw std::invalid_argument("Invalid meta hash length");
    }
    raw.insert(raw.end(), metaBytes.begin(), metaBytes.end());

    std::string hexEncoded = bytesToHex(raw);
    if (hexEncoded.size() > 160) {
        Logger::log("[createExtendedTokenScriptPubKeyHex] ERROR: Hex data exceeds 80 bytes: " + std::to_string(hexEncoded.size()));
        throw std::runtime_error("Token data exceeds OP_RETURN size limit");
    }

    return "6a" + hexEncoded;
}


std::string generateMetaHash(const nlohmann::json& meta) {
    try {
        Logger::log("[generateMetaHash] TOKEN-AI-01C canonical metadata hash");

        // TOKEN-AI-01C canonical metadata domain:
        //   * object only
        //   * top-level keys are restricted to portable ASCII metadata names
        //   * values are strings only (no lossy object/array/number coercion)
        //   * the derived metaHash field is excluded from its own preimage
        //   * keys are lexicographically sorted before compact JSON serialization
        //   * even an empty object hashes the exact bytes "{}"
        if (meta.is_null() || !meta.is_object()) {
            throw std::invalid_argument("metadata must be a JSON object");
        }

        auto canonicalKey = [](const std::string& key) {
            if (key.empty() || key.size() > 64U) return false;
            for (unsigned char c : key) {
                const bool ok =
                    (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '_' || c == '-' || c == '.' || c == ':';
                if (!ok) return false;
            }
            return true;
        };

        std::vector<std::string> keys;
        for (const auto& item : meta.items()) {
            if (item.key() == "metaHash") continue;
            if (!canonicalKey(item.key())) {
                throw std::invalid_argument(
                    "invalid metadata key for canonical hash: " + item.key());
            }
            if (!item.value().is_string()) {
                throw std::invalid_argument(
                    "metadata value must be a string for key: " + item.key());
            }
            keys.push_back(item.key());
        }
        std::sort(keys.begin(), keys.end());

        nlohmann::json sortedMeta = nlohmann::json::object();
        for (const auto& key : keys) {
            sortedMeta[key] = meta.at(key).get<std::string>();
        }

        const std::string metaStr = sortedMeta.dump();
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(metaStr.data()), metaStr.size(), hash);

        const std::string result =
            bytesToHex(std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH));
        Logger::log("[generateMetaHash] Generated canonical hash: " + result);
        return result;
    } catch (const std::exception& e) {
        Logger::log("[generateMetaHash] Error: " + std::string(e.what()));
        throw std::runtime_error(
            "[generateMetaHash] Failed to generate canonical hash: " + std::string(e.what()));
    }
}

bool parseExtendedTokenScript(const std::string& scriptPubKeyHex, const std::string& txid, 
                             ExtendedTokenData& tokenData, std::string& ownerAddress, 
                             const Blockchain* blockchainPtr) {
    Logger logger;
    logger.log("[parseExtendedTokenScript] Parsing scriptPubKey=" + scriptPubKeyHex + ", txid=" + txid);

    // Check if it's an OP_RETURN script
    if (scriptPubKeyHex.size() < 2 || scriptPubKeyHex.substr(0, 2) != "6a") {
        logger.log("[parseExtendedTokenScript] Not an OP_RETURN script");
        return false;
    }

    // First, try to parse as TRUScript JSON
    try {
        std::string dataHex = scriptPubKeyHex.substr(2);
        
        // Parse length encoding
        size_t dataStart = 0;
        size_t dataLen = 0;
        
        if (dataHex.length() >= 2) {
            uint8_t lenByte = std::stoul(dataHex.substr(0, 2), nullptr, 16);
            
            if (lenByte <= 75) {
                dataStart = 2;
                dataLen = lenByte;
            } else if (lenByte == 0x4c && dataHex.length() >= 4) {
                dataStart = 4;
                dataLen = std::stoul(dataHex.substr(2, 2), nullptr, 16);
            } else if (lenByte == 0x4d && dataHex.length() >= 6) {
                dataStart = 6;
                uint16_t len = std::stoul(dataHex.substr(2, 2), nullptr, 16) |
                              (std::stoul(dataHex.substr(4, 2), nullptr, 16) << 8);
                dataLen = len;
            }
        }
        
        if (dataStart > 0 && dataLen > 0 && 
            dataHex.length() >= dataStart + (dataLen * 2)) {
            
            std::string actualDataHex = dataHex.substr(dataStart, dataLen * 2);
            
            // Convert hex to string
            std::string dataStr;
            for (size_t i = 0; i < actualDataHex.length(); i += 2) {
                std::string byteStr = actualDataHex.substr(i, 2);
                char byte = static_cast<char>(std::stoul(byteStr, nullptr, 16));
                dataStr += byte;
            }
            
            // Try to parse as JSON
            try {
                nlohmann::json parsedData = nlohmann::json::parse(dataStr);
                
                // Check if it's a TRUScript or TRUScript transfer
                if (parsedData.contains("type") && 
                    (parsedData["type"] == "TRUSCRIPT" || parsedData["type"] == "TRUSCRIPT_TRANSFER")) {
                    logger.log("[parseExtendedTokenScript] Found TRUScript JSON, not an extended token");
                    return false; // Not an extended token, it's a TRUScript
                }
            } catch (const nlohmann::json::parse_error& e) {
                // Not JSON, continue to parse as binary token
            }
        }
    } catch (const std::exception& e) {
        logger.log("[parseExtendedTokenScript] Error checking for TRUScript: " + std::string(e.what()));
    }

    // Now parse as binary extended token format. TOKEN-AI-01B2 defines
    // 69 bytes as canonical V2 (8-byte / 16-hex token ID) while retaining
    // exact 65-byte legacy V1 parsing for the existing development chain.
    std::string dataHex = scriptPubKeyHex.substr(2);
    std::vector<unsigned char> raw = hexDecode(dataHex);
    const bool tokenIdV2 = (raw.size() == 69U);
    const bool tokenIdV1Legacy = (raw.size() == 65U);
    if (!tokenIdV2 && !tokenIdV1Legacy) {
        logger.log("[parseExtendedTokenScript] Invalid extended-token binary size: " +
                   std::to_string(raw.size()) + " bytes (expected 69 canonical or 65 legacy)");
        return false;
    }
    const size_t tokenIdBytesLen = tokenIdV2 ? 8U : 4U;
    const size_t amountOffset = 1U + tokenIdBytesLen;
    const size_t ownerOffset = amountOffset + 8U;
    const size_t metaOffset = ownerOffset + 20U;

    // Parse token type
    tokenData.type = static_cast<TokenType>(raw[0]);
    if (tokenData.type != TokenType::FT && tokenData.type != TokenType::NFT && 
        tokenData.type != TokenType::SFT && tokenData.type != TokenType::NCFT) {
        logger.log("[parseExtendedTokenScript] Invalid token type: " + std::to_string(static_cast<int>(tokenData.type)));
        return false;
    }
    logger.log("[parseExtendedTokenScript] Token type: " + tokenTypeToString(tokenData.type));

    // Parse token ID (8 bytes canonical; 4 bytes legacy).
    std::vector<unsigned char> tokenIDBytes(
        raw.begin() + 1, raw.begin() + 1 + tokenIdBytesLen);
    tokenData.tokenID = bytesToHex(tokenIDBytes);
    logger.log("[parseExtendedTokenScript] Token ID: " + tokenData.tokenID +
               (tokenIdV2 ? " (64-bit canonical)" : " (32-bit legacy)"));

    // Parse amount (8 bytes).
    tokenData.amount = 0;
    for (size_t i = 0; i < 8U; ++i) {
        tokenData.amount = (tokenData.amount << 8) | raw[amountOffset + i];
    }
    logger.log("[parseExtendedTokenScript] Amount: " + std::to_string(tokenData.amount));

    // Extract owner address from hash160 (20 bytes).
    std::vector<unsigned char> hash160(
        raw.begin() + ownerOffset, raw.begin() + ownerOffset + 20U);
    std::vector<unsigned char> verHash = {tru_network::MAINNET_P2PKH_VERSION};
    verHash.insert(verHash.end(), hash160.begin(), hash160.end());
    unsigned char hash1[32], hash2[32];
    SHA256(verHash.data(), verHash.size(), hash1);
    SHA256(hash1, 32, hash2);
    verHash.insert(verHash.end(), hash2, hash2 + 4);
    ownerAddress = base58Encode(verHash);
    logger.log("[parseExtendedTokenScript] Owner address: " + ownerAddress);

    // Extract meta hash (32 bytes).
    std::vector<unsigned char> metaHashBytes(
        raw.begin() + metaOffset, raw.begin() + metaOffset + 32U);
    std::string metaHash = bytesToHex(metaHashBytes);
    logger.log("[parseExtendedTokenScript] Meta hash: " + metaHash);

    // Fetch and process metadata if blockchain pointer is available
    if (blockchainPtr) {
        try {
            std::string metaKey = "tokenMetadata:" + txid;
            ExtendedTokenData fetchedData = blockchainPtr->fetchTokenMetadata(metaKey);
            tokenData.meta = fetchedData.meta;

            // Validate tokenID and type consistency
            if (fetchedData.tokenID != tokenData.tokenID || fetchedData.type != tokenData.type) {
                logger.log("[parseExtendedTokenScript] Warning: Metadata mismatch for tokenID or type");
            }

            logger.log("[parseExtendedTokenScript] Fetched metadata with fields");
        } catch (const std::exception& e) {
            logger.log("[parseExtendedTokenScript] Warning: Failed to fetch metadata for txid=" + txid + ": " + e.what());
            tokenData.meta.data = nlohmann::json::object();
            tokenData.meta.data["name"] = "Token_" + tokenData.tokenID;
            tokenData.meta.data["description"] = "No metadata recorded";
        }
    } else {
        logger.log("[parseExtendedTokenScript] Warning: Blockchain pointer is null, skipping metadata fetch");
        tokenData.meta.data = nlohmann::json::object();
        tokenData.meta.data["name"] = "Token_" + tokenData.tokenID;
        tokenData.meta.data["description"] = "No metadata recorded";
    }

    return true;
}

// Token helper.
bool parseTRUScriptFromOPReturn(const std::string& scriptPubKeyHex, const std::string& txid,
                               nlohmann::json& truScriptData, const Blockchain* blockchainPtr) {
    Logger logger;
    logger.log("[parseTRUScriptFromOPReturn] Parsing scriptPubKey=" + scriptPubKeyHex);
    
    if (scriptPubKeyHex.size() < 2 || scriptPubKeyHex.substr(0, 2) != "6a") {
        return false;
    }
    
    try {
        std::string dataHex = scriptPubKeyHex.substr(2);
        
        // Parse length encoding
        size_t dataStart = 0;
        size_t dataLen = 0;
        
        if (dataHex.length() >= 2) {
            uint8_t lenByte = std::stoul(dataHex.substr(0, 2), nullptr, 16);
            
            if (lenByte <= 75) {
                dataStart = 2;
                dataLen = lenByte;
            } else if (lenByte == 0x4c && dataHex.length() >= 4) {
                dataStart = 4;
                dataLen = std::stoul(dataHex.substr(2, 2), nullptr, 16);
            } else if (lenByte == 0x4d && dataHex.length() >= 6) {
                dataStart = 6;
                uint16_t len = std::stoul(dataHex.substr(2, 2), nullptr, 16) |
                              (std::stoul(dataHex.substr(4, 2), nullptr, 16) << 8);
                dataLen = len;
            }
        }
        
        if (dataStart > 0 && dataLen > 0 && 
            dataHex.length() >= dataStart + (dataLen * 2)) {
            
            std::string actualDataHex = dataHex.substr(dataStart, dataLen * 2);
            
            // Convert hex to string
            std::string dataStr;
            for (size_t i = 0; i < actualDataHex.length(); i += 2) {
                std::string byteStr = actualDataHex.substr(i, 2);
                char byte = static_cast<char>(std::stoul(byteStr, nullptr, 16));
                dataStr += byte;
            }
            
            // Parse as JSON
            truScriptData = nlohmann::json::parse(dataStr);
            
            // Check if it's a TRUScript type
            if (truScriptData.contains("type") && 
                (truScriptData["type"] == "TRUSCRIPT" || truScriptData["type"] == "TRUSCRIPT_TRANSFER")) {
                logger.log("[parseTRUScriptFromOPReturn] Successfully parsed TRUScript JSON");
                return true;
            }
        }
    } catch (const std::exception& e) {
        logger.log("[parseTRUScriptFromOPReturn] Error: " + std::string(e.what()));
    }
    
    return false;
}

void cleanupOrphanedUTXOIndices(LevelDBStorage* storage) {
    if (!storage) return;
    
    std::vector<std::string> toDelete;
    std::string prefix = "address:";
    
    storage->iteratePrefix(prefix, [&](const std::string& key, const std::string& value) {
        // Check if this is a UTXO index entry
        if (key.find(":utxo:") == std::string::npos) return;
        
        // Extract the UTXO ID
        size_t utxoStart = key.find(":utxo:");
        if (utxoStart == std::string::npos) return;
        
        std::string utxoId = key.substr(utxoStart + 6);
        std::string utxoKey = "utxo:" + utxoId;
        
        // Check if the actual UTXO exists
        std::string dummy;
        if (!storage->getWithDataChecksum(utxoKey, dummy)) {
            // UTXO doesn't exist, mark index for deletion
            toDelete.push_back(key);
            Logger::log("[cleanupOrphanedUTXOIndices] Marking orphaned index for deletion: " + key);
        }
    });
    
    // Delete orphaned indices
    for (const auto& key : toDelete) {
        storage->del(key);
    }
    
    Logger::log("[cleanupOrphanedUTXOIndices] Cleaned up " + std::to_string(toDelete.size()) + " orphaned indices");
}
