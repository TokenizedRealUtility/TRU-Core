#pragma once
#ifndef TOKENS_H
#define TOKENS_H

#include <string>
#include <unordered_map>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include "leveldb_storage.h"
#include <optional>
#include <shared_mutex>

class LevelDBStorage;
class Blockchain;

enum class TokenType {
    NONE = 0,
    FT,
    NFT,
    SFT,
    NCFT,
    TRUSCRIPT
};

struct TRUScriptInfo {
    std::string txid;
    std::string data;
    uint64_t inscriptionIndex = 0;   // the “#94,883,028” style index
    uint64_t satNumber        = 0;   // the TRU atom offset
    uint64_t timestamp        = 0;   // when this was inscribed (unix secs)
    size_t   sizeBytes        = 0;
    std::string owner;
    uint32_t height = 0;
    std::string contentType = "text/plain";
    nlohmann::json metadata;
};

std::string tokenTypeToString(TokenType t);
TokenType stringToTokenType(const std::string &s);

struct TokenMeta {
    nlohmann::json data;
};

inline void to_json(nlohmann::json& j, const TokenMeta& meta) {
    j = meta.data;
}

inline void from_json(const nlohmann::json& j, TokenMeta& meta) {
    meta.data = j;
}

struct ExtendedTokenData {
    std::string tokenID;
    TokenType type;
    uint64_t amount;
    uint32_t version;
    TokenMeta meta;
    std::string metaHash;
    std::string offChainMetadata;
    std::string metadataSignature;
};

inline void to_json(nlohmann::json& j, const ExtendedTokenData& d) {
    j["tokenID"] = d.tokenID;
    j["type"] = tokenTypeToString(d.type);
    j["amount"] = d.amount;
    j["version"] = d.version;
    j["meta"] = d.meta;
    j["offChainMetadata"] = d.offChainMetadata;
    j["metadataSignature"] = d.metadataSignature;
}

inline void from_json(const nlohmann::json& j, ExtendedTokenData& d) {
    d.tokenID = j.at("tokenID").get<std::string>();
    d.type = stringToTokenType(j.at("type").get<std::string>());
    d.amount = j.at("amount").get<uint64_t>();
    d.version = j.contains("version") ? j.at("version").get<uint32_t>() : 1;
    d.meta = j.at("meta").get<TokenMeta>();
    d.offChainMetadata = j.at("offChainMetadata").get<std::string>();
    d.metadataSignature = j.at("metadataSignature").get<std::string>();
}

nlohmann::json extendedTokenDataToJson(const ExtendedTokenData &d);
std::string buildTokenIssueScript_OPRETURN(const ExtendedTokenData &data, const std::string &ownerAddress);
std::string buildExtendedTokenScript(const ExtendedTokenData &data);
/// Build an OP_RETURN script for a TRUSCRIPT (ordinal-like inscription)
std::string buildTRUScript_OPRETURN(const std::string& text,const std::string& owner,uint64_t inscriptionIndex,uint64_t satNumber,uint64_t timestamp);

bool parseExtendedTokenScript(const std::string& scriptPubKeyHex, const std::string& txid, ExtendedTokenData& td, std::string& ownerAddress, const Blockchain* blockchainPtr);
std::string extractAddressFromScriptPubKey(const std::string& scriptPubKeyHex, const std::string& txid, uint32_t vout, const Blockchain* blockchainPtr);
std::string extractTokenOwner(const std::string &script);
bool startsWithOpReturnHex(const std::string &scriptPubKeyHex);
std::string createExtendedTokenScriptPubKeyHex(const ExtendedTokenData &data, const std::string &ownerAddress);
std::string asciiToHex(const std::string &input);
std::string generateMetaHash(const nlohmann::json& meta);

bool storeUTXO(LevelDBStorage* storage, const std::string& txid, uint32_t vout, const std::string& address, const std::string& value, leveldb::WriteBatch* batch = nullptr);
bool getUTXOsForAddress(LevelDBStorage* storage, const std::string& address, std::vector<std::string>& utxos, int currentBlockHeight);
bool storeTokenOwnership(LevelDBStorage* storage, const std::string& hashedTokenID, const std::string& ownerAddress, uint64_t amount, const std::string& txid, leveldb::WriteBatch* batch = nullptr);
std::optional<uint64_t> getTokenOwnership(const LevelDBStorage* storage, const std::string& tokenID, const std::string& address);
bool updateTokenOwnership(LevelDBStorage* storage, const std::string& hashedTokenID, const std::string& fromAddress, const std::string& toAddress, uint64_t quantity);
void invalidateUTXOCacheForAddress(const std::string& address); // Added for cache invalidation

extern std::unordered_map<std::string, std::vector<std::pair<std::string, uint64_t>>> utxoCache;
extern std::shared_mutex utxoCacheMutex;
extern int cacheHeight;
bool parseTRUScriptFromOPReturn(const std::string& scriptPubKeyHex, const std::string& txid, nlohmann::json& truScriptData, const Blockchain* blockchainPtr);
void cleanupOrphanedUTXOIndices(LevelDBStorage* storage);
#endif // TOKENS_H

