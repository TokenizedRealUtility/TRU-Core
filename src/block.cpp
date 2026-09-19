#include "block.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include "logging.h"
#include "tokens.h"
#include "address_helpers.h"
#include "message.pb.h"
#include <nlohmann/json.hpp>
#include "tokens.h"

// zero-knowledge stub:
bool verifyZeroKnowledgeProof(const Transaction &tx)
{
#ifdef HAS_ZKPROOF
    if(tx.isCoinbase) {
        // Placeholder: coinbase zero-knowledge verification is not implemented.
    }
    // Placeholder: this function does not verify a zero-knowledge proof.
    return true;
#else
    return true; // default stub
#endif
}


// --------------------------------------------------
// Reverse 64-hex-chars -> 32 bytes in LE
// --------------------------------------------------
static bool hexToLE32(const std::string &hexStr, unsigned char out[32])
{
    if (hexStr.size() != 64) return false;

    unsigned char temp[32];
    // parse big-end from the 64-hex
    for (int i = 0; i < 32; i++) {
        unsigned int val=0;
        if (sscanf(hexStr.substr(i*2, 2).c_str(), "%02x", &val) != 1) {
            return false;
        }
        temp[i] = (unsigned char)val;
    }
    // reverse => out
    for (int i = 0; i < 32; i++) {
        out[i] = temp[31 - i];
    }
    return true;
}

//===================================================================
//			TO PROTO - NEW METHOD
//==================================================================
void Block::toProto(blockchain::BlockProto& proto) const {
    proto.set_hash(this->blockHash);
    proto.set_height(this->height);
    proto.set_chain_work(this->chainWork);
    proto.set_header(this->header.serialize());
    
    // Clear existing transactions
    proto.clear_transactions();
    
    // Serialize each transaction
    for (const auto& tx : this->transactions) {
        proto.add_transactions(tx.serialize());
    }
    
    proto.set_token_metadata(serializeMetadata());
    Logger::log("[Block::toProto] Serialized block with " + std::to_string(this->transactions.size()) + " transactions");
}

//===================================================================
//			FROM PROTO
//==================================================================
void Block::fromProto(const ::blockchain::BlockProto& proto) {
    // Validate and set blockHash
    if (proto.hash().empty()) {
        Logger::log("[Block::fromProto] Error: BlockProto hash is empty");
        throw std::runtime_error("BlockProto hash is empty");
    }
    this->blockHash = proto.hash();
    Logger::log("[Block::fromProto] Set blockHash: " + this->blockHash);

    // Validate and deserialize header
    std::string headerData = proto.header();
    if (headerData.empty()) {
        Logger::log("[Block::fromProto] Error: BlockProto header is empty");
        throw std::runtime_error("BlockProto header is empty");
    }
    try {
        this->header = BlockHeader::deserialize(headerData);
        Logger::log("[Block::fromProto] Header deserialized - version=" + std::to_string(this->header.version) +
                    ", prevHash=" + this->header.prevHash +
                    ", merkleRoot=" + this->header.merkleRoot +
                    ", timestamp=" + std::to_string(this->header.timestamp) +
                    ", bits=" + std::to_string(this->header.bits) +
                    ", nonce=" + std::to_string(this->header.nonce));
    } catch (const std::exception& e) {
        Logger::log("[Block::fromProto] Error deserializing header: " + std::string(e.what()));
        throw;
    }

    // Validate header fields
    if (this->header.prevHash.empty() || this->header.merkleRoot.empty()) {
        Logger::log("[Block::fromProto] Error: Invalid header fields - prevHash=" + this->header.prevHash +
                    ", merkleRoot=" + this->header.merkleRoot);
        throw std::runtime_error("Invalid header fields after deserialization");
    }

    // Set parentHash from header
    this->parentHash = this->header.prevHash;
    Logger::log("[Block::fromProto] Set parentHash: " + this->parentHash);

    // Populate transactions
    this->transactions.clear();
    for (int i = 0; i < proto.transactions_size(); ++i) {
        std::string txData = proto.transactions(i);
        if (txData.empty()) {
            Logger::log("[Block::fromProto] Warning: Empty transaction data at index " + std::to_string(i) + ", skipping");
            continue;
        }
        
        try {
            Logger::log("[Block::fromProto] Deserializing transaction " + std::to_string(i) + ", data length: " + std::to_string(txData.length()));
            Logger::log("[Block::fromProto] Transaction data preview: " + txData.substr(0, std::min(txData.length(), size_t(100))));
            
            Transaction tx = Transaction::deserialize(txData);
            this->transactions.push_back(tx);
            Logger::log("[Block::fromProto] Added transaction " + tx.txid + " at index " + std::to_string(i));
        } catch (const std::exception& e) {
            Logger::log("[Block::fromProto] Error deserializing transaction at index " + std::to_string(i) + ": " + e.what());
            Logger::log("[Block::fromProto] Transaction data that failed: " + txData);
            throw;
        }
    }

    if (!proto.token_metadata().empty()) {
        deserializeMetadata(proto.token_metadata());
        Logger::log("[Block::fromProto] Loaded token metadata");
    }

    //
    // chainWork is not committed by the block hash and is NOT authoritative.
    // Cumulative work lives only in Blockchain::BlockIndexEntry::chainWork.
    // Never accept a peer-supplied chain_work value.
    this->chainWork = 0;
    Logger::log("[Block::fromProto] Ignored peer chainWork; authoritative value is index-only");

    // Set height
    this->height = proto.height();
    Logger::log("[Block::fromProto] Set height: " + std::to_string(this->height));

    // Set previousBlockTime (default as not in proto)
    this->previousBlockTime = 0;
    Logger::log("[Block::fromProto] Set previousBlockTime to default: 0");

    // Verify hash consistency
    std::string computedHash = this->computeHash();
    if (computedHash != this->blockHash) {
        Logger::log("[Block::fromProto] Error: Hash mismatch after deserialization - computed=" + computedHash +
                    ", expected=" + this->blockHash);
        throw std::runtime_error("Hash mismatch after deserialization");
    }
}
// --------------------------------------------------
// buildBlockHeader80
// --------------------------------------------------
std::vector<unsigned char> buildBlockHeader80(const BlockHeader &hdr) {
    // TRU-LOGGING-01A: this function is on the block-hash/validation hot path.
    // Successful header construction is intentionally silent; malformed header
    // inputs still log immediately below before throwing. This changes logging
    // side effects only, not the canonical 80-byte header.
    std::vector<unsigned char> buf(80, 0);

    // Version (4 bytes, little-endian)
    write32LE(&buf[0], hdr.version);

    // Previous Hash (32 bytes, little-endian)
    unsigned char prevHashBytes[32];
    if (!hexToLE32(hdr.prevHash, prevHashBytes)) {
        Logger::log("[buildBlockHeader80] ERROR: Invalid previous hash: " + hdr.prevHash);
        throw std::runtime_error("Invalid previous hash");
    }
    std::memcpy(&buf[4], prevHashBytes, 32);

    // Merkle Root (32 bytes, little-endian)
    unsigned char merkleRootBytes[32];
    if (!hexToLE32(hdr.merkleRoot, merkleRootBytes)) {
        Logger::log("[buildBlockHeader80] ERROR: Invalid merkle root: " + hdr.merkleRoot);
        throw std::runtime_error("Invalid merkle root");
    }
    std::memcpy(&buf[36], merkleRootBytes, 32);

    // Timestamp (4 bytes, little-endian)
    write32LE(&buf[68], hdr.timestamp);

    // Bits (4 bytes, little-endian)
    write32LE(&buf[72], hdr.bits);

    // Nonce (4 bytes, little-endian)
    write32LE(&buf[76], static_cast<uint32_t>(hdr.nonce));

    return buf;
}

// =============================================================================
// BlockHeader Implementation
// =============================================================================
BlockHeader::BlockHeader()
 : version(0), prevHash(64, '0'), merkleRoot(64, '0'),
   timestamp(0), bits(0), nonce(0)
{}

BlockHeader::BlockHeader(int32_t ver, const std::string &ph,
                         uint32_t ts, uint32_t b)
 : version(ver), prevHash(ph), merkleRoot(64, '0'),
   timestamp(ts), bits(b), nonce(0)
{}

std::string BlockHeader::serializeHeader(const BlockHeader &header, bool includeNonce)
{
    // e.g. => "version|prevHash|merkleRoot|timestamp|bits|nonce" (if includeNonce=true)
    std::ostringstream oss;
    oss << header.version << "|"
        << header.prevHash << "|"
        << header.merkleRoot << "|"
        << header.timestamp << "|"
        << header.bits << "|";
    if (includeNonce) {
        oss << header.nonce;
    }
    return oss.str();
}

std::string BlockHeader::serialize() const
{
    return serializeHeader(*this, true);
}


// static
BlockHeader BlockHeader::deserialize(const std::string &data) {
    BlockHeader h;
    std::istringstream iss(data);
    char delim;

    if (!(iss >> h.version >> delim) || delim != '|') {
        Logger::log("[BlockHeader::deserialize] Error: Missing or invalid version in data: " + data);
        throw std::runtime_error("BlockHeader::deserialize => missing version?");
    }
    if (!std::getline(iss, h.prevHash, '|')) {
        Logger::log("[BlockHeader::deserialize] Error: Missing prevHash in data: " + data);
        throw std::runtime_error("BlockHeader::deserialize => missing prevHash?");
    }
    if (!std::getline(iss, h.merkleRoot, '|')) {
        Logger::log("[BlockHeader::deserialize] Error: Missing merkleRoot in data: " + data);
        throw std::runtime_error("BlockHeader::deserialize => missing merkleRoot?");
    }
    if (!(iss >> h.timestamp >> delim) || delim != '|') {
        Logger::log("[BlockHeader::deserialize] Error: Missing or invalid timestamp in data: " + data);
        throw std::runtime_error("BlockHeader::deserialize => missing timestamp?");
    }
    if (!(iss >> h.bits >> delim) || delim != '|') {
        Logger::log("[BlockHeader::deserialize] Error: Missing or invalid bits in data: " + data);
        throw std::runtime_error("BlockHeader::deserialize => missing bits?");
    }
    if (!(iss >> h.nonce)) {
        h.nonce = 0; // Optional
    }
    Logger::log("[BlockHeader::deserialize] Successfully deserialized header: version=" + std::to_string(h.version));
    return h;
}

// =============================================================================
//                      Block Implementation
// =============================================================================
Block::Block()
 : chainWork(0), parentHash(""), previousBlockTime(0), blockHash(""), height(0)
{}

Block::Block(int height, const std::string& ph, uint32_t ts, uint32_t b)
    : chainWork(0), parentHash(ph), previousBlockTime(0), blockHash(""), height(height) {
    header.version = 1;  // Fixed protocol version
    header.prevHash = ph;
    header.merkleRoot = std::string(64, '0');
    header.timestamp = ts;
    header.bits = b;
    header.nonce = 0;
}

// --------------------------------------------------
//     computeHash => double-SHA256 +21E8 injection
// --------------------------------------------------
std::string Block::computeHash() const {
    // TRU-LOGGING-01A: hash computation is consensus-critical and extremely hot.
    // Do not emit success-path log lines here. The byte/hash computation below
    // is unchanged; only per-hash diagnostic I/O is removed.
    // Build 80-byte header
    std::vector<unsigned char> hdrBytes = buildBlockHeader80(header);
    // First SHA256
    unsigned char h1[32];
    SHA256(hdrBytes.data(), hdrBytes.size(), h1);
    // Second SHA256
    unsigned char h2[32];
    SHA256(h1, 32, h2);
    // Apply 21E8 injection
    uint32_t last32 = (static_cast<uint32_t>(h2[28]) << 24) |
                      (static_cast<uint32_t>(h2[29]) << 16) |
                      (static_cast<uint32_t>(h2[30]) << 8) |
                      static_cast<uint32_t>(h2[31]);
    last32 = (last32 + 0x21E8U) & 0xffffffffU;
    h2[28] = static_cast<unsigned char>((last32 >> 24) & 0xff);
    h2[29] = static_cast<unsigned char>((last32 >> 16) & 0xff);
    h2[30] = static_cast<unsigned char>((last32 >> 8) & 0xff);
    h2[31] = static_cast<unsigned char>(last32 & 0xff);

    // Convert to big-endian hex
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        oss << std::setw(2) << static_cast<int>(h2[i]);
    }
    std::string hash = oss.str();
    return hash;
}

// =============================================================================
//               SERIALIZE
// =============================================================================
std::string Block::serialize() const {
    std::ostringstream oss;
    
    // Serialize header and block metadata
    oss << header.serialize() << "|"
        << blockHash << "|"
        << chainWork << "|"
        << parentHash << "|"
        << height << "|"
        << transactions.size();  // Add transaction count
    
    // Serialize each transaction with length prefix
    for (size_t i = 0; i < transactions.size(); i++) {
        std::string txData = transactions[i].serialize();
        oss << "|" << txData.length() << ":" << txData;
    }
    
    // Add metadata at the end
    std::string metadataStr = serializeMetadata();
    oss << "|METADATA:" << metadataStr.length() << ":" << metadataStr;
    
    return oss.str();
}
// =============================================================================
//              DESERIALIZE
// =============================================================================
Block Block::deserialize(const std::string& data) {
    if (data.empty()) {
        Logger::log("[deserialize] Error: Empty block data received");
        throw std::runtime_error("Empty block data");
    }

    Block block;
    
    // Find positions of first 11 delimiters (header + metadata + tx count)
    std::vector<size_t> delimPositions;
    size_t pos = 0;
    while (delimPositions.size() < 11 && pos < data.length()) {
        pos = data.find('|', pos);
        if (pos == std::string::npos) break;
        delimPositions.push_back(pos);
        pos++;
    }
    
    if (delimPositions.size() < 10) {
        Logger::log("[deserialize] Error: Insufficient block fields");
        throw std::runtime_error("Insufficient block fields");
    }
    
    // Helper functions for safe conversions
    auto safeStoi = [](const std::string& str, const std::string& fieldName) -> int {
        if (str.empty()) {
            throw std::runtime_error("Empty string for " + fieldName);
        }
        try {
            return std::stoi(str);
        } catch (...) {
            throw std::runtime_error("Invalid integer for " + fieldName);
        }
    };
    
    auto safeStoul = [](const std::string& str, const std::string& fieldName) -> unsigned long {
        if (str.empty()) {
            throw std::runtime_error("Empty string for " + fieldName);
        }
        try {
            return std::stoul(str);
        } catch (...) {
            throw std::runtime_error("Invalid unsigned long for " + fieldName);
        }
    };
    
    auto safeStoull = [](const std::string& str, const std::string& fieldName) -> unsigned long long {
        if (str.empty()) {
            throw std::runtime_error("Empty string for " + fieldName);
        }
        try {
            return std::stoull(str);
        } catch (...) {
            throw std::runtime_error("Invalid unsigned long long for " + fieldName);
        }
    };
    
    // Parse header fields
    block.header.version = safeStoi(data.substr(0, delimPositions[0]), "version");
    block.header.prevHash = data.substr(delimPositions[0] + 1, delimPositions[1] - delimPositions[0] - 1);
    block.header.merkleRoot = data.substr(delimPositions[1] + 1, delimPositions[2] - delimPositions[1] - 1);
    block.header.timestamp = safeStoul(data.substr(delimPositions[2] + 1, delimPositions[3] - delimPositions[2] - 1), "timestamp");
    block.header.bits = safeStoul(data.substr(delimPositions[3] + 1, delimPositions[4] - delimPositions[3] - 1), "bits");
    block.header.nonce = safeStoul(data.substr(delimPositions[4] + 1, delimPositions[5] - delimPositions[4] - 1), "nonce");
    block.blockHash = data.substr(delimPositions[5] + 1, delimPositions[6] - delimPositions[5] - 1);
    //
    // Consume the legacy serialized field for format compatibility, but do not
    // trust/store it in memory. Authoritative cumulative work is recomputed into
    // BlockIndexEntry::chainWork by Blockchain.
    (void)safeStoull(data.substr(delimPositions[6] + 1, delimPositions[7] - delimPositions[6] - 1), "chainWork");
    block.chainWork = 0;
    block.parentHash = data.substr(delimPositions[7] + 1, delimPositions[8] - delimPositions[7] - 1);
    block.height = safeStoi(data.substr(delimPositions[8] + 1, delimPositions[9] - delimPositions[8] - 1), "height");
    
    // Parse transaction count
    size_t txCount = 0;
    if (delimPositions.size() > 10) {
        std::string txCountStr = data.substr(delimPositions[9] + 1, delimPositions[10] - delimPositions[9] - 1);
        txCount = safeStoul(txCountStr, "txCount");
    } else if (delimPositions.size() == 10) {
        std::string txCountStr = data.substr(delimPositions[9] + 1);
        size_t colonPos = txCountStr.find(':');
        if (colonPos != std::string::npos) {
            txCount = safeStoul(txCountStr.substr(0, colonPos), "txCount");
        } else {
            txCount = safeStoul(txCountStr, "txCount");
        }
    }
    
    Logger::log("[deserialize] Block has " + std::to_string(txCount) + " transactions");
    
    // Initialize currentPos for transaction parsing
    size_t currentPos = 0;
    
    // Parse transactions using length prefixes
    if (txCount > 0) {
        currentPos = (delimPositions.size() > 10) ? delimPositions[10] + 1 : data.find(':', delimPositions[9] + 1) + 1;
        
        for (size_t i = 0; i < txCount; i++) {
            // Find the length prefix
            size_t colonPos = data.find(':', currentPos);
            if (colonPos == std::string::npos) {
                Logger::log("[deserialize] Error: Missing length prefix for transaction " + std::to_string(i));
                break;
            }
            
            std::string lengthStr = data.substr(currentPos, colonPos - currentPos);
            size_t txLength = safeStoul(lengthStr, "txLength");
            
            // Extract transaction data
            if (colonPos + 1 + txLength > data.length()) {
                Logger::log("[deserialize] Error: Transaction data extends beyond block data");
                break;
            }
            
            std::string txData = data.substr(colonPos + 1, txLength);
            
            try {
                Transaction tx = Transaction::deserialize(txData);
                block.transactions.push_back(tx);
                Logger::log("[deserialize] Added transaction: " + tx.txid);
            } catch (const std::exception& e) {
                Logger::log("[deserialize] Error deserializing transaction: " + std::string(e.what()));
                Logger::log("[deserialize] Transaction data: " + txData);
                throw;
            }
            
            // Move to next transaction (skip the pipe delimiter if present)
            currentPos = colonPos + 1 + txLength;
            if (currentPos < data.length() && data[currentPos] == '|') {
                currentPos++;
            }
        }
    }
    
    // Parse metadata if present
    size_t metadataPos = data.find("|METADATA:", currentPos);
    if (metadataPos != std::string::npos) {
        size_t colonPos = data.find(':', metadataPos + 10);
        if (colonPos != std::string::npos) {
            size_t metadataLength = safeStoul(
                data.substr(metadataPos + 10, colonPos - metadataPos - 10), 
                "metadataLength"
            );
            
            if (colonPos + 1 + metadataLength <= data.length()) {
                std::string metadataStr = data.substr(colonPos + 1, metadataLength);
                block.deserializeMetadata(metadataStr);
                Logger::log("[deserialize] Loaded block metadata");
            }
        }
    }

    Logger::log("[deserialize] Successfully deserialized block at height " + std::to_string(block.height) + 
                " with " + std::to_string(block.transactions.size()) + " transactions");
    
    return block;
}


std::string Block::serializeMetadata() const {
    if (tokenMetadata.empty()) {
        return "";
    }
    
    nlohmann::json metaArray = nlohmann::json::array();
    for (const auto& [txid, metadata] : tokenMetadata) {
        nlohmann::json entry;
        entry["txid"] = txid;
        entry["data"] = metadata;
        metaArray.push_back(entry);
    }
    
    return metaArray.dump();
}

void Block::deserializeMetadata(const std::string& data) {
    tokenMetadata.clear();
    
    if (data.empty()) {
        return;
    }
    
    try {
        nlohmann::json metaArray = nlohmann::json::parse(data);
        if (!metaArray.is_array()) {
            Logger::log("[Block::deserializeMetadata] Error: Metadata is not an array");
            return;
        }
        
        for (const auto& entry : metaArray) {
            if (entry.contains("txid") && entry.contains("data")) {
                std::string txid = entry["txid"].get<std::string>();
                tokenMetadata[txid] = entry["data"];
            }
        }
        
        Logger::log("[Block::deserializeMetadata] Loaded metadata for " + 
                    std::to_string(tokenMetadata.size()) + " transactions");
    } catch (const std::exception& e) {
        Logger::log("[Block::deserializeMetadata] Error parsing metadata: " + 
                    std::string(e.what()));
    }
}

void Block::extractTokenMetadata(LevelDBStorage* storage) {
    Logger::log("[Block::extractTokenMetadata] Extracting metadata from " + 
                std::to_string(transactions.size()) + " transactions");
    
    tokenMetadata.clear();

    // Living-token evolution anchors are normal OP_RETURN
    // transactions, not token issuance/TRUScript payloads. Recognize the
    // first pushed chunk "TRU_EVOLVE_V1" so metadata extraction leaves the
    // anchor transaction untouched for normal mining/confirmation.
    const auto isTRUEvolutionAnchor = [](const std::string& scriptHex) -> bool {
        static const std::string markerHex =
            "5452555f45564f4c56455f5631"; // "TRU_EVOLVE_V1"

        if (scriptHex.size() < 4 || scriptHex.rfind("6a", 0) != 0) {
            return false;
        }

        try {
            size_t pos = 2;
            auto readHexByte = [&](size_t p) -> uint8_t {
                if (p + 2 > scriptHex.size()) {
                    throw std::runtime_error("short OP_RETURN push");
                }
                return static_cast<uint8_t>(
                    std::stoul(scriptHex.substr(p, 2), nullptr, 16)
                );
            };

            const uint8_t opcode = readHexByte(pos);
            pos += 2;
            size_t pushedLen = 0;

            if (opcode <= 75) {
                pushedLen = opcode;
            } else if (opcode == 0x4c) {
                pushedLen = readHexByte(pos);
                pos += 2;
            } else if (opcode == 0x4d) {
                const uint8_t lo = readHexByte(pos);
                const uint8_t hi = readHexByte(pos + 2);
                pushedLen = static_cast<size_t>(lo) |
                            (static_cast<size_t>(hi) << 8);
                pos += 4;
            } else {
                return false;
            }

            if (pushedLen * 2 != markerHex.size()) return false;
            if (pos + markerHex.size() > scriptHex.size()) return false;
            return scriptHex.compare(pos, markerHex.size(), markerHex) == 0;
        } catch (...) {
            return false;
        }
    };
    
    for (const auto& tx : transactions) {
        // First check if transaction has metadata attached (from network propagation)
        if (!tx.tokenMetadata.empty()) {
            for (const auto& [txid, metadata] : tx.tokenMetadata) {
                tokenMetadata[txid] = metadata;
                Logger::log("[Block::extractTokenMetadata] Found attached metadata in tx " + txid);
                
                // Store in local database if we don't have it
                if (storage) {
                    std::string metaKey = "tokenMetadata:" + txid;
                    std::string existingMeta;
                    if (!storage->getWithDataChecksum(metaKey, existingMeta)) {
                        // We don't have this metadata locally, store it
                        storage->putWithDataChecksum(metaKey, metadata.dump());
                        Logger::log("[Block::extractTokenMetadata] Stored propagated metadata for " + txid);
                    }
                }
            }
        }
        
        // Check each output for tokens or TRUScripts
        for (size_t voutIndex = 0; voutIndex < tx.vout.size(); ++voutIndex) {
            const auto& out = tx.vout[voutIndex];
            
            // Check if this is an OP_RETURN output (starts with "6a")
            if (out.scriptPubKey.substr(0, 2) == "6a" && out.amount == 0) {
                if (isTRUEvolutionAnchor(out.scriptPubKey)) {
                    Logger::log(
                        "[Block::extractTokenMetadata] Recognized TRU_EVOLVE_V1 "
                        "anchor in tx " + tx.txid +
                        "; skipping token/TRUScript metadata parser"
                    );
                    continue;
                }

                // Try to parse as TRUScript first
                try {
                    // Extract the data portion from OP_RETURN script
                    std::string scriptHex = out.scriptPubKey;
                    if (scriptHex.length() < 4) continue; // Too short
                    
                    // Skip "6a" prefix
                    std::string dataHex = scriptHex.substr(2);
                    
                    // Parse length encoding
                    size_t dataStart = 0;
                    size_t dataLen = 0;
                    
                    if (dataHex.length() >= 2) {
                        uint8_t lenByte = std::stoul(dataHex.substr(0, 2), nullptr, 16);
                        
                        if (lenByte <= 75) {
                            // Direct push
                            dataStart = 2;
                            dataLen = lenByte;
                        } else if (lenByte == 0x4c && dataHex.length() >= 4) {
                            // OP_PUSHDATA1
                            dataStart = 4;
                            dataLen = std::stoul(dataHex.substr(2, 2), nullptr, 16);
                        } else if (lenByte == 0x4d && dataHex.length() >= 6) {
                            // OP_PUSHDATA2
                            dataStart = 6;
                            uint16_t len = std::stoul(dataHex.substr(2, 2), nullptr, 16) |
                                          (std::stoul(dataHex.substr(4, 2), nullptr, 16) << 8);
                            dataLen = len;
                        }
                    }
                    
                    // Check if we have enough data
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
                        
                        // Try to parse as JSON (for TRUScripts)
                        try {
                            nlohmann::json parsedData = nlohmann::json::parse(dataStr);
                            
                            // Check if it's a TRUScript inscription
                            if (parsedData.contains("type") && parsedData["type"] == "TRUSCRIPT") {
                                // This is a new TRUScript inscription
                                tokenMetadata[tx.txid] = parsedData;
                                
                                // Store in database if storage is available
                                if (storage) {
                                    std::string metaKey = "tokenMetadata:" + tx.txid;
                                    
                                    // Create complete metadata including creation info
                                    nlohmann::json fullMetadata = parsedData;
                                    fullMetadata["creationTxid"] = tx.txid;
                                    fullMetadata["currentTxid"] = tx.txid;
                                    
                                    storage->putWithDataChecksum(metaKey, fullMetadata.dump());
                                    
                                    Logger::log("[Block::extractTokenMetadata] Stored TRUScript inscription " + 
                                              tx.txid + " with data: " + parsedData.value("data", ""));
                                }
                                
                                continue; // Skip to next output
                            }
                            // Check if it's a TRUScript transfer
                            else if (parsedData.contains("type") && parsedData["type"] == "TRUSCRIPT_TRANSFER") {
                                std::string inscriptionTxid = parsedData.value("inscription", "");
                                std::string from = parsedData.value("from", "");
                                std::string to = parsedData.value("to", "");
                                
                                Logger::log("[Block::extractTokenMetadata] Found TRUScript transfer in tx " + 
                                          tx.txid + " for inscription " + inscriptionTxid);
                                
                                if (!inscriptionTxid.empty() && storage) {
                                    // Try to get the original inscription's metadata
                                    std::string metaKey = "tokenMetadata:" + inscriptionTxid;
                                    std::string metaValue;
                                    
                                    // First check if we already have it in this block's metadata
                                    nlohmann::json inscriptionMeta;
                                    bool foundInBlock = false;
                                    
                                    auto it = tokenMetadata.find(inscriptionTxid);
                                    if (it != tokenMetadata.end()) {
                                        inscriptionMeta = it->second;
                                        foundInBlock = true;
                                        Logger::log("[Block::extractTokenMetadata] Found inscription metadata in current block");
                                    } else if (storage->getWithDataChecksum(metaKey, metaValue)) {
                                        // Found in storage
                                        try {
                                            inscriptionMeta = nlohmann::json::parse(metaValue);
                                            Logger::log("[Block::extractTokenMetadata] Found inscription metadata in storage");
                                        } catch (const std::exception& e) {
                                            Logger::log("[Block::extractTokenMetadata] Error parsing stored metadata: " + 
                                                      std::string(e.what()));
                                            continue;
                                        }
                                    } else {
                                        // We don't have the original inscription metadata
                                        // This can happen when receiving blocks from other nodes
                                        // We need to trust the transfer data and create minimal metadata
                                        Logger::log("[Block::extractTokenMetadata] Original inscription not found locally, creating from transfer data");
                                        
                                        inscriptionMeta["type"] = "TRUSCRIPT";
                                        inscriptionMeta["creationTxid"] = inscriptionTxid;
                                        inscriptionMeta["currentTxid"] = tx.txid;
                                        inscriptionMeta["owner"] = to;
                                        inscriptionMeta["lastTransfer"] = tx.txid;
                                        
                                        // Try to get additional data from the transfer if available
                                        if (parsedData.contains("data")) {
                                            inscriptionMeta["data"] = parsedData["data"];
                                        }
                                        if (parsedData.contains("inscriptionIndex")) {
                                            inscriptionMeta["inscriptionIndex"] = parsedData["inscriptionIndex"];
                                        }
                                        if (parsedData.contains("satNumber")) {
                                            inscriptionMeta["satNumber"] = parsedData["satNumber"];
                                        }
                                        if (parsedData.contains("timestamp")) {
                                            inscriptionMeta["timestamp"] = parsedData["timestamp"];
                                        }
                                        if (parsedData.contains("creationTimestamp")) {
                                            inscriptionMeta["creationTimestamp"] = parsedData["creationTimestamp"];
                                        }
                                        storage->putWithDataChecksum(metaKey, inscriptionMeta.dump());
                                    }
                                    
                                    // Update owner
                                    inscriptionMeta["owner"] = to;
                                    inscriptionMeta["lastTransfer"] = tx.txid;
                                    inscriptionMeta["currentTxid"] = tx.txid;
                                    
                                    // Update in storage
                                    storage->putWithDataChecksum(metaKey, inscriptionMeta.dump());
                                    
                                    // IMPORTANT: Store the updated metadata in this block's tokenMetadata
                                    // This ensures it gets propagated to other nodes
                                    tokenMetadata[inscriptionTxid] = inscriptionMeta;
                                    
                                    // Store transfer record
                                    std::string transferKey = "truScriptTransfer:" + tx.txid;
                                    nlohmann::json transferRecord = parsedData;
                                    transferRecord["blockHeight"] = this->height;
                                    transferRecord["transferTxid"] = tx.txid;
                                    storage->putWithDataChecksum(transferKey, transferRecord.dump());
                                    
                                    Logger::log("[Block::extractTokenMetadata] Updated TRUScript owner for " + 
                                              inscriptionTxid + " from " + from + " to " + to);
                                }
                                continue; // Skip to next output
                            }
                            // Check if it's a regular token (legacy format in JSON)
                            else if (parsedData.contains("token")) {
                                // Handle legacy token format
                                tokenMetadata[tx.txid] = parsedData;
                                if (storage) {
                                    std::string metaKey = "tokenMetadata:" + tx.txid;
                                    storage->putWithDataChecksum(metaKey, parsedData.dump());
                                }
                                Logger::log("[Block::extractTokenMetadata] Found legacy token in tx " + tx.txid);
                                continue;
                            }
                        } catch (const nlohmann::json::parse_error& e) {
                            // Not valid JSON, might be extended token binary format
                            // Check if it starts with "TOKENISSUE|"
                            if (dataStr.find("TOKENISSUE|") == 0) {
                                // Legacy ASCII token format
                                std::string tokenData = dataStr.substr(11); // Skip "TOKENISSUE|"
                                try {
                                    nlohmann::json tokenJson = nlohmann::json::parse(tokenData);
                                    tokenMetadata[tx.txid] = tokenJson;
                                    if (storage) {
                                        std::string metaKey = "tokenMetadata:" + tx.txid;
                                        storage->putWithDataChecksum(metaKey, tokenJson.dump());
                                    }
                                    Logger::log("[Block::extractTokenMetadata] Found ASCII token in tx " + tx.txid);
                                    continue;
                                } catch (...) {
                                    // Not a valid token format
                                }
                            }
                            
                            // NEW: Try parsing as extended binary token format
                            ExtendedTokenData tokenData;
                            std::string ownerAddress;
                            
                            // For extended tokens, we need to pass the full scriptPubKey hex (including "6a" prefix)
                            if (parseExtendedTokenScript(out.scriptPubKey, tx.txid, tokenData, 
                                                       ownerAddress, nullptr)) {
                                Logger::log("[Block::extractTokenMetadata] Found extended binary token in tx " + 
                                          tx.txid + ", type: " + tokenTypeToString(tokenData.type));
                                
                                // First check if we have metadata attached to the transaction
                                nlohmann::json extTokenMeta;
                                bool foundAttachedMetadata = false;
                                
                                if (!tx.tokenMetadata.empty() && tx.tokenMetadata.count(tx.txid)) {
                                    // Use the metadata that was propagated with the transaction
                                    extTokenMeta = tx.tokenMetadata.at(tx.txid);
                                    foundAttachedMetadata = true;
                                    Logger::log("[Block::extractTokenMetadata] Using attached metadata for token");
                                } else {
                                    // Build metadata from parsed data
                                    extTokenMeta["type"] = tokenTypeToString(tokenData.type);
                                    extTokenMeta["tokenID"] = tokenData.tokenID;
                                    extTokenMeta["amount"] = std::to_string(tokenData.amount);
                                    extTokenMeta["owner"] = ownerAddress;
                                    extTokenMeta["version"] = std::to_string(tokenData.version);
                                    extTokenMeta["metadataSignature"] = tokenData.metadataSignature;
                                    extTokenMeta["offChainMetadata"] = tokenData.offChainMetadata;
                                    
                                    // If we don't have full metadata, use defaults
                                    if (tokenData.meta.data.empty()) {
                                        tokenData.meta.data["name"] = "Token_" + tokenData.tokenID;
                                        tokenData.meta.data["symbol"] = tokenTypeToString(tokenData.type);
                                        tokenData.meta.data["description"] = "No metadata available";
                                        tokenData.meta.data["decimals"] = "0";
                                    }
                                    extTokenMeta["meta"] = tokenData.meta.data;
                                    
                                    Logger::log("[Block::extractTokenMetadata] Built metadata from binary token data");
                                }
                                
                                // Store in block's metadata
                                tokenMetadata[tx.txid] = extTokenMeta;
                                
                                // Store in database if available
                                if (storage) {
                                    std::string metaKey = "tokenMetadata:" + tx.txid;
                                    storage->putWithDataChecksum(metaKey, extTokenMeta.dump());
                                    
                                    // Store token UTXO info
                                    uint32_t controllingVout = voutIndex + 1; // Typically next output
                                    if (controllingVout < tx.vout.size()) {
                                        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":" + 
                                                                  std::to_string(controllingVout);
                                        nlohmann::json tokenUtxoJson = {
                                            {"tokenID", tokenData.tokenID},
                                            {"amount", std::to_string(tokenData.amount)},
                                            {"owner", ownerAddress},
                                            {"type", tokenTypeToString(tokenData.type)},
                                            {"controllingVout", controllingVout}
                                        };
                                        storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoJson.dump());
                                        
                                        // Store ownership index
                                        std::string tokenIndexKey = "tokenOwnerUTXO:" + tokenData.tokenID + ":" + 
                                                                   ownerAddress + ":" + tx.txid + ":" + 
                                                                   std::to_string(controllingVout);
                                        storage->putWithDataChecksum(tokenIndexKey, "1");
                                    }
                                    
                                    Logger::log("[Block::extractTokenMetadata] Stored extended token metadata and indexes");
                                }
                                
                                continue; // Skip to next output
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::log("[Block::extractTokenMetadata] Error parsing OP_RETURN: " + std::string(e.what()));
                }
            }
            // REMOVED: The section checking for extended tokens with out.amount > 0
            // Extended tokens are stored in OP_RETURN outputs (amount == 0), not regular outputs
        }
    }
    
    if (storage)
    {
        // For each transfer found, also include the original inscription metadata
        std::unordered_set<std::string> transferredInscriptions;

        for (const auto &tx : transactions)
        {
            for (const auto &out : tx.vout)
            {
                if (out.scriptPubKey.substr(0, 2) == "6a")
                {
                    if (isTRUEvolutionAnchor(out.scriptPubKey))
                    {
                        // evolution proof, not a TRUScript transfer.
                        continue;
                    }

                    nlohmann::json parsedData;
                    try
                    {
                        if (parseTRUScriptFromOPReturn(
                                out.scriptPubKey,
                                tx.txid,
                                parsedData,
                                nullptr))
                        {
                            if (parsedData.contains("type") &&
                                parsedData["type"] == "TRUSCRIPT_TRANSFER")
                            {
                                std::string inscriptionTxid =
                                    parsedData.value("inscription", "");
                                if (!inscriptionTxid.empty())
                                {
                                    transferredInscriptions.insert(inscriptionTxid);
                                }
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        Logger::log(
                            "[Block::extractTokenMetadata] Ignoring non-token "
                            "OP_RETURN during TRUScript transfer scan tx " +
                            tx.txid + ": " + std::string(e.what())
                        );
                    }
                    catch (...)
                    {
                        Logger::log(
                            "[Block::extractTokenMetadata] Ignoring non-token "
                            "OP_RETURN during TRUScript transfer scan tx " +
                            tx.txid + ": unknown parser exception"
                        );
                    }
                }
            }
        }

        // Include metadata for all transferred inscriptions
        for (const auto &inscriptionTxid : transferredInscriptions)
        {
            if (tokenMetadata.find(inscriptionTxid) == tokenMetadata.end())
            {
                std::string metaKey = "tokenMetadata:" + inscriptionTxid;
                std::string metaValue;
                if (storage->getWithDataChecksum(metaKey, metaValue))
                {
                    try
                    {
                        tokenMetadata[inscriptionTxid] = nlohmann::json::parse(metaValue);
                        Logger::log("[Block::extractTokenMetadata] Added inscription metadata for network propagation: " + inscriptionTxid);
                    }
                    catch (...)
                    {
                    }
                }
            }
        }
    }
    Logger::log("[Block::extractTokenMetadata] Extracted metadata for " + 
                std::to_string(tokenMetadata.size()) + " token transactions");
}

void Block::storeReceivedMetadata(LevelDBStorage* storage) {
    if (!storage || tokenMetadata.empty()) {
        return;
    }
    
    Logger::log("[Block::storeReceivedMetadata] Storing metadata for " + 
                std::to_string(tokenMetadata.size()) + " tokens from received block");
    
    for (const auto& [txid, metadata] : tokenMetadata) {
        std::string metaKey = "tokenMetadata:" + txid;
        std::string existingMeta;
        
        // Only store if we don't already have it
        if (!storage->getWithDataChecksum(metaKey, existingMeta)) {
            storage->putWithDataChecksum(metaKey, metadata.dump());
            Logger::log("[Block::storeReceivedMetadata] Stored metadata for token: " + txid);
        } else {
            Logger::log("[Block::storeReceivedMetadata] Already have metadata for token: " + txid);
        }
    }
}   
