#pragma once
#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <cstdint>
#include "tx.h"
#include "message.pb.h"
#include <nlohmann/json.hpp>
#include "leveldb_storage.h"


/**
 * @brief The BlockHeader structure
 *
 * Contains the minimal fields needed for block identification:
 *  - version      : protocol version
 *  - prevHash     : 64-char hex of the previous block's hash (big-end)
 *  - merkleRoot   : 64-char hex of the merkle root (big-end)
 *  - timestamp    : Unix epoch
 *  - bits         : compact difficulty representation
 *  - nonce        : up to 64-bit 
 */
class BlockHeader {
public:
    int32_t  version;
    std::string prevHash;      // 64-hex
    std::string merkleRoot;    // 64-hex
    uint32_t timestamp;
    uint32_t bits;
    uint64_t nonce;            // typically 32-bit in Bitcoin, but we use 64
    // Constructors
    BlockHeader();
    BlockHeader(int32_t ver, const std::string &ph, uint32_t ts, uint32_t b);

    /**
     * @brief serialize
     * @return a text-based serialization of the header
     */
    std::string serialize() const;

    /**
     * @brief serializeHeader
     * 
     * @param header
     * @param includeNonce
     * @return
     */
    static std::string serializeHeader(const BlockHeader &header, bool includeNonce);

    /**
     * @brief deserialize
     * @param data - the text-based data
     * @return a BlockHeader object
     */
    static BlockHeader deserialize(const std::string &data);
};

/**
 * @brief buildBlockHeader80
 *
 * Creates the classic 80-byte block header (Bitcoin style) from the fields in
 * a BlockHeader. Reverses the prevHash and merkleRoot from big-end to little-end.
 * @param hdr
 * @return 80-byte vector
 */
std::vector<unsigned char> buildBlockHeader80(const BlockHeader &hdr);

/**
 * @brief The Block class
 *
 * A full block includes:
 *  - A BlockHeader
 *  - A set of transactions
 *  - A blockHash (puzzle solution)
 *  - chainWork, parentHash, etc. for easy chain indexing
 */
class Block {
public:
    BlockHeader header;
    std::string blockHash;               ///< final puzzle solution
    // legacy wire/disk field only. It is not
    // committed by the block hash and MUST NOT be used for fork selection.
    // Authoritative cumulative work lives in BlockIndexEntry::chainWork.
    uint64_t    chainWork;
    std::string parentHash;              ///< convenience copy of header.prevHash
    uint32_t    previousBlockTime;       ///< optional: store parent's timestamp
    int height;
    std::vector<Transaction> transactions;
    void toProto(blockchain::BlockProto& proto) const;
    void fromProto(const blockchain::BlockProto& proto);
    std::unordered_map<std::string, nlohmann::json> tokenMetadata;
    void storeReceivedMetadata(LevelDBStorage* storage);
public:
    Block();
    Block(int32_t ver, const std::string &ph, uint32_t ts, uint32_t b);

    /**
     * @brief computeHash
     *  - Builds the 80-byte header
     *  - double-SHA256
     *  - +21E8 injection
     */
    std::string computeHash() const;

    /**
     * @brief computeRawHex
     *  - Creates a minimal raw block in hex: 80-byte header + varint(#tx) + serialized TXs
     */
    std::string computeRawHex() const;

    /**
     * @brief serialize
     *  - Text-based block serialization
     */
    std::string serialize() const;

    /**
     * @brief deserialize
     *  - Reconstruct from text-based representation
     */
    static Block deserialize(const std::string &data);
    void extractTokenMetadata(LevelDBStorage* storage = nullptr);
    std::string serializeMetadata() const;
    void deserializeMetadata(const std::string& data);
};

// zero-knowledge proof check
bool verifyZeroKnowledgeProof(const Transaction &tx);

#endif // BLOCK_H
