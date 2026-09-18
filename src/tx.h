#pragma once
#ifndef TX_H
#define TX_H

#include <string>
#include <vector>
#include <cstdint>
#include "crypto_ecdsa.h"   // Must provide ECDSAKey
#include "script_interpreter.h" // For VerifyScripts(...) or EvaluateScript(...)
#include <unordered_map>
#include <nlohmann/json.hpp>

// -----------------------------------------------------------------------------
// Forward-declared small helpers, if you want them here or in a utils header
// -----------------------------------------------------------------------------
static void write32LE(std::vector<unsigned char> &buf, uint32_t val);
static void write64LE(std::vector<unsigned char> &buf, uint64_t val);
static void writeVarInt(std::vector<unsigned char> &buf, uint64_t value);

// -----------------------------------------------------------------------------
// TxIn: Transaction Input
// -----------------------------------------------------------------------------
struct TxIn {
    std::string txid;                ///< Hash of the previous transaction
    //uint32_t    vout;                ///< Output index from that transaction
    int vout;
    std::vector<unsigned char> scriptSig;  ///< Unlocking script
    std::vector<unsigned char> pubKey;     ///< Public key used for ECDSA checks
    std::vector<unsigned char> scriptPubKey;
    uint32_t sequence;               ///< Sequence number

    // Constructors
    TxIn();
    TxIn(const std::string &txid, uint32_t vout, uint32_t sequence = 0xFFFFFFFF);
    TxIn(const std::string &txid, uint32_t vout,
         const std::vector<unsigned char> &scriptSig,
         const std::vector<unsigned char> &pubKey,
         uint32_t sequence = 0xFFFFFFFF);

    std::string serialize() const;
    static TxIn deserialize(const std::string &data);
    bool isCoinbase() const {return txid == std::string(32, '\0') && vout == 0; }
};

// -----------------------------------------------------------------------------
// TxOut: Transaction Output
// -----------------------------------------------------------------------------
struct TxOut {
    uint64_t    amount;         ///< Amount in TRU atoms
    std::string scriptPubKey;   ///< Locking script

    TxOut();
    TxOut(uint64_t amount, const std::string &scriptPubKey);

    std::string serialize() const;
    static TxOut deserialize(const std::string &data);
};


class Blockchain;
// -----------------------------------------------------------------------------
// Transaction: A full transaction with inputs and outputs
// -----------------------------------------------------------------------------
class Transaction {
public:
    bool isCoinbase;           ///< True if this TX is coinbase
    std::string txid;          ///< Double-SHA256 of the serialized transaction
    std::string sender;        ///< Optional convenience: the sender's address

    std::vector<TxIn>  vin;    ///< Inputs
    std::vector<TxOut> vout;   ///< Outputs

    // Basic fields
    //int32_t  version;   ///< Typically 1 or 2 in Bitcoin-like systems
    //uint32_t lockTime;  ///< Usually 0 for basic TX
    int32_t version = 1;       ///< Typically 1 or 2
    uint32_t lockTime = 0;

    explicit Transaction(bool coinbase = false);

    std::vector<unsigned char> getSigHash(size_t inputIndex, const std::vector<unsigned char>& scriptPubKey) const;
    // For quick usage
    void set_sender(const std::string &s);
    //std::string get_sender() const;
    std::string get_sender(const Blockchain* blockchain) const;
    // Add a single output paying to some address (P2PKH style).
    void set_recipient(const std::string &recipient);

    // Set the first output’s amount in decimal “coins” => convert to TRU atoms
    void set_amount(double coins);

    // Recompute txid as double-SHA256(serialize())
    void computeTxId();

    // ECDSA-based signature for an input. TRU Security Patch 11 removed the
    // legacy ASCII "SIGHASH|txid|index" signing path; getSigHash() is authoritative.
    bool signInput(size_t index, const ECDSAKey &key, const std::string &scriptPubKeyHex);

    // TRU Security Patch 12A removed the unused verifyInput()/verifyInputScript()
    // methods. Consensus and mempool verification must stay on VerifyScripts()
    // rather than accumulating dormant alternate verification paths.

    // Text-based serialization
    std::string serialize() const;
    static Transaction deserialize(const std::string &data);

    // Binary (wire-format) serialization / deserialization
    std::vector<unsigned char> serializeBinary() const;
    static Transaction deserializeBinary(const std::vector<unsigned char> &raw);

    // Extra variant if you want to store scriptSig+pubKey differently
    std::vector<unsigned char> serializeBinary2() const;
    static Transaction deserializeBinary2(const std::vector<unsigned char> &raw);

    bool verify(Blockchain* blockchainPtr) const;
    uint64_t computeFee(const Blockchain& chain) const;
    std::unordered_map<std::string, nlohmann::json> tokenMetadata;
};

// Compute a simple Merkle root from a vector of transactions
std::string computeMerkleRoot(const std::vector<Transaction>& txs);

#endif // TX_H
