
#include "tx.h"
#include "tru_limits.h"  // shared MAX_MONEY
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <unordered_set>
#include <openssl/sha.h>
#include "address_helpers.h"  
#include "script_interpreter.h" 
#include "utils.h"             
#include <iostream>          
#include "utxo.h"
#include "blockchain.h"
#include "mempool.h"



// =============================================================================
//			TODO TRANSACTION VERIFY
// =============================================================================

bool Transaction::verify(Blockchain* blockchainPtr) const {
    // Implement verification logic
    return true; // Placeholder
}

uint64_t Transaction::computeFee(const Blockchain& chain) const {
    // fee calculation is used by getblocktemplate and
    // must mirror block-validation duplicate-input / MAX_MONEY invariants.
    if (isCoinbase) {
        throw std::runtime_error("Coinbase transaction has no mempool fee");
    }

    uint64_t totalIn = 0;
    uint64_t totalOut = 0;
    std::unordered_set<std::string> seenInputs;

    for (const auto& input : vin) {
        if (input.txid.size() != 64 || !isValidHex(input.txid) ||
            input.vout < 0) {
            throw std::runtime_error("Malformed transaction input");
        }

        const uint32_t voutIndex = static_cast<uint32_t>(input.vout);
        const std::string outpoint =
            input.txid + ":" + std::to_string(voutIndex);
        if (!seenInputs.insert(outpoint).second) {
            throw std::runtime_error("Duplicate transaction input");
        }

        UTXO utxo;
        if (!chain.utxoSet.getUTXO(input.txid, voutIndex, utxo)) {
            throw std::runtime_error("Missing UTXO for input");
        }

        if (utxo.amount > tru_limits::MAX_MONEY ||
            totalIn > tru_limits::MAX_MONEY - utxo.amount) {
            throw std::runtime_error("Input value/sum exceeds MAX_MONEY");
        }
        totalIn += utxo.amount;
    }

    for (const auto& output : vout) {
        if (output.amount > tru_limits::MAX_MONEY ||
            totalOut > tru_limits::MAX_MONEY - output.amount) {
            throw std::runtime_error("Output value/sum exceeds MAX_MONEY");
        }
        totalOut += output.amount;
    }

    if (totalIn < totalOut) {
        throw std::runtime_error("Invalid transaction: output > input");
    }

    const uint64_t fee = totalIn - totalOut;
    if (fee > tru_limits::MAX_MONEY) {
        throw std::runtime_error("Transaction fee exceeds MAX_MONEY");
    }
    return fee;
}
//------------------------------------------------------------------------------
//             doubleSha256 - single, then second SHA256
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

// =============================================================================
//                      TxIn Implementation
// =============================================================================
TxIn::TxIn() : vout(0), sequence(0xFFFFFFFF) {}

TxIn::TxIn(const std::string &txid, uint32_t vout, uint32_t sequence)
    : txid(txid), vout(vout), sequence(sequence)
{}

TxIn::TxIn(const std::string &txid, uint32_t vout,
           const std::vector<unsigned char> &scriptSig,
           const std::vector<unsigned char> &pubKey,
           uint32_t sequence)
    : txid(txid), vout(vout), scriptSig(scriptSig), pubKey(pubKey), sequence(sequence)
{}


std::string TxIn::serialize() const {
    std::ostringstream oss;
    oss << txid << "|" 
        << vout << "|"
        << (scriptSig.empty() ? "" : hexEncode(scriptSig)) << "|"
        << (pubKey.empty() ? "" : hexEncode(pubKey)) << "|"
        << sequence;
    return oss.str();
}

TxIn TxIn::deserialize(const std::string &data) {
    std::istringstream iss(data);
    std::string txidStr, voutStr, sigHex, pubHex, seqStr;
    std::vector<std::string> parts;

    // Split the entire string by '|'
    std::string part;
    while (std::getline(iss, part, '|')) {
        parts.push_back(part);
    }

    // Log the parsed parts for debugging
    std::ostringstream debugLog;
    debugLog << "[TxIn::deserialize] Parsed " << parts.size() << " parts from data: " << data;
    Logger::log(debugLog.str());

    // Need at least 3 parts (txid, vout, scriptSig), pubKey and sequence are optional
    if (parts.size() < 3) {
        Logger::log("[TxIn::deserialize] Error: Insufficient fields, expected at least 3, got " + std::to_string(parts.size()));
        throw std::runtime_error("[TxIn::deserialize] parse error: insufficient fields");
    }

    txidStr = parts[0];
    voutStr = parts[1];
    sigHex = parts[2];
    
    // Optional fields
    if (parts.size() > 3) {
        pubHex = parts[3];
    }
    if (parts.size() > 4) {
        seqStr = parts[4];
    }

    // Parse vout
    uint32_t voutVal;
    try {
        if (voutStr.empty()) {
            throw std::runtime_error("Empty vout field");
        }
        voutVal = std::stoul(voutStr);
    } catch (const std::exception& e) {
        Logger::log("[TxIn::deserialize] Error parsing vout: " + voutStr + ", error: " + e.what());
        throw std::runtime_error("[TxIn::deserialize] invalid vout");
    }

    // Parse sequence (default to 0xFFFFFFFF if not provided)
    uint32_t seqVal = 0xFFFFFFFF;
    if (!seqStr.empty()) {
        try {
            seqVal = std::stoul(seqStr);
        } catch (const std::exception& e) {
            Logger::log("[TxIn::deserialize] Error parsing sequence: " + seqStr + ", using default");
        }
    }

    TxIn result(txidStr, voutVal, seqVal);
    
    // Decode scriptSig only if not empty
    if (!sigHex.empty()) {
        try {
            result.scriptSig = hexDecode(sigHex);
        } catch (const std::exception& e) {
            Logger::log("[TxIn::deserialize] Warning: Failed to decode scriptSig hex: " + sigHex);
            // Don't throw, just leave scriptSig empty
        }
    }
    
    // Decode pubKey only if not empty
    if (!pubHex.empty()) {
        try {
            result.pubKey = hexDecode(pubHex);
        } catch (const std::exception& e) {
            Logger::log("[TxIn::deserialize] Warning: Failed to decode pubKey hex: " + pubHex);
            // Don't throw, just leave pubKey empty
        }
    }

    Logger::log("[TxIn::deserialize] Successfully deserialized TxIn: txid=" + txidStr + 
                ", vout=" + std::to_string(voutVal) + ", sequence=" + std::to_string(seqVal));
    return result;
}


// =============================================================================
//                         TxOut Implementation
// =============================================================================
TxOut::TxOut() : amount(0) {}

TxOut::TxOut(uint64_t amt, const std::string &spk)
  : amount(amt), scriptPubKey(spk)
{}

std::string TxOut::serialize() const {
    // e.g. => "amount|scriptPubKey"
    std::ostringstream oss;
    oss << amount << "|" << scriptPubKey;
    return oss.str();
}

TxOut TxOut::deserialize(const std::string &data) {
    std::istringstream iss(data);
    uint64_t amt=0;
    char delim;
    std::string spk;
    if(!(iss >> amt >> delim)) {
        throw std::runtime_error("[TxOut::deserialize] parse error: no amount?");
    }
    if(!std::getline(iss, spk)) {
        throw std::runtime_error("[TxOut::deserialize] parse error: no scriptPubKey?");
    }
    return TxOut(amt, spk);
}

// =============================================================================
//                      Transaction Implementation
// =============================================================================
Transaction::Transaction(bool coinbase)
    : isCoinbase(coinbase), txid(""), sender(""),
      version(1), lockTime(0)
{}


void Transaction::set_sender(const std::string &s) {
    sender = s;
}
// =============================================================================
//				GET SENDER
// =============================================================================
std::string Transaction::get_sender(const Blockchain* blockchain) const {
    if (isCoinbase || vin.empty()) {
        return ""; // No sender for coinbase or empty inputs
    }
    const TxIn& input = vin[0];
    if (input.pubKey.empty()) {
        return ""; // No public key available
    }
    return pubkeyToAddress(input.pubKey);
}



void Transaction::set_recipient(const std::string &recipient) {
    // For a single-output P2PKH:
    TxOut out;
    out.scriptPubKey = createP2PKHScriptHexFromAddress(recipient);
    out.amount       = 0; // set_amount() later
    vout.push_back(out);
}

void Transaction::set_amount(double coins) {
    if(vout.empty()) return;
    static const uint64_t TRU_ATOMS_PER_TRU = 100000000ULL;
    vout[0].amount = (uint64_t)(coins * TRU_ATOMS_PER_TRU);
}


void Transaction::computeTxId() {
    // the transaction ID must NOT depend on scriptSig.
    //
    // serializeBinary() writes each input's scriptSig. That is correct for
    // the wire format, but it meant computeTxId() returned one value before
    // signing (empty scriptSigs) and a different value after (~106 bytes per
    // input). The ID was therefore malleable, and worse, it silently changed
    // underneath anything that had already filed data against it.
    //
    // Concretely: wallet.cpp computes the ID, keys the token metadata to it,
    // and then signs. signTransaction() keeps the pre-existing ID, so far so
    // good. But the miner (my_miner.cpp:753, my_gpu_miner.cpp:1616)
    // deserialises each mempool transaction out of the block template and
    // calls computeTxId() again. By then it is signed, so it got a NEW id.
    // The block used the new id, the metadata was filed under the old one,
    // applyBlock found nothing, fell back to parsing the OP_RETURN, and wrote
    // a second impoverished record. That is the source of every duplicate
    // "Token_" / "No metadata recorded" entry and the duplicate TRUScripts.
    //
    // Clearing scriptSig for the duration of the hash makes all ~30
    // computeTxId() call sites idempotent: signing can no longer move the id,
    // so it does not matter who recomputes it or when.
    //
    // COINBASE IS EXEMPT, AND MUST BE.
    // A coinbase has no real outpoint to make it unique: every one of them
    // spends "COINBASE:0". Uniqueness comes entirely from data the miner
    // stuffs into vin[0].scriptSig:
    //     blockchain.cpp ~4502   "GPUHeight:<height>"
    //     my_miner.cpp   ~724    "TRU:<height>|CPU:<extraNonce>"
    // serializeBinary() covers version, inputs, outputs and lockTime, and
    // nothing else -- no height, no timestamp. So if the coinbase scriptSig
    // were cleared here, two empty blocks paying the same reward to the same
    // address would hash to the SAME coinbase txid. Two things break:
    //   1. utxo:<txid>:0 collides and the earlier mining reward is silently
    //      overwritten.
    //   2. extraNonce stops working. The miner bumps extraNonce specifically
    //      to change the coinbase txid, hence the merkle root, hence the
    //      header search space. With scriptSig excluded, extraNonce would
    //      have no effect and the miner would re-sweep an identical header
    //      space forever.
    // A coinbase scriptSig is arbitrary miner data, never a signature, so
    // including it costs nothing in malleability terms.
    //
    // Non-coinbase inputs are safe to exclude because the txid still commits
    // to the outpoints being spent. Two transactions that differ only in
    // their unlocking data spend the same inputs, so they are conflicting
    // double-spends and at most one can ever confirm. There is no equivalent
    // of the coinbase's reused "COINBASE:0" outpoint.
    //
    // The signature still covers everything that matters. signInput() builds
    // its sighash from a copy with the scriptSigs cleared and the relevant
    // scriptPubKey substituted, and it does NOT clear tokenMetadata, so token
    // metadata remains signature-protected even though it is excluded here.
    //
    // tokenMetadata stays out of the hash for a separate reason: the map is
    // keyed BY the txid, so including it would be circular. That is what the
    // "pending" key in the issuance paths exists to work around.
    std::unordered_map<std::string, nlohmann::json> tempMetadata = tokenMetadata;
    tokenMetadata.clear();

    std::vector<std::vector<unsigned char>> tempScriptSigs;
    if (!isCoinbase) {
        tempScriptSigs.reserve(vin.size());
        for (auto& in : vin) {
            tempScriptSigs.push_back(in.scriptSig);
            in.scriptSig.clear();
        }
    }

    std::vector<unsigned char> binary = serializeBinary();

    // Restore metadata and signatures
    tokenMetadata = tempMetadata;
    if (!isCoinbase) {
        for (size_t i = 0; i < vin.size() && i < tempScriptSigs.size(); ++i) {
            vin[i].scriptSig = tempScriptSigs[i];
        }
    }

    std::string binaryStr(binary.begin(), binary.end());
    this->txid = doubleSha256(binaryStr); // Double SHA-256 hash
    Logger::log("[computeTxId] Computed txid: " + this->txid + ", length: " + std::to_string(this->txid.length()));
}

// -----------------------------------------------------------------------------
// signInput(...) => store the canonical transaction signature in scriptSig
// plus the compressed public key. VerifyScripts() is the live validation path.
// -----------------------------------------------------------------------------
bool Transaction::signInput(size_t index, const ECDSAKey &key, const std::string &scriptPubKeyHex) 
{
    if (index >= vin.size()) {
        Logger::log("[Transaction::signInput] ERROR => index out of range => " + std::to_string(index));
        return false;
    }

    const std::vector<unsigned char> scriptPubKey =
        hexDecode(scriptPubKeyHex);

    // one sighash implementation only.
    const std::vector<unsigned char> sighashBytes =
        getSigHash(index, scriptPubKey);
    const std::string sighash(
        sighashBytes.begin(), sighashBytes.end());

    std::vector<unsigned char> signature = key.sign(sighash);
    signature.push_back(0x01); // SIGHASH_ALL

    // Use compressed public key instead of DER
    std::vector<unsigned char> pubkey = key.getCompressedSec1(); // Typically 33 bytes

    std::vector<unsigned char> finalScriptSig;
    auto pushData = [&](const std::vector<unsigned char> &data) {
        size_t len = data.size();
        if (len < 0x4c) {
            finalScriptSig.push_back(static_cast<unsigned char>(len));
        } else if (len <= 0xff) {
            finalScriptSig.push_back(0x4c);
            finalScriptSig.push_back(static_cast<unsigned char>(len));
        } else if (len <= 0xffff) {
            finalScriptSig.push_back(0x4d);
            finalScriptSig.push_back(static_cast<unsigned char>(len & 0xff));
            finalScriptSig.push_back(static_cast<unsigned char>((len >> 8) & 0xff));
        } else {
            throw std::runtime_error("Data too large for script push.");
        }
        finalScriptSig.insert(finalScriptSig.end(), data.begin(), data.end());
    };

    pushData(signature);
    pushData(pubkey);

    vin[index].scriptSig = finalScriptSig;
    vin[index].pubKey = pubkey;

    Logger::log("[Transaction::signInput] Signed input #" + std::to_string(index) +
                ", sigLen=" + std::to_string(signature.size()) +
                ", pubLen=" + std::to_string(pubkey.size()));
    return true;
}
// -----------------------------------------------------------------------------
//
// The old signInputRpc() ASCII "SIGHASH|txid|index" algorithm was removed.
// Transaction::getSigHash() is the single transaction-signature digest.
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
//
// Removed unused verifyInput()/verifyInputScript() alternate verification paths.
// Consensus and mempool validation use VerifyScripts() exclusively.
// -----------------------------------------------------------------------------
// =============================================================================
//              SERIALIZE - WITH METADATA SUPPORT
// =============================================================================
std::string Transaction::serialize() const {
    std::ostringstream oss;
    
    // Start with basic transaction info
    oss << txid << "|" << (isCoinbase ? "1" : "0") << "|" << vin.size() << "|" << vout.size();
    
    // Serialize inputs
    for (size_t i = 0; i < vin.size(); ++i) {
        const TxIn& in = vin[i];
        // For coinbase transactions, ensure txid is properly formatted
        std::string inputTxid = in.txid;
        if (isCoinbase && i == 0) {
            // Coinbase input should have null txid (64 zeros)
            inputTxid = std::string(64, '0');
        }
        
        oss << "|" << inputTxid 
            << "|" << in.vout 
            << "|" << hexEncode(in.scriptSig) 
            << "|" << hexEncode(in.pubKey)
            << "|" << in.sequence;
    }
    
    // Serialize outputs
    for (size_t i = 0; i < vout.size(); ++i) {
        const TxOut& out = vout[i];
        oss << "|" << out.amount << "|" << out.scriptPubKey;
    }
    
    //
    // The legacy text/block transaction representation omitted version and
    // lockTime. Keep byte-for-byte legacy output for ordinary v1/lockTime=0
    // transactions, but carry the core fields whenever either is non-default.
    // This keeps historical blocks readable while making CLTV transactions
    // survive Block::serialize() -> Block::deserialize() without txid drift.
    if (version != 1 || lockTime != 0) {
        oss << "|TXCORE:" << version << ":" << lockTime;
    }

    // NEW: Serialize token metadata if present
    if (!tokenMetadata.empty()) {
        nlohmann::json metaJson(tokenMetadata);
        std::string metaStr = metaJson.dump();
        
        // Add metadata marker and length-prefixed data
        oss << "|METADATA:" << metaStr.length() << ":" << metaStr;
        Logger::log("[Transaction::serialize] Added metadata: " + std::to_string(metaStr.length()) + " bytes");
    }
    
    return oss.str();
}

// =============================================================================
//              DESERIALIZE - WITH METADATA SUPPORT
// =============================================================================
Transaction Transaction::deserialize(const std::string& data) {
    Transaction tx;
    
    if (data.empty()) {
        Logger::log("[Transaction::deserialize] Error: Empty transaction data");
        throw std::runtime_error("Empty transaction data");
    }
    
    // Split by delimiter to get all parts
    std::vector<std::string> parts;
    std::istringstream iss(data);
    std::string part;
    while (std::getline(iss, part, '|')) {
        parts.push_back(part);
    }
    
    // Also check if the last part contains metadata marker
    if (!parts.empty()) {
        std::string& lastPart = parts.back();
        size_t metadataPos = lastPart.find("METADATA:");
        if (metadataPos != std::string::npos) {
            // Split the last part to separate the previous field from metadata
            std::string beforeMetadata = lastPart.substr(0, metadataPos);
            std::string metadataMarker = lastPart.substr(metadataPos);
            
            if (!beforeMetadata.empty()) {
                parts.back() = beforeMetadata;
                parts.push_back(metadataMarker);
            } else {
                parts.back() = metadataMarker;
            }
        }
    }
    
    if (parts.size() < 4) {
        Logger::log("[Transaction::deserialize] Error: Insufficient header fields");
        throw std::runtime_error("Insufficient transaction header fields");
    }
    
    // Parse header
    tx.txid = parts[0];
    tx.isCoinbase = (parts[1] == "1");
    size_t vinCount = std::stoul(parts[2]);
    size_t voutCount = std::stoul(parts[3]);
    
    size_t currentIdx = 4;
    
    // Parse inputs
    for (size_t i = 0; i < vinCount; i++) {
        if (currentIdx + 5 > parts.size()) {
            Logger::log("[Transaction::deserialize] Error: Insufficient input fields");
            throw std::runtime_error("Insufficient input fields");
        }
        
        TxIn in;
        in.txid = parts[currentIdx++];
        in.vout = std::stoul(parts[currentIdx++]);
        
        // Handle empty hex strings gracefully
        std::string scriptSigHex = parts[currentIdx++];
        if (!scriptSigHex.empty()) {
            in.scriptSig = hexDecode(scriptSigHex);
        }
        
        std::string pubKeyHex = parts[currentIdx++];
        if (!pubKeyHex.empty()) {
            in.pubKey = hexDecode(pubKeyHex);
        }
        
        in.sequence = std::stoul(parts[currentIdx++]);
        
        tx.vin.push_back(in);
    }
    
    // Parse outputs
    for (size_t i = 0; i < voutCount; i++) {
        if (currentIdx + 2 > parts.size()) {
            Logger::log("[Transaction::deserialize] Error: Insufficient output fields");
            throw std::runtime_error("Insufficient output fields");
        }
        
        TxOut out;
        out.amount = std::stoull(parts[currentIdx++]);
        out.scriptPubKey = parts[currentIdx++];
        
        tx.vout.push_back(out);
    }
    
    //
    // Parse optional tagged transaction-core fields plus the pre-existing
    // metadata trailer. Historical transactions have no TXCORE field and
    // therefore retain the constructor defaults version=1 / lockTime=0.
    while (currentIdx < parts.size()) {
        const std::string& extraPart = parts[currentIdx++];

        if (extraPart.find("TXCORE:") == 0) {
            const size_t firstColon = 7; // Length of "TXCORE:"
            const size_t secondColon = extraPart.find(':', firstColon);
            if (secondColon == std::string::npos || secondColon + 1 >= extraPart.size()) {
                Logger::log("[Transaction::deserialize] Invalid TXCORE extension");
                throw std::runtime_error("Invalid transaction TXCORE extension");
            }

            try {
                const long long parsedVersion =
                    std::stoll(extraPart.substr(firstColon, secondColon - firstColon));
                const unsigned long long parsedLockTime =
                    std::stoull(extraPart.substr(secondColon + 1));

                if (parsedVersion < -2147483648LL || parsedVersion > 2147483647LL ||
                    parsedLockTime > 0xffffffffULL) {
                    throw std::out_of_range("TXCORE field out of range");
                }

                tx.version = static_cast<int32_t>(parsedVersion);
                tx.lockTime = static_cast<uint32_t>(parsedLockTime);
                Logger::log("[Transaction::deserialize] Restored TXCORE version=" +
                            std::to_string(tx.version) + ", lockTime=" +
                            std::to_string(tx.lockTime));
            } catch (const std::exception& e) {
                Logger::log("[Transaction::deserialize] Failed to parse TXCORE: " +
                            std::string(e.what()));
                throw std::runtime_error("Invalid transaction TXCORE values");
            }
            continue;
        }

        if (extraPart.find("METADATA:") == 0) {
            // Extract length and data
            size_t firstColon = 9; // Length of "METADATA:"
            size_t secondColon = extraPart.find(':', firstColon);

            if (secondColon != std::string::npos) {
                std::string lengthStr = extraPart.substr(firstColon, secondColon - firstColon);
                size_t metadataLength = std::stoul(lengthStr);

                // Extract metadata JSON
                size_t dataStart = secondColon + 1;
                if (dataStart + metadataLength <= extraPart.length()) {
                    std::string metadataStr = extraPart.substr(dataStart, metadataLength);

                    try {
                        nlohmann::json metaJson = nlohmann::json::parse(metadataStr);
                        tx.tokenMetadata = metaJson.get<std::unordered_map<std::string, nlohmann::json>>();
                        Logger::log("[Transaction::deserialize] Successfully parsed metadata for " +
                                    std::to_string(tx.tokenMetadata.size()) + " entries");
                    } catch (const std::exception& e) {
                        Logger::log("[Transaction::deserialize] Failed to parse token metadata: " +
                                    std::string(e.what()));
                    }
                } else {
                    Logger::log("[Transaction::deserialize] Metadata length exceeds available data");
                }
            } else {
                Logger::log("[Transaction::deserialize] Invalid metadata format - missing length");
            }
            continue;
        }

        // Preserve the legacy parser's permissive treatment of unknown trailing
        // fields instead of turning an unrelated old record into a hard failure.
        if (!extraPart.empty()) {
            Logger::log("[Transaction::deserialize] Ignoring unknown trailing field");
        }
    }
    
    Logger::log("[Transaction::deserialize] Successfully deserialized transaction: " + tx.txid + 
                " with " + std::to_string(tx.vin.size()) + " inputs and " + 
                std::to_string(tx.vout.size()) + " outputs" +
                (tx.tokenMetadata.empty() ? "" : " and metadata"));
    
    return tx;
}
// -----------------------------------------------------------------------------
//                    A minimal Merkle root for demonstration
// -----------------------------------------------------------------------------
std::string computeMerkleRoot(const std::vector<Transaction> &txs) {
    if (txs.empty()) {
        return doubleSha256("");
    }
    // For each TX => use tx.txid
    std::vector<std::string> layer;
    layer.reserve(txs.size());
    for(const auto &tx : txs) {
        layer.push_back(tx.txid);
    }
    while(layer.size() > 1) {
        if(layer.size() & 1) {
            layer.push_back(layer.back());
        }
        std::vector<std::string> newLayer;
        newLayer.reserve(layer.size()/2);
        for(size_t i=0; i<layer.size(); i+=2) {
            std::string combined = layer[i] + layer[i+1];
            newLayer.push_back(doubleSha256(combined));
        }
        layer.swap(newLayer);
    }
    return layer[0];
}

// -----------------------------------
// Some minimal binary serialize logic
// -----------------------------------
static void writeVarInt(std::vector<unsigned char> &buf, uint64_t val) {
    if(val < 0xFD) {
        buf.push_back(static_cast<unsigned char>(val));
    } else if(val <= 0xFFFF) {
        buf.push_back(0xFD);
        buf.push_back((unsigned char)(val & 0xff));
        buf.push_back((unsigned char)((val >> 8) & 0xff));
    } else {
        throw std::runtime_error("writeVarInt too large for demo");
    }
}
static void write32LE(std::vector<unsigned char> &buf, uint32_t val) {
    buf.push_back((unsigned char)( val        & 0xff));
    buf.push_back((unsigned char)((val >>  8) & 0xff));
    buf.push_back((unsigned char)((val >> 16) & 0xff));
    buf.push_back((unsigned char)((val >> 24) & 0xff));
}
static void write64LE(std::vector<unsigned char> &buf, uint64_t val) {
    for(int i=0; i<8; i++){
        buf.push_back((unsigned char)(val & 0xff));
        val >>= 8;
    }
}
static uint32_t read32LE(const std::vector<unsigned char> &raw, size_t &pos);
static uint64_t read64LE(const std::vector<unsigned char> &raw, size_t &pos);
static uint64_t readVarInt(const std::vector<unsigned char> &raw, size_t &pos);
//___________________________________________________________________
//       TX SERIALIZE BIANARY
//___________________________________________________________________
std::vector<unsigned char> Transaction::serializeBinary() const {
    Logger::log("[serializeBinary] Serializing transaction: " + txid);
    std::vector<unsigned char> out;

    // Write version
    write32LE(out, version);
    Logger::log("[serializeBinary] Version written: " + std::to_string(version));

    // Write number of inputs
    writeVarInt(out, vin.size());
    Logger::log("[serializeBinary] Number of inputs: " + std::to_string(vin.size()));

    // Serialize inputs
    for (size_t i = 0; i < vin.size(); ++i) {
        const auto &in = vin[i];
        if (isCoinbase) {
            // For coinbase, txid is 32 bytes of 0x00
            std::vector<unsigned char> zeroTxid(32, 0x00);
            out.insert(out.end(), zeroTxid.begin(), zeroTxid.end());
            Logger::log("[serializeBinary] Input #" + std::to_string(i) + " txid written: 32 bytes of 0x00 (coinbase)");
        } else {
            // Write txid (big-endian, no reverse)
            auto txidBytes = hexDecode(in.txid);
            if (txidBytes.size() != 32) {
                Logger::log("[serializeBinary] ERROR: Invalid txid length for input #" + std::to_string(i));
                throw std::runtime_error("Invalid txid length");
            }
            out.insert(out.end(), txidBytes.begin(), txidBytes.end());
            Logger::log("[serializeBinary] Input #" + std::to_string(i) + " txid written: " + in.txid);
        }    
        // Write vout
        write32LE(out, in.vout);
        Logger::log("[serializeBinary] Input #" + std::to_string(i) + " vout written: " + std::to_string(in.vout));

        // Write scriptSig (length-prefixed)
        writeVarInt(out, in.scriptSig.size());
        out.insert(out.end(), in.scriptSig.begin(), in.scriptSig.end());
        Logger::log("[serializeBinary] Input #" + std::to_string(i) + " scriptSig written: " + hexEncode(in.scriptSig));

        // Write sequence
        write32LE(out, in.sequence);
        Logger::log("[serializeBinary] Input #" + std::to_string(i) + " sequence written: " + std::to_string(in.sequence));
    }

    // Write number of outputs
    writeVarInt(out, vout.size());
    Logger::log("[serializeBinary] Number of outputs: " + std::to_string(vout.size()));

    // Serialize outputs
    for (size_t i = 0; i < vout.size(); ++i) {
        const auto &o = vout[i];
        write64LE(out, o.amount);
        Logger::log("[serializeBinary] Output #" + std::to_string(i) + " amount written: " + std::to_string(o.amount));

        // Convert scriptPubKey from hex string to bytes (if stored as hex)
        std::vector<unsigned char> spk = hexDecode(o.scriptPubKey);
        writeVarInt(out, spk.size());
        out.insert(out.end(), spk.begin(), spk.end());
        Logger::log("[serializeBinary] Output #" + std::to_string(i) + " scriptPubKey written: " + hexEncode(spk));
    }

    // Write lockTime
    write32LE(out, lockTime);
    Logger::log("[serializeBinary] Lock time written: " + std::to_string(lockTime));

    // NEW: Write token metadata
    if (!tokenMetadata.empty()) {
        // Write metadata flag (1 = has metadata)
        out.push_back(1);
        
        // Serialize metadata as JSON string
        nlohmann::json metaJson(tokenMetadata);
        std::string metaStr = metaJson.dump();
        
        // Write metadata length
        writeVarInt(out, metaStr.size());
        
        // Write metadata
        out.insert(out.end(), metaStr.begin(), metaStr.end());
        Logger::log("[serializeBinary] Token metadata written: " + std::to_string(metaStr.size()) + " bytes");
    } else {
        // Write metadata flag (0 = no metadata)
        out.push_back(0);
        Logger::log("[serializeBinary] No token metadata");
    }

    Logger::log("[serializeBinary] Serialization complete for transaction: " + txid);
    return out;
}
//___________________________________________________________________
//       TX DESERIALIZE BIANARY
//___________________________________________________________________
Transaction Transaction::deserializeBinary(const std::vector<unsigned char>& bytes) {
    Transaction tx;
    size_t pos = 0;
    Logger::log("[deserializeBinary] Starting deserialization, total bytes=" + std::to_string(bytes.size()));

    // Version (little-endian)
    tx.version = read32LE(bytes, pos);
    Logger::log("[deserializeBinary] Version=" + std::to_string(tx.version) + ", pos=" + std::to_string(pos));

    // Inputs
    uint64_t vinCount = readVarInt(bytes, pos);
    Logger::log("[deserializeBinary] vinCount=" + std::to_string(vinCount) + ", pos=" + std::to_string(pos));
    for (uint64_t i = 0; i < vinCount; i++) {
        TxIn in;
        if (pos + 32 > bytes.size()) throw std::runtime_error("Invalid transaction: incomplete txid");
        // Read txid as big-endian (no reverse)
        std::vector<unsigned char> txidBytes(bytes.begin() + pos, bytes.begin() + pos + 32);
        in.txid = hexEncode(txidBytes);  // Directly encode to hex without reversing
        pos += 32;
        Logger::log("[deserializeBinary] Input " + std::to_string(i) + " txid=" + in.txid + ", pos=" + std::to_string(pos));

        // Check if this is a coinbase input
        if (std::all_of(txidBytes.begin(), txidBytes.end(), [](unsigned char b) { return b == 0; })) {
            tx.isCoinbase = true;
        }

        // Read vout (little-endian)
        in.vout = read32LE(bytes, pos);
        Logger::log("[deserializeBinary] Input " + std::to_string(i) + " vout=" + std::to_string(in.vout) + ", pos=" + std::to_string(pos));

        // Read scriptSig
        uint64_t scriptLen = readVarInt(bytes, pos);
        Logger::log("[deserializeBinary] Input " + std::to_string(i) + " scriptSig length=" + std::to_string(scriptLen) + ", pos=" + std::to_string(pos));
        if (pos + scriptLen > bytes.size()) throw std::runtime_error("Invalid transaction: incomplete scriptSig");
        in.scriptSig.assign(bytes.begin() + pos, bytes.begin() + pos + scriptLen);
        pos += scriptLen;
        Logger::log("[deserializeBinary] Input " + std::to_string(i) + " scriptSig hex=" + hexEncode(in.scriptSig) + ", pos=" + std::to_string(pos));

        // Read sequence (little-endian)
        in.sequence = read32LE(bytes, pos);
        Logger::log("[deserializeBinary] Input " + std::to_string(i) + " sequence=" + std::to_string(in.sequence) + ", pos=" + std::to_string(pos));

        tx.vin.push_back(in);
    }

    // Outputs
    uint64_t voutCount = readVarInt(bytes, pos);
    Logger::log("[deserializeBinary] voutCount=" + std::to_string(voutCount) + ", pos=" + std::to_string(pos));
    for (uint64_t i = 0; i < voutCount; i++) {
        TxOut out;
        // Read amount (little-endian)
        out.amount = read64LE(bytes, pos);
        Logger::log("[deserializeBinary] Output " + std::to_string(i) + " amount=" + std::to_string(out.amount) + ", pos=" + std::to_string(pos));

        // Read scriptPubKey
        uint64_t scriptLen = readVarInt(bytes, pos);
        Logger::log("[deserializeBinary] Output " + std::to_string(i) + " scriptPubKey length=" + std::to_string(scriptLen) + ", pos=" + std::to_string(pos));
        if (pos + scriptLen > bytes.size()) throw std::runtime_error("Invalid transaction: incomplete scriptPubKey");
        std::vector<unsigned char> spkBytes(bytes.begin() + pos, bytes.begin() + pos + scriptLen);
        out.scriptPubKey = hexEncode(spkBytes);
        pos += scriptLen;
        Logger::log("[deserializeBinary] Output " + std::to_string(i) + " scriptPubKey=" + out.scriptPubKey + ", pos=" + std::to_string(pos));

        tx.vout.push_back(out);
    }

    // Lock time (little-endian)
    tx.lockTime = read32LE(bytes, pos);
    Logger::log("[deserializeBinary] Lock time=" + std::to_string(tx.lockTime) + ", pos=" + std::to_string(pos));

    // NEW: Read token metadata
    if (pos < bytes.size()) {
        uint8_t hasMetadata = bytes[pos++];
        Logger::log("[deserializeBinary] Metadata flag=" + std::to_string(hasMetadata) + ", pos=" + std::to_string(pos));
        
        if (hasMetadata == 1) {
            uint64_t metaLen = readVarInt(bytes, pos);
            Logger::log("[deserializeBinary] Metadata length=" + std::to_string(metaLen) + ", pos=" + std::to_string(pos));
            
            if (pos + metaLen <= bytes.size()) {
                std::string metaStr(bytes.begin() + pos, bytes.begin() + pos + metaLen);
                pos += metaLen;
                
                try {
                    nlohmann::json metaJson = nlohmann::json::parse(metaStr);
                    tx.tokenMetadata = metaJson.get<std::unordered_map<std::string, nlohmann::json>>();
                    Logger::log("[deserializeBinary] Token metadata parsed successfully, entries=" + 
                              std::to_string(tx.tokenMetadata.size()));
                } catch (const std::exception& e) {
                    Logger::log("[deserializeBinary] Failed to parse token metadata: " + std::string(e.what()));
                }
            } else {
                Logger::log("[deserializeBinary] Metadata extends beyond transaction data");
            }
        }
    }

    return tx;
}
//________________________________________________________________
//
//________________________________________________________________
static uint32_t read32LE(const std::vector<unsigned char> &raw, size_t &pos)
{
    if(pos+4>raw.size()) throw std::runtime_error("read32LE out of range");
    uint32_t val = (uint32_t)raw[pos] 
                 | ((uint32_t)raw[pos+1]<<8)
                 | ((uint32_t)raw[pos+2]<<16)
                 | ((uint32_t)raw[pos+3]<<24);
    pos+=4;
    return val;
}
//________________________________________________________________
//
//________________________________________________________________
static uint64_t read64LE(const std::vector<unsigned char> &raw, size_t &pos)
{
    if(pos+8>raw.size()) throw std::runtime_error("read64LE out of range");
    uint64_t val=0;
    for(int i=0; i<8; i++){
        val |= ((uint64_t)raw[pos+i])<<(8*i);
    }
    pos+=8;
    return val;
}
//________________________________________________________________
//
//________________________________________________________________
static uint64_t readVarInt(const std::vector<unsigned char> &raw, size_t &pos) {
    if (pos >= raw.size()) throw std::runtime_error("readVarInt: out of range");
    unsigned char c = raw[pos++];
    if (c < 0xFD) {
        return c;
    } else if (c == 0xFD) {
        if (pos + 2 > raw.size()) throw std::runtime_error("readVarInt[0xFD]: out of range");
        uint16_t val = (uint16_t)raw[pos] | ((uint16_t)raw[pos + 1] << 8);
        pos += 2;
        return val;
    } else if (c == 0xFE) {
        if (pos + 4 > raw.size()) throw std::runtime_error("readVarInt[0xFE]: out of range");
        // AUDIT-REMEDIATION-01 / Track 01: read32LE advances pos.
        // Do not advance the cursor a second time here.
        uint32_t val = read32LE(raw, pos);
        return val;
    } else if (c == 0xFF) {
        if (pos + 8 > raw.size()) throw std::runtime_error("readVarInt[0xFF]: out of range");
        // AUDIT-REMEDIATION-01 / Track 01: read64LE advances pos.
        // Do not advance the cursor a second time here.
        uint64_t val = read64LE(raw, pos);
        return val;
    }
    throw std::runtime_error("Invalid varint prefix");
}
//________________________________________________________________
//
//________________________________________________________________
std::vector<unsigned char> Transaction::getSigHash(size_t inputIndex, const std::vector<unsigned char>& scriptPubKey) const {
    if (inputIndex >= vin.size()) {
        Logger::log("[Transaction::getSigHash] ERROR: Index out of range: " + std::to_string(inputIndex));
        throw std::runtime_error("[Transaction::getSigHash] Index out of range: " + std::to_string(inputIndex));
    }

    // Create a temporary copy of the transaction
    Transaction tempTx = *this;
    Logger::log("[getSigHash] Created tempTx for input #" + std::to_string(inputIndex));

    // Clear all scriptSig fields and pubKey fields in inputs
    for (size_t i = 0; i < tempTx.vin.size(); ++i) {
        tempTx.vin[i].scriptSig.clear();
        tempTx.vin[i].pubKey.clear(); // Ensure pubKey doesn’t affect serialization
        Logger::log("[getSigHash] Cleared scriptSig and pubKey for input #" + std::to_string(i));
    }

    // Set the scriptSig of the input being signed to the scriptPubKey
    tempTx.vin[inputIndex].scriptSig = scriptPubKey;
    Logger::log("[getSigHash] Set scriptSig for input #" + std::to_string(inputIndex) + " to scriptPubKey: " + hexEncode(scriptPubKey));

    // Serialize the modified transaction
    std::vector<unsigned char> serialized = tempTx.serializeBinary();
    Logger::log("[getSigHash] Serialized TX for sighash: " + hexEncode(serialized));

    // Append SIGHASH_ALL (0x01) as 4 bytes little-endian (0x01000000)
    serialized.push_back(0x01);
    serialized.push_back(0x00);
    serialized.push_back(0x00);
    serialized.push_back(0x00);
    Logger::log("[getSigHash] Appended SIGHASH_ALL (0x01000000)");

    // Compute double SHA256
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(serialized.data(), serialized.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    std::vector<unsigned char> sighash(hash2, hash2 + SHA256_DIGEST_LENGTH);

    Logger::log("[getSigHash] Computed sighash for input #" + std::to_string(inputIndex) + ": " + hexEncode(sighash));
    return sighash;
}
