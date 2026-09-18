#include "wallet.h"
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sodium.h>
#include "wallet_encryption_v1.h"
#include "hdwallet.h"          
#include "utils.h"             
#include "tokens.h"
#include "token_burn_v1.h"  // TOKEN-BURN-01 non-consensus retirement sink
#include "globals.h"
#include "address_helpers.h"
#include "logging.h"
#include "mempool.h"
#include "tru_limits.h"
#include "crypto_ecdsa.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <wally_core.h>
#include <wally_bip32.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_transaction.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <mutex>
#include <cassert>
#include <cctype>
#include <limits>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include "rpc_utils.h"
#include "wallet_cli.h"   
#include "blockchain.h"   

#include "script_interpreter.h"  
#include <wally_core.h>
#include <wally_address.h> 
#define HASH160_LEN 20  
#include <nlohmann/json.hpp>
#include <ctime>
#include "tru_network_params.h"
#include "tru_amount.h"
#include "contract_call_policy.h"  // canonical Multisig + HTLC V1 builders
#include "tru_swap_prepared_funding_guard.h"  // SWAP GROUP-01 durable input reservation
#include <leveldb/write_batch.h>

using json = nlohmann::json;

// ============================================================================
// TRU SWAP GROUP-01 — durable local prepared-funding reservation helpers.
// These keys are local wallet/node policy state and are not consensus state.
// ============================================================================
static std::string swapPreparedChecksummedValue(
    LevelDBStorage& storage,
    const json& value)
{
    const std::string payload = value.dump();
    return storage.computeDataChecksum(payload) + "|" + payload;
}

static bool loadSwapPreparedFundingRecord(
    LevelDBStorage* storage,
    const std::string& operationId,
    json& out)
{
    out = json{};
    if (!storage ||
        !tru_swap_prepared_funding::isLowerHex64(operationId)) {
        return false;
    }
    std::string payload;
    if (!storage->getWithDataChecksum(
            tru_swap_prepared_funding::opKey(operationId), payload)) {
        return false;
    }
    try {
        out = json::parse(payload);
    } catch (...) {
        throw std::runtime_error(
            "Prepared funding record JSON is corrupt for operationId");
    }
    if (out.value("version", std::string{}) !=
            tru_swap_prepared_funding::RECORD_VERSION ||
        out.value("operationId", std::string{}) != operationId) {
        throw std::runtime_error(
            "Prepared funding record identity/version mismatch");
    }
    return true;
}

static std::vector<std::pair<std::string, std::uint32_t>>
swapPreparedFundingInputs(const json& record)
{
    std::vector<std::pair<std::string, std::uint32_t>> out;
    if (!record.contains("reservedInputs") ||
        !record.at("reservedInputs").is_array()) {
        throw std::runtime_error("Prepared funding reservedInputs missing");
    }
    for (const auto& item : record.at("reservedInputs")) {
        const std::string txid = item.value("txid", std::string{});
        if (!tru_swap_prepared_funding::isLowerHex64(txid) ||
            !item.contains("vout") || !item.at("vout").is_number_unsigned()) {
            throw std::runtime_error("Prepared funding reserved input malformed");
        }
        const std::uint64_t vout64 = item.at("vout").get<std::uint64_t>();
        if (vout64 > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("Prepared funding reserved vout overflow");
        }
        out.emplace_back(txid, static_cast<std::uint32_t>(vout64));
    }
    if (out.empty()) {
        throw std::runtime_error("Prepared funding has no reserved inputs");
    }
    return out;
}

static bool swapPreparedFundingReservationIntact(
    LevelDBStorage* storage,
    const json& record)
{
    if (!storage) return false;
    const std::string operationId =
        record.value("operationId", std::string{});
    const std::string preparedTxid =
        record.value("preparedTxid", std::string{});
    const std::string rawTxSha256 =
        record.value("rawTxSha256", std::string{});
    if (!tru_swap_prepared_funding::isLowerHex64(operationId) ||
        !tru_swap_prepared_funding::isLowerHex64(preparedTxid) ||
        !tru_swap_prepared_funding::isLowerHex64(rawTxSha256)) {
        return false;
    }
    for (const auto& input : swapPreparedFundingInputs(record)) {
        std::string payload;
        if (!storage->getWithDataChecksum(
                tru_swap_prepared_funding::inputKey(
                    input.first, input.second),
                payload)) {
            return false;
        }
        std::string op, txid, rawHash;
        if (!tru_swap_prepared_funding::parseInputMarker(
                payload, op, txid, rawHash) ||
            op != operationId ||
            txid != preparedTxid ||
            rawHash != rawTxSha256) {
            return false;
        }
    }
    return true;
}

static bool isSwapPreparedFundingInputReserved(
    LevelDBStorage* storage,
    const std::string& txid,
    std::uint32_t vout)
{
    if (!storage) return false;
    std::string payload;
    return storage->getWithDataChecksum(
        tru_swap_prepared_funding::inputKey(txid, vout), payload);
}

static std::vector<std::string> splitString(const std::string &s, char delim) {
    std::vector<std::string> elems;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

static inline bool parseContractOutpoint(const std::string& addr, std::string& txidOut, uint32_t& voutOut) {
    auto p = addr.find(':');
    if (p == std::string::npos) return false;
    txidOut = addr.substr(0, p);
    try {
        voutOut = static_cast<uint32_t>(std::stoul(addr.substr(p + 1)));
    } catch (...) { return false; }
    return (txidOut.size() == 64);
}


// ============================================================================
// size-aware wallet fee compatibility
// ============================================================================
// Patch 12B admits unconfirmed transactions only when fee >= serialized bytes
// * MIN_RELAY_FEE_SAT_PER_BYTE. Preserve the historical 10,000-TRU-atom wallet
// minimum, but size large wallet-created transactions before signing.
//
// Canonical P2PKH scriptSigs are roughly 107 bytes. MagicLock unlock scripts
// are larger. Reserving 512 bytes per input avoids a sign/resize/re-sign loop
// while remaining conservative for every current wallet-owned signing path.
static constexpr uint64_t WALLET_MIN_BASE_FEE = 10000ULL;
static constexpr std::size_t WALLET_SIGNING_RESERVE_PER_INPUT = 512;
static constexpr std::size_t WALLET_FEE_FIXED_RESERVE_BYTES = 64;
static constexpr std::size_t WALLET_NO_FEE_BEARING_VOUT =
    std::numeric_limits<std::size_t>::max();

static constexpr uint32_t TOKEN_MAX_DECIMALS_V1 = 18U;

// TOKEN-AI-01A — token supply scaling is integer-only.
// Token amounts are consensus-adjacent uint64 values and must never pass
// through floating point.  Keep native issuance byte-for-byte deterministic
// with the browser BigInt path.
static uint64_t scaleTokenSupplyToAtomsV1(
    uint64_t totalSupply,
    uint32_t decimals)
{
    if (totalSupply == 0U) {
        throw std::invalid_argument("Token supply must be greater than zero");
    }
    if (decimals > TOKEN_MAX_DECIMALS_V1) {
        throw std::invalid_argument("Token decimals must be between 0 and 18");
    }

    uint64_t scale = 1U;
    for (uint32_t i = 0; i < decimals; ++i) {
        if (scale > std::numeric_limits<uint64_t>::max() / 10U) {
            throw std::overflow_error("Token decimal scale overflow");
        }
        scale *= 10U;
    }

    if (totalSupply > std::numeric_limits<uint64_t>::max() / scale) {
        throw std::overflow_error("Token supply exceeds uint64 atom range");
    }
    return totalSupply * scale;
}

static uint64_t estimateWalletPolicyFee(const Transaction& tx) {
    const std::size_t rawUnsignedBytes = tx.serializeBinary().size();

    if (rawUnsignedBytes >
        std::numeric_limits<std::size_t>::max() -
            WALLET_FEE_FIXED_RESERVE_BYTES) {
        throw std::runtime_error("Wallet fee estimate size overflow");
    }
    const std::size_t fixedBytes =
        rawUnsignedBytes + WALLET_FEE_FIXED_RESERVE_BYTES;

    if (tx.vin.size() >
        (std::numeric_limits<std::size_t>::max() - fixedBytes) /
            WALLET_SIGNING_RESERVE_PER_INPUT) {
        throw std::runtime_error(
            "Wallet fee estimate overflow: too many transaction inputs");
    }

    const std::size_t estimatedSignedBytes =
        fixedBytes +
        tx.vin.size() * WALLET_SIGNING_RESERVE_PER_INPUT;

    if (tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE == 0) {
        return WALLET_MIN_BASE_FEE;
    }
    if (estimatedSignedBytes >
        static_cast<std::size_t>(
            tru_limits::MAX_MONEY /
            tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE)) {
        throw std::runtime_error("Wallet fee estimate exceeds MAX_MONEY");
    }

    const uint64_t policyFee =
        static_cast<uint64_t>(estimatedSignedBytes) *
        tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE;
    return std::max<uint64_t>(WALLET_MIN_BASE_FEE, policyFee);
}

// canonical Hash Lock helpers.
static bool parseCanonicalHashLockScriptHex(
    const std::string& scriptHex,
    std::string* expectedHash160Hex = nullptr)
{
    std::vector<unsigned char> script;
    try {
        script = hexDecode(scriptHex);
    } catch (...) {
        return false;
    }

    if (script.size() != 23 ||
        script[0] != OP_HASH160 ||
        script[1] != 0x14 ||
        script[22] != OP_EQUAL) {
        return false;
    }

    if (expectedHash160Hex) {
        *expectedHash160Hex = bytesToHex(
            std::vector<unsigned char>(script.begin() + 2, script.begin() + 22));
        std::transform(
            expectedHash160Hex->begin(),
            expectedHash160Hex->end(),
            expectedHash160Hex->begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
    }
    return true;
}

// canonical Time Lock helper.
// Exact script: 04<4-byte little-endian unix time>b17576a914<20-byte HASH160>88ac
static bool parseCanonicalTimeLockScriptHex(
    const std::string& scriptHex,
    uint32_t* lockTimeOut = nullptr,
    std::string* ownerHash160Hex = nullptr)
{
    std::vector<unsigned char> script;
    try {
        script = hexDecode(scriptHex);
    } catch (...) {
        return false;
    }

    if (script.size() != 32 ||
        script[0] != 0x04 ||
        script[5] != OP_CHECKLOCKTIMEVERIFY ||
        script[6] != OP_DROP ||
        script[7] != OP_DUP ||
        script[8] != OP_HASH160 ||
        script[9] != 0x14 ||
        script[30] != OP_EQUALVERIFY ||
        script[31] != OP_CHECKSIG) {
        return false;
    }

    if (lockTimeOut) {
        *lockTimeOut =
            static_cast<uint32_t>(script[1]) |
            (static_cast<uint32_t>(script[2]) << 8) |
            (static_cast<uint32_t>(script[3]) << 16) |
            (static_cast<uint32_t>(script[4]) << 24);
    }
    if (ownerHash160Hex) {
        *ownerHash160Hex = bytesToHex(
            std::vector<unsigned char>(script.begin() + 10, script.begin() + 30));
        std::transform(
            ownerHash160Hex->begin(), ownerHash160Hex->end(),
            ownerHash160Hex->begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
    }
    return true;
}

static uint32_t getWalletChainMedianTimePast(const Blockchain& chain)
{
    std::string tipHash;
    int tipHeight = -1;
    chain.getBestTipSnapshot(tipHash, tipHeight);
    if (tipHeight < 0 || tipHash.empty()) {
        throw std::runtime_error("No active chain tip for MTP");
    }
    if (tipHeight == std::numeric_limits<int>::max()) {
        throw std::runtime_error("Next execution height exceeds int range");
    }
    return chain.getMedianTimePast(tipHash, tipHeight + 1);
}

static std::string hashLockPreimageHash160Hex(const std::string& preimage)
{
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(
        reinterpret_cast<const unsigned char*>(preimage.data()),
        preimage.size(),
        sha);

    unsigned char ripe[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, ripe);

    std::string out = bytesToHex(
        std::vector<unsigned char>(ripe, ripe + RIPEMD160_DIGEST_LENGTH));
    std::transform(
        out.begin(), out.end(), out.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return out;
}

// HTLC-01C: HASH160 over exact binary preimage bytes. Atomic-swap secrets are
// byte strings, not locale/text values, so the generated path keeps the raw
// 32-byte preimage intact and only hex-encodes it for operator transport.
static std::string htlcPreimageHash160Hex(
    const std::vector<unsigned char>& preimage)
{
    if (preimage.empty()) {
        throw std::invalid_argument("HTLC preimage must not be empty");
    }

    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(preimage.data(), preimage.size(), sha);

    unsigned char ripe[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha, SHA256_DIGEST_LENGTH, ripe);

    std::string out = bytesToHex(
        std::vector<unsigned char>(ripe, ripe + RIPEMD160_DIGEST_LENGTH));
    std::transform(
        out.begin(), out.end(), out.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return out;
}

static void appendHashLockPreimagePush(
    std::vector<unsigned char>& scriptSig,
    const std::vector<unsigned char>& preimage)
{
    const std::size_t len = preimage.size();
    if (len <= 0x4b) {
        scriptSig.push_back(static_cast<unsigned char>(len));
    } else if (len <= 0xff) {
        scriptSig.push_back(OP_PUSHDATA1);
        scriptSig.push_back(static_cast<unsigned char>(len));
    } else {
        throw std::runtime_error(
            "Hash Lock preimage exceeds the supported one-byte PUSHDATA1 length");
    }
    scriptSig.insert(scriptSig.end(), preimage.begin(), preimage.end());
}

static uint64_t applyWalletPolicyFee(
    Transaction& tx,
    uint64_t currentFee,
    std::size_t feeBearingVout,
    const char* context)
{
    const uint64_t requiredFee = estimateWalletPolicyFee(tx);
    if (requiredFee <= currentFee) {
        Logger::log(
            std::string("[Patch12B.1] ") + context +
            " fee=" + std::to_string(currentFee) +
            " already satisfies size-aware policy");
        return currentFee;
    }

    const uint64_t delta = requiredFee - currentFee;
    if (feeBearingVout == WALLET_NO_FEE_BEARING_VOUT ||
        feeBearingVout >= tx.vout.size()) {
        throw std::runtime_error(
            std::string(context) +
            ": transaction requires a larger size-aware fee but has no "
            "change/fee-bearing output; select a larger funding UTXO");
    }
    if (tx.vout[feeBearingVout].amount <= delta) {
        throw std::runtime_error(
            std::string(context) +
            ": change/output value is insufficient for the size-aware fee; "
            "select a larger funding UTXO");
    }

    const std::string oldTxid = tx.txid;
    bool metadataWasKeyedByOldTxid = false;
    nlohmann::json metadataForRekey;
    if (!oldTxid.empty()) {
        const auto metaIt = tx.tokenMetadata.find(oldTxid);
        if (metaIt != tx.tokenMetadata.end()) {
            metadataWasKeyedByOldTxid = true;
            metadataForRekey = metaIt->second;
        }
    }

    tx.vout[feeBearingVout].amount -= delta;

    // Fee adjustment changes a committed output and therefore the txid.
    if (!oldTxid.empty()) {
        tx.computeTxId();
        if (metadataWasKeyedByOldTxid && tx.txid != oldTxid) {
            tx.tokenMetadata.erase(oldTxid);
            tx.tokenMetadata[tx.txid] = metadataForRekey;
        }
    }

    Logger::log(
        std::string("[Patch12B.1] ") + context +
        " raised wallet fee from " + std::to_string(currentFee) +
        " to " + std::to_string(requiredFee) +
        " TRU atoms; delta=" + std::to_string(delta));
    return requiredFee;
}

//=============================================================================
//                      Overload for PrivKey
//=============================================================================
std::string Wallet::getPrivateKeyForAddress(const std::string &addr) const {
    // Forward through const_cast to reuse the existing implementation
    return const_cast<Wallet*>(this)->getPrivateKeyForAddress(addr);
}

//=============================================================================
//			Get PubKey
//=============================================================================
std::vector<unsigned char> Wallet::getPublicKeyForAddress(const std::string& address) const {
    // 1) Fetch private key PEM for this Base58 P2PKH address (now const-safe)
    std::string privPem = getPrivateKeyForAddress(address);
    if (privPem.empty()) {
        throw std::runtime_error("getPublicKeyForAddress: no private key found for " + address);
    }

    // 2) Build ECDSA key from PEM (secp256k1)
    ECDSAKey key = ECDSAKey::fromPrivateKey(privPem);

    // 3) Prefer compressed SEC1
    std::vector<unsigned char> pubCompressed = key.getCompressedSec1();
    try {
        if (doesPubKeyMatchAddress(pubCompressed, address)) {
            return pubCompressed;
        }
    } catch (const std::exception& e) {
        Logger::log(std::string("[getPublicKeyForAddress] compressed match check threw: ") + e.what());
    }

    // 4) Fallback to uncompressed SEC1 for legacy addresses
    std::vector<unsigned char> pubUncompressed = key.getUncompressedSec1();
    try {
        if (doesPubKeyMatchAddress(pubUncompressed, address)) {
            return pubUncompressed;
        }
    } catch (const std::exception& e) {
        Logger::log(std::string("[getPublicKeyForAddress] uncompressed match check threw: ") + e.what());
    }

    // 5) Neither matched => keystore/address mismatch
    Logger::log("[getPublicKeyForAddress] ERROR: computed pubkey does not match address " + address);
    throw std::runtime_error("getPublicKeyForAddress: derived public key does not match address " + address);
}

//=============================================================================
//			Wallet Helper
//=============================================================================
bool Wallet::hasMatchingPublicKeyForAddress(const std::string& address) const {
    try {
        (void)getPublicKeyForAddress(address);
        return true;
    } catch (...) {
        return false;
    }
}

//============================================================================
//			Create Social Post
//============================================================================
Transaction Wallet::createSocialPostTransaction(const std::string& senderAddress, 
                                       const std::string& content, 
                                       const std::vector<std::string>& mediaUrls, 
                                       const std::string& privateKey) {
    Transaction tx;
    
    // Derive public key from private key
    ECDSAKey key = ECDSAKey::fromPrivateKey(privateKey);
    std::vector<unsigned char> pubkeyBytes = key.getCompressedSec1();
    std::string pubkey = bytesToHex(pubkeyBytes);  // Convert to hex string

    // Prepare data to sign (example: concatenate content and media URLs)
    std::string dataToSign = senderAddress + content;
    for (const auto& url : mediaUrls) {
        dataToSign += url;
    }

    // Sign the data
    std::vector<unsigned char> signatureBytes = key.sign(dataToSign);
    std::string signature = bytesToHex(signatureBytes);

    // Create OP_RETURN data (example payload)
    std::string opReturnData = "social:" + pubkey + ":" + signature + ":" + content;
    std::vector<unsigned char> opReturnBytes(opReturnData.begin(), opReturnData.end());
    
    // Encode OP_RETURN script
    std::string opReturnHex = "6a" + varIntEncode(opReturnData.size()) + bytesToHex(opReturnBytes);

    // Populate transaction
    tx.vin = {};  // Add real inputs as needed
    tx.vout.push_back({0, opReturnHex});  // OP_RETURN output
    tx.sender = senderAddress;  // Use sender instead of senderAddress

    return tx;
}
//=============================================================================
//                              Get address w/ Balance
//=============================================================================
std::vector<std::pair<std::string,double>> Wallet::getAddressesWithBalance() const {
    std::lock_guard<std::mutex> lk(addressesMutex);
    std::vector<std::pair<std::string,double>> out;
    for (const auto &addr : addresses) {
        double bal = blockchainPtr
            ? blockchainPtr->calculate_balance(addr)
            : 0.0;
        out.emplace_back(addr, bal);
    }
    return out;
}

//=============================================================================
//                              Gererate Private KEY
//=============================================================================
void Wallet::addKeyPair(const std::string& privateKeyPEM, const std::string& address) {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        throw std::runtime_error(
            "[SEC-14E.3.3B] encrypted wallet mutation refused until authenticated persistence is active");
    }

    requirePrivateAccess("addKeyPair");
    bool added = false;
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
            addresses.push_back(address);
            privateKeys[address] = privateKeyPEM;
            added = true;
            Logger::log("[addKeyPair] Imported " + address);
        }
    }
    if (added) {
        saveToFile(walletFilePath);
    }
}

//=============================================================================
//				Gererate Derministic Visual
//=============================================================================

std::string Wallet::generateDeterministicVisual(const std::string& id, const std::string& imageUrl) {
    // Concatenate id and imageUrl to create a unique input
    std::string input = id + imageUrl;

    // Compute SHA256 hash of the input
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    // Generate a hex color code using the first 3 bytes of the hash as RGB values
    std::string colorHex = fmt::format("#{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2]);
    
    return colorHex;
}
//=============================================================================
//			Import Priv Keys
//=============================================================================
std::string Wallet::importPrivateKey(const std::string& privKeyHex) {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        throw std::runtime_error(
            "[SEC-14E.3.3B] encrypted wallet mutation refused until authenticated persistence is active");
    }

    requirePrivateAccess("importPrivateKey");
    try {
        // Convert hex to binary
        std::vector<unsigned char> privKeyBytes = hexDecode(privKeyHex);
        // Create ECDSA key from private key bytes
        ECDSAKey key = ECDSAKey::fromRawBytes(privKeyBytes);
        // Get the compressed public key
        std::vector<unsigned char> pubKey = key.getCompressedSec1();
        // Generate the address from the public key
        std::string address = pubkeyToAddress(pubKey);
        // Add the address to the wallet's address list
        addresses.push_back(address);
        // Store the private key securely (e.g., in a map)
        privateKeys[address] = privKeyHex; // Assuming privateKeys is a map<std::string, std::string>
        Logger::log("[Wallet] Imported private key for address: " + address);
        return address;
    } catch (const std::exception& e) {
        Logger::log("[Wallet] Failed to import private key: " + std::string(e.what()));
        throw;
    }
}
//=============================================================================
//                           RPC GET UTXO VALUE
//=============================================================================

uint64_t Wallet::rpcGetUtxoValue(const std::string &nodeIP,
                                 int nodePort,
                                 const std::string &txid,
                                 uint32_t vout) const {
    std::string address = getCurrentAddress();
    auto utxos = rpcListUnspent(nodeIP, nodePort, address);
    for (const auto &u : utxos) {
        if (u.txid == txid && u.vout == vout) {
            return u.amount;
        }
    }
    throw std::runtime_error("[rpcGetUtxoValue] UTXO not found => " + txid + ":" + std::to_string(vout));
}
//--------------------------------------------------------------------
//	 LIST TOKENS
//--------------------------------------------------------------------
std::string Wallet::listMyTokensFancy() const {
    if (!isLocalChain || !blockchainPtr) {
        return "[listMyTokensFancy] Not in local chain mode => cannot list tokens.";
    }

    struct TokenEntry {
        TokenType type;
        uint64_t totalAmount;
        ExtendedTokenData example;
    };
    std::unordered_map<std::string, TokenEntry> tokenMap;

    blockchainPtr->utxoSet.iterateAll(
        [&](const std::string& key, const std::string& value) {
            size_t delim = value.rfind('|');
            if (delim == std::string::npos) return;

            std::string scriptPubKey = value.substr(delim + 1);
            ExtendedTokenData td;
            std::string owner;
            std::string txid = key.substr(0, key.find(':'));
            if (!parseExtendedTokenScript(scriptPubKey, txid, td, owner, blockchainPtr)) {
                return;
            }
            if (td.type == TokenType::NONE) {
                return;
            }

            auto itAddr = std::find(addresses.begin(), addresses.end(), owner);
            if (itAddr == addresses.end()) {
                return;
            }

            auto itTok = tokenMap.find(td.tokenID);
            if (itTok == tokenMap.end()) {
                TokenEntry e;
                e.type = td.type;
                e.totalAmount = td.amount;
                e.example = td;
                tokenMap[td.tokenID] = e;
            } else {
                itTok->second.totalAmount += td.amount;
            }
        });

    if (tokenMap.empty()) {
        return "No tokens owned by this wallet.\n";
    }

    std::ostringstream oss;
    oss << fmt::format("{:═^70}\n", " MY TOKENS ");
    oss << fmt::format("  {:<20} | {:<6} | {:>10}\n", "TokenID", "Type", "Owned");
    oss << fmt::format("{:─^70}\n", "");

    for (const auto& [tokenID, entry] : tokenMap) {
        const TokenEntry& entryRef = entry;
        const ExtendedTokenData& ex = entryRef.example;

        oss << fmt::format("  {:<20} | {:<6} | {:>10}\n",
                           tokenID,
                           tokenTypeToString(entryRef.type),
                           entryRef.totalAmount);

        oss << "    Metadata:\n";
        if (ex.meta.data.is_null() || ex.meta.data.empty()) {
            oss << "      No metadata available.\n";
        } else {
            for (const auto& item : ex.meta.data.items()) {
                std::string value = item.value().is_string() ? item.value().get<std::string>() : item.value().dump();
                oss << fmt::format("      {:<20}: {}\n", item.key(), value);
            }
        }
        oss << "\n";
    }

    oss << fmt::format("{:═^70}\n", "");
    return oss.str();
}
//--------------------------------------------------------------------
//	Build Op Return Token Script
//--------------------------------------------------------------------
std::string buildOpReturnTokenScript(const ExtendedTokenData &data,
                                     const std::string &ownerAddress)
{
    Logger::log("[buildOpReturnTokenScript] Building for tokenID=" + data.tokenID);
    // 1) Construct the token JSON payload
    nlohmann::json j;
    j["type"]      = tokenTypeToString(data.type);
    j["tokenID"]   = data.tokenID;
    j["amount"]    = data.amount;
    j["meta"]      = data.meta.data;  
    j["owner"]     = ownerAddress;   

    // Convert JSON -> string
    std::string jsonStr = j.dump(); 
    Logger::log("[buildOpReturnTokenScript] JSON: " + jsonStr);
    // Convert JSON string to hex
    std::vector<unsigned char> jsonBytes(jsonStr.begin(), jsonStr.end());
    //std::string jsonHex = bytesToHex(std::string(jsonBytes.begin(), jsonBytes.end()));
    std::string jsonHex = bytesToHex(jsonBytes);

    // Ensure OP_RETURN script format is correct
    std::ostringstream scriptText;
    scriptText << "OP_RETURN " << jsonHex;

    // Compile to bytecode
    std::vector<unsigned char> scriptBytes;
    try {
        scriptBytes = compileTextScript(scriptText.str());
    }
    catch (const std::exception &e) {
        throw std::runtime_error("[buildOpReturnTokenScript] compile error: " + std::string(e.what()));
    }

    //return bytesToHex(std::string(scriptBytes.begin(), scriptBytes.end()));
    return bytesToHex(scriptBytes);
}
//=========================================================================
//           ADD UTXO
//========================================================================
void Wallet::addTokenUTXO(const std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData, std::string>& tokenUtxo) {
    const std::string& txid = std::get<0>(tokenUtxo);
    uint32_t vout = std::get<1>(tokenUtxo);
    std::string key = txid + ":" + std::to_string(vout);
    localTokenUtxos[key] = tokenUtxo;
    Logger::log("[Wallet::addTokenUTXO] Added token UTXO: " + key + " for address: " + std::get<4>(tokenUtxo));
}

const std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData, std::string>>& Wallet::getTokenUTXOs() const {
    return localTokenUtxos;
}

// ---------------------------------------------------------
// Small local helper to parse the *integer* value of a chain UTXO
// from the chain’s "height=NNN|amount|script" format.
// This avoids using floating point for coin amounts in token issuance.
// ---------------------------------------------------------
static uint64_t getUtxoValueInAtoms(const Blockchain &chain,
                                   const std::string &txid,
                                   uint32_t vout)
{
    UTXO utxo;
    // 1) Lookup the UTXO in the chain’s UTXO set
    if (!chain.utxoSet.getUTXO(txid, vout, utxo)) {
        throw std::runtime_error(
            "No UTXO found for (txid=" + txid +
            ", vout=" + std::to_string(vout) + ")"
        );
    }

    // 2) Simply return the numeric 'amount' field (already in TRU atoms)
    return utxo.amount;
}
// ---------------------------------------------------------
// A small helper for random "meta_id" or "visual" usage:
// ---------------------------------------------------------
static std::string generateMetaID(const std::string &tokenID)
{
    static const std::string kSalt = "mySpecialRandomSalt42";
    std::string material = tokenID + kSalt;
    std::string digestHex = doubleSha256Hex(material);
    // e.g. "did:on_tru:" + first 16 hex
    std::ostringstream oss;
    oss << "did:on_tru:" << digestHex.substr(0, 16);
    return oss.str();
}
static std::string generateDeterministicVisual(const std::string &tokenID,
                                               const std::string &existingImageUrl)
{
    if(!existingImageUrl.empty()) {
        return "multi://" + tokenID + "?src=" + existingImageUrl;
    }
    // Minimal fallback identicon approach
    return "identicon://" + tokenID;
}

// ----------------------------------------------------------------
//                  Wallet methods
// ----------------------------------------------------------------
void Wallet::addTransaction(const Transaction &tx)
{
    if (!blockchainPtr) {
        throw std::runtime_error("[Wallet] addTransaction => no local chain pointer");
    }

    // Blockchain::addTransaction() now performs
    // bounded queue admission and can reject. Preserve Wallet's existing void
    // API, but make rejection visible to every caller by throwing instead of
    // silently pretending the transaction was accepted.
    if (!blockchainPtr->addTransaction(tx)) {
        Logger::log("[Wallet] addTransaction => bounded queue admission rejected: " + tx.txid);
        throw std::runtime_error("[Wallet] Transaction queue admission rejected");
    }
}

const Blockchain& Wallet::getBlockchain() const
{
    if (!blockchainPtr) {
        throw std::runtime_error("[Wallet] getBlockchain() => no local chain pointer");
    }
    return *blockchainPtr; // Return a reference to the pointed-to chain
}

//===============================================================================
// SEC-14E.3.1B — encrypted locked-startup foundation
//===============================================================================
namespace {
struct WalletEncryptedStartupArtifactsV1 {
    std::string walletBase;
    std::string publicPath;
    std::string seedEncryptedPath;
    std::string privateEncryptedPath;
    bool anyEncryptedArtifact = false;
    bool completeEncryptedSet = false;
};
WalletEncryptedStartupArtifactsV1 walletEncryptedStartupArtifactsV1(const std::string& walletFilePath)
{
    WalletEncryptedStartupArtifactsV1 out;
    out.walletBase = walletFilePath.empty() ? "tru.dat" : walletFilePath;
    out.publicPath = out.walletBase + ".public";
    out.privateEncryptedPath = out.walletBase + ".enc";
    out.seedEncryptedPath = "wallet_seed.dat.enc";
    const bool hasPublic = std::filesystem::exists(out.publicPath);
    const bool hasPrivate = std::filesystem::exists(out.privateEncryptedPath);
    const bool hasSeed = std::filesystem::exists(out.seedEncryptedPath);
    out.anyEncryptedArtifact = hasPublic || hasPrivate || hasSeed;
    out.completeEncryptedSet = hasPublic && hasPrivate && hasSeed;
    return out;
}
void loadWalletPublicMetadataV1(const std::string& publicPath,
    std::vector<std::string>& addresses, std::uint32_t& currentIndex,
    std::uint32_t& addressIndex,
    std::unordered_map<std::string, std::string>& privateKeys)
{
    std::ifstream ifs(publicPath);
    if (!ifs.good()) throw std::runtime_error("[SEC-14E.3.1B] encrypted wallet public metadata cannot be opened");
    json j; ifs >> j;
    if (!j.is_object() || j.value("format", std::string{}) != "TRU_WALLET_PUBLIC_V1" ||
        !j.contains("addresses") || !j["addresses"].is_array() ||
        !j.contains("currentIndex") || !j["currentIndex"].is_number_unsigned() ||
        j.contains("privateKeys")) {
        throw std::runtime_error("[SEC-14E.3.1B] invalid encrypted-wallet public metadata");
    }
    const auto loadedAddresses = j["addresses"].get<std::vector<std::string>>();
    const auto loadedCurrent = j["currentIndex"].get<std::uint32_t>();
    if (loadedAddresses.empty() || loadedCurrent >= loadedAddresses.size())
        throw std::runtime_error("[SEC-14E.3.1B] invalid public wallet address/index state");
    addresses = loadedAddresses;
    currentIndex = loadedCurrent;
    addressIndex = static_cast<std::uint32_t>(addresses.size());
    privateKeys.clear();
}
} // namespace

//===============================================================================
// SEC-14G — encrypted-first wallet bootstrap
//===============================================================================
bool bootstrapEncryptedWalletV1(
    const std::string& walletBasePath,
    const std::string& passphrase,
    std::string& outAddress,
    std::string* errorOut)
{
    namespace enc = tru_wallet_encryption_v1;

    outAddress.clear();
    if (errorOut) errorOut->clear();

    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (passphrase.empty()) {
        setError("SEC-14G bootstrap passphrase must not be empty");
        return false;
    }

    if (sodium_init() < 0) {
        setError("SEC-14G libsodium initialization failed");
        return false;
    }

    const std::string walletBase =
        walletBasePath.empty() ? std::string("tru.dat") : walletBasePath;
    const std::filesystem::path walletPath(walletBase);
    std::filesystem::path parent = walletPath.parent_path();
    if (parent.empty()) parent = ".";

    const std::string seedEncryptedPath =
        (parent / "wallet_seed.dat.enc").string();
    const std::string privateEncryptedPath = walletBase + ".enc";
    const std::string publicPath = walletBase + ".public";
    const std::string plaintextSeedPath =
        (parent / "wallet_seed.dat").string();
    const std::string txnPath = walletBase + ".bootstrap.txn";

    const std::string seedStage = seedEncryptedPath + ".sec14g.new";
    const std::string privateStage = privateEncryptedPath + ".sec14g.new";
    const std::string publicStage = publicPath + ".sec14g.new";
    const std::string txnStage = txnPath + ".new";

    auto secureClear = [](std::vector<std::uint8_t>& bytes) noexcept {
        if (!bytes.empty()) sodium_memzero(bytes.data(), bytes.size());
        bytes.clear();
    };
    auto secureClearString = [](std::string& value) noexcept {
        if (!value.empty()) sodium_memzero(value.data(), value.size());
        value.clear();
    };

    auto fsyncParent = [](const std::string& path) {
        std::filesystem::path p(path);
        std::filesystem::path dir = p.parent_path();
        if (dir.empty()) dir = ".";
        const int fd = ::open(dir.string().c_str(), O_RDONLY | O_DIRECTORY);
        if (fd < 0) {
            throw std::runtime_error(
                "SEC-14G cannot open parent directory for fsync: " +
                dir.string());
        }
        const int rc = ::fsync(fd);
        const int saved = errno;
        ::close(fd);
        if (rc != 0) {
            throw std::runtime_error(
                "SEC-14G parent directory fsync failed: " +
                std::string(std::strerror(saved)));
        }
    };

    auto writeExclusiveAndSync = [](const std::string& path,
                                    const std::vector<std::uint8_t>& bytes) {
        const int fd = ::open(
            path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            throw std::runtime_error(
                "SEC-14G create-exclusive failed for " + path + ": " +
                std::strerror(errno));
        }
        std::size_t off = 0;
        try {
            while (off < bytes.size()) {
                const ssize_t n = ::write(
                    fd, bytes.data() + off, bytes.size() - off);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    throw std::runtime_error(
                        "SEC-14G write failed for " + path);
                }
                if (n == 0) {
                    throw std::runtime_error(
                        "SEC-14G short write for " + path);
                }
                off += static_cast<std::size_t>(n);
            }
            if (::fsync(fd) != 0) {
                throw std::runtime_error(
                    "SEC-14G fsync failed for " + path);
            }
            if (::close(fd) != 0) {
                throw std::runtime_error(
                    "SEC-14G close failed for " + path);
            }
        } catch (...) {
            ::close(fd);
            ::unlink(path.c_str());
            throw;
        }
    };

    auto readAll = [](const std::string& path) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in.good()) {
            throw std::runtime_error("SEC-14G cannot open artifact: " + path);
        }
        const std::streamsize size = in.tellg();
        if (size < 0) {
            throw std::runtime_error("SEC-14G artifact size failed: " + path);
        }
        in.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
        if (!out.empty() &&
            !in.read(reinterpret_cast<char*>(out.data()), size)) {
            throw std::runtime_error("SEC-14G artifact read failed: " + path);
        }
        return out;
    };

    auto sha256Hex = [](const std::vector<std::uint8_t>& bytes) {
        unsigned char digest[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(
            digest,
            bytes.empty() ? nullptr : bytes.data(),
            static_cast<unsigned long long>(bytes.size()));
        static const char* hex = "0123456789abcdef";
        std::string out(crypto_hash_sha256_BYTES * 2U, '0');
        for (std::size_t i = 0; i < crypto_hash_sha256_BYTES; ++i) {
            out[2U * i] = hex[(digest[i] >> 4U) & 0x0fU];
            out[2U * i + 1U] = hex[digest[i] & 0x0fU];
        }
        sodium_memzero(digest, sizeof(digest));
        return out;
    };

    auto sha256File = [&](const std::string& path) {
        auto bytes = readAll(path);
        const std::string hash = sha256Hex(bytes);
        secureClear(bytes);
        return hash;
    };

    auto publishRename = [&](const std::string& from,
                             const std::string& to) {
        if (::rename(from.c_str(), to.c_str()) != 0) {
            throw std::runtime_error(
                "SEC-14G atomic publish rename failed " + from + " -> " +
                to + ": " + std::strerror(errno));
        }
        fsyncParent(to);
    };

    auto removeAndSync = [&](const std::string& path) {
        if (!std::filesystem::exists(path)) return;
        if (::unlink(path.c_str()) != 0) {
            throw std::runtime_error(
                "SEC-14G cleanup unlink failed: " + path);
        }
        fsyncParent(path);
    };

    // Recovery is bootstrap-specific and create-only. If all three final
    // artifacts match a surviving journal, the prior bootstrap committed and
    // only journal cleanup is needed. A partial exact transaction is rolled
    // back; a mismatching artifact is never deleted automatically.
    if (std::filesystem::exists(txnPath)) {
        try {
            std::ifstream journalIn(txnPath);
            json journal;
            journalIn >> journal;
            if (!journal.is_object() ||
                journal.value("format", std::string{}) !=
                    "TRU_WALLET_BOOTSTRAP_TXN_V1") {
                throw std::runtime_error(
                    "SEC-14G bootstrap journal format mismatch");
            }

            const auto exactOrAbsent = [&](const std::string& path,
                                           const std::string& expected) {
                if (!std::filesystem::exists(path)) return true;
                return sha256File(path) == expected;
            };

            const std::string seedHash = journal.at("seed_sha256").get<std::string>();
            const std::string privateHash = journal.at("private_sha256").get<std::string>();
            const std::string publicHash = journal.at("public_sha256").get<std::string>();

            if (!exactOrAbsent(seedEncryptedPath, seedHash) ||
                !exactOrAbsent(privateEncryptedPath, privateHash) ||
                !exactOrAbsent(publicPath, publicHash) ||
                !exactOrAbsent(seedStage, seedHash) ||
                !exactOrAbsent(privateStage, privateHash) ||
                !exactOrAbsent(publicStage, publicHash)) {
                throw std::runtime_error(
                    "SEC-14G recovery found an artifact that does not match "
                    "the bootstrap journal; refusing automatic deletion");
            }

            const bool finalsComplete =
                !std::filesystem::exists(walletBase) &&
                !std::filesystem::exists(plaintextSeedPath) &&
                std::filesystem::exists(seedEncryptedPath) &&
                std::filesystem::exists(privateEncryptedPath) &&
                std::filesystem::exists(publicPath) &&
                sha256File(seedEncryptedPath) == seedHash &&
                sha256File(privateEncryptedPath) == privateHash &&
                sha256File(publicPath) == publicHash;

            if (finalsComplete) {
                std::ifstream publicIn(publicPath);
                json publicJson;
                publicIn >> publicJson;
                const auto addresses =
                    publicJson.at("addresses").get<std::vector<std::string>>();
                if (publicJson.value("format", std::string{}) !=
                        "TRU_WALLET_PUBLIC_V1" ||
                    addresses.size() != 1U ||
                    publicJson.at("currentIndex").get<std::uint32_t>() != 0U) {
                    throw std::runtime_error(
                        "SEC-14G recovered public metadata is invalid");
                }
                outAddress = addresses.front();
                removeAndSync(seedStage);
                removeAndSync(privateStage);
                removeAndSync(publicStage);
                removeAndSync(txnPath);
                return true;
            }

            removeAndSync(seedEncryptedPath);
            removeAndSync(privateEncryptedPath);
            removeAndSync(publicPath);
            removeAndSync(seedStage);
            removeAndSync(privateStage);
            removeAndSync(publicStage);
            removeAndSync(txnPath);
        } catch (const std::exception& e) {
            setError(e.what());
            return false;
        }
    }

    for (const std::string& path : {
             walletBase,
             plaintextSeedPath,
             seedEncryptedPath,
             privateEncryptedPath,
             publicPath,
             walletBase + ".txn",
             txnStage,
             seedStage,
             privateStage,
             publicStage}) {
        if (std::filesystem::exists(path)) {
            setError(
                "SEC-14G create-only collision; refusing existing artifact: " +
                path);
            return false;
        }
    }

    std::vector<std::uint8_t> seed(64U);
    std::vector<std::uint8_t> rawPrivate;
    std::vector<std::uint8_t> privatePlain;
    std::vector<std::uint8_t> seedEnvelope;
    std::vector<std::uint8_t> privateEnvelope;
    std::vector<std::uint8_t> publicBytes;
    std::vector<std::uint8_t> verifiedSeed;
    std::vector<std::uint8_t> verifiedPrivate;
    std::string privatePem;
    std::string privateText;
    struct ext_key master {};
    struct ext_key child {};
    bool journalPublished = false;

    auto clearSecrets = [&]() noexcept {
        secureClear(seed);
        secureClear(rawPrivate);
        secureClear(privatePlain);
        secureClear(seedEnvelope);
        secureClear(privateEnvelope);
        secureClear(verifiedSeed);
        secureClear(verifiedPrivate);
        secureClearString(privatePem);
        secureClearString(privateText);
        sodium_memzero(&master, sizeof(master));
        sodium_memzero(&child, sizeof(child));
    };

    try {
        randombytes_buf(seed.data(), seed.size());

        if (bip32_key_from_seed(
                seed.data(), seed.size(), BIP32_VER_MAIN_PRIVATE, 0, &master) !=
            WALLY_OK) {
            throw std::runtime_error("SEC-14G bip32 master-key derivation failed");
        }

        const std::uint32_t path[5] = {
            0x80000000U | 44U,
            0x80000000U | tru_network::TRU_BIP44_COIN_TYPE,
            0x80000000U,
            0U,
            0U
        };
        if (bip32_key_from_parent_path(
                &master, path, 5, BIP32_FLAG_KEY_PRIVATE, &child) != WALLY_OK) {
            throw std::runtime_error("SEC-14G BIP44 child-key derivation failed");
        }

        rawPrivate.assign(child.priv_key + 1, child.priv_key + 33);
        ECDSAKey key = ECDSAKey::fromRawBytes(rawPrivate);
        privatePem = key.getPrivateKey();
        const std::vector<unsigned char> pubkey = key.getCompressedSec1();

        unsigned char hash160[HASH160_LEN];
        if (wally_hash160(
                pubkey.data(), pubkey.size(), hash160, HASH160_LEN) != WALLY_OK) {
            throw std::runtime_error("SEC-14G wally_hash160 failed");
        }
        unsigned char versioned[1 + HASH160_LEN];
        versioned[0] = tru_network::MAINNET_P2PKH_VERSION;
        std::memcpy(versioned + 1, hash160, HASH160_LEN);
        char* addrOut = nullptr;
        if (wally_base58_from_bytes(
                versioned, sizeof(versioned), BASE58_FLAG_CHECKSUM, &addrOut) !=
            WALLY_OK) {
            throw std::runtime_error("SEC-14G Base58Check address encoding failed");
        }
        outAddress.assign(addrOut);
        wally_free_string(addrOut);

        json privateObject = json::object();
        privateObject[outAddress] = privatePem;
        privateText = privateObject.dump();
        privatePlain.assign(privateText.begin(), privateText.end());

        json publicJson;
        publicJson["addresses"] = std::vector<std::string>{outAddress};
        publicJson["currentIndex"] = 0U;
        publicJson["format"] = "TRU_WALLET_PUBLIC_V1";
        if (publicJson.contains("privateKeys")) {
            throw std::runtime_error(
                "SEC-14G public metadata unexpectedly contains private keys");
        }
        const std::string publicText = publicJson.dump() + "\n";
        publicBytes.assign(publicText.begin(), publicText.end());

        std::string cryptoError;
        if (!enc::encrypt(seed, passphrase, seedEnvelope, &cryptoError)) {
            throw std::runtime_error(
                "SEC-14G seed encryption failed: " + cryptoError);
        }
        cryptoError.clear();
        if (!enc::encrypt(
                privatePlain, passphrase, privateEnvelope, &cryptoError)) {
            throw std::runtime_error(
                "SEC-14G private-material encryption failed: " + cryptoError);
        }

        cryptoError.clear();
        if (!enc::decrypt(
                seedEnvelope, passphrase, verifiedSeed, &cryptoError) ||
            verifiedSeed != seed) {
            throw std::runtime_error(
                "SEC-14G seed authenticated roundtrip failed: " + cryptoError);
        }
        cryptoError.clear();
        if (!enc::decrypt(
                privateEnvelope, passphrase, verifiedPrivate, &cryptoError) ||
            verifiedPrivate != privatePlain) {
            throw std::runtime_error(
                "SEC-14G private-material authenticated roundtrip failed: " +
                cryptoError);
        }

        const json verifiedPrivateObject = json::parse(
            verifiedPrivate.begin(), verifiedPrivate.end());
        const auto keyIt = verifiedPrivateObject.find(outAddress);
        if (!verifiedPrivateObject.is_object() ||
            verifiedPrivateObject.size() != 1U ||
            keyIt == verifiedPrivateObject.end() ||
            !keyIt->is_string()) {
            throw std::runtime_error(
                "SEC-14G private-material semantic verification failed");
        }

        const std::string verifiedPem = keyIt->get<std::string>();
        ECDSAKey verifiedKey = ECDSAKey::fromPrivateKey(verifiedPem);
        const auto verifiedPub = verifiedKey.getCompressedSec1();
        unsigned char verifiedHash160[HASH160_LEN];
        if (wally_hash160(
                verifiedPub.data(), verifiedPub.size(),
                verifiedHash160, HASH160_LEN) != WALLY_OK) {
            throw std::runtime_error(
                "SEC-14G verified private key public-hash derivation failed");
        }
        unsigned char verifiedVersioned[1 + HASH160_LEN];
        verifiedVersioned[0] = tru_network::MAINNET_P2PKH_VERSION;
        std::memcpy(
            verifiedVersioned + 1, verifiedHash160, HASH160_LEN);
        char* verifiedAddrOut = nullptr;
        if (wally_base58_from_bytes(
                verifiedVersioned, sizeof(verifiedVersioned),
                BASE58_FLAG_CHECKSUM, &verifiedAddrOut) != WALLY_OK) {
            throw std::runtime_error(
                "SEC-14G verified address encoding failed");
        }
        const std::string verifiedAddress(verifiedAddrOut);
        wally_free_string(verifiedAddrOut);
        if (verifiedAddress != outAddress) {
            throw std::runtime_error(
                "SEC-14G private key does not match generated public address");
        }

        writeExclusiveAndSync(seedStage, seedEnvelope);
        writeExclusiveAndSync(privateStage, privateEnvelope);
        writeExclusiveAndSync(publicStage, publicBytes);
        fsyncParent(seedStage);

        const std::string seedHash = sha256Hex(seedEnvelope);
        const std::string privateHash = sha256Hex(privateEnvelope);
        const std::string publicHash = sha256Hex(publicBytes);

        json journal;
        journal["format"] = "TRU_WALLET_BOOTSTRAP_TXN_V1";
        journal["seed_sha256"] = seedHash;
        journal["private_sha256"] = privateHash;
        journal["public_sha256"] = publicHash;
        journal["seed_path"] = seedEncryptedPath;
        journal["private_path"] = privateEncryptedPath;
        journal["public_path"] = publicPath;
        const std::string journalText = journal.dump() + "\n";
        const std::vector<std::uint8_t> journalBytes(
            journalText.begin(), journalText.end());
        writeExclusiveAndSync(txnStage, journalBytes);
        publishRename(txnStage, txnPath);
        journalPublished = true;

        publishRename(seedStage, seedEncryptedPath);
        publishRename(privateStage, privateEncryptedPath);
        publishRename(publicStage, publicPath);

        if (sha256File(seedEncryptedPath) != seedHash ||
            sha256File(privateEncryptedPath) != privateHash ||
            sha256File(publicPath) != publicHash) {
            throw std::runtime_error(
                "SEC-14G final artifact hash verification failed");
        }

        if (std::filesystem::exists(walletBase) ||
            std::filesystem::exists(plaintextSeedPath)) {
            throw std::runtime_error(
                "SEC-14G plaintext wallet artifact appeared unexpectedly");
        }

        removeAndSync(txnPath);
        clearSecrets();
        return true;
    } catch (const std::exception& e) {
        if (!journalPublished) {
            ::unlink(seedStage.c_str());
            ::unlink(privateStage.c_str());
            ::unlink(publicStage.c_str());
            ::unlink(txnStage.c_str());
        }
        clearSecrets();
        setError(e.what());
        return false;
    }
}

//===============================================================================
// SEC-14E.3.4B — pair transaction journal / crash recovery foundation
//===============================================================================
namespace {
constexpr const char* TRU_WALLET_TXN_FORMAT_V1 = "TRU_WALLET_TXN_V1";

std::string walletTxnPathV1(const std::string& walletFilePath)
{
    const std::string walletBase = walletFilePath.empty() ? "tru.dat" : walletFilePath;
    return walletBase + ".txn";
}

void fsyncParentDirectoryTxnV1(const std::string& path)
{
    std::filesystem::path p(path);
    std::filesystem::path parent = p.parent_path();
    if (parent.empty()) parent = ".";
    const int dfd = ::open(parent.string().c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) throw std::runtime_error("[SEC-14E.3.4B] cannot open journal parent directory");
    const int rc = ::fsync(dfd);
    const int saved = errno;
    ::close(dfd);
    if (rc != 0) throw std::runtime_error(std::string("[SEC-14E.3.4B] directory fsync failed: ") + std::strerror(saved));
}

void writeWalletTxnJournalV1(const std::string& path, const json& journal)
{
    const std::string tmp = path + ".tmp." + std::to_string(static_cast<unsigned long long>(::getpid()));
    if (std::filesystem::exists(tmp)) throw std::runtime_error("[SEC-14E.3.4B] journal temp collision");
    const std::string data = journal.dump() + "\n";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error(std::string("[SEC-14E.3.4B] journal temp create failed: ") + std::strerror(errno));
    std::size_t off=0;
    try {
        while (off < data.size()) {
            const ssize_t n = ::write(fd, data.data()+off, data.size()-off);
            if (n < 0) { if (errno == EINTR) continue; throw std::runtime_error("[SEC-14E.3.4B] journal write failed"); }
            if (n == 0) throw std::runtime_error("[SEC-14E.3.4B] journal short write");
            off += static_cast<std::size_t>(n);
        }
        if (::fsync(fd) != 0) throw std::runtime_error("[SEC-14E.3.4B] journal fsync failed");
        if (::close(fd) != 0) throw std::runtime_error("[SEC-14E.3.4B] journal close failed");
    } catch (...) { ::close(fd); ::unlink(tmp.c_str()); throw; }
    if (::rename(tmp.c_str(), path.c_str()) != 0) { const int saved=errno; ::unlink(tmp.c_str()); throw std::runtime_error(std::string("[SEC-14E.3.4B] journal rename failed: ")+std::strerror(saved)); }
    fsyncParentDirectoryTxnV1(path);
}

json readWalletTxnJournalV1(const std::string& path)
{
    std::ifstream in(path);
    if (!in.good()) throw std::runtime_error("[SEC-14E.3.4B] cannot open wallet transaction journal");
    json j; in >> j;
    if (!j.is_object() || j.value("format", std::string{}) != TRU_WALLET_TXN_FORMAT_V1)
        throw std::runtime_error("[SEC-14E.3.4B] wallet transaction journal format mismatch");
    for (const char* key : {"phase","privatePath","publicPath","oldPrivateSha256","newPrivateSha256","oldPublicSha256","newPublicSha256"})
        if (!j.contains(key)) throw std::runtime_error(std::string("[SEC-14E.3.4B] journal missing ")+key);
    const std::string phase=j.at("phase").get<std::string>();
    if (phase!="PREPARED" && phase!="PRIVATE_PUBLISHED" && phase!="COMMITTED")
        throw std::runtime_error("[SEC-14E.3.4B] wallet transaction journal phase invalid");
    return j;
}

std::string sha256FileHexV1(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        throw std::runtime_error(
            "[SEC-14E.3.4C] cannot open artifact for SHA256: " + path);
    }

    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1)
        throw std::runtime_error("[SEC-14E.3.4C] SHA256_Init failed");

    std::array<unsigned char, 8192> buf{};
    while (in.good()) {
        in.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 && SHA256_Update(
                &ctx, buf.data(), static_cast<std::size_t>(got)) != 1) {
            throw std::runtime_error("[SEC-14E.3.4C] SHA256_Update failed");
        }
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (SHA256_Final(digest, &ctx) != 1)
        throw std::runtime_error("[SEC-14E.3.4C] SHA256_Final failed");

    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : digest) {
        out.push_back(HEX[(b >> 4) & 0x0f]);
        out.push_back(HEX[b & 0x0f]);
    }
    return out;
}

void verifyWalletTxnRecoveryStateV1(
    const std::string& walletFilePath)
{
    const auto artifacts =
        walletEncryptedStartupArtifactsV1(walletFilePath);
    const std::string txnPath = walletTxnPathV1(walletFilePath);

    if (!std::filesystem::exists(txnPath)) return;

    const json j = readWalletTxnJournalV1(txnPath);
    const std::string phase = j.at("phase").get<std::string>();
    const std::string privatePath = j.at("privatePath").get<std::string>();
    const std::string publicPath = j.at("publicPath").get<std::string>();

    if (privatePath != artifacts.privateEncryptedPath ||
        publicPath != artifacts.publicPath) {
        throw std::runtime_error(
            "[SEC-14E.3.4C] transaction journal path mismatch; refusing startup");
    }

    const std::array<const char*, 4> recoveryKeys = {
        "oldPrivateBackup", "oldPublicBackup",
        "newPrivateStage", "newPublicStage"
    };
    for (const char* key : recoveryKeys) {
        if (!j.contains(key) || !j[key].is_string()) {
            throw std::runtime_error(
                std::string("[SEC-14E.3.4C] transaction journal missing recovery path: ") + key);
        }
    }

    const std::string oldPrivateBackup = j.at("oldPrivateBackup").get<std::string>();
    const std::string oldPublicBackup = j.at("oldPublicBackup").get<std::string>();
    const std::string newPrivateStage = j.at("newPrivateStage").get<std::string>();
    const std::string newPublicStage = j.at("newPublicStage").get<std::string>();

    const std::string oldPrivate = j.at("oldPrivateSha256").get<std::string>();
    const std::string newPrivate = j.at("newPrivateSha256").get<std::string>();
    const std::string oldPublic = j.at("oldPublicSha256").get<std::string>();
    const std::string newPublic = j.at("newPublicSha256").get<std::string>();

    auto removeIfExists = [](const std::string& path) {
        if (!path.empty() && std::filesystem::exists(path)) {
            if (::unlink(path.c_str()) != 0) {
                throw std::runtime_error(
                    "[SEC-14E.3.4C] recovery cleanup unlink failed: " + path);
            }
        }
    };

    auto copyBackupToLivePreservingSource = [&](
        const std::string& backupPath,
        const std::string& livePath,
        const std::string& expectedSha) {

        if (!std::filesystem::exists(backupPath)) {
            throw std::runtime_error(
                "[SEC-14E.3.4D] rollback backup missing: " + backupPath);
        }

        if (sha256FileHexV1(backupPath) != expectedSha) {
            throw std::runtime_error(
                "[SEC-14E.3.4D] rollback backup hash mismatch: " + backupPath);
        }

        const std::string recoveryTemp =
            livePath + ".sec14e34d.recovery.tmp";

        if (std::filesystem::exists(recoveryTemp)) {
            if (sha256FileHexV1(recoveryTemp) != expectedSha) {
                throw std::runtime_error(
                    "[SEC-14E.3.4D] stale recovery temp hash mismatch: " +
                    recoveryTemp);
            }
        } else {
            std::ifstream in(backupPath, std::ios::binary);
            if (!in.good()) {
                throw std::runtime_error(
                    "[SEC-14E.3.4D] cannot open rollback backup");
            }

            const int fd = ::open(
                recoveryTemp.c_str(),
                O_WRONLY | O_CREAT | O_EXCL,
                S_IRUSR | S_IWUSR);

            if (fd < 0) {
                throw std::runtime_error(
                    std::string(
                        "[SEC-14E.3.4D] recovery temp create failed: ") +
                    std::strerror(errno));
            }

            bool fdOpen = true;
            try {
                std::array<char, 8192> buf{};
                while (in.good()) {
                    in.read(
                        buf.data(),
                        static_cast<std::streamsize>(buf.size()));
                    const std::streamsize got = in.gcount();
                    std::size_t off = 0;

                    while (off < static_cast<std::size_t>(got)) {
                        const ssize_t n = ::write(
                            fd,
                            buf.data() + off,
                            static_cast<std::size_t>(got) - off);

                        if (n < 0) {
                            if (errno == EINTR) continue;
                            throw std::runtime_error(
                                std::string(
                                    "[SEC-14E.3.4D] recovery temp write failed: ") +
                                std::strerror(errno));
                        }
                        if (n == 0) {
                            throw std::runtime_error(
                                "[SEC-14E.3.4D] recovery temp short write");
                        }
                        off += static_cast<std::size_t>(n);
                    }
                }

                if (::fsync(fd) != 0) {
                    throw std::runtime_error(
                        std::string(
                            "[SEC-14E.3.4D] recovery temp fsync failed: ") +
                        std::strerror(errno));
                }

                if (::close(fd) != 0) {
                    fdOpen = false;
                    throw std::runtime_error(
                        std::string(
                            "[SEC-14E.3.4D] recovery temp close failed: ") +
                        std::strerror(errno));
                }
                fdOpen = false;
            } catch (...) {
                if (fdOpen) ::close(fd);
                if (std::filesystem::exists(recoveryTemp)) {
                    try {
                        if (sha256FileHexV1(recoveryTemp) != expectedSha) {
                            ::unlink(recoveryTemp.c_str());
                        }
                    } catch (...) {
                        ::unlink(recoveryTemp.c_str());
                    }
                }
                throw;
            }

            if (sha256FileHexV1(recoveryTemp) != expectedSha) {
                ::unlink(recoveryTemp.c_str());
                throw std::runtime_error(
                    "[SEC-14E.3.4D] recovery temp verification failed");
            }
        }

        if (::rename(recoveryTemp.c_str(), livePath.c_str()) != 0) {
            throw std::runtime_error(
                std::string("[SEC-14E.3.4D] recovery publish failed: ") +
                std::strerror(errno));
        }

        fsyncParentDirectoryTxnV1(livePath);

        if (sha256FileHexV1(livePath) != expectedSha) {
            throw std::runtime_error(
                "[SEC-14E.3.4D] recovery live-artifact verification failed");
        }
    };

    auto restoreOldPair = [&]() {
        const bool privateAlreadyOld =
            std::filesystem::exists(privatePath) &&
            sha256FileHexV1(privatePath) == oldPrivate;

        const bool publicAlreadyOld =
            std::filesystem::exists(publicPath) &&
            sha256FileHexV1(publicPath) == oldPublic;

        if (!(privateAlreadyOld && publicAlreadyOld)) {
            if (!std::filesystem::exists(oldPrivateBackup) ||
                !std::filesystem::exists(oldPublicBackup)) {
                throw std::runtime_error(
                    "[SEC-14E.3.4D] incomplete rollback lacks both old backups");
            }

            if (sha256FileHexV1(oldPrivateBackup) != oldPrivate ||
                sha256FileHexV1(oldPublicBackup) != oldPublic) {
                throw std::runtime_error(
                    "[SEC-14E.3.4D] rollback backup hash mismatch");
            }

            // Backups remain intact through BOTH publications.
            copyBackupToLivePreservingSource(
                oldPrivateBackup, privatePath, oldPrivate);
            copyBackupToLivePreservingSource(
                oldPublicBackup, publicPath, oldPublic);
        }

        if (!std::filesystem::exists(privatePath) ||
            !std::filesystem::exists(publicPath) ||
            sha256FileHexV1(privatePath) != oldPrivate ||
            sha256FileHexV1(publicPath) != oldPublic) {
            throw std::runtime_error(
                "[SEC-14E.3.4D] rollback pair verification failed");
        }

        // Cleanup after an already-completed rollback must be restart-safe.
        // Journal is removed LAST.
        removeIfExists(newPrivateStage);
        removeIfExists(newPublicStage);
        removeIfExists(privatePath + ".sec14e34d.recovery.tmp");
        removeIfExists(publicPath + ".sec14e34d.recovery.tmp");
        removeIfExists(oldPrivateBackup);
        removeIfExists(oldPublicBackup);

        if (::unlink(txnPath.c_str()) != 0) {
            throw std::runtime_error(
                "[SEC-14E.3.4D] rollback journal removal failed");
        }
        fsyncParentDirectoryTxnV1(txnPath);

        Logger::log(
            "[SEC-14E.3.4D] incomplete encrypted-wallet transaction "
            "idempotently rolled back to prior committed pair");
    };

    if (phase == "PREPARED" || phase == "PRIVATE_PUBLISHED") {
        restoreOldPair();
        return;
    }

    if (phase == "COMMITTED") {
        if (!std::filesystem::exists(privatePath) ||
            !std::filesystem::exists(publicPath) ||
            sha256FileHexV1(privatePath) != newPrivate ||
            sha256FileHexV1(publicPath) != newPublic) {
            throw std::runtime_error(
                "[SEC-14E.3.4C] committed transaction new-pair hash mismatch");
        }
        removeIfExists(oldPrivateBackup);
        removeIfExists(oldPublicBackup);
        removeIfExists(newPrivateStage);
        removeIfExists(newPublicStage);
        if (::unlink(txnPath.c_str()) != 0) {
            throw std::runtime_error(
                "[SEC-14E.3.4C] committed journal cleanup failed");
        }
        fsyncParentDirectoryTxnV1(txnPath);
        Logger::log(
            "[SEC-14E.3.4C] committed encrypted-wallet transaction verified and cleaned");
        return;
    }

    throw std::runtime_error(
        "[SEC-14E.3.4C] unsupported wallet transaction journal phase");
}
} // namespace

//===============================================================================
// Constructors / Destructor
//===============================================================================
Wallet::Wallet(const std::string& filePath, Blockchain *chainPtr,const std::string& nodeIP, int nodePort)
    : blockchainPtr(chainPtr),
      isLocalChain(chainPtr != nullptr),
      nodeIP(nodeIP),
      nodePort(nodePort),
      mempool(chainPtr ? chainPtr->mempool.get() : nullptr),
      walletFilePath(filePath)
{
    // SEC-14E.3.4B: fail closed on incomplete pair publication.
    verifyWalletTxnRecoveryStateV1(walletFilePath);

    const auto encryptedArtifacts = walletEncryptedStartupArtifactsV1(walletFilePath);

    // SEC-14E.5B: plaintext startup is retired. A wallet may start only from
    // the complete authenticated encrypted artifact set.
    if (!encryptedArtifacts.completeEncryptedSet) {
        throw std::runtime_error(
            "[SEC-14E.5B] complete encrypted wallet artifact set required; "
            "legacy plaintext startup is retired");
    }

    beginEncryptedWalletModeForMigration();
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        loadWalletPublicMetadataV1(
            encryptedArtifacts.publicPath,
            addresses,
            currentIndex,
            addressIndex,
            privateKeys);
    }

    if (!masterSeed.empty()) {
        std::fill(masterSeed.begin(), masterSeed.end(), 0);
        masterSeed.clear();
    }

    Logger::log(
        "[SEC-14E.5B] encrypted-only startup; mode=ENCRYPTED_LOCKED; "
        "plaintext seed/privateKeys were not loaded");

    // 4) Register with local chain
    if (blockchainPtr) {
        blockchainPtr->registerWallet(this);
    }

    // 5) Crypto init & log
    OpenSSL_add_all_algorithms();
    Logger::log("[Wallet] Initialized. LocalChain=" + std::string(isLocalChain ? "true" : "false") +
                ", Addresses=" + std::to_string(addresses.size()) +
                ", Node=" + nodeIP + ":" + std::to_string(nodePort));
    {
        std::lock_guard<std::mutex> lk(gConsoleMutex);
        std::cout << "[Wallet] Initialized. "
                  << "LocalChain=" << (isLocalChain ? "true" : "false")
                  << ", Addresses=" << addresses.size() << "\n";
    }
}

Wallet::Wallet()
    : blockchainPtr(nullptr),
      isLocalChain(false),
      mempool(nullptr),
      walletFilePath("")  // no file
{
    // SEC-14E.3.4B: fail closed on incomplete pair publication.
    verifyWalletTxnRecoveryStateV1(walletFilePath);

    const auto encryptedArtifacts = walletEncryptedStartupArtifactsV1(walletFilePath);

    // SEC-14E.5B: plaintext startup is retired. A wallet may start only from
    // the complete authenticated encrypted artifact set.
    if (!encryptedArtifacts.completeEncryptedSet) {
        throw std::runtime_error(
            "[SEC-14E.5B] complete encrypted wallet artifact set required; "
            "legacy plaintext startup is retired");
    }

    beginEncryptedWalletModeForMigration();
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        loadWalletPublicMetadataV1(
            encryptedArtifacts.publicPath,
            addresses,
            currentIndex,
            addressIndex,
            privateKeys);
    }

    if (!masterSeed.empty()) {
        std::fill(masterSeed.begin(), masterSeed.end(), 0);
        masterSeed.clear();
    }

    Logger::log(
        "[SEC-14E.5B] encrypted-only startup; mode=ENCRYPTED_LOCKED; "
        "plaintext seed/privateKeys were not loaded");

    // 3) Crypto init & log
    OpenSSL_add_all_algorithms();
    {
        std::lock_guard<std::mutex> lk(gConsoleMutex);
        std::cout << "[Wallet] Initialized with no local chain. "
                  << "Addresses=" << addresses.size() << "\n";
    }
}

Wallet::~Wallet()
{
    // Zero out sensitive seed material
    if (!masterSeed.empty()) {
        std::fill(masterSeed.begin(), masterSeed.end(), 0);
    }
    // hdwallet’s own internal seed is also freed by its destructor
}
//===============================================================================
//                  CREATE NEW WALLET
//===============================================================================

bool Wallet::unlockEncryptedWalletFromFiles(
    const std::string& passphrase,
    std::string* errorOut)
{
    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_LOCKED) {
        if (errorOut) *errorOut =
            "wallet encrypted-file unlock requires ENCRYPTED_LOCKED mode";
        return false;
    }

    const auto artifacts = walletEncryptedStartupArtifactsV1(walletFilePath);
    if (!artifacts.completeEncryptedSet) {
        lockEncryptedWallet();
        if (errorOut) *errorOut = "encrypted wallet artifact set is incomplete";
        return false;
    }

    auto readEnvelope = [](const std::string& path) -> std::vector<std::uint8_t> {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in.good()) throw std::runtime_error("cannot open encrypted wallet envelope: " + path);
        const std::streamsize size = in.tellg();
        if (size <= 0) throw std::runtime_error("encrypted wallet envelope is empty: " + path);
        in.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if (!in.read(reinterpret_cast<char*>(bytes.data()), size))
            throw std::runtime_error("cannot read encrypted wallet envelope: " + path);
        return bytes;
    };

    try {
        const auto encryptedSeed = readEnvelope(artifacts.seedEncryptedPath);
        const auto encryptedPrivate = readEnvelope(artifacts.privateEncryptedPath);

        const bool ok = unlockEncryptedWallet(
            encryptedSeed, encryptedPrivate, passphrase, errorOut);

        if (!ok) {
            lockEncryptedWallet();
            return false;
        }
        if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
            lockEncryptedWallet();
            if (errorOut) *errorOut =
                "authenticated unlock did not enter ENCRYPTED_UNLOCKED";
            return false;
        }

        // E.3.2 intentionally does not hydrate masterSeed/privateKeys.
        return true;
    } catch (const std::exception& e) {
        lockEncryptedWallet();
        if (errorOut) *errorOut = e.what();
        return false;
    }
}

bool Wallet::persistEncryptedWalletSnapshot(
    const std::string& passphrase,
    std::string* errorOut) const
{
    namespace enc = tru_wallet_encryption_v1;

    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        setError("encrypted persistence requires ENCRYPTED_UNLOCKED authenticated session");
        return false;
    }

    if (passphrase.empty()) {
        setError("encrypted persistence passphrase must not be empty");
        return false;
    }

    const auto artifacts = walletEncryptedStartupArtifactsV1(walletFilePath);
    if (!artifacts.completeEncryptedSet) {
        setError("encrypted persistence requires complete artifact set");
        return false;
    }

    auto readAll = [](const std::string& path) -> std::vector<std::uint8_t> {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in.good()) throw std::runtime_error("cannot open encrypted wallet artifact: " + path);
        const std::streamsize size = in.tellg();
        if (size <= 0) throw std::runtime_error("encrypted wallet artifact is empty: " + path);
        in.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if (!in.read(reinterpret_cast<char*>(bytes.data()), size))
            throw std::runtime_error("cannot read encrypted wallet artifact: " + path);
        return bytes;
    };

    auto secureClear = [](std::vector<std::uint8_t>& bytes) noexcept {
        if (!bytes.empty()) {
            sodium_memzero(bytes.data(), bytes.size());
            bytes.clear();
        }
    };

    auto writeCreateExclusiveAndSync = [](
        const std::string& path,
        const std::vector<std::uint8_t>& bytes)
    {
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0)
            throw std::runtime_error("cannot create encrypted wallet temp artifact: " + path + ": " + std::strerror(errno));

        std::size_t written = 0;
        try {
            while (written < bytes.size()) {
                const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    throw std::runtime_error("cannot write encrypted wallet temp artifact: " + path + ": " + std::strerror(errno));
                }
                if (n == 0) throw std::runtime_error("short write to encrypted wallet temp artifact: " + path);
                written += static_cast<std::size_t>(n);
            }
            if (::fsync(fd) != 0)
                throw std::runtime_error("fsync failed for encrypted wallet temp artifact: " + path + ": " + std::strerror(errno));
            if (::close(fd) != 0)
                throw std::runtime_error("close failed for encrypted wallet temp artifact: " + path + ": " + std::strerror(errno));
        } catch (...) {
            ::close(fd);
            ::unlink(path.c_str());
            throw;
        }
    };

    auto fsyncParentDirectory = [](const std::string& path) {
        std::filesystem::path p(path);
        std::filesystem::path parent = p.parent_path();
        if (parent.empty()) parent = ".";
        const int dfd = ::open(parent.string().c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd < 0)
            throw std::runtime_error("cannot open wallet artifact parent directory for fsync: " + parent.string());
        const int rc = ::fsync(dfd);
        const int saved = errno;
        ::close(dfd);
        if (rc != 0)
            throw std::runtime_error("directory fsync failed for wallet artifact parent: " + parent.string() + ": " + std::strerror(saved));
    };

    auto atomicReplace = [&](const std::string& finalPath,
                             const std::vector<std::uint8_t>& bytes,
                             const char* label)
    {
        const std::string tmpPath = finalPath + ".sec14e34a." +
            std::to_string(static_cast<unsigned long long>(::getpid())) + ".tmp";
        if (std::filesystem::exists(tmpPath))
            throw std::runtime_error(std::string(label) + " temp artifact collision: " + tmpPath);
        writeCreateExclusiveAndSync(tmpPath, bytes);
        if (::rename(tmpPath.c_str(), finalPath.c_str()) != 0) {
            const int saved = errno;
            ::unlink(tmpPath.c_str());
            throw std::runtime_error(std::string(label) + " atomic rename failed: " + std::strerror(saved));
        }
        fsyncParentDirectory(finalPath);
    };

    std::vector<std::uint8_t> currentSeedEnvelope;
    std::vector<std::uint8_t> verifiedSeed;
    std::vector<std::uint8_t> newPrivateEnvelope;
    std::vector<std::uint8_t> verifiedPrivate;

    try {
        currentSeedEnvelope = readAll(artifacts.seedEncryptedPath);

        std::string cryptoError;
        if (!enc::decrypt(currentSeedEnvelope, passphrase, verifiedSeed, &cryptoError))
            throw std::runtime_error("encrypted persistence seed authentication failed: " + cryptoError);

        const auto& sessionSeed = walletSecurityController_->unlockedSeed();
        if (verifiedSeed != sessionSeed)
            throw std::runtime_error("encrypted persistence seed/session mismatch");

        const auto& privatePlain = walletSecurityController_->unlockedPrivateMaterial();
        if (privatePlain.empty())
            throw std::runtime_error("authenticated private material is empty");

        cryptoError.clear();
        if (!enc::encrypt(privatePlain, passphrase, newPrivateEnvelope, &cryptoError))
            throw std::runtime_error("encrypted private-material persistence encrypt failed: " + cryptoError);

        cryptoError.clear();
        if (!enc::decrypt(newPrivateEnvelope, passphrase, verifiedPrivate, &cryptoError))
            throw std::runtime_error("encrypted private-material persistence verify failed: " + cryptoError);
        if (verifiedPrivate != privatePlain)
            throw std::runtime_error("encrypted private-material persistence roundtrip mismatch");

        std::vector<std::string> publicAddresses;
        std::uint32_t publicCurrent = 0;
        {
            std::lock_guard<std::mutex> lk(addressesMutex);
            publicAddresses = addresses;
            publicCurrent = currentIndex;
        }
        if (publicAddresses.empty() || publicCurrent >= publicAddresses.size())
            throw std::runtime_error("cannot persist invalid public wallet address/index state");

        json publicJson;
        publicJson["addresses"] = publicAddresses;
        publicJson["currentIndex"] = publicCurrent;
        publicJson["format"] = "TRU_WALLET_PUBLIC_V1";
        if (publicJson.contains("privateKeys"))
            throw std::runtime_error("public wallet metadata unexpectedly contains privateKeys");

        const std::string publicText = publicJson.dump() + "\n";
        std::vector<std::uint8_t> publicBytes(publicText.begin(), publicText.end());

        // E.3.4C — journaled pair publication.
        const std::string txnPath = walletTxnPathV1(walletFilePath);
        const std::string suffix =
            ".sec14e34c." +
            std::to_string(static_cast<unsigned long long>(::getpid()));

        const std::string oldPrivateBackup =
            artifacts.privateEncryptedPath + suffix + ".old";
        const std::string oldPublicBackup =
            artifacts.publicPath + suffix + ".old";
        const std::string newPrivateStage =
            artifacts.privateEncryptedPath + suffix + ".new";
        const std::string newPublicStage =
            artifacts.publicPath + suffix + ".new";

        if (std::filesystem::exists(txnPath) ||
            std::filesystem::exists(oldPrivateBackup) ||
            std::filesystem::exists(oldPublicBackup) ||
            std::filesystem::exists(newPrivateStage) ||
            std::filesystem::exists(newPublicStage)) {
            throw std::runtime_error(
                "encrypted persistence transaction artifact collision");
        }

        const auto oldPrivateBytes =
            readAll(artifacts.privateEncryptedPath);
        const auto oldPublicBytes =
            readAll(artifacts.publicPath);

        writeCreateExclusiveAndSync(oldPrivateBackup, oldPrivateBytes);
        writeCreateExclusiveAndSync(oldPublicBackup, oldPublicBytes);
        writeCreateExclusiveAndSync(newPrivateStage, newPrivateEnvelope);
        writeCreateExclusiveAndSync(newPublicStage, publicBytes);

        const std::string oldPrivateSha =
            sha256FileHexV1(oldPrivateBackup);
        const std::string oldPublicSha =
            sha256FileHexV1(oldPublicBackup);
        const std::string newPrivateSha =
            sha256FileHexV1(newPrivateStage);
        const std::string newPublicSha =
            sha256FileHexV1(newPublicStage);

        json journal;
        journal["format"] = TRU_WALLET_TXN_FORMAT_V1;
        journal["phase"] = "PREPARED";
        journal["privatePath"] = artifacts.privateEncryptedPath;
        journal["publicPath"] = artifacts.publicPath;
        journal["oldPrivateSha256"] = oldPrivateSha;
        journal["newPrivateSha256"] = newPrivateSha;
        journal["oldPublicSha256"] = oldPublicSha;
        journal["newPublicSha256"] = newPublicSha;
        journal["privatePublished"] = false;
        journal["publicPublished"] = false;
        journal["oldPrivateBackup"] = oldPrivateBackup;
        journal["oldPublicBackup"] = oldPublicBackup;
        journal["newPrivateStage"] = newPrivateStage;
        journal["newPublicStage"] = newPublicStage;

        writeWalletTxnJournalV1(txnPath, journal);

        if (::rename(
                newPrivateStage.c_str(),
                artifacts.privateEncryptedPath.c_str()) != 0) {
            throw std::runtime_error(
                "encrypted persistence private publish failed");
        }
        fsyncParentDirectoryTxnV1(artifacts.privateEncryptedPath);

        journal["phase"] = "PRIVATE_PUBLISHED";
        journal["privatePublished"] = true;
        writeWalletTxnJournalV1(txnPath, journal);

        if (::rename(
                newPublicStage.c_str(),
                artifacts.publicPath.c_str()) != 0) {
            throw std::runtime_error(
                "encrypted persistence public publish failed");
        }
        fsyncParentDirectoryTxnV1(artifacts.publicPath);

        journal["phase"] = "COMMITTED";
        journal["publicPublished"] = true;
        writeWalletTxnJournalV1(txnPath, journal);

        if (sha256FileHexV1(artifacts.privateEncryptedPath) != newPrivateSha ||
            sha256FileHexV1(artifacts.publicPath) != newPublicSha) {
            throw std::runtime_error(
                "encrypted persistence committed pair verification failed");
        }

        if (::unlink(oldPrivateBackup.c_str()) != 0 ||
            ::unlink(oldPublicBackup.c_str()) != 0) {
            throw std::runtime_error(
                "encrypted persistence committed backup cleanup failed");
        }

        if (::unlink(txnPath.c_str()) != 0) {
            throw std::runtime_error(
                "encrypted persistence committed journal cleanup failed");
        }
        fsyncParentDirectoryTxnV1(txnPath);

        secureClear(currentSeedEnvelope);
        secureClear(verifiedSeed);
        secureClear(verifiedPrivate);
        secureClear(newPrivateEnvelope);
        return true;
    } catch (const std::exception& e) {
        secureClear(currentSeedEnvelope);
        secureClear(verifiedSeed);
        secureClear(verifiedPrivate);
        secureClear(newPrivateEnvelope);
        setError(e.what());
        return false;
    }
}

bool Wallet::setCurrentAddressEncrypted(
    const std::string& address,
    const std::string& passphrase,
    std::string* errorOut)
{
    std::lock_guard<std::mutex> mutationLock(encryptedMutationMutex_);

    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        setError(
            "authenticated current-address mutation requires "
            "ENCRYPTED_UNLOCKED session");
        return false;
    }

    if (passphrase.empty()) {
        setError(
            "authenticated current-address mutation passphrase must not be empty");
        return false;
    }

    std::uint32_t oldIndex = 0;
    std::uint32_t newIndex = 0;

    {
        std::lock_guard<std::mutex> lk(addressesMutex);

        const auto it =
            std::find(addresses.begin(), addresses.end(), address);

        if (it == addresses.end()) {
            setError("requested current address is not in wallet");
            return false;
        }

        oldIndex = currentIndex;
        newIndex = static_cast<std::uint32_t>(
            std::distance(addresses.begin(), it));

        if (newIndex == oldIndex) {
            return true;
        }

        currentIndex = newIndex;
    }

    std::string persistError;
    if (persistEncryptedWalletSnapshot(passphrase, &persistError)) {
        return true;
    }

    try {
        verifyWalletTxnRecoveryStateV1(walletFilePath);

        const auto artifacts =
            walletEncryptedStartupArtifactsV1(walletFilePath);

        std::ifstream in(artifacts.publicPath);
        if (!in.good()) {
            throw std::runtime_error(
                "cannot reopen public wallet metadata after recovery");
        }

        json recoveredPublic;
        in >> recoveredPublic;

        if (!recoveredPublic.is_object() ||
            recoveredPublic.value("format", std::string{}) !=
                "TRU_WALLET_PUBLIC_V1" ||
            !recoveredPublic.contains("addresses") ||
            !recoveredPublic["addresses"].is_array() ||
            !recoveredPublic.contains("currentIndex") ||
            !recoveredPublic["currentIndex"].is_number_unsigned()) {
            throw std::runtime_error(
                "recovered public wallet metadata is invalid");
        }

        const auto recoveredAddresses =
            recoveredPublic["addresses"].get<std::vector<std::string>>();

        const std::uint32_t recoveredIndex =
            recoveredPublic["currentIndex"].get<std::uint32_t>();

        if (recoveredAddresses.empty() ||
            recoveredIndex >= recoveredAddresses.size()) {
            throw std::runtime_error(
                "recovered public wallet index is out of range");
        }

        {
            std::lock_guard<std::mutex> lk(addressesMutex);

            if (recoveredAddresses != addresses) {
                throw std::runtime_error(
                    "recovered public wallet addresses differ "
                    "from authenticated in-memory state");
            }

            currentIndex = recoveredIndex;
        }

        if (recoveredIndex == newIndex) {
            return true;
        }

        if (recoveredIndex == oldIndex) {
            setError(
                "authenticated current-address persistence failed and "
                "recovery rolled back the old committed pair: " +
                persistError);
            return false;
        }

        throw std::runtime_error(
            "recovered current index matches neither old nor new state");
    } catch (const std::exception& recoveryError) {
        lockEncryptedWallet();

        {
            std::lock_guard<std::mutex> lk(addressesMutex);
            currentIndex = oldIndex;
        }

        setError(
            "authenticated current-address persistence failed; "
            "recovery could not establish a committed state; wallet "
            "relocked and restart is required. persist=" +
            persistError + " recovery=" + recoveryError.what());
        return false;
    }
}

// -----------------------------------------------------------------------------
// TRU-SWAP-FRESH-01A — deterministic public-only per-swap role derivation.
//
// The allocationId is NOT secret. A caller must generate a unique random
// 256-bit allocationId before canonical swap creation and persist that public
// identifier with the swap/offer metadata. The wallet derives independent claim
// and refund children under a domain-separated BIP32 branch.
//
// This function returns PUBLIC material only. It deliberately does not add the
// derived children to the wallet address list and does not persist private keys.
// SWAP-FRESH-01B will wire authenticated signing to the same allocationId.
// -----------------------------------------------------------------------------
TruFreshSwapRoleKeysV1 Wallet::deriveFreshSwapRoleKeysV1(
    const std::string& allocationId) const
{
    requirePrivateAccess("deriveFreshSwapRoleKeysV1");

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        throw std::runtime_error(
            "TRU-SWAP fresh role derivation requires ENCRYPTED_UNLOCKED session");
    }

    if (allocationId.size() != 64U) {
        throw std::invalid_argument(
            "TRU-SWAP allocationId must be exactly 64 lowercase hex characters");
    }

    bool anyNonZero = false;
    for (char ch : allocationId) {
        const bool digit = ch >= '0' && ch <= '9';
        const bool lowerHex = ch >= 'a' && ch <= 'f';
        if (!digit && !lowerHex) {
            throw std::invalid_argument(
                "TRU-SWAP allocationId must be exactly 64 lowercase hex characters");
        }
        if (ch != '0') anyNonZero = true;
    }
    if (!anyNonZero) {
        throw std::invalid_argument(
            "TRU-SWAP allocationId must not be the all-zero sentinel");
    }

    const std::vector<uint8_t>* seedSource = nullptr;
    if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
        seedSource = &walletSecurityController_->unlockedSeed();
    } else {
        seedSource = &masterSeed;
    }
    if (seedSource->empty()) {
        throw std::runtime_error(
            "TRU-SWAP fresh role derivation has no authenticated seed");
    }

    const std::string domain =
        std::string("TRU-SWAP-FRESH-HD-V1|") + allocationId;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (SHA256(
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size(),
            digest) == nullptr) {
        throw std::runtime_error(
            "TRU-SWAP fresh role derivation SHA256 failed");
    }

    auto read31 = [&digest](std::size_t off) -> std::uint32_t {
        const std::uint32_t v =
            (static_cast<std::uint32_t>(digest[off]) << 24U) |
            (static_cast<std::uint32_t>(digest[off + 1U]) << 16U) |
            (static_cast<std::uint32_t>(digest[off + 2U]) << 8U) |
            static_cast<std::uint32_t>(digest[off + 3U]);
        return v & 0x7fffffffU;
    };

    const std::uint32_t a = read31(0U);
    const std::uint32_t b = read31(4U);
    const std::uint32_t c = read31(8U);
    const std::uint32_t d = read31(12U);

    struct ext_key master;
    std::memset(&master, 0, sizeof(master));

    if (bip32_key_from_seed(
            seedSource->data(),
            seedSource->size(),
            BIP32_VER_MAIN_PRIVATE,
            0,
            &master) != WALLY_OK) {
        std::memset(digest, 0, sizeof(digest));
        throw std::runtime_error(
            "TRU-SWAP fresh role derivation master-key creation failed");
    }

    auto deriveRole = [&](std::uint32_t role) -> std::vector<unsigned char> {
        // 0x54525553 == ASCII "TRUS" and is below the hardened-bit boundary.
        std::uint32_t path[10] = {
            0x80000000U | derivationPath.purpose,
            0x80000000U | derivationPath.coin_type,
            0x80000000U | derivationPath.account,
            derivationPath.change,
            0x54525553U,
            a,
            b,
            c,
            d,
            role
        };

        struct ext_key child;
        std::memset(&child, 0, sizeof(child));

        if (bip32_key_from_parent_path(
                &master,
                path,
                10,
                BIP32_FLAG_KEY_PRIVATE,
                &child) != WALLY_OK) {
            std::memset(&child, 0, sizeof(child));
            throw std::runtime_error(
                "TRU-SWAP fresh role child derivation failed");
        }

        std::vector<unsigned char> rawKey(
            child.priv_key + 1,
            child.priv_key + 33);

        ECDSAKey ecKey = ECDSAKey::fromRawBytes(rawKey);
        const std::vector<unsigned char> pub = ecKey.getCompressedSec1();

        std::fill(rawKey.begin(), rawKey.end(), 0U);
        std::memset(&child, 0, sizeof(child));

        if (pub.size() != 33U ||
            (pub[0] != 0x02U && pub[0] != 0x03U)) {
            throw std::runtime_error(
                "TRU-SWAP fresh role compressed-pubkey invariant failed");
        }

        return pub;
    };

    try {
        const std::vector<unsigned char> claimPub = deriveRole(0U);
        const std::vector<unsigned char> refundPub = deriveRole(1U);

        if (claimPub == refundPub) {
            throw std::runtime_error(
                "TRU-SWAP fresh claim/refund derivation collision");
        }

        TruFreshSwapRoleKeysV1 out;
        out.allocationId = allocationId;
        out.claimAddress = pubkeyToAddress(claimPub);
        out.claimPubkeyHex = bytesToHex(claimPub);
        out.refundAddress = pubkeyToAddress(refundPub);
        out.refundPubkeyHex = bytesToHex(refundPub);

        if (out.claimAddress.empty() ||
            out.refundAddress.empty() ||
            out.claimAddress == out.refundAddress) {
            throw std::runtime_error(
                "TRU-SWAP fresh role address invariant failed");
        }

        std::memset(digest, 0, sizeof(digest));
        std::memset(&master, 0, sizeof(master));
        return out;
    } catch (...) {
        std::memset(digest, 0, sizeof(digest));
        std::memset(&master, 0, sizeof(master));
        throw;
    }
}

TruSwapRoleKeysV1 Wallet::getSwapRoleKeysV1() const
{
    requirePrivateAccess("getSwapRoleKeysV1");

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        throw std::runtime_error(
            "TRU-SWAP role-key read requires ENCRYPTED_UNLOCKED session");
    }

    const std::vector<unsigned char> claimPub = deriveHDPublicKey(1U);
    const std::vector<unsigned char> refundPub = deriveHDPublicKey(2U);

    if (claimPub.size() != 33U ||
        (claimPub[0] != 0x02U && claimPub[0] != 0x03U) ||
        refundPub.size() != 33U ||
        (refundPub[0] != 0x02U && refundPub[0] != 0x03U) ||
        claimPub == refundPub) {
        throw std::runtime_error(
            "TRU-SWAP reserved role pubkey derivation invariant failed");
    }

    TruSwapRoleKeysV1 out;
    out.claimAddress = pubkeyToAddress(claimPub);
    out.claimPubkeyHex = bytesToHex(claimPub);
    out.refundAddress = pubkeyToAddress(refundPub);
    out.refundPubkeyHex = bytesToHex(refundPub);

    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        if (addresses.size() < 3U) {
            throw std::runtime_error(
                "TRU-SWAP role keys are not provisioned");
        }
        if (addresses[1] != out.claimAddress ||
            addresses[2] != out.refundAddress) {
            throw std::runtime_error(
                "TRU-SWAP reserved role/address binding mismatch");
        }
    }

    const ECDSAKey claimKey =
        ECDSAKey::fromPrivateKey(getPrivateKeyForAddress(out.claimAddress));
    const ECDSAKey refundKey =
        ECDSAKey::fromPrivateKey(getPrivateKeyForAddress(out.refundAddress));

    if (claimKey.getCompressedSec1() != claimPub ||
        refundKey.getCompressedSec1() != refundPub) {
        throw std::runtime_error(
            "TRU-SWAP persisted role private/public binding mismatch");
    }

    return out;
}

bool Wallet::provisionSwapRoleKeysV1(
    const std::string& passphrase,
    TruSwapRoleKeysV1& out,
    std::string* errorOut)
{
    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        setError(
            "TRU-SWAP role-key provisioning requires ENCRYPTED_UNLOCKED session");
        return false;
    }

    if (passphrase.empty()) {
        setError("TRU-SWAP role-key provisioning passphrase must not be empty");
        return false;
    }

    const std::vector<unsigned char> claimPub = deriveHDPublicKey(1U);
    const std::vector<unsigned char> refundPub = deriveHDPublicKey(2U);
    if (claimPub.size() != 33U ||
        (claimPub[0] != 0x02U && claimPub[0] != 0x03U) ||
        refundPub.size() != 33U ||
        (refundPub[0] != 0x02U && refundPub[0] != 0x03U) ||
        claimPub == refundPub) {
        setError("TRU-SWAP role pubkey derivation invariant failed");
        return false;
    }

    const std::string claimAddress = pubkeyToAddress(claimPub);
    const std::string refundAddress = pubkeyToAddress(refundPub);
    if (claimAddress.empty() || refundAddress.empty() ||
        claimAddress == refundAddress) {
        setError("TRU-SWAP role address derivation invariant failed");
        return false;
    }

    std::vector<std::string> beforeAddresses;
    std::uint32_t beforeCurrent = 0U;
    std::uint32_t beforeAddressIndex = 0U;
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        beforeAddresses = addresses;
        beforeCurrent = currentIndex;
        beforeAddressIndex = addressIndex;
    }

    // Idempotent replay after a prior successful provisioning.
    if (beforeAddresses.size() >= 3U) {
        if (beforeAddresses[1] != claimAddress ||
            beforeAddresses[2] != refundAddress) {
            setError(
                "TRU-SWAP reserved HD indices 1/2 conflict with existing wallet addresses");
            return false;
        }
        try {
            out = getSwapRoleKeysV1();
            return true;
        } catch (const std::exception& e) {
            setError(e.what());
            return false;
        }
    }

    // The live SEC-14G encrypted-first wallet has child 0 only.
    // A two-address state is treated as interrupted/ambiguous, not guessed.
    if (beforeAddresses.size() != 1U) {
        setError(
            "TRU-SWAP first role-key provisioning requires exactly one bootstrap address");
        return false;
    }

    bool sessionReplaced = false;
    bool publicMutated = false;

    std::string claimPem;
    std::string refundPem;
    std::string nextText;
    json privateObject;

    auto wipeString = [](std::string& value) {
        std::fill(value.begin(), value.end(), '\0');
        value.clear();
    };

    try {
        claimPem = deriveHDPrivateKey(1U);
        refundPem = deriveHDPrivateKey(2U);

        const ECDSAKey claimKey = ECDSAKey::fromPrivateKey(claimPem);
        const ECDSAKey refundKey = ECDSAKey::fromPrivateKey(refundPem);
        if (claimKey.getCompressedSec1() != claimPub ||
            refundKey.getCompressedSec1() != refundPub) {
            throw std::runtime_error(
                "TRU-SWAP newly derived role private/public binding mismatch");
        }

        const auto& currentMaterial =
            walletSecurityController_->unlockedPrivateMaterial();
        privateObject = json::parse(
            currentMaterial.begin(), currentMaterial.end());

        if (!privateObject.is_object()) {
            throw std::runtime_error(
                "TRU-SWAP authenticated private material is not a flat JSON object");
        }

        if (privateObject.contains(claimAddress) ||
            privateObject.contains(refundAddress)) {
            throw std::runtime_error(
                "TRU-SWAP role private keys already exist without matching public role state");
        }

        privateObject[claimAddress] = claimPem;
        privateObject[refundAddress] = refundPem;
        nextText = privateObject.dump();

        std::vector<std::uint8_t> nextPrivate(
            nextText.begin(), nextText.end());

        walletSecurityController_->replaceUnlockedPrivateMaterial(
            std::move(nextPrivate));
        sessionReplaced = true;

        {
            std::lock_guard<std::mutex> lk(addressesMutex);
            addresses.push_back(claimAddress);
            addresses.push_back(refundAddress);
            addressIndex = static_cast<std::uint32_t>(addresses.size());
            currentIndex = beforeCurrent;
        }
        publicMutated = true;

        privateObject.clear();
        wipeString(claimPem);
        wipeString(refundPem);
        wipeString(nextText);

        std::string persistError;
        if (!persistEncryptedWalletSnapshot(passphrase, &persistError)) {
            // Existing journal/recovery machinery is authoritative. Relock
            // and abort startup; the next constructor run performs recovery.
            lockEncryptedWallet();
            {
                std::lock_guard<std::mutex> lk(addressesMutex);
                addresses = beforeAddresses;
                currentIndex = beforeCurrent;
                addressIndex = beforeAddressIndex;
            }
            setError(
                "TRU-SWAP encrypted role-key persistence failed; wallet was "
                "relocked and startup must abort/restart for journal recovery: " +
                persistError);
            return false;
        }

        out = getSwapRoleKeysV1();
        return true;
    } catch (const std::exception& e) {
        privateObject.clear();
        wipeString(claimPem);
        wipeString(refundPem);
        wipeString(nextText);

        if (publicMutated) {
            std::lock_guard<std::mutex> lk(addressesMutex);
            addresses = beforeAddresses;
            currentIndex = beforeCurrent;
            addressIndex = beforeAddressIndex;
        }

        if (sessionReplaced) {
            lockEncryptedWallet();
            setError(
                std::string("TRU-SWAP role-key provisioning failed after "
                            "authenticated session mutation; wallet relocked and "
                            "startup must abort/restart: ") + e.what());
        } else {
            setError(e.what());
        }
        return false;
    }
}




//===============================================================================
// WALLET-ADDRESS-01 — authenticated public-only persistence
//===============================================================================
bool Wallet::persistEncryptedWalletPublicMetadata(
    std::string* errorOut)
{
    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        setError(
            "encrypted public-wallet persistence requires ENCRYPTED_UNLOCKED session");
        return false;
    }

    const auto artifacts = walletEncryptedStartupArtifactsV1(walletFilePath);
    if (!artifacts.completeEncryptedSet) {
        setError("encrypted public-wallet persistence requires complete artifact set");
        return false;
    }

    std::vector<std::string> publicAddresses;
    std::uint32_t publicCurrent = 0U;
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        publicAddresses = addresses;
        publicCurrent = currentIndex;
    }

    if (publicAddresses.empty() || publicCurrent >= publicAddresses.size()) {
        setError("cannot persist invalid public wallet address/index state");
        return false;
    }

    json publicJson;
    publicJson["addresses"] = publicAddresses;
    publicJson["currentIndex"] = publicCurrent;
    publicJson["format"] = "TRU_WALLET_PUBLIC_V1";
    if (publicJson.contains("privateKeys")) {
        setError("public wallet metadata unexpectedly contains privateKeys");
        return false;
    }

    const std::string publicText = publicJson.dump() + "\n";
    const std::string tempPath =
        artifacts.publicPath + ".walletaddr01." +
        std::to_string(static_cast<unsigned long long>(::getpid())) + ".new";
    bool published = false;

    try {
        // Do not interleave a public-only write with an unfinished pair-level
        // SEC-14E.3.4C transaction. Recovery remains authoritative.
        verifyWalletTxnRecoveryStateV1(walletFilePath);

        if (std::filesystem::exists(tempPath)) {
            throw std::runtime_error(
                "WALLET-ADDRESS-01 public metadata stage collision");
        }

        const int fd = ::open(
            tempPath.c_str(),
            O_WRONLY | O_CREAT | O_EXCL,
            S_IRUSR | S_IWUSR);
        if (fd < 0) {
            throw std::runtime_error(
                "WALLET-ADDRESS-01 cannot create public metadata stage: " +
                std::string(std::strerror(errno)));
        }

        bool fdOpen = true;
        try {
            std::size_t off = 0U;
            while (off < publicText.size()) {
                const ssize_t n = ::write(
                    fd,
                    publicText.data() + off,
                    publicText.size() - off);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    throw std::runtime_error(
                        "WALLET-ADDRESS-01 public metadata write failed: " +
                        std::string(std::strerror(errno)));
                }
                if (n == 0) {
                    throw std::runtime_error(
                        "WALLET-ADDRESS-01 public metadata short write");
                }
                off += static_cast<std::size_t>(n);
            }
            if (::fsync(fd) != 0) {
                throw std::runtime_error(
                    "WALLET-ADDRESS-01 public metadata fsync failed: " +
                    std::string(std::strerror(errno)));
            }
            if (::close(fd) != 0) {
                fdOpen = false;
                throw std::runtime_error(
                    "WALLET-ADDRESS-01 public metadata close failed: " +
                    std::string(std::strerror(errno)));
            }
            fdOpen = false;
        } catch (...) {
            if (fdOpen) ::close(fd);
            ::unlink(tempPath.c_str());
            throw;
        }

        if (::rename(tempPath.c_str(), artifacts.publicPath.c_str()) != 0) {
            const int saved = errno;
            ::unlink(tempPath.c_str());
            throw std::runtime_error(
                "WALLET-ADDRESS-01 public metadata atomic rename failed: " +
                std::string(std::strerror(saved)));
        }
        published = true;
        fsyncParentDirectoryTxnV1(artifacts.publicPath);

        std::ifstream verifyIn(artifacts.publicPath);
        if (!verifyIn.good()) {
            throw std::runtime_error(
                "WALLET-ADDRESS-01 cannot reopen committed public metadata");
        }
        json verified;
        verifyIn >> verified;
        if (verified != publicJson) {
            throw std::runtime_error(
                "WALLET-ADDRESS-01 committed public metadata readback mismatch");
        }
        return true;
    } catch (const std::exception& e) {
        if (!published) {
            ::unlink(tempPath.c_str());
            setError(e.what());
            return false;
        }

        // Rename occurred but durability/readback failed. Do not continue with
        // an authenticated signing session whose durable public state is
        // uncertain. Startup will reload the authoritative committed file.
        lockEncryptedWallet();
        setError(
            std::string(
                "WALLET-ADDRESS-01 public metadata publication became uncertain; "
                "wallet relocked and restart is required: ") + e.what());
        return false;
    }
}

//===============================================================================
// WALLET-ADDRESS-01 — authenticated encrypted getnewaddress
//===============================================================================
bool Wallet::generateNewAddressEncrypted(
    std::string& addressOut,
    std::string& publicKeyHexOut,
    std::uint32_t& indexOut,
    std::string* errorOut)
{
    std::lock_guard<std::mutex> mutationLock(encryptedMutationMutex_);

    addressOut.clear();
    publicKeyHexOut.clear();
    indexOut = 0U;
    auto setError = [errorOut](const std::string& msg) {
        if (errorOut) *errorOut = msg;
    };

    if (getWalletSecurityMode() != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !walletSecurityController_->sessionUnlocked()) {
        setError("getnewaddress requires an authenticated ENCRYPTED_UNLOCKED wallet");
        return false;
    }
    requirePrivateAccess("generateNewAddressEncrypted");

    std::vector<std::string> beforeAddresses;
    std::uint32_t beforeCurrent = 0U;
    std::uint32_t beforeAddressIndex = 0U;
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        beforeAddresses = addresses;
        beforeCurrent = currentIndex;
        beforeAddressIndex = addressIndex;
    }

    // Children 1 and 2 are permanently reserved by TRU-SWAP-B. The existing
    // production wallet provisions them at public positions 1 and 2. Refuse
    // ambiguous address ordering rather than consume or renumber a swap key.
    if (beforeAddresses.size() < 3U) {
        setError(
            "WALLET-ADDRESS-01 requires reserved swap HD children 1/2 to be "
            "provisioned before general address generation");
        return false;
    }
    if (beforeAddresses.size() >
        static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        setError("WALLET-ADDRESS-01 address index overflow");
        return false;
    }

    // Prove the persisted public ordering is the canonical HD-child ordering.
    // This makes the address position itself a durable HD index without
    // introducing a second plaintext index database.
    try {
        for (std::size_t i = 0; i < beforeAddresses.size(); ++i) {
            const auto pub = deriveHDPublicKey(static_cast<std::uint32_t>(i));
            if (pubkeyToAddress(pub) != beforeAddresses[i]) {
                setError(
                    "WALLET-ADDRESS-01 refuses non-canonical/ambiguous HD address ordering");
                return false;
            }
        }
    } catch (const std::exception& e) {
        setError(std::string("WALLET-ADDRESS-01 HD ordering proof failed: ") + e.what());
        return false;
    }

    const std::uint32_t idx =
        static_cast<std::uint32_t>(beforeAddresses.size());
    std::vector<unsigned char> pub;
    std::string addr;
    std::string privPem;
    try {
        pub = deriveHDPublicKey(idx);
        if (pub.size() != 33U || (pub[0] != 0x02U && pub[0] != 0x03U)) {
            throw std::runtime_error("derived compressed public key is invalid");
        }
        addr = pubkeyToAddress(pub);
        if (addr.empty()) {
            throw std::runtime_error("derived address is empty");
        }
        if (std::find(beforeAddresses.begin(), beforeAddresses.end(), addr) !=
            beforeAddresses.end()) {
            throw std::runtime_error("derived address already exists in wallet");
        }

        // Spendability proof before publishing public state. The private key is
        // derived only from the authenticated encrypted seed, never persisted
        // in plaintext and never returned by RPC.
        privPem = deriveHDPrivateKey(idx);
        const ECDSAKey key = ECDSAKey::fromPrivateKey(privPem);
        if (key.getCompressedSec1() != pub) {
            throw std::runtime_error("derived private/public binding mismatch");
        }
    } catch (const std::exception& e) {
        if (!privPem.empty()) {
            sodium_memzero(privPem.data(), privPem.size());
            privPem.clear();
        }
        setError(std::string("WALLET-ADDRESS-01 derivation failed: ") + e.what());
        return false;
    }
    if (!privPem.empty()) {
        sodium_memzero(privPem.data(), privPem.size());
        privPem.clear();
        privPem.shrink_to_fit();
    }

    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        if (addresses != beforeAddresses ||
            currentIndex != beforeCurrent ||
            addressIndex != beforeAddressIndex) {
            setError("WALLET-ADDRESS-01 concurrent wallet mutation detected");
            return false;
        }
        addresses.push_back(addr);
        addressIndex = static_cast<std::uint32_t>(addresses.size());
        currentIndex = idx;
    }

    std::string persistError;
    if (!persistEncryptedWalletPublicMetadata(&persistError)) {
        if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
            std::lock_guard<std::mutex> lk(addressesMutex);
            addresses = beforeAddresses;
            currentIndex = beforeCurrent;
            addressIndex = beforeAddressIndex;
        }
        setError(
            "WALLET-ADDRESS-01 public persistence failed: " + persistError);
        return false;
    }

    addressOut = addr;
    publicKeyHexOut = bytesToHex(pub);
    indexOut = idx;
    Logger::log(
        "[WALLET-ADDRESS-01] generated authenticated encrypted HD address index=" +
        std::to_string(idx) + " address=" + addr);
    return true;
}

std::string Wallet::create_wallet(const std::string& filePath) {
    // SEC-14D.0: creation is create-only. Never allow a load/decrypt/parse
    // failure to fall through into truncating or replacing an existing wallet.
    if (!filePath.empty() && std::filesystem::exists(filePath)) {
        Logger::log("[create_wallet] REFUSING to overwrite existing wallet file: " + filePath);
        throw std::runtime_error(
            "[create_wallet] Wallet file already exists; refusing destructive recreation");
    }

    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        Logger::log("[create_wallet] Clearing old addresses");
        addresses.clear();
        privateKeys.clear();
        addressIndex = 0;
        currentIndex = 0;
    }

    // Derive first address (this will call generateNewAddress, which now
    // saves outside its own lock)
    std::string firstAddr = generateNewAddress();
    Logger::log("[create_wallet] First address=" + firstAddr);

    // Persist file (no deadlock, mutex not held here)
    if (!saveToFile(filePath)) {
        throw std::runtime_error("[create_wallet] saveToFile failed");
    }
    return firstAddr;
}
//===============================================================================
//                     LOAD WALLET
//===============================================================================
bool Wallet::loadFromFile(const std::string& filepath) {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        throw std::runtime_error("[SEC-14E.3.1B] plaintext wallet load refused in encrypted mode");
    }
    // A missing wallet is the only condition represented by false. If a file
    // exists but cannot be opened/parsed/initialized, fail closed by throwing.
    if (!std::filesystem::exists(filepath)) {
        return false;
    }

    std::ifstream ifs(filepath);
    if (!ifs.good()) {
        Logger::log("[loadFromFile] Existing wallet file cannot be opened: " + filepath);
        throw std::runtime_error(
            "[loadFromFile] Existing wallet file cannot be opened");
    }

    try {
        json j; ifs >> j;
        std::lock_guard<std::mutex> lk(addressesMutex);

        addresses    = j.value("addresses", std::vector<std::string>{});
        privateKeys  = j.value("privateKeys", std::unordered_map<std::string,std::string>{});
        currentIndex = j.value("currentIndex", 0u);
        addressIndex = static_cast<uint32_t>(addresses.size());
        if (addresses.empty()) {
            generateNewAddress();
        }
        return true;
    } catch (const std::exception& e) {
        Logger::log(
            "[loadFromFile] REFUSING unreadable/corrupt existing wallet file: " +
            filepath + " error=" + e.what());
        throw;
    } catch (...) {
        Logger::log(
            "[loadFromFile] REFUSING unreadable/corrupt existing wallet file: " +
            filepath + " error=unknown");
        throw;
    }
}

//===============================================================================
//                     SAVE TO FILE
//===============================================================================
bool Wallet::saveToFile(const std::string& filepath) const {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        Logger::log(
            "[SEC-14E.3.3B] plaintext wallet save refused in encrypted mode");
        return false;
    }

    if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_LOCKED) {
        Logger::log("[SEC-14E.3.1B] plaintext wallet save refused while ENCRYPTED_LOCKED");
        return false;
    }
    std::lock_guard<std::mutex> lk(addressesMutex);
    try {
        json j;
        j["addresses"]    = addresses;
        j["privateKeys"]  = privateKeys;
        j["currentIndex"] = currentIndex;
        std::ofstream ofs(filepath);
        if (!ofs.good()) return false;
        ofs << j.dump(4);
        return true;
    } catch (...) {
        return false;
    }
}

//===============================================================================
//                      GENERATE NEW ADDRESS
//===============================================================================
std::string Wallet::generateNewAddress() {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        throw std::runtime_error(
            "[SEC-14E.3.3B] encrypted wallet mutation refused until authenticated persistence is active");
    }

    std::string addr, priv;
    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        uint32_t idx = getNextIndex();                 // persistent index
        addr = deriveHDAddress(idx);
        priv = deriveHDPrivateKey(idx);
        addresses.push_back(addr);
        privateKeys[addr] = priv;
        addressIndex   = static_cast<uint32_t>(addresses.size());
        currentIndex   = addressIndex - 1;
        Logger::log("[generateNewAddress] idx=" + std::to_string(idx) + " addr=" + addr);
    }
    // Save _after_ unlocking
    saveToFile(walletFilePath);
    return addr;
}
//===============================================================================
// 			GET CURRENT Index
//===============================================================================
uint32_t Wallet::getCurrentIndex() const {
    std::lock_guard<std::mutex> lock(addressesMutex);
    return currentIndex;
}
//===============================================================================
// 			GET CURRENT ADDRESS
//===============================================================================
std::string Wallet::getCurrentAddress() const {
    std::lock_guard<std::mutex> lock(addressesMutex);
    if (addresses.empty()) {
        throw std::runtime_error("[Wallet] No addresses in wallet");
    }
    return addresses[currentIndex];
}
//===============================================================================
//                      GET ALL ADDRESS
//===============================================================================
std::vector<std::string> Wallet::getAllAddresses() const {
    std::lock_guard<std::mutex> lock(addressesMutex);
    Logger::log("[Wallet::getAllAddresses] Returning " + std::to_string(addresses.size()) + " addresses");
    return addresses;
}
//===============================================================================
// 			SET ADDRESS
//===============================================================================
 void Wallet::setCurrentAddress(const std::string& address) {
    if (getWalletSecurityMode() != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        throw std::runtime_error(
            "[SEC-14E.3.3B] encrypted wallet mutation refused until authenticated persistence is active");
    }

    {
        std::lock_guard<std::mutex> lk(addressesMutex);
        auto it = std::find(addresses.begin(), addresses.end(), address);
        if (it == addresses.end()) {
            throw std::runtime_error("[setCurrentAddress] Not found: " + address);
        }
        currentIndex = static_cast<uint32_t>(std::distance(addresses.begin(), it));
    }
    // Persist outside the lock
    if (!saveToFile(walletFilePath)) {
        throw std::runtime_error("[setCurrentAddress] Failed to persist currentIndex");
    }
}
//===============================================================================
//                      GET PRIVATE KEYS FOR ADDRESS
//===============================================================================
std::string Wallet::getPrivateKeyForAddress(const std::string& addr) {
    requirePrivateAccess("getPrivateKeyForAddress");

    if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
        const auto& material =
            walletSecurityController_->unlockedPrivateMaterial();

        json privateObject;
        try {
            privateObject = json::parse(material.begin(), material.end());
        } catch (const std::exception&) {
            throw std::runtime_error(
                "[getPrivateKeyForAddress] authenticated private material is not valid JSON");
        }

        if (!privateObject.is_object()) {
            throw std::runtime_error(
                "[getPrivateKeyForAddress] authenticated private material is not an object");
        }

        const auto persisted = privateObject.find(addr);
        if (persisted != privateObject.end()) {
            if (!persisted->is_string()) {
                throw std::runtime_error(
                    "[getPrivateKeyForAddress] persisted private key has invalid encoding");
            }
            return persisted->get<std::string>();
        }

        // WALLET-ADDRESS-01: newly generated encrypted-wallet receive keys are
        // deterministic HD children of the authenticated encrypted seed. They
        // intentionally do not duplicate PEM material into tru.dat.enc.
        std::uint32_t hdIndex = 0U;
        {
            std::lock_guard<std::mutex> lk(addressesMutex);
            const auto it = std::find(addresses.begin(), addresses.end(), addr);
            if (it == addresses.end()) {
                throw std::runtime_error(
                    "[getPrivateKeyForAddress] Unknown address");
            }
            const auto distance = std::distance(addresses.begin(), it);
            if (distance < 0 ||
                static_cast<unsigned long long>(distance) >
                    static_cast<unsigned long long>(
                        std::numeric_limits<std::uint32_t>::max())) {
                throw std::runtime_error(
                    "[getPrivateKeyForAddress] HD address index overflow");
            }
            hdIndex = static_cast<std::uint32_t>(distance);
        }

        const auto pub = deriveHDPublicKey(hdIndex);
        if (pubkeyToAddress(pub) != addr) {
            throw std::runtime_error(
                "[getPrivateKeyForAddress] address is not bound to its canonical HD index");
        }
        return deriveHDPrivateKey(hdIndex);
    }

    std::lock_guard<std::mutex> lk(addressesMutex);
    auto it = privateKeys.find(addr);
    if (it == privateKeys.end()) {
        throw std::runtime_error("[getPrivateKeyForAddress] Unknown address");
    }
    return it->second;
}

// ------------------------------
// debugPrintWalletAddressHashes
// ------------------------------
void Wallet::debugPrintWalletAddressHashes() const
{
    std::cout << "[debugPrintWalletAddressHashes] wallet has " << addresses.size() << " addresses.\n";
    for(size_t i=0; i<addresses.size(); i++){
        const std::string &addr = addresses[i];
        try {
            std::vector<unsigned char> raw = base58Decode(addr);
            if(raw.size()!=25){
                std::cout << "   ["<<i<<"] " << addr << " => not 25 bytes?!\n";
                continue;
            }
            // raw[0] => TRU P2PKH version, next 20 => hash160
            std::vector<unsigned char> h20(raw.begin()+1, raw.begin()+21);
            std::string hexHash = bytesToHex(h20);
            std::cout << "   ["<< i <<"] " << addr
                      << "\n        hash160=" << hexHash << "\n";
        } catch(...){
            std::cout << "   ["<< i <<"] " << addr << " => error decoding base58?\n";
        }
    }
}

//================================================================================
//			Get ADDRESS BALANCE
//================================================================================
double Wallet::getAddressBalance(const std::string& addr) const {
    if (!isLocalChain || !blockchainPtr) {
        throw std::runtime_error("[getAddressBalance] No local chain available");
    }
    return blockchainPtr->calculate_balance(addr);
}
//================================================================================
//			CHECK BALANCE
//================================================================================


double Wallet::check_balance(bool includeUnconfirmed) const {
    double totalSatoshis = 0.0;

    // Sum all confirmed local UTXOs
    for (const auto& kv : localUtxos) {
        const LocalUtxo& u = kv.second;
        totalSatoshis += static_cast<double>(u.amount);
        Logger::log("[check_balance] Added confirmed UTXO " + u.txid + ":" + std::to_string(u.vout) + ", amount: " + std::to_string(u.amount));
    }

    // Adjust for unconfirmed transactions if requested and mempool is available
    if (includeUnconfirmed && mempool && blockchainPtr) {
        // Subtract UTXOs spent in the mempool
        for (const auto& kv : localUtxos) {
            const LocalUtxo& u = kv.second;
            if (mempool->isUTXOSpentInMempool(u.txid, u.vout)) {
                totalSatoshis -= static_cast<double>(u.amount);
                Logger::log("[check_balance] Subtracted spent mempool UTXO " + u.txid + ":" + std::to_string(u.vout) + ", amount: " + std::to_string(u.amount));
            }
        }

        // Add outputs from mempool transactions to wallet addresses
        auto mempoolTxns = mempool->getAllTransactions();
        for (const auto& tx : mempoolTxns) {
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                const TxOut& vout = tx.vout[i];
                std::string addr = extractAddressFromScriptPubKey(vout.scriptPubKey, tx.txid, static_cast<uint32_t>(i), blockchainPtr);
                if (!addr.empty() && ownsAddress(addr)) {
                    totalSatoshis += static_cast<double>(vout.amount);
                    Logger::log("[check_balance] Added mempool output " + tx.txid + ":" + std::to_string(i) + " to " + addr + ", amount: " + std::to_string(vout.amount));
                }
            }
        }
    }

    // Convert from TRU atoms to TRU (1 TRU = 10^8 TRU atoms)
    double balance = totalSatoshis / 1e8;
    Logger::log("[check_balance] Final balance: " + std::to_string(balance) + " TRU (includeUnconfirmed=" + (includeUnconfirmed ? "true" : "false") + ")");
    return balance;
}
//================================================================================
//                      Force Clear
//================================================================================
void Wallet::forceClearUTXOCache() {
    {
        extern std::unordered_map<std::string, std::vector<std::pair<std::string, uint64_t>>> utxoCache;
        extern std::shared_mutex utxoCacheMutex;
        extern int cacheHeight;

        std::unique_lock<std::shared_mutex> lock(utxoCacheMutex);
        utxoCache.clear();
        cacheHeight = 0;
        Logger::log("[Wallet::forceClearUTXOCache] Cleared in-memory UTXO cache.");
    }
}

//================================================================================
//			Wallet Mine
//================================================================================
std::string Wallet::mine() {
    if (!isLocalChain || !blockchainPtr) {
        return "[mine] No local chain => can't CPU mine.";
    }
    if (addresses.empty()) {
        Logger::log("[mine] No addresses in wallet, generating one.");
        generateNewAddress(); // Ensure at least one address exists
    }
    std::string minerAddr = getCurrentAddress();
    Logger::log("[DEBUG] CPU mining to => " + minerAddr);
    Block b = blockchainPtr->mineBlockCPU(nullptr, minerAddr);
    if (b.blockHash.empty()) {
        return "[mine] Mining failed => no solution found.";
    }
    return "[mine] Mined block => " + b.blockHash;
}
//================================================================================
//                      Wallet SEND TRANSACTION
//================================================================================
std::string Wallet::send_transaction(const std::string &recipient, uint64_t amountAtoms, const std::string &nodeIP, int nodePort) {
    Logger::log("[send_transaction] Starting transaction: recipient=" + recipient +
                ", amount=" + tru_amount::format(amountAtoms) +
                ", atoms=" + std::to_string(amountAtoms) +
                ", node=" + nodeIP + ":" + std::to_string(nodePort));

    try {
        // Validate inputs
        if (amountAtoms == 0 || amountAtoms > tru_limits::MAX_MONEY) {
            Logger::log("[send_transaction] Error: Amount outside valid monetary range");
            throw std::invalid_argument("[send_transaction] Amount must be 1..MAX_MONEY TRU atoms");
        }

        std::string sender = getCurrentAddress();
        if (sender.empty()) {
            Logger::log("[send_transaction] Error: No current address set");
            throw std::runtime_error("[send_transaction] No sender address available");
        }
        Logger::log("[send_transaction] Sender address: " + sender);

        // Validate recipient address
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            Logger::log("[send_transaction] Error: Invalid recipient address: " + err);
            throw std::invalid_argument("[send_transaction] Invalid recipient address: " + err);
        }

        // 30B3: caller supplies exact TRU atoms; no floating-point conversion.
        uint64_t fee = WALLET_MIN_BASE_FEE;
        if (amountAtoms > std::numeric_limits<uint64_t>::max() - fee) {
            throw std::overflow_error("[send_transaction] amount + fee overflow");
        }
        uint64_t needed = amountAtoms + fee;
        Logger::log("[send_transaction] Amount to send: " + std::to_string(amountAtoms) + " TRU atoms, fee: " +
                    std::to_string(fee) + ", total needed: " + std::to_string(needed));

        // Fetch UTXOs
        std::vector<UTXO> utxos;
        if (isLocalChain && blockchainPtr) {
            utxos = blockchainPtr->utxoSet.getUTXOsForAddress(sender);
            Logger::log("[send_transaction] Retrieved " + std::to_string(utxos.size()) + " UTXOs from local chain for " + sender);
        } else {
            utxos = getUTXOsForAddressRPC(sender, nodeIP, nodePort);
            Logger::log("[send_transaction] Retrieved " + std::to_string(utxos.size()) + " UTXOs via RPC for " + sender);
        }

        // apply consensus spendability rules before
        // ordinary TRU input selection.
        std::vector<UTXO> availableUtxos;
        if (isLocalChain && blockchainPtr) {
            LevelDBStorage* storage = blockchainPtr->getStorage();
            const int tipHeight = blockchainPtr->getBestTipHeight();
            const uint32_t candidateHeight =
                tipHeight >= 0 ? static_cast<uint32_t>(tipHeight + 1) : 0;

            for (const auto& u : utxos) {
                const std::string outpoint = u.txid + ":" + std::to_string(u.vout);

                if (mempool && mempool->isUTXOSpentInMempool(u.txid, u.vout)) {
                    Logger::log("[send_transaction] UTXO spent in mempool, skipped: " + outpoint);
                    continue;
                }
                if (isSwapPreparedFundingInputReserved(storage, u.txid, u.vout)) {
                    Logger::log(
                        "[send_transaction] Prepared-funding reserved UTXO skipped: " +
                        outpoint);
                    continue;
                }

                // Never spend a token-controlling output as ordinary TRU.
                if (storage && storage->exists("tokenUTXO:" + u.txid + ":" + std::to_string(u.vout))) {
                    Logger::log("[send_transaction] Token-controlling UTXO skipped: " + outpoint);
                    continue;
                }

                if (u.isCoinbase) {
                    if (tipHeight < 0 || candidateHeight <= u.createdAtHeight ||
                        (candidateHeight - u.createdAtHeight) <
                            static_cast<uint32_t>(COINBASE_MATURITY)) {
                        const uint32_t spendableAt =
                            u.createdAtHeight + static_cast<uint32_t>(COINBASE_MATURITY);
                        Logger::log(
                            "[send_transaction] Immature coinbase skipped: " + outpoint +
                            " created=" + std::to_string(u.createdAtHeight) +
                            " tip=" + std::to_string(tipHeight) +
                            " spendableAt=" + std::to_string(spendableAt));
                        continue;
                    }
                }

                // ordinary TRU sends may
                // spend only canonical P2PKH coin outputs owned by `sender`.
                // Protocol/data/control outputs can carry TRU atoms too, but
                // must never be treated as generic spendable TRU.
                const std::string& spk = u.scriptPubKey;
                const bool canonicalP2PKH =
                    spk.size() == 50 &&
                    spk.rfind("76a914", 0) == 0 &&
                    spk.compare(spk.size() - 4, 4, "88ac") == 0 &&
                    std::all_of(spk.begin(), spk.end(),
                        [](unsigned char c) {
                            return std::isxdigit(c) != 0;
                        });

                if (!canonicalP2PKH) {
                    Logger::log(
                        "[send_transaction] Non-P2PKH/protocol UTXO skipped: " +
                        outpoint + " script=" + spk);
                    continue;
                }

                if (!doesScriptPayToAddress(spk, sender)) {
                    Logger::log(
                        "[send_transaction] P2PKH UTXO does not pay sender, skipped: " +
                        outpoint);
                    continue;
                }

                availableUtxos.push_back(u);
                Logger::log("[send_transaction] Spendable standard P2PKH UTXO: " +
                            outpoint + " amount=" + std::to_string(u.amount));
            }
        } else {
            // Remote mode relies on listunspent RPC to return spendable UTXOs.
            availableUtxos = utxos;
        }

        if (availableUtxos.empty()) {
            Logger::log("[send_transaction] Error: No available UTXOs for sender");
            throw std::runtime_error("[send_transaction] No available UTXOs for sender");
        }

        // Select UTXOs
        uint64_t totalInput = 0;
        std::vector<UTXO> selected;
        for (const auto& u : availableUtxos) {
            Logger::log("[send_transaction] Evaluating UTXO: txid=" + u.txid + ", vout=" + std::to_string(u.vout) +
                        ", amount=" + std::to_string(u.amount) + " TRU atoms");
            if (u.amount == 0) {
                Logger::log("[send_transaction] Skipping UTXO with zero amount: " + u.txid + ":" + std::to_string(u.vout));
                continue;
            }

            // defense in depth.
            const std::string& selectedSpk = u.scriptPubKey;
            const bool selectedIsP2PKH =
                selectedSpk.size() == 50 &&
                selectedSpk.rfind("76a914", 0) == 0 &&
                selectedSpk.compare(selectedSpk.size() - 4, 4, "88ac") == 0 &&
                std::all_of(selectedSpk.begin(), selectedSpk.end(),
                    [](unsigned char c) {
                        return std::isxdigit(c) != 0;
                    });

            if (!selectedIsP2PKH ||
                !doesScriptPayToAddress(selectedSpk, sender)) {
                Logger::log(
                    "[send_transaction] Defensive selection reject: " +
                    u.txid + ":" + std::to_string(u.vout));
                continue;
            }

            selected.push_back(u);
            totalInput += u.amount;
            if (totalInput >= needed) break;
        }

        if (totalInput < needed) {
            Logger::log("[send_transaction] Error: Insufficient balance: need=" + std::to_string(needed) +
                        ", have=" + std::to_string(totalInput));
            throw std::runtime_error("[send_transaction] Insufficient balance: need " + std::to_string(needed) +
                                     ", have " + std::to_string(totalInput));
        }
        Logger::log("[send_transaction] Selected " + std::to_string(selected.size()) +
                    " UTXOs with total input: " + std::to_string(totalInput) + " TRU atoms");

        // Build transaction
        Transaction tx(false);
        tx.set_sender(sender);
        for (const auto& s : selected) {
            Logger::log("[send_transaction] Adding input: txid=" + s.txid + ", vout=" + std::to_string(s.vout));
            tx.vin.emplace_back(s.txid, s.vout);
        }

        std::string recScript = createP2PKHScriptHexFromAddress(recipient);
        Logger::log("[send_transaction] Adding output: amount=" + std::to_string(amountAtoms) +
                    " TRU atoms, scriptPubKey=" + recScript);
        tx.vout.emplace_back(amountAtoms, recScript);

        uint64_t leftover = totalInput - needed;
        std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
        if (leftover > 0) {
            std::string changeScript = createP2PKHScriptHexFromAddress(sender);
            Logger::log("[send_transaction] Adding change output: amount=" + std::to_string(leftover) +
                        " TRU atoms, scriptPubKey=" + changeScript);
            tx.vout.emplace_back(leftover, changeScript);
            feeBearingVout = tx.vout.size() - 1;
        }

        fee = applyWalletPolicyFee(
            tx, fee, feeBearingVout, "send_transaction");

        // Sign transaction, passing nodeIP and nodePort for RPC mode
        Logger::log("[send_transaction] Signing transaction");
        if (!signTransaction(tx, nodeIP, nodePort)) {
            Logger::log("[send_transaction] Error: Failed to sign transaction");
            throw std::runtime_error("[send_transaction] Failed to sign transaction");
        }

        // Compute TXID
        tx.computeTxId();
        Logger::log("[send_transaction] Transaction ID computed: " + tx.txid);

        // Serialize transaction
        std::string txHex = bytesToHex(tx.serializeBinary());
        Logger::log("[send_transaction] Serialized transaction hex: " + txHex);

        // success means accepted by the mempool,
        // never merely queued for later validation.
        if (isLocalChain) {
            if (!blockchainPtr || !blockchainPtr->mempool) {
                throw std::runtime_error("[send_transaction] Local blockchain/mempool unavailable");
            }

            Logger::log("[send_transaction] Submitting synchronously to local mempool");
            if (!blockchainPtr->broadcastTransaction(tx)) {
                Logger::log("[send_transaction] ERROR: local mempool rejected TX => " + tx.txid);
                throw std::runtime_error(
                    "[send_transaction] Transaction rejected by local mempool; see Tru_debug.log");
            }
            Logger::log("[send_transaction] Transaction accepted by local mempool: " + tx.txid);
        } else {
            Logger::log("[send_transaction] Broadcasting transaction to " + nodeIP + ":" + std::to_string(nodePort));
            if (!rpcBroadcastTx(txHex, nodeIP, nodePort)) {
                Logger::log("[send_transaction] ERROR: RPC broadcast failed");
                throw std::runtime_error("[send_transaction] RPC broadcast failed");
            }
            Logger::log("[send_transaction] Transaction successfully broadcasted");
        }

        Logger::log("[send_transaction] Transaction accepted successfully, txid: " + tx.txid);
        return "[send_transaction] TX => " + tx.txid;

    } catch (const std::exception& ex) {
        Logger::log("[send_transaction] Exception: " + std::string(ex.what()));
        throw std::runtime_error("[send_transaction] Exception: " + std::string(ex.what()));
    } catch (...) {
        Logger::log("[send_transaction] Unknown error occurred");
        throw std::runtime_error("[send_transaction] Unknown error occurred");
    }
}
//====================================================================================
//              MS-01D — Deterministic Multisig / Escrow V1 Spend Template
//====================================================================================
namespace {
struct MultisigEscrowSpendTemplateV1 {
    Transaction tx;
    UTXO utxo;
    std::vector<unsigned char> lockScript;
    tru_contract_call::CanonicalMultisig2of3V1Info info;
    std::vector<unsigned char> sighash;
    std::uint64_t releaseAmountAtoms{0};
    std::uint64_t feeAtoms{0};
};

static MultisigEscrowSpendTemplateV1 buildMultisigEscrowSpendTemplateV1(
    Blockchain* chain,
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress)
{
    if (!chain || !chain->mempool) {
        throw std::runtime_error(
            "Multisig / Escrow V1 redemption requires a local chain + mempool");
    }
    if (contractTxid.size() != 64U || !isValidHex(contractTxid)) {
        throw std::invalid_argument("Multisig / Escrow V1 requires a 64-hex funding TXID");
    }
    if (contractVout != 1U) {
        throw std::invalid_argument(
            "Multisig / Escrow V1 canonical contract output is vout 1");
    }
    if (!isValidAddress(recipientAddress)) {
        throw std::invalid_argument(
            "Multisig / Escrow V1 redemption recipient must be a valid TRU P2PKH address");
    }
    if (chain->mempool->isUTXOSpentInMempool(contractTxid, contractVout)) {
        throw std::runtime_error(
            "Multisig / Escrow V1 outpoint already has a pending mempool spend");
    }

    UTXO utxo;
    if (!chain->utxoSet.getUTXO(contractTxid, contractVout, utxo)) {
        throw std::runtime_error(
            "Confirmed Multisig / Escrow V1 UTXO not found; mine/confirm creation first or it is already spent");
    }
    if (utxo.amount == 0 || utxo.amount > tru_limits::MAX_MONEY) {
        throw std::runtime_error("Multisig / Escrow V1 UTXO amount is invalid");
    }

    std::vector<unsigned char> lockScript;
    if (!tru_contract_call::DecodeScriptHexStrict(utxo.scriptPubKey, lockScript)) {
        throw std::runtime_error("Multisig / Escrow V1 locking script hex is malformed");
    }

    tru_contract_call::CanonicalMultisig2of3V1Info info;
    if (!tru_contract_call::ParseCanonicalMultisig2of3V1Script(lockScript, info)) {
        throw std::runtime_error(
            "Funding outpoint is not canonical Multisig / Escrow V1");
    }

    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(contractTxid, contractVout);
    tx.vout.emplace_back(1U, createP2PKHScriptHexFromAddress(recipientAddress));

    const std::uint64_t fee = estimateWalletPolicyFee(tx);
    if (utxo.amount <= fee) {
        throw std::runtime_error(
            "Multisig / Escrow V1 value is too small to pay the current relay fee");
    }
    const std::uint64_t releaseAmount = utxo.amount - fee;
    tx.vout[0].amount = releaseAmount;

    const std::vector<unsigned char> sighash = tx.getSigHash(0, lockScript);
    if (sighash.size() != 32U) {
        throw std::runtime_error("Multisig / Escrow V1 sighash invariant failed");
    }

    MultisigEscrowSpendTemplateV1 out;
    out.tx = std::move(tx);
    out.utxo = utxo;
    out.lockScript = std::move(lockScript);
    out.info = info;
    out.sighash = sighash;
    out.releaseAmountAtoms = releaseAmount;
    out.feeAtoms = fee;
    return out;
}

static std::size_t multisigParticipantIndexV1(
    const tru_contract_call::CanonicalMultisig2of3V1Info& info,
    const std::vector<unsigned char>& pubkey)
{
    for (std::size_t i = 0; i < info.pubkeys.size(); ++i) {
        if (std::equal(info.pubkeys[i].begin(), info.pubkeys[i].end(), pubkey.begin(), pubkey.end())) {
            return i;
        }
    }
    return info.pubkeys.size();
}

static ECDSAKey loadWalletPrivateMaterialV1(const std::string& material)
{
    if (material.find("-----BEGIN") != std::string::npos) {
        return ECDSAKey::fromPrivateKey(material);
    }
    if (material.size() == 64U && isValidHex(material)) {
        const auto raw = hexDecode(material);
        if (raw.size() != 32U) {
            throw std::runtime_error("raw private key must be 32 bytes");
        }
        return ECDSAKey::fromRawBytes(raw);
    }
    throw std::runtime_error("unsupported wallet private-key encoding");
}
} // namespace

//====================================================================================
//              MS-01C — Create Multisig / Escrow V1
//====================================================================================
MultisigEscrowCreateResult Wallet::createMultisigEscrowV1(
    const std::array<std::string, 3>& compressedPubkeysHex,
    std::uint64_t amountAtoms)
{
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "Multisig / Escrow V1 creation requires a local chain + mempool");
    }
    if (amountAtoms == 0 || amountAtoms > tru_limits::MAX_MONEY) {
        throw std::invalid_argument(
            "Multisig / Escrow V1 amount must be 1..MAX_MONEY TRU atoms");
    }

    const std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error(
            "Multisig / Escrow V1 requires a current funding address");
    }

    std::array<std::array<unsigned char, 33>, 3> participantKeys{};
    for (std::size_t i = 0; i < compressedPubkeysHex.size(); ++i) {
        std::vector<unsigned char> decoded;
        if (!tru_contract_call::DecodeScriptHexStrict(
                compressedPubkeysHex[i], decoded) ||
            decoded.size() != 33U) {
            throw std::invalid_argument(
                "Participant " + std::to_string(i + 1) +
                " must be exactly 33-byte compressed SEC1 hex");
        }
        std::copy(decoded.begin(), decoded.end(), participantKeys[i].begin());
        if (!tru_contract_call::IsCanonicalCompressedSecp256k1Encoding(
                participantKeys[i])) {
            throw std::invalid_argument(
                "Participant " + std::to_string(i + 1) +
                " must begin with compressed SEC1 prefix 02 or 03");
        }
    }

    std::vector<unsigned char> lockScript;
    tru_contract_call::CanonicalMultisig2of3V1Info canonicalInfo;
    if (!tru_contract_call::BuildCanonicalMultisig2of3V1Script(
            participantKeys, lockScript, &canonicalInfo)) {
        throw std::invalid_argument(
            "Multisig / Escrow V1 requires three unique compressed public keys");
    }
    const std::string scriptHex = bytesToHex(lockScript);

    // Keep the permanent contract outpoint at vout 1, consistent with the
    // Contract Vault convention used by the other V1 application creators.
    const std::string meta = "TRU_CONTRACT:Multisig_Escrow_V1";
    const std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
    if (metaBytes.empty() || metaBytes.size() > 75U) {
        throw std::runtime_error("Multisig / Escrow V1 metadata size invariant failed");
    }
    std::vector<unsigned char> metadataScript;
    metadataScript.reserve(2U + metaBytes.size());
    metadataScript.push_back(static_cast<unsigned char>(OP_RETURN));
    metadataScript.push_back(static_cast<unsigned char>(metaBytes.size()));
    metadataScript.insert(
        metadataScript.end(), metaBytes.begin(), metaBytes.end());
    const std::string metadataHex = bytesToHex(metadataScript);

    // Funding must use ordinary mature, wallet-owned P2PKH coins only. This
    // mirrors send_transaction() so protocol/token/control UTXOs are never
    // accidentally consumed to create an escrow.
    std::vector<UTXO> candidates =
        blockchainPtr->utxoSet.getUTXOsForAddress(sender);
    std::vector<UTXO> spendable;
    LevelDBStorage* storage = blockchainPtr->getStorage();
    const int tipHeight = blockchainPtr->getBestTipHeight();
    const std::uint32_t candidateHeight =
        tipHeight >= 0 ? static_cast<std::uint32_t>(tipHeight + 1) : 0U;

    for (const auto& u : candidates) {
        const std::string outpoint =
            u.txid + ":" + std::to_string(u.vout);

        if (blockchainPtr->mempool->isUTXOSpentInMempool(u.txid, u.vout)) {
            Logger::log(
                "[MS-01C] funding UTXO spent in mempool, skipped: " + outpoint);
            continue;
        }
        if (isSwapPreparedFundingInputReserved(storage, u.txid, u.vout)) {
            Logger::log(
                "[MS-01C] prepared-funding reserved UTXO skipped: " + outpoint);
            continue;
        }
        if (storage &&
            storage->exists(
                "tokenUTXO:" + u.txid + ":" + std::to_string(u.vout))) {
            Logger::log(
                "[MS-01C] token-controlling UTXO skipped: " + outpoint);
            continue;
        }
        if (u.isCoinbase) {
            if (tipHeight < 0 ||
                candidateHeight <= u.createdAtHeight ||
                (candidateHeight - u.createdAtHeight) <
                    static_cast<std::uint32_t>(COINBASE_MATURITY)) {
                Logger::log(
                    "[MS-01C] immature coinbase skipped: " + outpoint);
                continue;
            }
        }

        const std::string& spk = u.scriptPubKey;
        const bool canonicalP2PKH =
            spk.size() == 50U &&
            spk.rfind("76a914", 0) == 0 &&
            spk.compare(spk.size() - 4U, 4U, "88ac") == 0 &&
            std::all_of(
                spk.begin(), spk.end(),
                [](unsigned char c) { return std::isxdigit(c) != 0; });

        if (!canonicalP2PKH || !doesScriptPayToAddress(spk, sender) ||
            u.amount == 0 || u.amount > tru_limits::MAX_MONEY) {
            Logger::log(
                "[MS-01C] nonstandard/unowned funding UTXO skipped: " + outpoint);
            continue;
        }
        spendable.push_back(u);
    }

    if (spendable.empty()) {
        throw std::runtime_error(
            "No mature wallet-owned P2PKH UTXOs available for escrow funding");
    }

    std::vector<UTXO> selected;
    std::uint64_t totalInput = 0;
    std::uint64_t fee = WALLET_MIN_BASE_FEE;
    const std::string changeScript = createP2PKHScriptHexFromAddress(sender);

    // The estimator depends on input count. Recompute after every selected
    // coin and include a placeholder change output when change is possible;
    // TxOut amount is fixed-width, so placeholder and final change size match.
    for (const auto& u : spendable) {
        if (u.amount > tru_limits::MAX_MONEY - totalInput) {
            throw std::overflow_error("Multisig / Escrow V1 funding sum overflow");
        }
        selected.push_back(u);
        totalInput += u.amount;

        Transaction probe(false);
        probe.version = 1;
        probe.lockTime = 0;
        probe.set_sender(sender);
        for (const auto& in : selected) {
            probe.vin.emplace_back(in.txid, in.vout);
        }
        probe.vout.emplace_back(0, metadataHex);
        probe.vout.emplace_back(amountAtoms, scriptHex);
        if (totalInput > amountAtoms) {
            probe.vout.emplace_back(1, changeScript);
        }
        fee = estimateWalletPolicyFee(probe);

        if (amountAtoms <= tru_limits::MAX_MONEY - fee &&
            totalInput >= amountAtoms + fee) {
            break;
        }
    }

    if (amountAtoms > tru_limits::MAX_MONEY - fee ||
        totalInput < amountAtoms + fee) {
        throw std::runtime_error(
            "Insufficient mature P2PKH funds for Multisig / Escrow V1 amount + fee");
    }

    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.set_sender(sender);
    for (const auto& in : selected) {
        tx.vin.emplace_back(in.txid, in.vout);
    }
    tx.vout.emplace_back(0, metadataHex);
    tx.vout.emplace_back(amountAtoms, scriptHex);

    const std::uint64_t changeAmount = totalInput - amountAtoms - fee;
    if (changeAmount > 0) {
        tx.vout.emplace_back(changeAmount, changeScript);
    }

    if (!signTransaction(tx)) {
        throw std::runtime_error(
            "Failed to sign Multisig / Escrow V1 funding transaction");
    }
    tx.computeTxId();

    if (!blockchainPtr->broadcastTransaction(tx)) {
        throw std::runtime_error(
            "Multisig / Escrow V1 funding transaction rejected by mempool");
    }

    MultisigEscrowCreateResult result;
    result.txid = tx.txid;
    result.contractVout = 1U;
    result.scriptHex = scriptHex;
    result.amountAtoms = amountAtoms;
    result.feeAtoms = fee;
    for (std::size_t i = 0; i < canonicalInfo.pubkeys.size(); ++i) {
        result.pubkeysHex[i] = bytesToHex(
            std::vector<unsigned char>(
                canonicalInfo.pubkeys[i].begin(),
                canonicalInfo.pubkeys[i].end()));
    }

    Logger::log(
        "[MS-01C] Multisig / Escrow V1 MEMPOOL ACCEPTED outpoint=" +
        result.txid + ":" + std::to_string(result.contractVout) +
        " amount=" + std::to_string(result.amountAtoms) +
        " fee=" + std::to_string(result.feeAtoms));

    return result;
}

//====================================================================================
//              HTLC-01C — Generate Atomic-Swap Secret
//====================================================================================
HtlcAtomicSwapSecretV1 Wallet::generateHtlcAtomicSwapSecretV1() const
{
    std::vector<unsigned char> preimage(32U, 0U);
    if (RAND_bytes(preimage.data(), static_cast<int>(preimage.size())) != 1) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 secure secret generation failed");
    }

    HtlcAtomicSwapSecretV1 out;
    out.preimageHex = bytesToHex(preimage);
    out.hash160Hex = htlcPreimageHash160Hex(preimage);
    return out;
}

//====================================================================================
//              HTLC-01C — Create HTLC / Atomic Swap V1
//====================================================================================
//====================================================================================
// SWAP-FRESH-01B4D2 — Prepare signed HTLC funding transaction / NO BROADCAST
//====================================================================================
HtlcAtomicSwapPrepareResult Wallet::prepareHtlcAtomicSwapV1(
    const std::string& secretHash160Hex,
    const std::string& claimCompressedPubkeyHex,
    const std::string& refundCompressedPubkeyHex,
    std::uint32_t refundLockTime,
    std::uint64_t amountAtoms,
    const std::string& operationId)
{
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;

    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 preparation requires a local chain + mempool");
    }
    if (!tru_swap_prepared_funding::isLowerHex64(operationId)) {
        throw std::invalid_argument(
            "HTLC prepared funding operationId must be exactly 64 lowercase hex characters");
    }

    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (!storage) {
        throw std::runtime_error(
            "HTLC prepared funding reservation requires local durable storage");
    }

    // One process-wide guard serializes prepared-input reservation creation
    // against every mempool admission path (Mempool::addTransaction takes the
    // same recursive mutex). This closes the select/sign/reserve race locally.
    std::lock_guard<std::recursive_mutex> reservationLock(
        tru_swap_prepared_funding::mutex());
    if (amountAtoms == 0 || amountAtoms > tru_limits::MAX_MONEY) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 amount must be 1..MAX_MONEY TRU atoms");
    }
    if (refundLockTime < TRU_CLTV_TIMESTAMP_THRESHOLD) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 refund time must be a Unix timestamp >=500000000");
    }

    const std::uint32_t currentMtp = getWalletChainMedianTimePast(*blockchainPtr);
    if (currentMtp > 0 && refundLockTime <= currentMtp) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 refund time must be later than current chain MTP");
    }

    const std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 requires a current funding address");
    }

    std::vector<unsigned char> secretHashBytes;
    if (!tru_contract_call::DecodeScriptHexStrict(
            secretHash160Hex, secretHashBytes) ||
        secretHashBytes.size() != 20U) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 secret commitment must be exactly 20-byte HASH160 hex");
    }

    std::vector<unsigned char> claimBytes;
    std::vector<unsigned char> refundBytes;
    if (!tru_contract_call::DecodeScriptHexStrict(
            claimCompressedPubkeyHex, claimBytes) ||
        claimBytes.size() != 33U) {
        throw std::invalid_argument(
            "HTLC claim pubkey must be exactly 33-byte compressed SEC1 hex");
    }
    if (!tru_contract_call::DecodeScriptHexStrict(
            refundCompressedPubkeyHex, refundBytes) ||
        refundBytes.size() != 33U) {
        throw std::invalid_argument(
            "HTLC refund pubkey must be exactly 33-byte compressed SEC1 hex");
    }

    std::array<unsigned char, 20> secretHash{};
    std::array<unsigned char, 33> claimPubkey{};
    std::array<unsigned char, 33> refundPubkey{};
    std::copy(secretHashBytes.begin(), secretHashBytes.end(), secretHash.begin());
    std::copy(claimBytes.begin(), claimBytes.end(), claimPubkey.begin());
    std::copy(refundBytes.begin(), refundBytes.end(), refundPubkey.begin());

    if (!tru_contract_call::IsCanonicalCompressedSecp256k1Encoding(claimPubkey) ||
        !tru_contract_call::IsCanonicalCompressedSecp256k1Encoding(refundPubkey)) {
        throw std::invalid_argument(
            "HTLC claim/refund keys must use compressed SEC1 prefix 02 or 03");
    }
    if (claimPubkey == refundPubkey) {
        throw std::invalid_argument(
            "HTLC claim and refund roles require distinct public keys");
    }

    std::vector<unsigned char> lockScript;
    tru_contract_call::CanonicalHtlcAtomicSwapV1Info canonicalInfo;
    if (!tru_contract_call::BuildCanonicalHtlcAtomicSwapV1Script(
            secretHash, claimPubkey, refundPubkey, refundLockTime,
            lockScript, &canonicalInfo)) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 canonical script construction failed");
    }
    const std::string scriptHex = bytesToHex(lockScript);

    // V1 identity is always the exact funding outpoint txid:1.
    const std::string meta = "TRU_CONTRACT:HTLC_Atomic_Swap_V1";
    const std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
    if (metaBytes.empty() || metaBytes.size() > 75U) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 metadata size invariant failed");
    }
    std::vector<unsigned char> metadataScript;
    metadataScript.reserve(2U + metaBytes.size());
    metadataScript.push_back(static_cast<unsigned char>(OP_RETURN));
    metadataScript.push_back(static_cast<unsigned char>(metaBytes.size()));
    metadataScript.insert(
        metadataScript.end(), metaBytes.begin(), metaBytes.end());
    const std::string metadataHex = bytesToHex(metadataScript);

    // Node-side idempotence dominates wallet selection. If this operation was
    // already prepared before a process crash, return the exact persisted
    // signed transaction only after re-validating its canonical request and
    // every reserved input marker.
    json existingRecord;
    if (loadSwapPreparedFundingRecord(storage, operationId, existingRecord)) {
        if (existingRecord.value("state", std::string{}) != "PREPARED") {
            throw std::runtime_error(
                "Prepared funding operation is not in PREPARED state");
        }
        if (existingRecord.value("secretHash160", std::string{}) != secretHash160Hex ||
            existingRecord.value("claimPubkey", std::string{}) != claimCompressedPubkeyHex ||
            existingRecord.value("refundPubkey", std::string{}) != refundCompressedPubkeyHex ||
            existingRecord.value("refundTime", 0U) != refundLockTime ||
            existingRecord.value("amountAtoms", std::uint64_t{0}) != amountAtoms ||
            existingRecord.value("scriptHex", std::string{}) != scriptHex ||
            existingRecord.value("metadataHex", std::string{}) != metadataHex) {
            throw std::runtime_error(
                "Prepared funding operationId request drift detected");
        }

        const std::string storedTxid =
            existingRecord.value("preparedTxid", std::string{});
        const std::string storedRaw =
            existingRecord.value("rawTxHex", std::string{});
        const std::string storedRawHash =
            existingRecord.value("rawTxSha256", std::string{});
        if (!tru_swap_prepared_funding::isLowerHex64(storedTxid) ||
            !tru_swap_prepared_funding::isLowerHex64(storedRawHash) ||
            storedRaw.empty() || !isHex(storedRaw) ||
            tru_swap_prepared_funding::sha256Hex(hexDecode(storedRaw)) != storedRawHash ||
            !swapPreparedFundingReservationIntact(storage, existingRecord)) {
            throw std::runtime_error(
                "Prepared funding durable reservation is incomplete/corrupt");
        }

        HtlcAtomicSwapPrepareResult reused;
        reused.operationId = operationId;
        reused.txid = storedTxid;
        reused.contractVout =
            existingRecord.value("contractVout", std::uint32_t{1});
        reused.rawTxHex = storedRaw;
        reused.scriptHex = existingRecord.value("scriptHex", std::string{});
        reused.amountAtoms =
            existingRecord.value("amountAtoms", std::uint64_t{0});
        reused.feeAtoms =
            existingRecord.value("feeAtoms", std::uint64_t{0});
        reused.secretHash160Hex =
            existingRecord.value("secretHash160", std::string{});
        reused.claimPubkeyHex =
            existingRecord.value("claimPubkey", std::string{});
        reused.refundPubkeyHex =
            existingRecord.value("refundPubkey", std::string{});
        reused.refundLockTime =
            existingRecord.value("refundTime", std::uint32_t{0});
        reused.reservedInputCount =
            static_cast<std::uint32_t>(
                swapPreparedFundingInputs(existingRecord).size());
        reused.reservationActive = true;
        reused.idempotentReuse = true;

        Logger::log(
            "[TRU-SWAP-GROUP-01] Reused durable prepared funding operation; "
            "wallet selection/signing skipped operationId=" + operationId);
        return reused;
    }

    // Funding is deliberately restricted to mature wallet-owned canonical
    // P2PKH UTXOs. Token-control and pending-spend outputs are never consumed.
    std::vector<UTXO> candidates =
        blockchainPtr->utxoSet.getUTXOsForAddress(sender);
    std::vector<UTXO> spendable;
    const int tipHeight = blockchainPtr->getBestTipHeight();
    const std::uint32_t candidateHeight =
        tipHeight >= 0 ? static_cast<std::uint32_t>(tipHeight + 1) : 0U;

    for (const auto& u : candidates) {
        const std::string outpoint =
            u.txid + ":" + std::to_string(u.vout);

        if (blockchainPtr->mempool->isUTXOSpentInMempool(u.txid, u.vout)) {
            Logger::log(
                "[HTLC-01C] funding UTXO spent in mempool, skipped: " + outpoint);
            continue;
        }
        if (isSwapPreparedFundingInputReserved(storage, u.txid, u.vout)) {
            Logger::log(
                "[TRU-SWAP-GROUP-01] prepared-funding reserved UTXO skipped: " +
                outpoint);
            continue;
        }
        if (storage &&
            storage->exists(
                "tokenUTXO:" + u.txid + ":" + std::to_string(u.vout))) {
            Logger::log(
                "[HTLC-01C] token-controlling UTXO skipped: " + outpoint);
            continue;
        }
        if (u.isCoinbase) {
            if (tipHeight < 0 ||
                candidateHeight <= u.createdAtHeight ||
                (candidateHeight - u.createdAtHeight) <
                    static_cast<std::uint32_t>(COINBASE_MATURITY)) {
                Logger::log(
                    "[HTLC-01C] immature coinbase skipped: " + outpoint);
                continue;
            }
        }

        const std::string& spk = u.scriptPubKey;
        const bool canonicalP2PKH =
            spk.size() == 50U &&
            spk.rfind("76a914", 0) == 0 &&
            spk.compare(spk.size() - 4U, 4U, "88ac") == 0 &&
            std::all_of(
                spk.begin(), spk.end(),
                [](unsigned char c) { return std::isxdigit(c) != 0; });

        if (!canonicalP2PKH || !doesScriptPayToAddress(spk, sender) ||
            u.amount == 0 || u.amount > tru_limits::MAX_MONEY) {
            Logger::log(
                "[HTLC-01C] nonstandard/unowned funding UTXO skipped: " + outpoint);
            continue;
        }
        spendable.push_back(u);
    }

    if (spendable.empty()) {
        throw std::runtime_error(
            "No mature wallet-owned P2PKH UTXOs available for HTLC funding");
    }

    std::vector<UTXO> selected;
    std::uint64_t totalInput = 0;
    std::uint64_t fee = WALLET_MIN_BASE_FEE;
    const std::string changeScript = createP2PKHScriptHexFromAddress(sender);

    for (const auto& u : spendable) {
        if (u.amount > tru_limits::MAX_MONEY - totalInput) {
            throw std::overflow_error(
                "HTLC / Atomic Swap V1 funding sum overflow");
        }
        selected.push_back(u);
        totalInput += u.amount;

        Transaction probe(false);
        probe.version = 1;
        probe.lockTime = 0;
        probe.set_sender(sender);
        for (const auto& in : selected) {
            probe.vin.emplace_back(in.txid, in.vout);
        }
        probe.vout.emplace_back(0, metadataHex);
        probe.vout.emplace_back(amountAtoms, scriptHex);
        if (totalInput > amountAtoms) {
            probe.vout.emplace_back(1, changeScript);
        }
        fee = estimateWalletPolicyFee(probe);

        if (amountAtoms <= tru_limits::MAX_MONEY - fee &&
            totalInput >= amountAtoms + fee) {
            break;
        }
    }

    if (amountAtoms > tru_limits::MAX_MONEY - fee ||
        totalInput < amountAtoms + fee) {
        throw std::runtime_error(
            "Insufficient mature P2PKH funds for HTLC amount + fee");
    }

    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.set_sender(sender);
    for (const auto& in : selected) {
        tx.vin.emplace_back(in.txid, in.vout);
    }
    tx.vout.emplace_back(0, metadataHex);
    tx.vout.emplace_back(amountAtoms, scriptHex);

    const std::uint64_t changeAmount = totalInput - amountAtoms - fee;
    if (changeAmount > 0) {
        tx.vout.emplace_back(changeAmount, changeScript);
    }

    if (!signTransaction(tx)) {
        throw std::runtime_error(
            "Failed to sign HTLC / Atomic Swap V1 funding transaction");
    }
    tx.computeTxId();

    const std::vector<unsigned char> signedRaw = tx.serializeBinary();
    const std::string signedRawHex = bytesToHex(signedRaw);
    const std::string signedRawSha256 =
        tru_swap_prepared_funding::sha256Hex(signedRaw);

    // We still hold the global prepared-funding guard. Re-check each selected
    // input immediately before one synchronous LevelDB batch reserves them.
    // Every mempool admission path takes the same guard, so no local admission
    // can cross this boundary between the checks and durable reservation.
    json reservedInputs = json::array();
    for (const auto& in : selected) {
        UTXO live;
        if (!blockchainPtr->utxoSet.getUTXO(in.txid, in.vout, live)) {
            throw std::runtime_error(
                "Selected prepared-funding input disappeared before reservation");
        }
        if (blockchainPtr->mempool->isUTXOSpentInMempool(in.txid, in.vout)) {
            throw std::runtime_error(
                "Selected prepared-funding input entered mempool before reservation");
        }
        if (isSwapPreparedFundingInputReserved(storage, in.txid, in.vout)) {
            throw std::runtime_error(
                "Selected prepared-funding input became reserved concurrently");
        }
        reservedInputs.push_back(json{
            {"txid", in.txid},
            {"vout", in.vout}
        });
    }

    const auto preparedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    json opRecord{
        {"version", tru_swap_prepared_funding::RECORD_VERSION},
        {"operationId", operationId},
        {"state", "PREPARED"},
        {"preparedTxid", tx.txid},
        {"rawTxHex", signedRawHex},
        {"rawTxSha256", signedRawSha256},
        {"contractVout", 1U},
        {"scriptHex", scriptHex},
        {"metadataHex", metadataHex},
        {"amountAtoms", amountAtoms},
        {"feeAtoms", fee},
        {"secretHash160", secretHash160Hex},
        {"claimPubkey", claimCompressedPubkeyHex},
        {"refundPubkey", refundCompressedPubkeyHex},
        {"refundTime", refundLockTime},
        {"sender", sender},
        {"preparedMs", preparedMs},
        {"reservedInputs", reservedInputs}
    };

    leveldb::WriteBatch reservationBatch;
    reservationBatch.Put(
        tru_swap_prepared_funding::opKey(operationId),
        swapPreparedChecksummedValue(*storage, opRecord));

    for (const auto& in : selected) {
        json marker{
            {"version", tru_swap_prepared_funding::INPUT_VERSION},
            {"operationId", operationId},
            {"preparedTxid", tx.txid},
            {"rawTxSha256", signedRawSha256}
        };
        reservationBatch.Put(
            tru_swap_prepared_funding::inputKey(in.txid, in.vout),
            swapPreparedChecksummedValue(*storage, marker));
    }

    if (!storage->putBatch(reservationBatch, true)) {
        throw std::runtime_error(
            "Failed to durably reserve prepared-funding inputs");
    }
    if (!swapPreparedFundingReservationIntact(storage, opRecord)) {
        throw std::runtime_error(
            "Prepared-funding reservation post-write verification failed");
    }

    HtlcAtomicSwapPrepareResult result;
    result.operationId = operationId;
    result.txid = tx.txid;
    result.contractVout = 1U;
    result.rawTxHex = signedRawHex;
    result.scriptHex = scriptHex;
    result.amountAtoms = amountAtoms;
    result.feeAtoms = fee;
    result.secretHash160Hex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.secretHash160.begin(), canonicalInfo.secretHash160.end()));
    result.claimPubkeyHex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.claimPubkey.begin(), canonicalInfo.claimPubkey.end()));
    result.refundPubkeyHex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.refundPubkey.begin(), canonicalInfo.refundPubkey.end()));
    result.refundLockTime = canonicalInfo.refundLockTime;
    result.reservationActive = true;
    result.reservedInputCount =
        static_cast<std::uint32_t>(selected.size());
    result.idempotentReuse = false;

    Logger::log(
        "[TRU-SWAP-GROUP-01] HTLC funding SIGNED + RESERVED NOT BROADCAST outpoint=" +
        result.txid + ":" + std::to_string(result.contractVout) +
        " amount=" + std::to_string(result.amountAtoms) +
        " fee=" + std::to_string(result.feeAtoms) +
        " hash160=" + result.secretHash160Hex +
        " refundTime=" + std::to_string(result.refundLockTime));

    return result;
}


//====================================================================================
// TRU SWAP GROUP-01 — persistent prepared-funding status / release / exact broadcast
//====================================================================================
HtlcPreparedFundingStatusV1 Wallet::getPreparedHtlcFundingStatusV1(
    const std::string& operationId) const
{
    HtlcPreparedFundingStatusV1 out;
    out.operationId = operationId;

    if (!tru_swap_prepared_funding::isLowerHex64(operationId)) {
        throw std::invalid_argument(
            "Prepared funding operationId must be 64 lowercase hex characters");
    }
    if (!isLocalChain || !blockchainPtr) {
        throw std::runtime_error(
            "Prepared funding status requires local chain");
    }
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (!storage) {
        throw std::runtime_error(
            "Prepared funding status requires durable storage");
    }

    std::lock_guard<std::recursive_mutex> lock(
        tru_swap_prepared_funding::mutex());

    json record;
    if (!loadSwapPreparedFundingRecord(storage, operationId, record)) {
        return out;
    }

    out.found = true;
    out.state = record.value("state", std::string{});
    out.preparedTxid =
        record.value("preparedTxid", std::string{});
    out.contractVout =
        record.value("contractVout", std::uint32_t{1});

    const auto inputs = swapPreparedFundingInputs(record);
    out.reservedInputCount =
        static_cast<std::uint32_t>(inputs.size());

    out.reservationActive =
        (out.state == "PREPARED" || out.state == "BROADCASTED") &&
        swapPreparedFundingReservationIntact(storage, record);

    out.inMempool =
        blockchainPtr->mempool &&
        tru_swap_prepared_funding::isLowerHex64(out.preparedTxid) &&
        blockchainPtr->mempool->hasTransaction(out.preparedTxid);

    return out;
}

HtlcPreparedFundingStatusV1 Wallet::releasePreparedHtlcFundingV1(
    const std::string& operationId,
    const std::string& expectedPreparedTxid)
{
    if (!tru_swap_prepared_funding::isLowerHex64(operationId) ||
        !tru_swap_prepared_funding::isLowerHex64(expectedPreparedTxid)) {
        throw std::invalid_argument(
            "Prepared funding release requires canonical operationId + txid");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "Prepared funding release requires local chain + mempool");
    }
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (!storage) {
        throw std::runtime_error(
            "Prepared funding release requires durable storage");
    }

    std::lock_guard<std::recursive_mutex> lock(
        tru_swap_prepared_funding::mutex());

    json record;
    if (!loadSwapPreparedFundingRecord(storage, operationId, record)) {
        throw std::runtime_error("Prepared funding operation not found");
    }
    if (record.value("state", std::string{}) != "PREPARED") {
        throw std::runtime_error(
            "Only an unbroadcast PREPARED operation may release reservations");
    }
    if (record.value("preparedTxid", std::string{}) != expectedPreparedTxid) {
        throw std::runtime_error(
            "Prepared funding release txid mismatch");
    }
    if (!swapPreparedFundingReservationIntact(storage, record)) {
        throw std::runtime_error(
            "Prepared funding reservation is incomplete; refusing release");
    }
    if (blockchainPtr->mempool->hasTransaction(expectedPreparedTxid)) {
        throw std::runtime_error(
            "Prepared funding transaction is in mempool; release forbidden");
    }

    const auto inputs = swapPreparedFundingInputs(record);
    record["state"] = "RELEASED";
    record["releasedMs"] = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    // Once terminally released, do not retain broadcastable signed bytes.
    record["rawTxHex"] = "";

    leveldb::WriteBatch batch;
    for (const auto& input : inputs) {
        batch.Delete(
            tru_swap_prepared_funding::inputKey(
                input.first, input.second));
    }
    batch.Put(
        tru_swap_prepared_funding::opKey(operationId),
        swapPreparedChecksummedValue(*storage, record));

    if (!storage->putBatch(batch, true)) {
        throw std::runtime_error(
            "Prepared funding release durable batch failed");
    }

    for (const auto& input : inputs) {
        std::string payload;
        if (storage->getWithDataChecksum(
                tru_swap_prepared_funding::inputKey(
                    input.first, input.second),
                payload)) {
            throw std::runtime_error(
                "Prepared funding input marker remained after release");
        }
    }

    Logger::log(
        "[TRU-SWAP-GROUP-01] Released prepared funding reservation operationId=" +
        operationId);

    return getPreparedHtlcFundingStatusV1(operationId);
}

HtlcPreparedFundingBroadcastResult Wallet::broadcastPreparedHtlcFundingV1(
    const std::string& operationId,
    const std::string& expectedPreparedTxid,
    bool dryRun)
{
    if (!tru_swap_prepared_funding::isLowerHex64(operationId) ||
        !tru_swap_prepared_funding::isLowerHex64(expectedPreparedTxid)) {
        throw std::invalid_argument(
            "Prepared funding broadcast requires canonical operationId + txid");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "Prepared funding broadcast requires local chain + mempool");
    }
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (!storage) {
        throw std::runtime_error(
            "Prepared funding broadcast requires durable storage");
    }

    std::lock_guard<std::recursive_mutex> lock(
        tru_swap_prepared_funding::mutex());

    json record;
    if (!loadSwapPreparedFundingRecord(storage, operationId, record)) {
        throw std::runtime_error("Prepared funding operation not found");
    }
    const std::string state = record.value("state", std::string{});
    if (state != "PREPARED" && state != "BROADCASTED") {
        throw std::runtime_error(
            "Prepared funding broadcast requires PREPARED or BROADCASTED state");
    }

    const std::string preparedTxid =
        record.value("preparedTxid", std::string{});
    const std::string rawTxHex =
        record.value("rawTxHex", std::string{});
    const std::string rawTxSha256 =
        record.value("rawTxSha256", std::string{});

    if (preparedTxid != expectedPreparedTxid ||
        !tru_swap_prepared_funding::isLowerHex64(preparedTxid) ||
        !tru_swap_prepared_funding::isLowerHex64(rawTxSha256) ||
        rawTxHex.empty() || !isHex(rawTxHex)) {
        throw std::runtime_error(
            "Prepared funding broadcast durable identity mismatch");
    }
    const std::vector<unsigned char> raw = hexDecode(rawTxHex);
    if (tru_swap_prepared_funding::sha256Hex(raw) != rawTxSha256) {
        throw std::runtime_error(
            "Prepared funding broadcast raw transaction hash mismatch");
    }
    if (!swapPreparedFundingReservationIntact(storage, record)) {
        throw std::runtime_error(
            "Prepared funding input reservation is not intact");
    }

    Transaction tx = Transaction::deserializeBinary(raw);
    const std::vector<unsigned char> roundTripRaw = tx.serializeBinary();
    if (roundTripRaw != raw) {
        throw std::runtime_error(
            "Prepared funding transaction failed exact byte round-trip");
    }
    tx.computeTxId();
    if (tx.txid != preparedTxid) {
        throw std::runtime_error(
            "Prepared funding broadcast recomputed txid mismatch");
    }
    if (tx.vout.size() <= 1U ||
        record.value("contractVout", std::uint32_t{1}) != 1U ||
        tx.vout[1].scriptPubKey !=
            record.value("scriptHex", std::string{}) ||
        tx.vout[1].amount !=
            record.value("amountAtoms", std::uint64_t{0})) {
        throw std::runtime_error(
            "Prepared funding broadcast canonical contract output mismatch");
    }

    HtlcPreparedFundingBroadcastResult out;
    out.operationId = operationId;
    out.preparedTxid = preparedTxid;
    out.contractVout = 1U;
    out.dryRun = dryRun;
    out.reservationActive = true;
    out.alreadyInMempool =
        blockchainPtr->mempool->hasTransaction(preparedTxid);

    if (dryRun) {
        return out;
    }

    const char* enabled =
        std::getenv("TRU_SWAP_PREPARED_BROADCAST_ENABLE");
    if (!enabled || std::string(enabled) != "1") {
        throw std::runtime_error(
            "Prepared funding real broadcast is disabled; "
            "TRU_SWAP_PREPARED_BROADCAST_ENABLE=1 is required");
    }

    if (!out.alreadyInMempool) {
        if (!blockchainPtr->broadcastTransaction(tx)) {
            throw std::runtime_error(
                "Exact persisted prepared transaction was rejected");
        }
    }

    // Crash-safe idempotence: if the exact tx was already accepted before a
    // process death, this call observes it and only advances local operation
    // metadata. Input markers stay reserved through BROADCASTED.
    record["state"] = "BROADCASTED";
    record["broadcastedMs"] = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    leveldb::WriteBatch batch;
    batch.Put(
        tru_swap_prepared_funding::opKey(operationId),
        swapPreparedChecksummedValue(*storage, record));
    if (!storage->putBatch(batch, true)) {
        throw std::runtime_error(
            "Prepared funding BROADCASTED marker persistence failed");
    }

    out.broadcast = true;
    out.alreadyInMempool =
        blockchainPtr->mempool->hasTransaction(preparedTxid);
    if (!out.alreadyInMempool) {
        throw std::runtime_error(
            "Prepared funding broadcast returned without mempool presence");
    }

    return out;
}

HtlcAtomicSwapCreateResult Wallet::createHtlcAtomicSwapV1(
    const std::string& secretHash160Hex,
    const std::string& claimCompressedPubkeyHex,
    const std::string& refundCompressedPubkeyHex,
    std::uint32_t refundLockTime,
    std::uint64_t amountAtoms)
{
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;

    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 creation requires a local chain + mempool");
    }
    if (amountAtoms == 0 || amountAtoms > tru_limits::MAX_MONEY) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 amount must be 1..MAX_MONEY TRU atoms");
    }
    if (refundLockTime < TRU_CLTV_TIMESTAMP_THRESHOLD) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 refund time must be a Unix timestamp >=500000000");
    }

    const std::uint32_t currentMtp = getWalletChainMedianTimePast(*blockchainPtr);
    if (currentMtp > 0 && refundLockTime <= currentMtp) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 refund time must be later than current chain MTP");
    }

    const std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 requires a current funding address");
    }

    std::vector<unsigned char> secretHashBytes;
    if (!tru_contract_call::DecodeScriptHexStrict(
            secretHash160Hex, secretHashBytes) ||
        secretHashBytes.size() != 20U) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 secret commitment must be exactly 20-byte HASH160 hex");
    }

    std::vector<unsigned char> claimBytes;
    std::vector<unsigned char> refundBytes;
    if (!tru_contract_call::DecodeScriptHexStrict(
            claimCompressedPubkeyHex, claimBytes) ||
        claimBytes.size() != 33U) {
        throw std::invalid_argument(
            "HTLC claim pubkey must be exactly 33-byte compressed SEC1 hex");
    }
    if (!tru_contract_call::DecodeScriptHexStrict(
            refundCompressedPubkeyHex, refundBytes) ||
        refundBytes.size() != 33U) {
        throw std::invalid_argument(
            "HTLC refund pubkey must be exactly 33-byte compressed SEC1 hex");
    }

    std::array<unsigned char, 20> secretHash{};
    std::array<unsigned char, 33> claimPubkey{};
    std::array<unsigned char, 33> refundPubkey{};
    std::copy(secretHashBytes.begin(), secretHashBytes.end(), secretHash.begin());
    std::copy(claimBytes.begin(), claimBytes.end(), claimPubkey.begin());
    std::copy(refundBytes.begin(), refundBytes.end(), refundPubkey.begin());

    if (!tru_contract_call::IsCanonicalCompressedSecp256k1Encoding(claimPubkey) ||
        !tru_contract_call::IsCanonicalCompressedSecp256k1Encoding(refundPubkey)) {
        throw std::invalid_argument(
            "HTLC claim/refund keys must use compressed SEC1 prefix 02 or 03");
    }
    if (claimPubkey == refundPubkey) {
        throw std::invalid_argument(
            "HTLC claim and refund roles require distinct public keys");
    }

    std::vector<unsigned char> lockScript;
    tru_contract_call::CanonicalHtlcAtomicSwapV1Info canonicalInfo;
    if (!tru_contract_call::BuildCanonicalHtlcAtomicSwapV1Script(
            secretHash, claimPubkey, refundPubkey, refundLockTime,
            lockScript, &canonicalInfo)) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 canonical script construction failed");
    }
    const std::string scriptHex = bytesToHex(lockScript);

    // V1 identity is always the exact funding outpoint txid:1.
    const std::string meta = "TRU_CONTRACT:HTLC_Atomic_Swap_V1";
    const std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
    if (metaBytes.empty() || metaBytes.size() > 75U) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 metadata size invariant failed");
    }
    std::vector<unsigned char> metadataScript;
    metadataScript.reserve(2U + metaBytes.size());
    metadataScript.push_back(static_cast<unsigned char>(OP_RETURN));
    metadataScript.push_back(static_cast<unsigned char>(metaBytes.size()));
    metadataScript.insert(
        metadataScript.end(), metaBytes.begin(), metaBytes.end());
    const std::string metadataHex = bytesToHex(metadataScript);

    // Funding is deliberately restricted to mature wallet-owned canonical
    // P2PKH UTXOs. Token-control and pending-spend outputs are never consumed.
    std::vector<UTXO> candidates =
        blockchainPtr->utxoSet.getUTXOsForAddress(sender);
    std::vector<UTXO> spendable;
    LevelDBStorage* storage = blockchainPtr->getStorage();
    const int tipHeight = blockchainPtr->getBestTipHeight();
    const std::uint32_t candidateHeight =
        tipHeight >= 0 ? static_cast<std::uint32_t>(tipHeight + 1) : 0U;

    for (const auto& u : candidates) {
        const std::string outpoint =
            u.txid + ":" + std::to_string(u.vout);

        if (blockchainPtr->mempool->isUTXOSpentInMempool(u.txid, u.vout)) {
            Logger::log(
                "[HTLC-01C] funding UTXO spent in mempool, skipped: " + outpoint);
            continue;
        }
        if (storage &&
            storage->exists(
                "tokenUTXO:" + u.txid + ":" + std::to_string(u.vout))) {
            Logger::log(
                "[HTLC-01C] token-controlling UTXO skipped: " + outpoint);
            continue;
        }
        if (u.isCoinbase) {
            if (tipHeight < 0 ||
                candidateHeight <= u.createdAtHeight ||
                (candidateHeight - u.createdAtHeight) <
                    static_cast<std::uint32_t>(COINBASE_MATURITY)) {
                Logger::log(
                    "[HTLC-01C] immature coinbase skipped: " + outpoint);
                continue;
            }
        }

        const std::string& spk = u.scriptPubKey;
        const bool canonicalP2PKH =
            spk.size() == 50U &&
            spk.rfind("76a914", 0) == 0 &&
            spk.compare(spk.size() - 4U, 4U, "88ac") == 0 &&
            std::all_of(
                spk.begin(), spk.end(),
                [](unsigned char c) { return std::isxdigit(c) != 0; });

        if (!canonicalP2PKH || !doesScriptPayToAddress(spk, sender) ||
            u.amount == 0 || u.amount > tru_limits::MAX_MONEY) {
            Logger::log(
                "[HTLC-01C] nonstandard/unowned funding UTXO skipped: " + outpoint);
            continue;
        }
        spendable.push_back(u);
    }

    if (spendable.empty()) {
        throw std::runtime_error(
            "No mature wallet-owned P2PKH UTXOs available for HTLC funding");
    }

    std::vector<UTXO> selected;
    std::uint64_t totalInput = 0;
    std::uint64_t fee = WALLET_MIN_BASE_FEE;
    const std::string changeScript = createP2PKHScriptHexFromAddress(sender);

    for (const auto& u : spendable) {
        if (u.amount > tru_limits::MAX_MONEY - totalInput) {
            throw std::overflow_error(
                "HTLC / Atomic Swap V1 funding sum overflow");
        }
        selected.push_back(u);
        totalInput += u.amount;

        Transaction probe(false);
        probe.version = 1;
        probe.lockTime = 0;
        probe.set_sender(sender);
        for (const auto& in : selected) {
            probe.vin.emplace_back(in.txid, in.vout);
        }
        probe.vout.emplace_back(0, metadataHex);
        probe.vout.emplace_back(amountAtoms, scriptHex);
        if (totalInput > amountAtoms) {
            probe.vout.emplace_back(1, changeScript);
        }
        fee = estimateWalletPolicyFee(probe);

        if (amountAtoms <= tru_limits::MAX_MONEY - fee &&
            totalInput >= amountAtoms + fee) {
            break;
        }
    }

    if (amountAtoms > tru_limits::MAX_MONEY - fee ||
        totalInput < amountAtoms + fee) {
        throw std::runtime_error(
            "Insufficient mature P2PKH funds for HTLC amount + fee");
    }

    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.set_sender(sender);
    for (const auto& in : selected) {
        tx.vin.emplace_back(in.txid, in.vout);
    }
    tx.vout.emplace_back(0, metadataHex);
    tx.vout.emplace_back(amountAtoms, scriptHex);

    const std::uint64_t changeAmount = totalInput - amountAtoms - fee;
    if (changeAmount > 0) {
        tx.vout.emplace_back(changeAmount, changeScript);
    }

    if (!signTransaction(tx)) {
        throw std::runtime_error(
            "Failed to sign HTLC / Atomic Swap V1 funding transaction");
    }
    tx.computeTxId();

    if (!blockchainPtr->broadcastTransaction(tx)) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 funding transaction rejected by mempool");
    }

    HtlcAtomicSwapCreateResult result;
    result.txid = tx.txid;
    result.contractVout = 1U;
    result.scriptHex = scriptHex;
    result.amountAtoms = amountAtoms;
    result.feeAtoms = fee;
    result.secretHash160Hex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.secretHash160.begin(), canonicalInfo.secretHash160.end()));
    result.claimPubkeyHex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.claimPubkey.begin(), canonicalInfo.claimPubkey.end()));
    result.refundPubkeyHex = bytesToHex(
        std::vector<unsigned char>(
            canonicalInfo.refundPubkey.begin(), canonicalInfo.refundPubkey.end()));
    result.refundLockTime = canonicalInfo.refundLockTime;

    Logger::log(
        "[HTLC-01C] HTLC / Atomic Swap V1 MEMPOOL ACCEPTED outpoint=" +
        result.txid + ":" + std::to_string(result.contractVout) +
        " amount=" + std::to_string(result.amountAtoms) +
        " fee=" + std::to_string(result.feeAtoms) +
        " hash160=" + result.secretHash160Hex +
        " refundTime=" + std::to_string(result.refundLockTime));

    return result;
}


//====================================================================================
//              HTLC-01D — Deterministic Claim / Refund Spend Paths
//====================================================================================
namespace {
struct HtlcAtomicSwapSpendTemplateV1 {
    Transaction tx;
    UTXO utxo;
    std::vector<unsigned char> lockScript;
    tru_contract_call::CanonicalHtlcAtomicSwapV1Info info;
    std::vector<unsigned char> sighash;
    std::uint64_t releaseAmountAtoms{0};
    std::uint64_t feeAtoms{0};
};

static void appendHtlcMinimalPushV1(
    std::vector<unsigned char>& scriptSig,
    const std::vector<unsigned char>& data,
    const char* label)
{
    if (data.empty()) {
        throw std::invalid_argument(
            std::string("HTLC ") + label + " must not be empty");
    }
    if (data.size() <= 0x4bU) {
        scriptSig.push_back(static_cast<unsigned char>(data.size()));
    } else if (data.size() <= 0xffU) {
        scriptSig.push_back(static_cast<unsigned char>(OP_PUSHDATA1));
        scriptSig.push_back(static_cast<unsigned char>(data.size()));
    } else {
        throw std::invalid_argument(
            std::string("HTLC ") + label +
            " exceeds the canonical one-byte PUSHDATA1 limit");
    }
    scriptSig.insert(scriptSig.end(), data.begin(), data.end());
}

static std::vector<unsigned char> htlcArrayToVector20(
    const std::array<unsigned char, 20>& value)
{
    return std::vector<unsigned char>(value.begin(), value.end());
}

static std::vector<unsigned char> htlcArrayToVector33(
    const std::array<unsigned char, 33>& value)
{
    return std::vector<unsigned char>(value.begin(), value.end());
}

static HtlcAtomicSwapSpendTemplateV1 buildHtlcAtomicSwapSpendTemplateV1(
    Blockchain* chain,
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress,
    bool refundBranch)
{
    if (!chain || !chain->mempool) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 spend requires a local chain + mempool");
    }
    if (contractTxid.size() != 64U || !isValidHex(contractTxid)) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 requires a 64-hex funding TXID");
    }
    if (contractVout != 1U) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 canonical contract output is vout 1");
    }
    if (!isValidAddress(recipientAddress)) {
        throw std::invalid_argument(
            "HTLC / Atomic Swap V1 recipient must be a valid TRU P2PKH address");
    }
    if (chain->mempool->isUTXOSpentInMempool(contractTxid, contractVout)) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 outpoint already has a pending mempool spend");
    }

    UTXO utxo;
    if (!chain->utxoSet.getUTXO(contractTxid, contractVout, utxo)) {
        throw std::runtime_error(
            "Confirmed HTLC / Atomic Swap V1 UTXO not found; mine/confirm creation first or it is already spent");
    }
    if (utxo.amount == 0 || utxo.amount > tru_limits::MAX_MONEY) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 UTXO amount is invalid");
    }

    std::vector<unsigned char> lockScript;
    if (!tru_contract_call::DecodeScriptHexStrict(
            utxo.scriptPubKey, lockScript)) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 locking script hex is malformed");
    }

    tru_contract_call::CanonicalHtlcAtomicSwapV1Info info;
    if (!tru_contract_call::ParseCanonicalHtlcAtomicSwapV1Script(
            lockScript, info)) {
        throw std::runtime_error(
            "Funding outpoint is not canonical HTLC / Atomic Swap V1");
    }

    if (refundBranch) {
        const std::uint32_t currentMtp =
            getWalletChainMedianTimePast(*chain);
        if (currentMtp < info.refundLockTime) {
            throw std::runtime_error(
                "HTLC refund is not mature: parent-chain MTP=" +
                std::to_string(currentMtp) +
                " required=" + std::to_string(info.refundLockTime));
        }
    }

    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = refundBranch ? info.refundLockTime : 0U;
    tx.vin.emplace_back(
        contractTxid,
        contractVout,
        refundBranch ? 0xfffffffeU : 0xffffffffU);
    tx.vout.emplace_back(
        1U, createP2PKHScriptHexFromAddress(recipientAddress));

    const std::uint64_t fee = estimateWalletPolicyFee(tx);
    if (utxo.amount <= fee) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 value is too small to pay the current relay fee");
    }
    const std::uint64_t releaseAmount = utxo.amount - fee;
    tx.vout[0].amount = releaseAmount;

    const std::vector<unsigned char> sighash =
        tx.getSigHash(0, lockScript);
    if (sighash.size() != 32U) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 sighash invariant failed");
    }

    HtlcAtomicSwapSpendTemplateV1 out;
    out.tx = std::move(tx);
    out.utxo = utxo;
    out.lockScript = std::move(lockScript);
    out.info = info;
    out.sighash = sighash;
    out.releaseAmountAtoms = releaseAmount;
    out.feeAtoms = fee;
    return out;
}

static ECDSAKey loadWalletRoleKeyForHtlcV1(
    const Wallet& wallet,
    const std::vector<unsigned char>& expectedPubkey,
    const char* role)
{
    for (const auto& addr : wallet.getAllAddresses()) {
        try {
            ECDSAKey candidate =
                loadWalletPrivateMaterialV1(
                    wallet.getPrivateKeyForAddress(addr));
            if (candidate.getCompressedSec1() == expectedPubkey) {
                return candidate;
            }
        } catch (const std::exception& e) {
            Logger::log(
                std::string("[HTLC-01D] skipped wallet key while matching ") +
                role + " key: " + e.what());
        }
    }
    throw std::runtime_error(
        std::string("This wallet does not contain the private key for the HTLC ") +
        role + " role");
}

static std::vector<unsigned char> signHtlcSpendV1(
    const ECDSAKey& signerKey,
    const std::vector<unsigned char>& signerPubkey,
    const std::vector<unsigned char>& sighash,
    const char* role)
{
    const std::string sighashBinary(sighash.begin(), sighash.end());
    std::vector<unsigned char> derSignature =
        signerKey.sign(sighashBinary);

    if (!ECDSAKey::isStrictDERLowS(derSignature) ||
        !ECDSAKey::verifyCanonicalTransactionSignature(
            signerPubkey, sighashBinary, derSignature)) {
        throw std::runtime_error(
            std::string("Locally produced HTLC ") + role +
            " signature failed strict DER/low-S/ECDSA verification");
    }

    derSignature.push_back(0x01U); // SIGHASH_ALL
    return derSignature;
}
} // namespace

// -----------------------------------------------------------------------------
// TRU-SWAP-FRESH-01B1 — fresh per-swap role signing.
//
// allocationId is public metadata. The private child is re-derived only inside
// Wallet from the authenticated encrypted-wallet seed. The derived pubkey must
// exactly match the pubkey committed in the HTLC before any signature is made.
// Only the canonical DER/low-S SIGHASH_ALL signature leaves this function.
// -----------------------------------------------------------------------------
std::vector<unsigned char> Wallet::signFreshSwapRoleDigestV1(
    const std::string& allocationId,
    std::uint32_t role,
    const std::vector<unsigned char>& expectedCompressedPubkey,
    const std::vector<unsigned char>& sighash) const
{
    requirePrivateAccess("signFreshSwapRoleDigestV1");

    if (role > 1U) {
        throw std::invalid_argument(
            "TRU-SWAP fresh signing role must be 0=claim or 1=refund");
    }
    if (expectedCompressedPubkey.size() != 33U ||
        (expectedCompressedPubkey[0] != 0x02U &&
         expectedCompressedPubkey[0] != 0x03U)) {
        throw std::invalid_argument(
            "TRU-SWAP fresh signing expected pubkey is not compressed secp256k1");
    }
    if (sighash.size() != 32U) {
        throw std::invalid_argument(
            "TRU-SWAP fresh signing requires a 32-byte sighash");
    }

    const TruFreshSwapRoleKeysV1 publicRoles =
        deriveFreshSwapRoleKeysV1(allocationId);
    const std::string expectedHex = bytesToHex(expectedCompressedPubkey);
    const std::string derivedHex =
        role == 0U ? publicRoles.claimPubkeyHex : publicRoles.refundPubkeyHex;
    if (derivedHex != expectedHex) {
        throw std::runtime_error(
            "TRU-SWAP fresh allocationId does not own the HTLC role pubkey");
    }

    const std::vector<uint8_t>* seedSource =
        &walletSecurityController_->unlockedSeed();
    if (seedSource->empty()) {
        throw std::runtime_error(
            "TRU-SWAP fresh signing has no authenticated seed");
    }

    const std::string domain =
        std::string("TRU-SWAP-FRESH-HD-V1|") + allocationId;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (SHA256(
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size(),
            digest) == nullptr) {
        throw std::runtime_error(
            "TRU-SWAP fresh signing SHA256 failed");
    }

    auto read31 = [&digest](std::size_t off) -> std::uint32_t {
        const std::uint32_t v =
            (static_cast<std::uint32_t>(digest[off]) << 24U) |
            (static_cast<std::uint32_t>(digest[off + 1U]) << 16U) |
            (static_cast<std::uint32_t>(digest[off + 2U]) << 8U) |
            static_cast<std::uint32_t>(digest[off + 3U]);
        return v & 0x7fffffffU;
    };

    std::uint32_t path[10] = {
        0x80000000U | derivationPath.purpose,
        0x80000000U | derivationPath.coin_type,
        0x80000000U | derivationPath.account,
        derivationPath.change,
        0x54525553U,
        read31(0U),
        read31(4U),
        read31(8U),
        read31(12U),
        role
    };

    struct ext_key master;
    struct ext_key child;
    std::memset(&master, 0, sizeof(master));
    std::memset(&child, 0, sizeof(child));

    try {
        if (bip32_key_from_seed(
                seedSource->data(),
                seedSource->size(),
                BIP32_VER_MAIN_PRIVATE,
                0,
                &master) != WALLY_OK) {
            throw std::runtime_error(
                "TRU-SWAP fresh signing master-key creation failed");
        }

        if (bip32_key_from_parent_path(
                &master,
                path,
                10,
                BIP32_FLAG_KEY_PRIVATE,
                &child) != WALLY_OK) {
            throw std::runtime_error(
                "TRU-SWAP fresh signing child derivation failed");
        }

        std::vector<unsigned char> rawKey(
            child.priv_key + 1,
            child.priv_key + 33);
        ECDSAKey signer = ECDSAKey::fromRawBytes(rawKey);
        const std::vector<unsigned char> derivedPub =
            signer.getCompressedSec1();

        std::fill(rawKey.begin(), rawKey.end(), 0U);

        if (derivedPub != expectedCompressedPubkey) {
            throw std::runtime_error(
                "TRU-SWAP fresh private-child/pubkey binding mismatch");
        }

        const std::string sighashBinary(sighash.begin(), sighash.end());
        std::vector<unsigned char> derSignature =
            signer.sign(sighashBinary);

        if (!ECDSAKey::isStrictDERLowS(derSignature) ||
            !ECDSAKey::verifyCanonicalTransactionSignature(
                expectedCompressedPubkey,
                sighashBinary,
                derSignature)) {
            throw std::runtime_error(
                "TRU-SWAP fresh signature failed strict DER/low-S/ECDSA verification");
        }

        derSignature.push_back(0x01U);

        std::memset(digest, 0, sizeof(digest));
        std::memset(&child, 0, sizeof(child));
        std::memset(&master, 0, sizeof(master));
        return derSignature;
    } catch (...) {
        std::memset(digest, 0, sizeof(digest));
        std::memset(&child, 0, sizeof(child));
        std::memset(&master, 0, sizeof(master));
        throw;
    }
}

HtlcAtomicSwapSpendResult Wallet::claimHtlcAtomicSwapV1(
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress,
    const std::string& preimageHex,
    const std::string& freshAllocationId)
{
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 claim requires a local chain + mempool");
    }

    auto spend = buildHtlcAtomicSwapSpendTemplateV1(
        blockchainPtr, contractTxid, contractVout,
        recipientAddress, false);

    std::vector<unsigned char> preimage;
    if (!tru_contract_call::DecodeScriptHexStrict(preimageHex, preimage) ||
        preimage.empty() || preimage.size() > 0xffU) {
        throw std::invalid_argument(
            "HTLC claim preimage must be 1..255 binary bytes encoded as even-length hex");
    }

    const std::string actualHash160 = htlcPreimageHash160Hex(preimage);
    const std::string expectedHash160 =
        bytesToHex(htlcArrayToVector20(spend.info.secretHash160));
    if (actualHash160 != expectedHash160) {
        throw std::invalid_argument(
            "HTLC claim preimage does not match the contract HASH160 commitment");
    }

    const std::vector<unsigned char> claimPubkey =
        htlcArrayToVector33(spend.info.claimPubkey);
        std::vector<unsigned char> fullSignature;
    if (!freshAllocationId.empty()) {
        fullSignature = signFreshSwapRoleDigestV1(
            freshAllocationId, 0U, claimPubkey, spend.sighash);
    } else {
        ECDSAKey signerKey =
            loadWalletRoleKeyForHtlcV1(*this, claimPubkey, "claim");
        fullSignature =
            signHtlcSpendV1(
                signerKey, claimPubkey, spend.sighash, "claim");
    }

    spend.tx.vin[0].scriptSig.clear();
    appendHtlcMinimalPushV1(
        spend.tx.vin[0].scriptSig, fullSignature, "claim signature");
    appendHtlcMinimalPushV1(
        spend.tx.vin[0].scriptSig, preimage, "claim preimage");
    spend.tx.vin[0].scriptSig.push_back(
        static_cast<unsigned char>(OP_1));

    spend.tx.computeTxId();
    if (!blockchainPtr->broadcastTransaction(spend.tx)) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 claim transaction rejected by mempool");
    }

    HtlcAtomicSwapSpendResult result;
    result.txid = spend.tx.txid;
    result.contractTxid = contractTxid;
    result.contractVout = contractVout;
    result.branch = "CLAIM";
    result.recipient = recipientAddress;
    result.sighashHex = bytesToHex(spend.sighash);
    result.signerPubkeyHex = bytesToHex(claimPubkey);
    result.secretHash160Hex = expectedHash160;
    result.refundLockTime = spend.info.refundLockTime;
    result.releaseAmountAtoms = spend.releaseAmountAtoms;
    result.feeAtoms = spend.feeAtoms;

    Logger::log(
        "[HTLC-01D] CLAIM MEMPOOL ACCEPTED txid=" + result.txid +
        " outpoint=" + contractTxid + ":" + std::to_string(contractVout) +
        " hash160=" + result.secretHash160Hex +
        " release=" + std::to_string(result.releaseAmountAtoms) +
        " fee=" + std::to_string(result.feeAtoms));
    return result;
}

HtlcAtomicSwapSpendResult Wallet::refundHtlcAtomicSwapV1(
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress,
    const std::string& freshAllocationId)
{
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 refund requires a local chain + mempool");
    }

    auto spend = buildHtlcAtomicSwapSpendTemplateV1(
        blockchainPtr, contractTxid, contractVout,
        recipientAddress, true);

    const std::vector<unsigned char> refundPubkey =
        htlcArrayToVector33(spend.info.refundPubkey);
        std::vector<unsigned char> fullSignature;
    if (!freshAllocationId.empty()) {
        fullSignature = signFreshSwapRoleDigestV1(
            freshAllocationId, 1U, refundPubkey, spend.sighash);
    } else {
        ECDSAKey signerKey =
            loadWalletRoleKeyForHtlcV1(*this, refundPubkey, "refund");
        fullSignature =
            signHtlcSpendV1(
                signerKey, refundPubkey, spend.sighash, "refund");
    }

    spend.tx.vin[0].scriptSig.clear();
    appendHtlcMinimalPushV1(
        spend.tx.vin[0].scriptSig, fullSignature, "refund signature");
    spend.tx.vin[0].scriptSig.push_back(
        static_cast<unsigned char>(OP_0));

    spend.tx.computeTxId();
    if (!blockchainPtr->broadcastTransaction(spend.tx)) {
        throw std::runtime_error(
            "HTLC / Atomic Swap V1 refund transaction rejected by mempool");
    }

    HtlcAtomicSwapSpendResult result;
    result.txid = spend.tx.txid;
    result.contractTxid = contractTxid;
    result.contractVout = contractVout;
    result.branch = "REFUND";
    result.recipient = recipientAddress;
    result.sighashHex = bytesToHex(spend.sighash);
    result.signerPubkeyHex = bytesToHex(refundPubkey);
    result.secretHash160Hex =
        bytesToHex(htlcArrayToVector20(spend.info.secretHash160));
    result.refundLockTime = spend.info.refundLockTime;
    result.releaseAmountAtoms = spend.releaseAmountAtoms;
    result.feeAtoms = spend.feeAtoms;

    Logger::log(
        "[HTLC-01D] REFUND MEMPOOL ACCEPTED txid=" + result.txid +
        " outpoint=" + contractTxid + ":" + std::to_string(contractVout) +
        " refundTime=" + std::to_string(result.refundLockTime) +
        " release=" + std::to_string(result.releaseAmountAtoms) +
        " fee=" + std::to_string(result.feeAtoms));
    return result;
}

//====================================================================================
//              MS-01D — Sign Multisig / Escrow V1 Redemption Package
//====================================================================================
MultisigEscrowSignaturePackage Wallet::signMultisigEscrowV1(
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress,
    const std::string& signerCompressedPubkeyHex) const
{
    if (!isLocalChain || !blockchainPtr) {
        throw std::runtime_error(
            "Multisig / Escrow V1 signing requires a local chain");
    }

    const auto spend = buildMultisigEscrowSpendTemplateV1(
        blockchainPtr, contractTxid, contractVout, recipientAddress);

    std::vector<unsigned char> requestedPubkey;
    if (!tru_contract_call::DecodeScriptHexStrict(
            signerCompressedPubkeyHex, requestedPubkey) ||
        requestedPubkey.size() != 33U ||
        (requestedPubkey[0] != 0x02U && requestedPubkey[0] != 0x03U)) {
        throw std::invalid_argument(
            "Signer pubkey must be a 33-byte compressed SEC1 key");
    }

    const std::size_t requestedIndex =
        multisigParticipantIndexV1(spend.info, requestedPubkey);
    if (requestedIndex >= spend.info.pubkeys.size()) {
        throw std::invalid_argument(
            "Signer pubkey is not one of this escrow's three participants");
    }

    bool found = false;
    ECDSAKey signerKey;
    for (const auto& addr : getAllAddresses()) {
        try {
            ECDSAKey candidate =
                loadWalletPrivateMaterialV1(getPrivateKeyForAddress(addr));
            if (candidate.getCompressedSec1() == requestedPubkey) {
                signerKey = std::move(candidate);
                found = true;
                break;
            }
        } catch (const std::exception& e) {
            Logger::log(
                "[MS-01D] skipped wallet key while matching signer pubkey: " +
                std::string(e.what()));
        }
    }
    if (!found) {
        throw std::runtime_error(
            "This wallet does not contain the private key for the requested escrow participant");
    }

    const std::string sighashBinary(
        spend.sighash.begin(), spend.sighash.end());
    std::vector<unsigned char> derSignature = signerKey.sign(sighashBinary);
    if (!ECDSAKey::isStrictDERLowS(derSignature) ||
        !ECDSAKey::verifyCanonicalTransactionSignature(
            requestedPubkey, sighashBinary, derSignature)) {
        throw std::runtime_error(
            "Locally produced Multisig / Escrow V1 signature failed canonical verification");
    }

    derSignature.push_back(0x01U); // SIGHASH_ALL

    MultisigEscrowSignaturePackage out;
    out.contractTxid = contractTxid;
    out.contractVout = contractVout;
    out.recipient = recipientAddress;
    out.sighashHex = bytesToHex(spend.sighash);
    out.signerPubkeyHex = bytesToHex(requestedPubkey);
    out.signatureHex = bytesToHex(derSignature);
    out.releaseAmountAtoms = spend.releaseAmountAtoms;
    out.feeAtoms = spend.feeAtoms;
    return out;
}

//====================================================================================
//              MS-01D — Verify, Assemble and Relay Multisig Redemption
//====================================================================================
MultisigEscrowRedeemResult Wallet::redeemMultisigEscrowV1(
    const std::string& contractTxid,
    std::uint32_t contractVout,
    const std::string& recipientAddress,
    const std::array<std::string, 2>& signerCompressedPubkeysHex,
    const std::array<std::string, 2>& signaturesHex)
{
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error(
            "Multisig / Escrow V1 redemption requires a local chain + mempool");
    }

    auto spend = buildMultisigEscrowSpendTemplateV1(
        blockchainPtr, contractTxid, contractVout, recipientAddress);
    const std::string sighashBinary(
        spend.sighash.begin(), spend.sighash.end());

    struct VerifiedSig {
        std::size_t participantIndex{0};
        std::vector<unsigned char> pubkey;
        std::vector<unsigned char> fullSignature;
    };
    std::array<VerifiedSig, 2> verified{};

    for (std::size_t i = 0; i < verified.size(); ++i) {
        std::vector<unsigned char> pubkey;
        if (!tru_contract_call::DecodeScriptHexStrict(
                signerCompressedPubkeysHex[i], pubkey) ||
            pubkey.size() != 33U ||
            (pubkey[0] != 0x02U && pubkey[0] != 0x03U)) {
            throw std::invalid_argument(
                "Redemption signer " + std::to_string(i + 1) +
                " pubkey is not canonical compressed SEC1");
        }

        const std::size_t participantIndex =
            multisigParticipantIndexV1(spend.info, pubkey);
        if (participantIndex >= spend.info.pubkeys.size()) {
            throw std::invalid_argument(
                "Redemption signer " + std::to_string(i + 1) +
                " is not a participant in this escrow");
        }

        std::vector<unsigned char> fullSignature;
        if (!tru_contract_call::DecodeScriptHexStrict(
                signaturesHex[i], fullSignature) ||
            fullSignature.size() < 9U ||
            fullSignature.size() > 73U ||
            fullSignature.back() != 0x01U) {
            throw std::invalid_argument(
                "Redemption signature " + std::to_string(i + 1) +
                " must be strict DER plus trailing SIGHASH_ALL 01");
        }

        std::vector<unsigned char> derSignature(
            fullSignature.begin(), fullSignature.end() - 1);
        if (!ECDSAKey::isStrictDERLowS(derSignature) ||
            !ECDSAKey::verifyCanonicalTransactionSignature(
                pubkey, sighashBinary, derSignature)) {
            throw std::runtime_error(
                "Redemption signature " + std::to_string(i + 1) +
                " failed strict DER/low-S/ECDSA verification");
        }

        verified[i].participantIndex = participantIndex;
        verified[i].pubkey = std::move(pubkey);
        verified[i].fullSignature = std::move(fullSignature);
    }

    if (verified[0].participantIndex == verified[1].participantIndex) {
        throw std::invalid_argument(
            "Multisig / Escrow V1 requires signatures from two distinct participants");
    }
    if (verified[1].participantIndex < verified[0].participantIndex) {
        std::swap(verified[0], verified[1]);
    }

    // The VM preserves Bitcoin's historical CHECKMULTISIG extra pop, so the
    // canonical unlock starts with OP_0, followed by the two signatures in
    // increasing on-chain pubkey order.
    std::vector<unsigned char> scriptSig;
    scriptSig.reserve(
        1U + 1U + verified[0].fullSignature.size() +
        1U + verified[1].fullSignature.size());
    scriptSig.push_back(static_cast<unsigned char>(OP_0));
    for (const auto& item : verified) {
        if (item.fullSignature.empty() || item.fullSignature.size() > 75U) {
            throw std::runtime_error("Multisig signature push size invariant failed");
        }
        scriptSig.push_back(
            static_cast<unsigned char>(item.fullSignature.size()));
        scriptSig.insert(
            scriptSig.end(),
            item.fullSignature.begin(), item.fullSignature.end());
    }

    spend.tx.vin[0].scriptSig = std::move(scriptSig);
    spend.tx.vin[0].pubKey.clear();
    spend.tx.computeTxId();

    if (!blockchainPtr->broadcastTransaction(spend.tx)) {
        throw std::runtime_error(
            "Multisig / Escrow V1 redemption rejected by mempool");
    }

    MultisigEscrowRedeemResult out;
    out.txid = spend.tx.txid;
    out.contractTxid = contractTxid;
    out.contractVout = contractVout;
    out.recipient = recipientAddress;
    out.releaseAmountAtoms = spend.releaseAmountAtoms;
    out.feeAtoms = spend.feeAtoms;
    out.signerPubkeysHex[0] = bytesToHex(verified[0].pubkey);
    out.signerPubkeysHex[1] = bytesToHex(verified[1].pubkey);
    return out;
}

//====================================================================================
//                              Sign Transaction
//====================================================================================
bool Wallet::signTransaction(Transaction& tx, const std::string &nodeIP, int nodePort) const {
    Logger::log("Entering signTransaction with nodeIP=" + nodeIP + ", nodePort=" + std::to_string(nodePort) +
                ", transaction input count=" + std::to_string(tx.vin.size()));

    if (addresses.empty()) {
        Logger::log("Error: Wallet has no addresses");
        throw std::runtime_error("No addresses available in wallet");
    }
    Logger::log("Wallet has " + std::to_string(addresses.size()) + " addresses: [" +
                std::accumulate(addresses.begin(), addresses.end(), std::string(),
                    [](const std::string& a, const std::string& b) { return a.empty() ? b : a + ", " + b; }) + "]");

    if (tx.txid.empty()) {
        Logger::log("TXID is empty, computing new TXID");
        tx.computeTxId();
        Logger::log("Computed TXID: " + tx.txid);
    } else {
        Logger::log("Using pre-existing TXID: " + tx.txid);
    }

    // In RPC mode, fetch all UTXOs for wallet addresses
    std::unordered_map<std::string, UTXO> utxoMap;
    if (!blockchainPtr) {
        if (nodeIP.empty() || nodePort == 0) {
            Logger::log("Error: Node IP or port not provided for RPC mode");
            throw std::runtime_error("Node IP or port not set");
        }
        Logger::log("Fetching UTXOs for " + std::to_string(addresses.size()) + " addresses via RPC");
        for (const auto& addr : addresses) {
            Logger::log("Calling rpcListUnspent for address: " + addr);
            std::vector<UTXO> utxos = rpcListUnspent(nodeIP, nodePort, addr);
            Logger::log("Received " + std::to_string(utxos.size()) + " UTXOs for address " + addr);
            for (const auto& u : utxos) {
                std::string key = u.txid + ":" + std::to_string(u.vout);
                utxoMap[key] = u;
                Logger::log("Mapped UTXO key=" + key + ", amount=" + std::to_string(u.amount) +
                            ", scriptPubKey=" + u.scriptPubKey);
            }
        }
        Logger::log("Total UTXOs mapped: " + std::to_string(utxoMap.size()));
    } else {
        Logger::log("Using local blockchain mode; UTXOs will be fetched from blockchainPtr");
    }

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        TxIn& input = tx.vin[i];
        std::string inputKey = input.txid + ":" + std::to_string(input.vout);
        Logger::log("Processing input #" + std::to_string(i) + " with key=" + inputKey);

        try {
            std::vector<unsigned char> scriptPubKey;
            std::string controllingAddr;

            UTXO utxo;
            if (blockchainPtr) {
                Logger::log("Fetching UTXO from local blockchain for " + inputKey);
                bool utxoFound = blockchainPtr->utxoSet.getUTXO(input.txid, input.vout, utxo);
                if (!utxoFound) {
                    Logger::log("UTXO not found in local blockchain for " + inputKey);
                    throw std::runtime_error("UTXO not found in local chain: " + inputKey);
                }
                Logger::log("Found UTXO in local blockchain: txid=" + utxo.txid + ", vout=" +
                            std::to_string(utxo.vout) + ", amount=" + std::to_string(utxo.amount));
                scriptPubKey = hexDecode(utxo.scriptPubKey);
                controllingAddr = extractAddressFromScriptPubKey(utxo.scriptPubKey, input.txid, input.vout, blockchainPtr);
            } else {
                Logger::log("Looking up UTXO in RPC map for " + inputKey);
                auto it = utxoMap.find(inputKey);
                if (it == utxoMap.end()) {
                    Logger::log("UTXO not found in RPC map for " + inputKey);
                    throw std::runtime_error("UTXO not found for input: " + inputKey + ". Ensure wallet controls this UTXO.");
                }
                utxo = it->second;
                Logger::log("Found UTXO in map: txid=" + utxo.txid + ", vout=" + std::to_string(utxo.vout) +
                            ", amount=" + std::to_string(utxo.amount) + ", scriptPubKey=" + utxo.scriptPubKey);
                scriptPubKey = hexDecode(utxo.scriptPubKey);
                controllingAddr = extractAddressFromScriptPubKey(utxo.scriptPubKey, input.txid, input.vout, nullptr);
            }

            if (controllingAddr.empty()) {
                Logger::log("Failed to extract controlling address for " + inputKey + ", scriptPubKey=" + bytesToHex(scriptPubKey));
                throw std::runtime_error("Failed to determine controlling address for UTXO: " + inputKey);
            }
            Logger::log("Controlling address for input #" + std::to_string(i) + ": " + controllingAddr);

            // Extract the expected pubkey hash from scriptPubKey
            std::string expectedPubkeyHash;
            if (scriptPubKey.size() >= 25 && scriptPubKey[0] == 0x76 && scriptPubKey[1] == 0xa9 &&
                scriptPubKey[2] == 0x14 && scriptPubKey[23] == 0x88 && scriptPubKey[24] == 0xac) {
                expectedPubkeyHash = bytesToHex(std::vector<unsigned char>(scriptPubKey.begin() + 3, scriptPubKey.begin() + 23));
                Logger::log("Expected pubkey hash from scriptPubKey: " + expectedPubkeyHash);
            } else if (scriptPubKey.size() == 32 &&
                       scriptPubKey[0] == 0x04 &&
                       scriptPubKey[5] == OP_CHECKLOCKTIMEVERIFY &&
                       scriptPubKey[6] == OP_DROP &&
                       scriptPubKey[7] == OP_DUP &&
                       scriptPubKey[8] == OP_HASH160 &&
                       scriptPubKey[9] == 0x14 &&
                       scriptPubKey[30] == OP_EQUALVERIFY &&
                       scriptPubKey[31] == OP_CHECKSIG) {
                // Time Lock retains a normal P2PKH ownership tail.
                expectedPubkeyHash = bytesToHex(
                    std::vector<unsigned char>(scriptPubKey.begin() + 10, scriptPubKey.begin() + 30));
                Logger::log("Expected Time Lock pubkey hash: " + expectedPubkeyHash);
            } else {
                Logger::log("Non-standard scriptPubKey for " + inputKey + ": " + bytesToHex(scriptPubKey));
                throw std::runtime_error("Non-standard scriptPubKey for UTXO: " + inputKey);
            }

            // Verify controlling address is in wallet
            auto addrIt = std::find(addresses.begin(), addresses.end(), controllingAddr);
            if (addrIt == addresses.end()) {
                Logger::log("Controlling address " + controllingAddr + " not found in wallet addresses");
                throw std::runtime_error("Wallet does not control address " + controllingAddr + " for UTXO: " + inputKey);
            }

            // Derive key pair and validate
            uint32_t addrIndex = static_cast<uint32_t>(std::distance(addresses.begin(), addrIt));
            Logger::log("Using address " + controllingAddr + " at index " + std::to_string(addrIndex));

            std::string privPEM = deriveHDPrivateKey(addrIndex);
            std::vector<unsigned char> pubKey = deriveHDPublicKey(addrIndex);
            Logger::log("Derived public key for index " + std::to_string(addrIndex) + ": " + hexEncode(pubKey));

            // Compute HASH160 of the public key
            unsigned char sha256[SHA256_DIGEST_LENGTH];
            SHA256(pubKey.data(), pubKey.size(), sha256);
            unsigned char ripemd160[RIPEMD160_DIGEST_LENGTH];
            RIPEMD160(sha256, SHA256_DIGEST_LENGTH, ripemd160);
            std::string computedPubkeyHash = bytesToHex(std::vector<unsigned char>(ripemd160, ripemd160 + RIPEMD160_DIGEST_LENGTH));
            Logger::log("Computed pubkey hash: " + computedPubkeyHash);

            if (computedPubkeyHash != expectedPubkeyHash) {
                Logger::log("Public key hash mismatch for index " + std::to_string(addrIndex) +
                            ": expected=" + expectedPubkeyHash + ", computed=" + computedPubkeyHash);
                throw std::runtime_error("Public key hash mismatch for UTXO: " + inputKey +
                                         ", expected=" + expectedPubkeyHash + ", computed=" + computedPubkeyHash);
            }
            Logger::log("Public key hash matches for index " + std::to_string(addrIndex));

            // Validate ECDSA key derivation
            ECDSAKey keyObj = ECDSAKey::fromPrivateKey(privPEM);
            std::vector<unsigned char> pubKeyFromECDSA = keyObj.getCompressedSec1();
            if (pubKey != pubKeyFromECDSA) {
                Logger::log("Public key mismatch - HD derived: " + hexEncode(pubKey) + ", ECDSA: " + hexEncode(pubKeyFromECDSA));
                throw std::runtime_error("Public key mismatch between HD derivation and ECDSAKey for index " +
                                         std::to_string(addrIndex));
            }

            // Generate signature
            std::vector<unsigned char> sigHash = tx.getSigHash(i, scriptPubKey);
            Logger::log("Computed sighash for input #" + std::to_string(i) + ": " + bytesToHex(sigHash));

            std::vector<unsigned char> signature = keyObj.sign(std::string(sigHash.begin(), sigHash.end()));
            signature.push_back(0x01); // Append SIGHASH_ALL
            Logger::log("Generated signature for input #" + std::to_string(i) + ": " + hexEncode(signature));

            // Construct scriptSig
            input.scriptSig.clear();
            input.scriptSig.push_back(static_cast<unsigned char>(signature.size()));
            input.scriptSig.insert(input.scriptSig.end(), signature.begin(), signature.end());
            input.scriptSig.push_back(static_cast<unsigned char>(pubKey.size()));
            input.scriptSig.insert(input.scriptSig.end(), pubKey.begin(), pubKey.end());
            input.pubKey = pubKey;
            Logger::log("Constructed scriptSig for input #" + std::to_string(i) + ": " + hexEncode(input.scriptSig));
        } catch (const std::exception& e) {
            Logger::log("Error processing input #" + std::to_string(i) + ": " + std::string(e.what()));
            throw std::runtime_error("Failed to process input #" + std::to_string(i) + ": " + e.what());
        }
    }

    Logger::log("Successfully signed all " + std::to_string(tx.vin.size()) + " inputs");
    Logger::log("Exiting signTransaction");
    return true;
}
// ------------------------------
// broadcastTxToExternalNode
// ------------------------------
bool Wallet::broadcastTxToExternalNode(const std::string &txHex, const std::string &nodeIP, int nodePort) {
    Logger::log("[Wallet::broadcastTxToExternalNode] Starting broadcast to " + nodeIP + ":" + std::to_string(nodePort));
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    nlohmann::json jreq;
    jreq["jsonrpc"] = "2.0";  // Changed from "1.0" to "2.0"
    jreq["id"] = 1;  // Changed to integer as expected by the server
    jreq["method"] = "sendrawtransaction";
    jreq["params"] = {{"txHex", txHex}};  // Changed from array to object format
    
    Logger::log("[Wallet::broadcastTxToExternalNode] Sending request: " + jreq.dump());
    auto resp = cli.Post("/rpc", jreq.dump(), "application/json");
    if (!resp) {
        Logger::log("[Wallet::broadcastTxToExternalNode] Failed to connect to node at " + nodeIP + ":" + std::to_string(nodePort));
        return false;
    }
    Logger::log("[Wallet::broadcastTxToExternalNode] Received response, status: " + std::to_string(resp->status));
    if (resp->status != 200) {
        Logger::log("[Wallet::broadcastTxToExternalNode] HTTP error: " + std::to_string(resp->status) + ", body: " + resp->body);
        return false;
    }
    try {
        auto jr = nlohmann::json::parse(resp->body);
        Logger::log("[Wallet::broadcastTxToExternalNode] Response parsed: " + jr.dump());
        if (jr.contains("error") && !jr["error"].is_null()) {
            Logger::log("[Wallet::broadcastTxToExternalNode] Node rejected transaction: " + jr["error"].dump());
            return false;
        }
        Logger::log("[Wallet::broadcastTxToExternalNode] Transaction broadcasted successfully");
        return true;
    } catch (const std::exception& e) {
        Logger::log("[Wallet::broadcastTxToExternalNode] Failed to parse response: " + std::string(e.what()));
        return false;
    }
}
/*
bool Wallet::broadcastTxToExternalNode(const std::string &txHex, const std::string &nodeIP, int nodePort) {
    Logger::log("[Wallet::broadcastTxToExternalNode] Starting broadcast to " + nodeIP + ":" + std::to_string(nodePort));
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    nlohmann::json jreq;
    jreq["jsonrpc"] = "1.0";
    jreq["id"] = "wallet_broadcast";
    jreq["method"] = "sendrawtransaction";
    jreq["params"] = {txHex};
    Logger::log("[Wallet::broadcastTxToExternalNode] Sending request: " + jreq.dump());
    auto resp = cli.Post("/rpc", jreq.dump(), "application/json");
    if (!resp) {
        Logger::log("[Wallet::broadcastTxToExternalNode] Failed to connect to node at " + nodeIP + ":" + std::to_string(nodePort));
        return false;
    }
    Logger::log("[Wallet::broadcastTxToExternalNode] Received response, status: " + std::to_string(resp->status));
    if (resp->status != 200) {
        Logger::log("[Wallet::broadcastTxToExternalNode] HTTP error: " + std::to_string(resp->status) + ", body: " + resp->body);
        return false;
    }
    try {
        auto jr = nlohmann::json::parse(resp->body);
        Logger::log("[Wallet::broadcastTxToExternalNode] Response parsed: " + jr.dump());
        if (jr.contains("error") && !jr["error"].is_null()) {
            Logger::log("[Wallet::broadcastTxToExternalNode] Node rejected transaction: " + jr["error"].dump());
            return false;
        }
        Logger::log("[Wallet::broadcastTxToExternalNode] Transaction broadcasted successfully");
        return true;
    } catch (const std::exception& e) {
        Logger::log("[Wallet::broadcastTxToExternalNode] Failed to parse response: " + std::string(e.what()));
        return false;
    }
}
*/
//==========================================================
//                   FT (Fungible Token)
//==========================================================


    // Metadata Ideas (ported from your current iteration, commented out for future use)
    // meta.data["liquidity_pool_id"] = "lp_" + tokenID; // Links to a decentralized liquidity pool
    // meta.data["yield_farming_enabled"] = "true";     // Enables yield farming via OP_CHAINSTATECHECK
    // meta.data["oracle_price_feed"] = "price:" + symbol; // Ties to OP_DATAFEED for real-time pricing
    // meta.data["carbon_offset"] = "0";                // Tracks carbon footprint offset via smart contract
    // meta.data["ai_trading_rule"] = "buy_low_sell_high_v1"; // AI-driven trading rule using OP_EXTERNALDATA
    // New unique metadata fields for DeFi, atomic swaps, and new-age use cases
    // meta.data["defi_vesting_schedule"] = "vest_" + tokenID; // Defines a vesting schedule for DeFi incentives
    // meta.data["atomic_swap_peg"] = "peg:" + symbol + ":BTC"; // Pegs token for atomic swaps with BTC
    // meta.data["temporal_value_lock"] = "lock_6months"; // Locks value for a time period via OP_TIMELOCK
    // meta.data["holographic_consensus"] = "holo_vote_v1"; // Enables holographic consensus voting
    // meta.data["neuro_token_evolution"] = "neuro_evo_v1"; // Token evolves based on neural network inputs
    // meta.data["quantum_liquidity_factor"] = "qlf_" + shortID; // Quantum computing liquidity adjustment
    // meta.data["metaverse_staking_pool"] = "msp_" + shortID;   // Staking in metaverse ecosystems
    // meta.data["holo_trade_signature"] = "hts_v1";             // Holographic trade verification
    // meta.data["nano_payment_channel"] = "npc_" + shortID;     // Nano-transaction payment channel
    // meta.data["eco_reward_tier"] = "tier_1";                  // Eco-friendly reward tier system

std::string Wallet::issueExtendedFT(
    const std::string& tokenID,
    uint64_t totalSupply,
    const std::string& name,
    const std::string& symbol,
    const std::string& desc,
    const std::string& imageUrl,
    uint32_t decimals,
    const std::unordered_map<std::string, std::string>& additionalMeta
) {
    Logger::log("[issueExtendedFT] Starting FT issuance for tokenID=" + tokenID);

    if (tokenID.empty() || totalSupply == 0) {
        throw std::invalid_argument("Token ID must be non-empty and supply > 0");
    }
    std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error("No sender address available");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error("Requires local chain with valid blockchain & mempool");
    }
    Logger::log("[issueExtendedFT] Sender: " + sender);

    unsigned char hash256[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(tokenID.data()), tokenID.size(), hash256);
    std::string fullHash = bytesToHex({hash256, hash256 + SHA256_DIGEST_LENGTH});
    std::string shortID = fullHash.substr(0, 16);
    Logger::log("[issueExtendedFT] tokenID hash=" + fullHash + ", short=" + shortID);

    auto [feeTxid, feeVout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (feeTxid.empty()) {
        throw std::runtime_error("No spendable UTXO found for fees");
    }
    uint64_t feeUtxoValue = getUtxoValueInAtoms(*blockchainPtr, feeTxid, feeVout);
    uint64_t fee = WALLET_MIN_BASE_FEE;
    if (feeUtxoValue < fee + 1) {
        throw std::runtime_error("Insufficient funds for fee + token UTXO");
    }

    // Build metadata
    TokenMeta meta;
    meta.data["name"] = name.empty() ? "Unnamed Token" : name;
    meta.data["symbol"] = symbol.empty() ? "TOK" : symbol;
    meta.data["description"] = desc;
    meta.data["image"] = imageUrl;
    meta.data["decimals"] = std::to_string(decimals);
    meta.data["meta_id"] = generateMetaID(tokenID);
    meta.data["dynamic_visual"] = generateDeterministicVisual(tokenID, imageUrl);
    for (const auto& [key, value] : additionalMeta) {
        if (!key.empty() && !value.empty()) {
            meta.data[key] = value;
        }
    }
    std::string metaHash = generateMetaHash(meta.data);
    meta.data["metaHash"] = metaHash;
    Logger::log("[issueExtendedFT] Computed metaHash=" + metaHash);

    // Build token data
    ExtendedTokenData tok;
    tok.tokenID = shortID;
    tok.type = TokenType::FT;
    tok.amount = scaleTokenSupplyToAtomsV1(totalSupply, decimals);
    tok.version = 1;
    tok.meta = meta;
    tok.offChainMetadata = "";
    tok.metadataSignature = "";
    std::string opReturnHex = createExtendedTokenScriptPubKeyHex(tok, sender);

    // Build transaction
    Transaction tx(false);
    tx.set_sender(sender);
    tx.vin.emplace_back(feeTxid, feeVout);
    tx.vout.emplace_back(0, opReturnHex);  // OP_RETURN at vout 0
    tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(sender));  // Controlling output at vout 1
    uint64_t change = feeUtxoValue - fee - 1;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        tx.vout.emplace_back(change, createP2PKHScriptHexFromAddress(sender));
        feeBearingVout = tx.vout.size() - 1;
    }

    nlohmann::json metadataJson;
    metadataJson["type"] = "FT";
    metadataJson["tokenID"] = tok.tokenID;
    metadataJson["amount"] = std::to_string(tok.amount);
    metadataJson["owner"] = sender;
    metadataJson["version"] = std::to_string(tok.version);
    metadataJson["metadataSignature"] = tok.metadataSignature;
    metadataJson["offChainMetadata"] = tok.offChainMetadata;
    metadataJson["meta"] = tok.meta.data;

    // Store in transaction's tokenMetadata map with temporary key
    tx.tokenMetadata["pending"] = metadataJson;

    tx.computeTxId();

    if (tx.tokenMetadata.count("pending")) {
        tx.tokenMetadata[tx.txid] = tx.tokenMetadata["pending"];
        tx.tokenMetadata.erase("pending");
    }

    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "issueExtendedFT");

    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign FT issuance TX");
    }
    Logger::log("[issueExtendedFT] Built & signed TX " + tx.txid);
/*
    // Store data in LevelDB
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (storage) {
        // Store metadata
        nlohmann::json metadataJson;
        metadataJson["type"] = "FT";
        metadataJson["tokenID"] = tok.tokenID;
        metadataJson["amount"] = std::to_string(tok.amount);
        metadataJson["owner"] = sender;
        metadataJson["version"] = std::to_string(tok.version);
        metadataJson["metadataSignature"] = tok.metadataSignature;
        metadataJson["offChainMetadata"] = tok.offChainMetadata;
        metadataJson["meta"] = tok.meta.data;
        
        std::string metaStr = metadataJson.dump();
        std::string metadataKey = "tokenMetadata:" + tx.txid;
        Logger::log("[issueExtendedFT] Storing metadata with key: " + metadataKey);
        if (!storage->putWithDataChecksum(metadataKey, metaStr)) {
            Logger::log("[issueExtendedFT] Error: Failed to store metadata");
        } else {
            Logger::log("[issueExtendedFT] Successfully stored metadata: " + metaStr);
        }

        // Store token UTXO at the controlling output (vout 1)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":1";  // Note: vout 1, not 0
        nlohmann::json tokenUtxoJson = {
            {"tokenID", shortID},
            {"amount", std::to_string(tok.amount)},
            {"owner", sender},
            {"type", "FT"},
            {"controllingVout", 1}
        };
        std::string tokenUtxoValue = tokenUtxoJson.dump();
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[issueExtendedFT] Error: Failed to store token UTXO data");
        } else {
            Logger::log("[issueExtendedFT] Stored token UTXO data at key=" + tokenUtxoKey);
        }
        
        // Store ownership index
        std::string tokenIndexKey = "tokenOwnerUTXO:" + shortID + ":" + sender + ":" + tx.txid + ":1";
        if (!storage->putWithDataChecksum(tokenIndexKey, "1")) {
            Logger::log("[issueExtendedFT] Error: Failed to store token ownership index");
        } else {
            Logger::log("[issueExtendedFT] Stored token ownership index: " + tokenIndexKey);
        }
        
        // Store issuance mapping for easier lookup
        std::string issuanceKey = "tokenIssuance:" + shortID;
        if (!storage->putWithDataChecksum(issuanceKey, tx.txid)) {
            Logger::log("[issueExtendedFT] Error: Failed to store issuance mapping");
        } else {
            Logger::log("[issueExtendedFT] Stored issuance mapping: " + issuanceKey + " -> " + tx.txid);
        }
    } else {
        Logger::log("[issueExtendedFT] Warning: Storage not available");
    }
*/
    // Add to mempool
    if (blockchainPtr->mempool->addTransaction(tx) != MempoolAddStatus::SUCCESS) {
        throw std::runtime_error("Mempool rejected FT issuance TX");
    }
    Logger::log("[issueExtendedFT] FT issuance TX added to mempool: " + tx.txid);

    return tx.txid;
}
//==========================================================
//                NFT (Non-Fungible Token)
//==========================================================


    // Metadata Ideas (ported from your current iteration, commented out for future use)
    // meta.data["vr_experience_url"] = "vr://nft/" + nftID; // Links to a VR experience via OP_EXTERNALDATA
    // meta.data["ar_interaction"] = "ar_script_v1";         // AR interaction script using OP_STORE/OP_LOAD
    // meta.data["royalty_split"] = "10%:" + creator;       // Dynamic royalty split via OP_CHAINSTATECHECK
    // meta.data["provenance_hash"] = "sha3:" + nftID;      // Provenance tracking with OP_SHA3
    // meta.data["ai_personality"] = "friendly_v2";         // AI-driven personality for NFT interaction
    // New unique metadata fields for DeFi, atomic swaps, and new-age use cases
    // meta.data["defi_auction_pool"] = "auction_" + nftID; // Links to a DeFi auction pool
    // meta.data["atomic_swap_nft_pair"] = "pair:" + nftID + ":ETH"; // Pairs NFT for atomic swap with ETH
    // meta.data["sentient_memory"] = "memory_v1"; // Stores sentient-like memory states via OP_STORE
    // meta.data["cosmic_signature"] = "cosmo_" + nftID; // Unique cosmic identifier for interstellar use
    // meta.data["dreamscape_link"] = "dream://" + nftID; // Links to a dreamscape simulation
    // meta.data["augmented_reality_layer"] = "arl_" + shortID;  // AR layer for real-world integration
    // meta.data["nft_dao_membership"] = "dao_" + shortID;       // Membership in NFT governance DAO
    // meta.data["virtual_land_deed"] = "vld_" + shortID;       // Deed to virtual land in metaverse
    // meta.data["crypto_genome_id"] = "cgid_" + shortID;       // Genomic identifier for digital evolution
    // meta.data["time_capsule_unlock"] = "unlock_2030";        // Time-locked content reveal

std::string Wallet::issueExtendedNFT(
    const std::string& nftID,
    const std::string& nftName,
    const std::string& desc,
    const std::string& imageUrl,
    const std::string& creator,
    const std::string& externalLink,
    const std::unordered_map<std::string, std::string>& additionalMeta
) {
    Logger::log("[issueExtendedNFT] Starting NFT issuance for nftID=" + nftID);

    if (nftID.empty()) {
        throw std::invalid_argument("NFT ID must be non-empty");
    }
    std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error("No sender address available");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error("Requires local chain with valid blockchain & mempool");
    }
    Logger::log("[issueExtendedNFT] Sender: " + sender);

    unsigned char hash256[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(nftID.data()), nftID.size(), hash256);
    std::string fullHash = bytesToHex({hash256, hash256 + SHA256_DIGEST_LENGTH});
    std::string shortID = fullHash.substr(0, 16);
    Logger::log("[issueExtendedNFT] nftID hash=" + fullHash + ", short=" + shortID);

    auto [feeTxid, feeVout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (feeTxid.empty()) {
        throw std::runtime_error("No spendable UTXO found for fees");
    }
    uint64_t feeUtxoValue = getUtxoValueInAtoms(*blockchainPtr, feeTxid, feeVout);
    uint64_t fee = WALLET_MIN_BASE_FEE;
    if (feeUtxoValue < fee + 1) {
        throw std::runtime_error("Insufficient funds for fee + token UTXO");
    }

    // Build metadata
    TokenMeta meta;
    meta.data["name"] = nftName.empty() ? "Unnamed NFT" : nftName;
    meta.data["description"] = desc;
    meta.data["image"] = imageUrl;
    meta.data["creator"] = creator;
    meta.data["external_link"] = externalLink;
    meta.data["meta_id"] = generateMetaID(nftID);
    meta.data["dynamic_visual"] = generateDeterministicVisual(nftID, imageUrl);
    meta.data["decimals"] = "0";  // NFTs don't have decimals
    for (const auto& [key, value] : additionalMeta) {
        if (!key.empty() && !value.empty()) {
            meta.data[key] = value;
        }
    }
    std::string metaHash = generateMetaHash(meta.data);
    meta.data["metaHash"] = metaHash;
    Logger::log("[issueExtendedNFT] Computed metaHash=" + metaHash);

    // Build token data
    ExtendedTokenData tok;
    tok.tokenID = shortID;
    tok.type = TokenType::NFT;
    tok.amount = 1;  // NFT always has amount 1
    tok.version = 1;
    tok.meta = meta;
    tok.offChainMetadata = "";
    tok.metadataSignature = "";
    std::string opReturnHex = createExtendedTokenScriptPubKeyHex(tok, sender);

    // Build transaction
    Transaction tx(false);
    tx.set_sender(sender);
    tx.vin.emplace_back(feeTxid, feeVout);
    tx.vout.emplace_back(0, opReturnHex);  // OP_RETURN at vout 0
    tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(sender));  // Controlling output at vout 1
    uint64_t change = feeUtxoValue - fee - 1;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        tx.vout.emplace_back(change, createP2PKHScriptHexFromAddress(sender));
        feeBearingVout = tx.vout.size() - 1;
    }

    nlohmann::json metadataJson;
    metadataJson["type"] = "NFT";
    metadataJson["tokenID"] = tok.tokenID;
    metadataJson["amount"] = "1";
    metadataJson["owner"] = sender;
    metadataJson["version"] = std::to_string(tok.version);
    metadataJson["metadataSignature"] = tok.metadataSignature;
    metadataJson["offChainMetadata"] = tok.offChainMetadata;
    metadataJson["meta"] = tok.meta.data;
    
    // Store in transaction's tokenMetadata map with temporary key
    tx.tokenMetadata["pending"] = metadataJson;

    tx.computeTxId();
    if (tx.tokenMetadata.count("pending")) {
        tx.tokenMetadata[tx.txid] = tx.tokenMetadata["pending"];
        tx.tokenMetadata.erase("pending");
    }

    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "issueExtendedNFT");

    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign NFT issuance TX");
    }
    Logger::log("[issueExtendedNFT] Built & signed TX " + tx.txid);
/*
    // Store data in LevelDB
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (storage) {
        // Store metadata
        nlohmann::json metadataJson;
        metadataJson["type"] = "NFT";
        metadataJson["tokenID"] = tok.tokenID;
        metadataJson["amount"] = "1";
        metadataJson["owner"] = sender;
        metadataJson["version"] = std::to_string(tok.version);
        metadataJson["metadataSignature"] = tok.metadataSignature;
        metadataJson["offChainMetadata"] = tok.offChainMetadata;
        metadataJson["meta"] = tok.meta.data;
        
        std::string metaStr = metadataJson.dump();
        std::string metadataKey = "tokenMetadata:" + tx.txid;
        Logger::log("[issueExtendedNFT] Storing metadata with key: " + metadataKey);
        if (!storage->putWithDataChecksum(metadataKey, metaStr)) {
            Logger::log("[issueExtendedNFT] Error: Failed to store metadata");
        } else {
            Logger::log("[issueExtendedNFT] Successfully stored metadata: " + metaStr);
        }

        // Store token UTXO at the controlling output (vout 1)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":1";  // Note: vout 1, not 0
        nlohmann::json tokenUtxoJson = {
            {"tokenID", shortID},
            {"amount", "1"},
            {"owner", sender},
            {"type", "NFT"},
            {"controllingVout", 1}
        };
        std::string tokenUtxoValue = tokenUtxoJson.dump();
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[issueExtendedNFT] Error: Failed to store token UTXO data");
        } else {
            Logger::log("[issueExtendedNFT] Stored token UTXO data at key=" + tokenUtxoKey);
        }
        
        // Store ownership index
        std::string tokenIndexKey = "tokenOwnerUTXO:" + shortID + ":" + sender + ":" + tx.txid + ":1";
        if (!storage->putWithDataChecksum(tokenIndexKey, "1")) {
            Logger::log("[issueExtendedNFT] Error: Failed to store token ownership index");
        } else {
            Logger::log("[issueExtendedNFT] Stored token ownership index: " + tokenIndexKey);
        }
        
        // Store issuance mapping
        std::string issuanceKey = "tokenIssuance:" + shortID;
        if (!storage->putWithDataChecksum(issuanceKey, tx.txid)) {
            Logger::log("[issueExtendedNFT] Error: Failed to store issuance mapping");
        } else {
            Logger::log("[issueExtendedNFT] Stored issuance mapping: " + issuanceKey + " -> " + tx.txid);
        }
    } else {
        Logger::log("[issueExtendedNFT] Warning: Storage not available");
    }
*/
    // Add to mempool
    if (blockchainPtr->mempool->addTransaction(tx) != MempoolAddStatus::SUCCESS) {
        throw std::runtime_error("Mempool rejected NFT issuance TX");
    }
    Logger::log("[issueExtendedNFT] NFT issuance TX added to mempool: " + tx.txid);

    return tx.txid;
}

//==========================================================
//		Sentient Fungable Token
//==========================================================


    // Additional AI or “living” fields (ported from your current iteration, commented out)
    // meta.data["ai_version"]      = "1.2";
    // meta.data["learning_mode"]   = "on-chain usage patterns";
    // meta.data["growth_algorithm"] = "neural-adaptive";
    // meta.data["adaptation_rate"]  = "0.05";
    // meta.data["evolution_epoch"]  = "5000";
    // meta.data["description_ai"]   = "This SFT can auto-adjust minting fees if usage is low.";
    // meta.data["sentiment_score"] = "0.0";            // Tracks token sentiment via OP_DATAFEED
    // meta.data["self_evolution"] = "enabled";         // Allows self-updating via OP_CHAINSTATECHECK
    // meta.data["behavior_model"] = "adaptive_v3";     // Defines AI behavior using OP_EXTERNALDATA
    // meta.data["privacy_level"] = "high";             // Privacy settings for token interactions
    // meta.data["context_aware_rule"] = "context_v1";  // Context-aware logic with OP_STORE/OP_LOAD
    // New unique metadata fields for DeFi, atomic swaps, and new-age use cases
    // meta.data["defi_insurance_pool"] = "insure_" + tokenID; // Links to a DeFi insurance pool
    // meta.data["atomic_swap_sft_bundle"] = "bundle:" + tokenID + ":USDT"; // Bundles SFT for atomic swap
    // meta.data["emotional_resonance"] = "resonance_v1"; // Tracks emotional impact via OP_DATAFEED
    // meta.data["interdimensional_id"] = "idim_" + tokenID; // Identifier for interdimensional tracking
    // meta.data["bio_token_adaptation"] = "bio_adapt_v1"; // Adapts based on biometric data
    // meta.data["neuro_feedback_loop"] = "nfl_" + shortID;      // Neural feedback for sentient behavior
    // meta.data["ai_governance_vote"] = "agv_" + shortID;       // Voting weight in AI governance
    // meta.data["bio_sensor_trigger"] = "bst_v1";               // Triggers based on bio-sensor data
    // meta.data["multiverse_presence"] = "mvp_" + shortID;      // Presence across multiverse platforms
    // meta.data["empathic_response_id"] = "eri_v1";             // Empathic response identifier

std::string Wallet::issueExtendedSFT(
    const std::string& tokenID,
    uint64_t totalSupply,
    const std::string& name,
    const std::string& symbol,
    const std::string& description,
    const std::string& imageUrl,
    uint32_t decimals,
    const std::unordered_map<std::string, std::string>& additionalMeta
) {
    Logger::log("[issueExtendedSFT] Starting SFT issuance for tokenID=" + tokenID);

    if (tokenID.empty() || totalSupply == 0) {
        throw std::invalid_argument("Token ID must be non-empty and supply > 0");
    }
    std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error("No sender address available");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error("Requires local chain with valid blockchain & mempool");
    }
    Logger::log("[issueExtendedSFT] Sender: " + sender);

    unsigned char hash256[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(tokenID.data()), tokenID.size(), hash256);
    std::string fullHash = bytesToHex({hash256, hash256 + SHA256_DIGEST_LENGTH});
    std::string shortID = fullHash.substr(0, 16);
    Logger::log("[issueExtendedSFT] tokenID hash=" + fullHash + ", short=" + shortID);

    auto [feeTxid, feeVout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (feeTxid.empty()) {
        throw std::runtime_error("No spendable UTXO found for fees");
    }
    uint64_t feeUtxoValue = getUtxoValueInAtoms(*blockchainPtr, feeTxid, feeVout);
    uint64_t fee = WALLET_MIN_BASE_FEE;
    if (feeUtxoValue < fee + 1) {
        throw std::runtime_error("Insufficient funds for fee + token UTXO");
    }

    // Build metadata
    TokenMeta meta;
    meta.data["name"] = name.empty() ? "Unnamed SFT" : name;
    meta.data["symbol"] = symbol.empty() ? "SFT" : symbol;
    meta.data["description"] = description;
    meta.data["image"] = imageUrl;
    meta.data["decimals"] = std::to_string(decimals);
    meta.data["meta_id"] = generateMetaID(tokenID);
    meta.data["dynamic_visual"] = generateDeterministicVisual(tokenID, imageUrl);
    meta.data["ai_version"] = "1.2";
    meta.data["learning_mode"] = "on-chain usage patterns";
    meta.data["growth_algorithm"] = "neural-adaptive";
    for (const auto& [key, value] : additionalMeta) {
        if (!key.empty() && !value.empty()) {
            meta.data[key] = value;
        }
    }
    std::string metaHash = generateMetaHash(meta.data);
    meta.data["metaHash"] = metaHash;
    Logger::log("[issueExtendedSFT] Computed metaHash=" + metaHash);

    // Build token data
    ExtendedTokenData tok;
    tok.tokenID = shortID;
    tok.type = TokenType::SFT;
    tok.amount = scaleTokenSupplyToAtomsV1(totalSupply, decimals);
    tok.version = 1;
    tok.meta = meta;
    tok.offChainMetadata = "";
    tok.metadataSignature = "";
    std::string opReturnHex = createExtendedTokenScriptPubKeyHex(tok, sender);

    // Build transaction
    Transaction tx(false);
    tx.set_sender(sender);
    tx.vin.emplace_back(feeTxid, feeVout);
    tx.vout.emplace_back(0, opReturnHex);  // OP_RETURN at vout 0
    tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(sender));  // Controlling output at vout 1
    uint64_t change = feeUtxoValue - fee - 1;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        tx.vout.emplace_back(change, createP2PKHScriptHexFromAddress(sender));
        feeBearingVout = tx.vout.size() - 1;
    }

    nlohmann::json metadataJson;
    metadataJson["type"] = "SFT";
    metadataJson["tokenID"] = tok.tokenID;
    metadataJson["amount"] = std::to_string(tok.amount);
    metadataJson["owner"] = sender;
    metadataJson["version"] = std::to_string(tok.version);
    metadataJson["metadataSignature"] = tok.metadataSignature;
    metadataJson["offChainMetadata"] = tok.offChainMetadata;
    metadataJson["meta"] = tok.meta.data;
    
    // Store in transaction's tokenMetadata map with temporary key
    tx.tokenMetadata["pending"] = metadataJson;

    tx.computeTxId();
    if (tx.tokenMetadata.count("pending")) {
        tx.tokenMetadata[tx.txid] = tx.tokenMetadata["pending"];
        tx.tokenMetadata.erase("pending");
    }

    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "issueExtendedSFT");

    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign SFT issuance TX");
    }
    Logger::log("[issueExtendedSFT] Built & signed TX " + tx.txid);
/*
    // Store data in LevelDB
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (storage) {
        // Store metadata
        nlohmann::json metadataJson;
        metadataJson["type"] = "SFT";
        metadataJson["tokenID"] = tok.tokenID;
        metadataJson["amount"] = std::to_string(tok.amount);
        metadataJson["owner"] = sender;
        metadataJson["version"] = std::to_string(tok.version);
        metadataJson["metadataSignature"] = tok.metadataSignature;
        metadataJson["offChainMetadata"] = tok.offChainMetadata;
        metadataJson["meta"] = tok.meta.data;
        
        std::string metaStr = metadataJson.dump();
        std::string metadataKey = "tokenMetadata:" + tx.txid;
        Logger::log("[issueExtendedSFT] Storing metadata with key: " + metadataKey);
        if (!storage->putWithDataChecksum(metadataKey, metaStr)) {
            Logger::log("[issueExtendedSFT] Error: Failed to store metadata");
        } else {
            Logger::log("[issueExtendedSFT] Successfully stored metadata: " + metaStr);
        }

        // Store token UTXO at the controlling output (vout 1)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":1";  // Note: vout 1, not 0
        nlohmann::json tokenUtxoJson = {
            {"tokenID", shortID},
            {"amount", std::to_string(tok.amount)},
            {"owner", sender},
            {"type", "SFT"},
            {"controllingVout", 1}
        };
        std::string tokenUtxoValue = tokenUtxoJson.dump();
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[issueExtendedSFT] Error: Failed to store token UTXO data");
        } else {
            Logger::log("[issueExtendedSFT] Stored token UTXO data at key=" + tokenUtxoKey);
        }
        
        // Store ownership index
        std::string tokenIndexKey = "tokenOwnerUTXO:" + shortID + ":" + sender + ":" + tx.txid + ":1";
        if (!storage->putWithDataChecksum(tokenIndexKey, "1")) {
            Logger::log("[issueExtendedSFT] Error: Failed to store token ownership index");
        } else {
            Logger::log("[issueExtendedSFT] Stored token ownership index: " + tokenIndexKey);
        }
        
        // Store issuance mapping
        std::string issuanceKey = "tokenIssuance:" + shortID;
        if (!storage->putWithDataChecksum(issuanceKey, tx.txid)) {
            Logger::log("[issueExtendedSFT] Error: Failed to store issuance mapping");
        } else {
            Logger::log("[issueExtendedSFT] Stored issuance mapping: " + issuanceKey + " -> " + tx.txid);
        }
    } else {
        Logger::log("[issueExtendedSFT] Warning: Storage not available");
    }
*/
    // Add to mempool
    if (blockchainPtr->mempool->addTransaction(tx) != MempoolAddStatus::SUCCESS) {
        throw std::runtime_error("Mempool rejected SFT issuance TX");
    }
    Logger::log("[issueExtendedSFT] SFT issuance TX added to mempool: " + tx.txid);

    return tx.txid;
}
//==========================================================
//           Neural Canvas Fungible Tokens
//==========================================================

    // Additional AI/art fields (ported from your current iteration, commented out)
    // meta.data["ai_engine"]        = "StableDiffusion-v2";
    // meta.data["style_descriptor"] = "Van Gogh meets fractal geometry";
    // meta.data["dynamic_morph"]    = "transfer-based evolution";
    // meta.data["update_interval"]  = "1 transfer";
    // meta.data["creator_signature"] = "0xabcd...";
    // meta.data["last_evolution"]   = "None";
    // meta.data["neural_layer_count"] = "5";           // Defines neural network depth for generation
    // meta.data["generative_seed"] = "seed_" + tokenID; // Seed for generative art using OP_HASHBLAKE2B
    // meta.data["emotion_response"] = "dynamic";       // Emotional response logic via OP_DATAFEED
    // meta.data["holographic_url"] = "holo://" + tokenID; // Holographic display link
    // meta.data["ai_collaboration_id"] = "collab_v1";  // Links to AI collaboration network
    // New unique metadata fields for DeFi, atomic swaps, and new-age use cases
    // meta.data["defi_art_loan_value"] = "loan_" + tokenID; // Defines art-backed loan value in DeFi
    // meta.data["atomic_swap_ncft_chain"] = "chain:" + tokenID + ":SOL"; // Links NCFT for atomic swap with Solana
    // meta.data["quantum_art_resonance"] = "qres_" + tokenID; // Quantum resonance for art evolution
    // meta.data["telepathic_interface"] = "tele_v1"; // Enables telepathic-like interaction via OP_EXTERNALDATA
    // meta.data["galactic_exhibit_id"] = "galex_" + tokenID; // ID for galactic art exhibition
    // meta.data["neural_art_evolution"] = "nae_" + shortID;     // Neural network-driven art evolution
    // meta.data["cross_platform_avatar"] = "cpa_" + shortID;    // Avatar usable across platforms
    // meta.data["synaptic_pattern_id"] = "spi_v1";             // Synaptic pattern for AI rendering
    // meta.data["virtual_gallery_space"] = "vgs_" + shortID;   // Space in virtual art galleries
    // meta.data["dynamic_narrative_link"] = "dnl_" + shortID;   // Links to evolving narrative content

std::string Wallet::issueExtendedNCFT(
    const std::string& tokenID,
    uint64_t quantity,
    const std::string& name,
    const std::string& description,
    const std::string& imageOrMediaUrl,
    const std::unordered_map<std::string, std::string>& additionalMeta
) {
    Logger::log("[issueExtendedNCFT] Starting NCFT issuance for tokenID=" + tokenID);

    if (tokenID.empty() || quantity == 0) {
        throw std::invalid_argument("Token ID must be non-empty and quantity > 0");
    }
    std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error("No sender address available");
    }
    if (!isLocalChain || !blockchainPtr || !blockchainPtr->mempool) {
        throw std::runtime_error("Requires local chain with valid blockchain & mempool");
    }
    Logger::log("[issueExtendedNCFT] Sender: " + sender);

    unsigned char hash256[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(tokenID.data()), tokenID.size(), hash256);
    std::string fullHash = bytesToHex({hash256, hash256 + SHA256_DIGEST_LENGTH});
    std::string shortID = fullHash.substr(0, 16);
    Logger::log("[issueExtendedNCFT] tokenID hash=" + fullHash + ", short=" + shortID);

    auto [feeTxid, feeVout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (feeTxid.empty()) {
        throw std::runtime_error("No spendable UTXO found for fees");
    }
    uint64_t feeUtxoValue = getUtxoValueInAtoms(*blockchainPtr, feeTxid, feeVout);
    uint64_t fee = WALLET_MIN_BASE_FEE;
    if (feeUtxoValue < fee + 1) {
        throw std::runtime_error("Insufficient funds for fee + token UTXO");
    }

    // Build metadata
    TokenMeta meta;
    meta.data["name"] = name.empty() ? "Unnamed NCFT" : name;
    meta.data["description"] = description;
    meta.data["image"] = imageOrMediaUrl;
    meta.data["decimals"] = "0";  // NCFTs typically don't have decimals
    meta.data["meta_id"] = generateMetaID(tokenID);
    meta.data["dynamic_visual"] = generateDeterministicVisual(tokenID, imageOrMediaUrl);
    meta.data["ai_engine"] = "StableDiffusion-v2";
    meta.data["style_descriptor"] = "Van Gogh meets fractal geometry";
    meta.data["dynamic_morph"] = "transfer-based evolution";
    for (const auto& [key, value] : additionalMeta) {
        if (!key.empty() && !value.empty()) {
            meta.data[key] = value;
        }
    }
    std::string metaHash = generateMetaHash(meta.data);
    meta.data["metaHash"] = metaHash;
    Logger::log("[issueExtendedNCFT] Computed metaHash=" + metaHash);

    // Build token data
    ExtendedTokenData tok;
    tok.tokenID = shortID;
    tok.type = TokenType::NCFT;
    tok.amount = quantity;
    tok.version = 1;
    tok.meta = meta;
    tok.offChainMetadata = "";
    tok.metadataSignature = "";
    std::string opReturnHex = createExtendedTokenScriptPubKeyHex(tok, sender);

    // Build transaction
    Transaction tx(false);
    tx.set_sender(sender);
    tx.vin.emplace_back(feeTxid, feeVout);
    tx.vout.emplace_back(0, opReturnHex);  // OP_RETURN at vout 0
    tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(sender));  // Controlling output at vout 1
    uint64_t change = feeUtxoValue - fee - 1;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        tx.vout.emplace_back(change, createP2PKHScriptHexFromAddress(sender));
        feeBearingVout = tx.vout.size() - 1;
    }

    nlohmann::json metadataJson;
    metadataJson["type"] = "NCFT";
    metadataJson["tokenID"] = tok.tokenID;
    metadataJson["amount"] = std::to_string(quantity);
    metadataJson["owner"] = sender;
    metadataJson["version"] = std::to_string(tok.version);
    metadataJson["metadataSignature"] = tok.metadataSignature;
    metadataJson["offChainMetadata"] = tok.offChainMetadata;
    metadataJson["meta"] = tok.meta.data;
    
    // Store in transaction's tokenMetadata map with temporary key
    tx.tokenMetadata["pending"] = metadataJson;

    tx.computeTxId();
    if (tx.tokenMetadata.count("pending")) {
        tx.tokenMetadata[tx.txid] = tx.tokenMetadata["pending"];
        tx.tokenMetadata.erase("pending");
    }

    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "issueExtendedNCFT");

    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign NCFT issuance TX");
    }
    Logger::log("[issueExtendedNCFT] Built & signed TX " + tx.txid);
/*
    // Store data in LevelDB
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (storage) {
        // Store metadata
        nlohmann::json metadataJson;
        metadataJson["type"] = "NCFT";
        metadataJson["tokenID"] = tok.tokenID;
        metadataJson["amount"] = std::to_string(quantity);
        metadataJson["owner"] = sender;
        metadataJson["version"] = std::to_string(tok.version);
        metadataJson["metadataSignature"] = tok.metadataSignature;
        metadataJson["offChainMetadata"] = tok.offChainMetadata;
        metadataJson["meta"] = tok.meta.data;
        
        std::string metaStr = metadataJson.dump();
        std::string metadataKey = "tokenMetadata:" + tx.txid;
        Logger::log("[issueExtendedNCFT] Storing metadata with key: " + metadataKey);
        if (!storage->putWithDataChecksum(metadataKey, metaStr)) {
            Logger::log("[issueExtendedNCFT] Error: Failed to store metadata");
        } else {
            Logger::log("[issueExtendedNCFT] Successfully stored metadata: " + metaStr);
        }

        // Store token UTXO at the controlling output (vout 1)
        std::string tokenUtxoKey = "tokenUTXO:" + tx.txid + ":1";  // Note: vout 1, not 0
        nlohmann::json tokenUtxoJson = {
            {"tokenID", shortID},
            {"amount", std::to_string(quantity)},
            {"owner", sender},
            {"type", "NCFT"},
            {"controllingVout", 1}
        };
        std::string tokenUtxoValue = tokenUtxoJson.dump();
        if (!storage->putWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[issueExtendedNCFT] Error: Failed to store token UTXO data");
        } else {
            Logger::log("[issueExtendedNCFT] Stored token UTXO data at key=" + tokenUtxoKey);
        }
        
        // Store ownership index
        std::string tokenIndexKey = "tokenOwnerUTXO:" + shortID + ":" + sender + ":" + tx.txid + ":1";
        if (!storage->putWithDataChecksum(tokenIndexKey, "1")) {
            Logger::log("[issueExtendedNCFT] Error: Failed to store token ownership index");
        } else {
            Logger::log("[issueExtendedNCFT] Stored token ownership index: " + tokenIndexKey);
        }
        
        // Store issuance mapping
        std::string issuanceKey = "tokenIssuance:" + shortID;
        if (!storage->putWithDataChecksum(issuanceKey, tx.txid)) {
            Logger::log("[issueExtendedNCFT] Error: Failed to store issuance mapping");
        } else {
            Logger::log("[issueExtendedNCFT] Stored issuance mapping: " + issuanceKey + " -> " + tx.txid);
        }
    } else {
        Logger::log("[issueExtendedNCFT] Warning: Storage not available");
    }
*/
    // Add to mempool
    if (blockchainPtr->mempool->addTransaction(tx) != MempoolAddStatus::SUCCESS) {
        throw std::runtime_error("Mempool rejected NCFT issuance TX");
    }
    Logger::log("[issueExtendedNCFT] NCFT issuance TX added to mempool: " + tx.txid);

    return tx.txid;
}

//==========================================================
// Calculate the atom ordinal.
//=========================================================
uint64_t Wallet::calculateCurrentSatNumber() {
    uint64_t totalSats = 0;
    uint32_t currentHeight = blockchainPtr->getBestTipHeight();
    
    for (uint32_t height = 0; height <= currentHeight; height++) {
        uint64_t blockReward = getBlockReward(height);
        totalSats += blockReward;
    }
    
    // Return the next available TRU atom ordinal
    return totalSats;
}
//==========================================================
// 			GET BLOCKREWARD FOR 
//=========================================================
uint64_t Wallet::getBlockReward(uint32_t height) {
    // Genesis block and first 210,000 blocks: 50 TRU = 5,000,000,000 TRU atoms
    if (height < 210000) {
        return 5000000000; // NOT 10000000000!
    }
    // Halving every 210,000 blocks
    uint32_t halvings = height / 210000;
    uint64_t reward = 5000000000;
    
    for (uint32_t i = 0; i < halvings && reward > 0; i++) {
        reward /= 2;
    }
    
    return reward;
}

//==========================================================================================
//					Inscribe TRUScript
//==========================================================================================
std::string Wallet::inscribeTRUScript(const std::string& humanData,
                                      const std::string& ownerAddress)
{
    if (!blockchainPtr || !isLocalChain)
        throw std::runtime_error("Local chain not available");
        
    // 1) pick a UTXO for the fee
    auto [feeTxid, feeVout] = findOneSpendableUtxo(ownerAddress, blockchainPtr->mempool.get());
    if (feeTxid.empty())
        throw std::runtime_error("Insufficient UTXOs for fee");
    uint64_t feeAmount = WALLET_MIN_BASE_FEE;
    
    // —————————————————————————————————————————————————————
    // Compute metadata *before* we create the transaction
    // —————————————————————————————————————————————————————
    
    // a) timestamp = now
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
    
    // b) satNumber = cumulative TRU atoms from genesis
    uint64_t satNumber = calculateCurrentSatNumber();
    
    // c) inscriptionIndex = count(existing) + 1
    uint64_t inscriptionIndex = 0;
    {   
        int count = 0;
        blockchainPtr->getStorage()
            ->iteratePrefix("tokenMetadata:", [&](auto const&, auto const& raw) {
                try {
                    auto j = nlohmann::json::parse(raw);
                    if (j.value("type","") == "TRUSCRIPT")
                        ++count;
                } catch (...) {
                    // Ignore parse errors
                }
            });
        inscriptionIndex = static_cast<uint64_t>(count) + 1;
    }
    
    // 2) build the OP_RETURN script with ALL metadata
    std::string scriptHex = buildTRUScript_OPRETURN(humanData, ownerAddress, 
                                                    inscriptionIndex, satNumber, timestamp);
    
    // do not construct a script Patch 12A consensus rejects.
    if (scriptHex.length() / 2 > tru_limits::MAX_SCRIPT_BYTES) {
        throw std::runtime_error(
            "TRUScript data exceeds consensus script-size limit");
    }
    
    // 3) build the transaction
    Transaction tx;
    tx.isCoinbase = false;
    tx.vin.emplace_back(feeTxid, feeVout);
    tx.vout.emplace_back(0, scriptHex);
    
    // change
    UTXO utxo;
    if (!blockchainPtr->utxoSet.getUTXO(feeTxid, feeVout, utxo))
        throw std::runtime_error("Fee UTXO not found");
    uint64_t change = utxo.amount - feeAmount;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        auto changeScript = createP2PKHScriptHexFromAddress(ownerAddress);
        tx.vout.emplace_back(change, changeScript);
        feeBearingVout = tx.vout.size() - 1;
    }
    
    feeAmount = applyWalletPolicyFee(
        tx, feeAmount, feeBearingVout, "inscribeTRUScript");

    // 4) sign & broadcast
    tx.computeTxId();
    if (!signTransaction(tx))
        throw std::runtime_error("Failed to sign TRUScript tx");
    
    // Broadcast to network
    if (!blockchainPtr->broadcastTransaction(tx)) {
        throw std::runtime_error("Failed to broadcast inscription transaction");
    }
    // 5) STILL store metadata locally for fast access
    // This is now redundant but improves performance for local queries
    nlohmann::json meta;
    meta["type"]             = "TRUSCRIPT";
    meta["owner"]            = ownerAddress;
    meta["data"]             = humanData;
    meta["inscriptionIndex"] = inscriptionIndex;
    meta["satNumber"]        = satNumber;
    meta["timestamp"]        = timestamp;
    meta["sizeBytes"]        = (scriptHex.size() - 2) / 2;
    meta["creationTxid"]     = tx.txid;
    meta["currentTxid"]      = tx.txid;
    
    std::string key = "tokenMetadata:" + tx.txid;
    blockchainPtr->getStorage()->putWithDataChecksum(key, meta.dump());
    
    Logger::log("[inscribeTRUScript] Created TRUScript " + tx.txid + 
                " with inscriptionIndex=" + std::to_string(inscriptionIndex) +
                " satNumber=" + std::to_string(satNumber));
    
    return tx.txid;
}

//===========================================================================================
//				OWNED TRUSCRIPTS
//===========================================================================================
std::vector<TRUScriptInfo> Wallet::getTRUScripts(const std::string& ownerAddress) const
{
    std::vector<TRUScriptInfo> result;
    if (!blockchainPtr) return result;

    auto storage = blockchainPtr->getStorage();
    storage->iteratePrefix("tokenMetadata:", [&](const std::string& key, const std::string& rawValue) {
        try {
            auto entry = nlohmann::json::parse(rawValue);
            if (entry.value("type","") == "TRUSCRIPT"
             && entry.value("owner","") == ownerAddress)
            {
                TRUScriptInfo info;
                
                // The key from iteratePrefix might already have the prefix removed
                // or it might include it. We need to handle both cases.
                std::string fullKey = key;
                std::string prefix = "tokenMetadata:";
                
                // If the key starts with the prefix, remove it
                if (fullKey.find(prefix) == 0) {
                    info.txid = fullKey.substr(prefix.length());
                } else {
                    // The key is already just the txid
                    info.txid = fullKey;
                }
                
                // Alternative: get the txid from the metadata itself if stored
                std::string storedTxid = entry.value("creationTxid", "");
                if (!storedTxid.empty() && storedTxid.length() == 64) {
                    info.txid = storedTxid;
                }
                
                Logger::log("[getTRUScripts] Processing key: " + key + 
                           ", extracted txid: " + info.txid + 
                           " (length: " + std::to_string(info.txid.length()) + ")");
                
                info.data             = entry.value("data","");
                info.owner            = ownerAddress;
                info.inscriptionIndex = entry.value("inscriptionIndex", 0ULL);
                info.satNumber        = entry.value("satNumber",        0ULL);
                info.timestamp        = entry.value("timestamp",         0ULL);
                info.sizeBytes        = entry.value("sizeBytes",         0ULL);
                info.height           = blockchainPtr->getTxBlockHeight(info.txid);
                info.contentType      = "text/plain";
                info.metadata         = entry;

                result.push_back(std::move(info));
            }
        } catch (const std::exception& e) {
            Logger::log("[getTRUScripts] Error parsing entry for key " + key + ": " + e.what());
        }
    });

    return result;
}
//==============================================================================
//                        Transfer TRUScript
//==============================================================================
std::string Wallet::transferTRUScript(const std::string& inscriptionTxid, 
                                      const std::string& newOwnerAddress) {
    Logger::log("[transferTRUScript] Starting transfer of " + inscriptionTxid + " to " + newOwnerAddress);
    
    if (!blockchainPtr || !isLocalChain) {
        throw std::runtime_error("Local chain not available");
    }
    
    // Validate new owner address
    std::string err;
    if (!validateBase58Address(newOwnerAddress, err)) {
        throw std::runtime_error("Invalid recipient address: " + err);
    }
    
    // Get current owner (first address in wallet)
    if (addresses.empty()) {
        throw std::runtime_error("No addresses in wallet");
    }
    std::string currentOwner = addresses[0];
    
    // Fetch TRUScript metadata
    std::string metaKey = "tokenMetadata:" + inscriptionTxid;
    std::string metaValue;
    if (!blockchainPtr->getStorage()->getWithDataChecksum(metaKey, metaValue)) {
        throw std::runtime_error("TRUScript not found: " + inscriptionTxid);
    }
    
    nlohmann::json meta;
    try {
        meta = nlohmann::json::parse(metaValue);
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid TRUScript metadata: " + std::string(e.what()));
    }
    
    if (meta.value("type", "") != "TRUSCRIPT") {
        throw std::runtime_error("Not a TRUScript: " + inscriptionTxid);
    }
    
    if (meta.value("owner", "") != currentOwner) {
        throw std::runtime_error("You don't own this TRUScript. Current owner: " + 
                               meta.value("owner", "unknown") + ", Your address: " + currentOwner);
    }
    
    // Find a UTXO for fees
    auto [feeTxid, feeVout] = findOneSpendableUtxo(currentOwner, blockchainPtr->mempool.get());
    if (feeTxid.empty()) {
        throw std::runtime_error("No UTXO available for fees");
    }
    
    UTXO feeUtxo;
    if (!blockchainPtr->utxoSet.getUTXO(feeTxid, feeVout, feeUtxo)) {
        throw std::runtime_error("Fee UTXO not found");
    }
    
    uint64_t fee = WALLET_MIN_BASE_FEE;
    const uint64_t dustLimit = 546; // Standard dust limit
    
    if (feeUtxo.amount < fee + dustLimit) {
        throw std::runtime_error("Insufficient funds for transfer. Need at least " + 
                               std::to_string(fee + dustLimit) + " TRU atoms");
    }
    
    // Build transfer transaction
    Transaction tx(false); // Not coinbase
    
    // Input: fee UTXO
    tx.vin.emplace_back(feeTxid, feeVout);
    
    // Output 0: Transfer marker (OP_RETURN with transfer data)
    nlohmann::json transferData = {
    {"type", "TRUSCRIPT_TRANSFER"},
    {"inscription", inscriptionTxid},
    {"from", currentOwner},
    {"to", newOwnerAddress},
    {"timestamp", static_cast<uint64_t>(std::time(nullptr))},
    // Include the full inscription data for nodes that don't have it
    {"data", meta.value("data", "")},
    {"inscriptionIndex", meta.value("inscriptionIndex", 0)},
    {"satNumber", meta.value("satNumber", 0)},
    {"creationTimestamp", meta.value("timestamp", 0)},
    {"sizeBytes", meta.value("sizeBytes", 0)}
    };

    std::string transferJson = transferData.dump();
    
    // Convert JSON to hex for OP_RETURN
    std::string dataHex;
    for (unsigned char c : transferJson) {
        char buf[3];
        sprintf(buf, "%02x", c);
        dataHex += buf;
    }
    
    // Build OP_RETURN script with proper length encoding
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
    } else if (dataLen <= 65535) {
        // OP_PUSHDATA2
        lenHex = "4d";
        char buf[5];
        sprintf(buf, "%02x%02x", (unsigned int)(dataLen & 0xFF), (unsigned int)(dataLen >> 8));
        lenHex += buf;
    } else {
        throw std::runtime_error("Transfer data too large for OP_RETURN");
    }
    
    std::string transferScriptHex = "6a" + lenHex + dataHex;
    if (transferScriptHex.size() / 2 > tru_limits::MAX_SCRIPT_BYTES) {
        throw std::runtime_error(
            "TRUScript transfer metadata exceeds consensus script-size limit");
    }
    tx.vout.emplace_back(0, transferScriptHex); // 0 amount for OP_RETURN
    
    // Output 1: Dust to new owner (this represents ownership of the inscription)
    std::string newOwnerScript = createP2PKHScriptHexFromAddress(newOwnerAddress);
    tx.vout.emplace_back(dustLimit, newOwnerScript);
    
    // Output 2: Change back to sender (if any)
    uint64_t change = feeUtxo.amount - fee - dustLimit;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > dustLimit) { // Only create change output if it's above dust
        std::string changeScript = createP2PKHScriptHexFromAddress(currentOwner);
        tx.vout.emplace_back(change, changeScript);
        feeBearingVout = tx.vout.size() - 1;
    } else if (change > 0) {
        // If change is dust, add it to the fee instead
        Logger::log("[transferTRUScript] Change amount " + std::to_string(change) + 
                   " is dust, adding to fee");
        fee += change;
    }
    
    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "transferTRUScript");

    // Compute txid before signing
    tx.computeTxId();
    
    // Sign the transaction
    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign transfer transaction");
    }
    
    // DON'T do optimistic updates here - let the blockchain handle it when the tx is mined
    
    // require validated mempool acceptance before
    // recording a transfer, so rejection cannot leave false history.
    if (!blockchainPtr->broadcastTransaction(tx)) {
        throw std::runtime_error("TRUScript transfer rejected by mempool/broadcast path");
    }

    std::string transferKey = "truScriptTransfer:" + tx.txid;
    nlohmann::json transferRecord = {
        {"inscriptionTxid", inscriptionTxid},
        {"from", currentOwner},
        {"to", newOwnerAddress},
        {"timestamp", static_cast<uint64_t>(std::time(nullptr))},
        {"transferTxid", tx.txid},
        {"data", meta.value("data", "")}
    };
    blockchainPtr->getStorage()->putWithDataChecksum(transferKey, transferRecord.dump());

    Logger::log("[transferTRUScript] Transfer transaction created: " + tx.txid);
    Logger::log("[transferTRUScript] Inscription " + inscriptionTxid + 
               " transferred from " + currentOwner + " to " + newOwnerAddress);
    
    return tx.txid;
}
//==============================================================
//              CHECK CONTROLLING UTXO
//==============================================================
std::set<std::pair<std::string, uint32_t>> Wallet::getControllingUtxos(const std::string& address) const {
    std::set<std::pair<std::string, uint32_t>> controllingUtxos;
    if (isLocalChain && blockchainPtr) {
        LevelDBStorage* storage = blockchainPtr->getStorage();
        if (storage) {
            std::string prefix = "tokenOwnerUTXO::" + address + ":";
            storage->iteratePrefix(prefix, [&](const std::string& key, const std::string& value) {
                // key format: tokenOwnerUTXO:tokenID:address:txid:vout
                size_t pos1 = key.find(':', strlen("tokenOwnerUTXO:"));
                size_t pos2 = key.find(':', pos1 + 1);
                size_t pos3 = key.find(':', pos2 + 1);
                if (pos3 != std::string::npos) {
                    std::string txid = key.substr(pos2 + 1, pos3 - pos2 - 1);
                    std::string voutStr = key.substr(pos3 + 1);
                    uint32_t vout = std::stoul(voutStr);
                    controllingUtxos.insert({txid, vout});
                }
            });
        }
    }
    return controllingUtxos;
}
//==============================================================
//		GET UTXO FOR RPC ADDRESS
//==============================================================
std::vector<UTXO> Wallet::getUTXOsForAddressRPC(const std::string& address, const std::string& nodeIP, int nodePort) const {
    return rpcListUnspent(nodeIP, nodePort, address);
}
//==============================================================
// 			FindTokenUTXO
//==============================================================
std::tuple<std::string, uint32_t, uint32_t> Wallet::findTokenUTXO(const std::string& tokenID, const std::string& senderAddress) const {
    Logger::log("[findTokenUTXO] Looking for tokenID=" + tokenID + " owner=" + senderAddress);

    if (isLocalChain) {
        auto* storage = blockchainPtr->getStorage();
        if (!storage || !blockchainPtr->mempool) {
            Logger::log("[findTokenUTXO] Storage or mempool not available");
            return {"", 0, 0};
        }

        std::string prefix = "tokenOwnerUTXO:" + tokenID + ":" + senderAddress + ":";
        std::string foundKey;
        std::string foundValue;

        storage->iteratePrefix(prefix, [&](const std::string& keySansPrefix, const std::string& value) -> bool {
            std::string fullKey = prefix + keySansPrefix;
            Logger::log("[findTokenUTXO] Found key: " + fullKey);

            size_t pos = fullKey.find_last_of(':');
            if (pos == std::string::npos) return true;

            std::string txid_vout = fullKey.substr(prefix.length());
            size_t vout_pos = txid_vout.find_last_of(':');
            if (vout_pos == std::string::npos) return true;

            foundKey = txid_vout.substr(0, vout_pos);
            foundValue = txid_vout.substr(vout_pos + 1);
            Logger::log("[findTokenUTXO] Extracted txid=" + foundKey + ", controllingVout=" + foundValue);

            // Validate UTXO is unspent
            uint32_t controllingVout = std::stoul(foundValue);
            UTXO utxo;
            if (!blockchainPtr->utxoSet.getUTXO(foundKey, controllingVout, utxo)) {
                Logger::log("[findTokenUTXO] UTXO " + foundKey + ":" + foundValue + " not in UTXO set");
                return true; // Continue searching
            }
            if (blockchainPtr->mempool->isUTXOSpentInMempool(foundKey, controllingVout)) {
                Logger::log("[findTokenUTXO] UTXO " + foundKey + ":" + foundValue + " spent in mempool");
                return true; // Continue searching
            }
            return false; // Found a valid UTXO
        });

        if (foundKey.empty()) {
            Logger::log("[findTokenUTXO] No unspent UTXO found for tokenID=" + tokenID + " owner=" + senderAddress);
            return {"", 0, 0};
        }

        uint32_t controllingVout = std::stoul(foundValue);
        uint32_t tokenVout = controllingVout - 1;

        //std::string tokenUtxoKey = "tokenUTXO:" + foundKey + ":" + std::to_string(tokenVout);
        std::string tokenUtxoKey = "tokenUTXO:" + foundKey + ":" + std::to_string(controllingVout);
        std::string tokenUtxoValue;
        if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[findTokenUTXO] Error: Token UTXO data not found for key=" + tokenUtxoKey);
            return {"", 0, 0};
        }

        nlohmann::json j = nlohmann::json::parse(tokenUtxoValue);
        if (!j.contains("tokenID") || j["tokenID"] != tokenID) {
            Logger::log("[findTokenUTXO] Error: Token ID mismatch in tokenUTXO data");
            return {"", 0, 0};
        }

        Logger::log("[findTokenUTXO] Found controlling vout=" + std::to_string(controllingVout) + ", token vout=" + std::to_string(tokenVout));
        return {foundKey, controllingVout, tokenVout};
    } else {
        if (nodeIP.empty() || nodePort == 0) {
            Logger::log("[findTokenUTXO] Error: Node IP or port not configured in standalone mode");
            return {"", 0, 0};
        }

        try {
            // Fetch token UTXOs
            nlohmann::json params = {{"tokenID", tokenID}, {"address", senderAddress}};
            auto response = rpcCall("gettokenutxo", params, nodeIP, nodePort);
            if (response.contains("error") || !response.contains("result") || response["result"].empty()) {
                Logger::log("[findTokenUTXO] No token UTXOs found: " + response.dump());
                return {"", 0, 0};
            }

            // Fetch unspent UTXOs
            params = {{"address", senderAddress}};
            auto unspentResponse = rpcCall("listunspent", params, nodeIP, nodePort);
            if (unspentResponse.contains("error") || !unspentResponse.contains("result")) {
                Logger::log("[findTokenUTXO] Failed to fetch unspent UTXOs: " + unspentResponse.dump());
                return {"", 0, 0};
            }
            std::unordered_set<std::string> unspentUTXOs;
            for (const auto& unspent : unspentResponse["result"]) {
                std::string key = unspent["txid"].get<std::string>() + ":" + std::to_string(unspent["vout"].get<uint32_t>());
                unspentUTXOs.insert(key);
            }

            // Find a valid, unspent token UTXO
            for (const auto& result : response["result"]) {
                std::string txid = result["txid"].get<std::string>();
                uint32_t controllingVout = result["controllingVout"].get<uint32_t>();
                uint32_t tokenVout = result["tokenVout"].get<uint32_t>();
                std::string utxoKey = txid + ":" + std::to_string(controllingVout);

                if (unspentUTXOs.count(utxoKey)) {
                    Logger::log("[findTokenUTXO] Found unspent UTXO: txid=" + txid + ", controllingVout=" + std::to_string(controllingVout));
                    return {txid, controllingVout, tokenVout};
                }
            }

            Logger::log("[findTokenUTXO] No unspent token UTXOs found for tokenID=" + tokenID);
            return {"", 0, 0};
        } catch (const std::exception& e) {
            Logger::log("[findTokenUTXO] Exception: " + std::string(e.what()));
            return {"", 0, 0};
        }
    }
}
//==========================================================
// 		transferExtendedToken
//==========================================================
std::string Wallet::transferExtendedToken(
    const std::string& oldTxid,
    uint32_t oldVout,
    uint64_t quantityToSend,
    const std::string& newOwnerAddress
) {
    Logger::log("[transferExtendedToken] Starting transfer: txid=" + oldTxid +
                ", vout=" + std::to_string(oldVout) +
                ", quantity=" + std::to_string(quantityToSend) +
                ", to=" + newOwnerAddress);

    std::string sender = getCurrentAddress();
    if (sender.empty()) {
        throw std::runtime_error("No sender address");
    }

    if (isLocalChain) {
        if (!blockchainPtr || !blockchainPtr->mempool) {
            throw std::runtime_error("Requires local chain with mempool");
        }

        UTXO oldUtxo;
        if (!blockchainPtr->utxoSet.getUTXO(oldTxid, oldVout, oldUtxo)) {
            throw std::runtime_error("Token UTXO not found");
        }
        LevelDBStorage* storage = blockchainPtr->getStorage();
        if (!storage) {
            throw std::runtime_error("Storage not available");
        }

        std::string tokenUtxoKey = "tokenUTXO:" + oldTxid + ":" + std::to_string(oldVout);
        std::string tokenUtxoValue;
        if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            throw std::runtime_error("Token UTXO association not found");
        }

        nlohmann::json j = nlohmann::json::parse(tokenUtxoValue);
        std::string truncatedTokenID = j["tokenID"].get<std::string>();
        uint64_t utxoAmount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
        std::string utxoOwner = j["owner"].get<std::string>();
        std::string tokenTypeStr = j.value("type", "FT");

        if (utxoOwner != sender) {
            throw std::runtime_error("Sender does not own UTXO");
        }
        if (quantityToSend > utxoAmount) {
            throw std::runtime_error("Insufficient token amount");
        }

        ExtendedTokenData oldData;
        oldData.tokenID = truncatedTokenID;
        oldData.amount = utxoAmount;
        oldData.type = stringToTokenType(tokenTypeStr);
        if (oldData.type == TokenType::NONE) {
            oldData.type = TokenType::FT;
        }

        // Fetch metadata
        std::string metadataKey = "tokenMetadata:" + oldTxid;
        std::string metadataValue;
        if (!storage->getWithDataChecksum(metadataKey, metadataValue)) {
            throw std::runtime_error("Metadata not found");
        }
        nlohmann::json metadataJson = nlohmann::json::parse(metadataValue);
        if (metadataJson.contains("meta") && metadataJson["meta"].is_object()) {
            oldData.meta.data = metadataJson["meta"];
        } else {
            oldData.meta.data = nlohmann::json::object();
            for (auto& item : metadataJson.items()) {
                if (item.key() != "amount" && item.key() != "owner" &&
                    item.key() != "tokenID" && item.key() != "type") {
                    oldData.meta.data[item.key()] = item.value();
                }
            }
        }

        nlohmann::json tdJson;
        tdJson["type"] = tokenTypeToString(oldData.type);
        tdJson["tokenID"] = truncatedTokenID;
        tdJson["amount"] = std::to_string(quantityToSend);
        tdJson["owner"] = newOwnerAddress;
        tdJson["version"] = metadataJson.contains("version") ? metadataJson["version"] : "1";
        tdJson["metadataSignature"] = metadataJson.contains("metadataSignature") ? metadataJson["metadataSignature"] : "";
        tdJson["offChainMetadata"] = metadataJson.contains("offChainMetadata") ? metadataJson["offChainMetadata"] : "";

        // CRITICAL: Include ALL metadata fields, not just the basic ones
        tdJson["meta"] = oldData.meta.data;

        // Also preserve any additional fields from the original metadata
        for (auto& [key, value] : metadataJson.items()) {
            if (key != "amount" && key != "owner" && key != "type" && key != "tokenID" && 
                key != "version" && key != "metadataSignature" && key != "offChainMetadata" && 
                key != "meta") {
                tdJson[key] = value;
            }
        }

        auto [feeTxid, feeVout] = findOneCoinUtxo(sender);
        if (feeTxid.empty()) {
            throw std::runtime_error("No fee UTXO available");
        }
        uint64_t coinValue = getUtxoValueInAtoms(*blockchainPtr, feeTxid, feeVout);
        uint64_t fee = WALLET_MIN_BASE_FEE;
        uint64_t minRequired = fee + ((utxoAmount - quantityToSend) > 0 ? 1 : 0);
        if (coinValue < minRequired) {
            throw std::runtime_error("Insufficient fee funds");
        }

        Transaction tx(false);
        tx.set_sender(sender);
        tx.vin.emplace_back(oldTxid, oldVout);
        tx.vin.emplace_back(feeTxid, feeVout);

        ExtendedTokenData newData = oldData;
        newData.amount = quantityToSend;
        std::string newTokenScriptHex = createExtendedTokenScriptPubKeyHex(newData, newOwnerAddress);
        tx.vout.emplace_back(0, newTokenScriptHex);
        std::string newOwnerScript = createP2PKHScriptHexFromAddress(newOwnerAddress);
        tx.vout.emplace_back(1, newOwnerScript);

        uint64_t leftoverAmt = utxoAmount - quantityToSend;
        bool isFungible = (oldData.type == TokenType::FT || oldData.type == TokenType::SFT || oldData.type == TokenType::NCFT);
        if (leftoverAmt > 0 && isFungible) {
            ExtendedTokenData changeData = oldData;
            changeData.amount = leftoverAmt;
            std::string changeTokenScriptHex = createExtendedTokenScriptPubKeyHex(changeData, sender);
            tx.vout.emplace_back(0, changeTokenScriptHex);
            std::string senderScript = createP2PKHScriptHexFromAddress(sender);
            tx.vout.emplace_back(1, senderScript);
        }

        uint64_t leftoverCoin = coinValue - fee - ((leftoverAmt > 0 && isFungible) ? 1 : 0);
        std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
        if (leftoverCoin > 0) {
            std::string changeScript = createP2PKHScriptHexFromAddress(sender);
            tx.vout.emplace_back(leftoverCoin, changeScript);
            feeBearingVout = tx.vout.size() - 1;
        }

        tx.computeTxId();

        tx.tokenMetadata[tx.txid] = tdJson;

        Logger::log("[transferExtendedToken] Attached metadata to transaction: " + tdJson.dump());

        fee = applyWalletPolicyFee(
            tx, fee, feeBearingVout, "transferExtendedToken(local)");

        if (!signTransaction(tx)) {
            throw std::runtime_error("Failed to sign transaction");
        }

        // one signature pass is sufficient.
        Logger::log("[transferExtendedToken] Transaction ID: " + tx.txid);

        // do NOT mutate confirmed token/UTXO/
        // ownership indexes before confirmation. applyBlock() is the source of
        // truth once this transaction is actually mined.
        if (blockchainPtr->mempool->addTransaction(tx) != MempoolAddStatus::SUCCESS) {
            throw std::runtime_error(
                "Mempool rejected token transfer; confirmed token state was not changed");
        }

        // Already accepted locally; this call now only needs to propagate to peers.
        if (!blockchainPtr->broadcastTransaction(tx)) {
            Logger::log("[transferExtendedToken] Warning: peer broadcast failed after local mempool acceptance");
        }

        Logger::log("[transferExtendedToken] Transfer successful: txid=" + tx.txid);
        return tx.txid;
    } else {
        // Standalone mode implementation would be similar but with RPC calls
        // ... existing standalone code ...
        if (nodeIP.empty() || nodePort == 0) {
            throw std::runtime_error("Node IP or port not configured in standalone mode");
        }
        if (oldVout == 0) {
            throw std::runtime_error("Invalid vout: cannot use vout=0 for token data");
        }

        nlohmann::json params = {{"txid", oldTxid}, {"vout", oldVout - 1}};
        Logger::log("[transferExtendedToken] Fetching token UTXO with params: " + params.dump());
        auto tokenResponse = rpcCall("gettokenutxo", params, nodeIP, nodePort);
        Logger::log("[transferExtendedToken] RPC response: " + tokenResponse.dump());

        if (tokenResponse.contains("error") || !tokenResponse.contains("result") || 
            !tokenResponse["result"].is_array() || tokenResponse["result"].empty()) {
            throw std::runtime_error("Failed to fetch token UTXO via RPC: " + 
                (tokenResponse.contains("error") ? tokenResponse["error"]["message"].get<std::string>() : "Empty result"));
        }

        auto tokenUtxo = tokenResponse["result"][0];
        if (!tokenUtxo.contains("tokenID") || !tokenUtxo.contains("amount") || 
            !tokenUtxo.contains("owner") || !tokenUtxo.contains("type") ||
            !tokenUtxo["tokenID"].is_string() || !tokenUtxo["amount"].is_number_unsigned() ||
            !tokenUtxo["owner"].is_string() || !tokenUtxo["type"].is_string()) {
            throw std::runtime_error("Invalid token UTXO data: missing or invalid fields");
        }

        std::string truncatedTokenID = tokenUtxo["tokenID"].get<std::string>();
        uint64_t utxoAmount = tokenUtxo["amount"].get<uint64_t>();
        std::string utxoOwner = tokenUtxo["owner"].get<std::string>();
        std::string tokenTypeStr = tokenUtxo["type"].get<std::string>();

        if (utxoOwner != sender) {
            throw std::runtime_error("Sender does not own UTXO, expected=" + sender + ", found=" + utxoOwner);
        }
        if (quantityToSend > utxoAmount) {
            throw std::runtime_error("Insufficient token amount: requested=" + 
                std::to_string(quantityToSend) + ", available=" + std::to_string(utxoAmount));
        }

        params = {{"txid", oldTxid}};
        Logger::log("[transferExtendedToken] Fetching metadata with params: " + params.dump());
        auto metadataResponse = rpcCall("gettokenmetadata", params, nodeIP, nodePort);
        Logger::log("[transferExtendedToken] Metadata RPC response: " + metadataResponse.dump());

        if (metadataResponse.contains("error") || !metadataResponse.contains("result")) {
            throw std::runtime_error("Failed to fetch metadata via RPC: " + 
                (metadataResponse.contains("error") ? metadataResponse["error"]["message"].get<std::string>() : "No result"));
        }
        auto metadata = metadataResponse["result"];

        ExtendedTokenData oldData;
        oldData.tokenID = truncatedTokenID;
        oldData.amount = utxoAmount;
        oldData.type = stringToTokenType(tokenTypeStr);
        if (metadata.contains("meta") && metadata["meta"].is_object()) {
            oldData.meta.data = metadata["meta"];
        }

        auto feeUtxos = rpcListUnspent(nodeIP, nodePort, sender);
        if (feeUtxos.empty()) {
            throw std::runtime_error("No fee UTXO available");
        }
        std::string feeTxid = feeUtxos[0].txid;
        uint32_t feeVout = feeUtxos[0].vout;
        uint64_t coinValue = feeUtxos[0].amount;

        uint64_t fee = WALLET_MIN_BASE_FEE;
        uint64_t minRequired = fee + ((utxoAmount - quantityToSend) > 0 ? 1 : 0);
        if (coinValue < minRequired) {
            throw std::runtime_error("Insufficient fee funds: have=" + 
                std::to_string(coinValue) + ", need=" + std::to_string(minRequired));
        }

        Transaction tx(false);
        tx.set_sender(sender);
        tx.vin.emplace_back(oldTxid, oldVout);
        tx.vin.emplace_back(feeTxid, feeVout);

        ExtendedTokenData newData = oldData;
        newData.amount = quantityToSend;
        std::string newTokenScriptHex = createExtendedTokenScriptPubKeyHex(newData, newOwnerAddress);
        tx.vout.emplace_back(0, newTokenScriptHex);
        tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(newOwnerAddress));

        uint64_t leftoverAmt = utxoAmount - quantityToSend;
        bool isFungible = (oldData.type == TokenType::FT || oldData.type == TokenType::SFT || oldData.type == TokenType::NCFT);
        if (leftoverAmt > 0 && isFungible) {
            ExtendedTokenData changeData = oldData;
            changeData.amount = leftoverAmt;
            std::string changeTokenScriptHex = createExtendedTokenScriptPubKeyHex(changeData, sender);
            tx.vout.emplace_back(0, changeTokenScriptHex);
            tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(sender));
        }

        uint64_t leftoverCoin = coinValue - fee - ((leftoverAmt > 0 && isFungible) ? 1 : 0);
        std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
        if (leftoverCoin > 0) {
            tx.vout.emplace_back(leftoverCoin, createP2PKHScriptHexFromAddress(sender));
            feeBearingVout = tx.vout.size() - 1;
        }

        fee = applyWalletPolicyFee(
            tx, fee, feeBearingVout, "transferExtendedToken(RPC)");

        if (!signTransaction(tx, nodeIP, nodePort)) {
            throw std::runtime_error("Failed to sign transaction");
        }

        std::string txHex = bytesToHex(tx.serializeBinary());
        nlohmann::json broadcastParams = {{"txHex", txHex}};
        Logger::log("[transferExtendedToken] Broadcasting transaction with params: " + broadcastParams.dump());
        auto broadcastResponse = rpcCall("sendrawtransaction", broadcastParams, nodeIP, nodePort);
        Logger::log("[transferExtendedToken] Broadcast response: " + broadcastResponse.dump());

        if (broadcastResponse.contains("error")) {
            throw std::runtime_error("Failed to broadcast transaction: " + 
                broadcastResponse["error"]["message"].get<std::string>());
        }

        std::string txid = broadcastResponse["result"]["txid"].get<std::string>();
        Logger::log("[transferExtendedToken] Transfer successful: txid=" + txid);
        return txid;
        throw std::runtime_error("Standalone mode not updated for metadata transmission");
    }
}
//==============================================================
//              TOKEN-BURN-01 — Burn current token holding
//==============================================================
std::string Wallet::burnToken(const std::string& tokenID,
                              const std::string& senderAddress) {
    if (tokenID.empty())
        throw std::invalid_argument("[burnToken] Token ID cannot be empty");
    if (senderAddress.empty())
        throw std::invalid_argument("[burnToken] Sender address cannot be empty");
    if (!ownsAddress(senderAddress))
        throw std::runtime_error("[burnToken] Sender address not found in wallet");

    // transferExtendedToken() signs with the wallet's current address.  Do not
    // silently mutate persisted wallet selection merely to perform a burn.
    if (getCurrentAddress() != senderAddress)
        throw std::runtime_error(
            "[burnToken] Sender must be the wallet's current address");

    auto [txid, controllingVout, tokenVout] =
        findTokenUTXO(tokenID, senderAddress);
    (void)tokenVout;
    if (txid.empty())
        throw std::runtime_error(
            "[burnToken] No current token UTXO found for this sender");

    uint64_t fullAmount = 0;
    std::string owner;

    if (isLocalChain) {
        if (!blockchainPtr)
            throw std::runtime_error("[burnToken] Local blockchain unavailable");
        LevelDBStorage* storage = blockchainPtr->getStorage();
        if (!storage)
            throw std::runtime_error("[burnToken] Storage unavailable");

        std::string raw;
        const std::string key =
            "tokenUTXO:" + txid + ":" + std::to_string(controllingVout);
        if (!storage->getWithDataChecksum(key, raw))
            throw std::runtime_error(
                "[burnToken] Current token-control record unavailable");

        const auto j = nlohmann::json::parse(raw);
        fullAmount = j.at("amount").is_string()
            ? std::stoull(j.at("amount").get<std::string>())
            : j.at("amount").get<uint64_t>();
        owner = j.value("owner", "");
    } else {
        if (nodeIP.empty() || nodePort == 0)
            throw std::runtime_error("[burnToken] RPC node is not configured");

        const auto response = rpcCall(
            "gettokenutxo",
            nlohmann::json{{"tokenID", tokenID}, {"address", senderAddress}},
            nodeIP, nodePort);
        if (response.contains("error") || !response.contains("result") ||
            !response["result"].is_array())
            throw std::runtime_error(
                "[burnToken] Failed to fetch token holding via RPC");

        bool matched = false;
        for (const auto& row : response["result"]) {
            if (row.value("txid", "") != txid ||
                row.value("controllingVout", UINT32_MAX) != controllingVout)
                continue;
            fullAmount = row.at("amount").is_string()
                ? std::stoull(row.at("amount").get<std::string>())
                : row.at("amount").get<uint64_t>();
            owner = row.value("owner", "");
            matched = true;
            break;
        }
        if (!matched)
            throw std::runtime_error(
                "[burnToken] Selected token holding disappeared");
    }

    if (owner != senderAddress)
        throw std::runtime_error("[burnToken] Token holding is not owned by sender");
    if (fullAmount == 0)
        throw std::runtime_error("[burnToken] Refusing zero-amount burn");

    Logger::log(
        "[TOKEN-BURN-01] Retiring tokenID=" + tokenID +
        " rawAmount=" + std::to_string(fullAmount) +
        " from=" + senderAddress +
        " sink=" + std::string(tru_token_burn_v1::BURN_ADDRESS));

    return transferExtendedToken(
        txid, controllingVout, fullAmount,
        tru_token_burn_v1::BURN_ADDRESS);
}

//==============================================================
//			Send TOKEN
//==============================================================
std::string Wallet::sendToken(const std::string& tokenID, uint64_t amount,
                              const std::string& recipient, const std::string& senderAddress) {
    Logger::log("[sendToken] Initiating token transfer: tokenID=" + tokenID + ", amount=" +
                std::to_string(amount) + ", recipient=" + recipient + ", sender=" + senderAddress);

    // Validate inputs
    if (tokenID.empty()) {
        Logger::log("[sendToken] Error: Token ID is empty");
        throw std::invalid_argument("[sendToken] Token ID cannot be empty");
    }
    if (amount == 0) {
        Logger::log("[sendToken] Error: Amount is zero");
        throw std::invalid_argument("[sendToken] Amount must be greater than zero");
    }
    if (recipient.empty()) {
        Logger::log("[sendToken] Error: Recipient address is empty");
        throw std::invalid_argument("[sendToken] Recipient address cannot be empty");
    }
    if (senderAddress.empty()) {
        Logger::log("[sendToken] Error: Sender address is empty");
        throw std::invalid_argument("[sendToken] Sender address cannot be empty");
    }

    // In standalone mode, ensure nodeIP and nodePort are configured
    if (!isLocalChain && (nodeIP.empty() || nodePort == 0)) {
        Logger::log("[sendToken] Error: Node IP or port not configured in standalone mode");
        throw std::runtime_error("[sendToken] Node IP or port not configured");
    }

    // Verify sender address is in wallet
    if (!ownsAddress(senderAddress)) {
        Logger::log("[sendToken] Error: Sender address " + senderAddress + " not found in wallet");
        throw std::runtime_error("[sendToken] Sender address not found in wallet");
    }

    std::string fullTokenID = tokenID; // Adjust if truncation is needed
    Logger::log("[sendToken] Using tokenID=" + fullTokenID);

    // Find the controlling UTXO
    auto [txid, controllingVout, tokenVout] = findTokenUTXO(fullTokenID, senderAddress);
    if (txid.empty()) {
        Logger::log("[sendToken] Error: No UTXO found for tokenID=" + fullTokenID + " and sender=" + senderAddress);
        throw std::runtime_error("[sendToken] No UTXO found for tokenID=" + fullTokenID + " with sender=" + senderAddress);
    }
    Logger::log("[sendToken] Found UTXO: txid=" + txid + ", controllingVout=" +
                std::to_string(controllingVout) + ", tokenVout=" + std::to_string(tokenVout));

    // Fetch token UTXO data - FIX: Use controllingVout instead of tokenVout
    nlohmann::json j;
    uint64_t utxoAmount;
    std::string utxoOwner;
    std::string tokenTypeStr;
    if (isLocalChain) {
        LevelDBStorage* storage = blockchainPtr->getStorage();
        if (!storage) {
            Logger::log("[sendToken] Error: Storage not available in local mode");
            throw std::runtime_error("[sendToken] Storage not available");
        }
        // FIX: Look up token data at the controlling vout, not the token vout
        std::string tokenUtxoKey = "tokenUTXO:" + txid + ":" + std::to_string(controllingVout);
        if (controllingVout == 0) {
            Logger::log("[sendToken] WARNING: Controlling vout is 0, this might be an OP_RETURN");
            // The controlling output should be vout 1 for tokens
            controllingVout = 1;
            tokenUtxoKey = "tokenUTXO:" + txid + ":1";
        }
        std::string tokenUtxoValue;
        if (!storage->getWithDataChecksum(tokenUtxoKey, tokenUtxoValue)) {
            Logger::log("[sendToken] Error: Token UTXO data not found for key=" + tokenUtxoKey);
            throw std::runtime_error("[sendToken] Token UTXO data not found for " + tokenUtxoKey);
        }
        try {
            j = nlohmann::json::parse(tokenUtxoValue);
            utxoAmount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
            utxoOwner = j["owner"].get<std::string>();
            tokenTypeStr = j["type"].get<std::string>();
        } catch (const std::exception& e) {
            Logger::log("[sendToken] Error: Failed to parse token UTXO data: " + std::string(e.what()));
            throw std::runtime_error("[sendToken] Invalid token UTXO data: " + std::string(e.what()));
        }
    } else {
        // Standalone mode: Use RPC
        nlohmann::json params = {{"tokenID", fullTokenID}, {"address", senderAddress}};
        auto response = rpcCall("gettokenutxo", params, nodeIP, nodePort);
        if (response.contains("error") || !response.contains("result") ||
            !response["result"].is_array() || response["result"].empty()) {
            Logger::log("[sendToken] Error: RPC 'gettokenutxo' failed or returned no results for tokenID=" +
                        fullTokenID + ", address=" + senderAddress);
            throw std::runtime_error("[sendToken] Failed to fetch token UTXO via RPC");
        }
        j = response["result"][0];
        try {
            utxoAmount = j["amount"].is_string() ? std::stoull(j["amount"].get<std::string>()) : j["amount"].get<uint64_t>();
            utxoOwner = j["owner"].get<std::string>();
            tokenTypeStr = j["type"].get<std::string>();
            tokenVout = j["vout"].get<uint32_t>(); // Update tokenVout from RPC
        } catch (const std::exception& e) {
            Logger::log("[sendToken] Error: Failed to parse RPC response: " + std::string(e.what()));
            throw std::runtime_error("[sendToken] Invalid RPC response data: " + std::string(e.what()));
        }
    }

    // Verify ownership
    if (utxoOwner != senderAddress) {
        Logger::log("[sendToken] Error: UTXO owned by " + utxoOwner + ", not sender " + senderAddress);
        throw std::runtime_error("[sendToken] UTXO not owned by sender: owned by " + utxoOwner);
    }

    // Fetch decimals from metadata
    int decimals = 0;
    if (isLocalChain) {
        LevelDBStorage* storage = blockchainPtr->getStorage();
        std::string metadataKey = "tokenMetadata:" + txid;
        std::string metadataValue;
        if (storage->getWithDataChecksum(metadataKey, metadataValue)) {
            try {
                nlohmann::json metadataJson = nlohmann::json::parse(metadataValue);
                if (metadataJson.contains("meta") && metadataJson["meta"].contains("decimals")) {
                    decimals = std::stoi(metadataJson["meta"]["decimals"].get<std::string>());
                    Logger::log("[sendToken] Decimals from metadata: " + std::to_string(decimals));
                }
            } catch (const std::exception& e) {
                Logger::log("[sendToken] Warning: Failed to parse metadata: " + std::string(e.what()) + ", assuming decimals=0");
            }
        } else {
            Logger::log("[sendToken] Warning: Metadata not found for txid=" + txid + ", assuming decimals=0");
        }
    } else {
        nlohmann::json params = {{"txid", txid}};
        auto metadataResponse = rpcCall("gettokenmetadata", params, nodeIP, nodePort);
        if (metadataResponse.contains("result") && metadataResponse["result"].is_object()) {
            auto metadata = metadataResponse["result"];
            if (metadata.contains("meta") && metadata["meta"].contains("decimals")) {
                try {
                    decimals = std::stoi(metadata["meta"]["decimals"].get<std::string>());
                    Logger::log("[sendToken] Decimals from RPC metadata: " + std::to_string(decimals));
                } catch (const std::exception& e) {
                    Logger::log("[sendToken] Warning: Failed to parse decimals: " + std::string(e.what()) + ", assuming 0");
                }
            }
        } else {
            Logger::log("[sendToken] Warning: Metadata not found via RPC for txid=" + txid + ", assuming decimals=0");
        }
    }

    // Scale amount based on decimals
    uint64_t scale = 1;
    for (int i = 0; i < decimals; ++i) scale *= 10;
    if (amount > (std::numeric_limits<uint64_t>::max() / scale)) {
        Logger::log("[sendToken] Error: Amount scaling exceeds uint64_t limit");
        throw std::runtime_error("[sendToken] Amount too large for scaling");
    }
    uint64_t amountInSmallestUnits = amount * scale;
    Logger::log("[sendToken] Scaled amount: " + std::to_string(amount) + " -> " + std::to_string(amountInSmallestUnits) +
                " (decimals=" + std::to_string(decimals) + ")");

    if (utxoAmount < amountInSmallestUnits) {
        Logger::log("[sendToken] Error: Insufficient token amount, have=" + std::to_string(utxoAmount) +
                    ", need=" + std::to_string(amountInSmallestUnits));
        throw std::runtime_error("[sendToken] Insufficient token amount: have " + std::to_string(utxoAmount) +
                                 ", need " + std::to_string(amountInSmallestUnits));
    }

    // SEC-14R.3:
    // senderAddress is already the wallet's selected sender supplied by the
    // caller and ownership-validated above. Do NOT invoke the persisted
    // current-address mutation API here; it is intentionally
    // refused in encrypted mode by SEC-14E.3.3B.
    //
    // transferExtendedToken() consumes the wallet's current address for
    // signing; the CLI/RPC send path supplies the same current sender.
    // Therefore changing/persisting currentIndex here is redundant.
    Logger::log("[SEC-14R.3] sendToken using authenticated current sender without persisted address mutation: " +
                senderAddress);
    std::string txidResult = transferExtendedToken(txid, controllingVout, amountInSmallestUnits, recipient);
    Logger::log("[sendToken] Transfer completed, txid=" + txidResult);

    // In local chain mode, add to mempool
    if (isLocalChain) {
        Transaction tx;
        if (!blockchainPtr->findTransaction(txidResult, tx)) {
            Logger::log("[sendToken] Warning: Transaction " + txidResult + " not found immediately after creation");
        } else {
            if (!blockchainPtr->addTransaction(tx)) {
                Logger::log(
                    "[sendToken] Queue admission rejected for transaction " +
                    txidResult);
                throw std::runtime_error(
                    "[sendToken] Transaction queue admission rejected");
            }
            blockchainPtr->broadcastTransaction(tx);
            Logger::log("[sendToken] Queued transaction " + txidResult + " for mempool validation");
        }
    }

    return txidResult;
}
//===================================================================================
//			RPC BROADCAS TX
//===================================================================================
bool Wallet::rpcBroadcastTx(const std::string &rawHex,
                            const std::string &nodeIP,
                            int nodePort)
{
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    nlohmann::json jreq;
    
    // Set the correct method name
    jreq["method"] = "sendrawtransaction";
    
    // Set params as an object with "txHex", as expected by handleSendTransaction
    jreq["params"] = {{"txHex", rawHex}};
    
    // Add JSON-RPC version and optional id
    jreq["jsonrpc"] = "2.0";
    jreq["id"] = 1; // Arbitrary ID for matching request/response
    
    // Log the request for debugging
    std::cout << "[rpcBroadcastTx] Sending RPC request: " << jreq.dump() << std::endl;
    
    // Send the POST request
    auto resp = cli.Post("/rpc", jreq.dump(), "application/json");
    if (!resp || resp->status != 200) {
        std::cerr << "[rpcBroadcastTx] RPC fail or non-200 status: " 
                  << (resp ? std::to_string(resp->status) : "no response") << "\n";
        return false;
    }
    
    // Log the response for debugging
    std::cout << "[rpcBroadcastTx] Received response: " << resp->body << std::endl;
    
    // Parse the response
    try {
        auto jr = nlohmann::json::parse(resp->body);
        
        // Check for JSON-RPC error
        if (jr.contains("error") && !jr["error"].is_null()) {
            std::cerr << "[rpcBroadcastTx] Node error => " << jr["error"].dump() << "\n";
            return false;
        }
        
        // Verify successful result with txid
        if (jr.contains("result") && jr["result"].contains("txid")) {
            std::cout << "[rpcBroadcastTx] Transaction broadcasted successfully: " 
                      << jr["result"]["txid"] << std::endl;
            return true;
        } else {
            std::cerr << "[rpcBroadcastTx] Unexpected response format.\n";
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[rpcBroadcastTx] Failed to parse response: " << e.what() << "\n";
        return false;
    }
}


// ------------------------------
// RPC-specific methods
// ------------------------------
std::vector<UTXO> Wallet::rpcListUnspent(const std::string &nodeIP, int nodePort, const std::string &address) const {
    std::vector<UTXO> ret;
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(10, 0);

    // Log function entry with input parameters
    Logger::log("Entering rpcListUnspent with nodeIP=" + nodeIP + ", nodePort=" + std::to_string(nodePort) + ", address=" + address);

    // Prepare the RPC request
    nlohmann::json jreq;
    jreq["method"] = "listunspent";
    jreq["params"] = {{"address", address}};
    std::string requestBody = jreq.dump();

    Logger::log("Prepared RPC request: " + requestBody);

    // Make the RPC call
    Logger::log("Sending POST request to /rpc at " + nodeIP + ":" + std::to_string(nodePort));
    auto resp = cli.Post("/rpc", requestBody, "application/json");
    if (!resp) {
        Logger::log("Failed to get response from RPC server");
        throw std::runtime_error("Failed to connect to RPC server");
    }

    Logger::log("Received response with HTTP status: " + std::to_string(resp->status) + ", body length: " + std::to_string(resp->body.size()));

    if (resp->status != 200) {
        Logger::log("HTTP error - Status: " + std::to_string(resp->status) + ", Body: " + resp->body);
        throw std::runtime_error("HTTP error: " + std::to_string(resp->status));
    }

    // Parse the response
    nlohmann::json jr;
    try {
        Logger::log("Parsing response body: " + resp->body.substr(0, 100) + (resp->body.size() > 100 ? "..." : ""));
        jr = nlohmann::json::parse(resp->body);
        Logger::log("Successfully parsed JSON response");
    } catch (const std::exception& e) {
        Logger::log("JSON parsing failed: " + std::string(e.what()) + ", raw body: " + resp->body);
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }

    // Check for RPC error
    if (jr.contains("error") && !jr["error"].is_null()) {
        std::string errorMsg = jr["error"].dump();
        Logger::log("RPC returned an error: " + errorMsg);
        throw std::runtime_error("RPC error: " + errorMsg);
    }

    // Validate result
    if (!jr.contains("result") || !jr["result"].is_array()) {
        Logger::log("Invalid RPC response: 'result' missing or not an array - Full response: " + jr.dump(2));
        throw std::runtime_error("Invalid response format: 'result' missing or not an array");
    }

    auto arr = jr["result"];
    Logger::log("Found " + std::to_string(arr.size()) + " UTXOs in response");

    // Process each UTXO
    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& u = arr[i];
        Logger::log("Processing UTXO #" + std::to_string(i) + ": " + u.dump(2));
        try {
            UTXO utxo;
            if (!u.contains("txid") || !u["txid"].is_string() ||
                !u.contains("vout") || !u["vout"].is_number_unsigned() ||
                (!u.contains("amount_atoms") && !u.contains("amount")) ||
                !u.contains("scriptPubKey") || !u["scriptPubKey"].is_string()) {
                Logger::log("Skipping UTXO #" + std::to_string(i) + " due to missing or invalid fields");
                continue;
            }

            utxo.txid = u["txid"].get<std::string>();
            utxo.vout = u["vout"].get<uint32_t>();
            if (u.contains("amount_atoms") && u["amount_atoms"].is_number_unsigned()) {
                utxo.amount = u["amount_atoms"].get<uint64_t>();
            } else {
                std::string amountText;
                if (u["amount"].is_string()) amountText = u["amount"].get<std::string>();
                else if (u["amount"].is_number()) amountText = u["amount"].dump();
                else {
                    Logger::log("Skipping UTXO #" + std::to_string(i) + " due to invalid amount type");
                    continue;
                }
                std::string amountReason;
                if (!tru_amount::parse(amountText, utxo.amount, amountReason)) {
                    Logger::log("Skipping UTXO #" + std::to_string(i) + " due to invalid TRU amount: " + amountReason);
                    continue;
                }
            }
            utxo.scriptPubKey = u["scriptPubKey"].get<std::string>();

            if (utxo.scriptPubKey.empty() || !isValidHex(utxo.scriptPubKey)) {
                Logger::log("Skipping UTXO #" + std::to_string(i) + " due to invalid scriptPubKey: " + utxo.scriptPubKey);
                continue;
            }

            Logger::log("Valid UTXO #" + std::to_string(i) + " - txid=" + utxo.txid + ", vout=" + std::to_string(utxo.vout) +
                        ", amount=" + std::to_string(utxo.amount) + " TRU atoms");
            ret.push_back(utxo);
        } catch (const std::exception& e) {
            Logger::log("Error processing UTXO #" + std::to_string(i) + ": " + std::string(e.what()));
            continue;
        }
    }

    Logger::log("Exiting rpcListUnspent with " + std::to_string(ret.size()) + " UTXOs for address " + address);
    return ret;
}
//===========================================================================
//			FIND ONE UTXO SPENDABLE
//===========================================================================
std::pair<std::string, unsigned int> Wallet::findOneSpendableUtxo(const std::string& address, const Mempool* mempool) const {
    // Validate blockchain pointer
    if (!blockchainPtr) {
        Logger::log("[findOneSpendableUtxo] ERROR: blockchainPtr is null");
        return {"", 0};
    }

    // Retrieve storage
    LevelDBStorage* storage = blockchainPtr->getStorage();
    if (!storage) {
        Logger::log("[findOneSpendableUtxo] ERROR: storage is null");
        return {"", 0};
    }

    // Get current block height
    int currentBlockHeight = blockchainPtr->getBestTipHeight();

    // Store UTXOs for the address
    std::vector<std::string> utxos;
    Logger::log("[findOneSpendableUtxo] Searching for spendable UTXO for address: " + address);

    // Fetch UTXOs
    if (!getUTXOsForAddress(storage, address, utxos, currentBlockHeight)) {
        Logger::log("[findOneSpendableUtxo] Failed to retrieve UTXOs for address: " + address);
        return {"", 0};
    }

    if (utxos.empty()) {
        Logger::log("[findOneSpendableUtxo] No UTXOs found for address: " + address);
        return {"", 0};
    }

    // Search for a spendable UTXO
    for (const auto& utxoStr : utxos) {
        std::vector<std::string> parts = splitString(utxoStr, ':');
        if (parts.size() != 3) {
            Logger::log("[findOneSpendableUtxo] Malformed UTXO string: " + utxoStr);
            continue;
        }

        std::string txid = parts[0];
        uint32_t vout;
        uint64_t amount;
        try {
            vout = std::stoul(parts[1]);
            amount = std::stoull(parts[2]);
        } catch (const std::exception& e) {
            Logger::log("[findOneSpendableUtxo] Error parsing UTXO " + utxoStr + ": " + e.what());
            continue;
        }

        std::string fullKey = "utxo:" + txid + ":" + std::to_string(vout);
        Logger::log("[findOneSpendableUtxo] Checking UTXO key: " + fullKey);

        std::string raw;
        if (!storage->getWithDataChecksum(fullKey, raw)) {
            Logger::log("[findOneSpendableUtxo] UTXO not found in storage: " + fullKey);
            continue;
        }
// ------------------------------------------------------------
// FIX: Skip immature coinbase UTXOs.
// Must match the mempool/consensus maturity rule exactly.
// The transaction would be included in the next block: tip + 1.
// ------------------------------------------------------------
        {
            uint32_t createdAtHeight = 0;
            bool isCoinbase = false;
            bool haveHeight = false;

            std::vector<std::string> rawParts = splitString(raw, '|');

            for (const auto& field : rawParts) {
                if (field.rfind("height=", 0) == 0) {
                    try {
                        createdAtHeight =
                            static_cast<uint32_t>(std::stoul(field.substr(7)));
                        haveHeight = true;
                    } catch (...) {
                        Logger::log(
                            "[findOneSpendableUtxo] Invalid UTXO height in: " + raw);
                    }
                }
                else if (field == "cb=1") {
                    isCoinbase = true;
                }
            }

            if (isCoinbase) {
                if (!haveHeight || currentBlockHeight < 0) {
                    Logger::log(
                        "[findOneSpendableUtxo] Coinbase maturity data unavailable, "
                        "skipping: " + fullKey);
                    continue;
                }

                uint32_t candidateHeight =
                    static_cast<uint32_t>(currentBlockHeight + 1);

                if (candidateHeight <= createdAtHeight ||
                    (candidateHeight - createdAtHeight) <
                        static_cast<uint32_t>(COINBASE_MATURITY)) {

                    uint32_t maturesAt =
                        createdAtHeight +
                        static_cast<uint32_t>(COINBASE_MATURITY);

                    Logger::log(
                        "[findOneSpendableUtxo] Skipping immature coinbase: " +
                         fullKey +
                        " created=" + std::to_string(createdAtHeight) +
                        " tip=" + std::to_string(currentBlockHeight) +
                        " spendableAt=" + std::to_string(maturesAt));

                    continue;
                }
            }
        }

        // Check if spent in mempool
        if (mempool && mempool->isUTXOSpentInMempool(txid, vout)) {
            Logger::log("[findOneSpendableUtxo] UTXO " + txid + ":" + std::to_string(vout) + " is spent in mempool");
            continue;
        }
        if (isSwapPreparedFundingInputReserved(storage, txid, vout)) {
            Logger::log(
                "[findOneSpendableUtxo] Prepared-funding reserved UTXO skipped: " +
                txid + ":" + std::to_string(vout));
            continue;
        }

        // tokenUTXO is the authoritative direct
        // association for a token-controlling output.
        const std::string controllingKey = "tokenUTXO:" + txid + ":" + std::to_string(vout);
        if (storage->exists(controllingKey)) {
            Logger::log("[findOneSpendableUtxo] Token-controlling UTXO skipped: " +
                        txid + ":" + std::to_string(vout));
            continue;
        }

        Logger::log("[findOneSpendableUtxo] Found spendable UTXO: " + fullKey + " with amount: " + std::to_string(amount));
        return {txid, vout};
    }

    Logger::log("[findOneSpendableUtxo] No spendable UTXOs found for address: " + address);
    return {"", 0};
}
//=======================================================================================
//			Find ONE UTxO COIN
//=======================================================================================
std::pair<std::string, uint32_t> Wallet::findOneCoinUtxo(const std::string &address) const {
    Logger::log("[findOneCoinUtxo] Searching for coin UTXO for " + address);

    // Validate storage
    auto* storage = blockchainPtr->getStorage();
    if (!storage) {
        throw std::runtime_error("[findOneCoinUtxo] No storage available");
    }

    // Collect spent UTXOs from mempool
    std::unordered_set<std::string> spent;
    if (auto* mp = blockchainPtr->mempool.get()) {
        for (const auto &tx : mp->getAllTransactions()) {
            for (const auto &vin : tx.vin) {
                spent.emplace(vin.txid + ":" + std::to_string(vin.vout));
            }
        }
    }

    std::string bestKey;
    uint64_t bestAmt = 0;

    // Iterate over UTXOs for the address
    std::string prefix = "address:" + address + ":utxo:";
    storage->iteratePrefix(prefix, [&](const std::string &keySansPrefix, const std::string &value) {
        std::string utxoKey = keySansPrefix;
        if (spent.count(utxoKey)) return;

        const auto reservationParts = splitString(utxoKey, ':');
        if (reservationParts.size() == 2U &&
            reservationParts[0].size() == 64U) {
            try {
                const std::uint32_t reservationVout =
                    static_cast<std::uint32_t>(
                        std::stoul(reservationParts[1]));
                if (isSwapPreparedFundingInputReserved(
                        storage, reservationParts[0], reservationVout)) {
                    Logger::log(
                        "[findOneCoinUtxo] Prepared-funding reserved UTXO skipped: " +
                        utxoKey);
                    return;
                }
            } catch (...) {
                return;
            }
        }

        std::string utxoDataKey = "utxo:" + utxoKey;
        std::string raw;
        // request decoded checksummed payload.
        if (!storage->getWithDataChecksum(utxoDataKey, raw)) {
            Logger::log("[findOneCoinUtxo] UTXO data not found for key: " + utxoDataKey);
            return;
        }

        auto parts = splitString(raw, '|');
        if (parts.size() < 3) {
            Logger::log("[findOneCoinUtxo] Malformed UTXO data for key: " + utxoDataKey);
            return;
        }

        uint64_t amt;
        try {
            amt = std::stoull(parts[1]);
        } catch (...) {
            Logger::log("[findOneCoinUtxo] Invalid amount in UTXO data for key: " + utxoDataKey);
            return;
        }
        if (amt == 0) return;

        // token transfers use this helper for their
        // TRU fee input, so it must enforce coinbase maturity too.
        bool isCoinbase = false;
        uint32_t createdAtHeight = 0;
        bool haveHeight = false;
        for (const auto& field : parts) {
            if (field.rfind("height=", 0) == 0) {
                try {
                    createdAtHeight = static_cast<uint32_t>(std::stoul(field.substr(7)));
                    haveHeight = true;
                } catch (...) {
                    Logger::log("[findOneCoinUtxo] Invalid height in " + utxoDataKey);
                    return;
                }
            } else if (field == "cb=1") {
                isCoinbase = true;
            }
        }

        if (isCoinbase) {
            const int tipHeight = blockchainPtr->getBestTipHeight();
            if (!haveHeight || tipHeight < 0) {
                Logger::log("[findOneCoinUtxo] Coinbase maturity data unavailable: " + utxoKey);
                return;
            }
            const uint32_t candidateHeight = static_cast<uint32_t>(tipHeight + 1);
            if (candidateHeight <= createdAtHeight ||
                (candidateHeight - createdAtHeight) < static_cast<uint32_t>(COINBASE_MATURITY)) {
                Logger::log(
                    "[findOneCoinUtxo] Immature coinbase skipped: " + utxoKey +
                    " created=" + std::to_string(createdAtHeight) +
                    " tip=" + std::to_string(tipHeight) +
                    " spendableAt=" + std::to_string(
                        createdAtHeight + static_cast<uint32_t>(COINBASE_MATURITY)));
                return;
            }
        }

        const std::string &spk = parts[2];

        // Patch16D: this helper selects a normal TRU fee input, not a
        // smart-contract output. Require the exact canonical P2PKH hex form
        // and exact address match. Do NOT pass ordinary P2PKH through
        // isAllowedSmartContractScript(), whose allow-list intentionally
        // recognizes smart-contract templates rather than standard P2PKH.
        const bool isCanonicalP2PKH =
            spk.size() == 50 &&
            spk.rfind("76a914", 0) == 0 &&
            spk.compare(spk.size() - 4, 4, "88ac") == 0 &&
            std::all_of(
                spk.begin(), spk.end(),
                [](unsigned char c) { return std::isxdigit(c) != 0; });
        if (!isCanonicalP2PKH ||
            !doesScriptPayToAddress(spk, address)) {
            Logger::log(
                "[findOneCoinUtxo][Patch16D] Non-P2PKH/address-mismatch fee UTXO skipped: " +
                utxoDataKey);
            return;
        }

        // Validate UTXO key format
        auto uv = splitString(utxoKey, ':');
        if (uv.size() != 2) {
            Logger::log("[findOneCoinUtxo] Invalid utxoKey format: " + utxoKey);
            return;
        }
        if (uv[0].size() != 64) {
            Logger::log("[findOneCoinUtxo] Invalid txid length in utxoKey: " + utxoKey + ", length=" + std::to_string(uv[0].size()));
            return;
        }

        // use the direct token UTXO association.
        const std::string controllingKey = "tokenUTXO:" + uv[0] + ":" + uv[1];
        if (storage->exists(controllingKey)) {
            Logger::log("[findOneCoinUtxo] Token-controlling UTXO skipped: " + uv[0] + ":" + uv[1]);
            return;
        }

        // Update best UTXO if amount is higher
        if (amt > bestAmt) {
            bestAmt = amt;
            bestKey = utxoKey;
        }
    });

    if (bestKey.empty()) {
        throw std::runtime_error("[findOneCoinUtxo] No coin UTXO found for address => " + address);
    }

    auto uv = splitString(bestKey, ':');
    if (uv.size() != 2 || uv[0].size() != 64) {
        Logger::log("[findOneCoinUtxo] Invalid bestKey format or txid length: " + bestKey);
        throw std::runtime_error("[findOneCoinUtxo] Invalid UTXO key format or txid length");
    }

    uint32_t vout;
    try {
        vout = std::stoul(uv[1]);
    } catch (...) {
        Logger::log("[findOneCoinUtxo] Invalid vout in bestKey: " + bestKey);
        throw std::runtime_error("[findOneCoinUtxo] Invalid vout format");
    }

    Logger::log("[findOneCoinUtxo] Found coin UTXO: txid=" + uv[0] + ", vout=" + std::to_string(vout));
    return {uv[0], vout};
}
//====================================================================================
//
//====================================================================================
void Wallet::addLocalUTXO(const std::string& txid, uint32_t vout, uint64_t amount, const std::string& script) {
    // key = txid:vout
    std::string key = txid + ":" + std::to_string(vout);
    localUtxos[key] = LocalUtxo{txid, vout, amount, script};
}

//====================================================================================
//
//====================================================================================
void Wallet::removeLocalUTXO(const std::string& txid, uint32_t vout) {
    std::string key = txid + ":" + std::to_string(vout);
    localUtxos.erase(key);
}

//====================================================================================
//
//====================================================================================
bool Wallet::ownsAddress(const std::string& addr) const {
    std::lock_guard<std::mutex> lock(addressesMutex);
    return std::find(addresses.begin(), addresses.end(), addr)
           != addresses.end();
}


// ------------------------------
// updateLocalUTXOSetFromChain
// ------------------------------
void Wallet::updateLocalUTXOSetFromChain() {
    if (!blockchainPtr) {
        Logger::log("[updateLocalUTXOSetFromChain] No blockchain pointer available, skipping update");
        return;
    }

    UTXOSet& utxoSet = blockchainPtr->utxoSet;
    std::unordered_map<std::string, LocalUtxo> updated;

    // Clear token UTXOs too
    localTokenUtxos.clear();

    Logger::log("[updateLocalUTXOSetFromChain] Starting UTXO set synchronization");
    std::vector<UTXO> allUTXOs = utxoSet.getAllUTXOs();

    for (const UTXO& u : allUTXOs) {
        Logger::log("[updateLocalUTXOSetFromChain] Processing UTXO: " + u.txid + " (length=" + std::to_string(u.txid.length()) + "):" + std::to_string(u.vout));
        Logger::log("[updateLocalUTXOSetFromChain] ScriptPubKey: " + u.scriptPubKey);

        // First check if this is a token UTXO by examining the scriptPubKey
        if (startsWithOpReturnHex(u.scriptPubKey)) {
            Logger::log("[updateLocalUTXOSetFromChain] Found OP_RETURN script, checking for token data");
            
            ExtendedTokenData tokenData;
            std::string tokenOwner;
            
            // Try to parse as extended token
            if (parseExtendedTokenScript(u.scriptPubKey, u.txid, tokenData, tokenOwner, blockchainPtr)) {
                Logger::log("[updateLocalUTXOSetFromChain] Successfully parsed extended token: " + tokenData.tokenID);
                
                // Check if we own this token
                if (ownsAddress(tokenOwner)) {
                    // Create ExtendedTokenData with fetched metadata
                    ExtendedTokenData extTokenData = tokenData;
                    
                    // Try to fetch full metadata if available
                    std::string metadataKey = "tokenMetadata:" + u.txid;
                    try {
                        ExtendedTokenData fetchedData = blockchainPtr->fetchTokenMetadata(metadataKey);
                        extTokenData.meta = fetchedData.meta;
                    } catch (const std::exception& e) {
                        Logger::log("[updateLocalUTXOSetFromChain] Warning: Could not fetch metadata for " + u.txid);
                    }
                    
                    // Add to token UTXOs
                    std::string tokenUtxoKey = u.txid + ":" + std::to_string(u.vout);
                    localTokenUtxos[tokenUtxoKey] = std::make_tuple(
                        u.txid, 
                        u.vout, 
                        tokenData.amount,  // Use the amount from the parsed token data
                        extTokenData, 
                        tokenOwner
                    );
                    
                    Logger::log("[updateLocalUTXOSetFromChain] Added token UTXO: " + 
                               tokenData.tokenID + " amount: " + std::to_string(tokenData.amount) + 
                               " at " + tokenUtxoKey + " for owner: " + tokenOwner);
                    
                    // Also add as regular UTXO for the blockchain amount (if any)
                    if (u.amount > 0) {
                        LocalUtxo lu = {u.txid, u.vout, u.amount, u.scriptPubKey};
                        updated.emplace(tokenUtxoKey, std::move(lu));
                    }
                } else {
                    Logger::log("[updateLocalUTXOSetFromChain] Token owner " + tokenOwner + " is not ours");
                }
            } else {
                // Not a token, might be TRUScript or other OP_RETURN data
                Logger::log("[updateLocalUTXOSetFromChain] OP_RETURN is not an extended token");
            }
        } else {
            // Regular UTXO - extract address normally
            std::string addr = extractAddressFromScriptPubKey(u.scriptPubKey, u.txid, u.vout, blockchainPtr);
            if (addr.empty()) {
                Logger::log("[updateLocalUTXOSetFromChain] Failed to extract address for UTXO " + u.txid + ":" + std::to_string(u.vout));
                continue;
            }

            if (ownsAddress(addr)) {
                // Add regular UTXO
                std::string key = u.txid + ":" + std::to_string(u.vout);
                LocalUtxo lu = {u.txid, u.vout, u.amount, u.scriptPubKey};
                updated.emplace(key, std::move(lu));
                Logger::log("[updateLocalUTXOSetFromChain] Included regular UTXO " + key + " for address " + addr + ", amount: " + std::to_string(u.amount));
            }
        }
    }
    
    // NEW: Also check for any stored token data (for backwards compatibility)
    // This handles tokens that might have been stored separately
    try {
        blockchainPtr->getStorage()->iteratePrefix("tokenUTXO:", [&](const std::string& key, const std::string& tokenData) {
            try {
                Logger::log("[updateLocalUTXOSetFromChain] Found stored token data at tokenUTXO:" + key);
                
                // Parse the key to get txid and vout
                size_t colonPos = key.find(':');
                if (colonPos == std::string::npos) return;
                
                std::string txid = key.substr(0, colonPos);
                uint32_t vout = std::stoul(key.substr(colonPos + 1));
                
                // Parse token data
                auto tokenJson = nlohmann::json::parse(tokenData);
                
                std::string tokenID = tokenJson["tokenID"].get<std::string>();
                std::string tokenType = tokenJson["type"].get<std::string>();
                uint64_t tokenAmount = std::stoull(tokenJson["amount"].get<std::string>());
                std::string owner = tokenJson["owner"].get<std::string>();
                
                // Only add if we own it and haven't already added it
                std::string tokenUtxoKey = txid + ":" + std::to_string(vout);
                if (ownsAddress(owner) && localTokenUtxos.find(tokenUtxoKey) == localTokenUtxos.end()) {
                    // Create ExtendedTokenData
                    ExtendedTokenData extTokenData;
                    extTokenData.tokenID = tokenID;
                    extTokenData.type = stringToTokenType(tokenType);
                    extTokenData.amount = tokenAmount;
                    
                    // Get full metadata
                    std::string metadataKey = "tokenMetadata:" + txid;
                    try {
                        ExtendedTokenData fetchedData = blockchainPtr->fetchTokenMetadata(metadataKey);
                        extTokenData.meta = fetchedData.meta;
                    } catch (const std::exception& e) {
                        Logger::log("[updateLocalUTXOSetFromChain] Warning: Could not fetch metadata for stored token " + txid);
                        extTokenData.meta.data = nlohmann::json::object();
                        extTokenData.meta.data["name"] = "Token_" + tokenID;
                    }
                    
                    // Add to token UTXOs
                    localTokenUtxos[tokenUtxoKey] = std::make_tuple(
                        txid, 
                        vout, 
                        tokenAmount, 
                        extTokenData, 
                        owner
                    );
                    
                    Logger::log("[updateLocalUTXOSetFromChain] Added stored token UTXO: " + 
                               tokenID + " amount: " + std::to_string(tokenAmount) + 
                               " at " + tokenUtxoKey);
                }
            } catch (const std::exception& e) {
                Logger::log("[updateLocalUTXOSetFromChain] Error parsing stored token data: " + std::string(e.what()));
            }
        });
    } catch (const std::exception& e) {
        Logger::log("[updateLocalUTXOSetFromChain] Error iterating stored tokens: " + std::string(e.what()));
    }

    localUtxos.swap(updated);
    Logger::log("[updateLocalUTXOSetFromChain] Synchronization complete, coin UTXOs: " + 
                std::to_string(localUtxos.size()) + ", token UTXOs: " + 
                std::to_string(localTokenUtxos.size()));
}
// ------------------------------
// Derivation: BIP32 => address, private key
// ------------------------------
std::string Wallet::deriveHDPrivateKey(uint32_t index) const {
    requirePrivateAccess("deriveHDPrivateKey");

    const std::vector<uint8_t>* seedSource = nullptr;
    if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
        seedSource = &walletSecurityController_->unlockedSeed();
    } else {
        seedSource = &masterSeed;
    }

    if (seedSource->empty()) {
        throw std::runtime_error("[Wallet] deriveHDPrivateKey => no authenticated seed");
    }

    struct ext_key master;
    if (bip32_key_from_seed(seedSource->data(), seedSource->size(),
            BIP32_VER_MAIN_PRIVATE, 0, &master) != WALLY_OK) {
        throw std::runtime_error("[Wallet] bip32_key_from_seed fail");
    }

    uint32_t path[5] = {
        0x80000000 | derivationPath.purpose,
        0x80000000 | derivationPath.coin_type,
        0x80000000 | derivationPath.account,
        derivationPath.change,
        index
    };

    struct ext_key child;
    if (bip32_key_from_parent_path(&master, path, 5,
            BIP32_FLAG_KEY_PRIVATE, &child) != WALLY_OK) {
        throw std::runtime_error("[Wallet] deriveHDPrivateKey => parent_path fail");
    }

    std::vector<unsigned char> rawKey(child.priv_key + 1, child.priv_key + 33);
    ECDSAKey ecKey = ECDSAKey::fromRawBytes(rawKey);
    return ecKey.getPrivateKey();
}

std::vector<unsigned char> Wallet::deriveHDPublicKey(uint32_t index) const {
    requirePrivateAccess("deriveHDPublicKey");

    const std::vector<uint8_t>* seedSource = nullptr;
    if (getWalletSecurityMode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED) {
        seedSource = &walletSecurityController_->unlockedSeed();
    } else {
        seedSource = &masterSeed;
    }

    if (seedSource->empty()) {
        throw std::runtime_error("[Wallet] deriveHDPublicKey => no authenticated seed");
    }

    struct ext_key master;
    if (bip32_key_from_seed(seedSource->data(), seedSource->size(),
            BIP32_VER_MAIN_PRIVATE, 0, &master) != WALLY_OK) {
        throw std::runtime_error("[Wallet] bip32_key_from_seed fail");
    }

    uint32_t path[5] = {
        0x80000000 | derivationPath.purpose,
        0x80000000 | derivationPath.coin_type,
        0x80000000 | derivationPath.account,
        derivationPath.change,
        index
    };

    struct ext_key child;
    if (bip32_key_from_parent_path(&master, path, 5,
            BIP32_FLAG_KEY_PRIVATE, &child) != WALLY_OK) {
        throw std::runtime_error("[Wallet] deriveHDPublicKey => parent_path fail");
    }

    std::vector<unsigned char> rawKey(child.priv_key + 1, child.priv_key + 33);
    ECDSAKey ecKey = ECDSAKey::fromRawBytes(rawKey);
    return ecKey.getCompressedSec1();
}

std::string Wallet::deriveHDAddress(uint32_t index) const {
    std::vector<unsigned char> pubkey = deriveHDPublicKey(index); // Use consistent public key derivation
    unsigned char hash160[HASH160_LEN];
    if (wally_hash160(pubkey.data(), pubkey.size(), hash160, HASH160_LEN) != WALLY_OK) {
        throw std::runtime_error("[Wallet] deriveHDAddress => wally_hash160 fail");
    }
    unsigned char verplus[1 + HASH160_LEN];
    verplus[0] = tru_network::MAINNET_P2PKH_VERSION; // TRU mainnet
    memcpy(verplus + 1, hash160, HASH160_LEN);
    char* addr_out = nullptr;
    if (wally_base58_from_bytes(verplus, sizeof(verplus), BASE58_FLAG_CHECKSUM, &addr_out) != WALLY_OK) {
        throw std::runtime_error("[Wallet] deriveHDAddress => base58 fail");
    }
    std::string result(addr_out);
    wally_free_string(addr_out);
    return result;
}

// -------------------------------------------------
//              rpcFindOneCoinUtxo
// -------------------------------------------------
std::pair<std::string, uint32_t> Wallet::rpcFindOneCoinUtxo(const std::string &nodeIP,
                                                            int nodePort,
                                                            const std::string &address)
{
    httplib::Client cli(nodeIP, nodePort);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(nodePort));

    // Example request (depends on your node’s actual methods):
    nlohmann::json jreq;
    jreq["method"] = "listunspent";
    jreq["params"] = { { "address", address } };

    auto resp = cli.Post("/rpc", jreq.dump(), "application/json");
    if(!resp || resp->status != 200) {
        throw std::runtime_error("[rpcFindOneCoinUtxo] RPC call failed or non-200");
    }
    auto jresp = nlohmann::json::parse(resp->body);
    if(jresp.contains("error") && !jresp["error"].is_null()) {
        throw std::runtime_error("[rpcFindOneCoinUtxo] RPC error: "
                                 + jresp["error"].dump());
    }
    // Suppose result is an array:  jresp["result"] = [...]
    auto arr = jresp["result"];
    if(!arr.is_array()) {
        throw std::runtime_error("[rpcFindOneCoinUtxo] result not array?");
    }

    for(auto &utxo : arr) {
        // We want a coin-based UTXO => either we check “token” field or 
        // we assume if “amount”>0, it’s coin. 
        // Adjust to your format:
        double amt = utxo["amount"].get<double>();
        // if amt>0 => it's a coin-based UTXO
        if(amt > 0) {
            std::string txid = utxo["txid"].get<std::string>();
            uint32_t vout    = utxo["vout"].get<uint32_t>();
            return { txid, vout };
        }
    }
    throw std::runtime_error("[rpcFindOneCoinUtxo] No spendable coin UTXO found.");
}


std::string Wallet::getPubKeyHashForAddress(const std::string& address) {
    // Extract pubkeyhash from address
    std::vector<unsigned char> decoded = decodeBase58Check(address);  // Changed from decodeBase58
    if (decoded.size() < 25) {
        throw std::runtime_error("Invalid address format");
    }
    
    // Skip version byte and extract 20-byte pubkeyhash
    std::vector<unsigned char> pubkeyhash(decoded.begin() + 1, decoded.begin() + 21);
    return bytesToHex(pubkeyhash);
}

std::vector<SmartContractInfo> Wallet::getSmartContracts() {
    std::vector<SmartContractInfo> contracts;
    
    // Check if local blockchain is available
    if (!isLocalChainAvailable()) {
        Logger::log("[Wallet::getSmartContracts] No blockchain available");
        return contracts;
    }
    
    try {
        // Get contracts from blockchain using the reference
        const Blockchain& chain = getBlockchain();
        nlohmann::json contractsJson = chain.getContracts();
        
        if (contractsJson.contains("contracts") && contractsJson["contracts"].is_array()) {
            for (const auto& contractData : contractsJson["contracts"]) {
                SmartContractInfo info;
                
                // Extract basic info
                info.name = contractData.value("name", "Unnamed Contract");
                info.type = contractData.value("type", "Unknown");
                info.address = contractData.value("identifier", "");
                info.createdAt = contractData.value("creationTime", 0);
                info.scriptHex = "";  // Not directly available in the JSON
                
                // Determine status by checking if UTXO is spent
                std::string txid = contractData.value("txid", "");
                bool isSpent = false;
                
                // Parse contract address to get vout
                size_t colonPos = info.address.find(':');
                if (colonPos != std::string::npos) {
                    uint32_t vout = std::stoul(info.address.substr(colonPos + 1));
                    UTXO utxo;
                    isSpent = !chain.utxoSet.getUTXO(txid, vout, utxo);
                    if (!isSpent) {
                        info.value = utxo.amount;
                    }
                }
                
                info.status = isSpent ? "Redeemed" : "Active";
                
                contracts.push_back(info);
            }
        }
        
        Logger::log("[Wallet::getSmartContracts] Found " + std::to_string(contracts.size()) + " contracts");
        
    } catch (const std::exception& e) {
        Logger::log("[Wallet::getSmartContracts] Error: " + std::string(e.what()));
    }
    
    return contracts;
}

ContractDetails Wallet::getContractDetails(const std::string& address) {
    ContractDetails details;
    details.name = "Unknown";
    details.type = "Unknown";
    details.scriptHex = "";
    details.state = "Unknown";
    details.canExecute = false;
    
    if (!isLocalChainAvailable()) {
        Logger::log("[Wallet::getContractDetails] No blockchain available");
        return details;
    }
    
    try {
        const Blockchain& chain = getBlockchain();
        
        // Parse address to get txid and vout
        size_t colonPos = address.find(':');
        if (colonPos == std::string::npos) {
            throw std::runtime_error("Invalid contract address format");
        }
        
        std::string txid = address.substr(0, colonPos);
        uint32_t vout = std::stoul(address.substr(colonPos + 1));
        
        // Get the transaction from blockchain
        Transaction tx;
        if (!chain.getTransaction(txid, tx)) {
            throw std::runtime_error("Transaction not found");
        }
        
        // Get contract script
        if (vout >= tx.vout.size()) {
            throw std::runtime_error("Invalid output index");
        }
        
        details.scriptHex = tx.vout[vout].scriptPubKey;
        
        // Check for OP_RETURN metadata in previous output
        if (vout > 0 && tx.vout[vout-1].scriptPubKey.substr(0, 2) == "6a") {
            std::string metaHex = tx.vout[vout-1].scriptPubKey.substr(4);
            std::vector<unsigned char> metaBytes = hexDecode(metaHex);
            std::string metaStr(metaBytes.begin(), metaBytes.end());
            
            if (metaStr.find("TRU_CONTRACT:") == 0) {
                std::string remainder = metaStr.substr(13);
                size_t reasonPos = remainder.find(":REASON:");
                details.name = (reasonPos != std::string::npos) ? 
                    remainder.substr(0, reasonPos) : remainder;
            }
        }
        
        // Determine contract type
        uint32_t parsedTimeLock = 0;
        if (parseCanonicalTimeLockScriptHex(details.scriptHex, &parsedTimeLock)) {
            details.type = "Time Lock";
            const uint32_t currentMtp = getWalletChainMedianTimePast(*blockchainPtr);
            details.canExecute =
                parsedTimeLock >= 500000000U && currentMtp >= parsedTimeLock;
            details.state = details.canExecute
                ? "Unlocked by MTP"
                : "Locked until MTP reaches " + std::to_string(parsedTimeLock) +
                  " (current MTP=" + std::to_string(currentMtp) + ")";
            
        } else if (parseCanonicalHashLockScriptHex(details.scriptHex)) {
            details.type = "Hash Lock";
            details.canExecute = true; // Can execute if you know the preimage
            details.state = "Requires HASH160 preimage";
            
        } else if (details.scriptHex.find("f2") != std::string::npos) {
            details.type = "Oracle-Based";
            details.canExecute = true; // Depends on oracle data
            details.state = "Depends on oracle data";
            
        } else {
            details.type = "Custom Script";
            details.canExecute = true;
            details.state = "Active";
        }
        
        // Check if UTXO is still available
        UTXO utxo;
        if (!chain.utxoSet.getUTXO(txid, vout, utxo)) {
            details.state = "Already spent";
            details.canExecute = false;
        }
        
    } catch (const std::exception& e) {
        Logger::log("[Wallet::getContractDetails] Error: " + std::string(e.what()));
    }
    
    return details;
}

std::string Wallet::redeemHashLock(
    const std::string& contractAddr,
    const std::string& preimage)
{
    try {
        if (!isLocalChainAvailable() || !blockchainPtr || !blockchainPtr->mempool) {
            throw std::runtime_error(
                "Hash Lock redemption requires the local blockchain and mempool");
        }

        const size_t colonPos = contractAddr.find(':');
        if (colonPos == std::string::npos ||
            contractAddr.find(':', colonPos + 1) != std::string::npos) {
            throw std::runtime_error(
                "Invalid Hash Lock output format; expected txid:vout");
        }

        const std::string txid = contractAddr.substr(0, colonPos);
        if (txid.size() != 64 ||
            txid.find_first_not_of("0123456789abcdef") != std::string::npos) {
            throw std::runtime_error(
                "Hash Lock txid must be canonical lowercase 64-hex");
        }

        uint32_t vout = 0;
        try {
            const std::string voutText = contractAddr.substr(colonPos + 1);
            if (voutText.empty() ||
                voutText.find_first_not_of("0123456789") != std::string::npos) {
                throw std::runtime_error("bad vout");
            }
            const unsigned long parsed = std::stoul(voutText);
            if (parsed > std::numeric_limits<uint32_t>::max()) {
                throw std::runtime_error("vout overflow");
            }
            vout = static_cast<uint32_t>(parsed);
        } catch (...) {
            throw std::runtime_error("Hash Lock vout is invalid");
        }

        UTXO utxo;
        if (!blockchainPtr->utxoSet.getUTXO(txid, vout, utxo)) {
            throw std::runtime_error(
                "Hash Lock UTXO not found or already spent");
        }

        std::string expectedHash160;
        if (!parseCanonicalHashLockScriptHex(
                utxo.scriptPubKey, &expectedHash160)) {
            throw std::runtime_error(
                "Selected output is not a canonical Hash Lock "
                "(expected a914<20-byte-hash>87)");
        }

        const std::vector<unsigned char> preimageBytes(
            preimage.begin(), preimage.end());
        if (preimageBytes.size() > 100) {
            throw std::runtime_error(
                "Hash Lock preimage exceeds the 100-byte contract limit");
        }

        const std::string actualHash160 =
            hashLockPreimageHash160Hex(preimage);
        if (actualHash160 != expectedHash160) {
            throw std::runtime_error(
                "Invalid preimage: HASH160 does not match the locked value");
        }

        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        tx.vin.emplace_back(txid, vout);

        uint64_t fee = WALLET_MIN_BASE_FEE;
        if (utxo.amount <= fee) {
            throw std::runtime_error(
                "Hash Lock value is too low to cover the redemption fee");
        }

        const std::string currentAddr = getCurrentAddress();
        if (currentAddr.empty()) {
            throw std::runtime_error(
                "Wallet has no current address for the redeemed TRU");
        }
        const std::string outputScript =
            createP2PKHScriptHexFromAddress(currentAddr);
        tx.vout.emplace_back(utxo.amount - fee, outputScript);

        tx.vin[0].scriptSig.clear();
        appendHashLockPreimagePush(tx.vin[0].scriptSig, preimageBytes);

        fee = applyWalletPolicyFee(
            tx, fee, 0, "redeemHashLock");

        tx.computeTxId();

        if (!blockchainPtr->broadcastTransaction(tx)) {
            throw std::runtime_error(
                "Hash Lock redemption was rejected by the local mempool");
        }

        Logger::log(
            "[Wallet::redeemHashLock] accepted txid=" + tx.txid +
            " output=" + contractAddr +
            " expectedHASH160=" + expectedHash160 +
            " feeAtoms=" + std::to_string(fee));
        return tx.txid;
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("Failed to redeem hash lock: ") + e.what());
    }
}

std::string Wallet::redeemTimeLock(const std::string& contractAddr) {
    try {
        if (!isLocalChainAvailable() || !blockchainPtr || !blockchainPtr->mempool) {
            throw std::runtime_error(
                "Time Lock redemption requires the local blockchain and mempool");
        }

        std::string txid;
        uint32_t vout = 0;
        if (!parseContractOutpoint(contractAddr, txid, vout) ||
            txid.find_first_not_of("0123456789abcdef") != std::string::npos) {
            throw std::runtime_error(
                "Invalid Time Lock output format; expected lowercase txid:vout");
        }

        UTXO utxo;
        if (!blockchainPtr->utxoSet.getUTXO(txid, vout, utxo)) {
            throw std::runtime_error("Time Lock UTXO not found or already spent");
        }

        uint32_t lockTime = 0;
        std::string ownerHash160;
        if (!parseCanonicalTimeLockScriptHex(
                utxo.scriptPubKey, &lockTime, &ownerHash160)) {
            throw std::runtime_error(
                "Selected output is not a canonical Time Lock");
        }

        static constexpr uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;
        if (lockTime < TRU_CLTV_TIMESTAMP_THRESHOLD) {
            throw std::runtime_error(
                "Unsupported height-domain Time Lock; TRU Time Lock V1 requires Unix timestamp >= 500000000");
        }

        const uint32_t currentMtp =
            getWalletChainMedianTimePast(*blockchainPtr);
        if (currentMtp < lockTime) {
            throw std::runtime_error(
                "Time Lock has not matured under parent-chain MTP; unlock Unix time=" +
                std::to_string(lockTime) +
                ", current MTP=" + std::to_string(currentMtp) +
                ", remaining MTP seconds=" +
                std::to_string(static_cast<uint64_t>(lockTime) - currentMtp));
        }

        const std::string currentAddr = getCurrentAddress();
        if (currentAddr.empty()) {
            throw std::runtime_error(
                "Wallet has no current address for the redeemed TRU");
        }

        Transaction tx;
        tx.version = 1;
        tx.lockTime = lockTime;
        tx.vin.emplace_back(txid, vout);
        // final sequence disables locktime. Use non-final sequence.
        tx.vin[0].sequence = 0xfffffffeU;

        uint64_t fee = WALLET_MIN_BASE_FEE;
        if (utxo.amount <= fee) {
            throw std::runtime_error(
                "Time Lock value is too low to cover the redemption fee");
        }
        tx.vout.emplace_back(
            utxo.amount - fee,
            createP2PKHScriptHexFromAddress(currentAddr));

        // Sign once so fee estimation sees the actual Time-Lock P2PKH scriptSig.
        tx.txid.clear();
        if (!signTransaction(tx)) {
            throw std::runtime_error("Failed to sign Time Lock redemption");
        }

        const uint64_t requiredFee = estimateWalletPolicyFee(tx);
        if (requiredFee > fee) {
            fee = requiredFee;
            if (utxo.amount <= fee) {
                throw std::runtime_error(
                    "Time Lock value is too low to cover the size-aware fee");
            }
            tx.vout[0].amount = utxo.amount - fee;
            tx.vin[0].scriptSig.clear();
            tx.vin[0].pubKey.clear();
            tx.txid.clear();
            if (!signTransaction(tx)) {
                throw std::runtime_error(
                    "Failed to re-sign Time Lock after fee adjustment");
            }
        }

        // signTransaction computes an unsigned/intermediate txid before it fills
        // scriptSig. Recompute after the final signature is installed.
        tx.computeTxId();

        if (!blockchainPtr->broadcastTransaction(tx)) {
            throw std::runtime_error(
                "Time Lock redemption was rejected by the local mempool");
        }

        Logger::log(
            "[Wallet::redeemTimeLock] accepted txid=" + tx.txid +
            " output=" + contractAddr +
            " lockTime=" + std::to_string(lockTime) +
            " parentMTP=" + std::to_string(currentMtp) +
            " ownerHASH160=" + ownerHash160 +
            " feeAtoms=" + std::to_string(fee));
        return tx.txid;
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("Failed to redeem time lock: ") + e.what());
    }
}

std::string Wallet::executeOracleContract(const std::string& contractAddr) {
    try {
        if (!isLocalChainAvailable()) {
            throw std::runtime_error("No blockchain available");
        }
        
        const Blockchain& chain = getBlockchain();
        
        // Parse contract address
        size_t colonPos = contractAddr.find(':');
        if (colonPos == std::string::npos) {
            throw std::runtime_error("Invalid contract address format");
        }
        
        std::string txid = contractAddr.substr(0, colonPos);
        uint32_t vout = std::stoul(contractAddr.substr(colonPos + 1));
        
        // Get UTXO
        UTXO utxo;
        if (!chain.utxoSet.getUTXO(txid, vout, utxo)) {
            throw std::runtime_error("Contract UTXO not found or already spent");
        }
        
        // Build execution transaction
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        
        // Add contract input
        tx.vin.emplace_back(txid, vout);
        
        // Create output to current address (minus fee)
        uint64_t fee = WALLET_MIN_BASE_FEE;
        if (utxo.amount <= fee) {
            throw std::runtime_error("Contract value too low to cover fee");
        }
        
        std::string currentAddr = getCurrentAddress();
        std::string outputScript = createP2PKHScriptHexFromAddress(currentAddr);
        tx.vout.emplace_back(utxo.amount - fee, outputScript);
        
        fee = applyWalletPolicyFee(
            tx, fee, 0, "executeOracleContract");

        // For oracle contracts, we need to provide the oracle data in the scriptSig
        // This is a simplified version - in reality, you'd fetch actual oracle data
        // and construct the proper unlocking script
        
        // Sign the transaction
        if (!signTransaction(tx)) {
            throw std::runtime_error("Failed to sign transaction");
        }
        
        // Broadcast
        std::string rawHex = hexEncode(tx.serializeBinary());
        bool broadcast = broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);
        
        if (!broadcast) {
            throw std::runtime_error("Failed to broadcast transaction");
        }
        
        Logger::log("[Wallet::executeOracleContract] Oracle contract executed, txid: " + tx.txid);
        return tx.txid;
        
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Failed to execute oracle contract: ") + e.what());
    }
}


std::vector<TransactionInfo> Wallet::getTransactionHistory(const std::vector<std::string>& addresses) const {
    std::vector<TransactionInfo> history;
    
    if (!blockchainPtr || !isLocalChain) {
        return history;
    }
    
    // Get current block height for confirmation calculation
    int currentHeight = blockchainPtr->getBestTipHeight();
    
    // Collect all unique transaction IDs first
    std::set<std::string> allTxids;
    for (const std::string& addr : addresses) {
        std::vector<std::string> txids = blockchainPtr->getTransactionsForAddress(addr);
        allTxids.insert(txids.begin(), txids.end());
    }
    
    Logger::log("[getTransactionHistory] Processing " + std::to_string(allTxids.size()) + " unique transactions");
    
    // Process each transaction
    for (const std::string& txid : allTxids) {
        Transaction tx;
        if (!blockchainPtr->getTransaction(txid, tx)) {
            Logger::log("[getTransactionHistory] Could not find transaction: " + txid);
            continue;
        }
        
        // Process for each address
        for (const std::string& addr : addresses) {
            TransactionInfo info;
            info.txid = txid;
            
            // Get block info for this transaction
            info.blockHeight = blockchainPtr->getTxBlockHeight(txid);
            if (info.blockHeight > 0) {
                info.confirmations = currentHeight - info.blockHeight + 1;
                
                // Get block to get timestamp
                auto block = blockchainPtr->getBlockByHeight(info.blockHeight);
                if (block.has_value()) {
                    info.timestamp = block.value().header.timestamp;
                } else {
                    info.timestamp = 0;
                }
            } else {
                info.confirmations = 0;
                info.timestamp = 0;
            }
            
            // Handle coinbase transactions
            if (tx.isCoinbase) {
                // Check if this address received the coinbase
                for (size_t i = 0; i < tx.vout.size(); ++i) {
                    std::string outputAddr = extractAddressFromScriptPubKey(
                        tx.vout[i].scriptPubKey, txid, i, blockchainPtr);
                    if (outputAddr == addr) {
                        info.type = "Received";
                        info.address = "Coinbase";
                        info.amount = tx.vout[i].amount / 100000000.0;
                        history.push_back(info);
                        break;
                    }
                }
                continue;
            }
            
            // For non-coinbase transactions, check if this is a send or receive
            bool isSend = false;
            double totalIn = 0, totalOut = 0;
            std::string otherAddr;
            
            // Check inputs - if any input is from our address, it's a send
            for (const auto& vin : tx.vin) {
                std::string inputAddr = blockchainPtr->utxoSet.getAddressFromUTXO(
                    vin.txid, vin.vout, blockchainPtr);
                if (inputAddr == addr) {
                    isSend = true;
                    // Get the amount from the spent UTXO
                    // Note: This might fail for historical transactions where the UTXO is already spent
                    // In that case, we'd need to look it up from the transaction that created it
                    break;
                }
            }
            
            // Check outputs
            double receivedAmount = 0;
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                std::string outputAddr = extractAddressFromScriptPubKey(
                    tx.vout[i].scriptPubKey, txid, i, blockchainPtr);
                
                if (outputAddr == addr) {
                    if (!isSend) {
                        // We're receiving
                        receivedAmount += tx.vout[i].amount;
                    }
                    // For sends, this is change back to us, ignore it
                } else if (isSend && !outputAddr.empty()) {
                    // For sends, track where we sent to
                    otherAddr = outputAddr;
                    totalOut += tx.vout[i].amount;
                }
            }
            
            // Set transaction info
            if (isSend) {
                info.type = "Sent";
                info.address = otherAddr.empty() ? "Unknown" : otherAddr;
                info.amount = totalOut / 100000000.0;
            } else if (receivedAmount > 0) {
                info.type = "Received";
                // Try to find sender address from first input
                if (!tx.vin.empty()) {
                    std::string senderAddr = blockchainPtr->utxoSet.getAddressFromUTXO(
                        tx.vin[0].txid, tx.vin[0].vout, blockchainPtr);
                    info.address = senderAddr.empty() ? "Unknown" : senderAddr;
                } else {
                    info.address = "Unknown";
                }
                info.amount = receivedAmount / 100000000.0;
            } else {
                // Skip transactions where this address is not involved
                continue;
            }
            
            history.push_back(info);
        }
    }
    
    // Sort by timestamp (newest first)
    std::sort(history.begin(), history.end(), 
              [](const TransactionInfo& a, const TransactionInfo& b) {
                  if (a.timestamp == b.timestamp) {
                      return a.blockHeight > b.blockHeight;
                  }
                  return a.timestamp > b.timestamp;
              });
    
    Logger::log("[getTransactionHistory] Returning " + std::to_string(history.size()) + " transactions");
    return history;
}


std::string Wallet::extractTargetFromMagicLockScript(const std::string& scriptHex) const {
    // Parse the script to extract the target prefix
    // The target is the first data push in the script
    if (scriptHex.length() < 4) return "";
    
    // First byte should be the length of the target
    size_t targetLen = std::stoul(scriptHex.substr(0, 2), nullptr, 16);
    if (targetLen * 2 + 2 > scriptHex.length()) return "";
    
    // Extract the target hex
    return scriptHex.substr(2, targetLen * 2);
}
//=========================================================================
// Extract the 20-byte PKH from the P2PKH tail of a MagicLock script
//=========================================================================
std::string Wallet::extractPkhFromMagicLock(const std::string& scriptHex) const {
    size_t pos = scriptHex.find("76a914"); // OP_DUP OP_HASH160 OP_PUSHDATA(20)
    if (pos == std::string::npos || pos + 6 + 40 > scriptHex.size()) return "";
    return scriptHex.substr(pos + 6, 40);
}

//=========================================================================
// Convert a 20-byte PKH hex string to TRU Base58Check P2PKH address
//=========================================================================
std::string Wallet::base58FromPubKeyHashHex(const std::string& pkhHex) const {
    std::vector<uint8_t> pkh = hexDecode(pkhHex);
    if (pkh.size() != 20) return "";
    std::vector<uint8_t> data = {tru_network::MAINNET_P2PKH_VERSION}; // TRU mainnet P2PKH
    data.insert(end(data), begin(pkh), end(pkh));
    unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), h1);
    SHA256(h1, SHA256_DIGEST_LENGTH, h2);
    data.insert(end(data), h2, h2 + 4);
    return base58Encode(data);
}

//=====================================================================
//                      STORE MAGIC LOCK SECRET
//=====================================================================
void Wallet::storeMagicLockSecret(const std::string& txid, 
                                  const std::string& targetPrefix, 
                                  const std::string& dataType,
                                  const std::string& encryptionKeyHex) {
    if (!blockchainPtr || !blockchainPtr->getStorage()) {
        throw std::runtime_error("[storeMagicLockSecret] Storage not available");
    }
    
    LevelDBStorage* storage = blockchainPtr->getStorage();
    
    // Create metadata JSON with all necessary info for later decryption
    nlohmann::json secretMeta;
    secretMeta["txid"] = txid;
    secretMeta["targetPrefix"] = targetPrefix;
    secretMeta["dataType"] = dataType;
    secretMeta["encryptionKey"] = encryptionKeyHex; // Store the key for later decryption
    secretMeta["timestamp"] = std::time(nullptr);
    secretMeta["version"] = "1.0";
    
    // Store with a key that can be easily retrieved when unlocking
    std::string storageKey = "magicLockSecret:" + txid;
    std::string metaStr = secretMeta.dump();
    
    if (!storage->putWithDataChecksum(storageKey, metaStr)) {
        Logger::log("[storeMagicLockSecret] WARNING: Failed to store secret metadata for txid: " + txid);
        throw std::runtime_error("Failed to store MagicLock secret metadata");
    }
    
    Logger::log("[storeMagicLockSecret] Successfully stored secret metadata for txid: " + txid);
    Logger::log("[storeMagicLockSecret] DataType: " + dataType + ", Target: " + targetPrefix);
}
//=========================================================================
// 		EXTRACT TARGET SMART
//=========================================================================
std::string extractTargetSmart(const std::string& scriptHex) {
    auto readPush = [&](size_t off) -> std::pair<std::string,size_t> {
        if (off + 2 > scriptHex.size()) return {"", off};
        size_t len = std::stoul(scriptHex.substr(off,2), nullptr, 16);
        size_t need = 2 + len*2;
        if (off + need > scriptHex.size()) return {"", off};
        return { scriptHex.substr(off+2, len*2), off + need };
    };

    // Try canonical pattern: 7c aa <N> 7f <push target> 88
    {
        size_t p = 0;
        auto find = [&](const std::string& needle)->bool{
            size_t pos = scriptHex.find(needle, p);
            if (pos == std::string::npos) return false;
            p = pos + needle.size();
            return true;
        };
        if (find("7caa")) {
            // after 7caa expect N (1 byte small-int OR 01 xx), then 7f, then push target
            // scan forward to first 7f
            size_t pos7f = scriptHex.find("7f", p);
            if (pos7f != std::string::npos) {
                // after 7f should be a PUSHDATA with target
                size_t tOff = pos7f + 2;
                auto [tgt, next] = readPush(tOff);
                // next must be followed by 88 (equalverify)
                if (!tgt.empty() && next + 2 <= scriptHex.size() && scriptHex.substr(next,2) == "88") {
                    return tgt;

                }
            }
        }
    }

    // Try Legacy A/B: script starts with a push <target>, then "... aa <N> 7f 88 ..."
    {
        auto [tgt, next] = readPush(0);
        if (!tgt.empty()) {
            // sanity: somewhere after target we must see aa .. 7f .. 88
            size_t posAA = scriptHex.find("aa", next);
            size_t pos7F = scriptHex.find("7f", next);
            size_t pos88 = scriptHex.find("88", next);
            if (posAA != std::string::npos && pos7F != std::string::npos && pos88 != std::string::npos
                && posAA < pos7F && pos7F < pos88) {
                return tgt;
            }
        }
    }

    return "";
}

static std::string extractPkhHex(const std::string& scriptHex) {
    size_t pos = scriptHex.find("76a914");
    if (pos == std::string::npos || pos + 6 + 40 > scriptHex.size()) return "";
    return scriptHex.substr(pos + 6, 40);
}
//===========================================
// Create a MagicLock   With Secret
//===========================================
std::string Wallet::createMagicLock(uint64_t amount, const std::string& targetPrefix, 
                                    const std::string& secretData, 
                                    const std::string& dataType) {
    std::string sender = getCurrentAddress();
    
    Logger::log("[createMagicLock] Creating MagicLock with secret data");
    Logger::log("[createMagicLock] Data type: " + dataType + ", size: " + 
                std::to_string(secretData.size()));
    
    // Find UTXO for funding
    auto [txid, vout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (txid.empty()) {
        throw std::runtime_error("No UTXO available");
    }
    
    UTXO utxo;
    if (!blockchainPtr->utxoSet.getUTXO(txid, vout, utxo)) {
        throw std::runtime_error("Failed to get UTXO details");
    }
    
    // Build transaction
    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(txid, vout);
    
    // Output 0: MagicLock output
    std::string pubKeyHash = getPubKeyHashForAddress(sender);
    std::string lockScript = createMagicLockScript(targetPrefix, pubKeyHash);
    tx.vout.emplace_back(amount, lockScript);
    
    // Declare encKey outside the if block so it's accessible later
    std::string encKey;
    
    // Output 1: OP_RETURN with encrypted secret data
    if (!secretData.empty()) {
        // Derive encryption key from target + pubKeyHash
        encKey = deriveEncryptionKey(targetPrefix, pubKeyHash);
        std::string encryptedData = encryptData(secretData, encKey);
        
        // Create metadata JSON
        nlohmann::json metadata;
        metadata["type"] = "MAGIC_SECRET";
        metadata["dataType"] = dataType;
        metadata["encrypted"] = base64Encode(encryptedData);
        metadata["hint"] = "Unlock with signature matching " + targetPrefix;
        metadata["timestamp"] = std::time(nullptr);
        
        std::string metaStr = metadata.dump();
        std::string opReturnScript = buildOpReturnScript(metaStr);
        tx.vout.emplace_back(0, opReturnScript);
        
        Logger::log("[createMagicLock] Added encrypted secret in OP_RETURN");
    }
    
    // Output 2: Change output  
    uint64_t fee = WALLET_MIN_BASE_FEE;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (utxo.amount > amount + fee) {
        uint64_t changeAmount = utxo.amount - amount - fee;
        std::string changeScript = createP2PKHScriptHexFromAddress(sender);
        tx.vout.emplace_back(changeAmount, changeScript);
        feeBearingVout = tx.vout.size() - 1;
    }
    
    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "createMagicLock(secret)");

    // Sign and broadcast
    tx.computeTxId();
    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign MagicLock transaction");
    }
    
    tx.computeTxId();
    
    // Store encryption key for later retrieval (only if we have a secret)
    if (!secretData.empty()) {
        storeMagicLockSecret(tx.txid, targetPrefix, dataType, encKey);
    }
    
    // Add to mempool and broadcast
    MempoolAddStatus status = blockchainPtr->mempool->addTransaction(tx);
    if (status != MempoolAddStatus::SUCCESS) {
        throw std::runtime_error("Failed to add to mempool");
    }
    
    blockchainPtr->broadcastTransaction(tx);
    Logger::log("[createMagicLock] MagicLock with secret created: " + tx.txid);
    
    return tx.txid;
}

//=========================================================
// Helper function to build OP_RETURN script
//=========================================================

std::string Wallet::buildOpReturnScript(const std::string& data) {
    std::vector<unsigned char> script;
    script.push_back(0x6a); // OP_RETURN
    
    std::vector<unsigned char> dataBytes(data.begin(), data.end());
    
    if (dataBytes.size() <= 75) {
        script.push_back(static_cast<unsigned char>(dataBytes.size()));
    } else if (dataBytes.size() <= 255) {
        script.push_back(0x4c); // OP_PUSHDATA1
        script.push_back(static_cast<unsigned char>(dataBytes.size()));
    } else {
        throw std::runtime_error("Data too large for OP_RETURN");
    }
    
    script.insert(script.end(), dataBytes.begin(), dataBytes.end());
    return bytesToHex(script);
}

//=========================================================
// Encryption helpers
//=========================================================

std::string Wallet::deriveEncryptionKey(const std::string& targetPrefix, 
                                        const std::string& pubKeyHash) {
    // Create deterministic key from target + PKH
    std::string combined = targetPrefix + pubKeyHash;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.length(), hash);
    return bytesToHex(std::vector<unsigned char>(hash, hash + 32));
}

std::string Wallet::encryptData(const std::string& plaintext, 
                                const std::string& keyHex) {
    // Use AES-256-CBC encryption
    std::vector<unsigned char> key = hexDecode(keyHex.substr(0, 64));
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    int ciphertext_len;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                     (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    std::vector<unsigned char> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    
    return std::string(result.begin(), result.end());
}

//=========================================================
// 	CREATE MAGIC LOCK SCRIPT
//=========================================================
std::string Wallet::createMagicLockScript(const std::string& targetPrefix,
                                          const std::string& pubKeyHash)
{
    if (targetPrefix.empty() || targetPrefix.length() % 2 != 0) {
        throw std::runtime_error("Invalid target prefix - must be non-empty hex with even length");
    }
    if (pubKeyHash.length() != 40) {
        throw std::runtime_error("Invalid pubKeyHash - must be 40 hex characters");
    }

    Logger::log("[createMagicLockScript] target=" + targetPrefix + ", pkh=" + pubKeyHash);

    std::vector<unsigned char> script;

    // 1) OP_SWAP OP_HASH256
    script.push_back(0x7c); // OP_SWAP
    script.push_back(0xaa); // OP_HASH256

    // 2) <N> OP_LEFT  (N = prefix length in bytes)
    const size_t prefixBytes = targetPrefix.length() / 2;
    if (prefixBytes >= 1 && prefixBytes <= 16) {
        script.push_back(0x50 + static_cast<unsigned char>(prefixBytes)); // OP_1..OP_16
    } else {
        script.push_back(0x01);                                           // push 1-byte length
        script.push_back(static_cast<unsigned char>(prefixBytes));
    }
    script.push_back(0x7f); // OP_LEFT

    // 3) <target> OP_EQUALVERIFY
    const auto targetBytes = hexDecode(targetPrefix);
    script.push_back(static_cast<unsigned char>(targetBytes.size()));
    script.insert(script.end(), targetBytes.begin(), targetBytes.end());
    script.push_back(0x88); // OP_EQUALVERIFY

    // 4) Standard P2PKH tail
    script.push_back(0x76); // OP_DUP
    script.push_back(0xa9); // OP_HASH160
    script.push_back(0x14); // push 20
    const auto pkh = hexDecode(pubKeyHash);
    script.insert(script.end(), pkh.begin(), pkh.end());
    script.push_back(0x88); // OP_EQUALVERIFY
    script.push_back(0xac); // OP_CHECKSIG

    const std::string hex = bytesToHex(script);
    Logger::log("[createMagicLockScript] hex=" + hex);
    return hex;
}


//==============================================
// Create a MagicLock transaction
//==============================================
std::string Wallet::createMagicLock(uint64_t amount, const std::string& targetPrefix) {
    std::string sender = getCurrentAddress();
    
    Logger::log("[createMagicLock] Creating MagicLock for address: " + sender);
    Logger::log("[createMagicLock] Amount: " + std::to_string(amount) + ", Target: " + targetPrefix);
    
    // Find UTXO for funding
    auto [txid, vout] = findOneSpendableUtxo(sender, blockchainPtr->mempool.get());
    if (txid.empty()) {
        throw std::runtime_error("No UTXO available");
    }
    
    UTXO utxo;
    if (!blockchainPtr->utxoSet.getUTXO(txid, vout, utxo)) {
        throw std::runtime_error("Failed to get UTXO details");
    }
    
    Logger::log("[createMagicLock] Using UTXO: " + txid + ":" + std::to_string(vout) + 
                " with amount: " + std::to_string(utxo.amount));
    
    // Build transaction
    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(txid, vout);
    
    // Create MagicLock output
    std::string pubKeyHash = getPubKeyHashForAddress(sender);
    std::string lockScript = createMagicLockScript(targetPrefix, pubKeyHash);
    tx.vout.emplace_back(amount, lockScript);
    
    Logger::log("[createMagicLock] Created MagicLock script: " + lockScript);
    
    // Change output
    uint64_t fee = WALLET_MIN_BASE_FEE;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (utxo.amount > amount + fee) {
        uint64_t changeAmount = utxo.amount - amount - fee;
        std::string changeScript = createP2PKHScriptHexFromAddress(sender);
        tx.vout.emplace_back(changeAmount, changeScript);
        feeBearingVout = tx.vout.size() - 1;
        Logger::log("[createMagicLock] Added change output: " + std::to_string(changeAmount));
    }
    
    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "createMagicLock");

    // Compute transaction ID before signing
    tx.computeTxId();
    Logger::log("[createMagicLock] Pre-sign TXID: " + tx.txid);
    
    // Sign the transaction
    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign MagicLock transaction");
    }
    
    // Recompute TXID after signing
    tx.computeTxId();
    Logger::log("[createMagicLock] Signed TXID: " + tx.txid);
    
    // Add to mempool
    MempoolAddStatus status = blockchainPtr->mempool->addTransaction(tx);
    if (status != MempoolAddStatus::SUCCESS) {
        std::string errorMsg = "Failed to add MagicLock to mempool. Status: ";
        switch(status) {
            case MempoolAddStatus::INVALID:
                errorMsg += "INVALID";
                break;
            case MempoolAddStatus::DUPLICATE:
                errorMsg += "DUPLICATE";
                break;
            default:
                errorMsg += std::to_string(static_cast<int>(status));
        }
        Logger::log("[createMagicLock] Mempool error: " + errorMsg);
        throw std::runtime_error(errorMsg);
    }
    
    Logger::log("[createMagicLock] Successfully added to mempool");
    
    // Broadcast the transaction to peers
    blockchainPtr->broadcastTransaction(tx);
    Logger::log("[createMagicLock] Broadcast to network");
    
    Logger::log("[createMagicLock] MagicLock created successfully with TXID: " + tx.txid);
    return tx.txid;
}

//===========================================
// Grind signatures to find one matching target prefix
//===========================================
std::pair<std::vector<unsigned char>, bool> Wallet::grindSignature(
    const std::vector<unsigned char>& msgHash, 
    const std::string& targetPrefix,
    const std::string& privateKeyPEM) {
    
    ECDSAKey key = ECDSAKey::fromPrivateKey(privateKeyPEM);
    int attempts = 0;
    const int maxAttempts = 1000000;
    
    while (attempts < maxAttempts) {
        // Generate random K for signature
        std::vector<unsigned char> randomK(32);
        RAND_bytes(randomK.data(), 32);
        
        // Sign with specific K value
        std::vector<unsigned char> derSignature = key.signWithK(
            std::string(msgHash.begin(), msgHash.end()), randomK);
        
        // Add SIGHASH_ALL to create the full signature
        std::vector<unsigned char> fullSignature = derSignature;
        fullSignature.push_back(0x01);
        
        // Hash the FULL signature (including SIGHASH_ALL) with double SHA256
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];
        SHA256(fullSignature.data(), fullSignature.size(), hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
        
        std::string hashHex = bytesToHex(std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH));
        
        // Check if it matches target prefix
        if (hashHex.substr(0, targetPrefix.length()) == targetPrefix) {
            Logger::log("[grindSignature] Found matching signature after " + 
                       std::to_string(attempts) + " attempts");
            return {fullSignature, true};  // Return the full signature with SIGHASH_ALL
        }
        
        attempts++;
        if (attempts % 10000 == 0) {
            Logger::log("[grindSignature] Attempt " + std::to_string(attempts) + 
                       " current hash: " + hashHex);
        }
    }
    
    return {{}, false};
}

//===========================================
// Unlock a MagicLock UTXO
//===========================================
std::string Wallet::unlockMagicLock(const std::string& lockTxid, uint32_t lockVout,
                                    const std::string& recipient)
{
    Logger::log("[unlockMagicLock] BEGIN " + lockTxid + ":" + std::to_string(lockVout));

    // 1) Fetch locked UTXO
    UTXO locked;
    if (!blockchainPtr->utxoSet.getUTXO(lockTxid, lockVout, locked)) {
        throw std::runtime_error("MagicLock UTXO not found - may already be spent");
    }
    const std::string scriptHex = locked.scriptPubKey;

    // 2) Parse target + owner address
    const std::string target = extractTargetSmart(scriptHex);
    if (target.empty()) {
        Logger::log("[unlockMagicLock] ERROR: could not extract target from script");
        throw std::runtime_error("Failed to extract target from MagicLock script");
    }
    const std::string pkhHex = extractPkhHex(scriptHex);
    if (pkhHex.empty()) {
        throw std::runtime_error("Failed to extract PKH from MagicLock script");
    }
    const std::string ownerAddr = base58FromPubKeyHashHex(pkhHex); // your existing helper

    Logger::log("[unlockMagicLock] target=" + target + " ownerAddr=" + ownerAddr);

    // 3) Build spending TX paying recipient (amount - fee)
    uint64_t fee = WALLET_MIN_BASE_FEE;
    if (locked.amount <= fee) throw std::runtime_error("Amount too small for fee");

    Transaction tx(false);
    tx.version  = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(lockTxid, lockVout);

    const uint64_t outAmt = locked.amount - fee;
    const std::string outScript = createP2PKHScriptHexFromAddress(recipient);
    tx.vout.emplace_back(outAmt, outScript);
    // The only output is the requested recipient payment. Never silently
    // reduce it to satisfy a future higher relay fee. If policy ever rises
    // above the 10,000-TRU-atom floor for this path, fail loudly instead.
    fee = applyWalletPolicyFee(
        tx, fee, WALLET_NO_FEE_BEARING_VOUT, "unlockMagicLock");
    tx.computeTxId();

    // 4) SIGHASH over the locked script
/*
    size_t posP2PKH = scriptHex.find("76a914");  // OP_DUP OP_HASH160 <20>
    if (posP2PKH == std::string::npos) {
        throw std::runtime_error("P2PKH tail not found in MagicLock script");
    }
    std::string p2pkhScriptHex = scriptHex.substr(posP2PKH);      // "76a914...88ac"
    std::vector<unsigned char> p2pkhScript = hexDecode(p2pkhScriptHex);

    const std::vector<unsigned char> sigHash = tx.getSigHash(0, p2pkhScript);
*/
    std::vector<unsigned char> fullScript = hexDecode(scriptHex);
    const std::vector<unsigned char> sigHash = tx.getSigHash(0, fullScript);
    Logger::log("[unlockMagicLock] Sighash for grinding: " + hexEncode(sigHash));

    // 5) Get correct keypair for owner address
    std::string privPEM = getPrivateKeyForAddress(ownerAddr); // (const overload already added)
    if (privPEM.empty()) throw std::runtime_error("Missing private key for lock owner");
    std::vector<unsigned char> pubKey = getPublicKeyForAddress(ownerAddr);

    // 6) Grind signature so HASH256(sig+SIGHASH_ALL) starts with <target>
    auto [sigBytes, ok] = grindSignature(sigHash, target, privPEM);
    if (!ok) throw std::runtime_error("Failed to grind matching signature");

    // 7) Build scriptSig = <sig> <pubkey>
    tx.vin[0].scriptSig.clear();

    // First signature (for CHECKSIG at the end)
    tx.vin[0].scriptSig.push_back(static_cast<unsigned char>(sigBytes.size()));
    tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(), sigBytes.begin(), sigBytes.end());

    // Second signature (for HASH256 + target matching)
    tx.vin[0].scriptSig.push_back(static_cast<unsigned char>(sigBytes.size()));
    tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(), sigBytes.begin(), sigBytes.end());

    // Public key
    tx.vin[0].scriptSig.push_back(static_cast<unsigned char>(pubKey.size()));
    tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(), pubKey.begin(), pubKey.end());

    tx.computeTxId();

    // 8) Manual validate (for clearer errors)
    const MempoolValidationStatus validation =
        blockchainPtr->mempool->validateTransaction(tx, blockchainPtr);
    Logger::log(
        std::string("[unlockMagicLock] manual validation: ") +
        (validation == MempoolValidationStatus::VALID ? "VALID" :
         validation == MempoolValidationStatus::BUSY ? "BUSY" : "INVALID"));
    if (validation == MempoolValidationStatus::BUSY) {
        throw std::runtime_error(
            "Unlock transaction validation busy - retry");
    }
    if (validation != MempoolValidationStatus::VALID) {
        throw std::runtime_error(
            "Unlock transaction failed validation - check logs for details");
    }

    // 9) Submit
    auto status = blockchainPtr->mempool->addTransaction(tx);
    if (status != MempoolAddStatus::SUCCESS) {
        std::string msg = "Failed to add unlock transaction to mempool. Status: ";
        msg += (status == MempoolAddStatus::INVALID) ? "INVALID" :
               (status == MempoolAddStatus::DUPLICATE) ? "DUPLICATE" :
               std::to_string((int)status);
        throw std::runtime_error(msg);
    }

    blockchainPtr->broadcastTransaction(tx);
    Logger::log("[unlockMagicLock] OK txid=" + tx.txid);
    return tx.txid;
}
/*
std::string Wallet::unlockMagicLock(const std::string& lockTxid, uint32_t lockVout, 
                                    const std::string& recipient) {
    Logger::log("[unlockMagicLock] === DEBUGGING UNLOCK PROCESS ===");
    Logger::log("[unlockMagicLock] Attempting to unlock: " + lockTxid + ":" + 
                std::to_string(lockVout));
    Logger::log("[unlockMagicLock] Recipient: " + recipient);
    
    // Get the locked UTXO
    UTXO lockedUtxo;
    if (!blockchainPtr->utxoSet.getUTXO(lockTxid, lockVout, lockedUtxo)) {
        throw std::runtime_error("MagicLock UTXO not found - may already be spent");
    }
    
    Logger::log("[unlockMagicLock] Found locked UTXO with amount: " + 
                std::to_string(lockedUtxo.amount));
    Logger::log("[unlockMagicLock] Lock script: " + lockedUtxo.scriptPubKey);
    
    // Parse the target prefix from the script
    std::string scriptHex = lockedUtxo.scriptPubKey;
    std::string targetPrefix = extractTargetFromMagicLockScript(scriptHex);
    
    if (targetPrefix.empty()) {
        Logger::log("[unlockMagicLock] ERROR: Failed to extract target prefix");
        Logger::log("[unlockMagicLock] Script: " + scriptHex);
        throw std::runtime_error("Failed to extract target prefix from MagicLock script");
    }
    
    Logger::log("[unlockMagicLock] Extracted target prefix: " + targetPrefix);
    
    // Build unlock transaction
    Transaction tx(false);
    tx.version = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(lockTxid, lockVout);
    
    // Output to recipient (minus fee)
    uint64_t fee = 10000;
    if (lockedUtxo.amount <= fee) {
        throw std::runtime_error("MagicLock amount too small to cover fee");
    }
    
    uint64_t outputAmount = lockedUtxo.amount - fee;
    std::string outScript = createP2PKHScriptHexFromAddress(recipient);
    tx.vout.emplace_back(outputAmount, outScript);
    
    Logger::log("[unlockMagicLock] Transaction structure:");
    Logger::log("[unlockMagicLock] - Input: " + lockTxid + ":" + std::to_string(lockVout));
    Logger::log("[unlockMagicLock] - Output amount: " + std::to_string(outputAmount) + " to " + recipient);
    Logger::log("[unlockMagicLock] - Output script: " + outScript);
    Logger::log("[unlockMagicLock] - Fee: " + std::to_string(fee));
    
    // Compute transaction ID before signing
    tx.computeTxId();
    Logger::log("[unlockMagicLock] Pre-sign TXID: " + tx.txid);
    
    // Get signing hash
    std::vector<unsigned char> scriptPubKey = hexDecode(scriptHex);
    std::vector<unsigned char> sigHash = tx.getSigHash(0, scriptPubKey);
    
    Logger::log("[unlockMagicLock] Computed sighash: " + bytesToHex(sigHash));
    
    // Grind for valid signature
    Logger::log("[unlockMagicLock] Starting signature grinding for prefix: " + targetPrefix);
    std::string privKey = getPrivateKeyForAddress(getCurrentAddress());
    auto [signature, found] = grindSignature(sigHash, targetPrefix, privKey);
    
    if (!found) {
        Logger::log("[unlockMagicLock] ERROR: Failed to find valid signature after max attempts");
        throw std::runtime_error("Failed to find valid signature after max attempts");
    }
    
    Logger::log("[unlockMagicLock] Found valid signature!");
    Logger::log("[unlockMagicLock] Signature: " + bytesToHex(signature));
    
    // Verify the signature produces the correct hash
    unsigned char sigHash1[SHA256_DIGEST_LENGTH];
    unsigned char sigHash2[SHA256_DIGEST_LENGTH];
    SHA256(signature.data(), signature.size(), sigHash1);
    SHA256(sigHash1, SHA256_DIGEST_LENGTH, sigHash2);
    std::string actualHash = bytesToHex(std::vector<unsigned char>(sigHash2, sigHash2 + SHA256_DIGEST_LENGTH));
    Logger::log("[unlockMagicLock] Signature hash: " + actualHash);
    Logger::log("[unlockMagicLock] Target prefix: " + targetPrefix);
    Logger::log("[unlockMagicLock] Hash starts with target: " + 
                std::string(actualHash.substr(0, targetPrefix.length()) == targetPrefix ? "YES" : "NO"));

    // Build unlock script
    std::vector<unsigned char> pubKey = deriveHDPublicKey(getCurrentIndex());
    tx.vin[0].scriptSig.clear();
    tx.vin[0].scriptSig.push_back(static_cast<unsigned char>(signature.size()));
    tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(), signature.begin(), signature.end());
    tx.vin[0].scriptSig.push_back(static_cast<unsigned char>(pubKey.size()));
    tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(), pubKey.begin(), pubKey.end());
    
    Logger::log("[unlockMagicLock] Built scriptSig: " + bytesToHex(tx.vin[0].scriptSig));
    Logger::log("[unlockMagicLock] Public key: " + bytesToHex(pubKey));
    
    // Compute final TXID
    tx.computeTxId();
    Logger::log("[unlockMagicLock] Final unlock transaction TXID: " + tx.txid);
    
    // DEBUG: Manually validate the transaction before adding to mempool
    Logger::log("[unlockMagicLock] === VALIDATING TRANSACTION MANUALLY ===");
    
    // Check if the transaction is valid
    MempoolValidationStatus manualValidation =
        blockchainPtr->mempool->validateTransaction(tx, blockchainPtr);
    Logger::log(
        "[unlockMagicLock] Manual validation result: " +
        std::string(
            manualValidation == MempoolValidationStatus::VALID ? "VALID" :
            manualValidation == MempoolValidationStatus::BUSY ? "BUSY" :
            "INVALID"));
    
    if (manualValidation == MempoolValidationStatus::BUSY) {
        throw std::runtime_error(
            "Unlock transaction validation busy - retry");
    }

    if (manualValidation != MempoolValidationStatus::VALID) {
        Logger::log("[unlockMagicLock] CRITICAL: Transaction failed manual validation!");
        
        // Try to get more specific error info
        Logger::log("[unlockMagicLock] Transaction details for debugging:");
        Logger::log("[unlockMagicLock] - Version: " + std::to_string(tx.version));
        Logger::log("[unlockMagicLock] - Inputs: " + std::to_string(tx.vin.size()));
        Logger::log("[unlockMagicLock] - Outputs: " + std::to_string(tx.vout.size()));
        Logger::log("[unlockMagicLock] - LockTime: " + std::to_string(tx.lockTime));
        Logger::log("[unlockMagicLock] - Is Coinbase: " + std::string(tx.isCoinbase ? "true" : "false"));
        
        // Check input validation specifically
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            Logger::log("[unlockMagicLock] Input " + std::to_string(i) + ":");
            Logger::log("[unlockMagicLock] - TXID: " + tx.vin[i].txid);
            Logger::log("[unlockMagicLock] - Vout: " + std::to_string(tx.vin[i].vout));
            Logger::log("[unlockMagicLock] - ScriptSig: " + bytesToHex(tx.vin[i].scriptSig));
            Logger::log("[unlockMagicLock] - Sequence: " + std::to_string(tx.vin[i].sequence));
        }
        
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            Logger::log("[unlockMagicLock] Output " + std::to_string(i) + ":");
            Logger::log("[unlockMagicLock] - Amount: " + std::to_string(tx.vout[i].amount));
            Logger::log("[unlockMagicLock] - Script: " + tx.vout[i].scriptPubKey);
        }
        
        throw std::runtime_error("Unlock transaction failed validation - check logs for details");
    }
    
    // Add to mempool
    MempoolAddStatus status = blockchainPtr->mempool->addTransaction(tx);
    if (status != MempoolAddStatus::SUCCESS) {
        std::string errorMsg = "Failed to add unlock transaction to mempool. Status: ";
        switch(status) {
            case MempoolAddStatus::INVALID:
                errorMsg += "INVALID";
                break;
            case MempoolAddStatus::DUPLICATE:
                errorMsg += "DUPLICATE";
                break;
            default:
                errorMsg += std::to_string(static_cast<int>(status));
        }
        Logger::log("[unlockMagicLock] Mempool error: " + errorMsg);
        throw std::runtime_error(errorMsg);
    }
    
    Logger::log("[unlockMagicLock] Successfully added to mempool");
    
    // Broadcast to network
    blockchainPtr->broadcastTransaction(tx);
    Logger::log("[unlockMagicLock] Broadcast to network");
    
    Logger::log("[unlockMagicLock] Successfully unlocked MagicLock with TXID: " + tx.txid);
    return tx.txid;
}

*/

//===========================================
// Unlock a MagicLock UTXO with SECRET
//===========================================
std::pair<std::string, std::string> Wallet::unlockMagicLockWithSecret(
    const std::string& lockTxid, 
    uint32_t lockVout,
    const std::string& recipient) {
    
    Logger::log("[unlockMagicLockWithSecret] Unlocking " + lockTxid);
    
    // First, perform the standard unlock
    std::string unlockTxid = unlockMagicLock(lockTxid, lockVout, recipient);
    
    // Now retrieve and decrypt the secret if it exists
    std::string decryptedSecret;
    
    // First check if we have stored secret metadata
    if (blockchainPtr && blockchainPtr->getStorage()) {
        LevelDBStorage* storage = blockchainPtr->getStorage();
        std::string storageKey = "magicLockSecret:" + lockTxid;
        std::string secretMeta;
        
        if (storage->getWithDataChecksum(storageKey, secretMeta)) {
            try {
                nlohmann::json meta = nlohmann::json::parse(secretMeta);
                std::string encKey = meta["encryptionKey"];
                std::string dataType = meta["dataType"];
                
                // Get the OP_RETURN data from the original transaction
                Transaction lockTx;
                if (blockchainPtr->getTransaction(lockTxid, lockTx)) {
                    for (const auto& out : lockTx.vout) {
                        if (out.scriptPubKey.substr(0, 2) == "6a") { // OP_RETURN
                            std::string opReturnData = extractOpReturnData(out.scriptPubKey);
                            
                            nlohmann::json opReturnMeta = nlohmann::json::parse(opReturnData);
                            if (opReturnMeta["type"] == "MAGIC_SECRET") {
                                std::string encryptedData = base64Decode(opReturnMeta["encrypted"]);
                                decryptedSecret = decryptData(encryptedData, encKey);
                                
                                Logger::log("[unlockMagicLockWithSecret] Secret decrypted successfully");
                                
                                // Handle different data types
                                if (dataType == "image" || dataType == "pdf") {
                                    std::string filename = "unlocked_" + lockTxid.substr(0, 8) + 
                                                          "." + dataType;
                                    saveDataToFile(filename, decryptedSecret);
                                    decryptedSecret = "File saved: " + filename;
                                }
                            }
                            break;
                        }
                    }
                }
            } catch (const std::exception& e) {
                Logger::log("[unlockMagicLockWithSecret] Error retrieving secret: " + std::string(e.what()));
            }
        } else {
            Logger::log("[unlockMagicLockWithSecret] No secret metadata found for " + lockTxid);
        }
    }
    
    return {unlockTxid, decryptedSecret};
}

//=====================================================================
//			EXTRACT the OP_RETURN MAGIC DATA
//=====================================================================
std::string Wallet::extractOpReturnData(const std::string& scriptHex) {
    if (scriptHex.substr(0, 2) != "6a") return "";
    
    size_t pos = 2;
    size_t dataLen = 0;
    
    // Parse length encoding
    if (pos + 2 <= scriptHex.size()) {
        std::string lenByte = scriptHex.substr(pos, 2);
        pos += 2;
        
        size_t len = std::stoul(lenByte, nullptr, 16);
        if (len <= 75) {
            dataLen = len;
        } else if (len == 0x4c && pos + 2 <= scriptHex.size()) {
            // OP_PUSHDATA1
            dataLen = std::stoul(scriptHex.substr(pos, 2), nullptr, 16);
            pos += 2;
        }
    }
    
    if (dataLen > 0 && pos + dataLen * 2 <= scriptHex.size()) {
        std::string dataHex = scriptHex.substr(pos, dataLen * 2);
        std::vector<unsigned char> dataBytes = hexDecode(dataHex);
        return std::string(dataBytes.begin(), dataBytes.end());
    }
    
    return "";
}

//=====================================================================
//                      DECRYPT MAGIC DATA
//=====================================================================
std::string Wallet::decryptData(const std::string& ciphertext, const std::string& keyHex) {
    // Simple XOR decryption (same as encryption for XOR)
    std::string decrypted;
    for (size_t i = 0; i < ciphertext.length(); i++) {
        unsigned char keyByte = keyHex[i % 32];
        decrypted += (char)(ciphertext[i] ^ keyByte);
    }
    return decrypted;
}

//=====================================================================
//                      MAGIC KEY DERIVE DATA
//=====================================================================
std::string Wallet::deriveDecryptionKeyFromUnlock(const std::string& txid, uint32_t vout) {
    std::string combined = txid + std::to_string(vout);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.length(), hash);
    return bytesToHex(std::vector<unsigned char>(hash, hash + 32));
}

//=====================================================================
//                      SAVE MAGIC DATA
//=====================================================================
bool Wallet::saveDataToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(data.c_str(), data.size());
    file.close();
    return true;
}


//=====================================================================
//				VOTING
//=====================================================================

std::string Wallet::castVote(
    const std::string& contractAddress,
    int voteOption)
{
    // fail closed on the pre-V1 wallet builder.
    //
    // The legacy implementation emitted OP_RETURN "VOTE:n" plus a small
    // payment to the contract script. That shape is not canonical Voting V1:
    // it does not consume the confirmed live anchor, does not bind TRUCALL to
    // vin[0] calldata, and cannot enforce stable-root/voter-marker semantics.
    //
    // Keep this method temporarily for source/API compatibility, but never
    // permit it to construct or broadcast a divergent voting transaction.
    Logger::log(
        "[castVote] Legacy vote builder blocked for contract " +
        contractAddress + " option=" + std::to_string(voteOption));
    throw std::runtime_error(
        "Legacy Wallet::castVote is disabled by Patch 17; use the canonical Voting V1 stable-root call path");
}

//=====================================================================
//			MINT TOKENS FROM CONTRACT
//=====================================================================

std::string Wallet::mintTokens(const std::string& contractAddress, uint64_t truAmount) {
    Logger::log("[mintTokens] Minting tokens from contract " + contractAddress + 
                " with " + std::to_string(truAmount) + " TRU atoms");

    // Parse contract address (txid:vout)
    std::string cTxid;
    uint32_t cVout = 0;
    if (!parseContractOutpoint(contractAddress, cTxid, cVout)) {
        throw std::runtime_error("Invalid contract address format");
    }

    // Get the contract UTXO to verify it exists
    UTXO contractUtxo;
    if (!blockchainPtr->utxoSet.getUTXO(cTxid, cVout, contractUtxo)) {
        throw std::runtime_error("Contract UTXO not found");
    }

    // Find a UTXO to pay from
    auto [utxoTxid, utxoVout] = findOneSpendableUtxo(getCurrentAddress(), 
                                                     blockchainPtr->mempool.get());
    if (utxoTxid.empty()) {
        throw std::runtime_error("No spendable UTXO for minting");
    }

    UTXO feeUtxo;
    if (!blockchainPtr->utxoSet.getUTXO(utxoTxid, utxoVout, feeUtxo)) {
        throw std::runtime_error("Failed to get fee UTXO");
    }

    // Build transaction
    Transaction tx;
    tx.version = 1;
    tx.lockTime = 0;
    tx.vin.emplace_back(utxoTxid, utxoVout);

    // Optional: OP_RETURN with mint request metadata
    std::string mintMeta = "MINT:" + contractAddress;
    std::vector<unsigned char> metaBytes(mintMeta.begin(), mintMeta.end());
    std::string opReturnHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + 
                              bytesToHex(metaBytes);
    tx.vout.emplace_back(0, opReturnHex);

    // Send truAmount to the contract script (this triggers minting)
    tx.vout.emplace_back(truAmount, contractUtxo.scriptPubKey);

    // Change output
    uint64_t fee = WALLET_MIN_BASE_FEE;
    uint64_t change = feeUtxo.amount - truAmount - fee;
    std::size_t feeBearingVout = WALLET_NO_FEE_BEARING_VOUT;
    if (change > 0) {
        std::string changeScript = createP2PKHScriptHexFromAddress(getCurrentAddress());
        tx.vout.emplace_back(change, changeScript);
        feeBearingVout = tx.vout.size() - 1;
    }

    fee = applyWalletPolicyFee(
        tx, fee, feeBearingVout, "mintTokens");

    // Sign and broadcast
    if (!signTransaction(tx)) {
        throw std::runtime_error("Failed to sign minting transaction");
    }

    std::string rawHex = hexEncode(tx.serializeBinary());
    if (!broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT)) {
        throw std::runtime_error("Failed to broadcast mint transaction");
    }

    return tx.txid;
}


std::string Wallet::createSmartContract(const std::string& type, const std::string& name, 
                                       const std::string& scriptText, const std::string& nodeIP, int port) {
    try {
        // Check if local blockchain is available
        if (!isLocalChainAvailable()) {
            throw std::runtime_error("No blockchain available");
        }
        
        const Blockchain& chain = getBlockchain();  // Get blockchain reference
        
        // Compile the script
        std::vector<unsigned char> scriptBytes = compileTextScript(scriptText);
        std::string scriptHex = bytesToHex(scriptBytes);
        
        // Build transaction
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        
        // Find UTXO
        std::string currentAddr = getCurrentAddress();
        auto [utxoTxid, utxoVout] = findOneSpendableUtxo(currentAddr, nullptr);
        if (utxoTxid.empty()) {
            throw std::runtime_error("No spendable UTXO available");
        }
        
        UTXO utxo;
        if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo)) {  // Changed from blockchain-> to chain.
            throw std::runtime_error("Failed to get UTXO");
        }
        
        tx.vin.emplace_back(utxoTxid, utxoVout);
        
        // OP_RETURN metadata
        std::string meta = "TRU_CONTRACT:" + name + ":" + type;
        std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
        std::string opReturnHex = "6a" + bytesToHex(std::vector<unsigned char>{static_cast<unsigned char>(metaBytes.size())}) + bytesToHex(metaBytes);
        tx.vout.emplace_back(0, opReturnHex);
        
        // Contract output
        tx.vout.emplace_back(0, scriptHex);
        
        // Change output
        uint64_t fee = WALLET_MIN_BASE_FEE;
        std::string changeScript = createP2PKHScriptHexFromAddress(currentAddr);
        tx.vout.emplace_back(utxo.amount - fee, changeScript);
        
        fee = applyWalletPolicyFee(
            tx, fee, tx.vout.size() - 1, "createSmartContract");

        // Sign and broadcast
        if (!signTransaction(tx)) {
            throw std::runtime_error("Failed to sign transaction");
        }
        
        std::string rawHex = hexEncode(tx.serializeBinary());
        bool broadcast = broadcastTxToExternalNode(rawHex, nodeIP, port);
        
        // Return result
        std::stringstream result;
        result << "Contract '" << name << "' deployed.\n";
        result << "ScriptHex: " << scriptHex << "\n";
        result << "TxID: " << tx.txid << "\n";
        result << "Contract Address: " << tx.txid << ":1\n";
        result << (broadcast ? "Broadcast succeeded." : "Broadcast failed.");
        
        return result.str();
        
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Failed to create contract: ") + e.what());
    }
}
