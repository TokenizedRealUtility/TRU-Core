#pragma once

#include "wallet_security_controller_v1.h"
#include <memory>
#ifndef WALLET_H
#define WALLET_H
#include <tuple>
#include <array>
#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <wally_bip32.h>  // For BIP32 key derivation
#include "tru_network_params.h"
#include "blockchain.h"
#include "tx.h"
#include "tokens.h"
#include "crypto_ecdsa.h"    // Assuming this defines ECDSAKey
#include "hdwallet.h"
#include "mempool.h"
#include <nlohmann/json.hpp>
#define HASH160_LEN 20
#define EC_PUBLIC_KEY_LEN 33
#define EC_PRIVATE_KEY_LEN 32


struct TransactionInfo {
    std::string txid;
    std::string type;
    std::string address;
    double amount;
    uint32_t timestamp;
    int confirmations;
    int blockHeight;
};

struct SmartContractInfo {
    std::string name;
    std::string type;
    std::string address;
    std::string status;
    uint64_t value;
    uint32_t createdAt;
    std::string scriptHex;
};

struct ContractDetails {
    std::string name;
    std::string type;
    std::string scriptHex;
    std::string state;
    bool canExecute;
};

struct MultisigEscrowCreateResult {
    std::string txid;
    std::uint32_t contractVout{1};
    std::string scriptHex;
    std::uint64_t amountAtoms{0};
    std::uint64_t feeAtoms{0};
    std::array<std::string, 3> pubkeysHex{};
};

struct MultisigEscrowSignaturePackage {
    std::string contractTxid;
    std::uint32_t contractVout{1};
    std::string recipient;
    std::string sighashHex;
    std::string signerPubkeyHex;
    std::string signatureHex;
    std::uint64_t releaseAmountAtoms{0};
    std::uint64_t feeAtoms{0};
};

struct MultisigEscrowRedeemResult {
    std::string txid;
    std::string contractTxid;
    std::uint32_t contractVout{1};
    std::string recipient;
    std::uint64_t releaseAmountAtoms{0};
    std::uint64_t feeAtoms{0};
    std::array<std::string, 2> signerPubkeysHex{};
};

// HTLC-01C: chain-agnostic creation inputs/results for one canonical
// Hashed Timelock Contract / Atomic Swap V1 output.
struct HtlcAtomicSwapSecretV1 {
    std::string preimageHex;
    std::string hash160Hex;
};

struct HtlcAtomicSwapCreateResult {
    std::string txid;
    std::uint32_t contractVout{1};
    std::string scriptHex;
    std::uint64_t amountAtoms{0};
    std::uint64_t feeAtoms{0};
    std::string secretHash160Hex;
    std::string claimPubkeyHex;
    std::string refundPubkeyHex;
    std::uint32_t refundLockTime{0};
};

// SWAP-FRESH-01B4D2: signed canonical TRU HTLC funding transaction prepared
// entirely before broadcast. rawTxHex contains the signed immutable transaction
// bytes and is intended only for the authenticated local swap Agent journal.
struct HtlcAtomicSwapPrepareResult {
    std::string operationId;
    std::string txid;
    std::uint32_t contractVout{1};
    std::string rawTxHex;
    std::string scriptHex;
    std::uint64_t amountAtoms{0};
    std::uint64_t feeAtoms{0};
    std::string secretHash160Hex;
    std::string claimPubkeyHex;
    std::string refundPubkeyHex;
    std::uint32_t refundLockTime{0};
    bool reservationActive{false};
    std::uint32_t reservedInputCount{0};
    bool idempotentReuse{false};
};

struct HtlcPreparedFundingStatusV1 {
    bool found{false};
    std::string operationId;
    std::string state;
    std::string preparedTxid;
    std::uint32_t contractVout{1};
    std::uint32_t reservedInputCount{0};
    bool reservationActive{false};
    bool inMempool{false};
};

struct HtlcPreparedFundingBroadcastResult {
    std::string operationId;
    std::string preparedTxid;
    std::uint32_t contractVout{1};
    bool dryRun{true};
    bool alreadyInMempool{false};
    bool broadcast{false};
    bool reservationActive{false};
};

struct HtlcAtomicSwapSpendResult {
    std::string txid;
    std::string contractTxid;
    std::uint32_t contractVout{1};
    std::string branch;
    std::string recipient;
    std::string sighashHex;
    std::string signerPubkeyHex;
    std::string secretHash160Hex;
    std::uint32_t refundLockTime{0};
    std::uint64_t releaseAmountAtoms{0};
    std::uint64_t feeAtoms{0};
};
/**
 * @brief BIP44-like derivation path structure
 */
struct DerivationPath {
    uint32_t purpose = 44;   // BIP44
    uint32_t coin_type = tru_network::TRU_BIP44_COIN_TYPE;  // TRU project-local coin type
    uint32_t account = 0;
    uint32_t change = 0;
};

// SEC-14G — encrypted-first bootstrap for a brand-new wallet.
// Creates only the authenticated encrypted artifact set; no plaintext seed or
// private-wallet file is ever published. The caller supplies a locally entered
// passphrase and receives only the new public address.
bool bootstrapEncryptedWalletV1(
    const std::string& walletBasePath,
    const std::string& passphrase,
    std::string& outAddress,
    std::string* errorOut = nullptr);

/**
 * @brief Represents a local UTXO entry discovered in our wallet,
 * if you maintain a local list separate from the chain's data.
 */
struct LocalUtxo {
    std::string txid;
    uint32_t    vout;
    uint64_t    amount;        ///< in TRU atoms
    std::string scriptPubKey;  ///< textual or raw
};

/**
 * @brief The Wallet class
 * 
 * Manages HD seed, derived addresses, local UTXOs, 
 * plus logic for sending transactions (both local chain and RPC modes).
 */
// TRU-SWAP-B — deterministic encrypted-wallet role keys.
// V1 reserves HD child index 1 for claim and index 2 for refund.
// Only public material leaves the wallet API.
struct TruSwapRoleKeysV1 {
    std::string claimAddress;
    std::string claimPubkeyHex;
    std::uint32_t claimIndex{1U};
    std::string refundAddress;
    std::string refundPubkeyHex;
    std::uint32_t refundIndex{2U};
};

// TRU-SWAP-FRESH-01A — public-only deterministic per-swap role material.
// allocationId is public 256-bit metadata generated before canonical swap
// creation. No private key, seed, or passphrase is carried by this object.
struct TruFreshSwapRoleKeysV1 {
    std::string allocationId;
    std::string claimAddress;
    std::string claimPubkeyHex;
    std::string refundAddress;
    std::string refundPubkeyHex;
};

class Wallet {
public:
    // Constructors
    explicit Wallet(const std::string& filePath, Blockchain *chainPtr = nullptr, const std::string& nodeIP = "", int nodePort = 0);
    Wallet();
    ~Wallet();

    // Creates a brand-new random wallet, generating a master seed
    std::string create_wallet(const std::string& filePath);

    // Load/save from a file. The file is *not* encrypted in this demo.
    bool loadFromFile(const std::string &filepath);
    bool saveToFile(const std::string &filepath) const;

    // Generate a new address from the HD derivation path
    std::string generateNewAddress();

    // Return the last or "current" address
    std::string getCurrentAddress() const;

    // Return all derived addresses
    std::vector<std::string> getAllAddresses() const;

    uint32_t getCurrentIndex() const;

    // Manually set an address as "current"
    void setCurrentAddress(const std::string &address);

    // Return a private key (PEM) for the given address
    std::string getPrivateKeyForAddress(const std::string &addr);
    std::string getPrivateKeyForAddress(const std::string &addr) const;
    // (Local chain) Mine funds to your address by calling the chain’s CPU miner
    std::string mineFundsToMyAddress();

    // (Local chain) Check wallet's total balance, optionally including unconfirmed
    double check_balance(bool includeUnconfirmed = false) const;

    // (Local chain) Start CPU mining => reward paid to current address
    std::string mine();

    //bool registerToken(const std::string& tokenID, const std::string& owner, uint64_t amount);
    std::string generateDeterministicVisual(const std::string& id, const std::string& imageUrl);

    // (Local chain) Construct, sign, and broadcast a transaction 
    // to send an exact integer TRU-atom amount to 'recipient'.
    std::string send_transaction(const std::string &recipient,
                                 uint64_t amountAtoms,
                                 const std::string &nodeIP = "127.0.0.1",
                                 int nodePort = tru_network::MAINNET_RPC_PORT);

    // MS-01C: construct, fund, sign and relay one canonical bare 2-of-3
    // Multisig / Escrow V1 output. Spending/redemption is activated in MS-01D.
    MultisigEscrowCreateResult createMultisigEscrowV1(
        const std::array<std::string, 3>& compressedPubkeysHex,
        std::uint64_t amountAtoms);

    // MS-01D: deterministic offline/co-signer signature package for one
    // confirmed Multisig / Escrow V1 outpoint. No transaction is broadcast.
    MultisigEscrowSignaturePackage signMultisigEscrowV1(
        const std::string& contractTxid,
        std::uint32_t contractVout,
        const std::string& recipientAddress,
        const std::string& signerCompressedPubkeyHex) const;

    // MS-01D: verify two independent signature packages, assemble the
    // canonical OP_0 <sig1> <sig2> unlock in on-chain pubkey order, and relay.
    MultisigEscrowRedeemResult redeemMultisigEscrowV1(
        const std::string& contractTxid,
        std::uint32_t contractVout,
        const std::string& recipientAddress,
        const std::array<std::string, 2>& signerCompressedPubkeysHex,
        const std::array<std::string, 2>& signaturesHex);

    // HTLC-01C: generate a cryptographically random 32-byte swap secret and
    // return both its raw hex preimage and HASH160 commitment. This does not
    // mutate the wallet or chain.
    HtlcAtomicSwapSecretV1 generateHtlcAtomicSwapSecretV1() const;

    // HTLC-01C: construct, fund, sign and relay one canonical HTLC / Atomic
    // Swap V1 output. Claim/refund spending is activated in HTLC-01D.

    // SWAP-FRESH-01B4D2: construct and sign the exact canonical HTLC funding
    // transaction but DO NOT submit it to the mempool. The returned txid and
    // raw bytes can be durably journaled before a later idempotent broadcast.
    HtlcAtomicSwapPrepareResult prepareHtlcAtomicSwapV1(
        const std::string& secretHash160Hex,
        const std::string& claimCompressedPubkeyHex,
        const std::string& refundCompressedPubkeyHex,
        std::uint32_t refundLockTime,
        std::uint64_t amountAtoms,
        const std::string& operationId);

    // TRU SWAP GROUP-01: local persistent reservation/status/broadcast barrier.
    // All methods are authenticated by their RPC handlers. The broadcast method
    // remains environment-gated until dual-chain funding activation.
    HtlcPreparedFundingStatusV1 getPreparedHtlcFundingStatusV1(
        const std::string& operationId) const;

    HtlcPreparedFundingStatusV1 releasePreparedHtlcFundingV1(
        const std::string& operationId,
        const std::string& expectedPreparedTxid);

    HtlcPreparedFundingBroadcastResult broadcastPreparedHtlcFundingV1(
        const std::string& operationId,
        const std::string& expectedPreparedTxid,
        bool dryRun);

    HtlcAtomicSwapCreateResult createHtlcAtomicSwapV1(
        const std::string& secretHash160Hex,
        const std::string& claimCompressedPubkeyHex,
        const std::string& refundCompressedPubkeyHex,
        std::uint32_t refundLockTime,
        std::uint64_t amountAtoms);

    // HTLC-01D: spend the claim branch with a matching binary preimage and
    // the wallet-owned claim private key encoded in the canonical lock.
    HtlcAtomicSwapSpendResult claimHtlcAtomicSwapV1(
        const std::string& contractTxid,
        std::uint32_t contractVout,
        const std::string& recipientAddress,
        const std::string& preimageHex,
        const std::string& freshAllocationId = "");

    // HTLC-01D: after parent-chain MTP reaches the canonical refund timestamp,
    // spend the refund branch using the wallet-owned refund private key.
    HtlcAtomicSwapSpendResult refundHtlcAtomicSwapV1(
        const std::string& contractTxid,
        std::uint32_t contractVout,
        const std::string& recipientAddress,
        const std::string& freshAllocationId = "");

    // (RPC-based) sendTransaction approach for a standalone wallet
    std::string send_transaction_rpc(const std::string &recipientAddr,
                                     double amountCoins,
                                     const std::string &nodeIP,
                                     int nodePort);

    // Issue extended tokens (FT, NFT, SFT, NCFT) on the local chain

    std::string issueExtendedFT(const std::string &tokenID,
                                uint64_t totalSupply,
                                const std::string &name,
                                const std::string &symbol,
                                const std::string &desc,
                                const std::string &imageUrl,
                                uint32_t decimals,
                                const std::unordered_map<std::string, std::string> &additionalMeta = {});

    std::string issueExtendedNFT(const std::string &nftID,
                                 const std::string &nftName,
                                 const std::string &desc,
                                 const std::string &imageUrl,
                                 const std::string &creator,
                                 const std::string &externalLink,
                                 const std::unordered_map<std::string, std::string> &additionalMeta = {});

    std::string issueExtendedSFT(const std::string &tokenID,
                                 uint64_t totalSupply,
                                 const std::string &name,
                                 const std::string &symbol,
                                 const std::string &desc,
                                 const std::string &imageUrl,
                                 uint32_t decimals,
                                 const std::unordered_map<std::string, std::string> &additionalMeta = {});

    std::string issueExtendedNCFT(const std::string &tokenID,
                                  uint64_t quantity,
                                  const std::string &name,
                                  const std::string &desc,
                                  const std::string &imageOrMediaUrl,
                                  const std::unordered_map<std::string, std::string> &additionalMeta = {});

    std::string inscribeTRUScript(const std::string& humanData,
                                  const std::string& ownerAddress);

   std::vector<TRUScriptInfo> getTRUScripts(const std::string& ownerAddress) const;

    std::string transferExtendedToken(const std::string &oldTxid,
                                      uint32_t oldVout,
                                      uint64_t quantityToSend,
                                      const std::string &newOwnerAddress);

    // List the tokens in the wallet
    std::string listMyTokens() const;
    std::string listMyTokensFancy() const;

    // For a quick token UTXO search
    std::tuple<std::string, uint32_t, uint32_t> findTokenUTXO(const std::string &tokenID, const std::string &senderAddress) const;
    // High-level: find & send
    //std::string sendToken(const std::string &tokenID, uint64_t quantity, const std::string &recipient);
    std::string sendToken(const std::string &tokenID, uint64_t quantity, const std::string &recipient, const std::string &senderAddress);
    // TOKEN-BURN-01: retire one current token-control holding by transferring
    // its complete raw amount to the canonical burn sink. Non-consensus.
    std::string burnToken(const std::string &tokenID, const std::string &senderAddress);
    // For a direct coin-based UTXO search
    std::pair<std::string, uint32_t> findOneCoinUtxo(const std::string &address) const;
    //std::pair<std::string, uint32_t> findOneSpendableUtxo(const std::string &address) const;
    //std::pair<std::string, uint32_t> findOneSpendableUtxo(const std::string &address, const Mempool* mempool) const;
    std::pair<std::string, unsigned int> findOneSpendableUtxo(const std::string& address, const Mempool* mempool) const;
    // Debug prints
    void debugPrintWalletAddressHashes() const;

    // RPC bridging methods (standalone usage)
    bool rpcBroadcastTx(const std::string &rawHex,
                        const std::string &nodeIP,
                        int nodePort);

    bool rpcGetTokenData(const std::string &nodeIP, int nodePort,
                         const std::string &txid, uint32_t vout,
                         ExtendedTokenData &outData);

    std::vector<UTXO> getUTXOsForAddressRPC(const std::string& address, const std::string& nodeIP, int nodePort) const;

    std::pair<std::string, uint32_t> rpcFindOneCoinUtxo(const std::string &nodeIP,
                                                        int nodePort,
                                                        const std::string &address);

    uint64_t rpcGetUtxoValue(const std::string &nodeIP, int nodePort,
                             const std::string &txid, uint32_t vout);

    //std::vector<std::tuple<std::string, uint32_t, uint64_t>>rpcListUnspent(const std::string &nodeIP, int nodePort, const std::string &address) const;
    std::vector<UTXO> rpcListUnspent(const std::string &nodeIP, int nodePort, const std::string &address) const;
    // Update local UTXO set from chain (optional usage)
    void updateLocalUTXOSetFromChain();

    // Accessors
    const Blockchain& getBlockchain() const;
    void addTransaction(const Transaction &tx);
    uint32_t getAddressIndex() const { return addressIndex; }
    std::string getHDPrivateKey(uint32_t index) const { return deriveHDPrivateKey(index); }

    // SEC-14D.1: explicit, observable security mode. Production remains
    // LEGACY_PLAINTEXT until SEC-14E performs verified migration.
    WalletSecurityModeV1 getWalletSecurityMode() const noexcept {
        return walletSecurityController_->mode();
    }
    const char* getWalletSecurityModeName() const noexcept {
        return walletSecurityController_->modeName();
    }
    bool isWalletPrivateAccessAllowed() const noexcept {
        return walletSecurityController_->privateAccessAllowed();
    }
    void requirePrivateAccess(const char* operation) const {
        walletSecurityController_->requirePrivateAccess(operation);
    }

    // SEC-14D.2 transition API. No direct enum setter exists.
    // SEC-14E migration will call beginEncryptedWalletModeForMigration()
    // only after encrypted artifacts have been safely created/verified.
    void beginEncryptedWalletModeForMigration() noexcept {
        walletSecurityController_->beginEncryptedModeForMigration();
    }
    bool unlockEncryptedWallet(
        const std::vector<std::uint8_t>& encryptedSeed,
        const std::vector<std::uint8_t>& encryptedPrivateMaterial,
        const std::string& passphrase,
        std::string* errorOut = nullptr) {
        return walletSecurityController_->unlockEncrypted(
            encryptedSeed, encryptedPrivateMaterial, passphrase, errorOut);
    }
    void lockEncryptedWallet() noexcept {
        walletSecurityController_->lockEncrypted();
    }

    // SEC-14E.3.2: authenticate canonical encrypted wallet envelopes.
    bool unlockEncryptedWalletFromFiles(
        const std::string& passphrase,
        std::string* errorOut = nullptr);

    // SEC-14E.3.4A: authenticated encrypted persistence foundation.
    // Explicit passphrase is required at the write boundary.
    bool persistEncryptedWalletSnapshot(
        const std::string& passphrase,
        std::string* errorOut = nullptr) const;

    // SEC-14E.3.4F.1: first controlled encrypted mutation API.
    // Changes only currentIndex; private material is not changed.
    bool setCurrentAddressEncrypted(
        const std::string& address,
        const std::string& passphrase,
        std::string* errorOut = nullptr);


    // WALLET-ADDRESS-01: generate the next canonical HD receive address from
    // the authenticated encrypted session. No passphrase/private key crosses RPC.
    bool generateNewAddressEncrypted(
        std::string& addressOut,
        std::string& publicKeyHexOut,
        std::uint32_t& indexOut,
        std::string* errorOut = nullptr);

    // TRU-SWAP-B: deterministic public view of reserved swap role keys.
    // Requires the encrypted wallet to be authenticated/unlocked.
    TruSwapRoleKeysV1 getSwapRoleKeysV1() const;

    // TRU-SWAP-FRESH-01A: derive fresh public claim/refund destinations from
    // one canonical 64-lowercase-hex allocationId. Requires an authenticated
    // wallet session. Private material never leaves the wallet API.
    TruFreshSwapRoleKeysV1 deriveFreshSwapRoleKeysV1(
        const std::string& allocationId) const;

    // TRU-SWAP-FRESH-01B1: re-derive exactly one fresh per-swap role
    // internally and sign a 32-byte HTLC sighash. Private key material
    // never leaves Wallet and is never returned over RPC.
    std::vector<unsigned char> signFreshSwapRoleDigestV1(
        const std::string& allocationId,
        std::uint32_t role,
        const std::vector<unsigned char>& expectedCompressedPubkey,
        const std::vector<unsigned char>& sighash) const;


    // One-time/idempotent provisioning of child indices 1 (claim) and 2
    // (refund). Private material is added only to the authenticated session
    // and committed through the existing journaled encrypted persistence path.
    bool provisionSwapRoleKeysV1(
        const std::string& passphrase,
        TruSwapRoleKeysV1& out,
        std::string* errorOut = nullptr);



    // HD derivation methods
    std::string deriveHDPrivateKey(uint32_t index) const;
    std::string deriveHDAddress(uint32_t index) const;
    std::vector<unsigned char> deriveHDPublicKey(uint32_t index) const; // Added for consistency
    uint64_t rpcGetUtxoValue(const std::string &nodeIP, int nodePort, const std::string &txid, uint32_t vout) const;
    bool signTransaction(Transaction &tx, const std::string &nodeIP = "", int nodePort = 0) const;
    bool broadcastTxToExternalNode(const std::string &txHex,
                                   const std::string &nodeIP,
                                   int nodePort);

    // New method to retrieve addresses
    std::vector<std::string> getAddresses() const {
        std::lock_guard<std::mutex> lock(addressesMutex); // Lock the mutex
        return addresses; // Return a copy of the addresses vector
    }

    void addAddress(const std::string& address) {
        std::lock_guard<std::mutex> lock(addressesMutex);
        if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
            addresses.push_back(address);
        }
    }

    std::vector<std::pair<std::string, double>> getAddressesWithBalance() const;

   void addKeyPair(const std::string& privateKey, const std::string& address);

   void forceClearUTXOCache();

    void addLocalUTXO(const std::string& txid,
                      uint32_t vout,
                      uint64_t amount,
                      const std::string& scriptPubKey);
    void removeLocalUTXO(const std::string& txid,
                         uint32_t vout);
    bool ownsAddress(const std::string& address) const;
    double getAddressBalance(const std::string& addr) const;
    std::string importPrivateKey(const std::string& privKeyHex);
    bool isLocalChainAvailable() const { return isLocalChain; }
    Transaction createSocialPostTransaction(const std::string& fromDID, const std::string& message, const std::vector<std::string>& tags, const std::string& privateKey);
    void addTokenUTXO(const std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData, std::string>& tokenUtxo);
    const std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData, std::string>>& getTokenUTXOs() const;
    std::set<std::pair<std::string, uint32_t>> getControllingUtxos(const std::string& address) const;
    std::string transferTRUScript(const std::string& inscriptionTxid, const std::string& newOwnerAddress);
    int getConnectedPeerCount() const {
        if (blockchainPtr && isLocalChain) {
            return blockchainPtr->getConnectedPeerCount();
        }
        return 0;
    }
    std::string createSmartContract(const std::string& type, const std::string& name, const std::string& scriptText, const std::string& nodeIP, int port);
    std::vector<SmartContractInfo> getSmartContracts();
    ContractDetails getContractDetails(const std::string& address);
    std::string getPubKeyHashForAddress(const std::string& address);
    std::string redeemHashLock(const std::string& contractAddr, const std::string& preimage);
    std::string redeemTimeLock(const std::string& contractAddr);
    std::string executeOracleContract(const std::string& contractAddr);
    std::vector<TransactionInfo> getTransactionHistory(const std::vector<std::string>& addresses) const;
    std::string deriveContractAddress(const std::string& txid, uint32_t vout);
    std::string createMagicLockScript(const std::string& targetPrefix, const std::string& pubKeyHash);
    std::string createMagicLock(uint64_t amount, const std::string& targetPrefix);
    std::string unlockMagicLock(const std::string& lockTxid, uint32_t lockVout, const std::string& recipient);
    std::string extractPkhFromMagicLock(const std::string& scriptHex) const;
    std::string base58FromPubKeyHashHex(const std::string& pkhHex) const;
    std::vector<unsigned char> getPublicKeyForAddress(const std::string& address) const;
    bool hasMatchingPublicKeyForAddress(const std::string& address) const;
    std::string extractOpReturnData(const std::string& scriptHex); 
    std::pair<std::string, std::string> unlockMagicLockWithSecret(const std::string& lockTxid, uint32_t lockVout, const std::string& recipient); 
    std::string deriveEncryptionKey(const std::string& targetPrefix, const std::string& pubKeyHash); 
    std::string buildOpReturnScript(const std::string& data);
    // Overloaded createMagicLock with secret data support
    std::string createMagicLock(uint64_t amount, const std::string& targetPrefix,const std::string& secretData, const std::string& dataType);
    // Encryption/Decryption methods
    std::string encryptData(const std::string& plaintext, const std::string& keyHex);
    std::string decryptData(const std::string& ciphertext, const std::string& keyHex);
    std::string deriveDecryptionKeyFromUnlock(const std::string& txid, uint32_t vout);
    // File saving for binary data
    bool saveDataToFile(const std::string& filename, const std::string& data);
    void storeMagicLockSecret(const std::string& txid, const std::string& targetPrefix, const std::string& dataType, const std::string& encryptionKeyHex);
    std::string castVote(const std::string& contractAddress, int voteOption);
    std::string mintTokens(const std::string& contractAddress, uint64_t truAmount);
private:
    std::string m_filePath;
    Blockchain *m_chain;
    const std::string walletFilePath;
    Blockchain* blockchainPtr;          ///< Local chain pointer (if any)
    bool isLocalChain;                  ///< Whether we have a local chain
    std::string nodeIP;       // New: RPC node IP for standalone mode
    int nodePort;             // New: RPC node port for standalone mode
    std::vector<unsigned char> masterSeed; ///< 64-byte random seed (fixed type)
    HDWallet hdwallet;
    DerivationPath derivationPath;      ///< e.g., (44, 0, 0, 0)
    uint32_t addressIndex = 0;          ///< How many derived so far
    uint32_t currentIndex = 0;
    std::vector<std::string> addresses; ///< Derived addresses
    mutable std::mutex localUtxoMutex;
    std::unordered_map<std::string, LocalUtxo> localUtxos;
    const Mempool* mempool;
    mutable std::mutex addressesMutex;
    // WALLET-ADDRESS-01: serializes authenticated public-wallet mutations.
    mutable std::mutex encryptedMutationMutex_;
    std::unordered_map<std::string, std::string> privateKeys;

    // WALLET-ADDRESS-01: public metadata contains no secret material, so an
    // already-authenticated encrypted session can durably publish it without
    // retaining or accepting the wallet passphrase over RPC.
    bool persistEncryptedWalletPublicMetadata(
        std::string* errorOut = nullptr);

    // SEC-14D.2: the controller exclusively owns security mode + secret
    // session transitions. There is intentionally no independent mode member.
    std::unique_ptr<WalletSecurityControllerV1> walletSecurityController_ =
        std::make_unique<WalletSecurityControllerV1>();
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint64_t, ExtendedTokenData, std::string>> localTokenUtxos;
    uint64_t calculateCurrentSatNumber();
    uint64_t getBlockReward(uint32_t height);

    std::pair<std::vector<unsigned char>, bool> grindSignature(
        const std::vector<unsigned char>& msgHash,
        const std::string& targetPrefix,
        const std::string& privateKeyPEM);
    
    // Wallet helper declaration.
    std::string extractTargetFromMagicLockScript(const std::string& scriptHex) const;
};

#endif // WALLET_H
