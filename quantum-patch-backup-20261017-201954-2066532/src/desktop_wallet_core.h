#pragma once

#include <cstdint>
#include "tru_desktop_07_model.h"
#include <string>
#include <vector>

struct DesktopWalletUtxo {
    std::string txid;
    std::uint32_t vout = 0;
    std::uint64_t amountAtoms = 0;
    std::string scriptPubKey;
    std::uint32_t keyIndex = 0;
};

struct DesktopWalletSignedTx {
    std::string txid;
    std::string rawHex;
    std::uint64_t inputAtoms = 0;
    std::uint64_t sendAtoms = 0;
    std::uint64_t feeAtoms = 0;
    std::uint64_t changeAtoms = 0;
};

class DesktopWalletCore {
public:
    DesktopWalletCore();
    ~DesktopWalletCore();

    DesktopWalletCore(const DesktopWalletCore&) = delete;
    DesktopWalletCore& operator=(const DesktopWalletCore&) = delete;

    bool exists(const std::string& path) const;
    bool create(const std::string& path,
                const std::string& passphrase,
                std::string* errorOut = nullptr);
    bool unlock(const std::string& path,
                const std::string& passphrase,
                std::string* errorOut = nullptr);
    void lock() noexcept;
    bool isUnlocked() const noexcept { return unlocked_; }

    std::uint32_t addressCount() const noexcept { return nextIndex_; }
    std::string address(std::uint32_t index) const;
    std::vector<std::string> addresses() const;
    std::string currentAddress() const;

    bool createNextAddress(const std::string& path,
                           const std::string& passphrase,
                           std::string& addressOut,
                           std::string* errorOut = nullptr);

    bool backup(const std::string& walletPath,
                const std::string& backupPath,
                std::string* errorOut = nullptr) const;
    bool restoreBackup(const std::string& backupPath,
                       const std::string& walletPath,
                       const std::string& passphrase,
                       std::string* errorOut = nullptr);

    // This is a full recovery secret, equivalent to a seed/private key.
    // It is intentionally not called BIP39: V1 preserves TRU's existing
    // canonical 64-byte HD seed exactly.
    std::string recoveryCode() const;
    bool restoreRecovery(const std::string& recoveryCode,
                         const std::string& walletPath,
                         const std::string& newPassphrase,
                         std::string* errorOut = nullptr);

    bool validateAddress(const std::string& address) const;
    std::string scriptForAddress(const std::string& address) const;

    DesktopWalletSignedTx buildAndSign(
        const std::vector<DesktopWalletUtxo>& inputs,
        const std::string& recipient,
        std::uint64_t amountAtoms,
        std::uint64_t requestedFeeAtoms) const;

    // Read a prepared transaction independently of the RPC builder.
    // This cannot sign or broadcast anything and exposes no keys.
    void assertPreparedOneInputV1(const std::string& unsignedTxHex,
                                  const std::string& expectedTxid,
                                  std::uint32_t expectedVout) const;
    std::vector<tru_desktop_07::Output> inspectPreparedOutputs(
        const std::string& unsignedTxHex) const;
    std::string inspectPreparedMetadataTail(
        const std::string& unsignedTxHex) const;
    std::string inspectPreparedMetadataJson(
        const std::string& unsignedTxHex) const;

    // Sign an unsigned TRU transaction built by a connected Core while
    // keeping every private key inside this Desktop wallet. The supplied
    // descriptors must match every transaction input exactly.
    DesktopWalletSignedTx signPrepared(
        const std::string& unsignedTxHex,
        const std::vector<DesktopWalletUtxo>& signingInputs) const;

    // 07B Voting V1: preserve exact canonical call data on vin[0], sign only
    // vin[1] using this standalone wallet's fee UTXO. Fail closed on outputs.
    DesktopWalletSignedTx signCanonicalVotingV1Ballot(
        const std::string& unsignedTxHex,
        const DesktopWalletUtxo& voterFeeInput,
        const std::string& expectedLiveAnchor,
        std::uint64_t expectedAnchorAtoms,
        const std::string& expectedUnlockScriptHex,
        const std::string& expectedCallScriptHex) const;

    // 07B: standalone self-custody redemption; never calls Core's wallet.
    // Exact confirmed UTXO amounts/scripts are retrieved from local Core, then
    // revalidated here. Hash preimages and private keys never enter RPC.
    DesktopWalletSignedTx redeemCanonicalHashLock(
        const std::string& txid, std::uint32_t vout,
        std::uint64_t amountAtoms, const std::string& scriptHex,
        const std::string& preimage, const std::string& destination) const;
    DesktopWalletSignedTx redeemCanonicalTimeLock(
        const std::string& txid, std::uint32_t vout,
        std::uint64_t amountAtoms, const std::string& scriptHex,
        std::uint32_t confirmedParentMtp, const std::string& destination) const;

    // Sign a domain-separated authorization message with a wallet address.
    // Used for actions such as exact AI-evolution commit authorization.
    bool signMessageSha256(
        const std::string& address,
        const std::string& canonicalMessage,
        std::string& publicKeyHexOut,
        std::string& signatureHexOut,
        std::string* errorOut = nullptr) const;

    static bool parseAmount(const std::string& text,
                            std::uint64_t& atomsOut,
                            std::string* errorOut = nullptr);
    static std::string formatAmount(std::uint64_t atoms);

private:
    std::vector<std::uint8_t> seed_;
    std::uint32_t nextIndex_ = 0;
    bool unlocked_ = false;
    bool memoryLocked_ = false;

    static constexpr std::uint64_t kAtomsPerTru = 100000000ULL;
    static constexpr std::uint64_t kDustAtoms = 546ULL;
    static constexpr std::uint64_t kMinimumFeeAtoms = 10000ULL;

    void setSeed(const std::vector<std::uint8_t>& seed);
    std::vector<std::uint8_t> makePayload() const;
    bool loadPayload(const std::vector<std::uint8_t>& plain,
                     std::string* errorOut);
    bool persist(const std::string& path,
                 const std::string& passphrase,
                 std::string* errorOut) const;

    std::vector<std::uint8_t> derivePrivateAny(std::uint32_t index) const;
    std::vector<std::uint8_t> derivePublicAny(std::uint32_t index) const;
    std::vector<std::uint8_t> derivePrivate(std::uint32_t index) const;
    std::vector<std::uint8_t> derivePublic(std::uint32_t index) const;
    std::string addressFromPublic(const std::vector<std::uint8_t>& pub) const;
};
