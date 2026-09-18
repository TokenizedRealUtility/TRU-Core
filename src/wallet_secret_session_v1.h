#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

class WalletSecretSessionV1 {
public:
    WalletSecretSessionV1() = default;
    ~WalletSecretSessionV1();

    WalletSecretSessionV1(const WalletSecretSessionV1&) = delete;
    WalletSecretSessionV1& operator=(const WalletSecretSessionV1&) = delete;
    WalletSecretSessionV1(WalletSecretSessionV1&&) = delete;
    WalletSecretSessionV1& operator=(WalletSecretSessionV1&&) = delete;

    bool unlock(
        const std::vector<std::uint8_t>& encryptedSeed,
        const std::vector<std::uint8_t>& encryptedPrivateMaterial,
        const std::string& passphrase,
        std::string* errorOut = nullptr);

    void lock() noexcept;

    bool isLocked() const noexcept;
    bool isUnlocked() const noexcept;

    // These return references specifically to avoid creating implicit secret
    // copies. Access while locked throws. lock() zeroes the backing buffers.
    const std::vector<std::uint8_t>& seed() const;
    const std::vector<std::uint8_t>& privateMaterial() const;

    // TRU-SWAP-B role-key provisioning: replace authenticated private
    // material only while this secret session is already unlocked.
    // The implementation zeroizes the prior backing buffer first.
    void replacePrivateMaterial(std::vector<std::uint8_t>&& replacement);

private:
    static void secureClear(std::vector<std::uint8_t>& bytes) noexcept;

    bool unlocked_ = false;
    std::vector<std::uint8_t> seed_;
    std::vector<std::uint8_t> privateMaterial_;
};
