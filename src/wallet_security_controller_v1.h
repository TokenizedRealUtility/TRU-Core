#pragma once

#include "wallet_security_mode_v1.h"
#include "wallet_secret_session_v1.h"

#include <cstdint>
#include <string>
#include <vector>

class WalletSecurityControllerV1 {
public:
    WalletSecurityControllerV1() = default;
    ~WalletSecurityControllerV1() = default;

    WalletSecurityControllerV1(const WalletSecurityControllerV1&) = delete;
    WalletSecurityControllerV1& operator=(const WalletSecurityControllerV1&) = delete;
    WalletSecurityControllerV1(WalletSecurityControllerV1&&) = delete;
    WalletSecurityControllerV1& operator=(WalletSecurityControllerV1&&) = delete;

    WalletSecurityModeV1 mode() const noexcept;
    const char* modeName() const noexcept;

    bool privateAccessAllowed() const noexcept;
    void requirePrivateAccess(const char* operation) const;

    // SEC-14E migration entry point. This transition is one-way in-process:
    // once encrypted mode begins, there is no API to return to LEGACY_PLAINTEXT.
    void beginEncryptedModeForMigration() noexcept;

    bool unlockEncrypted(
        const std::vector<std::uint8_t>& encryptedSeed,
        const std::vector<std::uint8_t>& encryptedPrivateMaterial,
        const std::string& passphrase,
        std::string* errorOut = nullptr);

    void lockEncrypted() noexcept;

    bool sessionUnlocked() const noexcept;
    const std::vector<std::uint8_t>& unlockedSeed() const;
    const std::vector<std::uint8_t>& unlockedPrivateMaterial() const;
    void replaceUnlockedPrivateMaterial(
        std::vector<std::uint8_t>&& replacement);

private:
    WalletSecurityModeV1 mode_ = WalletSecurityModeV1::LEGACY_PLAINTEXT;
    WalletSecretSessionV1 session_;
};
