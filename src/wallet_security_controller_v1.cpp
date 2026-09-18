#include "wallet_security_controller_v1.h"
#include <algorithm>
#include <utility>

WalletSecurityModeV1 WalletSecurityControllerV1::mode() const noexcept
{
    return mode_;
}

const char* WalletSecurityControllerV1::modeName() const noexcept
{
    return walletSecurityModeNameV1(mode_);
}

bool WalletSecurityControllerV1::privateAccessAllowed() const noexcept
{
    return walletPrivateAccessAllowedV1(mode_);
}

void WalletSecurityControllerV1::requirePrivateAccess(
    const char* operation) const
{
    requireWalletPrivateAccessV1(mode_, operation);
}

void WalletSecurityControllerV1::beginEncryptedModeForMigration() noexcept
{
    // Establish LOCKED state before clearing any prior session material.
    mode_ = WalletSecurityModeV1::ENCRYPTED_LOCKED;
    session_.lock();
}

bool WalletSecurityControllerV1::unlockEncrypted(
    const std::vector<std::uint8_t>& encryptedSeed,
    const std::vector<std::uint8_t>& encryptedPrivateMaterial,
    const std::string& passphrase,
    std::string* errorOut)
{
    // No implicit migration transition: legacy wallets cannot become
    // ENCRYPTED_UNLOCKED merely by presenting envelope bytes.
    if (mode_ == WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        if (errorOut) {
            *errorOut =
                "encrypted unlock refused before migration enters encrypted mode";
        }
        return false;
    }

    // Fail closed before authentication. WalletSecretSessionV1::unlock()
    // also destroys any previous session before attempting replacement.
    mode_ = WalletSecurityModeV1::ENCRYPTED_LOCKED;

    if (!session_.unlock(
            encryptedSeed,
            encryptedPrivateMaterial,
            passphrase,
            errorOut)) {
        mode_ = WalletSecurityModeV1::ENCRYPTED_LOCKED;
        return false;
    }

    // This is the ONLY assignment to ENCRYPTED_UNLOCKED in production.
    mode_ = WalletSecurityModeV1::ENCRYPTED_UNLOCKED;
    return true;
}

void WalletSecurityControllerV1::lockEncrypted() noexcept
{
    // State becomes locked before secret zeroization begins.
    if (mode_ != WalletSecurityModeV1::LEGACY_PLAINTEXT) {
        mode_ = WalletSecurityModeV1::ENCRYPTED_LOCKED;
    }
    session_.lock();
}

bool WalletSecurityControllerV1::sessionUnlocked() const noexcept
{
    return session_.isUnlocked();
}


const std::vector<std::uint8_t>&
WalletSecurityControllerV1::unlockedSeed() const
{
    if (mode_ != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !session_.isUnlocked()) {
        throw std::runtime_error(
            "wallet encrypted seed access requires ENCRYPTED_UNLOCKED");
    }
    return session_.seed();
}

const std::vector<std::uint8_t>&
WalletSecurityControllerV1::unlockedPrivateMaterial() const
{
    if (mode_ != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !session_.isUnlocked()) {
        throw std::runtime_error(
            "wallet encrypted private-material access requires ENCRYPTED_UNLOCKED");
    }
    return session_.privateMaterial();
}

void WalletSecurityControllerV1::replaceUnlockedPrivateMaterial(
    std::vector<std::uint8_t>&& replacement)
{
    if (mode_ != WalletSecurityModeV1::ENCRYPTED_UNLOCKED ||
        !session_.isUnlocked()) {
        std::fill(replacement.begin(), replacement.end(), 0U);
        replacement.clear();
        throw std::runtime_error(
            "wallet private-material replacement requires ENCRYPTED_UNLOCKED");
    }

    session_.replacePrivateMaterial(std::move(replacement));
}

