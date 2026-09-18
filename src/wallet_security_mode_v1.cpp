#include "wallet_security_mode_v1.h"

#include <string>

const char* walletSecurityModeNameV1(WalletSecurityModeV1 mode) noexcept
{
    switch (mode) {
        case WalletSecurityModeV1::LEGACY_PLAINTEXT:
            return "LEGACY_PLAINTEXT";
        case WalletSecurityModeV1::ENCRYPTED_LOCKED:
            return "ENCRYPTED_LOCKED";
        case WalletSecurityModeV1::ENCRYPTED_UNLOCKED:
            return "ENCRYPTED_UNLOCKED";
    }
    return "UNKNOWN";
}

bool walletPrivateAccessAllowedV1(WalletSecurityModeV1 mode) noexcept
{
    // SEC-14E.4: legacy plaintext private access is retired.
    // Private material is available only through an authenticated,
    // unlocked encrypted-wallet session.
    return mode == WalletSecurityModeV1::ENCRYPTED_UNLOCKED;
}

void requireWalletPrivateAccessV1(
    WalletSecurityModeV1 mode,
    const char* operation)
{
    if (!walletPrivateAccessAllowedV1(mode)) {
        throw std::runtime_error(
            std::string("[SEC-14] Wallet is locked; private operation denied: ") +
            (operation ? operation : "unknown"));
    }
}
