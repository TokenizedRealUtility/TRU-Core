#pragma once

#include <stdexcept>

enum class WalletSecurityModeV1 {
    LEGACY_PLAINTEXT = 0,
    ENCRYPTED_LOCKED = 1,
    ENCRYPTED_UNLOCKED = 2
};

const char* walletSecurityModeNameV1(WalletSecurityModeV1 mode) noexcept;

bool walletPrivateAccessAllowedV1(WalletSecurityModeV1 mode) noexcept;

void requireWalletPrivateAccessV1(
    WalletSecurityModeV1 mode,
    const char* operation);
