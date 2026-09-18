#include "wallet_security_mode_v1.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

static void require(bool ok, const char* what)
{
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        std::exit(1);
    }
}

static bool denied(WalletSecurityModeV1 mode)
{
    try {
        requireWalletPrivateAccessV1(mode, "test");
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main()
{
    require(walletPrivateAccessAllowedV1(
                WalletSecurityModeV1::LEGACY_PLAINTEXT),
            "legacy compatibility allows private access before migration");

    require(!walletPrivateAccessAllowedV1(
                WalletSecurityModeV1::ENCRYPTED_LOCKED),
            "encrypted locked denies private access");

    require(walletPrivateAccessAllowedV1(
                WalletSecurityModeV1::ENCRYPTED_UNLOCKED),
            "encrypted unlocked allows private access");

    require(!denied(WalletSecurityModeV1::LEGACY_PLAINTEXT),
            "legacy compatibility gate passes");
    require(denied(WalletSecurityModeV1::ENCRYPTED_LOCKED),
            "locked gate throws");
    require(!denied(WalletSecurityModeV1::ENCRYPTED_UNLOCKED),
            "unlocked gate passes");

    std::cout << "SEC_14D1_MODE_LEGACY_COMPAT_ALLOW=PASS\n";
    std::cout << "SEC_14D1_MODE_ENCRYPTED_LOCKED_DENY=PASS\n";
    std::cout << "SEC_14D1_MODE_ENCRYPTED_UNLOCKED_ALLOW=PASS\n";
    std::cout << "SEC_14D1_MODE_TRUTH_TABLE=PASS\n";
    return 0;
}
