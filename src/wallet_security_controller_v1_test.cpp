#include "wallet_encryption_v1.h"
#include "wallet_security_controller_v1.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace enc = tru_wallet_encryption_v1;

static void require(bool ok, const char* what)
{
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        std::exit(1);
    }
}

int main()
{
    const std::string pass = "TRU SEC-14D.2 test passphrase";
    const std::string wrong = "wrong passphrase";

    std::vector<std::uint8_t> seed(64);
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(0x5AU ^ i);
    }

    const std::string privateJson =
        R"({"privateKeys":{"A":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}})";
    std::vector<std::uint8_t> privateMaterial(
        privateJson.begin(), privateJson.end());

    std::vector<std::uint8_t> seedEnv;
    std::vector<std::uint8_t> privEnv;
    std::string err;

    require(enc::encrypt(seed, pass, seedEnv, &err),
            "encrypt seed");
    require(enc::encrypt(privateMaterial, pass, privEnv, &err),
            "encrypt private material");

    WalletSecurityControllerV1 ctl;

    require(ctl.mode() == WalletSecurityModeV1::LEGACY_PLAINTEXT,
            "controller starts legacy");
    require(ctl.privateAccessAllowed(),
            "legacy compatibility permits private access");
    require(!ctl.sessionUnlocked(),
            "legacy mode does not imply authenticated session");

    require(!ctl.unlockEncrypted(seedEnv, privEnv, pass, &err),
            "cannot jump legacy directly to encrypted unlocked");
    require(ctl.mode() == WalletSecurityModeV1::LEGACY_PLAINTEXT,
            "refused pre-migration unlock preserves legacy mode");

    ctl.beginEncryptedModeForMigration();
    require(ctl.mode() == WalletSecurityModeV1::ENCRYPTED_LOCKED,
            "migration entry establishes locked mode");
    require(!ctl.privateAccessAllowed(),
            "encrypted locked denies private access");
    require(!ctl.sessionUnlocked(),
            "encrypted locked has no live session");

    require(!ctl.unlockEncrypted(seedEnv, privEnv, wrong, &err),
            "wrong password rejected");
    require(ctl.mode() == WalletSecurityModeV1::ENCRYPTED_LOCKED,
            "wrong password leaves mode locked");
    require(!ctl.sessionUnlocked(),
            "wrong password leaves no session");

    require(ctl.unlockEncrypted(seedEnv, privEnv, pass, &err),
            "authenticated unlock succeeds");
    require(ctl.mode() == WalletSecurityModeV1::ENCRYPTED_UNLOCKED,
            "successful authentication earns unlocked state");
    require(ctl.privateAccessAllowed(),
            "encrypted unlocked allows private access");
    require(ctl.sessionUnlocked(),
            "successful authentication creates live session");

    auto tampered = privEnv;
    tampered.back() ^= 0x01U;

    require(!ctl.unlockEncrypted(seedEnv, tampered, pass, &err),
            "failed replacement unlock rejected");
    require(ctl.mode() == WalletSecurityModeV1::ENCRYPTED_LOCKED,
            "failed replacement unlock relocks mode");
    require(!ctl.sessionUnlocked(),
            "failed replacement unlock destroys old session");
    require(!ctl.privateAccessAllowed(),
            "failed replacement unlock denies private access");

    require(ctl.unlockEncrypted(seedEnv, privEnv, pass, &err),
            "re-unlock after failure succeeds");
    ctl.lockEncrypted();

    require(ctl.mode() == WalletSecurityModeV1::ENCRYPTED_LOCKED,
            "explicit lock transitions to encrypted locked");
    require(!ctl.sessionUnlocked(),
            "explicit lock clears session");
    require(!ctl.privateAccessAllowed(),
            "explicit lock denies private access");

    std::cout << "SEC_14D2_LEGACY_START=PASS\n";
    std::cout << "SEC_14D2_NO_DIRECT_LEGACY_TO_UNLOCKED=PASS\n";
    std::cout << "SEC_14D2_MIGRATION_ENTRY_LOCKED=PASS\n";
    std::cout << "SEC_14D2_WRONG_PASSWORD_STAYS_LOCKED=PASS\n";
    std::cout << "SEC_14D2_AUTH_SUCCESS_EARNS_UNLOCKED=PASS\n";
    std::cout << "SEC_14D2_FAILED_REUNLOCK_DESTROYS_SESSION=PASS\n";
    std::cout << "SEC_14D2_EXPLICIT_LOCK_ZEROIZES_SESSION=PASS\n";
    std::cout << "TRU_SEC_14D2_AUTHENTICATED_STATE_MACHINE=PASS\n";
    return 0;
}
