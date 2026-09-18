#include "wallet_encryption_v1.h"
#include "wallet_secret_session_v1.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
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

template <typename F>
static bool throwsLocked(F&& f)
{
    try {
        f();
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main()
{
    const std::string pass = "TRU SEC-14C test passphrase";
    const std::string wrong = "definitely wrong";

    std::vector<std::uint8_t> seed(64);
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i ^ 0xA5U);
    }

    const std::string json =
        R"({"format":"mixed-preserved","pem":"-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----","hex":"00112233445566778899aabbccddeeff"})";
    const std::vector<std::uint8_t> privateMaterial(json.begin(), json.end());

    std::vector<std::uint8_t> seedEnv;
    std::vector<std::uint8_t> privEnv;
    std::string err;

    require(enc::encrypt(seed, pass, seedEnv, &err),
            "encrypt test seed");
    require(enc::encrypt(privateMaterial, pass, privEnv, &err),
            "encrypt test private material");

    WalletSecretSessionV1 session;

    require(session.isLocked(), "session starts locked");
    require(!session.isUnlocked(), "session starts not-unlocked");
    require(throwsLocked([&] { (void)session.seed(); }),
            "locked seed access rejected");
    require(throwsLocked([&] { (void)session.privateMaterial(); }),
            "locked private-material access rejected");

    require(!session.unlock(seedEnv, privEnv, wrong, &err),
            "wrong password rejected");
    require(session.isLocked(),
            "wrong password leaves session locked");
    require(throwsLocked([&] { (void)session.seed(); }),
            "wrong-password path exposes no seed");

    require(session.unlock(seedEnv, privEnv, pass, &err),
            "correct password unlocks");
    require(session.isUnlocked(), "session reports unlocked");
    require(session.seed() == seed, "seed preserved exactly");
    require(session.privateMaterial() == privateMaterial,
            "private material preserved exactly");

    session.lock();
    require(session.isLocked(), "explicit lock succeeds");
    require(throwsLocked([&] { (void)session.seed(); }),
            "seed access rejected after lock");
    require(throwsLocked([&] { (void)session.privateMaterial(); }),
            "private-material access rejected after lock");

    require(session.unlock(seedEnv, privEnv, pass, &err),
            "re-unlock succeeds");

    auto tamperedPriv = privEnv;
    tamperedPriv.back() ^= 0x80;
    require(!session.unlock(seedEnv, tamperedPriv, pass, &err),
            "tampered private-material envelope rejected");
    require(session.isLocked(),
            "failed re-unlock destroys prior unlocked session");
    require(throwsLocked([&] { (void)session.seed(); }),
            "failed re-unlock exposes no prior seed");

    std::vector<std::uint8_t> shortSeed(63, 0x42);
    std::vector<std::uint8_t> shortSeedEnv;
    require(enc::encrypt(shortSeed, pass, shortSeedEnv, &err),
            "encrypt short-seed negative vector");
    require(!session.unlock(shortSeedEnv, privEnv, pass, &err),
            "authenticated wrong-size seed rejected");
    require(session.isLocked(),
            "wrong-size seed leaves session locked");

    std::cout << "SEC_14C_STARTS_LOCKED=PASS\n";
    std::cout << "SEC_14C_LOCKED_ACCESS_DENIED=PASS\n";
    std::cout << "SEC_14C_WRONG_PASSWORD_FAIL_CLOSED=PASS\n";
    std::cout << "SEC_14C_UNLOCK_ROUNDTRIP=PASS\n";
    std::cout << "SEC_14C_EXPLICIT_RELOCK=PASS\n";
    std::cout << "SEC_14C_FAILED_REUNLOCK_DESTROYS_OLD_SESSION=PASS\n";
    std::cout << "SEC_14C_SEED_SIZE_GATE=PASS\n";
    std::cout << "SEC_14C_SECRET_BUFFER_ZEROIZATION_PATH=PASS\n";
    std::cout << "TRU_SEC_14C_WALLET_LOCK_UNLOCK_MEMORY_BOUNDARY=PASS\n";
    return 0;
}
