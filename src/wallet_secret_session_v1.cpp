#include "wallet_secret_session_v1.h"
#include <utility>

#include "wallet_encryption_v1.h"

#include <sodium.h>

namespace {

void setError(std::string* out, const std::string& msg)
{
    if (out) *out = msg;
}

} // namespace

WalletSecretSessionV1::~WalletSecretSessionV1()
{
    lock();
}

void WalletSecretSessionV1::secureClear(
    std::vector<std::uint8_t>& bytes) noexcept
{
    if (!bytes.empty()) {
        sodium_memzero(bytes.data(), bytes.size());
    }
    bytes.clear();
}

bool WalletSecretSessionV1::lockMemory(std::vector<std::uint8_t>& bytes) noexcept
{
    return bytes.empty() || sodium_mlock(bytes.data(), bytes.size()) == 0;
}

void WalletSecretSessionV1::unlockMemory(std::vector<std::uint8_t>& bytes) noexcept
{
    if (!bytes.empty()) {
        // sodium_munlock() zeroes the region before releasing the page lock.
        sodium_munlock(bytes.data(), bytes.size());
    }
}

void WalletSecretSessionV1::lock() noexcept
{
    // Clear the state flag first so any concurrent/exceptional observation
    // cannot treat the session as usable while destruction is in progress.
    unlocked_ = false;
    if (seedMemoryLocked_) {
        unlockMemory(seed_);
        seedMemoryLocked_ = false;
        seed_.clear();
    } else {
        secureClear(seed_);
    }
    if (privateMemoryLocked_) {
        unlockMemory(privateMaterial_);
        privateMemoryLocked_ = false;
        privateMaterial_.clear();
    } else {
        secureClear(privateMaterial_);
    }
}

bool WalletSecretSessionV1::isLocked() const noexcept
{
    return !unlocked_;
}

bool WalletSecretSessionV1::isUnlocked() const noexcept
{
    return unlocked_;
}

const std::vector<std::uint8_t>& WalletSecretSessionV1::seed() const
{
    if (!unlocked_) {
        throw std::runtime_error("wallet secret session is locked");
    }
    return seed_;
}

const std::vector<std::uint8_t>&
WalletSecretSessionV1::privateMaterial() const
{
    if (!unlocked_) {
        throw std::runtime_error("wallet secret session is locked");
    }
    return privateMaterial_;
}

void WalletSecretSessionV1::replacePrivateMaterial(
    std::vector<std::uint8_t>&& replacement)
{
    if (!unlocked_) {
        secureClear(replacement);
        throw std::runtime_error(
            "wallet secret-session private-material replacement requires unlocked session");
    }

    // Pin replacement before making it the live secret buffer. Fail closed if
    // the OS refuses the page lock.
    if (!lockMemory(replacement)) {
        secureClear(replacement);
        throw std::runtime_error("unable to mlock replacement wallet private material");
    }
    if (privateMemoryLocked_) {
        unlockMemory(privateMaterial_);
        privateMemoryLocked_ = false;
        privateMaterial_.clear();
    } else {
        secureClear(privateMaterial_);
    }
    privateMaterial_ = std::move(replacement);
    privateMemoryLocked_ = true;
}


bool WalletSecretSessionV1::unlock(
    const std::vector<std::uint8_t>& encryptedSeed,
    const std::vector<std::uint8_t>& encryptedPrivateMaterial,
    const std::string& passphrase,
    std::string* errorOut)
{
    if (errorOut) errorOut->clear();

    // Fail closed: an unlock attempt invalidates any prior secret session
    // before authenticating replacement material.
    lock();

    std::vector<std::uint8_t> seedCandidate;
    std::vector<std::uint8_t> privateCandidate;
    std::string error;

    if (!tru_wallet_encryption_v1::decrypt(
            encryptedSeed, passphrase, seedCandidate, &error)) {
        secureClear(seedCandidate);
        secureClear(privateCandidate);
        setError(errorOut, "seed envelope unlock failed: " + error);
        return false;
    }

    if (seedCandidate.size() != 64U) {
        secureClear(seedCandidate);
        secureClear(privateCandidate);
        setError(errorOut, "decrypted wallet seed must be exactly 64 bytes");
        return false;
    }

    if (!tru_wallet_encryption_v1::decrypt(
            encryptedPrivateMaterial,
            passphrase,
            privateCandidate,
            &error)) {
        secureClear(seedCandidate);
        secureClear(privateCandidate);
        setError(errorOut, "private-material envelope unlock failed: " + error);
        return false;
    }

    // Pin authenticated plaintext before publishing the unlocked session.
    // This prevents the live seed/private material from being swapped to disk.
    const bool seedPinned = lockMemory(seedCandidate);
    const bool privatePinned = seedPinned && lockMemory(privateCandidate);
    if (!seedPinned || !privatePinned) {
        if (seedPinned) unlockMemory(seedCandidate); else secureClear(seedCandidate);
        if (privatePinned) unlockMemory(privateCandidate); else secureClear(privateCandidate);
        seedCandidate.clear();
        privateCandidate.clear();
        setError(errorOut, "unable to mlock wallet secret session");
        return false;
    }

    seed_.swap(seedCandidate);
    privateMaterial_.swap(privateCandidate);
    seedMemoryLocked_ = true;
    privateMemoryLocked_ = true;

    // The swapped candidates now contain the old (empty) session buffers,
    // but clear them explicitly to preserve the invariant if implementation
    // details change.
    secureClear(seedCandidate);
    secureClear(privateCandidate);

    unlocked_ = true;
    return true;
}
