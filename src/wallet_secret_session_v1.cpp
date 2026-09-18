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

void WalletSecretSessionV1::lock() noexcept
{
    // Clear the state flag first so any concurrent/exceptional observation
    // cannot treat the session as usable while destruction is in progress.
    unlocked_ = false;
    secureClear(seed_);
    secureClear(privateMaterial_);
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

    secureClear(privateMaterial_);
    privateMaterial_ = std::move(replacement);
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

    // Move authenticated plaintext into the sole live session buffers.
    seed_.swap(seedCandidate);
    privateMaterial_.swap(privateCandidate);

    // The swapped candidates now contain the old (empty) session buffers,
    // but clear them explicitly to preserve the invariant if implementation
    // details change.
    secureClear(seedCandidate);
    secureClear(privateCandidate);

    unlocked_ = true;
    return true;
}
