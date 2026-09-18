#include "wallet_encryption_v1.h"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace tru_wallet_encryption_v1 {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {
    'T','R','U','W','E','N','C','1'
};
constexpr std::uint8_t kVersion = 1;
constexpr std::uint8_t kKdfArgon2id13 = 1;
constexpr std::uint8_t kAeadXChaCha20Poly1305Ietf = 1;
constexpr std::uint8_t kReserved = 0;

constexpr std::size_t kFixedPrefix =
    kMagic.size() + 4U + 8U + 8U;

constexpr std::size_t kHeaderSize =
    kFixedPrefix +
    crypto_pwhash_SALTBYTES +
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == 32,
              "TRU wallet envelope expects a 32-byte AEAD key");

void setError(std::string* out, const std::string& msg)
{
    if (out) *out = msg;
}

void appendU64Le(std::vector<std::uint8_t>& out, std::uint64_t v)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8U)) & 0xffU));
    }
}

bool readU64Le(
    const std::vector<std::uint8_t>& in,
    std::size_t off,
    std::uint64_t& value)
{
    if (off > in.size() || in.size() - off < 8U) return false;
    value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(in[off + i]) << (i * 8U);
    }
    return true;
}

bool initSodium(std::string* errorOut)
{
    if (sodium_init() < 0) {
        setError(errorOut, "libsodium initialization failed");
        return false;
    }
    return true;
}

bool deriveKey(
    const std::string& passphrase,
    const unsigned char* salt,
    unsigned long long opslimit,
    std::size_t memlimit,
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
    std::string* errorOut)
{
    if (passphrase.empty()) {
        setError(errorOut, "wallet encryption passphrase must not be empty");
        return false;
    }

    if (crypto_pwhash(
            key.data(),
            key.size(),
            passphrase.data(),
            static_cast<unsigned long long>(passphrase.size()),
            salt,
            opslimit,
            memlimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        setError(errorOut, "Argon2id key derivation failed");
        sodium_memzero(key.data(), key.size());
        return false;
    }
    return true;
}

bool parseHeader(
    const std::vector<std::uint8_t>& envelope,
    unsigned long long& opslimit,
    std::size_t& memlimit,
    const unsigned char*& salt,
    const unsigned char*& nonce,
    std::string* errorOut)
{
    if (envelope.size() < kHeaderSize + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        setError(errorOut, "encrypted wallet envelope is truncated");
        return false;
    }

    if (!std::equal(kMagic.begin(), kMagic.end(), envelope.begin())) {
        setError(errorOut, "encrypted wallet envelope magic mismatch");
        return false;
    }

    std::size_t off = kMagic.size();
    if (envelope[off++] != kVersion) {
        setError(errorOut, "unsupported encrypted wallet envelope version");
        return false;
    }
    if (envelope[off++] != kKdfArgon2id13) {
        setError(errorOut, "unsupported encrypted wallet KDF");
        return false;
    }
    if (envelope[off++] != kAeadXChaCha20Poly1305Ietf) {
        setError(errorOut, "unsupported encrypted wallet AEAD");
        return false;
    }
    if (envelope[off++] != kReserved) {
        setError(errorOut, "encrypted wallet envelope reserved byte is nonzero");
        return false;
    }

    std::uint64_t ops64 = 0;
    std::uint64_t mem64 = 0;
    if (!readU64Le(envelope, off, ops64)) {
        setError(errorOut, "encrypted wallet envelope opslimit missing");
        return false;
    }
    off += 8U;
    if (!readU64Le(envelope, off, mem64)) {
        setError(errorOut, "encrypted wallet envelope memlimit missing");
        return false;
    }
    off += 8U;

    // V1 deliberately accepts only the exact work factors it emits. This
    // prevents corrupted/untrusted envelope metadata from requesting
    // attacker-controlled CPU or memory use during decryption.
    if (ops64 != static_cast<std::uint64_t>(crypto_pwhash_OPSLIMIT_MODERATE) ||
        mem64 != static_cast<std::uint64_t>(crypto_pwhash_MEMLIMIT_MODERATE)) {
        setError(errorOut, "encrypted wallet KDF parameters are not canonical V1 values");
        return false;
    }
    if (mem64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        setError(errorOut, "encrypted wallet memlimit exceeds platform size");
        return false;
    }

    opslimit = static_cast<unsigned long long>(ops64);
    memlimit = static_cast<std::size_t>(mem64);

    salt = reinterpret_cast<const unsigned char*>(envelope.data() + off);
    off += crypto_pwhash_SALTBYTES;
    nonce = reinterpret_cast<const unsigned char*>(envelope.data() + off);
    off += crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    if (off != kHeaderSize) {
        setError(errorOut, "encrypted wallet envelope header-size invariant failed");
        return false;
    }
    return true;
}

} // namespace

std::size_t headerSize()
{
    return kHeaderSize;
}

bool isEnvelopeV1(const std::vector<std::uint8_t>& envelope)
{
    return envelope.size() >= kHeaderSize &&
           std::equal(kMagic.begin(), kMagic.end(), envelope.begin()) &&
           envelope[kMagic.size()] == kVersion;
}

bool encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::string& passphrase,
    std::vector<std::uint8_t>& envelopeOut,
    std::string* errorOut)
{
    envelopeOut.clear();
    if (errorOut) errorOut->clear();
    if (!initSodium(errorOut)) return false;
    if (passphrase.empty()) {
        setError(errorOut, "wallet encryption passphrase must not be empty");
        return false;
    }

    const auto opslimit = static_cast<unsigned long long>(
        crypto_pwhash_OPSLIMIT_MODERATE);
    const auto memlimit = static_cast<std::size_t>(
        crypto_pwhash_MEMLIMIT_MODERATE);

    std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};

    randombytes_buf(salt.data(), salt.size());
    randombytes_buf(nonce.data(), nonce.size());

    if (!deriveKey(passphrase, salt.data(), opslimit, memlimit, key, errorOut)) {
        return false;
    }

    try {
        envelopeOut.reserve(
            kHeaderSize + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

        envelopeOut.insert(envelopeOut.end(), kMagic.begin(), kMagic.end());
        envelopeOut.push_back(kVersion);
        envelopeOut.push_back(kKdfArgon2id13);
        envelopeOut.push_back(kAeadXChaCha20Poly1305Ietf);
        envelopeOut.push_back(kReserved);
        appendU64Le(envelopeOut, static_cast<std::uint64_t>(opslimit));
        appendU64Le(envelopeOut, static_cast<std::uint64_t>(memlimit));
        envelopeOut.insert(envelopeOut.end(), salt.begin(), salt.end());
        envelopeOut.insert(envelopeOut.end(), nonce.begin(), nonce.end());

        if (envelopeOut.size() != kHeaderSize) {
            setError(errorOut, "encrypted wallet header construction invariant failed");
            sodium_memzero(key.data(), key.size());
            envelopeOut.clear();
            return false;
        }

        const std::size_t cipherOff = envelopeOut.size();
        envelopeOut.resize(
            cipherOff + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long cipherLen = 0;
        const unsigned char* plainPtr =
            plaintext.empty() ? nullptr : plaintext.data();

        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                envelopeOut.data() + cipherOff,
                &cipherLen,
                plainPtr,
                static_cast<unsigned long long>(plaintext.size()),
                envelopeOut.data(),
                static_cast<unsigned long long>(kHeaderSize),
                nullptr,
                nonce.data(),
                key.data()) != 0) {
            setError(errorOut, "XChaCha20-Poly1305 encryption failed");
            sodium_memzero(key.data(), key.size());
            envelopeOut.clear();
            return false;
        }

        envelopeOut.resize(cipherOff + static_cast<std::size_t>(cipherLen));
        sodium_memzero(key.data(), key.size());
        return true;
    } catch (...) {
        sodium_memzero(key.data(), key.size());
        envelopeOut.clear();
        setError(errorOut, "encrypted wallet envelope allocation/construction failed");
        return false;
    }
}

bool decrypt(
    const std::vector<std::uint8_t>& envelope,
    const std::string& passphrase,
    std::vector<std::uint8_t>& plaintextOut,
    std::string* errorOut)
{
    plaintextOut.clear();
    if (errorOut) errorOut->clear();
    if (!initSodium(errorOut)) return false;

    unsigned long long opslimit = 0;
    std::size_t memlimit = 0;
    const unsigned char* salt = nullptr;
    const unsigned char* nonce = nullptr;

    if (!parseHeader(
            envelope, opslimit, memlimit, salt, nonce, errorOut)) {
        return false;
    }

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
    if (!deriveKey(passphrase, salt, opslimit, memlimit, key, errorOut)) {
        return false;
    }

    const std::size_t cipherLen = envelope.size() - kHeaderSize;
    if (cipherLen < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        sodium_memzero(key.data(), key.size());
        setError(errorOut, "encrypted wallet ciphertext is truncated");
        return false;
    }

    try {
        plaintextOut.resize(
            cipherLen - crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long plainLen = 0;
        unsigned char* plainPtr =
            plaintextOut.empty() ? nullptr : plaintextOut.data();

        const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plainPtr,
            &plainLen,
            nullptr,
            envelope.data() + kHeaderSize,
            static_cast<unsigned long long>(cipherLen),
            envelope.data(),
            static_cast<unsigned long long>(kHeaderSize),
            nonce,
            key.data());

        sodium_memzero(key.data(), key.size());

        if (rc != 0) {
            plaintextOut.clear();
            setError(errorOut, "encrypted wallet authentication failed");
            return false;
        }

        plaintextOut.resize(static_cast<std::size_t>(plainLen));
        return true;
    } catch (...) {
        sodium_memzero(key.data(), key.size());
        plaintextOut.clear();
        setError(errorOut, "encrypted wallet decryption allocation failed");
        return false;
    }
}

} // namespace tru_wallet_encryption_v1
