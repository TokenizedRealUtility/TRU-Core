#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tru_wallet_encryption_v1 {

// Binary envelope:
//   magic[8]     = "TRUWENC1"
//   version      = 1
//   kdf_id       = 1 (Argon2id13)
//   aead_id      = 1 (XChaCha20-Poly1305 IETF)
//   reserved     = 0
//   opslimit     = uint64 LE
//   memlimit     = uint64 LE
//   salt[crypto_pwhash_SALTBYTES]
//   nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
//   ciphertext[] = plaintext + Poly1305 authentication tag
//
// Every header byte through nonce is authenticated as AEAD associated data.
// V1 accepts only the exact KDF work factors emitted by this implementation;
// corrupted envelopes therefore cannot request attacker-controlled resource use.

bool isEnvelopeV1(const std::vector<std::uint8_t>& envelope);

bool encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::string& passphrase,
    std::vector<std::uint8_t>& envelopeOut,
    std::string* errorOut = nullptr);

bool decrypt(
    const std::vector<std::uint8_t>& envelope,
    const std::string& passphrase,
    std::vector<std::uint8_t>& plaintextOut,
    std::string* errorOut = nullptr);

std::size_t headerSize();

} // namespace tru_wallet_encryption_v1
