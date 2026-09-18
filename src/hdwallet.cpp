#include "hdwallet.h"
#include "utils.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <openssl/rand.h>  // For RAND_bytes
#include <sstream>         // For std::ostringstream
#include <iomanip>         // For std::hex, std::setw, etc.
#include "crypto_ecdsa.h"

HDWallet::HDWallet() {
    // Generate random seed
    if (!RAND_bytes(seed_.data(), seed_.size())) {
        throw std::runtime_error("Failed to generate secure seed");
    }
    initFromSeed();
}

HDWallet::HDWallet(const std::array<uint8_t, SEED_SIZE>& seed) 
    : seed_(seed) {
    initFromSeed();
}

void HDWallet::initFromSeed() {
    // BIP32 seed to master key derivation
    const std::string HMAC_KEY = "Bitcoin seed";
    unsigned char hmac[64];
    
    HMAC(EVP_sha512(), 
         HMAC_KEY.data(), HMAC_KEY.size(),
         seed_.data(), seed_.size(),
         hmac, nullptr);

    // Split into master key and chain code
    std::copy(hmac, hmac + 32, master_key_.key.begin());
    std::copy(hmac + 32, hmac + 64, master_key_.chain_code.begin());
}

HDWallet::ExtendedKey HDWallet::deriveChildKey(const ExtendedKey& parent, 
                                             uint32_t index) const {
    // BIP32 child key derivation (simplified)
    std::array<uint8_t, 37> data;
    data[0] = 0x00;
    std::copy(parent.key.begin(), parent.key.end(), data.begin() + 1);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    unsigned char hmac[64];
    HMAC(EVP_sha512(), 
         parent.chain_code.data(), parent.chain_code.size(),
         data.data(), data.size(),
         hmac, nullptr);

    ExtendedKey child;
    std::copy(hmac, hmac + 32, child.key.begin());
    std::copy(hmac + 32, hmac + 64, child.chain_code.begin());
    return child;
}

std::string HDWallet::deriveAddress(uint32_t index) const {
    // Derive public key at specified index
    ExtendedKey key = master_key_;
    for (auto component : {path_.purpose, path_.coin_type, path_.account, path_.change}) {
        key = deriveChildKey(key, component | 0x80000000); // Hardened
    }
    key = deriveChildKey(key, index);
    
    // Create ECDSA key from derived data

    std::vector<uint8_t> rawKey(key.key.begin(), key.key.end());
    ECDSAKey ec_key = ECDSAKey::fromRawBytes(rawKey);
    
    // Generate address from public key
    std::string pub_key = ec_key.getPublicKey();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(pub_key.data()), pub_key.size(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string HDWallet::derivePrivateKey(uint32_t index) const {
    ExtendedKey key = master_key_;
    for (auto component : {path_.purpose, path_.coin_type, path_.account, path_.change}) {
        key = deriveChildKey(key, component | 0x80000000);
    }
    key = deriveChildKey(key, index);
    return std::string(key.key.begin(), key.key.end());
}

// Add remaining implementation details as needed...
std::string HDWallet::derivePrivateKeyPEM(uint32_t index) const
{
    // 1) Derive the raw child key
    ExtendedKey key = master_key_;
    for (auto component : {path_.purpose, path_.coin_type, path_.account, path_.change}) {
        key = deriveChildKey(key, component | 0x80000000); // hardened
    }
    key = deriveChildKey(key, index);

    // 2) Build an ECDSAKey from raw bytes
    std::vector<uint8_t> rawKey(key.key.begin(), key.key.end());
    ECDSAKey ecKey = ECDSAKey::fromRawBytes(rawKey);

    // 3) Now ask for a PEM-encoded private key
    return ecKey.getPrivateKey(); 
}

std::vector<uint8_t> HDWallet::derivePrivateKeyRaw(uint32_t index) const {
    ExtendedKey key = master_key_;
    for (auto component : {path_.purpose, path_.coin_type, path_.account, path_.change}) {
        key = deriveChildKey(key, component | 0x80000000);
    }
    key = deriveChildKey(key, index);
    
    // Return the raw 32-byte private key
    return std::vector<uint8_t>(key.key.begin(), key.key.end());
}