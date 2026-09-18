#ifndef HDWALLET_H
#define HDWALLET_H

#include <string>
#include <vector>
#include <array>
#include "crypto_ecdsa.h"

class HDWallet {
public:
    static const size_t SEED_SIZE = 64; // 512-bit seed
    
    // BIP32 derivation parameters
    struct DerivationPath {
        uint32_t purpose;
        uint32_t coin_type;
        uint32_t account;
        uint32_t change;
    };

    HDWallet();
    HDWallet(const std::array<uint8_t, SEED_SIZE>& seed);
    
    // BIP32 key derivation
    std::string getMasterPrivateKey() const;
    std::string deriveAddress(uint32_t index) const;
    std::string derivePrivateKey(uint32_t index) const;
    
    // 1) Declare new method:
    std::string derivePrivateKeyPEM(uint32_t index) const;

    // Seed management
    static HDWallet fromMnemonic(const std::vector<std::string>& mnemonic);
    static HDWallet fromSeed(const std::array<uint8_t, SEED_SIZE>& seed);
    
    // Wallet operations
    std::string getXPub() const;
    std::string getXPriv() const;
    std::vector<uint8_t> derivePrivateKeyRaw(uint32_t index) const;
private:
    std::array<uint8_t, SEED_SIZE> seed_;
    DerivationPath path_;
    
    // BIP32 extended keys
    struct ExtendedKey {
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 32> chain_code;
    };
    
    ExtendedKey master_key_;
    
    void initFromSeed();
    ExtendedKey deriveChildKey(const ExtendedKey& parent, uint32_t index) const;
};

#endif // HDWALLET_H
