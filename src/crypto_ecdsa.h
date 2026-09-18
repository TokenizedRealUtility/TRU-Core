#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

#include <vector>
#include <string>
#include <stdexcept>        // <-- for std::runtime_error
#include <openssl/evp.h>
#include <openssl/ec.h>     // <-- for EC_KEY, i2o_ECPublicKey, etc.
#include <openssl/ecdsa.h>  // <-- for ECDSA / EC_KEY functions
#include <openssl/obj_mac.h> // <-- for NID_secp256k1

/**
 * A simple ECDSA wrapper using OpenSSL, specifically for secp256k1.
 * We store the key in an EVP_PKEY, but retrieve an EC_KEY pointer if needed.
 */
class ECDSAKey {
public:
    ECDSAKey();
    ~ECDSAKey();

    // move semantics
    ECDSAKey(ECDSAKey&& other) noexcept;
    ECDSAKey& operator=(ECDSAKey&& other) noexcept;

    // Generate a brand-new random secp256k1 key (compressed).
    static ECDSAKey generate();

    // Load from a PEM-encoded private key string
    static ECDSAKey fromPrivateKey(const std::string& privKeyPEM);

    // Create from raw 32-byte private key (no PEM)
    static ECDSAKey fromRawBytes(const std::vector<uint8_t>& rawBytes);

    // Sign a message (SHA256)
    std::vector<unsigned char> sign(const std::string& message) const;

    // Return the public key in DER (SubjectPublicKeyInfo) form
    std::vector<unsigned char> getPublicKeyDER() const;
    std::vector<unsigned char> getCompressedSec1() const;
    std::vector<unsigned char> getUncompressedSec1() const;

    // Return private key in PEM
    std::string getPrivateKey() const;

    // Return public key in PEM
    std::string getPublicKey() const;

    // Verify an ECDSA signature. This legacy/general verifier intentionally does
    // not impose transaction canonicality because it is also used by
    // non-transaction application signatures.
    static bool verify(const std::vector<unsigned char>& pubKeyDER,
                       const std::string& message,
                       const std::vector<unsigned char>& signature);

    // transaction-signature canonicality.
    // signature is DER only; the trailing sighash byte is checked by script code.
    static bool isStrictDERLowS(const std::vector<unsigned char>& signature);
    static bool verifyCanonicalTransactionSignature(
        const std::vector<unsigned char>& pubKey,
        const std::string& message,
        const std::vector<unsigned char>& signature);

    /**
     * Return the raw 33-byte compressed public key.
     *
     * We do this by duplicating the underlying EC_KEY,
     * forcing compressed form, and calling i2o_ECPublicKey.
     */
    std::vector<unsigned char> getCompressedPublicKey() const {
        if (!pkey_) {
            throw std::runtime_error("ECDSAKey::getCompressedPublicKey: no key loaded");
        }

        // Obtain a (const) EC_KEY pointer from the EVP_PKEY
        // Some older openssl versions return 'const EC_KEY*', others 'EC_KEY*'.
        // We'll store it in a 'const EC_KEY*' then do EC_KEY_dup for a modifiable copy.
        const EC_KEY* ec_const = EVP_PKEY_get0_EC_KEY(pkey_);
        if (!ec_const) {
            throw std::runtime_error("ECDSAKey::getCompressedPublicKey: not an EC key?");
        }

        // Duplicate it so we can call EC_KEY_set_conv_form
        // This avoids the invalid conversion from const -> non-const.
        EC_KEY* ec = EC_KEY_dup(ec_const);
        if (!ec) {
            throw std::runtime_error("ECDSAKey::getCompressedPublicKey: EC_KEY_dup failed");
        }

        // Force compressed form
        EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);

        // Now compute size needed
        int size = i2o_ECPublicKey(ec, nullptr);
        if (size <= 0) {
            EC_KEY_free(ec);
            throw std::runtime_error("ECDSAKey::getCompressedPublicKey: i2o_ECPublicKey size error");
        }

        std::vector<unsigned char> buf(size);
        unsigned char* p = buf.data();
        if (i2o_ECPublicKey(ec, &p) != size) {
            EC_KEY_free(ec);
            throw std::runtime_error("ECDSAKey::getCompressedPublicKey: i2o_ECPublicKey mismatch");
        }

        // free the duplicate
        EC_KEY_free(ec);

        // Typically returns 33 bytes for a compressed secp256k1 pubkey
        return buf;
    }

// Sign with a specific K value (for signature grinding/MagicLock)
std::vector<unsigned char> signWithK(const std::string& message, 
                                     const std::vector<unsigned char>& k) const;

private:
    EVP_PKEY* pkey_ = nullptr;
};

#endif // CRYPTO_ECDSA_H





