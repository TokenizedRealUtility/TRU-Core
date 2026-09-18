#include "crypto_ecdsa.h"
#include <stdexcept>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <cstring>
#include <openssl/err.h>
#include "logging.h"
#include "address_helpers.h"

#include <memory>

// TRU Security Patch 11 -------------------------------------------------------
// Canonical secp256k1 transaction signatures.
namespace {

bool decodeStrictSecp256k1DER(
    const std::vector<unsigned char>& signature,
    ECDSA_SIG** outSig)
{
    if (outSig) *outSig = nullptr;
    if (signature.size() < 8 || signature.size() > 72) return false;

    const unsigned char* p = signature.data();
    const unsigned char* const end = signature.data() + signature.size();
    ECDSA_SIG* parsed = d2i_ECDSA_SIG(nullptr, &p, signature.size());
    if (!parsed || p != end) {
        ECDSA_SIG_free(parsed);
        return false;
    }

    const int canonicalLen = i2d_ECDSA_SIG(parsed, nullptr);
    if (canonicalLen <= 0 ||
        static_cast<std::size_t>(canonicalLen) != signature.size()) {
        ECDSA_SIG_free(parsed);
        return false;
    }
    std::vector<unsigned char> canonical(static_cast<std::size_t>(canonicalLen));
    unsigned char* q = canonical.data();
    if (i2d_ECDSA_SIG(parsed, &q) != canonicalLen ||
        canonical != signature) {
        ECDSA_SIG_free(parsed);
        return false;
    }

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(parsed, &r, &s);
    if (!r || !s || BN_is_zero(r) || BN_is_zero(s) ||
        BN_is_negative(r) || BN_is_negative(s)) {
        ECDSA_SIG_free(parsed);
        return false;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    BIGNUM* halfOrder = BN_new();
    bool ok = group && order && halfOrder &&
              EC_GROUP_get_order(group, order, nullptr) == 1 &&
              BN_cmp(r, order) < 0 &&
              BN_cmp(s, order) < 0;

    if (ok) {
        BN_rshift1(halfOrder, order);
        ok = BN_cmp(s, halfOrder) <= 0;
    }

    BN_free(halfOrder);
    BN_free(order);
    EC_GROUP_free(group);

    if (!ok) {
        ECDSA_SIG_free(parsed);
        return false;
    }

    if (outSig) {
        *outSig = parsed;
    } else {
        ECDSA_SIG_free(parsed);
    }
    return true;
}


std::vector<unsigned char> normalizeLowS(
    const std::vector<unsigned char>& signature)
{
    if (signature.empty()) {
        throw std::runtime_error("normalizeLowS: empty signature");
    }

    const unsigned char* p = signature.data();
    ECDSA_SIG* parsed = d2i_ECDSA_SIG(nullptr, &p, signature.size());
    if (!parsed || p != signature.data() + signature.size()) {
        ECDSA_SIG_free(parsed);
        throw std::runtime_error("normalizeLowS: invalid DER signature");
    }

    const BIGNUM* r0 = nullptr;
    const BIGNUM* s0 = nullptr;
    ECDSA_SIG_get0(parsed, &r0, &s0);
    if (!r0 || !s0) {
        ECDSA_SIG_free(parsed);
        throw std::runtime_error("normalizeLowS: missing r/s");
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    BIGNUM* halfOrder = BN_new();
    if (!group || !order || !halfOrder ||
        EC_GROUP_get_order(group, order, nullptr) != 1) {
        BN_free(halfOrder);
        BN_free(order);
        EC_GROUP_free(group);
        ECDSA_SIG_free(parsed);
        throw std::runtime_error("normalizeLowS: secp256k1 order failure");
    }
    BN_rshift1(halfOrder, order);

    if (BN_cmp(s0, halfOrder) > 0) {
        BIGNUM* r = BN_dup(r0);
        BIGNUM* s = BN_new();
        if (!r || !s || BN_sub(s, order, s0) != 1 ||
            ECDSA_SIG_set0(parsed, r, s) != 1) {
            BN_free(r);
            BN_free(s);
            BN_free(halfOrder);
            BN_free(order);
            EC_GROUP_free(group);
            ECDSA_SIG_free(parsed);
            throw std::runtime_error("normalizeLowS: normalization failure");
        }
    }

    BN_free(halfOrder);
    BN_free(order);
    EC_GROUP_free(group);

    const int len = i2d_ECDSA_SIG(parsed, nullptr);
    if (len <= 0) {
        ECDSA_SIG_free(parsed);
        throw std::runtime_error("normalizeLowS: DER length failure");
    }
    std::vector<unsigned char> out(static_cast<std::size_t>(len));
    unsigned char* q = out.data();
    if (i2d_ECDSA_SIG(parsed, &q) != len) {
        ECDSA_SIG_free(parsed);
        throw std::runtime_error("normalizeLowS: DER serialization failure");
    }
    ECDSA_SIG_free(parsed);

    if (!decodeStrictSecp256k1DER(out, nullptr)) {
        throw std::runtime_error("normalizeLowS: non-canonical result");
    }
    return out;
}

} // namespace

// Constructor
ECDSAKey::ECDSAKey() : pkey_(nullptr) {}

ECDSAKey ECDSAKey::fromPrivateKey(const std::string& privKeyPEM) {
    ECDSAKey obj;
    BIO* bio = BIO_new_mem_buf(privKeyPEM.data(), (int)privKeyPEM.size());
    if (!bio) {
        throw std::runtime_error("BIO_new_mem_buf failed");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        throw std::runtime_error("PEM_read_bio_PrivateKey failed");
    }
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Key is not EC");
    }

    // **Use get1 to get a modifiable EC_KEY**
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_get1_EC_KEY failed");
    }

    // Force compressed form
    EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);

    // Put it back into pkey
    if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_set1_EC_KEY failed");
    }
    // Free local handle
    EC_KEY_free(ec);

    // Done
    obj.pkey_ = pkey;
    return obj;
}

ECDSAKey ECDSAKey::fromRawBytes(const std::vector<uint8_t>& rawBytes) {
    ECDSAKey obj;

    // 1) Create a new EC_KEY on secp256k1
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    }

    // 2) Convert rawBytes -> BIGNUM
    BIGNUM* priv_bn = BN_bin2bn(rawBytes.data(), rawBytes.size(), nullptr);
    if (!priv_bn) {
        EC_KEY_free(ec_key);
        throw std::runtime_error("BN_bin2bn failed");
    }

    // 3) Set the private key
    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("EC_KEY_set_private_key failed");
    }

    // 4) Derive the corresponding public key
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_key = EC_POINT_new(group);
    if (!pub_key) {
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("EC_POINT_new failed");
    }
    if (EC_POINT_mul(group, pub_key, priv_bn, nullptr, nullptr, nullptr) != 1) {
        EC_POINT_free(pub_key);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("EC_POINT_mul failed");
    }
    if (EC_KEY_set_public_key(ec_key, pub_key) != 1) {
        EC_POINT_free(pub_key);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("EC_KEY_set_public_key failed");
    }

    // 5) **** Force Compressed ****
    EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

    // 6) Convert the EC_KEY -> EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_POINT_free(pub_key);
        BN_free(priv_bn);
        EC_KEY_free(ec_key);
        throw std::runtime_error("EVP_PKEY_new failed");
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        // Once assigned, ec_key is owned by pkey, so we must free carefully
        EC_POINT_free(pub_key);
        BN_free(priv_bn);
        throw std::runtime_error("EVP_PKEY_assign_EC_KEY failed");
    }

    // Cleanup
    BN_free(priv_bn);
    EC_POINT_free(pub_key);

    // 7) Store pkey in our object
    obj.pkey_ = pkey;

    // Optional sanity check
    if (!obj.pkey_ || EVP_PKEY_bits(obj.pkey_) != 256) {
        throw std::runtime_error("Invalid key generated");
    }

    return obj;
}

// Keep existing helper function
static std::vector<unsigned char> sha256(const unsigned char *data, size_t len) {
    std::vector<unsigned char> outDigest;
    outDigest.resize(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if(!mdctx) {
        throw std::runtime_error("sha256: EVP_MD_CTX_new failed");
    }
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("sha256: DigestInit failed");
    }
    if(EVP_DigestUpdate(mdctx, data, len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("sha256: DigestUpdate failed");
    }
    if(EVP_DigestFinal_ex(mdctx, outDigest.data(), &outLen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("sha256: DigestFinal failed");
    }
    EVP_MD_CTX_free(mdctx);
    outDigest.resize(outLen);
    return outDigest;
}

// Existing destructor
ECDSAKey::~ECDSAKey() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
}

// Existing move constructor
ECDSAKey::ECDSAKey(ECDSAKey&& other) noexcept {
    pkey_ = other.pkey_;
    other.pkey_ = nullptr;
}

// Existing move assignment
ECDSAKey& ECDSAKey::operator=(ECDSAKey&& other) noexcept {
    if (this != &other) {
        if (pkey_) EVP_PKEY_free(pkey_);
        pkey_ = other.pkey_;
        other.pkey_ = nullptr;
    }
    return *this;
}

// Existing generate method
ECDSAKey ECDSAKey::generate() {
    ECDSAKey obj;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if(!pctx) {
        throw std::runtime_error("ECDSAKey::generate: EVP_PKEY_CTX_new_from_name failed");
    }
    if(EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("ECDSAKey::generate: keygen_init failed");
    }
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("ECDSAKey::generate: set_ec_paramgen_curve_nid failed");
    }
    EVP_PKEY *localKey = nullptr;
    if(EVP_PKEY_keygen(pctx, &localKey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("ECDSAKey::generate: keygen failed");
    }
    EVP_PKEY_CTX_free(pctx);
    obj.pkey_ = localKey;
    return obj;
}

// Existing getPublicKeyDER
std::vector<unsigned char> ECDSAKey::getPublicKeyDER() const {
    if(!pkey_) {
        throw std::runtime_error("ECDSAKey::getPublicKeyDER: no key loaded");
    }
    BIO *mem = BIO_new(BIO_s_mem());
    if(!mem) {
        throw std::runtime_error("ECDSAKey::getPublicKeyDER: BIO_s_mem() failed");
    }
    if(i2d_PUBKEY_bio(mem, pkey_) <= 0) {
        BIO_free(mem);
        throw std::runtime_error("ECDSAKey::getPublicKeyDER: i2d_PUBKEY_bio failed");
    }
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    if(!bptr || bptr->length <= 0) {
        BIO_free(mem);
        throw std::runtime_error("ECDSAKey::getPublicKeyDER: empty buffer");
    }
    std::vector<unsigned char> der(bptr->length);
    std::memcpy(der.data(), bptr->data, bptr->length);
    BIO_free(mem);
    return der;
}

std::vector<unsigned char> ECDSAKey::getCompressedSec1() const {
    if (!pkey_) {
        throw std::runtime_error("ECDSAKey::getCompressedSec1(): No key loaded");
    }

    // 1) Get a const EC_KEY pointer out of the EVP_PKEY
    const EC_KEY* ec_const = EVP_PKEY_get0_EC_KEY(pkey_);
    if (!ec_const) {
        throw std::runtime_error("ECDSAKey::getCompressedSec1(): not an EC key");
    }

    // 2) Duplicate it so we have a non-const copy that we can call EC_KEY_set_conv_form on
    EC_KEY* ec_copy = EC_KEY_dup(ec_const);
    if (!ec_copy) {
        throw std::runtime_error("ECDSAKey::getCompressedSec1(): EC_KEY_dup failed");
    }

    // 3) Force compressed form in that copy
    EC_KEY_set_conv_form(ec_copy, POINT_CONVERSION_COMPRESSED);

    // 4) Figure out how many bytes we need
    int size = i2o_ECPublicKey(ec_copy, nullptr);
    if (size <= 0) {
        EC_KEY_free(ec_copy);
        throw std::runtime_error("ECDSAKey::getCompressedSec1(): i2o_ECPublicKey size error");
    }

    // 5) Allocate a buffer and serialize
    std::vector<unsigned char> sec1(size);
    unsigned char *p = sec1.data();
    if (i2o_ECPublicKey(ec_copy, &p) != size) {
        EC_KEY_free(ec_copy);
        throw std::runtime_error("ECDSAKey::getCompressedSec1(): i2o_ECPublicKey failed second call");
    }

    // 6) Clean up the copy
    EC_KEY_free(ec_copy);

    // 7) Return the final 33-byte compressed pubkey
    return sec1;
}

std::vector<unsigned char> ECDSAKey::getUncompressedSec1() const {
    if (!pkey_) {
        throw std::runtime_error("ECDSAKey::getUncompressedSec1(): No key loaded");
    }

    // 1) Obtain a const pointer to the EC_KEY
    const EC_KEY* ec_const = EVP_PKEY_get0_EC_KEY(pkey_);
    if (!ec_const) {
        throw std::runtime_error("ECDSAKey::getUncompressedSec1(): not an EC key");
    }

    // 2) Duplicate it so we can modify its conv_form
    EC_KEY* ec_copy = EC_KEY_dup(ec_const);
    if (!ec_copy) {
        throw std::runtime_error("ECDSAKey::getUncompressedSec1(): EC_KEY_dup failed");
    }

    // 3) Force uncompressed form => 65 bytes for secp256k1
    EC_KEY_set_conv_form(ec_copy, POINT_CONVERSION_UNCOMPRESSED);

    // 4) Determine how many bytes we need
    int size = i2o_ECPublicKey(ec_copy, nullptr);
    if (size <= 0) {
        EC_KEY_free(ec_copy);
        throw std::runtime_error("ECDSAKey::getUncompressedSec1(): i2o_ECPublicKey size error");
    }

    // 5) Allocate buffer + call again
    std::vector<unsigned char> uncompressed(size);
    unsigned char *p = uncompressed.data();
    if (i2o_ECPublicKey(ec_copy, &p) != size) {
        EC_KEY_free(ec_copy);
        throw std::runtime_error("ECDSAKey::getUncompressedSec1(): i2o_ECPublicKey failed second call");
    }

    // 6) Cleanup
    EC_KEY_free(ec_copy);

    // Now uncompressed = [0x04, X(32 bytes), Y(32 bytes)] => 65 bytes
    return uncompressed;
}

// Existing getPrivateKey
std::string ECDSAKey::getPrivateKey() const {
    if(!pkey_) {
        throw std::runtime_error("ECDSAKey::getPrivateKey: no key loaded");
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio) {
        throw std::runtime_error("ECDSAKey::getPrivateKey: BIO_new failed");
    }
    if(!PEM_write_bio_PrivateKey(bio, pkey_, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio);
        throw std::runtime_error("ECDSAKey::getPrivateKey: PEM_write_bio_PrivateKey failed");
    }
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if(!bptr || bptr->length <= 0) {
        BIO_free(bio);
        throw std::runtime_error("ECDSAKey::getPrivateKey: empty buffer");
    }
    std::string privateKey(bptr->data, bptr->length);
    BIO_free(bio);
    return privateKey;
}

// Existing getPublicKey
std::string ECDSAKey::getPublicKey() const {
    if(!pkey_) {
        throw std::runtime_error("ECDSAKey::getPublicKey: no key loaded");
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio) {
        throw std::runtime_error("ECDSAKey::getPublicKey: BIO_new failed");
    }
    if(!PEM_write_bio_PUBKEY(bio, pkey_)) {
        BIO_free(bio);
        throw std::runtime_error("ECDSAKey::getPublicKey: PEM_write_bio_PUBKEY failed");
    }
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    if(!bptr || bptr->length <= 0) {
        BIO_free(bio);
        throw std::runtime_error("ECDSAKey::getPublicKey: empty buffer");
    }
    std::string publicKey(bptr->data, bptr->length);
    BIO_free(bio);
    return publicKey;
}

std::vector<unsigned char> ECDSAKey::sign(const std::string &message) const {
    if (!pkey_) {
        throw std::runtime_error("ECDSAKey::sign: no private key loaded");
    }

    // Get the const EC_KEY* from EVP_PKEY
    const EC_KEY* const_ec_key = EVP_PKEY_get0_EC_KEY(pkey_);
    if (!const_ec_key) {
        throw std::runtime_error("ECDSAKey::sign: failed to get EC_KEY from EVP_PKEY");
    }

    // Cast away constness since ECDSA_sign needs EC_KEY* but won’t modify it
    EC_KEY* ec_key = const_cast<EC_KEY*>(const_ec_key);

    // Allocate signature buffer
    std::vector<unsigned char> signature(ECDSA_size(ec_key));
    unsigned int sigLen = signature.size();

    // Perform the signing operation
    if (ECDSA_sign(0, reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                   signature.data(), &sigLen, ec_key) != 1) {
        throw std::runtime_error("ECDSAKey::sign: ECDSA_sign failed");
    }

    // Resize to actual signature length, then force the unique low-S form.
    signature.resize(sigLen);
    return normalizeLowS(signature);
}

//================================================================================
//                    ECDSAKey::verify 
//================================================================================
bool ECDSAKey::verify(const std::vector<unsigned char> &pubkey,
                      const std::string &message,
                      const std::vector<unsigned char> &signature) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        Logger::log("[ECDSAKey::verify] ERROR: EC_KEY_new_by_curve_name failed");
        return false;
    }

    const unsigned char* pPub = pubkey.data();
    if (o2i_ECPublicKey(&ec_key, &pPub, pubkey.size()) == nullptr) {
        Logger::log("[ECDSAKey::verify] ERROR: o2i_ECPublicKey failed");
        EC_KEY_free(ec_key);
        return false;
    }

    // Handle the message as binary data properly
    std::vector<unsigned char> msgData;
    if (!message.empty()) {
        msgData.assign(message.begin(), message.end());
    }
    
    if (msgData.size() != 32) {
        Logger::log("[ECDSAKey::verify] ERROR: Invalid message length: " + std::to_string(msgData.size()) + ", expected 32");
        EC_KEY_free(ec_key);
        return false;
    }

    // Verify the signature against the message digest
    int result = ECDSA_verify(0, msgData.data(), msgData.size(), signature.data(), signature.size(), ec_key);
    if (result <= 0) {
        Logger::log("[ECDSAKey::verify] ERROR: ECDSA_verify failed, result=" + std::to_string(result));
        
        // Log additional debug info
        Logger::log("[ECDSAKey::verify] Message hash: " + hexEncode(msgData));
        Logger::log("[ECDSAKey::verify] Signature length: " + std::to_string(signature.size()));
        Logger::log("[ECDSAKey::verify] Public key length: " + std::to_string(pubkey.size()));
        
        EC_KEY_free(ec_key);
        return false;
    }

    EC_KEY_free(ec_key);
    Logger::log("[ECDSAKey::verify] Signature verified successfully");
    return true;
}

bool ECDSAKey::isStrictDERLowS(
    const std::vector<unsigned char>& signature)
{
    return decodeStrictSecp256k1DER(signature, nullptr);
}

bool ECDSAKey::verifyCanonicalTransactionSignature(
    const std::vector<unsigned char>& pubKey,
    const std::string& message,
    const std::vector<unsigned char>& signature)
{
    if (!isStrictDERLowS(signature)) {
        Logger::log(
            "[ECDSAKey::verifyCanonicalTransactionSignature] "
            "Rejected non-strict-DER or high-S signature");
        return false;
    }
    return verify(pubKey, message, signature);
}

std::vector<unsigned char> ECDSAKey::signWithK(const std::string& message, 
                                               const std::vector<unsigned char>& k) const {
    if (!pkey_) {
        throw std::runtime_error("ECDSAKey::signWithK: no private key loaded");
    }
    
    // Get EC_KEY from EVP_PKEY
    const EC_KEY* const_ec = EVP_PKEY_get0_EC_KEY(pkey_);
    if (!const_ec) {
        throw std::runtime_error("ECDSAKey::signWithK: failed to get EC_KEY");
    }
    
    // Need non-const for ECDSA operations
    EC_KEY* ec_key = const_cast<EC_KEY*>(const_ec);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const BIGNUM* priv_key = EC_KEY_get0_private_key(ec_key);
    
    // Convert K to BIGNUM
    BIGNUM* k_bn = BN_bin2bn(k.data(), k.size(), nullptr);
    if (!k_bn) {
        throw std::runtime_error("ECDSAKey::signWithK: failed to convert K to BIGNUM");
    }
    
    // Get order of the group
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    
    // Ensure K is in valid range [1, n-1]
    if (BN_cmp(k_bn, order) >= 0 || BN_is_zero(k_bn)) {
        BN_free(k_bn);
        BN_free(order);
        throw std::runtime_error("ECDSAKey::signWithK: K value out of range");
    }
    
    // Check if message is already a hash (32 bytes for SHA256)
    // If it's 32 bytes, assume it's already hashed and use directly
    std::vector<unsigned char> msgHash;
    if (message.size() == 32) {
        // Message is already a hash, use it directly
        msgHash.assign(message.begin(), message.end());
        Logger::log("[ECDSAKey::signWithK] Using pre-hashed message (32 bytes)");
    } else {
        // Hash the message with SHA256
        msgHash = sha256(
            reinterpret_cast<const unsigned char*>(message.data()), 
            message.size()
        );
        Logger::log("[ECDSAKey::signWithK] Hashed message of size " + std::to_string(message.size()));
    }
    
    // Create ECDSA_SIG structure
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        BN_free(k_bn);
        BN_free(order);
        throw std::runtime_error("ECDSAKey::signWithK: ECDSA_SIG_new failed");
    }
    
    // Calculate r = (k*G).x mod n
    EC_POINT* point = EC_POINT_new(group);
    BN_CTX* ctx = BN_CTX_new();
    
    // k*G
    EC_POINT_mul(group, point, k_bn, nullptr, nullptr, ctx);
    
    // Get x coordinate
    BIGNUM* r = BN_new();
    BIGNUM* y = BN_new(); // Not used but needed for the call
    EC_POINT_get_affine_coordinates(group, point, r, y, ctx);
    BN_mod(r, r, order, ctx);
    
    // Calculate s = k^-1 * (z + r*d) mod n
    BIGNUM* s = BN_new();
    BIGNUM* kinv = BN_mod_inverse(nullptr, k_bn, order, ctx);
    BIGNUM* z = BN_bin2bn(msgHash.data(), msgHash.size(), nullptr);
    BIGNUM* tmp = BN_new();
    
    BN_mod_mul(tmp, r, priv_key, order, ctx);  // r*d mod n
    BN_mod_add(tmp, tmp, z, order, ctx);       // (z + r*d) mod n
    BN_mod_mul(s, kinv, tmp, order, ctx);      // k^-1 * (z + r*d) mod n
    
    // Set r and s in signature (transfer ownership to ECDSA_SIG)
    ECDSA_SIG_set0(sig, r, s);
    
    // Serialize signature to DER
    int sig_len = i2d_ECDSA_SIG(sig, nullptr);
    if (sig_len <= 0) {
        ECDSA_SIG_free(sig);
        BN_free(k_bn);
        BN_free(order);
        BN_free(kinv);
        BN_free(z);
        BN_free(tmp);
        BN_free(y);
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        throw std::runtime_error("ECDSAKey::signWithK: i2d_ECDSA_SIG failed");
    }
    
    std::vector<unsigned char> signature(sig_len);
    unsigned char* sig_ptr = signature.data();
    i2d_ECDSA_SIG(sig, &sig_ptr);
    
    // Cleanup
    ECDSA_SIG_free(sig);
    BN_free(k_bn);
    BN_free(order);
    BN_free(kinv);
    BN_free(z);
    BN_free(tmp);
    BN_free(y);
    EC_POINT_free(point);
    BN_CTX_free(ctx);
    
    // fixed-K/MagicLock signatures are normalized too.
    return normalizeLowS(signature);
}
