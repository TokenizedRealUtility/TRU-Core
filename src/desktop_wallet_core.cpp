#include "desktop_wallet_core.h"
#include "wallet_encryption_v1.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sodium.h>

#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

constexpr std::uint8_t kTruP2pkhVersion = 0x41;
constexpr std::uint32_t kTruCoinType = 0x00545255u;
constexpr std::uint32_t kHardened = 0x80000000u;
constexpr char kPayloadMagic[] = "TRU_DESKTOP_WALLET_V1";
constexpr std::size_t kSeedBytes = 64;
constexpr std::size_t kMaxAddresses = 1000000;

struct TxInput {
    std::string txid;
    std::uint32_t vout = 0;
    std::vector<unsigned char> scriptSig;
    std::uint32_t sequence = 0xffffffffu;
};

struct TxOutput {
    std::uint64_t amount = 0;
    std::vector<unsigned char> script;
};

struct Tx {
    std::uint32_t version = 1;
    std::vector<TxInput> vin;
    std::vector<TxOutput> vout;
    std::uint32_t lockTime = 0;

    // Exact serialized token-metadata tail, beginning with the metadata flag.
    // Ordinary TRU transactions use the canonical single zero byte.
    std::vector<unsigned char> metadataTail{0};
};

void setError(std::string* out, const std::string& text) {
    if (out) *out = text;
}

void wipeString(std::string& s) noexcept {
    if (!s.empty()) sodium_memzero(s.data(), s.size());
    s.clear();
}

std::string toHex(const unsigned char* p, std::size_t n) {
    static constexpr char table[] = "0123456789abcdef";
    std::string out(n * 2, '\0');
    for (std::size_t i = 0; i < n; ++i) {
        out[2 * i] = table[p[i] >> 4];
        out[2 * i + 1] = table[p[i] & 0x0f];
    }
    return out;
}

std::string toHex(const std::vector<unsigned char>& v) {
    return toHex(v.data(), v.size());
}

bool fromHex(const std::string& s, std::vector<unsigned char>& out) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    if (s.size() % 2 != 0) return false;
    out.assign(s.size() / 2, 0);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int a = nibble(s[2 * i]);
        const int b = nibble(s[2 * i + 1]);
        if (a < 0 || b < 0) {
            out.clear();
            return false;
        }
        out[i] = static_cast<unsigned char>((a << 4) | b);
    }
    return true;
}

std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256(
    const unsigned char* p, std::size_t n) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> out{};
    SHA256(p, n, out.data());
    return out;
}

std::array<unsigned char, SHA256_DIGEST_LENGTH> doubleSha(
    const unsigned char* p, std::size_t n) {
    auto first = sha256(p, n);
    return sha256(first.data(), first.size());
}

std::vector<unsigned char> canonicalPrivateFromSeed(
    const std::vector<std::uint8_t>& seed, std::uint32_t index) {
    ext_key master{};
    ext_key child{};

    if (bip32_key_from_seed(
            seed.data(), seed.size(), BIP32_VER_MAIN_PRIVATE,
            0, &master) != WALLY_OK) {
        throw std::runtime_error("libwally master-key derivation failed");
    }

    const std::uint32_t path[5] = {
        kHardened | 44u,
        kHardened | kTruCoinType,
        kHardened | 0u,
        0u,
        index
    };

    if (bip32_key_from_parent_path(
            &master, path, 5, BIP32_FLAG_KEY_PRIVATE,
            &child) != WALLY_OK) {
        sodium_memzero(&master, sizeof(master));
        throw std::runtime_error("libwally TRU child-key derivation failed");
    }

    std::vector<unsigned char> raw(
        child.priv_key + 1, child.priv_key + 33);
    sodium_memzero(&master, sizeof(master));
    sodium_memzero(&child, sizeof(child));
    return raw;
}

std::vector<unsigned char> compressedPublic(
    const std::vector<unsigned char>& rawPrivate) {
    if (rawPrivate.size() != 32)
        throw std::runtime_error("private key must be 32 bytes");

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* bn = BN_bin2bn(
        rawPrivate.data(), static_cast<int>(rawPrivate.size()), nullptr);
    BN_CTX* ctx = BN_CTX_new();

    if (!ec || !bn || !ctx) {
        EC_KEY_free(ec);
        BN_free(bn);
        BN_CTX_free(ctx);
        throw std::runtime_error("secp256k1 allocation failed");
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    BIGNUM* order = BN_new();
    EC_POINT* point = EC_POINT_new(group);

    if (!order || !point ||
        EC_GROUP_get_order(group, order, ctx) != 1 ||
        BN_is_zero(bn) || BN_cmp(bn, order) >= 0 ||
        EC_KEY_set_private_key(ec, bn) != 1 ||
        EC_POINT_mul(group, point, bn, nullptr, nullptr, ctx) != 1 ||
        EC_KEY_set_public_key(ec, point) != 1) {
        EC_POINT_free(point);
        BN_free(order);
        EC_KEY_free(ec);
        BN_free(bn);
        BN_CTX_free(ctx);
        throw std::runtime_error("invalid secp256k1 private key");
    }

    EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);
    const int n = i2o_ECPublicKey(ec, nullptr);
    if (n != 33) {
        EC_POINT_free(point);
        BN_free(order);
        EC_KEY_free(ec);
        BN_free(bn);
        BN_CTX_free(ctx);
        throw std::runtime_error("compressed public key length invalid");
    }

    std::vector<unsigned char> out(static_cast<std::size_t>(n));
    unsigned char* q = out.data();
    if (i2o_ECPublicKey(ec, &q) != n) {
        out.clear();
        EC_POINT_free(point);
        BN_free(order);
        EC_KEY_free(ec);
        BN_free(bn);
        BN_CTX_free(ctx);
        throw std::runtime_error("compressed public key serialization failed");
    }

    EC_POINT_free(point);
    BN_free(order);
    EC_KEY_free(ec);
    BN_free(bn);
    BN_CTX_free(ctx);
    return out;
}

std::string addressFromPublic(const std::vector<unsigned char>& pub) {
    if (pub.size() != EC_PUBLIC_KEY_LEN)
        throw std::runtime_error("compressed public key must be 33 bytes");

    unsigned char h160[HASH160_LEN];
    if (wally_hash160(pub.data(), pub.size(), h160, sizeof(h160))
        != WALLY_OK) {
        throw std::runtime_error("libwally HASH160 failed");
    }

    unsigned char versioned[1 + HASH160_LEN];
    versioned[0] = kTruP2pkhVersion;
    std::memcpy(versioned + 1, h160, HASH160_LEN);

    char* encoded = nullptr;
    if (wally_base58_from_bytes(
            versioned, sizeof(versioned),
            BASE58_FLAG_CHECKSUM, &encoded) != WALLY_OK ||
        !encoded) {
        throw std::runtime_error("libwally TRU Base58Check failed");
    }

    std::string out(encoded);
    wally_free_string(encoded);
    sodium_memzero(h160, sizeof(h160));
    sodium_memzero(versioned, sizeof(versioned));
    return out;
}

bool decodeTruAddress(
    const std::string& address,
    std::array<unsigned char, HASH160_LEN>& hashOut) {
    // libwally BASE58_FLAG_CHECKSUM validates and strips the 4-byte checksum
    // from the returned payload, but the destination buffer must still have
    // room for those checksum bytes while validation is performed.
    unsigned char decoded[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    std::size_t written = 0;
    if (wally_base58_to_bytes(
            address.c_str(), BASE58_FLAG_CHECKSUM,
            decoded, sizeof(decoded), &written) != WALLY_OK ||
        written != (1 + HASH160_LEN) ||
        decoded[0] != kTruP2pkhVersion) {
        sodium_memzero(decoded, sizeof(decoded));
        return false;
    }
    std::copy(decoded + 1, decoded + 1 + HASH160_LEN, hashOut.begin());
    sodium_memzero(decoded, sizeof(decoded));
    return true;
}

std::vector<unsigned char> p2pkhScript(const std::string& address) {
    std::array<unsigned char, HASH160_LEN> h{};
    if (!decodeTruAddress(address, h))
        throw std::runtime_error("invalid TRU mainnet address");

    std::vector<unsigned char> out{0x76, 0xa9, 0x14};
    out.insert(out.end(), h.begin(), h.end());
    out.push_back(0x88);
    out.push_back(0xac);
    return out;
}

void writeU32Le(std::vector<unsigned char>& out, std::uint32_t v) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<unsigned char>((v >> (8u * i)) & 0xffu));
}

void writeU64Le(std::vector<unsigned char>& out, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(static_cast<unsigned char>((v >> (8u * i)) & 0xffu));
}

void writeVarInt(std::vector<unsigned char>& out, std::uint64_t v) {
    if (v < 0xfdULL) {
        out.push_back(static_cast<unsigned char>(v));
    } else if (v <= 0xffffULL) {
        out.push_back(0xfd);
        out.push_back(static_cast<unsigned char>(v & 0xff));
        out.push_back(static_cast<unsigned char>((v >> 8) & 0xff));
    } else if (v <= 0xffffffffULL) {
        out.push_back(0xfe);
        writeU32Le(out, static_cast<std::uint32_t>(v));
    } else {
        out.push_back(0xff);
        writeU64Le(out, v);
    }
}

std::uint32_t readU32Le(
    const std::vector<unsigned char>& raw, std::size_t& pos) {
    if (pos + 4 > raw.size())
        throw std::runtime_error("prepared transaction truncated at uint32");
    std::uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i)
        v |= static_cast<std::uint32_t>(raw[pos++]) << (8u * i);
    return v;
}

std::uint64_t readU64Le(
    const std::vector<unsigned char>& raw, std::size_t& pos) {
    if (pos + 8 > raw.size())
        throw std::runtime_error("prepared transaction truncated at uint64");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(raw[pos++]) << (8u * i);
    return v;
}

std::uint64_t readVarInt(
    const std::vector<unsigned char>& raw, std::size_t& pos) {
    if (pos >= raw.size())
        throw std::runtime_error("prepared transaction truncated at varint");
    const unsigned char first = raw[pos++];
    if (first < 0xfd) return first;
    if (first == 0xfd) {
        if (pos + 2 > raw.size())
            throw std::runtime_error("prepared transaction truncated at varint16");
        const std::uint64_t v =
            static_cast<std::uint64_t>(raw[pos]) |
            (static_cast<std::uint64_t>(raw[pos + 1]) << 8);
        pos += 2;
        if (v < 0xfdULL)
            throw std::runtime_error("non-canonical prepared varint16");
        return v;
    }
    if (first == 0xfe) {
        const std::uint64_t v = readU32Le(raw, pos);
        if (v <= 0xffffULL)
            throw std::runtime_error("non-canonical prepared varint32");
        return v;
    }
    const std::uint64_t v = readU64Le(raw, pos);
    if (v <= 0xffffffffULL)
        throw std::runtime_error("non-canonical prepared varint64");
    return v;
}

Tx parsePreparedTx(const std::string& rawHex) {
    constexpr std::uint64_t kMaxInputs = 256;
    constexpr std::uint64_t kMaxOutputs = 2048;
    constexpr std::uint64_t kMaxScriptBytes = 4ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t kMaxMetadataBytes = 4ULL * 1024ULL * 1024ULL;

    std::vector<unsigned char> raw;
    if (!fromHex(rawHex, raw) || raw.empty())
        throw std::runtime_error("prepared transaction is not valid hex");

    std::size_t pos = 0;
    Tx tx;
    tx.version = readU32Le(raw, pos);

    const std::uint64_t vinCount = readVarInt(raw, pos);
    if (vinCount == 0 || vinCount > kMaxInputs)
        throw std::runtime_error("prepared transaction input count out of range");

    tx.vin.reserve(static_cast<std::size_t>(vinCount));
    for (std::uint64_t i = 0; i < vinCount; ++i) {
        if (pos + 32 > raw.size())
            throw std::runtime_error("prepared transaction truncated at input txid");

        TxInput in;
        in.txid = toHex(raw.data() + pos, 32);
        pos += 32;
        in.vout = readU32Le(raw, pos);

        const std::uint64_t scriptLen = readVarInt(raw, pos);
        if (scriptLen > kMaxScriptBytes ||
            scriptLen > raw.size() - pos)
            throw std::runtime_error("prepared input script length invalid");
        in.scriptSig.assign(
            raw.begin() + static_cast<std::ptrdiff_t>(pos),
            raw.begin() + static_cast<std::ptrdiff_t>(pos + scriptLen));
        pos += static_cast<std::size_t>(scriptLen);
        in.sequence = readU32Le(raw, pos);
        tx.vin.push_back(std::move(in));
    }

    const std::uint64_t voutCount = readVarInt(raw, pos);
    if (voutCount == 0 || voutCount > kMaxOutputs)
        throw std::runtime_error("prepared transaction output count out of range");

    tx.vout.reserve(static_cast<std::size_t>(voutCount));
    for (std::uint64_t i = 0; i < voutCount; ++i) {
        TxOutput out;
        out.amount = readU64Le(raw, pos);
        const std::uint64_t scriptLen = readVarInt(raw, pos);
        if (scriptLen > kMaxScriptBytes ||
            scriptLen > raw.size() - pos)
            throw std::runtime_error("prepared output script length invalid");
        out.script.assign(
            raw.begin() + static_cast<std::ptrdiff_t>(pos),
            raw.begin() + static_cast<std::ptrdiff_t>(pos + scriptLen));
        pos += static_cast<std::size_t>(scriptLen);
        tx.vout.push_back(std::move(out));
    }

    tx.lockTime = readU32Le(raw, pos);
    if (pos >= raw.size())
        throw std::runtime_error("prepared transaction missing metadata flag");

    const std::size_t tailStart = pos;
    const unsigned char flag = raw[pos++];
    if (flag == 0) {
        if (pos != raw.size())
            throw std::runtime_error("prepared transaction has bytes after empty metadata flag");
    } else if (flag == 1) {
        const std::uint64_t metadataLen = readVarInt(raw, pos);
        if (metadataLen > kMaxMetadataBytes ||
            metadataLen > raw.size() - pos ||
            pos + metadataLen != raw.size())
            throw std::runtime_error("prepared transaction metadata length invalid");
        pos += static_cast<std::size_t>(metadataLen);
    } else {
        throw std::runtime_error("prepared transaction has invalid metadata flag");
    }

    tx.metadataTail.assign(
        raw.begin() + static_cast<std::ptrdiff_t>(tailStart),
        raw.end());
    return tx;
}

std::vector<unsigned char> serializeTx(const Tx& tx) {
    std::vector<unsigned char> out;
    writeU32Le(out, tx.version);
    writeVarInt(out, tx.vin.size());

    for (const auto& in : tx.vin) {
        std::vector<unsigned char> txid;
        if (!fromHex(in.txid, txid) || txid.size() != 32)
            throw std::runtime_error("UTXO txid must be 32-byte hex");

        // Mirrors current TRU serializeBinary(): displayed txid bytes are
        // written in the same order, not byte-reversed.
        out.insert(out.end(), txid.begin(), txid.end());
        writeU32Le(out, in.vout);
        writeVarInt(out, in.scriptSig.size());
        out.insert(out.end(), in.scriptSig.begin(), in.scriptSig.end());
        writeU32Le(out, in.sequence);
    }

    writeVarInt(out, tx.vout.size());
    for (const auto& o : tx.vout) {
        writeU64Le(out, o.amount);
        writeVarInt(out, o.script.size());
        out.insert(out.end(), o.script.begin(), o.script.end());
    }

    writeU32Le(out, tx.lockTime);

    if (tx.metadataTail.empty())
        throw std::runtime_error("transaction metadata tail is empty");
    out.insert(
        out.end(),
        tx.metadataTail.begin(),
        tx.metadataTail.end());
    return out;
}

std::array<unsigned char, 32> canonicalSigHash(
    const Tx& tx, std::size_t inputIndex,
    const std::vector<unsigned char>& previousScript) {
    if (inputIndex >= tx.vin.size())
        throw std::runtime_error("sighash input index out of range");

    Tx temp = tx;
    for (auto& in : temp.vin) in.scriptSig.clear();
    temp.vin[inputIndex].scriptSig = previousScript;

    auto serialized = serializeTx(temp);
    serialized.push_back(0x01); // SIGHASH_ALL uint32 little-endian
    serialized.push_back(0x00);
    serialized.push_back(0x00);
    serialized.push_back(0x00);
    return doubleSha(serialized.data(), serialized.size());
}

std::vector<unsigned char> strictDerLowSSign(
    const std::vector<unsigned char>& rawPrivate,
    const std::array<unsigned char, 32>& digest) {
    if (rawPrivate.size() != 32)
        throw std::runtime_error("private key must be 32 bytes");

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv = BN_bin2bn(rawPrivate.data(), 32, nullptr);
    BN_CTX* ctx = BN_CTX_new();
    if (!ec || !priv || !ctx) {
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("signing allocation failure");
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    BIGNUM* order = BN_new();
    EC_POINT* pubPoint = EC_POINT_new(group);
    if (!order || !pubPoint ||
        EC_GROUP_get_order(group, order, ctx) != 1 ||
        BN_is_zero(priv) || BN_cmp(priv, order) >= 0 ||
        EC_KEY_set_private_key(ec, priv) != 1 ||
        EC_POINT_mul(group, pubPoint, priv, nullptr, nullptr, ctx) != 1 ||
        EC_KEY_set_public_key(ec, pubPoint) != 1) {
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("signing key setup failure");
    }

    ECDSA_SIG* sig = ECDSA_do_sign(
        digest.data(), static_cast<int>(digest.size()), ec);
    if (!sig) {
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("ECDSA signing failed");
    }

    const BIGNUM *r0 = nullptr, *s0 = nullptr;
    ECDSA_SIG_get0(sig, &r0, &s0);
    BIGNUM* half = BN_dup(order);
    if (!half || BN_rshift1(half, half) != 1) {
        BN_free(half); ECDSA_SIG_free(sig);
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("low-S order setup failed");
    }

    if (BN_cmp(s0, half) > 0) {
        BIGNUM* r = BN_dup(r0);
        BIGNUM* s = BN_new();
        if (!r || !s || BN_sub(s, order, s0) != 1 ||
            ECDSA_SIG_set0(sig, r, s) != 1) {
            BN_free(r); BN_free(s); BN_free(half);
            ECDSA_SIG_free(sig); EC_POINT_free(pubPoint); BN_free(order);
            EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
            throw std::runtime_error("low-S normalization failed");
        }
    }

    const int derLen = i2d_ECDSA_SIG(sig, nullptr);
    if (derLen <= 0) {
        BN_free(half); ECDSA_SIG_free(sig);
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("DER signature length failed");
    }

    std::vector<unsigned char> der(static_cast<std::size_t>(derLen));
    unsigned char* p = der.data();
    if (i2d_ECDSA_SIG(sig, &p) != derLen) {
        der.clear();
        BN_free(half); ECDSA_SIG_free(sig);
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("DER signature serialization failed");
    }

    // Reparse exact bytes to prove canonical DER and low-S before returning.
    const unsigned char* read = der.data();
    ECDSA_SIG* parsed = d2i_ECDSA_SIG(nullptr, &read, der.size());
    if (!parsed || read != der.data() + der.size()) {
        ECDSA_SIG_free(parsed);
        BN_free(half); ECDSA_SIG_free(sig);
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("strict DER self-check failed");
    }
    const BIGNUM *pr = nullptr, *ps = nullptr;
    ECDSA_SIG_get0(parsed, &pr, &ps);
    if (!pr || !ps || BN_is_zero(pr) || BN_is_negative(pr) ||
        BN_is_zero(ps) || BN_is_negative(ps) ||
        BN_cmp(ps, half) > 0) {
        ECDSA_SIG_free(parsed);
        BN_free(half); ECDSA_SIG_free(sig);
        EC_POINT_free(pubPoint); BN_free(order);
        EC_KEY_free(ec); BN_free(priv); BN_CTX_free(ctx);
        throw std::runtime_error("low-S self-check failed");
    }

    ECDSA_SIG_free(parsed);
    BN_free(half);
    ECDSA_SIG_free(sig);
    EC_POINT_free(pubPoint);
    BN_free(order);
    EC_KEY_free(ec);
    BN_free(priv);
    BN_CTX_free(ctx);
    return der;
}

void pushData(
    std::vector<unsigned char>& script,
    const std::vector<unsigned char>& data) {
    if (data.size() <= 75) {
        script.push_back(static_cast<unsigned char>(data.size()));
    } else if (data.size() <= 255) {
        script.push_back(0x4c); // OP_PUSHDATA1
        script.push_back(static_cast<unsigned char>(data.size()));
    } else {
        throw std::runtime_error("script push exceeds PUSHDATA1");
    }
    script.insert(script.end(), data.begin(), data.end());
}

bool readFile(
    const std::string& path,
    std::vector<std::uint8_t>& out,
    std::string* errorOut) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        setError(errorOut, "cannot open wallet file");
        return false;
    }
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end <= 0 || end > static_cast<std::streamoff>(64 * 1024 * 1024)) {
        setError(errorOut, "wallet file size invalid");
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(end));
    if (!in.read(reinterpret_cast<char*>(out.data()), end)) {
        out.clear();
        setError(errorOut, "wallet file read failed");
        return false;
    }
    return true;
}

bool atomicWrite(
    const std::string& path,
    const std::vector<std::uint8_t>& bytes,
    std::string* errorOut) {
    namespace fs = std::filesystem;
    try {
        fs::path dst(path);
        if (!dst.has_parent_path()) {
            setError(errorOut, "wallet path requires a parent directory");
            return false;
        }
        fs::create_directories(dst.parent_path());
#ifndef _WIN32
        ::chmod(dst.parent_path().c_str(), 0700);
#endif
        fs::path tmp = dst;
        tmp += ".tmp";

        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) {
                setError(errorOut, "cannot create temporary wallet file");
                return false;
            }
            out.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
            out.flush();
            if (!out) {
                setError(errorOut, "temporary wallet write failed");
                return false;
            }
        }

#ifndef _WIN32
        ::chmod(tmp.c_str(), 0600);
        const int fd = ::open(tmp.c_str(), O_RDONLY);
        if (fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
        if (::rename(tmp.c_str(), dst.c_str()) != 0) {
            std::error_code ec;
            fs::remove(tmp, ec);
            setError(errorOut, "atomic wallet rename failed");
            return false;
        }
#else
        if (!MoveFileExW(
                tmp.wstring().c_str(), dst.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::error_code ec;
            fs::remove(tmp, ec);
            setError(errorOut, "atomic wallet replace failed");
            return false;
        }
#endif
        return true;
    } catch (const std::exception& e) {
        setError(errorOut, e.what());
        return false;
    }
}

} // namespace

DesktopWalletCore::DesktopWalletCore() {
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium initialization failed");
}

DesktopWalletCore::~DesktopWalletCore() {
    lock();
}

bool DesktopWalletCore::exists(const std::string& path) const {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

void DesktopWalletCore::setSeed(
    const std::vector<std::uint8_t>& seed) {
    if (seed.size() != kSeedBytes)
        throw std::runtime_error("desktop wallet seed must be 64 bytes");
    lock();
    seed_ = seed;
    memoryLocked_ = sodium_mlock(seed_.data(), seed_.size()) == 0;
    unlocked_ = true;
}

void DesktopWalletCore::lock() noexcept {
    if (!seed_.empty()) {
        sodium_memzero(seed_.data(), seed_.size());
        if (memoryLocked_) sodium_munlock(seed_.data(), seed_.size());
    }
    seed_.clear();
    seed_.shrink_to_fit();
    nextIndex_ = 0;
    unlocked_ = false;
    memoryLocked_ = false;
}

std::vector<std::uint8_t> DesktopWalletCore::makePayload() const {
    if (!unlocked_ || seed_.size() != kSeedBytes)
        throw std::runtime_error("wallet is locked");

    const std::size_t magicLen = std::strlen(kPayloadMagic);
    std::vector<std::uint8_t> out(
        kPayloadMagic, kPayloadMagic + magicLen);
    out.push_back(0);
    out.insert(out.end(), seed_.begin(), seed_.end());
    out.push_back(static_cast<std::uint8_t>(nextIndex_ & 0xff));
    out.push_back(static_cast<std::uint8_t>((nextIndex_ >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>((nextIndex_ >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((nextIndex_ >> 24) & 0xff));
    return out;
}

bool DesktopWalletCore::loadPayload(
    const std::vector<std::uint8_t>& plain,
    std::string* errorOut) {
    const std::size_t magicLen = std::strlen(kPayloadMagic);
    const std::size_t expected = magicLen + 1 + kSeedBytes + 4;

    if (plain.size() != expected ||
        std::memcmp(plain.data(), kPayloadMagic, magicLen) != 0 ||
        plain[magicLen] != 0) {
        setError(errorOut, "desktop wallet payload format invalid");
        return false;
    }

    std::vector<std::uint8_t> seed(
        plain.begin() + static_cast<std::ptrdiff_t>(magicLen + 1),
        plain.begin() + static_cast<std::ptrdiff_t>(magicLen + 1 + kSeedBytes));

    const std::size_t p = magicLen + 1 + kSeedBytes;
    const std::uint32_t next =
        static_cast<std::uint32_t>(plain[p]) |
        (static_cast<std::uint32_t>(plain[p + 1]) << 8) |
        (static_cast<std::uint32_t>(plain[p + 2]) << 16) |
        (static_cast<std::uint32_t>(plain[p + 3]) << 24);

    if (next == 0 || next > kMaxAddresses) {
        sodium_memzero(seed.data(), seed.size());
        setError(errorOut, "desktop wallet address counter invalid");
        return false;
    }

    setSeed(seed);
    sodium_memzero(seed.data(), seed.size());
    nextIndex_ = next;
    return true;
}

bool DesktopWalletCore::persist(
    const std::string& path,
    const std::string& passphrase,
    std::string* errorOut) const {
    if (passphrase.size() < 12) {
        setError(errorOut, "wallet passphrase must contain at least 12 characters");
        return false;
    }

    std::vector<std::uint8_t> plain;
    std::vector<std::uint8_t> encrypted;
    try {
        plain = makePayload();
        if (!tru_wallet_encryption_v1::encrypt(
                plain, passphrase, encrypted, errorOut)) {
            sodium_memzero(plain.data(), plain.size());
            return false;
        }

        const bool ok = atomicWrite(path, encrypted, errorOut);
        sodium_memzero(plain.data(), plain.size());
        sodium_memzero(encrypted.data(), encrypted.size());
        return ok;
    } catch (const std::exception& e) {
        if (!plain.empty()) sodium_memzero(plain.data(), plain.size());
        if (!encrypted.empty()) sodium_memzero(encrypted.data(), encrypted.size());
        setError(errorOut, e.what());
        return false;
    }
}

bool DesktopWalletCore::create(
    const std::string& path,
    const std::string& passphrase,
    std::string* errorOut) {
    if (exists(path)) {
        setError(errorOut, "wallet already exists");
        return false;
    }
    if (passphrase.size() < 12) {
        setError(errorOut, "wallet passphrase must contain at least 12 characters");
        return false;
    }

    std::vector<std::uint8_t> seed(kSeedBytes);
    if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
        setError(errorOut, "cryptographic random generator failed");
        return false;
    }

    try {
        setSeed(seed);
        sodium_memzero(seed.data(), seed.size());
        nextIndex_ = 1;

        if (!persist(path, passphrase, errorOut)) {
            lock();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        sodium_memzero(seed.data(), seed.size());
        lock();
        setError(errorOut, e.what());
        return false;
    }
}

bool DesktopWalletCore::unlock(
    const std::string& path,
    const std::string& passphrase,
    std::string* errorOut) {
    lock();

    std::vector<std::uint8_t> envelope;
    std::vector<std::uint8_t> plain;

    if (!readFile(path, envelope, errorOut)) return false;

    if (!tru_wallet_encryption_v1::isEnvelopeV1(envelope)) {
        sodium_memzero(envelope.data(), envelope.size());
        setError(errorOut, "wallet is not a TRU_WALLET_ENC_V1 envelope");
        return false;
    }

    if (!tru_wallet_encryption_v1::decrypt(
            envelope, passphrase, plain, errorOut)) {
        sodium_memzero(envelope.data(), envelope.size());
        return false;
    }

    sodium_memzero(envelope.data(), envelope.size());
    const bool ok = loadPayload(plain, errorOut);
    sodium_memzero(plain.data(), plain.size());
    if (!ok) lock();
    return ok;
}

std::vector<std::uint8_t> DesktopWalletCore::derivePrivateAny(
    std::uint32_t index) const {
    if (!unlocked_ || seed_.size() != kSeedBytes)
        throw std::runtime_error("wallet is locked");
    if (index >= kMaxAddresses)
        throw std::runtime_error("address index out of range");
    return canonicalPrivateFromSeed(seed_, index);
}

std::vector<std::uint8_t> DesktopWalletCore::derivePublicAny(
    std::uint32_t index) const {
    auto raw = derivePrivateAny(index);
    auto pub = compressedPublic(raw);
    sodium_memzero(raw.data(), raw.size());
    return pub;
}

std::vector<std::uint8_t> DesktopWalletCore::derivePrivate(
    std::uint32_t index) const {
    if (index >= nextIndex_)
        throw std::runtime_error("address index not generated");
    return derivePrivateAny(index);
}

std::vector<std::uint8_t> DesktopWalletCore::derivePublic(
    std::uint32_t index) const {
    if (index >= nextIndex_)
        throw std::runtime_error("address index not generated");
    return derivePublicAny(index);
}

std::string DesktopWalletCore::addressFromPublic(
    const std::vector<std::uint8_t>& pub) const {
    return ::addressFromPublic(pub);
}

std::string DesktopWalletCore::address(
    std::uint32_t index) const {
    return addressFromPublic(derivePublic(index));
}

std::vector<std::string> DesktopWalletCore::addresses() const {
    if (!unlocked_) throw std::runtime_error("wallet is locked");
    std::vector<std::string> out;
    out.reserve(nextIndex_);
    for (std::uint32_t i = 0; i < nextIndex_; ++i)
        out.push_back(address(i));
    return out;
}

std::string DesktopWalletCore::currentAddress() const {
    if (!unlocked_ || nextIndex_ == 0)
        throw std::runtime_error("wallet is locked");
    return address(nextIndex_ - 1);
}

bool DesktopWalletCore::createNextAddress(
    const std::string& path,
    const std::string& passphrase,
    std::string& addressOut,
    std::string* errorOut) {
    if (!unlocked_) {
        setError(errorOut, "unlock wallet first");
        return false;
    }

    // Authenticate the passphrase against the current encrypted file before
    // mutating the address counter.
    DesktopWalletCore verifier;
    std::string verifyError;
    if (!verifier.unlock(path, passphrase, &verifyError)) {
        setError(errorOut, "passphrase authentication failed");
        return false;
    }
    verifier.lock();

    if (nextIndex_ >= kMaxAddresses) {
        setError(errorOut, "address limit reached");
        return false;
    }

    const std::uint32_t old = nextIndex_;
    try {
        addressOut = addressFromPublic(derivePublicAny(nextIndex_));
        ++nextIndex_;
        if (!persist(path, passphrase, errorOut)) {
            nextIndex_ = old;
            addressOut.clear();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        nextIndex_ = old;
        addressOut.clear();
        setError(errorOut, e.what());
        return false;
    }
}

bool DesktopWalletCore::backup(
    const std::string& walletPath,
    const std::string& backupPath,
    std::string* errorOut) const {
    std::vector<std::uint8_t> bytes;
    if (!readFile(walletPath, bytes, errorOut)) return false;

    if (!tru_wallet_encryption_v1::isEnvelopeV1(bytes)) {
        sodium_memzero(bytes.data(), bytes.size());
        setError(errorOut, "source wallet is not a valid encrypted envelope");
        return false;
    }

    const bool ok = atomicWrite(backupPath, bytes, errorOut);
    sodium_memzero(bytes.data(), bytes.size());
    return ok;
}

bool DesktopWalletCore::restoreBackup(
    const std::string& backupPath,
    const std::string& walletPath,
    const std::string& passphrase,
    std::string* errorOut) {
    DesktopWalletCore probe;
    if (!probe.unlock(backupPath, passphrase, errorOut)) return false;
    probe.lock();

    std::vector<std::uint8_t> bytes;
    if (!readFile(backupPath, bytes, errorOut)) return false;

    if (!atomicWrite(walletPath, bytes, errorOut)) {
        sodium_memzero(bytes.data(), bytes.size());
        return false;
    }

    sodium_memzero(bytes.data(), bytes.size());
    return unlock(walletPath, passphrase, errorOut);
}

std::string DesktopWalletCore::recoveryCode() const {
    if (!unlocked_) throw std::runtime_error("wallet is locked");
    return std::string("TRU-DESKTOP-V1:") +
           toHex(seed_.data(), seed_.size()) + ":" +
           std::to_string(nextIndex_);
}

bool DesktopWalletCore::restoreRecovery(
    const std::string& code,
    const std::string& walletPath,
    const std::string& newPassphrase,
    std::string* errorOut) {
    static const std::string prefix = "TRU-DESKTOP-V1:";

    if (code.rfind(prefix, 0) != 0) {
        setError(errorOut, "recovery code prefix invalid");
        return false;
    }

    const std::size_t colon = code.find(':', prefix.size());
    if (colon == std::string::npos) {
        setError(errorOut, "recovery address counter missing");
        return false;
    }

    std::vector<unsigned char> seed;
    if (!fromHex(
            code.substr(prefix.size(), colon - prefix.size()), seed) ||
        seed.size() != kSeedBytes) {
        setError(errorOut, "recovery seed must be exactly 64 bytes");
        return false;
    }

    std::uint64_t count = 0;
    try {
        std::size_t used = 0;
        const std::string number = code.substr(colon + 1);
        count = std::stoull(number, &used);
        if (used != number.size()) throw std::runtime_error("trailing");
    } catch (...) {
        sodium_memzero(seed.data(), seed.size());
        setError(errorOut, "recovery address counter invalid");
        return false;
    }

    if (count == 0 || count > kMaxAddresses) {
        sodium_memzero(seed.data(), seed.size());
        setError(errorOut, "recovery address counter out of range");
        return false;
    }

    try {
        setSeed(seed);
        sodium_memzero(seed.data(), seed.size());
        nextIndex_ = static_cast<std::uint32_t>(count);

        if (!persist(walletPath, newPassphrase, errorOut)) {
            lock();
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        sodium_memzero(seed.data(), seed.size());
        lock();
        setError(errorOut, e.what());
        return false;
    }
}

bool DesktopWalletCore::validateAddress(
    const std::string& addressText) const {
    std::array<unsigned char, HASH160_LEN> h{};
    return decodeTruAddress(addressText, h);
}

std::string DesktopWalletCore::scriptForAddress(
    const std::string& addressText) const {
    return toHex(p2pkhScript(addressText));
}

DesktopWalletSignedTx DesktopWalletCore::buildAndSign(
    const std::vector<DesktopWalletUtxo>& inputs,
    const std::string& recipient,
    std::uint64_t amountAtoms,
    std::uint64_t requestedFeeAtoms) const {
    if (!unlocked_)
        throw std::runtime_error("wallet is locked");
    if (inputs.empty())
        throw std::runtime_error("no UTXOs selected");
    if (!validateAddress(recipient))
        throw std::runtime_error("recipient is not a valid TRU mainnet address");
    if (amountAtoms == 0)
        throw std::runtime_error("send amount is zero");

    std::uint64_t fee = std::max(requestedFeeAtoms, kMinimumFeeAtoms);
    std::uint64_t total = 0;

    Tx tx;
    tx.vin.reserve(inputs.size());

    for (const auto& u : inputs) {
        if (u.txid.size() != 64 ||
            u.amountAtoms == 0 ||
            u.keyIndex >= nextIndex_) {
            throw std::runtime_error("invalid selected UTXO");
        }

        std::string actualScript = u.scriptPubKey;
        std::transform(
            actualScript.begin(), actualScript.end(), actualScript.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        const std::string expectedScript =
            scriptForAddress(address(u.keyIndex));
        if (actualScript != expectedScript)
            throw std::runtime_error("UTXO script does not match local key");

        if (total >
            std::numeric_limits<std::uint64_t>::max() - u.amountAtoms)
            throw std::runtime_error("input sum overflow");
        total += u.amountAtoms;

        TxInput in;
        in.txid = u.txid;
        in.vout = u.vout;
        tx.vin.push_back(std::move(in));
    }

    if (amountAtoms > total || fee > total - amountAtoms)
        throw std::runtime_error("insufficient selected funds");

    tx.vout.push_back({amountAtoms, p2pkhScript(recipient)});

    std::uint64_t change = total - amountAtoms - fee;
    if (change > 0 && change < kDustAtoms) {
        fee += change;
        change = 0;
    }
    if (change >= kDustAtoms)
        tx.vout.push_back({change, p2pkhScript(currentAddress())});

    for (std::size_t i = 0; i < tx.vin.size(); ++i) {
        std::vector<unsigned char> previousScript;
        if (!fromHex(inputs[i].scriptPubKey, previousScript))
            throw std::runtime_error("UTXO script hex invalid");

        const auto digest =
            canonicalSigHash(tx, i, previousScript);

        auto privateKey = derivePrivate(inputs[i].keyIndex);
        auto publicKey = compressedPublic(privateKey);
        auto signature = strictDerLowSSign(privateKey, digest);
        signature.push_back(0x01); // canonical SIGHASH_ALL

        std::vector<unsigned char> scriptSig;
        pushData(scriptSig, signature);
        pushData(scriptSig, publicKey);
        tx.vin[i].scriptSig = std::move(scriptSig);

        sodium_memzero(privateKey.data(), privateKey.size());
    }

    // Mirrors current TRU computeTxId(): clear scriptSigs for txid hashing.
    Tx txForId = tx;
    for (auto& in : txForId.vin) in.scriptSig.clear();
    auto idSerialization = serializeTx(txForId);
    const auto idHash =
        doubleSha(idSerialization.data(), idSerialization.size());

    auto signedSerialization = serializeTx(tx);

    DesktopWalletSignedTx out;
    out.txid = toHex(idHash.data(), idHash.size());
    out.rawHex = toHex(signedSerialization);
    out.inputAtoms = total;
    out.sendAtoms = amountAtoms;
    out.feeAtoms = fee;
    out.changeAtoms = change;
    return out;
}

DesktopWalletSignedTx DesktopWalletCore::signPrepared(
    const std::string& unsignedTxHex,
    const std::vector<DesktopWalletUtxo>& signingInputs) const {
    if (!unlocked_)
        throw std::runtime_error("wallet is locked");

    Tx tx = parsePreparedTx(unsignedTxHex);
    if (tx.vin.size() != signingInputs.size())
        throw std::runtime_error(
            "prepared transaction input descriptors do not match input count");

    std::uint64_t total = 0;
    for (std::size_t i = 0; i < tx.vin.size(); ++i) {
        if (!tx.vin[i].scriptSig.empty())
            throw std::runtime_error(
                "prepared transaction is already signed");

        const DesktopWalletUtxo& descriptor = signingInputs[i];
        if (descriptor.txid != tx.vin[i].txid ||
            descriptor.vout != tx.vin[i].vout)
            throw std::runtime_error(
                "prepared transaction input identity mismatch");
        if (descriptor.amountAtoms == 0 ||
            descriptor.keyIndex >= nextIndex_)
            throw std::runtime_error(
                "prepared transaction signing descriptor invalid");

        std::string actualScript = descriptor.scriptPubKey;
        std::transform(
            actualScript.begin(), actualScript.end(), actualScript.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

        const std::string expectedScript =
            scriptForAddress(address(descriptor.keyIndex));
        if (actualScript != expectedScript)
            throw std::runtime_error(
                "prepared input script does not match local wallet key");

        if (total >
            std::numeric_limits<std::uint64_t>::max() -
            descriptor.amountAtoms)
            throw std::runtime_error(
                "prepared input amount sum overflow");
        total += descriptor.amountAtoms;
    }

    for (std::size_t i = 0; i < tx.vin.size(); ++i) {
        std::vector<unsigned char> previousScript;
        if (!fromHex(signingInputs[i].scriptPubKey, previousScript))
            throw std::runtime_error(
                "prepared input script hex invalid");

        const auto digest =
            canonicalSigHash(tx, i, previousScript);

        auto privateKey =
            derivePrivate(signingInputs[i].keyIndex);
        auto publicKey = compressedPublic(privateKey);
        auto signature = strictDerLowSSign(privateKey, digest);
        signature.push_back(0x01); // SIGHASH_ALL

        std::vector<unsigned char> scriptSig;
        pushData(scriptSig, signature);
        pushData(scriptSig, publicKey);
        tx.vin[i].scriptSig = std::move(scriptSig);

        sodium_memzero(privateKey.data(), privateKey.size());
    }

    // Current TRU computeTxId() intentionally excludes scriptSig and
    // transaction-level tokenMetadata from the stable transaction ID.
    Tx txForId = tx;
    for (auto& in : txForId.vin)
        in.scriptSig.clear();
    txForId.metadataTail.assign(1, 0);

    const auto idSerialization = serializeTx(txForId);
    const auto idHash =
        doubleSha(idSerialization.data(), idSerialization.size());

    const auto signedSerialization = serializeTx(tx);

    DesktopWalletSignedTx out;
    out.txid = toHex(idHash.data(), idHash.size());
    out.rawHex = toHex(signedSerialization);
    out.inputAtoms = total;
    return out;
}

bool DesktopWalletCore::signMessageSha256(
    const std::string& addressText,
    const std::string& canonicalMessage,
    std::string& publicKeyHexOut,
    std::string& signatureHexOut,
    std::string* errorOut) const {
    publicKeyHexOut.clear();
    signatureHexOut.clear();

    if (!unlocked_) {
        setError(errorOut, "wallet is locked");
        return false;
    }
    if (canonicalMessage.empty()) {
        setError(errorOut, "authorization message is empty");
        return false;
    }

    try {
        std::uint32_t keyIndex = nextIndex_;
        for (std::uint32_t i = 0; i < nextIndex_; ++i) {
            if (address(i) == addressText) {
                keyIndex = i;
                break;
            }
        }
        if (keyIndex >= nextIndex_) {
            setError(
                errorOut,
                "authorization address is not owned by this wallet");
            return false;
        }

        auto privateKey = derivePrivate(keyIndex);
        auto publicKey = compressedPublic(privateKey);
        const auto digest = sha256(
            reinterpret_cast<const unsigned char*>(
                canonicalMessage.data()),
            canonicalMessage.size());
        auto signature = strictDerLowSSign(privateKey, digest);

        publicKeyHexOut = toHex(publicKey);
        signatureHexOut = toHex(signature);
        sodium_memzero(privateKey.data(), privateKey.size());
        return true;
    } catch (const std::exception& e) {
        setError(errorOut, e.what());
        return false;
    }
}

bool DesktopWalletCore::parseAmount(
    const std::string& text,
    std::uint64_t& atomsOut,
    std::string* errorOut) {
    atomsOut = 0;
    if (text.empty()) {
        setError(errorOut, "amount is empty");
        return false;
    }

    const std::size_t dot = text.find('.');
    if (dot != std::string::npos &&
        text.find('.', dot + 1) != std::string::npos) {
        setError(errorOut, "amount contains multiple decimal points");
        return false;
    }

    std::string whole =
        dot == std::string::npos ? text : text.substr(0, dot);
    std::string fraction =
        dot == std::string::npos ? "" : text.substr(dot + 1);
    if (whole.empty()) whole = "0";

    if (fraction.size() > 8) {
        setError(errorOut, "TRU amount supports at most 8 decimals");
        return false;
    }

    for (char c : whole) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            setError(errorOut, "amount contains non-digits");
            return false;
        }
    }
    for (char c : fraction) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            setError(errorOut, "amount contains non-digits");
            return false;
        }
    }

    while (fraction.size() < 8) fraction.push_back('0');

    try {
        const std::uint64_t w = std::stoull(whole);
        const std::uint64_t f =
            fraction.empty() ? 0 : std::stoull(fraction);

        if (w >
            std::numeric_limits<std::uint64_t>::max() / kAtomsPerTru) {
            setError(errorOut, "amount overflow");
            return false;
        }

        const std::uint64_t base = w * kAtomsPerTru;
        if (base >
            std::numeric_limits<std::uint64_t>::max() - f) {
            setError(errorOut, "amount overflow");
            return false;
        }

        atomsOut = base + f;
        return true;
    } catch (...) {
        setError(errorOut, "amount parse failed");
        return false;
    }
}

std::string DesktopWalletCore::formatAmount(
    std::uint64_t atoms) {
    std::ostringstream out;
    out << (atoms / kAtomsPerTru) << '.'
        << std::setw(8) << std::setfill('0')
        << (atoms % kAtomsPerTru);
    return out.str();
}
