#ifndef ADDRESS_HELPERS_H
#define ADDRESS_HELPERS_H

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "utils.h"
#include "logging.h"
#include "tokens.h"
#include "tru_network_params.h"

// Base58 Alphabet
static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// decodeBase58Check() is defined below; declare it here so the
// canonical free helper can use the real Base58Check decoder.
inline std::vector<uint8_t> decodeBase58Check(const std::string &base58Addr);

// canonical TRU mainnet P2PKH validation.
inline bool isValidAddress(const std::string &addr) {
    try {
        const auto decoded = decodeBase58Check(addr);
        return decoded.size() == 25 &&
               decoded[0] == tru_network::MAINNET_P2PKH_VERSION;
    } catch (...) {
        return false;
    }
}


// ----------------------------------------------------------------------
// Hex-encode binary data
// ----------------------------------------------------------------------
inline std::string hexEncode(const std::vector<uint8_t> &data) {
    std::ostringstream oss;
    for (auto byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

// ----------------------------------------------------------------------
// Hex-decode into binary data
// ----------------------------------------------------------------------
inline std::vector<uint8_t> hexDecode(const std::string &hex) {
    // Handle empty string
    if (hex.empty()) {
        return std::vector<uint8_t>();
    }
    
    // Check for odd length
    if (hex.size() % 2 != 0) {
        Logger::log("[hexDecode] Warning: Hex string has odd length: " + std::to_string(hex.size()) + ", hex: " + hex);
        throw std::runtime_error("[hexDecode] Input length must be even.");
    }
    
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        try {
            int byteVal = std::stoi(byteStr, nullptr, 16);
            result.push_back(static_cast<uint8_t>(byteVal));
        } catch (const std::exception& e) {
            Logger::log("[hexDecode] Invalid hex characters at position " + std::to_string(i) + ": " + byteStr);
            throw std::runtime_error("[hexDecode] Invalid hex character detected.");
        }
    }
    
    return result;
}

// ----------------------------------------------------------------------
// Base58 Encoding
// ----------------------------------------------------------------------
inline std::string base58Encode(const std::vector<uint8_t> &input) {
    std::vector<uint8_t> data(input);
    int zeroCount = 0;
    while (zeroCount < data.size() && data[zeroCount] == 0) zeroCount++;

    std::string encoded;
    int start = zeroCount;
    while (start < data.size()) {
        int carry = 0;
        for (size_t i = start; i < data.size(); ++i) {
            int val = data[i] + carry * 256;
            data[i] = val / 58;
            carry = val % 58;
        }
        encoded.push_back(BASE58_ALPHABET[carry]);
        while (start < data.size() && data[start] == 0) start++;
    }

    for (int i = 0; i < zeroCount; ++i) encoded.push_back('1');
    std::reverse(encoded.begin(), encoded.end());
    return encoded;
}

// ----------------------------------------------------------------------
// Base58 Decoding
// ----------------------------------------------------------------------

inline std::vector<uint8_t> base58Decode(const std::string &input)
{
    Logger::log("[base58Decode] Decoding base58 string: " + input);

    // Result starts empty (NOT with an extra 0)
    std::vector<uint8_t> result;

    // 1) Convert each character from base58
    for (char c : input)
    {
        const char *p = std::strchr(BASE58_ALPHABET, c);
        if (!p)
        {
            std::string msg = "[base58Decode] Invalid character in base58: ";
            msg.push_back(c);
            Logger::log(msg);
            throw std::runtime_error(msg);
        }

        int digit = static_cast<int>(p - BASE58_ALPHABET);
        int carry = digit;

        // Multiply “result” by 58, add “digit”
        for (size_t i = 0; i < result.size(); i++)
        {
            int value = result[i] * 58 + carry;
            result[i] = static_cast<uint8_t>(value & 0xFF);
            carry     = (value >> 8);
        }
        // If carry remains, push new byte
        while (carry > 0)
        {
            result.push_back(static_cast<uint8_t>(carry & 0xFF));
            carry >>= 8;
        }
    }

    // 2) Count leading '1' chars => these represent leading zero bytes
    int leadingZeros = 0;
    for (char c : input)
    {
        if (c == '1') leadingZeros++;
        else break;
    }

    // 3) Append those leading zeros => each '1' means we add a 0x00 in final
    std::vector<uint8_t> decoded;
    decoded.reserve(leadingZeros + result.size());
    for (int i = 0; i < leadingZeros; i++)
    {
        decoded.push_back(0);
    }

    // 4) The computed result is in reverse order => reverse it to big‐endian
    // Example: if result = [0x39, 0x01], reversed is [0x01, 0x39]
    std::reverse(result.begin(), result.end());
    decoded.insert(decoded.end(), result.begin(), result.end());

    // Logging
    std::ostringstream oss;
    oss << "[base58Decode] raw decoded size=" << decoded.size()
        << ", hex=" << hexEncode(decoded);
    Logger::log(oss.str());

    return decoded;
}
// ----------------------------------------------------------------------
// Base58Check Decoding (with checksum verification)
// ----------------------------------------------------------------------

inline std::vector<uint8_t> decodeBase58Check(const std::string &base58Addr)
{
    Logger::log("[decodeBase58Check] Starting decode for address=" + base58Addr);

    // 1) Base58 decode
    std::vector<uint8_t> raw = base58Decode(base58Addr);
    if (raw.size() < 4) {
        Logger::log("[decodeBase58Check] Decoded data too short (<4 bytes).");
        throw std::runtime_error("[decodeBase58Check] Decoded data too short.");
    }

    // 2) The last 4 bytes are the checksum
    std::vector<uint8_t> data(raw.begin(), raw.end() - 4);
    std::vector<uint8_t> cksum(raw.end() - 4, raw.end());

    // 3) Double SHA256 of 'data'
    unsigned char hash1[32], hash2[32];
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, data.data(), data.size());
        SHA256_Final(hash1, &ctx);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, hash1, 32);
        SHA256_Final(hash2, &ctx);
    }

    // 4) Compare hash2[0..3] to cksum
    if (std::memcmp(hash2, cksum.data(), 4) != 0) {
        // Log the address mismatch for diagnosis.
        std::ostringstream oss;
        oss << "[decodeBase58Check] Checksum mismatch.\n"
            << "    data hex   : " << hexEncode(data) << "\n"
            << "    expected(4): " << std::hex << std::setw(2) << std::setfill('0')
            << (int)hash2[0] << (int)hash2[1] << (int)hash2[2] << (int)hash2[3] << "\n"
            << "    actual(4)  : "
            << (int)cksum[0] << (int)cksum[1] << (int)cksum[2] << (int)cksum[3];
        Logger::log(oss.str());

        throw std::runtime_error("[decodeBase58Check] Checksum mismatch.");
    }

    // 5) If we get here, success => raw is version+payload+4 cksum (often 25 bytes total)
    std::ostringstream oss;
    oss << "[decodeBase58Check] decode success => total bytes=" << raw.size()
        << ", hex=" << hexEncode(raw);
    Logger::log(oss.str());

    return raw;
}

// ----------------------------------------------------------------------
// createP2PKHScriptFromAddress (standard textual script)
// ----------------------------------------------------------------------
inline std::string createP2PKHScriptFromAddress(const std::string &base58Addr) {
    auto decoded = decodeBase58Check(base58Addr);
    std::string hashHex = bytesToHex({decoded.begin() + 1, decoded.begin() + 21});
    return "OP_DUP OP_HASH160 " + hashHex + " OP_EQUALVERIFY OP_CHECKSIG";
}

// ----------------------------------------------------------------------
// createP2PKHScriptFromAddressHex (raw HEX script for UTXO storage)
// ----------------------------------------------------------------------
inline std::string createP2PKHScriptFromAddressHex(const std::string &base58Addr) {
    auto decoded = decodeBase58Check(base58Addr);
    std::ostringstream scriptHex;
    scriptHex << "76a914" << hexEncode({decoded.begin() + 1, decoded.begin() + 21}) << "88ac";
    return scriptHex.str();
}


inline std::string createP2PKHScriptHexFromAddress(const std::string &base58Addr)
{
    // 1) Decode Base58Check => [TRU version, 20-byte hash160, 4-byte checksum]
    std::vector<unsigned char> decoded = decodeBase58Check(base58Addr);
    if (decoded.size() != 25) {
        throw std::runtime_error("[createP2PKHScriptHexFromAddress] Not a 25-byte P2PKH address");
    }
    if (decoded[0] != tru_network::MAINNET_P2PKH_VERSION) {
        throw std::runtime_error("[createP2PKHScriptHexFromAddress] Non-TRU mainnet P2PKH address");
    }

    // 2) The next 20 bytes is the hash160
    std::vector<unsigned char> hash20(decoded.begin() + 1, decoded.begin() + 21);

    // 3) Build the 25-byte script
    //    OP_DUP (0x76)
    //    OP_HASH160 (0xa9)
    //    push 20 (0x14)
    //    [hash160]
    //    OP_EQUALVERIFY (0x88)
    //    OP_CHECKSIG (0xac)
    std::vector<unsigned char> script;
    script.reserve(25);
    script.push_back(0x76);          // OP_DUP
    script.push_back(0xa9);          // OP_HASH160
    script.push_back(0x14);          // push 20 bytes
    script.insert(script.end(), hash20.begin(), hash20.end());
    script.push_back(0x88);          // OP_EQUALVERIFY
    script.push_back(0xac);          // OP_CHECKSIG

    // 4) Convert to hex
    return bytesToHex(script);
}


// ----------------------------------------------------------------------
// Verify scriptPubKey matches address
// ----------------------------------------------------------------------


inline bool doesScriptPayToAddress(const std::string &scriptPubKeyHexOrText,
                                   const std::string &base58Addr)
{
    // 1) If scriptPubKey is already textual "OP_DUP ...", compare directly
    const std::string textual = createP2PKHScriptFromAddress(base58Addr);
    if (scriptPubKeyHexOrText == textual) return true;

    // 2) If scriptPubKey is raw hex "76a914...88ac", parse that
    //    Compare to createP2PKHScriptFromAddressHex(base58Addr)
    const std::string hexNeeded = createP2PKHScriptHexFromAddress(base58Addr); 
    if (scriptPubKeyHexOrText == hexNeeded) return true;

    return false;
}

// ----------------------------------------------------------------------
// Hash160 calculation (RIPEMD160 of SHA256)
// ----------------------------------------------------------------------
inline std::vector<uint8_t> computeHash160(const std::vector<uint8_t> &data) {
    uint8_t shaHash[32];
    SHA256(data.data(), data.size(), shaHash);

    uint8_t ripeHash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(shaHash, SHA256_DIGEST_LENGTH, ripeHash);

    return {ripeHash, ripeHash + RIPEMD160_DIGEST_LENGTH};
}

// ----------------------------------------------------------------------
// Check if pubkey matches the provided address
// ----------------------------------------------------------------------
inline bool doesPubKeyMatchAddress(const std::vector<uint8_t> &pubkey, const std::string &base58Addr) {
    auto decoded = decodeBase58Check(base58Addr);
    if (decoded.size() != 25 || decoded[0] != tru_network::MAINNET_P2PKH_VERSION) return false;
    auto pubKeyHash = computeHash160(pubkey);
    return std::equal(pubKeyHash.begin(), pubKeyHash.end(), decoded.begin() + 1);
}

// ----------------------------------------------------------------------
// decodeP2PKHScriptToAddress (textual to Base58 address)
// ----------------------------------------------------------------------
inline std::string decodeP2PKHScriptToAddress(const std::string &scriptPubKey) {
    std::istringstream iss(scriptPubKey);
    std::string tok;
    std::vector<std::string> tokens;
    while (iss >> tok) tokens.push_back(tok);

    if (tokens.size() != 5 || tokens[0] != "OP_DUP" || tokens[1] != "OP_HASH160" ||
        tokens[3] != "OP_EQUALVERIFY" || tokens[4] != "OP_CHECKSIG" || tokens[2].size() != 40) {
        throw std::runtime_error("[decodeP2PKHScriptToAddress] Invalid script.");
    }

    auto hash160 = hexDecode(tokens[2]);
    std::vector<uint8_t> addrData = {tru_network::MAINNET_P2PKH_VERSION};
    addrData.insert(addrData.end(), hash160.begin(), hash160.end());

    uint8_t hash1[32], hash2[32];
    SHA256(addrData.data(), 21, hash1);
    SHA256(hash1, 32, hash2);

    addrData.insert(addrData.end(), hash2, hash2 + 4);
    return base58Encode(addrData);
}
// ----------------------------------------------------------------------
//  	BUILD OP_RETURN SCRIPT
// ----------------------------------------------------------------------
inline std::string buildOpReturnScriptHex(const std::vector<unsigned char> &payload)
{
    // Standard OP_RETURN:
    //   0x6a = OP_RETURN
    //   Then a single-byte push if payload.size() < 0x4c
    //   Then the payload
    if (payload.size() > 0xfc) {
        // For demonstration, we only do single-byte push
        throw std::runtime_error("buildOpReturnScriptHex => payload too large");
    }
    std::vector<unsigned char> script;
    script.reserve(1 + 1 + payload.size());
    script.push_back(0x6a); // OP_RETURN
    script.push_back(static_cast<unsigned char>(payload.size()));
    script.insert(script.end(), payload.begin(), payload.end());

    return bytesToHex(script);
}
// ----------------------------------------------------------------------
//			HELPER FOR UTXO GET SENDER
// ----------------------------------------------------------------------
inline std::string encodeBase58Check(const std::vector<unsigned char>& data) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    std::vector<unsigned char> fullData = data;
    fullData.insert(fullData.end(), hash2, hash2 + 4);
    return base58Encode(fullData);
}

inline std::string pubkeyToAddress(const std::vector<unsigned char>& pubkey) {
    std::vector<unsigned char> pubkeyHash = hash160(pubkey);
    std::vector<unsigned char> addressBytes = {tru_network::MAINNET_P2PKH_VERSION};
    addressBytes.insert(addressBytes.end(), pubkeyHash.begin(), pubkeyHash.end());
    return encodeBase58Check(addressBytes);
}

// removed unused duplicate script-to-address encoder.
// Native P2PKH address generation uses the canonical Base58Check path.

// Add new function specifically for contract addresses
inline bool isContractAddress(const std::string &addr) {
    size_t colonPos = addr.find(':');
    if (colonPos == std::string::npos) return false;
    
    std::string txid = addr.substr(0, colonPos);
    std::string voutStr = addr.substr(colonPos + 1);
    
    if (txid.length() != 64) return false;
    for (char c : txid) {
        if (!isxdigit(c)) return false;
    }
    
    try {
        std::stoul(voutStr);
        return true;
    } catch (...) {
        return false;
    }
}

// Add a new comprehensive validation function
inline bool isValidAddressOrContract(const std::string &addr) {
    return isValidAddress(addr) || isContractAddress(addr);
}


#endif // ADDRESS_HELPERS_H
