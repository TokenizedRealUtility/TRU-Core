#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <utility> // for std::pair

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>  // for memset
#include <openssl/sha.h>

#include "stb_image_write.h"
#include <fmt/core.h>
#include <cstdint>
#include <functional>
#include <mutex>

inline std::string colorText(const std::string &text, int colorCode, bool bold = false) {
    return fmt::format("\033[{};{}m{}\033[0m", (bold ? 1 : 0), colorCode, text);
}

inline std::string makeUTXOKey(const std::string& txid, uint32_t vout) {
    return txid + std::to_string(vout);
}


// ------------------------
// ANSI Color Escape Codes
// ------------------------
static constexpr const char* RED    = "\033[31m";
static constexpr const char* GREEN  = "\033[32m";
static constexpr const char* CYAN   = "\033[36m";
static constexpr const char* RESET  = "\033[0m";

// Simple helpers for colored output
void print_error(const std::string &message);
void print_success(const std::string &message);
void print_info(const std::string &message);

// Terminal size helper
std::pair<int, int> getTerminalSize();

// -------------
// Mining / Hash
// -------------
/**
 * @brief Convert a 64‑char hex string -> 32 bytes (little‑endian).
 *        Returns false if invalid.
 */
bool hexToBytes32LE(const std::string &hexStr, unsigned char out32[32]);

/**
 * @brief Compare two 256-bit values in LE. Return true if hashVal <= targetVal
 */
bool compare256LE(const unsigned char hashVal[32],
                  const unsigned char targetVal[32]);

/**
 * @brief bitsToTargetArrayFree
 * Convert compact difficulty bits -> 32-byte big-endian target array.
 */
void bitsToTargetArrayFree(uint32_t bits, unsigned char out[32]);
// -----------------------------------------------
// Provide or include a small base64 encoder:
// ------------------------------------------------
static std::string base64Encode(const unsigned char* data, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len/3)+1)*4);

    unsigned val=0;
    int valb=-6;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}


//========================================================
// Base64 decode function
//========================================================

inline std::string base64Decode(const std::string& encoded) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    
    std::vector<unsigned char> ret;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break;
        auto pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            ret.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return std::string(ret.begin(), ret.end());
}

//========================================================
// Overload for base64Encode to accept std::string
//========================================================
inline std::string base64Encode(const std::string& str) {
    return base64Encode(reinterpret_cast<const unsigned char*>(str.data()), str.size());
}

//========================================================
// Shared target extraction helper.
//========================================================
std::string extractTargetSmart(const std::string& scriptHex);
// ------------------------------------------------
//	Double Sha256
// ------------------------------------------------
static std::string doubleSha256Hex(const std::string &input)
{
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    // First pass
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input.data(), input.size());
    SHA256_Final(hash1, &ctx);

    // Second pass
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &ctx);

    // Convert to hex
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << (int)hash2[i];
    }
    return oss.str(); // 64 chars
}

inline void write32LE(unsigned char *dst, uint32_t val)
{
    dst[0] = val & 0xff;
    dst[1] = (val >> 8) & 0xff;
    dst[2] = (val >>16) & 0xff;
    dst[3] = (val >>24) & 0xff;
}

std::vector<unsigned char> hexToBytes(const std::string &hex);
std::string hexToString(const std::string &hex);
std::string bytesToHex(const std::vector<unsigned char> &bytes);
bool isHex(const std::string &str);
std::string bytesToHex(const std::vector<uint8_t> &data);

std::string hexToString(const std::string &hex);

std::vector<unsigned char> hash160(const std::vector<unsigned char>& input);

std::vector<std::string> loadFromConfig(const std::string& configKey);

bool isValidAddressFormat(const std::string& address);

bool isValidHex(const std::string& s);

std::vector<uint8_t> loadWalletSeed();

uint32_t getNextIndex();

inline std::string toLower(const std::string& str) {
    std::string lowerStr = str;
    for (char& c : lowerStr) {
        c = std::tolower(static_cast<unsigned char>(c));
    }
    return lowerStr;
}

void displayOutputProgressive(std::string& outputBuffer, const std::string& message, int& currentRow, int rows, std::mutex& coutMutex, int color = 32, bool addSpacing = false);

std::string getValidatedInput(
    const std::string& prompt,
    const std::function<bool(const std::string&)>& validator,
    const std::string& errorMessage,
    std::string& outputBuffer,
    int& currentRow,
    int ROWS,
    std::mutex& coutMutex
);

std::string trim(const std::string& str);

std::string readLineWithTimeout(int seconds);

std::pair<std::string, std::string> generateKeyPair();

bool validateBase58Address(const std::string &addr, std::string &err);

std::string varIntEncode(size_t value);

std::string toUpper(std::string_view s);

#endif // UTILS_H
