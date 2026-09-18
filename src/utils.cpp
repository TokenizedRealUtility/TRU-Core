#include "utils.h"
#include <cstdlib>   // std::getenv
#include <iostream>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio>     
#include <cstring>    
#include <mutex>
#include "globals.h"
#include <algorithm>
#include <cctype>     
#include <openssl/ripemd.h>  
#include <openssl/sha.h>     
#include <vector>            
#include <nlohmann/json.hpp>
#include <fstream>
#include "logging.h" 
#include <fstream>
#include <filesystem>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <cctype>
#include <termios.h>
#include <thread>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <iomanip>
#include "address_helpers.h"
#include "tru_network_params.h"
#include <sstream>

std::string toUpper(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    return out;
}
//============================================================================
//
//============================================================================
bool validateBase58Address(const std::string &addr, std::string &err) {
    try {
        // Decode the Base58 address with checksum verification
        std::vector<uint8_t> decoded = decodeBase58Check(addr);

        // Check if the decoded length is 25 bytes (standard for P2PKH addresses)
        if (decoded.size() != 25) {
            std::ostringstream oss;
            oss << "Invalid address length: expected 25 bytes, got " << decoded.size();
            err = oss.str();
            return false;
        }

        // Check TRU mainnet P2PKH version byte
        if (decoded[0] != tru_network::MAINNET_P2PKH_VERSION) {
            err = "Invalid TRU mainnet address version: got 0x" + bytesToHex({decoded[0]});
            return false;
        }

        // If all checks pass, the address is valid
        err = "";
        return true;
    } catch (const std::runtime_error &e) {
        // Handle specific errors from decodeBase58Check (e.g., checksum mismatch)
        err = e.what();
        return false;
    } catch (const std::exception &e) {
        // Handle any other unexpected errors
        err = "Unexpected error during validation: " + std::string(e.what());
        return false;
    }
}
//============================================================================
// Utility function to generate a private key and address
//============================================================================
std::pair<std::string, std::string> generateKeyPair() {
    // Generate ECDSA key pair
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key || !EC_KEY_generate_key(key)) {
        Logger::log("[generateKeyPair] ERROR: Failed to generate ECDSA key");
        if (key) EC_KEY_free(key);
        throw std::runtime_error("Key generation failed");
    }

    // Get private key (hex string)
    const BIGNUM* privKeyBN = EC_KEY_get0_private_key(key);
    char* privKeyHex = BN_bn2hex(privKeyBN);
    std::string privateKey = privKeyHex;
    OPENSSL_free(privKeyHex);

    // Get public key (compressed format)
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    unsigned char* pubKeyBuf = nullptr;
    int pubKeyLen = i2o_ECPublicKey(key, &pubKeyBuf);
    std::vector<unsigned char> publicKey(pubKeyBuf, pubKeyBuf + pubKeyLen);
    OPENSSL_free(pubKeyBuf);

    // Derive address: SHA256 -> RIPEMD160 -> Base58Check
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256(&publicKey[0], publicKey.size(), sha256);

    unsigned char ripemd160[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256, SHA256_DIGEST_LENGTH, ripemd160);

    // Add TRU mainnet P2PKH version byte
    std::vector<unsigned char> extended(1 + RIPEMD160_DIGEST_LENGTH);
    extended[0] = tru_network::MAINNET_P2PKH_VERSION;
    std::copy(ripemd160, ripemd160 + RIPEMD160_DIGEST_LENGTH, extended.begin() + 1);

    // Double SHA256 for checksum
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(extended.data(), extended.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // Append first 4 bytes of checksum
    extended.insert(extended.end(), hash2, hash2 + 4);

    // Base58 encode
    std::string address = base58Encode(extended); // Assume you have a base58Encode function
    EC_KEY_free(key);

    Logger::log("[generateKeyPair] Generated key pair for address: " + address);
    return {privateKey, address};
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::string readLineWithTimeout(int timeoutSeconds) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string input;
    char c;
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() < timeoutSeconds) {
        if (read(STDIN_FILENO, &c, 1) > 0) {
            if (c == '\n') break;
            input += c;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    if (input.empty()) throw std::runtime_error("Input timed out or empty");
    return input;
}


std::string getValidatedInput(
    const std::string& prompt,
    const std::function<bool(const std::string&)>& validator,
    const std::string& errorMessage,
    std::string& outputBuffer,
    int& currentRow,
    int ROWS,
    std::mutex& coutMutex
) {
    while (true) {
        displayOutputProgressive(outputBuffer, prompt, currentRow, ROWS, coutMutex, 33, true); // Yellow
        std::string input = readLineWithTimeout(30);
        input = trim(input);
        if (input == "back") {
            throw std::runtime_error("User cancelled");
        }
        if (validator(input)) {
            displayOutputProgressive(outputBuffer, prompt.substr(0, prompt.find(':')) + ": " + input, currentRow, ROWS, coutMutex, 32, true); // Green
            return input;
        } else {
            displayOutputProgressive(outputBuffer, errorMessage, currentRow, ROWS, coutMutex, 31, true); // Red
        }
    }
}
//=====================================================================
// Shared CLI helper.
//=====================================================================
void displayOutputProgressive(std::string& outputBuffer, const std::string& message, int& currentRow, int rows, std::mutex& coutMutex, int color, bool addSpacing) {
    std::lock_guard<std::mutex> lock(coutMutex);
    outputBuffer += colorText(message + "\n", color);
    if (addSpacing) {
        outputBuffer += "\n"; // Add extra newline for spacing
    }
    fmt::print("\033[s");           // Save cursor position
    fmt::print("\033[12;1H");       // Move to row 12
    fmt::print("\033[J");           // Clear below row 12
    fmt::print("{}", outputBuffer); // Print accumulated output
    fmt::print("\033[{};1H", currentRow++); // Move to next row
    fmt::print("\033[u");           // Restore cursor position
}
//===============================================================
//		LOAD WALLET SEED (Fixed Version)
//===============================================================

// File paths
const std::string SEED_FILE = "wallet_seed.dat";
const std::string INDEX_FILE = "wallet_index.dat";

std::vector<uint8_t> loadWalletSeed() {
    const size_t seedSize = 64; // Fixed seed size (matches HDWallet::SEED_SIZE if applicable)
    std::vector<uint8_t> seed;

    // Check if seed file exists
    if (std::filesystem::exists(SEED_FILE)) {
        std::ifstream file(SEED_FILE, std::ios::binary | std::ios::ate);
        if (!file) {
            Logger::log("[loadWalletSeed] Failed to open seed file: " + SEED_FILE);
            throw std::runtime_error("Failed to open seed file");
        }

        // Get file size
        size_t fileSize = file.tellg();
        Logger::log("[loadWalletSeed] Seed file size: " + std::to_string(fileSize) + " bytes");

        // Validate file size
        if (fileSize != seedSize) {
            Logger::log("[loadWalletSeed] REFUSING malformed existing seed file: " + SEED_FILE);
            Logger::log("[loadWalletSeed] Existing seed size is " + std::to_string(fileSize) +
                        " bytes; expected exactly " + std::to_string(seedSize) + " bytes.");
            Logger::log("[loadWalletSeed] Existing wallet seed will NOT be regenerated or overwritten.");
            throw std::runtime_error(
                "[loadWalletSeed] Existing wallet seed has invalid size; refusing regeneration");
        } else {
            // Read valid seed
            file.seekg(0, std::ios::beg);
            seed.resize(seedSize);
            file.read(reinterpret_cast<char*>(seed.data()), seedSize);
            if (file.gcount() != static_cast<std::streamsize>(seedSize)) {
                Logger::log("[loadWalletSeed] Failed to read full seed: read " +
                            std::to_string(file.gcount()) + " bytes, expected " + std::to_string(seedSize));
                throw std::runtime_error("Failed to read seed file correctly");
            }
            Logger::log("[loadWalletSeed] Loaded seed of size: " + std::to_string(seed.size()));
        }
    } else {
        // guard against SILENTLY minting a new wallet over an
        // existing funded chain. If chain data already exists, a missing seed
        // almost always means the real seed was lost/moved — generating a new
        // one here would orphan all prior coinbase rewards (balance reads 0).
        {
            bool chainExists = false;
            try {
                for (const char* p : { "data/utxo", "data", "./data/utxo", "./data" }) {
                    if (std::filesystem::exists(p) &&
                        std::filesystem::is_directory(p) &&
                        !std::filesystem::is_empty(p)) {
                        chainExists = true;
                        break;
                    }
                }
            } catch (...) { /* fs errors -> treat as no chain, fall through */ }

            const char* allow = std::getenv("TRU_ALLOW_NEW_SEED");
            if (chainExists && !(allow && std::string(allow) == "1")) {
                Logger::log("==================================================================");
                Logger::log("[loadWalletSeed] REFUSING to generate a new wallet seed.");
                Logger::log("[loadWalletSeed] A blockchain data directory already exists, but");
                Logger::log("[loadWalletSeed] wallet_seed.dat is MISSING from this directory:");
                Logger::log("[loadWalletSeed]   " + std::filesystem::current_path().string());
                Logger::log("[loadWalletSeed] Generating a new seed here would orphan any coins");
                Logger::log("[loadWalletSeed] mined to your old addresses (balance would show 0).");
                Logger::log("[loadWalletSeed] ");
                Logger::log("[loadWalletSeed] Fix: restore your wallet_seed.dat into this directory,");
                Logger::log("[loadWalletSeed] or run the node from the directory that has it.");
                Logger::log("[loadWalletSeed] To intentionally start a NEW wallet on this chain,");
                Logger::log("[loadWalletSeed] set TRU_ALLOW_NEW_SEED=1 and restart.");
                Logger::log("==================================================================");
                throw std::runtime_error(
                    "[loadWalletSeed] Refusing to auto-generate a new seed over an existing "
                    "chain (wallet_seed.dat missing). Restore the seed or set "
                    "TRU_ALLOW_NEW_SEED=1.");
            }
        }

        // No seed file exists; generate a new one
        Logger::log("[loadWalletSeed] No seed file found. Generating new seed.");
        seed.resize(seedSize);
        if (!RAND_bytes(seed.data(), seedSize)) {
            Logger::log("[loadWalletSeed] Failed to generate random bytes for seed");
            throw std::runtime_error("Failed to generate seed");
        }

        // Write new seed to file
        std::ofstream file(SEED_FILE, std::ios::binary | std::ios::trunc);
        if (!file) {
            Logger::log("[loadWalletSeed] Failed to create seed file: " + SEED_FILE);
            throw std::runtime_error("Failed to create seed file");
        }
        file.write(reinterpret_cast<const char*>(seed.data()), seedSize);
        if (!file) {
            Logger::log("[loadWalletSeed] Failed to write new seed to file");
            throw std::runtime_error("Failed to write seed file");
        }
        Logger::log("[loadWalletSeed] Generated and saved new seed of size: " + std::to_string(seed.size()));
    }

    // Final validation
    if (seed.size() != seedSize) {
        Logger::log("[loadWalletSeed] Unexpected seed size after processing: " + std::to_string(seed.size()));
        throw std::runtime_error("Seed size mismatch");
    }

    return seed;
}

//===============================================================
//		GENERATE NEXT INDEX (Unchanged but included for completeness)
//===============================================================
uint32_t getNextIndex() {
    uint32_t index = 0;
    if (std::filesystem::exists(INDEX_FILE)) {
        std::ifstream file(INDEX_FILE, std::ios::binary);
        if (!file) {
            Logger::log("[getNextIndex] Failed to open index file: " + INDEX_FILE);
            throw std::runtime_error("Failed to open index file");
        }
        file.read(reinterpret_cast<char*>(&index), sizeof(index));
        if (file.gcount() != sizeof(index)) {
            Logger::log("[getNextIndex] Failed to read index correctly");
            throw std::runtime_error("Failed to read index file");
        }
    }
    uint32_t nextIndex = index++;
    std::ofstream file(INDEX_FILE, std::ios::binary | std::ios::trunc);
    if (!file) {
        Logger::log("[getNextIndex] Failed to write index file: " + INDEX_FILE);
        throw std::runtime_error("Failed to write index file");
    }
    file.write(reinterpret_cast<const char*>(&index), sizeof(index));
    if (!file) {
        Logger::log("[getNextIndex] Failed to write index to file");
        throw std::runtime_error("Failed to write index file");
    }
    Logger::log("[getNextIndex] Returning index: " + std::to_string(nextIndex));
    return nextIndex;
}

// ... (Other existing functions in utils.cpp remain unchanged) ...
//===============================================================
//		IS VALID ADDRESS
//===============================================================
bool isValidAddressFormat(const std::string& address) {
    std::string err;
    return validateBase58Address(address, err);
}

bool isValidHex(const std::string& s) {
    for (char c : s) {
        if (!isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// ------------------------------------------------------------
// Existing color/terminal code
// ------------------------------------------------------------
void print_error(const std::string &message) {
    std::cerr << RED << "[Error] " << message << RESET << std::endl;
}
void print_success(const std::string &message) {
    std::cout << GREEN << "[Success] " << message << RESET << std::endl;
}
void print_info(const std::string &message) {
    std::cout << CYAN << "[Info] " << message << RESET << std::endl;
}
std::pair<int, int> getTerminalSize() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
        // Default size if unable to get terminal size
        return {80, 24};
    }
    return {w.ws_col, w.ws_row};
}

// ------------------------------------------------------------
// NEW: Mining / Hash utility definitions
// ------------------------------------------------------------

bool hexToBytes32LE(const std::string &hexStr, unsigned char out32[32]) {
    if (hexStr.size() != 64) {
        return false;
    }
    unsigned char temp[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byteVal;
        // parse two hex chars
        if (sscanf(hexStr.substr(i * 2, 2).c_str(), "%02x", &byteVal) != 1) {
            return false;
        }
        temp[i] = (unsigned char)(byteVal);
    }
    // reverse -> out32
    for (int i = 0; i < 32; i++) {
        out32[i] = temp[31 - i];
    }
    return true;
}

bool compare256LE(const unsigned char hashVal[32], const unsigned char targetVal[32]) {
    // Compare from highest index down to 0
    for (int i = 31; i >= 0; i--) {
        if (hashVal[i] < targetVal[i]) return true;
        if (hashVal[i] > targetVal[i]) return false;
    }
    return true; // if all bytes match or are less
}

/* OLD FUNCTION
void bitsToTargetArrayFree(uint32_t bits, unsigned char out[32]) {
    std::memset(out, 0, 32);
    unsigned int exponent = bits >> 24;
    unsigned int mantissa = bits & 0x007fffff;

    if (exponent < 3) {
        // Invalid for Bitcoin, set to max target
        std::memset(out, 0xff, 32);
        return;
    }

    int start = exponent - 3;
    if (start > 29) {
        // Exponent too large, set to max target
        std::memset(out, 0xff, 32);
    } else {
        out[start] = (unsigned char)((mantissa >> 16) & 0xff);     // Most significant byte
        if (start + 1 < 32) out[start + 1] = (unsigned char)((mantissa >> 8) & 0xff);
        if (start + 2 < 32) out[start + 2] = (unsigned char)(mantissa & 0xff); // Least significant byte
    }
}
*/

// NEW FUNCTION
void bitsToTargetArrayFree(uint32_t bits, unsigned char out[32]) {
    std::memset(out, 0, 32);

    unsigned int exponent = bits >> 24;
    unsigned int mantissa = bits & 0x007fffff;

    if (exponent < 3) {
        std::memset(out, 0xff, 32);
        return;
    }

    int start = exponent - 3;

    if (start > 29) {
        std::memset(out, 0xff, 32);
        return;
    }

    // Little-endian target
    out[start] = (unsigned char)(mantissa & 0xff);

    if (start + 1 < 32)
        out[start + 1] =
            (unsigned char)((mantissa >> 8) & 0xff);

    if (start + 2 < 32)
        out[start + 2] =
            (unsigned char)((mantissa >> 16) & 0xff);
}

std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string hexToString(const std::string &hex) {
    std::string output;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        char chr = (char)(int)strtol(hex.substr(i, 2).c_str(), nullptr, 16);
        output.push_back(chr);
    }
    return output;
}

bool isHex(const std::string &str) {
    return !str.empty() && 
           str.size() % 2 == 0 &&
           std::all_of(str.begin(), str.end(), ::isxdigit);
}

std::vector<unsigned char> hash160(const std::vector<unsigned char>& input) {
    unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
    SHA256(input.data(), input.size(), sha256Hash);

    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256Hash, SHA256_DIGEST_LENGTH, ripemd160Hash);

    return std::vector<unsigned char>(ripemd160Hash, ripemd160Hash + RIPEMD160_DIGEST_LENGTH);
}

std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        hex.push_back(hex_chars[byte >> 4]);
        hex.push_back(hex_chars[byte & 0x0F]);
    }
    return hex;
}

// ------------------------------------------------------------
// 	LOAD FILE FOR CONFIG SMART CONTRACT OP CODE
// ------------------------------------------------------------
std::vector<std::string> loadFromConfig(const std::string& configKey) {
    std::vector<std::string> patterns;
    try {
        std::ifstream configFile("src/allowed_scripts.json");
        if (!configFile.is_open()) {
            Logger::log("[loadFromConfig] Cannot open config file: allowed_scripts.json");
            // Use default patterns if file is missing
            patterns = {"f9f7", "f8", "fa", "fb"};
            Logger::log("[loadFromConfig] Using default patterns.");
            return patterns;
        }
        nlohmann::json configJson;
        configFile >> configJson;
        if (configJson.contains(configKey)) {
            for (const auto& pattern : configJson[configKey]) {
                patterns.push_back(pattern.get<std::string>());
            }
        } else {
            Logger::log("[loadFromConfig] Config key '" + configKey + "' not found.");
        }
    } catch (const std::exception& e) {
        Logger::log("[loadFromConfig] Error loading config: " + std::string(e.what()));
        // Fall back to defaults on error
        patterns = {"f9f7", "f8", "fa", "fb"};
    }
    return patterns;
}

// ------------------------------------------------------------
//      		VAR IN ENCODE
// ------------------------------------------------------------
std::string varIntEncode(size_t value) {
    std::vector<unsigned char> result;
    if (value < 0xfd) {
        result.push_back(static_cast<unsigned char>(value));
    } else if (value <= 0xffff) {
        result.push_back(0xfd);
        result.push_back(static_cast<unsigned char>(value & 0xff));
        result.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    } else if (value <= 0xffffffff) {
        result.push_back(0xfe);
        result.push_back(static_cast<unsigned char>(value & 0xff));
        result.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
        result.push_back(static_cast<unsigned char>((value >> 16) & 0xff));
        result.push_back(static_cast<unsigned char>((value >> 24) & 0xff));
    } else {
        result.push_back(0xff);
        for (int i = 0; i < 8; ++i) {
            result.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
        }
    }
    return bytesToHex(result);
}
