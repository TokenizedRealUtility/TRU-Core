#include "tru_network_params.h"
#include "tru_amount.h"
#include <fmt/core.h>
#include <fmt/format.h>
#include <cxxopts.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <unordered_map>
#include <fstream>
#include <chrono>
#include <termios.h>
#include <unistd.h>
#include <wally_core.h>
#include <wally_address.h>
#include <curl/curl.h>
#include <qrencode.h>
#include <limits>
#include "wallet.h"
#include "utils.h"
#include "address_helpers.h"
#include "tokens.h"
#include <sys/ioctl.h>
#include "rpc_server.h"
#include <algorithm>
#include <filesystem>
#include "rpc_utils.h"
#include <openssl/sha.h>
#include <cctype>

void displaySuccessMessageTX(const std::string& txid, const std::string& sender, const std::string& recipient, uint64_t amountAtoms, const std::string& nodeIP, int nodePort, std::mutex& coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("        🚀  TRANSACTION SENT SUCCESS - SECURED ON TRU BLOCKCHAIN  🚀       \n", 32, true));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("🔗 Transaction Details:\n", 32, true));
    fmt::print(colorText("  - Transaction ID: \033[1m" + txid + "\033[0m\n", 32));
    fmt::print(colorText("  - Sender Address: " + sender + "\n", 32));
    fmt::print(colorText("  - Recipient Address: " + recipient + "\n", 32));
    fmt::print(colorText("  - Amount: " + tru_amount::format(amountAtoms) + "\n", 32));
    fmt::print(colorText("🌐 Network Details:\n", 32, true));
    fmt::print(colorText("  - Node IP: " + nodeIP + "\n", 32));
    fmt::print(colorText("  - Node Port: " + std::to_string(nodePort) + "\n", 32));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("💰 Funds Transferred on the TRU Blockchain! 💰\n", 32));
    fmt::print(colorText("\nPress Enter to return to the menu...\n", 33));
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}


// Logger
std::ofstream logFile("wallet_cli.log", std::ios::app);

void log(const std::string& message) {
    if (!logFile.is_open()) {
        std::cerr << "Logger failed to open file!" << std::endl;
        return;
    }
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    logFile << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S") << " - " << message << std::endl;
    logFile.flush();
}

// CURL Write Callback
size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    FILE* fp = static_cast<FILE*>(userp);
    return fwrite(contents, size, nmemb, fp);
}

// Download Image from URL
std::string downloadImage(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to initialize CURL");

    std::string tempFile = "/tmp/ipfs_image_" + std::to_string(std::time(nullptr));
    FILE* fp = fopen(tempFile.c_str(), "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to open temporary file");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        remove(tempFile.c_str());
        throw std::runtime_error("Failed to download image: " + std::string(curl_easy_strerror(res)));
    }
    return tempFile;
}

// Upload to IPFS
std::string uploadToIPFS(const std::string& filePath, const std::string& ipfsServer = "localhost", int ipfsPort = 5001) {
    std::string command = (ipfsServer == "localhost" && ipfsPort == 5001) ?
        "ipfs add -Q \"" + filePath + "\"" :
        "ipfs --api /ip4/" + ipfsServer + "/tcp/" + std::to_string(ipfsPort) + " add -Q \"" + filePath + "\"";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) throw std::runtime_error("Failed to run IPFS command");

    char buffer[128];
    std::string ipfsHash;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) ipfsHash += buffer;
    int status = pclose(pipe);

    if (status != 0) throw std::runtime_error("IPFS upload failed with exit code: " + std::to_string(status));
    if (!ipfsHash.empty() && ipfsHash.back() == '\n') ipfsHash.pop_back();
    if (ipfsHash.empty()) throw std::runtime_error("IPFS returned an empty hash");
    return ipfsHash;
}

// Get Current Pubkeyhash
std::string getCurrentPubkeyhash(const Wallet& wallet) {
    std::string currentAddr = wallet.getCurrentAddress();
    if (currentAddr.empty()) throw std::runtime_error("No current address set in wallet.");
    std::vector<unsigned char> decoded = base58Decode(currentAddr);
    if (decoded.size() != 25) throw std::runtime_error("Invalid address format.");
    std::vector<unsigned char> pubkeyhash(decoded.begin() + 1, decoded.begin() + 21);
    return bytesToHex(pubkeyhash);
}

// SEND TRU
std::string sendTRU(Wallet&            wallet,
                    const std::string& nodeIP,
                    int                nodePort,
                    std::mutex&        coutMutex)
{
    // 1) Prompt under lock
    std::string recipient;
    uint64_t    amountAtoms = 0;
    {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("Enter recipient address: ");
        std::getline(std::cin, recipient);
        fmt::print("Enter amount (TRU): ");
        std::string s;
        std::getline(std::cin, s);
        std::string amountReason;
        if (!tru_amount::parse(s, amountAtoms, amountReason) || amountAtoms == 0) {
            if (amountReason.empty()) amountReason = "amount must be greater than 0";
            log("[sendTRU] Invalid amount: " + amountReason);
            return "Invalid amount: " + amountReason;
        }
    }

    log("[sendTRU] Sending " + tru_amount::format(amountAtoms) +
        " (" + tru_amount::formatAtoms(amountAtoms) + ") to " + recipient +
        " via " + nodeIP + ":" + std::to_string(nodePort));

    try {
        // 2) Build, sign and broadcast
        std::string result = wallet.send_transaction(recipient, amountAtoms, nodeIP, nodePort);
        log("[sendTRU] send_transaction returned: " + result);

        // 3) Extract TXID
        std::string txid = result;
        auto pos = result.find("TX => ");
        if (pos != std::string::npos) {
            txid = result.substr(pos + 6);
        }

        // 4) Show the full-screen dialog.
        displaySuccessMessageTX(
            txid,
            wallet.getCurrentAddress(),
            recipient,
            amountAtoms,
            nodeIP,
            nodePort,
            coutMutex
        );

        // An empty result indicates that the dialog already displayed the output.
        return "";
    }
    catch (const std::exception& e) {
        log("[sendTRU] Error: " + std::string(e.what()));
        // on error, return a message that the menu handler will show
        return "Failed to send TRU: " + std::string(e.what());
    }
}


// Interactive Input with Echo
std::string readLineWithEcho() {
    std::string input;
    char ch;
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::cout << "> " << std::flush;
    while (true) {
        ch = getchar();
        if (ch == '\n') {
            std::cout << std::endl;
            break;
        } else if (ch == 127) { // Backspace
            if (!input.empty()) {
                input.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        } else if (isprint(ch)) {
            input += ch;
            std::cout << ch << std::flush;
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return trim(input);
}
//===================================================================================================
//				SEND TOKENS
//===================================================================================================
void displaySuccessMessageTokenSend(const std::string& txid, const std::string& tokenID, uint64_t quantity, const std::string& recipient, const std::string& sender, const std::string& tokenType, const std::unordered_map<std::string, std::string>& metadata, std::mutex& coutMutex);

std::string sendTokenViaRPC(Wallet& wallet, const std::string& nodeIP, int nodePort, std::mutex& coutMutex) {
    std::string tokenID, recipient, senderAddress;
    uint64_t amount;
    
    // Step 1: Get user input
    {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print(colorText("Enter Token ID to send (e.g., 'myToken' or 8-char hex): ", 33, true));
        std::getline(std::cin, tokenID);
        if (tokenID.empty()) {
            return colorText("[CLI] Error: Token ID cannot be empty.", 31);
        }

        fmt::print(colorText("Enter quantity to send (positive integer): ", 33, true));
        std::string amountStr;
        std::getline(std::cin, amountStr);
        try {
            amount = std::stoull(amountStr);
            if (amount == 0) throw std::invalid_argument("Quantity must be greater than 0");
        } catch (const std::exception& e) {
            return colorText("[CLI] Error: Invalid quantity - " + std::string(e.what()), 31);
        }

        fmt::print(colorText("Enter recipient address (Base58 P2PKH): ", 33, true));
        std::getline(std::cin, recipient);
        if (recipient.empty()) {
            return colorText("[CLI] Error: Recipient address cannot be empty.", 31);
        }
        std::string err;
        if (!validateBase58Address(recipient, err)) {
            return colorText("[CLI] Error: Invalid recipient address - " + err, 31);
        }
    }

    Logger::log("[sendTokenViaRPC] User input: tokenID=" + tokenID + ", amount=" + std::to_string(amount) + ", recipient=" + recipient);

    try {
        Logger::log("[sendTokenViaRPC] Starting token send process with nodeIP=" + nodeIP + ", nodePort=" + std::to_string(nodePort));
        auto chainInfo = rpcCall("getchaininfo", {}, nodeIP, nodePort);
        Logger::log("[sendTokenViaRPC] Connected to node, chain height=" + std::to_string(chainInfo["result"]["bestHeight"].get<int>()));

        // Step 2: Get token UTXOs for all wallet addresses
        auto allAddresses = wallet.getAllAddresses();
        Logger::log("[sendTokenViaRPC] Fetching token UTXOs for " + std::to_string(allAddresses.size()) + " wallet addresses");
        nlohmann::json selectedTokenUtxo;
        bool foundSuitable = false;
        std::string controllingAddress;

        for (const auto& addr : allAddresses) {
            nlohmann::json params = {{"tokenID", tokenID}, {"address", addr}};
            Logger::log("[sendTokenViaRPC] Calling gettokenutxo with params: " + params.dump());
            auto tokenResponse = rpcCall("gettokenutxo", params, nodeIP, nodePort);
            Logger::log("[sendTokenViaRPC] Fetched token UTXOs for address " + addr + ": count=" + std::to_string(tokenResponse["result"].size()));

            if (!tokenResponse.contains("result") || !tokenResponse["result"].is_array()) {
                continue;
            }

            for (const auto& tokenUtxo : tokenResponse["result"]) {
                uint64_t utxoAmount = tokenUtxo["amount"].get<uint64_t>();
                if (utxoAmount >= amount) {
                    selectedTokenUtxo = tokenUtxo;
                    controllingAddress = addr;
                    foundSuitable = true;
                    break;
                }
            }
            if (foundSuitable) break;
        }

        if (!foundSuitable) {
            Logger::log("[sendTokenViaRPC] No suitable token UTXO found with sufficient balance for amount=" + std::to_string(amount));
            throw std::runtime_error(std::string("No suitable token UTXO found with sufficient balance. ") +
                                     "Required: " + std::to_string(amount) + " units");
        }

        std::string selectedTxid = selectedTokenUtxo["txid"].get<std::string>();
        uint32_t controllingVout = selectedTokenUtxo["controllingVout"].get<uint32_t>();
        uint32_t tokenVout = selectedTokenUtxo["tokenVout"].get<uint32_t>();
        uint64_t utxoAmount = selectedTokenUtxo["amount"].get<uint64_t>();
        std::string tokenType = selectedTokenUtxo["type"].get<std::string>();
        senderAddress = controllingAddress; // Use the controlling address of the token UTXO
        Logger::log("[sendTokenViaRPC] Selected token UTXO: txid=" + selectedTxid + ", controllingVout=" + std::to_string(controllingVout) + ", tokenVout=" + std::to_string(tokenVout) + ", amount=" + std::to_string(utxoAmount) + ", type=" + tokenType + ", senderAddress=" + senderAddress);
        Logger::log("[sendTokenViaRPC] Requested amount=" + std::to_string(amount) + ", available=" + std::to_string(utxoAmount));

        std::string err;
        if (!validateBase58Address(senderAddress, err)) {
            Logger::log("[sendTokenViaRPC] Invalid sender address: " + err);
            throw std::runtime_error("Invalid sender address: " + err);
        }

        // Step 3: Get token metadata
        nlohmann::json params = {{"txid", selectedTxid}};
        Logger::log("[sendTokenViaRPC] Getting metadata for txid: " + selectedTxid);
        auto metadataResponse = rpcCall("gettokenmetadata", params, nodeIP, nodePort);
        Logger::log("[sendTokenViaRPC] Metadata response: " + metadataResponse.dump());
        if (metadataResponse.contains("result") && metadataResponse["result"].contains("meta")) {
            std::string decimals = metadataResponse["result"]["meta"].value("decimals", "0");
            Logger::log("[sendTokenViaRPC] Token decimals=" + decimals);
        }
        if (!metadataResponse.contains("result")) {
            Logger::log("[sendTokenViaRPC] Warning: No metadata found for txid: " + selectedTxid);
        }

        // Step 4: Get all unspent UTXOs and find a fee UTXO
        params = {{"address", senderAddress}};
        auto unspentResponse = rpcCall("listunspent", params, nodeIP, nodePort);
        Logger::log("[sendTokenViaRPC] Unspent UTXOs count=" + std::to_string(unspentResponse["result"].size()) + ", response=" + unspentResponse.dump());
        
        if (!unspentResponse.contains("result") || unspentResponse["result"].empty()) {
            throw std::runtime_error("No UTXOs available for transaction fees");
        }

        nlohmann::json feeUtxo;
        bool foundFeeUtxo = false;
        
        // Verify the controlling UTXO exists
        bool controllingUtxoExists = false;
        for (const auto& utxo : unspentResponse["result"]) {
            if (utxo["txid"].get<std::string>() == selectedTxid && 
                utxo["vout"].get<uint32_t>() == controllingVout) {
                controllingUtxoExists = true;
                Logger::log("[sendTokenViaRPC] Found controlling UTXO in unspent list");
                break;
            }
        }
        
        if (!controllingUtxoExists) {
            Logger::log("[sendTokenViaRPC] Error: Controlling UTXO not found in listunspent");
            throw std::runtime_error("Controlling UTXO not found in unspent list");
        }
        
        for (const auto& utxo : unspentResponse["result"]) {
            std::string utxoTxid = utxo["txid"].get<std::string>();
            uint32_t utxoVout = utxo["vout"].get<uint32_t>();
            
            if (utxoTxid == selectedTxid && utxoVout == controllingVout) {
                continue;
            }
            
            uint64_t feeCandidateAtoms = 0;
            if (utxo.contains("amount_atoms") && utxo["amount_atoms"].is_number_unsigned()) {
                feeCandidateAtoms = utxo["amount_atoms"].get<uint64_t>();
            } else if (utxo.contains("amount")) {
                const std::string amountText = utxo["amount"].is_string()
                    ? utxo["amount"].get<std::string>() : utxo["amount"].dump();
                std::string amountReason;
                if (!tru_amount::parse(amountText, feeCandidateAtoms, amountReason)) continue;
            } else {
                continue;
            }
            if (feeCandidateAtoms >= 10002ULL) {
                feeUtxo = utxo;
                foundFeeUtxo = true;
                break;
            }
        }
        
        if (foundFeeUtxo) {
            uint64_t feeAmountAtoms = 0;
            if (feeUtxo.contains("amount_atoms") && feeUtxo["amount_atoms"].is_number_unsigned()) {
                feeAmountAtoms = feeUtxo["amount_atoms"].get<uint64_t>();
            } else {
                const std::string amountText = feeUtxo["amount"].is_string()
                    ? feeUtxo["amount"].get<std::string>() : feeUtxo["amount"].dump();
                std::string amountReason;
                if (!tru_amount::parse(amountText, feeAmountAtoms, amountReason)) {
                    throw std::runtime_error("Invalid fee UTXO amount: " + amountReason);
                }
            }
            Logger::log("[sendTokenViaRPC] Selected fee UTXO: txid=" + feeUtxo["txid"].get<std::string>() + ", vout=" + std::to_string(feeUtxo["vout"].get<uint32_t>()) + ", amount=" + tru_amount::format(feeAmountAtoms));
        } else {
            Logger::log("[sendTokenViaRPC] No suitable fee UTXO found (need >= 0.00010002 TRU)");
            throw std::runtime_error(std::string("No suitable UTXO found for transaction fees. ") +
                                     "Need at least 0.00010002 TRU for fee + control dust.");
        }

        // Step 5: Build the transaction
        Transaction tx;
        tx.isCoinbase = false;
        tx.set_sender(senderAddress);
        
        tx.vin.emplace_back(selectedTxid, controllingVout);
        tx.vin.emplace_back(feeUtxo["txid"].get<std::string>(), feeUtxo["vout"].get<uint32_t>());

        ExtendedTokenData recipientTokenData;
        // TOKEN-AI-01B2R: canonical transfer namespace is 16 hex / 64 bits.
        // Existing 8-hex development-chain IDs remain valid transfer targets.
        std::string normalizedTokenID;
        const bool suppliedNamespaceID =
            (tokenID.size() == 16U || tokenID.size() == 8U) &&
            std::all_of(tokenID.begin(), tokenID.end(), [](unsigned char c) {
                return std::isxdigit(c) != 0;
            });
        if (suppliedNamespaceID) {
            normalizedTokenID = tokenID;
            std::transform(
                normalizedTokenID.begin(), normalizedTokenID.end(),
                normalizedTokenID.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        } else {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(
                reinterpret_cast<const unsigned char*>(tokenID.data()),
                tokenID.size(), hash);
            normalizedTokenID = bytesToHex(
                std::vector<unsigned char>(
                    hash, hash + SHA256_DIGEST_LENGTH)).substr(0, 16);
        }
        recipientTokenData.tokenID = normalizedTokenID;
        recipientTokenData.amount = amount;
        recipientTokenData.type = stringToTokenType(tokenType);
        
        if (metadataResponse.contains("result") && metadataResponse["result"].contains("meta")) {
            recipientTokenData.meta.data = metadataResponse["result"]["meta"];
        }

        std::string recipientTokenScript = createExtendedTokenScriptPubKeyHex(recipientTokenData, recipient);
        tx.vout.emplace_back(0, recipientTokenScript);
        tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(recipient));

        uint64_t changeAmount = utxoAmount - amount;
        bool isFungible = (tokenType == "FT" || tokenType == "SFT" || tokenType == "NCFT");
        
        if (changeAmount > 0 && isFungible) {
            ExtendedTokenData changeTokenData = recipientTokenData;
            changeTokenData.amount = changeAmount;
            std::string changeTokenScript = createExtendedTokenScriptPubKeyHex(changeTokenData, senderAddress);
            tx.vout.emplace_back(0, changeTokenScript);
            tx.vout.emplace_back(1, createP2PKHScriptHexFromAddress(senderAddress));
        }

        uint64_t feeUtxoAmount = 0;
        if (feeUtxo.contains("amount_atoms") && feeUtxo["amount_atoms"].is_number_unsigned()) {
            feeUtxoAmount = feeUtxo["amount_atoms"].get<uint64_t>();
        } else {
            const std::string amountText = feeUtxo["amount"].is_string()
                ? feeUtxo["amount"].get<std::string>() : feeUtxo["amount"].dump();
            std::string amountReason;
            if (!tru_amount::parse(amountText, feeUtxoAmount, amountReason)) {
                throw std::runtime_error("Invalid fee UTXO amount: " + amountReason);
            }
        }
        const uint64_t fee = 10000ULL;
        uint64_t dustPerOutput = 1;
        uint64_t totalDust = dustPerOutput;
        if (changeAmount > 0 && isFungible) {
            totalDust += dustPerOutput;
        }
        
        if (feeUtxoAmount < fee + totalDust) {
            throw std::runtime_error("Fee UTXO is smaller than fee + required control dust");
        }
        uint64_t feeChange = feeUtxoAmount - fee - totalDust;
        if (feeChange > 0) {
            tx.vout.emplace_back(feeChange, createP2PKHScriptHexFromAddress(senderAddress));
        }

        // Step 6: Sign the transaction
        tx.computeTxId();
        Logger::log("[sendTokenViaRPC] Transaction to sign: txid=" + tx.txid + ", inputs=" + std::to_string(tx.vin.size()) + ", outputs=" + std::to_string(tx.vout.size()));
        
        if (!wallet.signTransaction(tx, nodeIP, nodePort)) {
            Logger::log("[sendTokenViaRPC] Failed to sign transaction");
            throw std::runtime_error("Failed to sign transaction - the controlling UTXO may have been spent");
        } else {
            Logger::log("[sendTokenViaRPC] Transaction signed successfully");
        }

        // Step 7: Broadcast the transaction
        std::string txHex = bytesToHex(tx.serializeBinary());
        Logger::log("[sendTokenViaRPC] Broadcasting transaction hex: " + txHex);
        
        params = {{"txHex", txHex}};
        auto broadcastResponse = rpcCall("sendrawtransaction", params, nodeIP, nodePort);
        Logger::log("[sendTokenViaRPC] Broadcast response: " + broadcastResponse.dump());
        if (broadcastResponse.contains("error")) {
            Logger::log("[sendTokenViaRPC] Broadcast error: " + broadcastResponse["error"]["message"].get<std::string>());
            throw std::runtime_error("Failed to broadcast transaction: " + 
                broadcastResponse["error"]["message"].get<std::string>());
        } else {
            std::string finalTxid = broadcastResponse["result"]["txid"].get<std::string>();
            Logger::log("[sendTokenViaRPC] Transaction broadcasted successfully: txid=" + finalTxid);
        }
        
        std::string finalTxid = broadcastResponse["result"]["txid"].get<std::string>();

        std::unordered_map<std::string, std::string> displayMetadata;
        if (metadataResponse.contains("result") && metadataResponse["result"].contains("meta")) {
            for (const auto& [key, value] : metadataResponse["result"]["meta"].items()) {
                displayMetadata[key] = value.is_string() ? value.get<std::string>() : value.dump();
            }
        }
        
        displaySuccessMessageTokenSend(
            finalTxid, tokenID, amount, recipient, senderAddress, 
            tokenType, displayMetadata, coutMutex
        );
        
        return "";
    } catch (const std::exception& e) {
        Logger::log("[sendTokenViaRPC] Error: " + std::string(e.what()));
        std::lock_guard<std::mutex> lock(coutMutex);
        return colorText("[CLI] Error: " + std::string(e.what()), 31);
    }
}
//===================================================================================================
//                              MATRIX
//===================================================================================================
bool getTerminalSize(int& rows, int& columns) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        return false; // Failed to get terminal size
    }
    rows = ws.ws_row;
    columns = ws.ws_col;
    return true;
}

void printBanner3(std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex); // Lock for thread-safe output
    srand(time(nullptr)); // Seed the random number generator once

    // Get terminal dimensions
    int rows, columns;
    if (!getTerminalSize(rows, columns)) {
        // Fallback to default values if terminal size detection fails
        rows = 45;
        columns = 80;
    }

    // Ensure minimum dimensions to prevent issues
    rows = std::max(rows, 20);
    columns = std::max(columns, 80);

    const int numFrames = 100; // Number of frames for the animation

    // Character set for random streams
    const std::string charSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()";

    // Words to display in the rain
    const std::vector<std::string> words = {
        "TRU", "NFT", "SFT", "NCFT", "FT", "blockchain", "A.i", "Tokenized Real Utility",
        "crypto", "decentralized", "ledger", "smart contract", "hash", "node", "peer", "wallet",
        "transaction", "consensus", "proof of work", "proof of stake", "mining", "block", "blockchain"
    };

    // Lambda to generate random characters for streams
    auto generateRandomCharacters = [&charSet](int length) {
        std::string result;
        for (int i = 0; i < length; i++) {
            result += charSet[rand() % charSet.size()];
        }
        return result;
    };

    // Structure to represent a stream in the Matrix rain
    struct Stream {
        int position;           // Current row of the head (bottom-most character)
        int length;             // Length of the stream or word
        int speed;              // Speed of falling (rows per frame)
        std::string characters; // Characters or word in the stream
        bool isWordStream;      // Flag to distinguish word streams
    };

    // Initialize streams for each column
    std::vector<Stream> streams(columns);
    for (int col = 0; col < columns; ++col) {
        Stream& stream = streams[col];
        if (rand() % 5 == 0) { // 20% chance to be a word stream
            int wordIndex = rand() % words.size();
            stream.characters = words[wordIndex];
            stream.length = stream.characters.length();
            stream.speed = 2; // Faster for words
            stream.isWordStream = true;
        } else {
            stream.length = rand() % 10 + 5; // Random length between 5 and 15
            stream.characters = generateRandomCharacters(stream.length);
            stream.speed = 1; // Slower for random characters
            stream.isWordStream = false;
        }
        // Random starting position to simulate continuous rain
        stream.position = rand() % (rows + stream.length);
    }

    // Animation loop
    for (int frame = 0; frame < numFrames; ++frame) {
        // Clear screen and move cursor to top-left
        fmt::print("\033[2J\033[1;1H");

        // Update and render each stream
        for (int col = 0; col < columns; ++col) {
            Stream& stream = streams[col];
            if (stream.isWordStream) {
                // Print word vertically, first character at the bottom
                for (size_t i = 0; i < stream.characters.length(); ++i) {
                    int row = stream.position - i;
                    if (row >= 0 && row < rows) {
                        char c = stream.characters[stream.characters.length() - 1 - i];
                        fmt::print("\033[{};{}H\033[32m{}\033[0m", row + 1, col + 1, c); // Green color
                    }
                }
            } else {
                // Print random character stream, head at bottom
                for (int i = 0; i < stream.length; ++i) {
                    int row = stream.position - i;
                    if (row >= 0 && row < rows) {
                        char c = stream.characters[i];
                        int color = (i == 0) ? 92 : 32; // Head light green, tail green
                        fmt::print("\033[{};{}H\033[{}m{}\033[0m", row + 1, col + 1, color, c);
                    }
                }
            }

            // Move stream downward
            stream.position += stream.speed;

            // Reset stream when it falls off the screen
            if (stream.position >= rows + stream.length - 1) {
                if (rand() % 5 == 0) { // 20% chance to become a word stream
                    int wordIndex = rand() % words.size();
                    stream.characters = words[wordIndex];
                    stream.length = stream.characters.length();
                    stream.speed = 2;
                    stream.isWordStream = true;
                } else {
                    stream.length = rand() % 10 + 5;
                    stream.characters = generateRandomCharacters(stream.length);
                    stream.speed = 1;
                    stream.isWordStream = false;
                }
                stream.position = 0; // Restart at top
            }
        }

        // Pause for 20 milliseconds per frame
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }

    // Clear screen and display the final banner
    fmt::print("\033[2J\033[1;1H");
    fmt::print("\033[36m" // Cyan color for the banner
               "    ████████╗██████╗ ██╗   ██╗    ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗\n"
               "    ╚══██╔══╝██╔══██╗██║   ██║    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║\n"
               "       ██║   ██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║██║     █████╔╝ ██║     ███████║███████║██║██╔██╗ ██║\n"
               "       ██║   ██╔══██╗██║   ██║    ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██║██║██║╚██╗██║\n"
               "       ██║   ██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗╚██████╗██║  ██║██║  ██║██║██║ ╚████║\n"
               "       ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝\n"
               "\033[0m");
    fmt::print("\033[90m" // Gray color for the subtitle
               "      T O K E N I Z E D  R E A L  U T I L I T Y   A N E X T - G E N   S T A N D A L O N E   W A L L E T   \n\n"
               "\033[0m");
}

// Display Functions
void printBanner(std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print(colorText(R"(
    ████████╗██████╗ ██╗   ██╗    ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
    ╚══██╔══╝██╔══██╗██║   ██║    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║████╗  ██║
       ██║   ██████╔╝██║   ██║    ██████╔╝██║     ██║   ██║██║     █████╔╝ ██║     ███████║███████║██║██╔██╗ ██║
       ██║   ██╔══██╗██║   ██║    ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██║     ██╔══██║██╔══██║██║██║╚██╗██║
       ██║   ██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗╚██████╗██║  ██║██║  ██║██║██║ ╚████║
       ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
)", 36, true));
    fmt::print(colorText("      T O K E N I Z E D  R E A L  U T I L I T Y   S T A N D A L O N E   W A L L E T    \n\n", 90, false));
}

void runSpinner(std::atomic<bool>& running, std::mutex& coutMutex) {
    const std::vector<std::string> spinnerChars = {"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"};
    size_t idx = 0;
    while (running) {
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[66;1H\033[K");
        auto spinSymbol = colorText(spinnerChars[idx % spinnerChars.size()], 32, true);
        fmt::print("{} {}\n\n", spinSymbol, colorText("Wallet Running Smoothly...", 97));
        idx++;
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
}

void displayMenu(int rows, std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    int menuTop = rows - 3;
    std::stringstream ss;
    ss << "\033[" << menuTop << ";1H" << "\033[K";
    ss << colorText("╔═══════════════  M E N U  O P T I O N S  ══════════════╗\n", 94, true);
    ss << colorText("║ 1. Create New Wallet                                  ║\n", 96);
    ss << colorText("║ 2. Load Wallet                                        ║\n", 96);
    ss << colorText("║ 3. Save Wallet                                        ║\n", 96);
    ss << colorText("║ 4. Generate New Address                               ║\n", 96);
    ss << colorText("║    4a => Display Private Key                          ║\n", 96);
    ss << colorText("║      4b => View QR Code for Current Address           ║\n", 96);
    ss << colorText("║ 5. Send Funds                                         ║\n", 96);
    ss << colorText("║ 6. Check Balance                                      ║\n", 96);
    ss << colorText("║ 8. View Chain Info                                    ║\n", 96);
    ss << colorText("║ 9. List Peers                                         ║\n", 96);
    ss << colorText("║10. Lookup Block by Hash                               ║\n", 96);
    ss << colorText("║11. Exit                                               ║\n", 96);
    ss << colorText("║12. List My Tokens (Simple View)                       ║\n", 96);
    ss << colorText("║    12a => List My Tokens (Detailed View)              ║\n", 96);
    ss << colorText("║13. Issue New Token (All Types)                        ║\n", 96);
    ss << colorText("║14. Show My Wallet Addresses                           ║\n", 96);
    ss << colorText("║15. Send Token (NFT/FT/SFT/NCFT)                       ║\n", 96);
    ss << colorText("║16. Connect to Peer                                    ║\n", 96);
    ss << colorText("║17. Send Message to Peer                               ║\n", 96);
    ss << colorText("║18. Create Smart Contract                              ║\n", 96);
    ss << colorText("║    18a => Get Current Pubkeyhash                      ║\n", 96);
    ss << colorText("║ C) Clear Output                                       ║\n", 96);
    ss << colorText("╚═══════════════════════════════════════════════════════╝\n", 94, true);
    ss << colorText("Select an option (1-18 or C): ", 93);
    fmt::print("{}", ss.str());
}

static void displayOutput(const std::string &message, int rows, std::mutex &coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[s");
    fmt::print("\033[12;1H");
    fmt::print("\033[J");
    fmt::print("{}\n", colorText(message, 96));
    fmt::print("\033[u");
}

void printChainInfoRPC(const std::string& nodeIP, int nodePort, std::mutex& coutMutex) {
    try {
        auto info = rpcCall("getchaininfo", {}, nodeIP, nodePort)["result"];
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[s");
        fmt::print("\033[12;1H");
        fmt::print("\033[K");
        fmt::print(colorText("[Chain Info]\n", 95, true));
        fmt::print("  {} {}\n", colorText("Chain size:     ", 94), info["chainSize"].get<int>());
        fmt::print("  {} {}\n", colorText("Best tip height:", 94), info["bestHeight"].get<int>());
        fmt::print("  {} {}\n", colorText("Best tip hash:  ", 94), info["bestHash"].get<std::string>());
        fmt::print("  {} 0x{:x}\n", colorText("Difficulty:     ", 94), info["difficulty"].get<uint32_t>());
        fmt::print("  {} {}\n", colorText("Chain valid:    ", 94), info["chainValid"].get<bool>() ? colorText("yes", 32) : colorText("no", 31));
        fmt::print("\033[u");
    } catch (const std::exception& e) {
        log("Error fetching chain info: " + std::string(e.what()));
        displayOutput("[CLI] Failed to fetch chain info: " + std::string(e.what()), 45, coutMutex);
    }
}

// QR Code Display
static void printQRCode(const std::string &data) {
    QRcode *q = QRcode_encodeString(data.c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!q) return;
    int sz = q->width;
    unsigned char *d = q->data;
    const std::string black = "██";
    const std::string white = "  ";

    for (int i = 0; i < sz + 2; i++) std::cout << white;
    std::cout << "\n";

    for (int y = 0; y < sz; y++) {
        std::cout << white;
        for (int x = 0; x < sz; x++) std::cout << (d[y * sz + x] & 1 ? black : white);
        std::cout << white << "\n";
    }

    for (int i = 0; i < sz + 2; i++) std::cout << white;
    std::cout << "\n";

    QRcode_free(q);
}

static void viewAddressQRCode(const std::string &addr) {
    std::cout << "\033[2J\033[H";
    std::cout << colorText("Address: ", 32, true) << colorText(addr, 32) << "\n\n";
    printQRCode(addr);
    std::cout << "\nPress Enter to return to menu...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "\033[2J\033[H";
}
std::string formatTokenTable(const Wallet &wallet, const std::string& nodeIP, int nodePort) {
    try {
        nlohmann::json params = {{"addresses", wallet.getAllAddresses()}};
        auto response = rpcCall("tokenmetadisplay", params, nodeIP, nodePort);
        if (!response.contains("result")) {
            throw std::runtime_error("Invalid RPC response");
        }
        auto tokens = response["result"];
        if (tokens.empty()) return colorText("No tokens owned by this wallet.\n", 31);

        std::unordered_map<std::string, std::vector<nlohmann::json>> tokenGroups;
        for (const auto& token : tokens) {
            std::string tokenID = token["tokenID"].get<std::string>();
            std::string type = token["type"].get<std::string>();
            std::string key = tokenID + ":" + type; // Group by tokenID and type
            tokenGroups[key].push_back(token);
        }

        std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::string>> tableEntries;
        for (const auto& pair : tokenGroups) {
            std::string key = pair.first;
            const auto& group = pair.second;
            std::string tokenID = group[0]["tokenID"].get<std::string>();
            std::string type = group[0]["type"].get<std::string>();
            if (type == "FT" || type == "SFT" || type == "NCFT") {
                uint64_t totalAmount = 0;
                std::vector<std::string> txids;
                for (const auto& token : group) {
                    std::string amountStr = token["amount"].get<std::string>();
                    totalAmount += std::stoull(amountStr);
                    txids.push_back(token["txid"].get<std::string>());
                }
                std::string owner = group[0]["owner"].get<std::string>();
                std::string metadata = group[0].contains("meta") ? group[0]["meta"].dump() : "N/A";
                std::string txidList = txids.empty() ? "None" : std::accumulate(
                    txids.begin(), std::min(txids.end(), txids.begin() + 3), std::string(),
                    [](const std::string& a, const std::string& b) { return a.empty() ? b : a + ", " + b; }
                ) + (txids.size() > 3 ? " + " + std::to_string(txids.size() - 3) + " more" : "");
                tableEntries.emplace_back(tokenID, type, std::to_string(totalAmount), owner, txidList, metadata);
            } else { // NFT or TRUSCRIPT
                for (const auto& token : group) {
                    std::string amountStr = token["amount"].get<std::string>();
                    std::string owner = token["owner"].get<std::string>();
                    std::string txid = token["txid"].get<std::string>();
                    std::string metadata = token.contains("meta") ? token["meta"].dump() : "N/A";
                    tableEntries.emplace_back(tokenID, type, amountStr, owner, txid, metadata);
                }
            }
        }

        std::ostringstream oss;
        const size_t pageSize = 10;
        size_t totalPages = (tableEntries.size() + pageSize - 1) / pageSize;
        size_t currentPage = 0;

        while (currentPage < totalPages) {
            oss.str("");
            oss.clear();
            oss << colorText("════════════════════════════════ MY TOKENS ════════════════════════════════\n", 36, true)
                << colorText(fmt::format("{:<20} | {:<10} | {:>10} | {:<34} | {:<34} | {:<50}\n", "Token ID", "Type", "Amount", "Owner", "Txid", "Metadata"), 33)
                << colorText("────────────────────────────────────────────────────────────────────────────────────────────\n", 36);

            size_t start = currentPage * pageSize;
            size_t end = std::min(start + pageSize, tableEntries.size());
            for (size_t i = start; i < end; ++i) {
                const auto& entry = tableEntries[i];
                std::string tokenID, type, amountStr, owner, txid, metadata;
                std::tie(tokenID, type, amountStr, owner, txid, metadata) = entry;
                int color = (type == "FT" ? 32 : type == "NFT" ? 35 : type == "SFT" ? 33 : type == "NCFT" ? 36 : type == "TRUSCRIPT" ? 34 : 37);
                auto tokTr = tokenID.substr(0, 20);
                auto ownTr = owner.substr(0, 34);
                auto txTr = txid.size() > 34 ? txid.substr(0, 31) + "..." : txid;
                auto mdTr = metadata.size() > 50 ? metadata.substr(0, 47) + "..." : metadata;
                oss << colorText(fmt::format("{:<20} | {:<10} | {:>10} | {:<34} | {:<34} | {:<50}\n", tokTr, type, amountStr, ownTr, txTr, mdTr), color);
            }
            oss << colorText("══════════════════════════════════════════════════════════════════════════════════════════════════\n", 36, true);
            oss << colorText(fmt::format("Page {} of {}. Press 'n' for next page, 'p' for previous, or Enter to exit.\n", currentPage + 1, totalPages), 33);

            std::cout << "\033[2J\033[1;1H" << oss.str();
            std::string input;
            std::getline(std::cin, input);
            if (input.empty()) break;
            if (input == "n" && currentPage + 1 < totalPages) ++currentPage;
            else if (input == "p" && currentPage > 0) --currentPage;
        }

        return oss.str();
    } catch (const std::exception& e) {
        log("Error formatting token table: " + std::string(e.what()));
        return "Failed to format token table: " + std::string(e.what());
    }
}

std::string formatTokenTable2(const Wallet &wallet, const std::string& nodeIP, int nodePort) {
    try {
        nlohmann::json params = {{"addresses", wallet.getAllAddresses()}};
        auto response = rpcCall("tokenmetadisplay", params, nodeIP, nodePort);
        if (!response.contains("result")) {
            throw std::runtime_error("Invalid RPC response");
        }
        auto tokens = response["result"];
        if (tokens.empty()) return colorText("No tokens owned by this wallet.\n", 31);

        std::unordered_map<std::string, std::vector<nlohmann::json>> tokenGroups;
        for (const auto& token : tokens) {
            std::string tokenID = token["tokenID"].get<std::string>();
            std::string type = token["type"].get<std::string>();
            std::string key = tokenID + ":" + type; // Group by tokenID and type
            tokenGroups[key].push_back(token);
        }

        std::vector<std::tuple<std::string, std::string, std::string, std::string, std::string, std::unordered_map<std::string, std::string>>> tableEntries;
        for (const auto& pair : tokenGroups) {
            std::string key = pair.first;
            const auto& group = pair.second;
            std::string tokenID = group[0]["tokenID"].get<std::string>();
            std::string type = group[0]["type"].get<std::string>();
            if (type == "FT" || type == "SFT" || type == "NCFT") {
                uint64_t totalAmount = 0;
                std::vector<std::string> txids;
                std::unordered_map<std::string, std::string> meta = group[0].contains("meta") ?
                    group[0]["meta"].get<std::unordered_map<std::string, std::string>>() : std::unordered_map<std::string, std::string>{};
                std::string owner = group[0]["owner"].get<std::string>();
                for (const auto& token : group) {
                    std::string amountStr = token["amount"].get<std::string>();
                    totalAmount += std::stoull(amountStr);
                    txids.push_back(token["txid"].get<std::string>());
                }
                std::string txidList = txids.empty() ? "None" : std::accumulate(
                    txids.begin(), std::min(txids.end(), txids.begin() + 3), std::string(),
                    [](const std::string& a, const std::string& b) { return a.empty() ? b : a + ", " + b; }
                ) + (txids.size() > 3 ? " + " + std::to_string(txids.size() - 3) + " more" : "");
                tableEntries.emplace_back(tokenID, type, std::to_string(totalAmount), owner, txidList, meta);
            } else { // NFT or TRUSCRIPT
                for (const auto& token : group) {
                    std::string amountStr = token["amount"].get<std::string>();
                    std::string owner = token["owner"].get<std::string>();
                    std::string txid = token["txid"].get<std::string>();
                    std::unordered_map<std::string, std::string> meta = token.contains("meta") ?
                        token["meta"].get<std::unordered_map<std::string, std::string>>() : std::unordered_map<std::string, std::string>{};
                    tableEntries.emplace_back(tokenID, type, amountStr, owner, txid, meta);
                }
            }
        }

        std::ostringstream oss;
        const size_t pageSize = 10;
        size_t totalPages = (tableEntries.size() + pageSize - 1) / pageSize;
        size_t currentPage = 0;

        while (currentPage < totalPages) {
            oss.str("");
            oss.clear();
            oss << colorText("══════════════════════════════════════════════════════ MY TOKENS (Detailed) ══════════════════════════════════════════════════════\n", 36, true);

            size_t start = currentPage * pageSize;
            size_t end = std::min(start + pageSize, tableEntries.size());
            for (size_t i = start; i < end; ++i) {
                const auto& entry = tableEntries[i];
                std::string tokenID, type, amountStr, owner, txid;
                std::unordered_map<std::string, std::string> meta;
                std::tie(tokenID, type, amountStr, owner, txid, meta) = entry;
                int typeColor = (type == "FT" ? 32 : type == "NFT" ? 35 : type == "SFT" ? 33 : type == "NCFT" ? 36 : type == "TRUSCRIPT" ? 34 : 37);
                oss << colorText(fmt::format("Token ID: {:<20} | Type: {:<10} | Amount: {:>10} | Owner: {:<34} | Txid: {:<34}\n", 
                    tokenID.substr(0, 20), type, amountStr, owner.substr(0, 34), txid.substr(0, 34)), typeColor);
                oss << colorText("  Metadata:\n", 36);
                static const std::vector<std::string> metaFields = {
                    "name", "symbol", "decimals", "description", "image", "creator", "external_link",
                    "data", "inscriptionIndex", "satNumber", "timestamp", "sizeBytes",
                    "ai_version", "learning_mode", "growth_algorithm", "ai_engine", "style_descriptor", "dynamic_morph"
                };
                for (const auto& fld : metaFields) {
                    if (meta.count(fld)) oss << colorText(fmt::format("    {:<15}: {}\n", fld, meta.at(fld)), 37);
                }
                for (const auto& [key, value] : meta) {
                    if (std::find(metaFields.begin(), metaFields.end(), key) == metaFields.end()) {
                        oss << colorText(fmt::format("    {:<15}: {}\n", key, value), 37);
                    }
                }
                if (type == "FT" || type == "SFT" || type == "NCFT") {
                    oss << colorText("  Show individual UTXOs? (y/n): ", 33);
                    std::cout << "\033[2J\033[1;1H" << oss.str();
                    std::string showIndividual;
                    std::getline(std::cin, showIndividual);
                    oss.str("");
                    oss.clear();
                    oss << colorText("══════════════════════════════════════════════════════ MY TOKENS (Detailed) ══════════════════════════════════════════════════════\n", 36, true);
                    if (toLower(showIndividual) == "y") {
                        std::string key = tokenID + ":" + type;
                        const auto& group = tokenGroups[key];
                        for (const auto& token : group) {
                            std::string indAmountStr = token["amount"].get<std::string>();
                            std::string indOwner = token["owner"].get<std::string>();
                            std::string indTxid = token["txid"].get<std::string>();
                            std::unordered_map<std::string, std::string> indMeta = token.contains("meta") ?
                                token["meta"].get<std::unordered_map<std::string, std::string>>() : std::unordered_map<std::string, std::string>{};
                            oss << colorText(fmt::format("Token ID: {:<20} | Type: {:<10} | Amount: {:>10} | Owner: {:<34} | Txid: {:<34}\n", 
                                tokenID.substr(0, 20), type, indAmountStr, indOwner.substr(0, 34), indTxid.substr(0, 34)), typeColor);
                            oss << colorText("  Metadata:\n", 36);
                            for (const auto& fld : metaFields) {
                                if (indMeta.count(fld)) oss << colorText(fmt::format("    {:<15}: {}\n", fld, indMeta.at(fld)), 37);
                            }
                            for (const auto& [key, value] : indMeta) {
                                if (std::find(metaFields.begin(), metaFields.end(), key) == metaFields.end()) {
                                    oss << colorText(fmt::format("    {:<15}: {}\n", key, value), 37);
                                }
                            }
                            oss << colorText("──────────────────────────────────────────────────────────────────────────────────────\n", 36);
                        }
                    } else {
                        oss << colorText(fmt::format("Token ID: {:<20} | Type: {:<10} | Amount: {:>10} | Owner: {:<34} | Txid: {:<34}\n", 
                            tokenID.substr(0, 20), type, amountStr, owner.substr(0, 34), txid.substr(0, 34)), typeColor);
                        oss << colorText("  Metadata:\n", 36);
                        for (const auto& fld : metaFields) {
                            if (meta.count(fld)) oss << colorText(fmt::format("    {:<15}: {}\n", fld, meta.at(fld)), 37);
                        }
                        for (const auto& [key, value] : meta) {
                            if (std::find(metaFields.begin(), metaFields.end(), key) == metaFields.end()) {
                                oss << colorText(fmt::format("    {:<15}: {}\n", key, value), 37);
                            }
                        }
                        oss << colorText("──────────────────────────────────────────────────────────────────────────────────────\n", 36);
                    }
                } else {
                    oss << colorText("──────────────────────────────────────────────────────────────────────────────────────\n", 36);
                }
            }

            oss << colorText("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n", 36, true);
            oss << colorText(fmt::format("Page {} of {}. Press 'n' for next page, 'p' for previous, or Enter to exit.\n", currentPage + 1, totalPages), 33);

            std::cout << "\033[2J\033[1;1H" << oss.str();
            std::string input;
            std::getline(std::cin, input);
            if (input.empty()) break;
            if (input == "n" && currentPage + 1 < totalPages) ++currentPage;
            else if (input == "p" && currentPage > 0) --currentPage;
        }

        return oss.str();
    } catch (const std::exception& e) {
        log("Error formatting token table 2: " + std::string(e.what()));
        return "Failed to format token table 2: " + std::string(e.what());
    }
}


void displayFormattedTokenList(const Wallet &wallet, const std::string& nodeIP, int nodePort, std::mutex &coutMutex, bool detailed = false) {
    std::string table = detailed ? formatTokenTable2(wallet, nodeIP, nodePort) : formatTokenTable(wallet, nodeIP, nodePort);
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print("{}", table);
    fmt::print("\nPress Enter to return to menu...");
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    fmt::print("\033[2J\033[1;1H");
}


int getColorForTokenType(const std::string& tokenType) {
    if (tokenType == "FT") return 34;
    if (tokenType == "NFT") return 35;
    if (tokenType == "SFT") return 36;
    if (tokenType == "NCFT") return 33;
    return 32;
}

void displayTokenCreationSuccess(const std::string& tokenType, const std::string& txid, const std::map<std::string, std::string>& tokenDetails, std::mutex& coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("        🚀  TOKEN CREATION SUCCESS - POWERED BY BLOCKCHAIN  🚀        \n", 32, true));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    int typeColor = getColorForTokenType(tokenType);
    fmt::print(colorText("🔗 Token Type: ", 32));
    fmt::print(colorText(tokenType + "\n", typeColor, true));
    fmt::print(colorText("🔗 Transaction ID: \033[1m" + txid + "\033[0m\n", 32));
    fmt::print(colorText("📜 Token Details:\n", 32));
    for (const auto& [key, value] : tokenDetails) {
        fmt::print(colorText("  - " + key + ": " + value + "\n", 32));
    }
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("💰 Token Minted on the Blockchain! Ready to Decentralize the Future! 💰\n", 32));
    fmt::print(colorText("\nPress Enter to return to the menu...\n", 33));
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void displaySuccessMessageTokenSend(const std::string& txid, const std::string& tokenID, uint64_t quantity, const std::string& recipient, const std::string& sender, const std::string& tokenType, const std::unordered_map<std::string, std::string>& metadata, std::mutex& coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("        🚀  TOKEN TRANSFER SUCCESS - POWERED BY TRU BLOCKCHAIN  🚀        \n", 32, true));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("🔗 Transaction ID: \033[1m" + txid + "\033[0m\n", 32));
    fmt::print(colorText("🔗 Token ID: \033[1m" + tokenID + "\033[0m\n", 32));
    fmt::print(colorText("🔗 Quantity: " + std::to_string(quantity) + "\n", 32));
    fmt::print(colorText("🔗 From (Sender): " + sender + "\n", 32));
    fmt::print(colorText("🔗 To (Recipient): " + recipient + "\n", 32));
    int typeColor = getColorForTokenType(tokenType);
    fmt::print(colorText("🔗 Token Type: ", 32));
    fmt::print(colorText(tokenType + "\n", typeColor, true));
    fmt::print(colorText("📜 Metadata:\n", 32));
    if (metadata.empty()) {
        fmt::print(colorText("  - No metadata available.\n", 33));
    } else {
        for (const auto& [key, value] : metadata) {
            fmt::print(colorText("  - " + key + ": " + value + "\n", 32));
        }
    }
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("💰 Transaction Secured on the Blockchain! 💰\n", 32));
    fmt::print(colorText("\nPress Enter to return to the menu...\n", 33));
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int getColorForContractType(const std::string& contractType) {
    if (contractType == "TIME LOCK") return 34;
    if (contractType == "OP_RETURN") return 33;
    if (contractType == "HASH LOCK") return 35;
    if (contractType == "CUSTOM SCRIPT") return 32;
    return 37;
}

void displaySuccessMessageContract(const std::string& contractType, const std::string& txid, const std::string& contractAddress, const std::string& scriptHex, const std::string& broadcastStatus, const std::string& senderAddress, const std::string& contractName, const std::string& lockReason, std::mutex& coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H");
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("        🚀  SMART CONTRACT DEPLOYED SUCCESSFULLY - TRU BLOCKCHAIN  🚀  \n", 32, true));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("📜 Contract Details:\n", 32, true));
    int typeColor = getColorForContractType(contractType);
    fmt::print(colorText("  - Contract Type: ", 32));
    fmt::print(colorText(contractType + "\n", typeColor, true));
    fmt::print(colorText("  - Contract Name: " + (contractName.empty() ? "N/A" : contractName) + "\n", 32));
    if (!lockReason.empty()) fmt::print(colorText("  - Lock Reason: " + lockReason + "\n", 32));
    fmt::print(colorText("🔗 Transaction Details:\n", 32, true));
    fmt::print(colorText("  - Transaction ID: \033[1m" + txid + "\033[0m\n", 32));
    fmt::print(colorText("  - Contract Address: " + contractAddress + "\n", 32));
    fmt::print(colorText("  - Sender Address: " + senderAddress + "\n", 32));
    fmt::print(colorText("  - Script Hex: " + scriptHex + "\n", 32));
    fmt::print(colorText("🌐 Broadcast Status:\n", 32, true));
    fmt::print(colorText("  - Status: " + broadcastStatus + "\n", 32));
    fmt::print(colorText("⛓️════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("💰 Contract Deployed on the TRU Blockchain! 💰\n", 32));
    fmt::print(colorText("\nPress Enter to return to the menu...\n", 33));
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

//============================================================================================
//                              Display TRUScripts (via displayOutput)
//============================================================================================
void displayTRUScriptsCLI(const std::vector<TRUScriptInfo>& scripts,
                          int rows,
                          std::mutex& coutMutex)
{
    // ANSI escapes
    constexpr const char* RST   = "\033[0m";
    constexpr const char* RED   = "\033[31m";
    constexpr const char* YEL   = "\033[33m";
    constexpr const char* GRN   = "\033[32m";
    constexpr const char* CYAN  = "\033[36m";
    constexpr const char* MAG   = "\033[35m";

    std::ostringstream oss;

    // header
    oss << MAG << "🐸  TRUScripts Collection 🐸" << RST << "\n\n";
    oss << YEL
        << std::left << std::setw(4)  << "No."
        << std::setw(66) << "TXID"
        << "Data\n"
        << std::string(100, '-') << "\n"
        << RST;

    // rows
    for (size_t i = 0; i < scripts.size(); ++i) {
        const auto& s = scripts[i];
        const char* rowCol = (i % 2 == 0) ? CYAN : GRN;

        oss << rowCol
            << std::right << std::setw(4) << (i+1) << " "
            << RED << "⛓️📜" << RST << " "
            << std::left << std::setw(66) << s.txid
            << s.data
            << RST
            << "\n";
    }

    // footer
    oss << "\n" << YEL
        << "Total: " << scripts.size()
        << RST
        << "\n";

    // Finally hand the whole thing to displayOutput
    displayOutput(oss.str(), rows, coutMutex);
}

// CLI Loop
void startCLI(Wallet &wallet, const std::string& nodeIP, int nodePort, std::atomic<bool> &spinnerRunning, std::mutex &coutMutex) {
    printBanner(coutMutex);
    std::thread spinnerThread(runSpinner, std::ref(spinnerRunning), std::ref(coutMutex));
    const int ROWS = 45;
    std::string ipfsServer = "localhost";
    int ipfsPort = 5001;

    while (true) {
        displayMenu(ROWS, coutMutex);
        spinnerRunning = false;
        fmt::print("\033[{};25H", ROWS - 2);
        fmt::print("\033[K");
        std::string choice = readLineWithEcho();
        spinnerRunning = true;

        if (choice == "1") {
            try {
                std::string result = wallet.create_wallet("tru.dat");
                displayOutput("[CLI] New wallet created: " + result, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to create wallet: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "2") {
            displayOutput("Enter wallet file path: ", ROWS, coutMutex);
            std::string filename = readLineWithEcho();
            try {
                wallet.loadFromFile(filename);
                displayOutput("[CLI] Wallet loaded from: " + filename, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to load wallet: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "3") {
            displayOutput("Enter filename to save: ", ROWS, coutMutex);
            std::string filename = readLineWithEcho();
            try {
                wallet.saveToFile(filename);
                displayOutput("[CLI] Wallet saved to: " + filename, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to save wallet: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "4") {
            try {
                std::string newAddress = wallet.generateNewAddress();
                displayOutput("[CLI] New address generated: " + newAddress, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to generate new address: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "4a") {
            try {
                auto allAddrs = wallet.getAllAddresses();
                if (allAddrs.empty()) {
                    displayOutput("[CLI] No addresses in wallet!", ROWS, coutMutex);
                } else {
                    // Clear screen
                    std::cout << "\033[2J\033[H";
                    // Display header
                    std::cout << colorText("[CLI] Private keys for all addresses:\n\n", 95, true);
                    // List addresses and private keys
                    for (size_t i = 0; i < allAddrs.size(); ++i) {
                        const auto& addr = allAddrs[i];
                        std::string priv;
                        try {
                            priv = wallet.getPrivateKeyForAddress(addr);
                        } catch (const std::exception& e) {
                            priv = std::string("Error: ") + e.what();
                        }
                        // Print address in green
                        std::cout << "  [" << i << "] " << colorText(addr, 32, true) << "\n";
                        // Print private key in magenta
                        std::cout << "       " << colorText("Private Key:", 95, true) << " "
                                  << colorText(priv, 95) << "\n\n";
                    }
                    // Pause for user input
                    std::cout << "Press Enter to return to menu...";
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    // Clear screen
                    std::cout << "\033[2J\033[H";
                }
            } catch (...) {
                displayOutput("[CLI] Failed to retrieve private keys.", ROWS, coutMutex);
            }
        } else if (choice == "4b") {
            try {
                std::string currentAddr = wallet.getCurrentAddress();
                if (currentAddr.empty()) {
                    displayOutput("[CLI] No current address set.", ROWS, coutMutex);
                } else {
                    viewAddressQRCode(currentAddr);
                }
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to display QR code: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "4c") {
                displayOutput("Enter private key in hex format: ", ROWS, coutMutex);
                std::string privKeyHex = readLineWithEcho();
                try {
                    std::string address = wallet.importPrivateKey(privKeyHex);
                    displayOutput("[CLI] Imported private key for address: " + address, ROWS, coutMutex);
                } catch (const std::exception& e) {
                    displayOutput("[CLI] Failed to import private key: " + std::string(e.what()), ROWS, coutMutex);
                }

        } else if (choice == "5") {
               spinnerRunning = false;
               std::string err = sendTRU(wallet, nodeIP, nodePort, coutMutex);
               if (!err.empty()) {
                   displayOutput(err, ROWS, coutMutex);
               }
               spinnerRunning = true;
        } else if (choice == "6") {
            displayOutput("Enter address to check balance (leave empty for current address): ", ROWS, coutMutex);
            std::string address = readLineWithEcho();
            if (address.empty()) {
                address = wallet.getCurrentAddress();
                if (address.empty()) {
                    displayOutput("[CLI] No current address set in wallet.", ROWS, coutMutex);
                    continue;
                }
            }

            std::string err;
            if (!validateBase58Address(address, err)) {
                displayOutput("[CLI] Invalid address: " + err, ROWS, coutMutex);
                continue;
            }

            try {

                nlohmann::json params = {{"address", address}};
                auto response = rpcCall("listunspent", params, nodeIP, nodePort);
                log("[CLI] Received listunspent response: " + response.dump(2));

                if (response.contains("error") && !response["error"].is_null()) {
                    throw std::runtime_error(response["error"]["message"].get<std::string>());
                }

                auto utxos = response["result"];
                if (!utxos.is_array()) {
                    throw std::runtime_error("Invalid response format from listunspent");
                }

                double balance = 0.0;
                for (const auto& utxo : utxos) {
                    balance += utxo["amount"].get<double>();
                }

                displayOutput("[CLI] Balance for " + address + ": " + fmt::format("{:.8f} TRU", balance), ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to check balance: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "8") {
            printChainInfoRPC(nodeIP, nodePort, coutMutex);
        } else if (choice == "9") {
            try {
                auto peers = rpcCall("getpeerinfo", {}, nodeIP, nodePort).dump(2);
                displayOutput("[CLI] Peers:\n" + peers, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to list peers: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "10") {
            displayOutput("Enter block hash: ", ROWS, coutMutex);
            std::string hash = readLineWithEcho();
            try {
                auto block = rpcCall("getblock", {{"hash", hash}}, nodeIP, nodePort).dump(2);
                displayOutput("[CLI] Block:\n" + block, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to lookup block: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "11") {
            displayOutput("Exiting...", ROWS, coutMutex);
            spinnerRunning = false;
            spinnerThread.join();
            wallet.saveToFile("tru.dat");
            break;
        } else if (choice == "12") {
            displayFormattedTokenList(wallet, nodeIP, nodePort, coutMutex, false);
        } else if (choice == "12a") {
            displayFormattedTokenList(wallet, nodeIP, nodePort, coutMutex, true);
        } else if (choice == "13") {
            spinnerRunning = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[2J\033[1;1H");

            std::cout << colorText("Which token type to create?\n1) FT\n2) NFT\n3) SFT\n4) NCFT\nEnter choice (or 'back' to return): ", 33, true);
            std::string typeChoice = readLineWithEcho();
            if (typeChoice == "back") {
                std::cout << colorText("Token creation cancelled.\n", 31);
                spinnerRunning = true;
                continue;
            }

            std::string tokenType;
            if (typeChoice == "1") tokenType = "FT";
            else if (typeChoice == "2") tokenType = "NFT";
            else if (typeChoice == "3") tokenType = "SFT";
            else if (typeChoice == "4") tokenType = "NCFT";
            else {
                std::cout << colorText("[CLI] Invalid choice. Use 1-4.\n", 31);
                spinnerRunning = true;
                continue;
            }
            std::cout << colorText("Token Type: " + tokenType + "\n", 32, true);

            try {
                std::string txid;
                std::map<std::string, std::string> tokenDetails;

                if (tokenType == "FT") {
                    std::cout << colorText("Enter TokenID (e.g., MYTOKEN, or 'back' to return): ", 33, true);
                    std::string tokenID = readLineWithEcho();
                    if (tokenID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["TokenID"] = tokenID;
                    std::cout << colorText("TokenID: " + tokenID + "\n", 32, true);

                    std::cout << colorText("Enter total supply (uint64_t, or 'back' to return): ", 33, true);
                    std::string supplyStr;
                    do {
                        supplyStr = readLineWithEcho();
                        if (supplyStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            uint64_t supply = std::stoull(supplyStr);
                            if (supply == 0) {
                                std::cout << colorText("[CLI] Total supply must be greater than 0.\n", 31);
                                supplyStr.clear();
                            }
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid number format.\n", 31);
                            supplyStr.clear();
                        }
                    } while (supplyStr.empty());
                    tokenDetails["Total Supply"] = supplyStr;
                    std::cout << colorText("Total Supply: " + supplyStr + "\n", 32, true);

                    std::cout << colorText("Enter name (or 'back' to return): ", 33, true);
                    std::string name = readLineWithEcho();
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    std::cout << colorText("Name: " + name + "\n", 32, true);

                    std::cout << colorText("Enter symbol (or 'back' to return): ", 33, true);
                    std::string symbol = readLineWithEcho();
                    if (symbol == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Symbol"] = symbol;
                    std::cout << colorText("Symbol: " + symbol + "\n", 32, true);

                    std::cout << colorText("Enter description (or 'back' to return): ", 33, true);
                    std::string desc = readLineWithEcho();
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    std::cout << colorText("Description: " + desc + "\n", 32, true);

                    std::cout << colorText("Enter image URL (or 'back' to return): ", 33, true);
                    std::string img = readLineWithEcho();
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    std::cout << colorText("Image URL: " + img + "\n", 32, true);

                    std::cout << colorText("Enter decimals (or 'back' to return): ", 33, true);
                    std::string decStr;
                    do {
                        decStr = readLineWithEcho();
                        if (decStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            std::stoi(decStr);
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid number format.\n", 31);
                            decStr.clear();
                        }
                    } while (decStr.empty());
                    tokenDetails["Decimals"] = decStr;
                    std::cout << colorText("Decimals: " + decStr + "\n", 32, true);

                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::cout << colorText("Add additional metadata? (y/n, or 'back' to return): ", 33, true);
                    std::string addMeta = readLineWithEcho();
                    if (addMeta == "back") throw std::runtime_error("User cancelled");
                    if (addMeta == "y" || addMeta == "Y") {
                        while (true) {
                            std::cout << colorText("Enter key (or 'done' to finish, 'back' to return): ", 33, true);
                            std::string key = readLineWithEcho();
                            if (key == "back") throw std::runtime_error("User cancelled");
                            if (key == "done") break;
                            std::cout << colorText("Key: " + key + "\n", 32, true);
                            std::cout << colorText("Enter value for " + key + " (or 'back' to return): ", 33, true);
                            std::string value = readLineWithEcho();
                            if (value == "back") throw std::runtime_error("User cancelled");
                            additionalMeta[key] = value;
                            std::cout << colorText("Value: " + value + "\n", 32, true);
                        }
                    }

                    std::cout << colorText("Upload image to IPFS? (y/n, or 'back' to return): ", 33, true);
                    std::string useIPFS = readLineWithEcho();
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::cout << colorText("Use default IPFS server (localhost:5001)? (y/n, or 'back' to return): ", 33, true);
                        std::string useDefault = readLineWithEcho();
                        if (useDefault == "back") throw std::runtime_error("User cancelled");
                        if (useDefault != "y" && useDefault != "Y") {
                            std::cout << colorText("Enter IPFS server address (or 'back' to return): ", 33, true);
                            std::string server = readLineWithEcho();
                            if (server == "back") throw std::runtime_error("User cancelled");
                            ipfsServer = server;
                            std::cout << colorText("IPFS Server: " + ipfsServer + "\n", 32, true);

                            std::cout << colorText("Enter IPFS server port (or 'back' to return): ", 33, true);
                            std::string portStr = readLineWithEcho();
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            ipfsPort = portStr.empty() ? 5001 : std::stoi(portStr);
                            std::cout << colorText("IPFS Port: " + std::to_string(ipfsPort) + "\n", 32, true);
                        }

                        std::string ipfsHash, localFile;
                        try {
                            std::cout << colorText("Downloading image...\n", 33, true);
                            localFile = downloadImage(img);
                            std::cout << colorText("Image downloaded to: " + localFile + "\n", 32, true);
                            std::cout << colorText("Uploading to IPFS...\n", 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsServer, ipfsPort);
                            std::cout << colorText("Image uploaded to IPFS with hash: " + ipfsHash + "\n", 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            std::cout << colorText("Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.\n", 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }

                    std::cout << colorText("Review your token details:\n", 32, true);
                    for (const auto& [key, value] : tokenDetails) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    for (const auto& [key, value] : additionalMeta) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    std::cout << colorText("Confirm creation? (y/n): ", 33, true);
                    std::string confirm = readLineWithEcho();
                    if (toLower(confirm) != "y") throw std::runtime_error("User cancelled");

                    txid = wallet.issueExtendedFT(tokenID, std::stoull(supplyStr), name, symbol, desc, img, std::stoi(decStr), additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("FT", txid, tokenDetails, coutMutex);
                } else if (tokenType == "NFT") {
                    std::cout << colorText("Enter NFT ID (or 'back' to return): ", 33, true);
                    std::string nftID = readLineWithEcho();
                    if (nftID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["NFT ID"] = nftID;
                    std::cout << colorText("NFT ID: " + nftID + "\n", 32, true);

                    std::cout << colorText("Enter NFT Name (or 'back' to return): ", 33, true);
                    std::string nftName = readLineWithEcho();
                    if (nftName == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = nftName;
                    std::cout << colorText("Name: " + nftName + "\n", 32, true);

                    std::cout << colorText("Enter description (or 'back' to return): ", 33, true);
                    std::string desc = readLineWithEcho();
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    std::cout << colorText("Description: " + desc + "\n", 32, true);

                    std::cout << colorText("Enter image URL (or 'back' to return): ", 33, true);
                    std::string img = readLineWithEcho();
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    std::cout << colorText("Image URL: " + img + "\n", 32, true);

                    std::cout << colorText("Enter creator (or 'back' to return): ", 33, true);
                    std::string creator = readLineWithEcho();
                    if (creator == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Creator"] = creator;
                    std::cout << colorText("Creator: " + creator + "\n", 32, true);

                    std::cout << colorText("Enter external link (or 'back' to return): ", 33, true);
                    std::string link = readLineWithEcho();
                    if (link == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["External Link"] = link;
                    std::cout << colorText("External Link: " + link + "\n", 32, true);

                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::cout << colorText("Add additional metadata? (y/n, or 'back' to return): ", 33, true);
                    std::string addMeta = readLineWithEcho();
                    if (addMeta == "back") throw std::runtime_error("User cancelled");
                    if (addMeta == "y" || addMeta == "Y") {
                        while (true) {
                            std::cout << colorText("Enter key (or 'done' to finish, 'back' to return): ", 33, true);
                            std::string key = readLineWithEcho();
                            if (key == "back") throw std::runtime_error("User cancelled");
                            if (key == "done") break;
                            std::cout << colorText("Key: " + key + "\n", 32, true);
                            std::cout << colorText("Enter value for " + key + " (or 'back' to return): ", 33, true);
                            std::string value = readLineWithEcho();
                            if (value == "back") throw std::runtime_error("User cancelled");
                            additionalMeta[key] = value;
                            std::cout << colorText("Value: " + value + "\n", 32, true);
                        }
                    }

                    std::cout << colorText("Upload image to IPFS? (y/n, or 'back' to return): ", 33, true);
                    std::string useIPFS = readLineWithEcho();
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::cout << colorText("Use default IPFS server (localhost:5001)? (y/n, or 'back' to return): ", 33, true);
                        std::string useDefault = readLineWithEcho();
                        if (useDefault == "back") throw std::runtime_error("User cancelled");
                        if (useDefault != "y" && useDefault != "Y") {
                            std::cout << colorText("Enter IPFS server address (or 'back' to return): ", 33, true);
                            std::string server = readLineWithEcho();
                            if (server == "back") throw std::runtime_error("User cancelled");
                            ipfsServer = server;
                            std::cout << colorText("IPFS Server: " + ipfsServer + "\n", 32, true);

                            std::cout << colorText("Enter IPFS server port (or 'back' to return): ", 33, true);
                            std::string portStr = readLineWithEcho();
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            ipfsPort = portStr.empty() ? 5001 : std::stoi(portStr);
                            std::cout << colorText("IPFS Port: " + std::to_string(ipfsPort) + "\n", 32, true);
                        }

                        std::string ipfsHash, localFile;
                        try {
                            std::cout << colorText("Downloading image...\n", 33, true);
                            localFile = downloadImage(img);
                            std::cout << colorText("Image downloaded to: " + localFile + "\n", 32, true);
                            std::cout << colorText("Uploading to IPFS...\n", 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsServer, ipfsPort);
                            std::cout << colorText("Image uploaded to IPFS with hash: " + ipfsHash + "\n", 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            std::cout << colorText("Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.\n", 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }

                    std::cout << colorText("Review your token details:\n", 32, true);
                    for (const auto& [key, value] : tokenDetails) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    for (const auto& [key, value] : additionalMeta) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    std::cout << colorText("Confirm creation? (y/n): ", 33, true);
                    std::string confirm = readLineWithEcho();
                    if (toLower(confirm) != "y") throw std::runtime_error("User cancelled");

                    txid = wallet.issueExtendedNFT(nftID, nftName, desc, img, creator, link, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("NFT", txid, tokenDetails, coutMutex);
                } else if (tokenType == "SFT") {
                    std::cout << colorText("Enter SFT TokenID (or 'back' to return): ", 33, true);
                    std::string tokenID = readLineWithEcho();
                    if (tokenID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["SFT TokenID"] = tokenID;
                    std::cout << colorText("SFT TokenID: " + tokenID + "\n", 32, true);

                    std::cout << colorText("Enter total supply (uint64_t, or 'back' to return): ", 33, true);
                    std::string supplyStr;
                    do {
                        supplyStr = readLineWithEcho();
                        if (supplyStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            uint64_t supply = std::stoull(supplyStr);
                            if (supply == 0) {
                                std::cout << colorText("[CLI] Total supply must be greater than 0.\n", 31);
                                supplyStr.clear();
                            }
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid number format.\n", 31);
                            supplyStr.clear();
                        }
                    } while (supplyStr.empty());
                    tokenDetails["Total Supply"] = supplyStr;
                    std::cout << colorText("Total Supply: " + supplyStr + "\n", 32, true);

                    std::cout << colorText("Enter name (or 'back' to return): ", 33, true);
                    std::string name = readLineWithEcho();
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    std::cout << colorText("Name: " + name + "\n", 32, true);

                    std::cout << colorText("Enter symbol (or 'back' to return): ", 33, true);
                    std::string symbol = readLineWithEcho();
                    if (symbol == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Symbol"] = symbol;
                    std::cout << colorText("Symbol: " + symbol + "\n", 32, true);

                    std::cout << colorText("Enter description (or 'back' to return): ", 33, true);
                    std::string desc = readLineWithEcho();
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    std::cout << colorText("Description: " + desc + "\n", 32, true);

                    std::cout << colorText("Enter image URL (or 'back' to return): ", 33, true);
                    std::string img = readLineWithEcho();
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image URL"] = img;
                    std::cout << colorText("Image URL: " + img + "\n", 32, true);

                    std::cout << colorText("Enter decimals (or 'back' to return): ", 33, true);
                    std::string decStr;
                    do {
                        decStr = readLineWithEcho();
                        if (decStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            std::stoi(decStr);
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid number format.\n", 31);
                            decStr.clear();
                        }
                    } while (decStr.empty());
                    tokenDetails["Decimals"] = decStr;
                    std::cout << colorText("Decimals: " + decStr + "\n", 32, true);

                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::vector<std::string> sftFields = {"ai_version", "learning_mode", "growth_algorithm", "adaptation_rate", "evolution_epoch", "description_ai"};
                    std::cout << colorText("Enter advanced AI metadata (leave blank to skip, or 'back' to return):\n", 33, true);
                    for (const auto& field : sftFields) {
                        std::cout << colorText("Enter " + field + " (or 'back' to return): ", 33, true);
                        std::string value = readLineWithEcho();
                        if (value == "back") throw std::runtime_error("User cancelled");
                        if (!value.empty()) {
                            additionalMeta[field] = value;
                            std::cout << colorText(field + ": " + value + "\n", 32, true);
                        }
                    }

                    std::cout << colorText("Upload image to IPFS? (y/n, or 'back' to return): ", 33, true);
                    std::string useIPFS = readLineWithEcho();
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::cout << colorText("Use default IPFS server (localhost:5001)? (y/n, or 'back' to return): ", 33, true);
                        std::string useDefault = readLineWithEcho();
                        if (useDefault == "back") throw std::runtime_error("User cancelled");
                        if (useDefault != "y" && useDefault != "Y") {
                            std::cout << colorText("Enter IPFS server address (or 'back' to return): ", 33, true);
                            std::string server = readLineWithEcho();
                            if (server == "back") throw std::runtime_error("User cancelled");
                            ipfsServer = server;
                            std::cout << colorText("IPFS Server: " + ipfsServer + "\n", 32, true);

                            std::cout << colorText("Enter IPFS server port (or 'back' to return): ", 33, true);
                            std::string portStr = readLineWithEcho();
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            ipfsPort = portStr.empty() ? 5001 : std::stoi(portStr);
                            std::cout << colorText("IPFS Port: " + std::to_string(ipfsPort) + "\n", 32, true);
                        }

                        std::string ipfsHash, localFile;
                        try {
                            std::cout << colorText("Downloading image...\n", 33, true);
                            localFile = downloadImage(img);
                            std::cout << colorText("Image downloaded to: " + localFile + "\n", 32, true);
                            std::cout << colorText("Uploading to IPFS...\n", 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsServer, ipfsPort);
                            std::cout << colorText("Image uploaded to IPFS with hash: " + ipfsHash + "\n", 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            std::cout << colorText("Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.\n", 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }

                    std::cout << colorText("Review your token details:\n", 32, true);
                    for (const auto& [key, value] : tokenDetails) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    for (const auto& [key, value] : additionalMeta) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    std::cout << colorText("Confirm creation? (y/n): ", 33, true);
                    std::string confirm = readLineWithEcho();
                    if (toLower(confirm) != "y") throw std::runtime_error("User cancelled");

                    txid = wallet.issueExtendedSFT(tokenID, std::stoull(supplyStr), name, symbol, desc, img, std::stoi(decStr), additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("SFT", txid, tokenDetails, coutMutex);
                } else if (tokenType == "NCFT") {
                    std::cout << colorText("Enter NCFT ID (or 'back' to return): ", 33, true);
                    std::string ncftID = readLineWithEcho();
                    if (ncftID == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["NCFT ID"] = ncftID;
                    std::cout << colorText("NCFT ID: " + ncftID + "\n", 32, true);

                    std::cout << colorText("Enter name (or 'back' to return): ", 33, true);
                    std::string name = readLineWithEcho();
                    if (name == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Name"] = name;
                    std::cout << colorText("Name: " + name + "\n", 32, true);

                    std::cout << colorText("Enter description (or 'back' to return): ", 33, true);
                    std::string desc = readLineWithEcho();
                    if (desc == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Description"] = desc;
                    std::cout << colorText("Description: " + desc + "\n", 32, true);

                    std::cout << colorText("Enter image/multimedia URL (or 'back' to return): ", 33, true);
                    std::string img = readLineWithEcho();
                    if (img == "back") throw std::runtime_error("User cancelled");
                    tokenDetails["Image/Multimedia URL"] = img;
                    std::cout << colorText("Image/Multimedia URL: " + img + "\n", 32, true);

                    std::cout << colorText("Enter quantity (uint64_t, or 'back' to return): ", 33, true);
                    std::string qtyStr;
                    do {
                        qtyStr = readLineWithEcho();
                        if (qtyStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            uint64_t quantity = std::stoull(qtyStr);
                            if (quantity == 0) {
                                std::cout << colorText("[CLI] Quantity must be greater than 0.\n", 31);
                                qtyStr.clear();
                            }
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid number format.\n", 31);
                            qtyStr.clear();
                        }
                    } while (qtyStr.empty());
                    tokenDetails["Quantity"] = qtyStr;
                    std::cout << colorText("Quantity: " + qtyStr + "\n", 32, true);

                    std::unordered_map<std::string, std::string> additionalMeta;
                    std::vector<std::string> ncftFields = {"ai_engine", "style_descriptor", "dynamic_morph", "update_interval", "creator_signature", "last_evolution"};
                    std::cout << colorText("Enter advanced AI/art metadata (leave blank to skip, or 'back' to return):\n", 33, true);
                    for (const auto& field : ncftFields) {
                        std::cout << colorText("Enter " + field + " (or 'back' to return): ", 33, true);
                        std::string value = readLineWithEcho();
                        if (value == "back") throw std::runtime_error("User cancelled");
                        if (!value.empty()) {
                            additionalMeta[field] = value;
                            std::cout << colorText(field + ": " + value + "\n", 32, true);
                        }
                    }

                    std::cout << colorText("Upload image to IPFS? (y/n, or 'back' to return): ", 33, true);
                    std::string useIPFS = readLineWithEcho();
                    if (useIPFS == "back") throw std::runtime_error("User cancelled");
                    if (useIPFS == "y" || useIPFS == "Y") {
                        std::cout << colorText("Use default IPFS server (localhost:5001)? (y/n, or 'back' to return): ", 33, true);
                        std::string useDefault = readLineWithEcho();
                        if (useDefault == "back") throw std::runtime_error("User cancelled");
                        if (useDefault != "y" && useDefault != "Y") {
                            std::cout << colorText("Enter IPFS server address (or 'back' to return): ", 33, true);
                            std::string server = readLineWithEcho();
                            if (server == "back") throw std::runtime_error("User cancelled");
                            ipfsServer = server;
                            std::cout << colorText("IPFS Server: " + ipfsServer + "\n", 32, true);

                            std::cout << colorText("Enter IPFS server port (or 'back' to return): ", 33, true);
                            std::string portStr = readLineWithEcho();
                            if (portStr == "back") throw std::runtime_error("User cancelled");
                            ipfsPort = portStr.empty() ? 5001 : std::stoi(portStr);
                            std::cout << colorText("IPFS Port: " + std::to_string(ipfsPort) + "\n", 32, true);
                        }

                        std::string ipfsHash, localFile;
                        try {
                            std::cout << colorText("Downloading image...\n", 33, true);
                            localFile = downloadImage(img);
                            std::cout << colorText("Image downloaded to: " + localFile + "\n", 32, true);
                            std::cout << colorText("Uploading to IPFS...\n", 33, true);
                            ipfsHash = uploadToIPFS(localFile, ipfsServer, ipfsPort);
                            std::cout << colorText("Image uploaded to IPFS with hash: " + ipfsHash + "\n", 32, true);
                            additionalMeta["ipfs_image"] = "ipfs://" + ipfsHash;
                        } catch (const std::exception& e) {
                            std::cout << colorText("Failed to upload to IPFS: " + std::string(e.what()) + ". Using original URL.\n", 31, true);
                        }
                        if (!localFile.empty()) remove(localFile.c_str());
                    }

                    std::cout << colorText("Review your token details:\n", 32, true);
                    for (const auto& [key, value] : tokenDetails) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    for (const auto& [key, value] : additionalMeta) {
                        std::cout << colorText("  " + key + ": " + value + "\n", 32);
                    }
                    std::cout << colorText("Confirm creation? (y/n): ", 33, true);
                    std::string confirm = readLineWithEcho();
                    if (toLower(confirm) != "y") throw std::runtime_error("User cancelled");

                    txid = wallet.issueExtendedNCFT(ncftID, std::stoull(qtyStr), name, desc, img, additionalMeta);
                    for (const auto& [key, value] : additionalMeta) tokenDetails[key] = value;
                    displayTokenCreationSuccess("NCFT", txid, tokenDetails, coutMutex);
                }
            } catch (const std::exception& e) {
                std::cout << colorText("[CLI] Failed to issue token: " + std::string(e.what()) + "\n", 31, true);
            }
            spinnerRunning = true;
        } else if (choice == "13a") {
                displayOutput(
                    "💡 Reminder: TRUScripts live in an 80-byte OP_RETURN; after JSON & prefix you get ~30–40 chars.",
                    ROWS, coutMutex
                  );
                 // 1) Prompt
                 displayOutput("Enter text to inscribe:", ROWS, coutMutex);
                 std::string data;
                 std::getline(std::cin, data);
                 if (data.empty()) {
                     displayOutput("⟵ No input provided. Returning to menu.", ROWS, coutMutex);
                     continue;   // <-- was `break;`
                 }
                try {
                    std::string txid = wallet.inscribeTRUScript(data, wallet.getCurrentAddress());
                    displayOutput("🏷️ TRUScript inscribed in tx: " + txid, ROWS, coutMutex);
                } catch (const std::exception &e) {
                    displayOutput("[Error] " + std::string(e.what()), ROWS, coutMutex);
                }

                continue; // make sure we go right back to the menu
        } else if (choice == "13b") {
                auto scripts = wallet.getTRUScripts(wallet.getCurrentAddress());
                if (scripts.empty()) {
                    displayOutput("You have no TRUScripts yet.", ROWS, coutMutex);
                } else {
                    displayTRUScriptsCLI(scripts, ROWS, coutMutex);
                }
                continue;
        } else if (choice == "14") {
            try {
                auto allAddrs = wallet.getAllAddresses();
                uint32_t currentIdx = wallet.getCurrentIndex();
                std::ostringstream oss;
                oss << "[CLI] Addresses in this wallet:\n";
                for (size_t i = 0; i < allAddrs.size(); i++) {
                    oss << "  [" << i << "] " << allAddrs[i];
                    if (i == currentIdx) {
                        oss << " (CURRENT)";
                    }
                    oss << "\n";
                }
                displayOutput(oss.str(), ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to list addresses: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "15") {
            std::string result = sendTokenViaRPC(wallet, nodeIP, nodePort, coutMutex);
               if (!result.empty()) {
                    displayOutput(result, ROWS, coutMutex);
            }
        } else if (choice == "16") {
            displayOutput("Enter peer IP: ", ROWS, coutMutex);
            std::string ip = readLineWithEcho();
            displayOutput("Enter peer port: ", ROWS, coutMutex);
            std::string portStr = readLineWithEcho();
            int port = std::stoi(portStr);
            try {
                auto result = rpcCall("connecttopeer", {{"ip", ip}, {"port", port}}, nodeIP, nodePort);
                displayOutput("[CLI] " + result["result"].get<std::string>(), ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to connect to peer: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "17") {
            displayOutput("Enter peer IP: ", ROWS, coutMutex);
            std::string ip = readLineWithEcho();
            displayOutput("Enter peer port: ", ROWS, coutMutex);
            std::string portStr = readLineWithEcho();
            int port = std::stoi(portStr);
            displayOutput("Enter message: ", ROWS, coutMutex);
            std::string message = readLineWithEcho();
            try {
                auto result = rpcCall("sendmessagetopeer", {{"ip", ip}, {"port", port}, {"message", message}}, nodeIP, nodePort);
                displayOutput("[CLI] " + result["result"].get<std::string>(), ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to send message: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "18") {
            spinnerRunning = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[2J\033[1;1H");

            try {
                const std::string senderAddr = wallet.getCurrentAddress();
                const std::string pubkeyhash = getCurrentPubkeyhash(wallet);
                std::cout << colorText("Your Address: " + senderAddr + "\n", 32, true);
                std::cout << colorText("Current Pubkeyhash: " + pubkeyhash + "\n", 32, true);

                std::cout << colorText("Choose contract type:\n  1) Time Lock\n  2) OP_RETURN\n  3) Hash Lock\n  4) Custom Script\nEnter choice (1-4 or 'back'): ", 33, true);
                std::string contractTypeChoice = readLineWithEcho();
                if (contractTypeChoice == "back") throw std::runtime_error("User cancelled");

                std::string contractType;
                if (contractTypeChoice == "1") contractType = "TIME LOCK";
                else if (contractTypeChoice == "2") contractType = "OP_RETURN";
                else if (contractTypeChoice == "3") contractType = "HASH LOCK";
                else if (contractTypeChoice == "4") contractType = "CUSTOM SCRIPT";
                else {
                    std::cout << colorText("[CLI] Invalid choice. Use 1-4.\n", 31);
                    throw std::runtime_error("Invalid contract type");
                }
                std::cout << colorText("Contract Type: " + contractType + "\n", 32, true);

                std::string scriptText, contractName, lockReason;
                if (contractType == "TIME LOCK") {
                    std::cout << colorText("Enter lock time (Unix ts, or 'back' to return): ", 33, true);
                    std::string lockTimeStr;
                    do {
                        lockTimeStr = readLineWithEcho();
                        if (lockTimeStr == "back") throw std::runtime_error("User cancelled");
                        try {
                            std::stoul(lockTimeStr);
                        } catch (...) {
                            std::cout << colorText("[CLI] Invalid timestamp.\n", 31);
                            lockTimeStr.clear();
                        }
                    } while (lockTimeStr.empty());
                    uint32_t lockTime = std::stoul(lockTimeStr);
                    std::cout << colorText("Lock Time: " + lockTimeStr + "\n", 32, true);

                    std::cout << colorText("Enter pubkeyhash (40 hex chars, or 'back' to return): ", 33, true);
                    std::string pubHash;
                    do {
                        pubHash = readLineWithEcho();
                        if (pubHash == "back") throw std::runtime_error("User cancelled");
                        if (pubHash.size() != 40 || !std::all_of(pubHash.begin(), pubHash.end(), ::isxdigit)) {
                            std::cout << colorText("[CLI] Must be 40 hex chars.\n", 31);
                            pubHash.clear();
                        }
                    } while (pubHash.empty());
                    std::cout << colorText("Pubkeyhash: " + pubHash + "\n", 32, true);

                    std::cout << colorText("Enter lock reason (optional, <=50 chars, or 'back' to return): ", 33, true);
                    lockReason = readLineWithEcho();
                    if (lockReason == "back") throw std::runtime_error("User cancelled");
                    if (lockReason.size() > 50) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Lock reason too long");
                    }
                    std::cout << colorText("Lock Reason: " + (lockReason.empty() ? "N/A" : lockReason) + "\n", 32, true);

                    std::cout << colorText("Enter contract name (<=50 chars, or 'back' to return): ", 33, true);
                    contractName = readLineWithEcho();
                    if (contractName == "back") throw std::runtime_error("User cancelled");
                    if (contractName.size() > 50) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Contract name too long");
                    }
                    std::cout << colorText("Contract Name: " + contractName + "\n", 32, true);

                    scriptText = fmt::format("{:08x}", lockTime) + " OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 " + pubHash + " OP_EQUALVERIFY OP_CHECKSIG";
                } else if (contractType == "OP_RETURN") {
                    std::cout << colorText("Enter data (<=75 bytes, or 'back' to return): ", 33, true);
                    std::string data = readLineWithEcho();
                    if (data == "back") throw std::runtime_error("User cancelled");
                    if (data.size() > 75) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Data too long");
                    }
                    std::cout << colorText("Data: " + data + "\n", 32, true);

                    std::cout << colorText("Enter contract name (<=50 chars, or 'back' to return): ", 33, true);
                    contractName = readLineWithEcho();
                    if (contractName == "back") throw std::runtime_error("User cancelled");
                    if (contractName.size() > 50) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Contract name too long");
                    }
                    std::cout << colorText("Contract Name: " + contractName + "\n", 32, true);

                    scriptText = "OP_RETURN " + asciiToHex(data);
                } else if (contractType == "HASH LOCK") {
                    std::cout << colorText("Enter preimage (<=100 chars, or 'back' to return): ", 33, true);
                    std::string pre = readLineWithEcho();
                    if (pre == "back") throw std::runtime_error("User cancelled");
                    if (pre.size() > 100) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Preimage too long");
                    }
                    std::cout << colorText("Preimage: " + pre + "\n", 32, true);

                    std::cout << colorText("Enter contract name (<=50 chars, or 'back' to return): ", 33, true);
                    contractName = readLineWithEcho();
                    if (contractName == "back") throw std::runtime_error("User cancelled");
                    if (contractName.size() > 50) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Contract name too long");
                    }
                    std::cout << colorText("Contract Name: " + contractName + "\n", 32, true);

                    unsigned char sha256sum[SHA256_DIGEST_LENGTH];
                    SHA256(reinterpret_cast<const unsigned char*>(pre.c_str()), pre.size(), sha256sum);
                    std::vector<unsigned char> h160(20);
                    RIPEMD160(sha256sum, SHA256_DIGEST_LENGTH, h160.data());
                    scriptText = "OP_HASH160 " + bytesToHex(h160) + " OP_EQUAL";
                } else if (contractType == "CUSTOM SCRIPT") {
                    std::cout << colorText("Enter custom script (or 'back' to return): ", 33, true);
                    scriptText = readLineWithEcho();
                    if (scriptText == "back") throw std::runtime_error("User cancelled");
                    if (scriptText.empty()) {
                        std::cout << colorText("[CLI] Cannot be empty.\n", 31);
                        throw std::runtime_error("Script cannot be empty");
                    }
                    std::cout << colorText("Custom Script: " + scriptText + "\n", 32, true);

                    std::cout << colorText("Enter contract name (<=50 chars, or 'back' to return): ", 33, true);
                    contractName = readLineWithEcho();
                    if (contractName == "back") throw std::runtime_error("User cancelled");
                    if (contractName.size() > 50) {
                        std::cout << colorText("[CLI] Too long.\n", 31);
                        throw std::runtime_error("Contract name too long");
                    }
                    std::cout << colorText("Contract Name: " + contractName + "\n", 32, true);
                }

                std::cout << colorText("Review your contract details:\n", 32, true);
                std::cout << colorText("  Contract Type: " + contractType + "\n", 32);
                std::cout << colorText("  Contract Name: " + contractName + "\n", 32);
                if (!lockReason.empty()) std::cout << colorText("  Lock Reason: " + lockReason + "\n", 32);
                std::cout << colorText("  Script: " + scriptText + "\n", 32);
                std::cout << colorText("Confirm creation? (y/n): ", 33, true);
                std::string confirm = readLineWithEcho();
                if (toLower(confirm) != "y") throw std::runtime_error("User cancelled");

                nlohmann::json params = {{"script", scriptText}};
                auto result = rpcCall("createsmartcontract", params, nodeIP, nodePort);
                std::string txid = result["result"]["txid"].get<std::string>();
                std::string broadcastStatus = "Broadcast succeeded."; // Simplified for standalone CLI
                std::string contractAddress = txid + ":1"; // Placeholder
                displaySuccessMessageContract(contractType, txid, contractAddress, scriptText, broadcastStatus, senderAddr, contractName, lockReason, coutMutex);
            } catch (const std::exception& e) {
                std::cout << colorText("[CLI] Failed to create contract: " + std::string(e.what()) + "\n", 31, true);
            }
            spinnerRunning = true;
        } else if (choice == "18a") {
            try {
                std::string pubkeyhash = getCurrentPubkeyhash(wallet);
                displayOutput("[CLI] Current Pubkeyhash: " + pubkeyhash, ROWS, coutMutex);
            } catch (const std::exception& e) {
                displayOutput("[CLI] Failed to get pubkeyhash: " + std::string(e.what()), ROWS, coutMutex);
            }
        } else if (choice == "C" || choice == "c") {
            //std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[2J\033[1;1H");
            printBanner3(coutMutex);
        } else {
            displayOutput("Invalid option. Please choose 1-18 or C", ROWS, coutMutex);
        }
    }
}

int main(int argc, char *argv[]) {
    cxxopts::Options options("wallet_cli", "Standalone Wallet CLI via RPC");
    options.add_options()
        ("n,node", "Node IP", cxxopts::value<std::string>()->default_value("127.0.0.1"))
        ("p,port", "Node RPC port", cxxopts::value<int>()->default_value(std::to_string(tru_network::MAINNET_RPC_PORT)))
        ("w,wallet", "Wallet file path", cxxopts::value<std::string>()->default_value("tru.dat"))
        ("h,help", "Show help");

    auto result = options.parse(argc, argv);
    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    std::string nodeIP = result["node"].as<std::string>();

    int nodePort = result["port"].as<int>();
    std::string walletFile = result["wallet"].as<std::string>();
    Wallet wallet(walletFile, nullptr, nodeIP, nodePort);

    // Automatic wallet initialization
    if (std::filesystem::exists(walletFile)) {
        try {
            if (!wallet.loadFromFile(walletFile)) {
                throw std::runtime_error("Failed to load wallet despite file existence.");
            }
            log("Loaded existing wallet from " + walletFile + " successfully.");
            std::cout << "Wallet loaded from " << walletFile << std::endl;
        } catch (const std::exception& e) {
            log("Error loading wallet: " + std::string(e.what()));
            std::cerr << "Error loading wallet: " << e.what() << std::endl;
            return 1;
        }
    } else {
        try {
            log("No existing wallet found at " + walletFile + ". Creating a new one...");
            std::string newAddress = wallet.create_wallet(walletFile); // Assuming this generates a new wallet and returns an address
            wallet.saveToFile(walletFile); // Ensure the new wallet is saved
            log("New wallet created and saved to " + walletFile + " with address: " + newAddress);
            std::cout << "New wallet created and saved to " << walletFile << std::endl;
            std::cout << "Your new address: " << newAddress << std::endl;
            std::cout << "Please back up your wallet file (" << walletFile << ") to avoid losing access to your funds." << std::endl;
        } catch (const std::exception& e) {
            log("Error creating new wallet: " + std::string(e.what()));
            std::cerr << "Error creating new wallet: " << e.what() << std::endl;
            return 1;
        }
    }

    std::atomic<bool> spinnerRunning(true);
    std::mutex coutMutex;
    startCLI(wallet, nodeIP, nodePort, spinnerRunning, coutMutex);
    log("Wallet CLI exited");
    return 0;
}
