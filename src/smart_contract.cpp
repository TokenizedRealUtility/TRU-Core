 #include "tru_network_params.h"
#include "tru_amount.h"
#include "tru_limits.h"
#include "smart_contract.h"
#include "utils.h"
#include "logging.h"
#include "tokens.h"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include "address_helpers.h"
#include <ctime>
#include <algorithm>
#include <limits> 
#include <cctype>
#include "mempool.h"
#include "script_context_builder.h"  // shared execution context

namespace SmartContract {


void displayOutput(const std::string& text, int rows, std::mutex& m) {
    std::lock_guard<std::mutex> lock(m);
    std::cout << text << std::endl;
}

std::string getContractTypeEmoji(const std::string& contractType) {
    if (contractType == "TIME LOCK") return "🔒";
    if (contractType == "OP_RETURN") return "📝";
    if (contractType == "HASH LOCK") return "🔑";
    if (contractType == "CUSTOM SCRIPT") return "⚙️";
    if (contractType == "ORACLE LOCK") return "🔮";
    if (contractType == "STATEFUL CONTRACT") return "💾";
    return "📄";
}

int getColorForContractType(const std::string& contractType) {
    if (contractType == "TIME LOCK") return 94;      // Blue
    if (contractType == "OP_RETURN") return 93;      // Yellow
    if (contractType == "HASH LOCK") return 95;      // Magenta
    if (contractType == "CUSTOM SCRIPT") return 96;  // Cyan
    if (contractType == "ORACLE LOCK") return 92;    // Green
    if (contractType == "STATEFUL CONTRACT") return 91; // Red
    return 37; // Default white
}

std::string formatAmount(uint64_t atoms) {
    return tru_amount::format(atoms);
}

std::string formatTimestamp(uint32_t timestamp) {
    time_t t = static_cast<time_t>(timestamp);
    struct tm* tm_info = localtime(&t);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buffer);
}

std::string truncateHex(const std::string& hex, size_t maxLen) {
    if (hex.length() <= maxLen) return hex;
    return hex.substr(0, maxLen - 3) + "...";
}

static std::string hexifyLockTime(uint32_t t) {
    // little-endian 4-byte hex
    return fmt::format("{:08x}", t);
}

static std::string askNonEmpty(const std::string& prompt) {
    std::string line;
    std::cout << prompt;
    std::getline(std::cin, line);
    if (line.empty())
        throw std::runtime_error("Input cannot be empty");
    return line;
}

// SC-22: relay policy is compiled and structural in Mempool.
// allowed_scripts.json is now documentation/reference only and is never
// loaded as a runtime policy source from the current working directory.

// Create Smart Contract
std::string createSmartContract(Wallet& wallet, Blockchain& chain, P2PNode& node) {
    try {
        // Clear any previous input stream issues
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        // Retrieve and log sender
        const std::string senderAddr = wallet.getCurrentAddress();
        Logger::log("[createSmartContract] Sender address: " + senderAddr);

        // Prompt for contract type
        enum ContractType { TIME_LOCK = 1, OP_RETURN_CT, HASH_LOCK, CUSTOM_SCRIPT, ORACLE_LOCK, STATEFUL_CONTRACT };
        ContractType choice = TIME_LOCK;
        
        while (true) {
            std::cout << "\nChoose contract type:\n"
                      << "  1) Time Lock\n"
                      << "  2) OP_RETURN\n"
                      << "  3) Hash Lock\n"
                      << "  4) Custom Script\n"
                      << "  5) Oracle-Locked\n"
                      << "  6) Stateful Key/Value\n"
                      << "Enter choice (1-6): " << std::flush;
            
            std::string input;
            if (!std::getline(std::cin, input)) {
                std::cerr << "Failed to read input. Clearing stream and retrying." << std::endl;
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }
            
            try {
                int idx = std::stoi(input);
                if (idx >= 1 && idx <= 6) { 
                    choice = static_cast<ContractType>(idx);
                    Logger::log("[createSmartContract] Selected contract type: " + std::to_string(idx));
                    break; 
                }
            } catch (...) {}
            std::cerr << "Invalid selection, please try again." << std::endl;
        }

        std::string scriptText;
        std::string contractName;
        std::string lockReason;
        uint64_t contractAmount = 0; // Amount to lock in contract
        uint32_t lockTime = 0; // For time lock contracts

        // Handle each contract type
        switch (choice) {
            case TIME_LOCK: {
                std::cout << "\n=== TIME LOCK CONTRACT ===" << std::endl;
                
                // Prompt lock time
                while (true) {
                    std::cout << "Enter lock time (Unix timestamp): " << std::flush;
                    std::string ts;
                    if (!std::getline(std::cin, ts)) {
                        std::cerr << "Failed to read input" << std::endl;
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        continue;
                    }
                    
                    try {
                        size_t used = 0;
                        const unsigned long long parsed =
                            std::stoull(ts, &used, 10);
                        if (used != ts.size() ||
                            parsed < 500000000ULL ||
                            parsed > std::numeric_limits<uint32_t>::max()) {
                            throw std::runtime_error("timestamp outside TRU Time Lock V1 domain");
                        }
                        lockTime = static_cast<uint32_t>(parsed);
                        std::cout << "Lock time set to: " << lockTime << std::endl;
                        break;
                    } catch (...) {
                        std::cerr <<
                            "Invalid timestamp; TRU Time Lock V1 requires Unix timestamp >= 500000000."
                            << std::endl;
                    }
                }
                
                // Convert to little-endian hex
                unsigned char timeBytes[4];
                timeBytes[0] = (lockTime >> 0) & 0xFF;
                timeBytes[1] = (lockTime >> 8) & 0xFF;
                timeBytes[2] = (lockTime >> 16) & 0xFF;
                timeBytes[3] = (lockTime >> 24) & 0xFF;
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (int i = 0; i < 4; i++) {
                    ss << std::setw(2) << static_cast<int>(timeBytes[i]);
                }
                std::string timeHex = ss.str();

                // PubKeyHash
                std::string pubkeyHash;
                while (true) {
                    std::cout << "Enter pubkey hash (40 hex chars): " << std::flush;
                    if (!std::getline(std::cin, pubkeyHash)) {
                        std::cerr << "Failed to read input" << std::endl;
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        continue;
                    }
                    
                    if (pubkeyHash.size() == 40 && std::all_of(pubkeyHash.begin(), pubkeyHash.end(), ::isxdigit)) {
                        std::cout << "Pubkey hash accepted: " << pubkeyHash << std::endl;
                        break;
                    }
                    std::cerr << "Invalid hex, must be exactly 40 hex chars." << std::endl;
                }

                // Amount to lock
                Logger::log("[createSmartContract] About to prompt for amount to lock");
                while (true) {
                    std::cout << "\nEnter amount to lock [TRU]: " << std::flush;
                    std::string amountStr;
                    if (!std::getline(std::cin, amountStr)) {
                        std::cerr << "Failed to read input" << std::endl;
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        continue;
                    }
                    std::string amountReason;
                    if (tru_amount::parse(amountStr, contractAmount, amountReason) &&
                        contractAmount > 0 && contractAmount <= tru_limits::MAX_MONEY) {
                        std::cout << "Amount to lock: " << tru_amount::format(contractAmount)
                                  << " (" << tru_amount::formatAtoms(contractAmount) << ")" << std::endl;
                        break;
                    }
                    if (amountReason.empty()) {
                        amountReason = contractAmount > tru_limits::MAX_MONEY
                            ? "amount exceeds MAX_MONEY"
                            : "amount must be greater than 0";
                    }
                    std::cerr << "Invalid amount: " << amountReason << std::endl;
                }

                // Optional reason
                std::cout << "Enter lock reason (optional, max 50 chars): " << std::flush;
                std::getline(std::cin, lockReason);
                if (lockReason.length() > 50) {
                    lockReason = lockReason.substr(0, 50);
                }

                // Contract name
                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);

                scriptText = timeHex + " OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 "
                             + pubkeyHash + " OP_EQUALVERIFY OP_CHECKSIG";
                break;
            }

            case OP_RETURN_CT: {
                std::cout << "\n=== OP_RETURN CONTRACT ===" << std::endl;
                std::cout << "Enter data to store: " << std::flush;
                std::string data;
                std::getline(std::cin, data);
                
                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);
                
                scriptText = "OP_RETURN " + asciiToHex(data);
                // OP_RETURN outputs always have 0 value
                contractAmount = 0;
                std::cout << "Note: OP_RETURN outputs always have 0 value" << std::endl;
                break;
            }

            case HASH_LOCK: {
                std::cout << "\n=== HASH LOCK CONTRACT ===" << std::endl;
                std::cout << "Enter preimage: " << std::flush;
                std::string preimage;
                std::getline(std::cin, preimage);
                
                // Amount to lock
                Logger::log("[createSmartContract] About to prompt for amount to lock (HASH_LOCK)");
                while (true) {
                    std::cout << "\nEnter amount to lock [TRU]: " << std::flush;
                    std::string amountStr;
                    if (!std::getline(std::cin, amountStr)) {
                        std::cerr << "Failed to read input" << std::endl;
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        continue;
                    }
                    std::string amountReason;
                    if (tru_amount::parse(amountStr, contractAmount, amountReason) &&
                        contractAmount > 0 && contractAmount <= tru_limits::MAX_MONEY) {
                        std::cout << "Amount to lock: " << tru_amount::format(contractAmount)
                                  << " (" << tru_amount::formatAtoms(contractAmount) << ")" << std::endl;
                        break;
                    }
                    if (amountReason.empty()) {
                        amountReason = contractAmount > tru_limits::MAX_MONEY
                            ? "amount exceeds MAX_MONEY"
                            : "amount must be greater than 0";
                    }
                    std::cerr << "Invalid amount: " << amountReason << std::endl;
                }
                
                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);
                
                // Compute RIPEMD160(SHA256(preimage))
                unsigned char sha[SHA256_DIGEST_LENGTH];
                SHA256(reinterpret_cast<const unsigned char*>(preimage.data()), preimage.size(), sha);
                std::vector<unsigned char> ripemd(20);
                RIPEMD160(sha, SHA256_DIGEST_LENGTH, ripemd.data());
                scriptText = "OP_HASH160 " + bytesToHex(ripemd) + " OP_EQUAL";
                break;
            }

            case CUSTOM_SCRIPT: {
                std::cout << "\n=== CUSTOM SCRIPT CONTRACT ===" << std::endl;
                std::cout << "Enter custom script: " << std::flush;
                std::getline(std::cin, scriptText);
                if (scriptText.empty()) {
                    throw std::runtime_error("Custom script cannot be empty.");
                }

                // SC-22 validates the COMPILED bytecode against the same
                // structural relay policy used by RPC/mempool. Textual opcode
                // names are never compared against hex regexes.
                
                // Amount to lock (if applicable)
                std::cout << "Enter amount to lock [TRU] (0 for no value): " << std::flush;
                std::string amountStr;
                std::getline(std::cin, amountStr);
                std::string amountReason;
                if (!tru_amount::parse(amountStr, contractAmount, amountReason) ||
                    contractAmount > tru_limits::MAX_MONEY) {
                    if (amountReason.empty()) amountReason = "amount exceeds MAX_MONEY";
                    throw std::runtime_error("Invalid TRU amount: " + amountReason);
                }
                if (contractAmount > 0) {
                    std::cout << "Amount to lock: " << tru_amount::format(contractAmount)
                              << " (" << tru_amount::formatAtoms(contractAmount) << ")" << std::endl;
                }
                
                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);
                break;
            }

            case ORACLE_LOCK: {
                std::cout << "\n=== ORACLE-LOCKED CONTRACT — V1 ===" << std::endl;
                std::cout << "Deterministic feeds:\n"
                          << "  chain:block_height\n"
                          << "  chain:total_supply\n"
                          << "  chain:block_reward\n";

                std::string oracleKey;
                while (true) {
                    std::cout << "Oracle feed key: " << std::flush;
                    std::getline(std::cin, oracleKey);
                    if (oracleKey == "chain:block_height" ||
                        oracleKey == "chain:total_supply" ||
                        oracleKey == "chain:block_reward") break;
                    std::cerr << "Unsupported feed. Oracle Feed V1 accepts only deterministic chain:* keys." << std::endl;
                }

                uint64_t threshold = 0;
                while (true) {
                    std::cout << "Threshold (uint64): " << std::flush;
                    std::string thresholdText;
                    std::getline(std::cin, thresholdText);
                    if (!thresholdText.empty() &&
                        std::all_of(thresholdText.begin(), thresholdText.end(),
                            [](unsigned char c){ return c >= '0' && c <= '9'; })) {
                        try {
                            size_t used = 0;
                            threshold = std::stoull(thresholdText, &used, 10);
                            if (used == thresholdText.size()) break;
                        } catch (...) {}
                    }
                    std::cerr << "Invalid uint64 decimal." << std::endl;
                }

                bool ge = true;
                while (true) {
                    std::cout << "Compare: 1) >=   2) <= : " << std::flush;
                    std::string cmp;
                    std::getline(std::cin, cmp);
                    if (cmp == "1") { ge = true; break; }
                    if (cmp == "2") { ge = false; break; }
                    std::cerr << "Enter 1 or 2." << std::endl;
                }

                Logger::log("[createSmartContract] About to prompt for amount to lock (ORACLE_LOCK)");
                while (true) {
                    std::cout << "\nEnter amount to lock [TRU]: " << std::flush;
                    std::string amountStr;
                    if (!std::getline(std::cin, amountStr)) {
                        std::cerr << "Failed to read input" << std::endl;
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        continue;
                    }
                    std::string amountReason;
                    if (tru_amount::parse(amountStr, contractAmount, amountReason) &&
                        contractAmount > 0 && contractAmount <= tru_limits::MAX_MONEY) {
                        std::cout << "Amount to lock: " << tru_amount::format(contractAmount)
                                  << " (" << tru_amount::formatAtoms(contractAmount) << ")" << std::endl;
                        break;
                    }
                    if (amountReason.empty()) {
                        amountReason = contractAmount > tru_limits::MAX_MONEY
                            ? "amount exceeds MAX_MONEY"
                            : "amount must be greater than 0";
                    }
                    std::cerr << "Invalid amount: " << amountReason << std::endl;
                }

                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);

                const std::vector<unsigned char> decoded = decodeBase58Check(senderAddr);
                if (decoded.size() != 25)
                    throw std::runtime_error("Invalid sender address for Oracle Lock owner binding");
                const std::vector<unsigned char> ownerHash(decoded.begin() + 1, decoded.begin() + 21);

                std::vector<unsigned char> thresholdBytes(8);
                for (size_t i = 0; i < thresholdBytes.size(); ++i)
                    thresholdBytes[i] = static_cast<unsigned char>((threshold >> (8 * i)) & 0xff);

                scriptText = asciiToHex(oracleKey) +
                             " OP_DATAFEED " + bytesToHex(thresholdBytes) +
                             (ge ? " OP_GREATERTHANOREQUAL" : " OP_LESSTHANOREQUAL") +
                             " OP_VERIFY OP_DUP OP_HASH160 " + bytesToHex(ownerHash) +
                             " OP_EQUALVERIFY OP_CHECKSIG";
                break;
            }

            case STATEFUL_CONTRACT: {
                std::cout << "\n=== STATEFUL KEY/VALUE CONTRACT ===" << std::endl;
                std::cout << "Enter initial key: " << std::flush;
                std::string key;
                std::getline(std::cin, key);
                
                std::cout << "Enter initial value: " << std::flush;
                std::string value;
                std::getline(std::cin, value);
                
                // Amount to lock (optional for stateful)
                std::cout << "Enter amount to lock [TRU] (0 for no value): " << std::flush;
                std::string amountStr;
                std::getline(std::cin, amountStr);
                std::string amountReason;
                if (!tru_amount::parse(amountStr, contractAmount, amountReason) ||
                    contractAmount > tru_limits::MAX_MONEY) {
                    if (amountReason.empty()) amountReason = "amount exceeds MAX_MONEY";
                    throw std::runtime_error("Invalid TRU amount: " + amountReason);
                }
                if (contractAmount > 0) {
                    std::cout << "Amount to lock: " << tru_amount::format(contractAmount)
                              << " (" << tru_amount::formatAtoms(contractAmount) << ")" << std::endl;
                }
                
                std::cout << "Enter contract name: " << std::flush;
                std::getline(std::cin, contractName);
                
                // Create stateful script
                scriptText = asciiToHex(value) + " " + asciiToHex(key) + " OP_STORE OP_1";
                break;
            }
        }

        // Ensure non-empty
        if (contractName.empty() || scriptText.empty()) {
            throw std::runtime_error("Contract name and script must not be empty.");
        }

        // Compile script
        std::vector<unsigned char> scriptBytes;
        try {
            scriptBytes = compileTextScript(scriptText);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Script compilation failed: ") + e.what());
        }
        const std::string scriptHex = bytesToHex(scriptBytes);
        Logger::log("[createSmartContract] Compiled script hex: " + scriptHex);

        if (choice == CUSTOM_SCRIPT) {
            if (!chain.mempool ||
                !chain.mempool->isAllowedSmartContractScript(scriptHex)) {
                throw std::runtime_error(
                    "Custom script is not relay-standard under SC-22 structural policy.");
            }
        }

        Logger::log("[createSmartContract] Contract amount: " + std::to_string(contractAmount));

        // Fee input
        uint64_t fee = 10000;
        std::cout << "\nEnter transaction fee [TRU] (default "
                  << tru_amount::format(fee) << "): " << std::flush;
        std::string feeInput;
        std::getline(std::cin, feeInput);
        if (!feeInput.empty()) {
            std::string feeReason;
            uint64_t parsedFee = 0;
            if (tru_amount::parse(feeInput, parsedFee, feeReason) &&
                parsedFee <= tru_limits::MAX_MONEY) {
                fee = parsedFee;
                std::cout << "Fee set to: " << tru_amount::format(fee)
                          << " (" << tru_amount::formatAtoms(fee) << ")" << std::endl;
            } else {
                if (feeReason.empty()) feeReason = "fee exceeds MAX_MONEY";
                std::cout << "Invalid fee (" << feeReason << "), using default: "
                          << tru_amount::format(fee) << std::endl;
            }
        }

        // Select UTXO
        Logger::log("[createSmartContract] Finding spendable UTXO");
        auto [utxoTxid, utxoVout] = wallet.findOneSpendableUtxo(senderAddr, chain.mempool.get());
        if (utxoTxid.empty()) {
            throw std::runtime_error("No spendable UTXO available.");
        }
        
        UTXO utxo;
        if (!chain.utxoSet.getUTXO(utxoTxid, utxoVout, utxo)) {
            throw std::runtime_error("Failed to retrieve selected UTXO.");
        }
        const uint64_t balance = utxo.amount;
        Logger::log("[createSmartContract] Selected UTXO: " + utxoTxid + ":" + std::to_string(utxoVout) + 
                    " with balance: " + std::to_string(balance));
        
        // Check if we have enough funds
        if (contractAmount > std::numeric_limits<uint64_t>::max() - fee) {
            throw std::overflow_error("Contract amount + fee overflow");
        }
        uint64_t totalNeeded = contractAmount + fee;
        if (balance < totalNeeded) {
            throw std::runtime_error("Insufficient funds. Have: " + std::to_string(balance) + 
                                   " TRU atoms, Need: " + std::to_string(totalNeeded) + " TRU atoms");
        }

        // Build transaction
        Logger::log("[createSmartContract] Building transaction");
        Transaction tx;
        tx.version = 1;
        tx.lockTime = 0;
        tx.vin.emplace_back(utxoTxid, utxoVout);

        // OP_RETURN metadata (output 0)
        std::string meta = "TRU_CONTRACT:" + contractName;
        if (!lockReason.empty()) meta += ":REASON:" + lockReason;
        std::vector<unsigned char> metaBytes(meta.begin(), meta.end());
        if (metaBytes.size() > 256) throw std::runtime_error("OP_RETURN data exceeds 256 bytes.");
        std::string opHex = "6a" + fmt::format("{:02x}", metaBytes.size()) + bytesToHex(metaBytes);
        tx.vout.emplace_back(0, opHex);

        // Contract output with the specified amount (output 1)
        tx.vout.emplace_back(contractAmount, scriptHex);
        Logger::log("[createSmartContract] Created contract output with amount: " + std::to_string(contractAmount));

        // Change output (output 2, if needed)
        uint64_t changeAmount = balance - contractAmount - fee;
        if (changeAmount > 0) {
            std::string changeScript = createP2PKHScriptHexFromAddress(senderAddr);
            tx.vout.emplace_back(changeAmount, changeScript);
            Logger::log("[createSmartContract] Change output: " + std::to_string(changeAmount));
        }

        // Sign
        Logger::log("[createSmartContract] Signing transaction");
        if (!wallet.signTransaction(tx)) {
            throw std::runtime_error("Transaction signing failed.");
        }

        // Broadcast
        Logger::log("[createSmartContract] Broadcasting transaction");
        const std::string rawHex = hexEncode(tx.serializeBinary());
        bool ok = wallet.broadcastTxToExternalNode(rawHex, "127.0.0.1", tru_network::MAINNET_RPC_PORT);
        const std::string statusMsg = ok ? "Broadcast succeeded." : "Broadcast failed.";

        // Determine contract address
        std::string contractAddr = extractAddressFromScriptPubKey(scriptHex, tx.txid, 1, &chain);
        if (contractAddr.empty()) contractAddr = tx.txid + ":1";

        // Summary
        std::ostringstream summary;
        summary << "\n" << std::string(50, '=') << "\n";
        summary << "CONTRACT DEPLOYMENT SUMMARY\n";
        summary << std::string(50, '=') << "\n";
        summary << "Contract Name: " << contractName << "\n";
        summary << "Contract Type: ";
        switch (choice) {
            case TIME_LOCK: summary << "Time Lock"; break;
            case OP_RETURN_CT: summary << "OP_RETURN"; break;
            case HASH_LOCK: summary << "Hash Lock"; break;
            case CUSTOM_SCRIPT: summary << "Custom Script"; break;
            case ORACLE_LOCK: summary << "Oracle Lock"; break;
            case STATEFUL_CONTRACT: summary << "Stateful Contract"; break;
        }
        summary << "\n";
        summary << "Amount Locked: " << tru_amount::format(contractAmount)
                << " (" << tru_amount::formatAtoms(contractAmount) << ")\n";
        
        if (choice == TIME_LOCK && lockTime > 0) {
            time_t timeT = static_cast<time_t>(lockTime);
            char buffer[100];
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&timeT));
            summary << "Lock Time: " << buffer << " (Unix: " << lockTime << ")\n";
            if (!lockReason.empty()) {
                summary << "Lock Reason: " << lockReason << "\n";
            }
        }
        
        summary << "Transaction ID: " << tx.txid << "\n";
        summary << "Contract Address: " << contractAddr << "\n";
        summary << "Status: " << statusMsg << "\n";
        summary << std::string(50, '=') << "\n";
        
        Logger::log("[createSmartContract] Contract deployment completed");
        return summary.str();

    } catch (const std::exception& e) {
        Logger::log(std::string("[createSmartContract] ERROR: ") + e.what());
        throw;
    }
}

// Query Contract State
// Query Contract State
void queryContractState(const Blockchain& chain, int rows, std::mutex& coutMutex) {
    Logger::log("[queryContractState] Starting contract query using getContracts()");
    
    try {
        // Use the existing getContracts() method
        nlohmann::json contractData = chain.getContracts();
        
        // Using the ContractInfo struct from the SmartContract namespace
        std::vector<SmartContract::ContractInfo> results;
        uint64_t totalLocked = 0;
        uint64_t totalSpent = 0;
        int activeContracts = 0;
        
        if (contractData.contains("contracts") && contractData["contracts"].is_array()) {
            for (const auto& contract : contractData["contracts"]) {
                SmartContract::ContractInfo info;
                info.identifier = contract.value("identifier", "Unknown");
                info.type = contract.value("type", "Unknown");
                info.name = contract.value("name", "Unnamed");
                info.txid = contract.value("txid", "");
                info.creator = contract.value("creator", "N/A");
                info.timestamp = contract.value("creationTime", 0);
                info.lockTime = contract.value("lockTime", 0);
                info.scriptHex = contract.value("scriptPubKey", "");
                
                // Extract vout from identifier
                info.vout = contract.value("vout", 0);
                size_t lastUnderscore = info.identifier.rfind('_');
                size_t colonPos = info.identifier.find(':');

                if (lastUnderscore != std::string::npos && lastUnderscore + 1 < info.identifier.length())
                {
                    // Format: contract_txid_vout
                    try
                    {
                        info.vout = std::stoul(info.identifier.substr(lastUnderscore + 1));
                    }
                    catch (...)
                    {
                    }
                }
                else if (colonPos != std::string::npos && colonPos + 1 < info.identifier.length())
                {
                    // Format: txid:vout
                    try
                    {
                        info.vout = std::stoul(info.identifier.substr(colonPos + 1));
                    }
                    catch (...)
                    {
                    }
                }

                // Check if UTXO is still unspent and get amount
                info.amount = 0;
                info.isUnspent = false;
                if (!info.txid.empty()) {
                    UTXO utxo;
                    info.isUnspent = chain.utxoSet.getUTXO(info.txid, info.vout, utxo);

    	            Logger::log("[queryContractState] UTXO lookup for " + info.txid + ":" + std::to_string(info.vout) + " = " + (info.isUnspent ? "found" : "not found"));

                    if (info.isUnspent) {
                        info.amount = utxo.amount;
                        totalLocked += info.amount;
                        activeContracts++;
                    } else {
                        // Try to get amount from stored contract data
                        info.amount = contract.value("amount", 0);
                        totalSpent += info.amount;
                    }
                }
                
                results.push_back(info);
            }
        }
        
        // Clear screen and display results
        {
            std::lock_guard<std::mutex> lock(coutMutex);
            fmt::print("\033[2J\033[1;1H"); // Clear screen
            
            // Header
            fmt::print(colorText("⛓️═══════════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
            fmt::print(colorText("                    📋 SMART CONTRACT STATE QUERY - TRU BLOCKCHAIN 📋           \n", 32, true));
            fmt::print(colorText("⛓️═══════════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
            
            if (results.empty()) {
                fmt::print(colorText("\n        No smart contracts found in blockchain.\n", 31));
                fmt::print(colorText("\n        Deploy contracts using option 18 from the main menu.\n", 33));
            } else {
                // Summary statistics
                fmt::print(colorText("\n📊 Summary Statistics:\n", 32, true));
                fmt::print(colorText(fmt::format("   Total Contracts:    {}\n", results.size()), 37));
                fmt::print(colorText(fmt::format("   Active Contracts:   {} ", activeContracts), 37));
                fmt::print(colorText(fmt::format("({:.1f}%)\n", (double)activeContracts / results.size() * 100), 92));
                fmt::print(colorText("   Total Value Locked: " + tru_amount::format(totalLocked) + "\n", 93, true));
                fmt::print(colorText("   Total Value Spent:  " + tru_amount::format(totalSpent) + "\n", 91));
                
                // Contract details table
                fmt::print(colorText("\n📜 Contract Details:\n", 32, true));
                fmt::print(colorText("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n", 36));
                
                // Table header
                fmt::print(colorText(fmt::format("{:<4} {:<15} {:<20} {:<15} {:<12} {:<8} {:<20} {:<10}\n", 
                                    "#", "Type", "Name", "Amount (TRU)", "Lock Until", "Status", "Creator", "Age"), 33, true));
                fmt::print(colorText("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n", 36));
                
                // Sort by status (active first) then by amount
                std::sort(results.begin(), results.end(), [](const SmartContract::ContractInfo& a, const SmartContract::ContractInfo& b) {
                    if (a.isUnspent != b.isUnspent) return a.isUnspent > b.isUnspent;
                    return a.amount > b.amount;
                });
                
                // Display each contract
                int idx = 1;
                for (const auto& info : results) {
                    // Determine emoji and color based on type
                    std::string emoji = getContractTypeEmoji(info.type);
                    int typeColor = getColorForContractType(info.type);
                    
                    // Format fields
                    std::string typeStr = emoji + " " + info.type;
                    if (typeStr.length() > 15) typeStr = typeStr.substr(0, 12) + "...";
                    
                    std::string nameStr = info.name;
                    if (nameStr.length() > 20) nameStr = nameStr.substr(0, 17) + "...";
                    
                    std::string amountStr = tru_amount::formatNumeric(info.amount);
                    
                    std::string lockStr = "-";
                    if (info.type == "TIME LOCK" && info.lockTime > 0) {
                        time_t now = time(nullptr);
                        if (info.lockTime > now) {
                            // Fix for fmt::localtime
                            time_t lockTimeT = static_cast<time_t>(info.lockTime);
                            struct tm* tm_info = localtime(&lockTimeT);
                            char buffer[20];
                            strftime(buffer, sizeof(buffer), "%m/%d %H:%M", tm_info);
                            lockStr = std::string(buffer);
                        } else {
                            lockStr = "UNLOCKED";
                        }
                    }
                    
                    std::string statusStr = info.isUnspent ? "✓ Active" : "✗ Spent";
                    int statusColor = info.isUnspent ? 92 : 91;
                    
                    std::string creatorStr = info.creator;
                    if (creatorStr.length() > 20) creatorStr = creatorStr.substr(0, 17) + "...";
                    
                    // Calculate age
                    std::string ageStr = "-";
                    if (info.timestamp > 0) {
                        time_t now = time(nullptr);
                        int ageSeconds = now - info.timestamp;
                        if (ageSeconds < 3600) {
                            ageStr = fmt::format("{}m ago", ageSeconds / 60);
                        } else if (ageSeconds < 86400) {
                            ageStr = fmt::format("{}h ago", ageSeconds / 3600);
                        } else {
                            ageStr = fmt::format("{}d ago", ageSeconds / 86400);
                        }
                    }
                    
                    // Print row
                    fmt::print(colorText(fmt::format("{:<4} ", idx), 37));
                    fmt::print(colorText(fmt::format("{:<15} ", typeStr), typeColor));
                    fmt::print(colorText(fmt::format("{:<20} ", nameStr), 37));
                    fmt::print(colorText(fmt::format("{:<15} ", amountStr), info.amount > 0 ? 93 : 90));
                    fmt::print(colorText(fmt::format("{:<12} ", lockStr), 94));
                    fmt::print(colorText(fmt::format("{:<8} ", statusStr), statusColor));
                    fmt::print(colorText(fmt::format("{:<20} ", creatorStr), 37));
                    fmt::print(colorText(fmt::format("{:<10}\n", ageStr), 90));
                    
                    idx++;
                }
                
                fmt::print(colorText("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n", 36));
                
                // Additional options
                fmt::print(colorText("\n📌 Options:\n", 32, true));
                //fmt::print(colorText("   • Enter contract # for details\n", 37));
                fmt::print(colorText("   • Press 'r' to refresh\n", 37));
                fmt::print(colorText("   • Press Enter to return to menu\n", 37));
                
                // Handle user input
                fmt::print(colorText("\nYour choice: ", 33));
                std::string choice;
                std::getline(std::cin, choice);
                
                if (!choice.empty() && choice != "r") {
                    try {
                        int selected = std::stoi(choice) - 1;
                        if (selected >= 0 && selected < results.size()) {
                            // Show detailed view of selected contract
                            displayContractDetails(results[selected], chain, coutMutex);
                        }
                    } catch (...) {
                        // Invalid input, just return
                    }
                } else if (choice == "r") {
                    // Refresh by calling this function again
                    queryContractState(chain, rows, coutMutex);
                    return;
                }
            }
        }
        
    } catch (const std::exception& e) {
        Logger::log("[queryContractState] ERROR: " + std::string(e.what()));
        
        // Display error
        std::lock_guard<std::mutex> lock(coutMutex);
        fmt::print("\033[2J\033[1;1H");
        fmt::print("{}", colorText("Error querying contracts: " + std::string(e.what()) + "\n", 31));
        fmt::print("\nPress Enter to continue...");
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

// Smart-contract helper.
bool spendTimeLockContract(
    Wallet& wallet,
    Blockchain& chain,
    const std::string& contractTxid,
    uint32_t contractVout,
    const std::string& recipientAddress,
    uint64_t fee)
{
    // retain the legacy API surface, but remove its independent
    // wall-clock/signing/broadcast implementation. Canonical Time Lock spends
    // are now constructed by Wallet::redeemTimeLock(), which is also used by
    // the CLI and RPC path. recipientAddress/fee were never consensus fields;
    // the canonical wallet path redeems to the wallet's current address using
    // size-aware policy fees.
    (void)chain;
    (void)recipientAddress;
    (void)fee;
    try {
        (void)wallet.redeemTimeLock(
            contractTxid + ":" + std::to_string(contractVout));
        return true;
    } catch (const std::exception& e) {
        Logger::log(
            "[spendTimeLock] canonical redemption failed: " +
            std::string(e.what()));
        return false;
    }
}

void displayContractDetails(const ContractInfo& contract, const Blockchain& chain, std::mutex& coutMutex) {
    std::lock_guard<std::mutex> lock(coutMutex);
    fmt::print("\033[2J\033[1;1H"); // Clear screen
    
    std::string emoji = getContractTypeEmoji(contract.type);
    int typeColor = getColorForContractType(contract.type);
    
    fmt::print(colorText("⛓️═══════════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText(fmt::format("                    {} CONTRACT DETAILS - {} {}                    \n", 
                        emoji, contract.name, emoji), typeColor, true));
    fmt::print(colorText("⛓️═══════════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    
    fmt::print(colorText("\n📋 Basic Information:\n", 32, true));
    fmt::print(colorText("   Contract Type:     ", 37)); fmt::print(colorText(contract.type + "\n", typeColor, true));
    fmt::print(colorText("   Contract Name:     ", 37)); fmt::print(colorText(contract.name + "\n", 33));
    fmt::print(colorText("   Transaction ID:    ", 37)); fmt::print(colorText(contract.txid + "\n", 36));
    fmt::print(colorText("   Output Index:      ", 37)); fmt::print(colorText(fmt::format("#{}\n", contract.vout), 33));
    fmt::print(colorText("   Contract Address:  ", 37)); fmt::print(colorText(contract.identifier + "\n", 35));
    
    fmt::print(colorText("\n💰 Financial Details:\n", 32, true));
    fmt::print(colorText("   Amount Locked:     ", 37)); 
    fmt::print(colorText(formatAmount(contract.amount) + "\n", contract.amount > 0 ? 93 : 90, true));
    fmt::print(colorText("   Status:            ", 37)); 
    fmt::print(colorText(contract.isUnspent ? "✓ Active (Unspent)\n" : "✗ Spent\n", contract.isUnspent ? 92 : 91, true));
    
    if (contract.type == "TIME LOCK" && contract.lockTime > 0) {
        fmt::print(colorText("\n🔒 Time Lock Details:\n", 32, true));
        fmt::print(colorText("   Lock Time:         ", 37)); 
        fmt::print(colorText(formatTimestamp(contract.lockTime) + "\n", 94));
        
        time_t now = time(nullptr);
        if (contract.lockTime > now) {
            int remaining = contract.lockTime - now;
            int days = remaining / 86400;
            int hours = (remaining % 86400) / 3600;
            int minutes = (remaining % 3600) / 60;
            fmt::print(colorText("   Time Remaining:    ", 37));
            fmt::print(colorText(fmt::format("{} days, {} hours, {} minutes\n", days, hours, minutes), 93));
            fmt::print(colorText("   Can Unlock After:  ", 37));
            fmt::print(colorText("NO - Still locked\n", 91, true));
        } else {
            fmt::print(colorText("   Status:            ", 37));
            fmt::print(colorText("UNLOCKED - Ready to spend ✓\n", 92, true));
        }
    }
    
    fmt::print(colorText("\n🔧 Technical Details:\n", 32, true));
    fmt::print(colorText("   Creator Address:   ", 37)); fmt::print(colorText(contract.creator + "\n", 32));
    fmt::print(colorText("   Creation Time:     ", 37)); 
    if (contract.timestamp > 0) {
        fmt::print(colorText(formatTimestamp(contract.timestamp) + "\n", 33));
    } else {
        fmt::print(colorText("Unknown\n", 90));
    }
    
    if (!contract.scriptHex.empty()) {
        fmt::print(colorText("   Script Size:       ", 37)); 
        fmt::print(colorText(fmt::format("{} bytes\n", contract.scriptHex.length() / 2), 33));
        fmt::print(colorText("   Script Hex:        ", 37)); 
        fmt::print(colorText(truncateHex(contract.scriptHex, 60) + "\n", 90));
    }
    
    // Instructions for spending
    if (contract.isUnspent && contract.amount > 0) {
        fmt::print(colorText("\n📖 How to Spend:\n", 32, true));
        if (contract.type == "TIME LOCK") {
            if (contract.lockTime > time(nullptr)) {
                fmt::print(colorText("   ⏳ Wait until the lock time expires\n", 93));
                fmt::print(colorText("   ⏳ Then use your private key to create a spending transaction\n", 93));
            } else {
                fmt::print(colorText("   ✓ Lock time has expired - you can spend this now!\n", 92));
                fmt::print(colorText("   ✓ Create a transaction with your private key as input\n", 92));
            }
        } else if (contract.type == "HASH LOCK") {
            fmt::print(colorText("   🔑 Provide the preimage that hashes to the stored value\n", 93));
            fmt::print(colorText("   🔑 Include the preimage in your spending transaction\n", 93));
        }
    }
    
    fmt::print(colorText("\n⛓️═══════════════════════════════════════════════════════════════════════════⛓️\n", 36, true));
    fmt::print(colorText("\nPress Enter to return to contract list...", 33));
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    // Return to main query view
    //queryContractState(chain, 24, coutMutex);
}

} // namespace SmartContract
