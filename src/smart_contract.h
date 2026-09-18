#pragma once

#include "wallet.h"
#include "blockchain.h"
#include "p2p.h"

#include <string>
#include <vector>
#include <mutex>

namespace SmartContract {

// Contract-state query result.
struct ContractInfo {
    std::string identifier;
    std::string type;
    uint64_t amount;
    std::string name;
    std::string creator;
    uint32_t timestamp;
    bool isUnspent;
    std::string txid;
    uint32_t vout;
    uint32_t lockTime;
    std::string scriptHex;
};

/// Supported contract types
enum class ContractType {
    TIME_LOCK = 1,
    OP_RETURN,
    HASH_LOCK,
    CUSTOM_SCRIPT,
    ORACLE_LOCK,
    STATEFUL_CONTRACT
};

/**
 * Builds, signs, and broadcasts a new contract UTXO.
 * @throws std::runtime_error on any validation/compile/broadcast error.
 * @returns A human-readable summary of the deployed contract.
 */
std::string createSmartContract(Wallet& wallet,
                               Blockchain& chain,
                               P2PNode& node);

/**
 * Scans the chain for contract records and prints a colorized table.
 * SC-22 relay standardness is compiled/structural and does not depend on
 * allowed_scripts.json regexes.
 */

void queryContractState(const Blockchain& chain,
                       int rows,
                       std::mutex& coutMutex);

void displayContractDetails(const ContractInfo& contract, const Blockchain& chain, std::mutex& coutMutex);
std::string getContractTypeEmoji(const std::string& contractType);
int getColorForContractType(const std::string& contractType);
std::string formatAmount(uint64_t atoms);
std::string formatTimestamp(uint32_t timestamp);
std::string truncateHex(const std::string& hex, size_t maxLen = 64);
void displayOutput(const std::string& text, int rows, std::mutex& m);
bool spendTimeLockContract( Wallet& wallet, Blockchain& chain, const std::string& contractTxid, uint32_t contractVout, const std::string& recipientAddress, uint64_t fee);
} // namespace SmartContract


// Utility functions declared externally
extern std::string createP2PKHScriptHexFromAddress(const std::string& address);
extern std::string hexEncode(const std::vector<unsigned char>& data);
extern bool isValidAddress(const std::string& address);

