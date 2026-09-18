#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>
#include "opcodes.h"

class Transaction;

struct ScriptExecutionContext {
    uint32_t blockTime;                             // Candidate/header or admission time for OP_BLOCKTIME
    // parent-chain Median-Time-Past (MTP) is a separate
    // consensus clock. OP_CHECKLOCKTIMEVERIFY uses this field; it must never
    // substitute the candidate header timestamp or a node-local wall clock.
    uint32_t medianTimePast{0};
    const Transaction* tx;                          // Pointer to the current transaction
    size_t inputIndex;                              // Index of the input being verified
    const std::vector<unsigned char>* scriptPubKey; // Pointer to the scriptPubKey of the UTXO
    std::vector<unsigned char> sighash;             // Precomputed sighash for signature checks
    std::string sender;
    size_t outputIndex;
    std::unordered_map<std::string, std::vector<unsigned char>>* state; // Pointer to contract state
    // FIX: opaque pointer to the Blockchain (cast inside OP_CHAINSTATECHECK).
    // Enables deterministic on-chain state reads without a header dependency.
    const void* chainCtx = nullptr;
    // Height at which this script executes (the block being validated), so
    // state reads are deterministic relative to THIS block, not the live tip.
    uint32_t execHeight = 0;
    uint64_t gasLimit;                              // Maximum gas allowed for execution
    uint64_t gasUsed;                               // Gas consumed during execution
    std::string contractAddress;                    // Address of the contract being executed

    // Callback functions for custom opcodes
    std::function<bool(const std::vector<unsigned char>& pubkey,
                       const std::vector<unsigned char>& signature,
                       const std::string& message)> signatureCheckFunc;
    // OP_DATAFEED has no pluggable callback. Consensus feed reads
    // are resolved directly from deterministic execution context.
    std::function<bool(const std::vector<unsigned char>&)> delegateCheckFunc;
    std::function<std::vector<unsigned char>()> chainStateFunc;
    std::function<std::vector<unsigned char>(const std::vector<unsigned char>&)> blake2bFunc;
    std::function<std::vector<unsigned char>(const std::vector<unsigned char>&)> sha3Func;
    // OP_EXTERNALDATA has no consensus callback and fails closed.
    std::vector<bool> execStack; // Tracks execution state for conditional blocks

    //ScriptExecutionContext();

    // Constructor with parameters for production flexibility
    ScriptExecutionContext(
        uint64_t gasLimit = 1000000,
        const Transaction* transaction = nullptr,
        uint32_t currentBlockTime = 0
    );

    // Check if in simulation mode (no transaction context)
    bool isSimulationMode() const {
        return tx == nullptr;
    }
};

// deterministic script resource accounting.
struct ScriptResourceMetrics {
    uint64_t opCount = 0;
    uint64_t sigOpCost = 0;
};

// Parses PUSHDATA exactly and counts non-push opcodes. CHECKMULTISIG is charged
// at the worst-case 20 signature checks so resource accounting cannot depend on
// attacker-controlled stack contents.
bool AnalyzeScriptResources(const std::vector<unsigned char>& script,
                            ScriptResourceMetrics& metrics);

// Function declarations
bool EvaluateScript(const std::vector<unsigned char>& script,
                    std::vector<std::vector<unsigned char>>& stack,
                    ScriptExecutionContext& ctx);

bool VerifyScripts(const std::vector<unsigned char>& scriptSig,
                   const std::vector<unsigned char>& scriptPubKey,
                   ScriptExecutionContext& ctx);

std::vector<unsigned char> compileTextScript(const std::string& scriptText);
