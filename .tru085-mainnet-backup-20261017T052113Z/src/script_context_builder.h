#pragma once

#include "script_interpreter.h"
#include "contract_state_lineage.h"  // stable lineage/state key primitives

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

// shared base execution-context construction.
//
// Every live script execution path must start from the ScriptExecutionContext
// constructor (which installs all callback defaults) and then populate the same
// base fields through this helper. Patch 14C defines contractAddress as the
// canonical CURRENT locking-output identity "<txid>:<vout>". Patch 14D1 adds
// separate stable state-domain/lineage key primitives without activating them.
// State and outputIndex remain explicit inputs because persistence/call-value
// semantics are later patches.
struct ScriptExecutionContextSpec {
    uint64_t gasLimit{1000000};
    const Transaction* tx{nullptr};
    uint32_t blockTime{0};
    uint32_t medianTimePast{0}; // parent-chain MTP for CLTV only
    size_t inputIndex{0};
    const std::vector<unsigned char>* scriptPubKey{nullptr};
    std::vector<unsigned char> sighash;
    const void* chainCtx{nullptr};
    uint32_t execHeight{0};
    std::string sender;
    std::unordered_map<std::string, std::vector<unsigned char>>* state{nullptr};
    std::string contractAddress;
    size_t outputIndex{size_t(-1)};
};

inline ScriptExecutionContext BuildScriptExecutionContext(
    const ScriptExecutionContextSpec& spec)
{
    // The constructor is authoritative for callbacks/gas defaults.
    ScriptExecutionContext ctx(spec.gasLimit, spec.tx, spec.blockTime);

    ctx.medianTimePast = spec.medianTimePast;
    ctx.inputIndex = spec.inputIndex;
    ctx.scriptPubKey = spec.scriptPubKey;
    ctx.sighash = spec.sighash;
    ctx.sender = spec.sender;
    ctx.outputIndex = spec.outputIndex;
    ctx.state = spec.state;
    ctx.chainCtx = spec.chainCtx;
    ctx.execHeight = spec.execHeight;
    ctx.contractAddress = spec.contractAddress;
    ctx.gasUsed = 0;

    // EvaluateScript requires exactly one active root frame on entry and returns
    // to that invariant after every well-formed script.
    ctx.execStack.assign(1, true);
    return ctx;
}
