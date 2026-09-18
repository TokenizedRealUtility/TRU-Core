#pragma once

#include <string>
#include <vector>
#include "script_interpreter.h"

namespace NOVOBridge {
    bool generateNOVOAddress(ScriptExecutionContext& ctx,
                             std::vector<std::vector<unsigned char>>& stack);
    bool confirmNOVODeposit(ScriptExecutionContext& ctx,
                            std::vector<std::vector<unsigned char>>& stack);
    bool redeemNOVO(ScriptExecutionContext& ctx,
                    std::vector<std::vector<unsigned char>>& stack);
    // Optional switch integration.
    bool verifyNOVO(ScriptExecutionContext& ctx,
                    std::vector<std::vector<unsigned char>>& stack);
}

namespace BSTYBridge {
    bool generateBSTYAddress(ScriptExecutionContext& ctx,
                             std::vector<std::vector<unsigned char>>& stack);
    bool confirmBSTYDeposit(ScriptExecutionContext& ctx,
                            std::vector<std::vector<unsigned char>>& stack);
    bool redeemBSTY(ScriptExecutionContext& ctx,
                    std::vector<std::vector<unsigned char>>& stack);
    // Optional switch integration.
    bool verifyBSTY(ScriptExecutionContext& ctx,
                    std::vector<std::vector<unsigned char>>& stack);
}

