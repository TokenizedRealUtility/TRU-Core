#pragma once
// Read-only RPC history. No persistent indexes or validation changes.
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <type_traits>
#include <vector>
#include <string>
namespace tru_address_history_v1 {
using json = nlohmann::json;
template<class Blocks, class AddressOf, class DecodeHex>
json collect(const Blocks& blocks, const std::string& address, int count,
             int maxBlocks, AddressOf addressOf, DecodeHex decodeHex) {
    json rows = json::array();
    const int tip = blocks.empty() ? 0 : blocks.back().height;

    // All references are used only while the caller holds the chain read lock.
    using Tx = typename std::decay<decltype(blocks.front().transactions.front())>::type;
    std::unordered_map<std::string, const Tx*> byID;
    for (const auto& block : blocks)
        for (const auto& tx : block.transactions) byID.emplace(tx.txid, &tx);
    for (auto blockIt = blocks.rbegin(); blockIt != blocks.rend() &&
         static_cast<int>(rows.size()) < count; ++blockIt) {
        const auto& block = *blockIt;
        const int height = block.height;
        if (maxBlocks > 0 && height < tip - maxBlocks + 1) break;

        for (auto txIt = block.transactions.rbegin();
             txIt != block.transactions.rend() &&
             static_cast<int>(rows.size()) < count;
             ++txIt) {

            const auto& tx = *txIt;

            uint64_t totalInputs = 0;
            uint64_t myInputs = 0;
            uint64_t totalOutputs = 0;
            uint64_t myOutputs = 0;
            uint64_t sentToOthers = 0;

            std::string firstInputAddress;
            std::string firstOtherOutputAddress;

            for (const auto& vin : tx.vin) {
                if (vin.isCoinbase()) continue;

                const auto previous = byID.find(vin.txid);
                if (previous == byID.end() || vin.vout >= previous->second->vout.size())
                    throw std::runtime_error("Address history has an unresolved confirmed input");
                const auto& prevOut = previous->second->vout[vin.vout];
                totalInputs += prevOut.amount;

                std::string inAddr;
                try {
                    inAddr = addressOf(prevOut.scriptPubKey);
                } catch (...) {
                    inAddr.clear();
                }

                if (firstInputAddress.empty() && !inAddr.empty())
                    firstInputAddress = inAddr;
                if (inAddr == address)
                    myInputs += prevOut.amount;
            }

            bool hasMyOutput = false;
            bool isScriptTransfer = false;
            std::string scriptFrom;
            std::string scriptTo;

            for (const auto& out : tx.vout) {
                totalOutputs += out.amount;

                std::string outAddr;
                try {
                    outAddr = addressOf(out.scriptPubKey);
                } catch (...) {
                    outAddr.clear();
                }

                if (outAddr == address) {
                    myOutputs += out.amount;
                    hasMyOutput = true;
                } else if (!outAddr.empty()) {
                    if (myInputs > 0)
                        sentToOthers += out.amount;
                    if (firstOtherOutputAddress.empty())
                        firstOtherOutputAddress = outAddr;
                }

                if (out.amount == 0 &&
                    out.scriptPubKey.rfind("6a", 0) == 0) {
                    try {
                        // WEB_WALLET_PATCH_2A:
                        // decodeOpReturn() is not visible in rpc_server.cpp.
                        // Decode standard OP_RETURN push data locally.
                        const std::string& scriptHex = out.scriptPubKey;
                        size_t pos = 2; // skip OP_RETURN (6a)
                        if (pos + 2 > scriptHex.size())
                            throw std::runtime_error("Malformed OP_RETURN");

                        const unsigned int pushOp =
                            static_cast<unsigned int>(
                                std::stoul(scriptHex.substr(pos, 2), nullptr, 16));
                        pos += 2;

                        size_t dataLen = 0;
                        if (pushOp <= 75) {
                            dataLen = pushOp;
                        } else if (pushOp == 0x4c) {
                            if (pos + 2 > scriptHex.size())
                                throw std::runtime_error("Malformed OP_PUSHDATA1");
                            dataLen = std::stoul(
                                scriptHex.substr(pos, 2), nullptr, 16);
                            pos += 2;
                        } else if (pushOp == 0x4d) {
                            if (pos + 4 > scriptHex.size())
                                throw std::runtime_error("Malformed OP_PUSHDATA2");
                            const size_t lo = std::stoul(
                                scriptHex.substr(pos, 2), nullptr, 16);
                            const size_t hi = std::stoul(
                                scriptHex.substr(pos + 2, 2), nullptr, 16);
                            dataLen = lo | (hi << 8);
                            pos += 4;
                        } else {
                            throw std::runtime_error(
                                "Unsupported OP_RETURN push opcode");
                        }

                        if (dataLen == 0 ||
                            pos + dataLen * 2 > scriptHex.size())
                            throw std::runtime_error(
                                "Malformed OP_RETURN payload");

                        const std::string dataHex =
                            scriptHex.substr(pos, dataLen * 2);
                        const std::vector<uint8_t> dataBytes =
                            decodeHex(dataHex);
                        const std::string decoded(
                            dataBytes.begin(), dataBytes.end());

                        const json marker = json::parse(decoded);
                        if (marker.value("type", "") ==
                            "TRUSCRIPT_TRANSFER") {
                            isScriptTransfer = true;
                            scriptFrom = marker.value("from", "");
                            scriptTo = marker.value("to", "");
                        }
                    } catch (...) {
                    }
                }
            }

            const bool involves =
                myInputs > 0 || hasMyOutput ||
                (isScriptTransfer &&
                 (scriptFrom == address || scriptTo == address));

            if (!involves)
                continue;

            std::string type;
            std::string counterparty;
            std::string asset = "TRU";
            double amount = 0.0;

            if (isScriptTransfer &&
                (scriptFrom == address || scriptTo == address)) {
                type = scriptFrom == address ? "Sent" : "Received";
                counterparty =
                    scriptFrom == address ? scriptTo : scriptFrom;
                asset = "TRUScript";
            } else if (tx.isCoinbase && hasMyOutput) {
                type = "Received";
                counterparty = "Mining Reward";
                amount = static_cast<double>(myOutputs) / 100000000.0;
            } else if (myInputs > 0) {
                type = "Sent";
                counterparty =
                    firstOtherOutputAddress.empty()
                        ? "Unknown"
                        : firstOtherOutputAddress;
                amount =
                    static_cast<double>(sentToOthers) / 100000000.0;
            } else {
                type = "Received";
                counterparty =
                    firstInputAddress.empty()
                        ? "Unknown"
                        : firstInputAddress;
                amount =
                    static_cast<double>(myOutputs) / 100000000.0;
            }

            uint64_t feeSat = 0;
            if (!tx.isCoinbase && totalInputs >= totalOutputs)
                feeSat = totalInputs - totalOutputs;

            rows.push_back({
                {"txid", tx.txid},
                {"type", type},
                {"address", counterparty},
                {"amount", amount},
                {"asset", asset},
                {"isTRUScript", asset == "TRUScript"},
                {"fee", static_cast<double>(feeSat) / 100000000.0},
                {"timestamp", block.header.timestamp},
                {"blockHeight", height},
                {"confirmations", tip >= height ? tip - height + 1 : 0}
            });
        }
    }

    return rows;
}
}
