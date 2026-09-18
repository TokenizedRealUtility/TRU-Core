#include "blockexplorer.h"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include "logging.h"
#include "tokens.h"
#include "utils.h"
#include "address_helpers.h" 
#include <optional>

static httplib::Server g_explorerServer;

BlockExplorer::BlockExplorer(Blockchain* bc) : blockchain_(bc) {}

void BlockExplorer::startServer(int port) {
    g_explorerServer.Get("/api/stats", [&](const httplib::Request&, httplib::Response& res) {
        nlohmann::json j = {
            {"height", blockchain_->getBestTipHeight()},
            {"best_tip_hash", blockchain_->getBestTipHash()},
            {"difficulty", blockchain_->getDifficulty()},
            {"block_reward", blockchain_->getBlockReward()},
            {"mempool_size", blockchain_->mempool->getAllTransactions().size()},
            {"totalTransactions", blockchain_->getTotalTransactions()},
            {"activeAddresses", blockchain_->getActiveAddresses().size()},
            {"activeMiners", blockchain_->getActiveMiners().size()},
            {"issuedTokens", blockchain_->getIssuedTokens()}
        };
        res.set_content(j.dump(), "application/json");
    });

g_explorerServer.Get("/api/blocks", [&](const httplib::Request&, httplib::Response& res) {
    try {
        Logger::log("[Explorer /api/blocks] Fetching blocks, bestTipHeight: " + 
                    std::to_string(blockchain_->getBestTipHeight()));
        nlohmann::json j = nlohmann::json::array();
        int tipHeight = blockchain_->getBestTipHeight();
        if (tipHeight == 0) {
            res.set_content(j.dump(), "application/json");
            return;
        }
        int start = std::max(1, tipHeight - 9);
        for (int i = start; i <= tipHeight; ++i) {
            auto optionalB = blockchain_->getBlockByHeight(i);
            if (optionalB.has_value()) {
                Block b = optionalB.value();
                nlohmann::json blockJson = {
                    {"height", i},
                    {"hash", b.blockHash},
                    {"timestamp", b.header.timestamp}
                };
                j.push_back(blockJson);
            } else {
                Logger::log("[Explorer /api/blocks] Block not found for height " + std::to_string(i));
            }
        }
        res.set_content(j.dump(), "application/json");
    } catch (const std::exception& e) {
        Logger::log("[Explorer /api/blocks] Error: " + std::string(e.what()));
        res.status = 500;
        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
    }
});

    g_explorerServer.Get(R"(/block/([a-fA-F0-9]+))", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            std::string hash = req.matches[1];
            Logger::log("[Explorer /block] Request for hash: " + hash);
            auto it = blockchain_->blockIndex.find(hash);
            if (it == blockchain_->blockIndex.end()) {
                res.status = 404;
                res.set_content("{\"error\":\"Block not found\"}", "application/json");
                return;
            }
            const Block& b = it->second.block;
            int blockHeight = it->second.height;
            nlohmann::json blockJson = {
                {"height", blockHeight},
                {"hash", b.blockHash},
                {"prevHash", b.header.prevHash},
                {"merkleRoot", b.header.merkleRoot},
                {"timestamp", b.header.timestamp},
                {"nonce", b.header.nonce},
                {"transactions", nlohmann::json::array()}
            };
            for (const auto& tx : b.transactions) {
                blockJson["transactions"].push_back(tx.txid);
            }
            res.set_content(blockJson.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /block] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.Get("/api/addresses", [&](const httplib::Request&, httplib::Response& res) {
        try {
            std::shared_lock<std::shared_mutex> lock(blockchain_->mtx);
            std::unordered_map<std::string, uint64_t> addressBalances;
            blockchain_->utxoSet.iterateAll([&](const std::string& key, const std::string& val) {
                size_t colonPos = key.find(':');
                if (colonPos == std::string::npos || colonPos != 64 || key.size() <= 65 || !isValidHex(key.substr(0, 64))) {
                    return;
                }
                std::string txid = key.substr(0, colonPos);
                uint32_t vout = std::stoul(key.substr(colonPos + 1));
                size_t firstDelim = val.find('|');
                if (firstDelim == std::string::npos) return;
                size_t secondDelim = val.find('|', firstDelim + 1);
                if (secondDelim == std::string::npos) return;
                std::string amountStr = val.substr(firstDelim + 1, secondDelim - firstDelim - 1);
                std::string scriptStr = val.substr(secondDelim + 1);
                uint64_t atoms = std::stoull(amountStr);
                std::string address = ::extractAddressFromScriptPubKey(scriptStr, txid, vout, blockchain_);
                if (!address.empty()) {
                    addressBalances[address] += atoms;
                }
            });
            nlohmann::json j = nlohmann::json::array();
            for (const auto& [addr, atoms] : addressBalances) {
                double balance = static_cast<double>(atoms) / 100000000.0;
                j.push_back({{"address", addr}, {"balance", balance}});
            }
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/addresses] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.Get("/api/transactions", [&](const httplib::Request&, httplib::Response& res) {
        try {
            std::shared_lock<std::shared_mutex> lock(blockchain_->mtx);
            nlohmann::json j = nlohmann::json::array();
            if (!blockchain_->chain.empty()) {
                const Block& lastBlock = blockchain_->chain.back();
                for (const auto& tx : lastBlock.transactions) {
                    nlohmann::json txJson = {{"txid", tx.txid}};
                    txJson["vin"] = nlohmann::json::array();
                    for (const auto& vin : tx.vin) {
                        txJson["vin"].push_back({{"txid", vin.txid}, {"vout", vin.vout}});
                    }
                    txJson["vout"] = nlohmann::json::array();
                    for (const auto& vout : tx.vout) {
                        txJson["vout"].push_back({{"amount", vout.amount}});
                    }
                    j.push_back(txJson);
                }
            }
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/transactions] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.Get(R"(/api/address/(T[1-9A-HJ-NP-Za-km-z]{33}))", 
        [&](const httplib::Request& req, httplib::Response& res) {
        std::string address = req.matches[1];
        Logger::log("[Explorer /api/address] Fetching details for: " + address);
        try {
            double balance = blockchain_->calculate_balance(address);
            std::vector<std::string> transactions;
            {
                std::shared_lock<std::shared_mutex> lock(blockchain_->mtx);
                for (const auto& block : blockchain_->chain) {
                    for (const auto& tx : block.transactions) {
                        bool involvesAddress = false;
                        for (const auto& vout : tx.vout) {
                            std::string addr = ::extractAddressFromScriptPubKey(vout.scriptPubKey, tx.txid, 0, blockchain_);
                            if (addr == address) {
                                involvesAddress = true;
                                break;
                            }
                        }
                        if (!involvesAddress) {
                            for (const auto& vin : tx.vin) {
                                if (!vin.txid.empty() && vin.txid != "COINBASE") {
                                    Transaction prevTx;
                                    if (blockchain_->findTransaction(vin.txid, prevTx)) {
                                        for (const auto& prevVout : prevTx.vout) {
                                            std::string prevAddr = ::extractAddressFromScriptPubKey(
                                                prevVout.scriptPubKey, prevTx.txid, 0, blockchain_);
                                            if (prevAddr == address) {
                                                involvesAddress = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (involvesAddress) break;
                            }
                        }
                        if (involvesAddress) {
                            transactions.push_back(tx.txid);
                        }
                    }
                }
            }
            std::vector<nlohmann::json> tokens;
            blockchain_->utxoSet.iterateAll([&](const std::string& key, const std::string& val) {
                size_t secondDelim = val.find('|', val.find('|') + 1);
                if (secondDelim == std::string::npos) return;
                std::string script = val.substr(secondDelim + 1);
                ExtendedTokenData tokenData;
                std::string owner;
                std::string txid = key.substr(0, key.find(':'));
                if (::parseExtendedTokenScript(script, txid, tokenData, owner, blockchain_) && 
                    tokenData.type != TokenType::NONE && owner == address) {
                    nlohmann::json tk = {
                        {"tokenID", tokenData.tokenID},
                        {"type", ::tokenTypeToString(tokenData.type)},
                        {"amount", tokenData.amount}
                    };
                    tokens.push_back(tk);
                }
            });
            nlohmann::json j = {
                {"address", address},
                {"balance", balance},
                {"transactions", transactions},
                {"tokens", tokens}
            };
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/address] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.Get(R"(/api/transaction/([a-fA-F0-9]{64}))", [&](const httplib::Request& req, httplib::Response& res) {
        std::string txid = req.matches[1];
        Logger::log("[Explorer /api/transaction] Processing txid: " + txid);
        try {
            std::shared_lock<std::shared_mutex> lock(blockchain_->mtx);
            Transaction tx;
            if (!blockchain_->findTransaction(txid, tx)) {
                res.status = 404;
                res.set_content("{\"error\":\"Transaction not found\"}", "application/json");
                return;
            }
            nlohmann::json j = {
                {"txid", tx.txid},
                {"version", tx.version},
                {"lockTime", tx.lockTime},
                {"isCoinbase", tx.isCoinbase},
                {"vin", nlohmann::json::array()},
                {"vout", nlohmann::json::array()}
            };
            for (const auto& block : blockchain_->chain) {
                for (const auto& blockTx : block.transactions) {
                    if (blockTx.txid == txid) {
                        j["blockHash"] = block.blockHash;
                        j["blockHeight"] = block.height;
                        j["timestamp"], block.header.timestamp;
                        break;
                    }
                }
                if (j.contains("blockHash")) break;
            }
            for (const auto& vin : tx.vin) {
                nlohmann::json input = {
                    {"txid", vin.txid},
                    {"vout", vin.vout},
                    {"scriptSig", ::hexEncode(vin.scriptSig)},
                    {"sequence", vin.sequence}
                };
                if (!vin.pubKey.empty()) {
                    input["pubKey"] = ::hexEncode(vin.pubKey);
                }
                j["vin"].push_back(input);
            }
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                const TxOut& vout = tx.vout[i];
                nlohmann::json output = {
                    {"amount", vout.amount},
                    {"scriptPubKey", vout.scriptPubKey},
                    {"n", i}
                };
                std::string addr = ::extractAddressFromScriptPubKey(vout.scriptPubKey, tx.txid, static_cast<uint32_t>(i), blockchain_);
                if (!addr.empty()) {
                    output["address"] = addr;
                }
                ExtendedTokenData tokenData;
                std::string owner;
                if (::parseExtendedTokenScript(vout.scriptPubKey, tx.txid, tokenData, owner, blockchain_)) {
                    nlohmann::json tokenJson = {
                        {"type", ::tokenTypeToString(tokenData.type)},
                        {"tokenID", tokenData.tokenID},
                        {"amount", tokenData.amount},
                        {"owner", owner}
                    };
                    if (!tokenData.meta.data.empty()) {
                        tokenJson["meta"] = tokenData.meta.data;
                    }
                    output["tokenData"] = tokenJson;
                }
                j["vout"].push_back(output);
            }
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/transaction] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

g_explorerServer.Get("/api/tokens", [&](const httplib::Request&, httplib::Response& res) {
    Logger::log("[Explorer /api/tokens] Request received");
    try {
        std::unordered_map<std::string, std::pair<ExtendedTokenData, std::unordered_set<std::string>>> tokenMap;
        nlohmann::json j = nlohmann::json::array();
        blockchain_->utxoSet.iterateAll([&](const std::string& key, const std::string& val) {
            size_t firstDelim = val.find('|');
            if (firstDelim == std::string::npos) return;
            size_t secondDelim = val.find('|', firstDelim + 1);
            if (secondDelim == std::string::npos) return;
            std::string scriptStr = val.substr(secondDelim + 1);
            ExtendedTokenData token;
            std::string owner;
            std::string txid = key.substr(0, key.find(':'));
            if (!::parseExtendedTokenScript(scriptStr, txid, token, owner, blockchain_) || 
                token.type == TokenType::NONE) return;
            auto& entry = tokenMap[token.tokenID];
            auto& tokenData = entry.first;
            auto& owners = entry.second;
            if (tokenData.tokenID.empty()) {
                tokenData = token;
            } else {
                tokenData.amount += token.amount;
                for (const auto& item : token.meta.data.items()) {
                    tokenData.meta.data[item.key()] = item.value();
                }
            }
            owners.insert(owner);
        });
        for (const auto& [tokenID, entry] : tokenMap) {
            const auto& tokenData = entry.first;
            const auto& owners = entry.second;
            nlohmann::json tokenJson = {
                {"tokenID", tokenData.tokenID},
                {"type", ::tokenTypeToString(tokenData.type)},
                {"amount", tokenData.amount},
                {"owner", (owners.size() == 1 ? *owners.begin() : "Multiple (" + std::to_string(owners.size()) + ")")}
            };
            if (!tokenData.meta.data.is_null() && !tokenData.meta.data.empty()) {
                tokenJson["meta"] = tokenData.meta.data;
            }
            if (!tokenData.offChainMetadata.empty()) {
                tokenJson["offChainMetadata"] = tokenData.offChainMetadata;
            }
            if (!tokenData.metadataSignature.empty()) {
                tokenJson["metadataSignature"] = tokenData.metadataSignature;
            }
            j.push_back(tokenJson);
        }
        res.set_content(j.dump(), "application/json");
    } catch (const std::exception& e) {
        Logger::log("[Explorer /api/tokens] Error: " + std::string(e.what()));
        res.status = 500;
        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
    }
});

    g_explorerServer.Get("/api/contracts", [&](const httplib::Request&, httplib::Response& res) {
        try {
            std::unordered_set<std::string> contractIdentifiers;
            blockchain_->utxoSet.iterateAll([&](const std::string& key, const std::string& val) {
                size_t lastDelim = val.find_last_of('|');
                if (lastDelim == std::string::npos) return;
                std::string scriptPubKey = val.substr(lastDelim + 1);
                if (blockchain_->isSmartContractScript(scriptPubKey)) {
                    contractIdentifiers.insert(key);
                }
            });
            nlohmann::json j = nlohmann::json::array();
            for (const auto& identifier : contractIdentifiers) {
                j.push_back({{"identifier", identifier}});
            }
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/contracts] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.Get("/api/miners", [&](const httplib::Request&, httplib::Response& res) {
        try {
            std::shared_lock<std::shared_mutex> lock(blockchain_->mtx);
            auto now = std::chrono::steady_clock::now();
            nlohmann::json j = nlohmann::json::array();
            for (const auto& [minerAddr, lastActivity] : blockchain_->minerLastActivity) {
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - lastActivity).count();
                if (duration < 300) {
                    double hashRate = blockchain_->minerHashRates.count(minerAddr) ? 
                                      blockchain_->minerHashRates.at(minerAddr) : 0.0;
                    uint64_t blocksMined = blockchain_->minerBlockCount.count(minerAddr) ? 
                                           blockchain_->minerBlockCount.at(minerAddr) : 0;
                    j.push_back({
                        {"address", minerAddr},
                        {"hashRate", hashRate},
                        {"blocksMined", blocksMined}
                    });
                }
            }
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            Logger::log("[Explorer /api/miners] Error: " + std::string(e.what()));
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json"); // FIX: safe JSON escaping
        }
    });

    g_explorerServer.set_mount_point("/", "../web");
    std::cout << "Starting Block Explorer Server: 0.0.0.0, Port: " << port << std::endl;
    g_explorerServer.listen("0.0.0.0", port);
}
