// main_ai_integration.cpp
#include "blockchain.h"
#include "ai_oracle_service.h"
#include "contract_storage.h"
#include "logging.h"
#include "block.h"
#include "opcodes.h"
#include "utils.h"
#include <memory>
#include <thread>
#include <vector>
#include <cstdint>

class TRUBlockchainAISystem {
private:
    Blockchain* blockchain;  // Changed to raw pointer
    std::shared_ptr<ConfigurableAIOracle> oracle;
    std::unique_ptr<ContractStorage> contractStorage;
    std::thread oracleThread;

public:
    TRUBlockchainAISystem(Blockchain* chain) : blockchain(chain) {}

    ~TRUBlockchainAISystem() {
        if (oracle) oracle->stopMonitoring();
        if (oracleThread.joinable()) oracleThread.join();
        oracle.reset();
        contractStorage.reset();
    }
    
    void initialize() {
        Logger::log("[AI System] Initializing TRU Blockchain AI System");
        
        // Initialize storage with explicit lifetime ownership.
        LevelDBStorage* storage = blockchain->getStorage();
        contractStorage = std::make_unique<ContractStorage>(storage);

        oracle = std::make_shared<ConfigurableAIOracle>(
            blockchain,
            contractStorage.get());

        // No detached thread may outlive Blockchain/LevelDB-backed state.
        oracleThread = std::thread([this]() {
            oracle->startMonitoring();
        });

        Logger::log("[AI System] AI System initialized with Oobabooga as default");
    }
    
    void deployAIContracts() {
        // Deploy main AI router contract
        deployAIRouterContract();
        
        // Deploy provider registry contract
        deployProviderRegistryContract();
        
        Logger::log("[AI System] AI contracts deployed");
    }
    
private:
    void deployAIRouterContract() {
        std::vector<uint8_t> script;
        
        // Helper to push data
        auto pushData = [&script](const std::string& data) {
            if (data.size() < 76) {
                script.push_back(data.size());
                script.insert(script.end(), data.begin(), data.end());
            }
        };
        
        // Router logic to handle AI requests
        pushData("AI_ROUTER_v2");
        script.push_back(OP_STORE);
        
        // Check if caller is AI-enabled token
        script.push_back(OP_CALLER);
        pushData("ai_tokens:");
        script.push_back(OP_SWAP);
        script.push_back(OP_CAT);
        script.push_back(OP_LOAD);
        
        script.push_back(OP_IF);
            // AI routing is off-chain and must never invoke the
            // deterministic consensus OP_DATAFEED namespace. Legacy router
            // execution therefore fails closed instead of fabricating a feed.
            pushData("ROUTE_AI_REQUEST_OFFCHAIN");
            script.push_back(OP_REVERT);
        script.push_back(OP_ELSE);
            script.push_back(OP_REVERT);
        script.push_back(OP_ENDIF);
        
        Transaction tx(false);
        tx.vout.emplace_back(0, bytesToHex(script));
        blockchain->mempool->addTransaction(tx);
    }
    
    void deployProviderRegistryContract() {
        std::vector<uint8_t> script;
        
        auto pushData = [&script](const std::string& data) {
            if (data.size() < 76) {
                script.push_back(data.size());
                script.insert(script.end(), data.begin(), data.end());
            }
        };
        
        // Registry to track available providers
        pushData("PROVIDER_REGISTRY_v2");
        script.push_back(OP_STORE);
        
        // Store default provider
        pushData("default_provider");
        pushData("oobabooga");
        script.push_back(OP_STORE);
        
        Transaction tx(false);
        tx.vout.emplace_back(0, bytesToHex(script));
        blockchain->mempool->addTransaction(tx);
    }
};
