// ai_oracle_service.h
#pragma once
#include "ai_provider_interface.h"
#include "blockchain.h"
#include "wallet.h"
#include "contract_storage.h"
#include <memory>
#include <thread>
#include <atomic>  // FIX: atomic running flag
#include <string>
#include <nlohmann/json.hpp>

using nlohmann::json;
class Blockchain;

// declaration now matches the implementation in
// ai_oracle_service.cpp. Oracle funding credentials are loaded internally
// from tru.conf by writeAIResponseOnChain().
bool writeAIResponseOnChain(
    Blockchain& chain,
    const std::string& requestID,
    const std::string& providerName,
    const std::string& content,            // AI text/content
    std::string& outTxid                   // filled with txid if broadcast
);

// signed on-chain commitment for a living-token evolution.
// Full metadata remains in TOKEN_EVOLUTION storage; hashes/provenance are
// committed to OP_RETURN.
bool writeTokenEvolutionOnChain(
    Blockchain& chain,
    const nlohmann::json& evolutionRecord,
    std::string& outTxid
);

// TOKEN-AI-02D: read-only runtime proof helper. It recomputes the
// transaction ID and validates that the committed OP_RETURN is exactly the
// canonical TRU_EVOLVE_V1 payload for the supplied persisted epoch record.
bool verifyTokenEvolutionAnchorTransaction(
    const Transaction& tx,
    const nlohmann::json& evolutionRecord,
    const std::string& expectedTxid,
    std::string& reason
);

class ConfigurableAIOracle {
public:
    // Change constructor to accept Blockchain* instead of shared_ptr
    ConfigurableAIOracle(
        Blockchain* chain,
        ContractStorage* stor,
        Wallet* authenticatedSigningWallet = nullptr);
    
    void initializeProviders();
    void loadUserConfigurations();
    std::string configureProvider(const std::string& userAddress, 
                                 const std::string& providerName,
                                 const nlohmann::json& config);
    std::shared_ptr<IAIProvider> getProviderForUser(const std::string& userAddress);
    void processAIRequest(const std::string& requestID);

    // retryable queue -> signed evolution anchor processor.
    void processTokenEvolutionAnchorQueue();

    // provider-agnostic manual SFT/NCFT evolution preview.
    // Produces/persists a TRU_TOKEN_EVOLVE_V1 preview only.
    // It does NOT modify balances/ownership/supply and does NOT broadcast.
    nlohmann::json evolveTokenManually(
        const std::string& tokenID,
        const std::string& tokenType,
        const nlohmann::json& currentMetadata,
        const std::string& providerName,
        const std::string& trigger = "manual"
    );

    void startMonitoring();
    void stopMonitoring();
    
    ContractStorage* storage;  // Made public for RPC handlers
    
private:
    Blockchain* blockchain;  // Changed from shared_ptr to raw pointer
    // SEC-14R.5: non-owning pointer to the core wallet authenticated by main.
    // Main owns this Wallet; RPC/oracle shutdown joins the worker before the
    // Wallet leaves main's scope.
    Wallet* authenticatedSigningWallet{nullptr};
    std::shared_ptr<IAIProvider> currentProvider;
    std::map<std::string, nlohmann::json> userProviderConfigs;
    std::atomic<bool> running{true};  // FIX(race): read from monitor thread, set from another
    
    std::string buildSystemPrompt(const std::string& tokenID, const std::string& provider);
    std::string buildEnhancedSystemPrompt(const std::string& tokenID, const nlohmann::json& metadata);
    void processAIResponse(const std::string& requestID, 
                          const nlohmann::json& response,
                          const std::string& providerUsed);
    void processEnhancedAIResponse(const std::string& requestID,
                                   const nlohmann::json& response,
                                   const std::string& tokenID,
                                   const std::string& providerUsed);
    // legacy OP_DATAFEED-based response transaction builder removed.
    std::vector<std::string> scanForRequests();
};

// Global initialization function
void initializeAIOracle(Blockchain& chain, Wallet* authenticatedSigningWallet = nullptr);
void shutdownAIOracle();

// Helper functions
std::string generateRandomHex(size_t bytes);
