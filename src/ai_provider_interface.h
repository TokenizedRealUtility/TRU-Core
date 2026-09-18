// ai_provider_interface.h
#pragma once
#include <string>
#include <memory>
#include <nlohmann/json.hpp>
#include <map>
#include <vector>

enum class AIProvider {
    OOBABOOGA,      // Default - local
    OPENAI,         // ChatGPT
    ANTHROPIC,      // Claude
    GROK,           // X.AI Grok
    OLLAMA,         // Ollama local
    NEMOTRON,       // Local/custom Nemotron OpenAI-compatible harness
    GEMINI,         // Google Gemini
    CUSTOM          // User-defined endpoint
};

class IAIProvider {
public:
    virtual ~IAIProvider() = default;
    virtual std::string getName() const = 0;
    // TOKEN-AI-03A2: provenance descriptors. provider_version identifies
    // the TRU adapter/request-mapping contract, not a remote service release.
    // model_id is empty when the adapter cannot determine it.
    virtual std::string getProviderVersion() const {
        return "TRU_AI_PROVIDER_ADAPTER_V1";
    }
    virtual std::string getModelId() const { return ""; }
    virtual nlohmann::json sendRequest(const nlohmann::json& request) = 0;
    virtual void configure(const nlohmann::json& config) = 0;
    virtual bool isConfigured() const = 0;
    virtual std::string getEndpoint() const = 0;
};

// Provider factory and registry
class AIProviderRegistry {
private:
    std::map<std::string, std::shared_ptr<IAIProvider>> providers;
    std::string defaultProvider = "oobabooga";
    
public:
    static AIProviderRegistry& getInstance() {
        static AIProviderRegistry instance;
        return instance;
    }
    
    void registerProvider(const std::string& name, std::shared_ptr<IAIProvider> provider) {
        providers[name] = provider;
    }
    
    std::shared_ptr<IAIProvider> getProvider(const std::string& name = "") {
        if (name.empty()) return providers[defaultProvider];
        auto it = providers.find(name);
        return (it != providers.end()) ? it->second : providers[defaultProvider];
    }
    
    std::vector<std::string> getAvailableProviders() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : providers) {
            names.push_back(name);
        }
        return names;
    }
};
