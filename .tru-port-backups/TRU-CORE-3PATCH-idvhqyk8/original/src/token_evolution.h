#pragma once

#include "ai_provider_interface.h"
#include "contract_storage.h"

#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>

struct TokenEvolutionResult {
    bool ok{false};
    std::string error;
    nlohmann::json metadata = nlohmann::json::object();
    nlohmann::json record = nlohmann::json::object();
};

class TokenEvolutionEngine {
public:
    explicit TokenEvolutionEngine(ContractStorage* storage);

    nlohmann::json normalizeMetadata(
        const std::string& tokenType,
        const nlohmann::json& currentMetadata,
        const std::string& providerName
    ) const;

    TokenEvolutionResult evolvePreview(
        const std::string& tokenID,
        const std::string& tokenType,
        const nlohmann::json& currentMetadata,
        const std::string& providerName,
        const std::string& trigger
    );

    bool persistPreview(const nlohmann::json& record);

    // TOKEN-AI-02C: verify the complete persisted epoch chain, the root
    // metadata hash, anchor queue state, prepared transactions and durable
    // anchor receipts without calling an AI provider or mutating storage.
    nlohmann::json verifyHistory(
        const std::string& tokenID,
        const nlohmann::json& issuanceMetadata
    ) const;

    nlohmann::json loadLatest(const std::string& tokenID) const;

private:
    ContractStorage* storage_{nullptr};

    static std::string sha256Hex(const std::string& data);
    static std::string extractProviderText(const nlohmann::json& response);
    static nlohmann::json parseJsonObject(const std::string& text);
    static nlohmann::json filterAllowedUpdates(
        const std::string& tokenType,
        const nlohmann::json& proposed
    );
    static uint64_t parseEpoch(const nlohmann::json& meta);

    // TOKEN-AI-03A2: canonical logical-request provenance.
    // The request hash commits to the structured request handed to the
    // provider adapter, not provider-specific HTTP/wire serialization.
    static std::string evolutionSystemPrompt();
    static void appendU32BE(std::string& out, uint32_t value);
    static void appendU64BE(std::string& out, uint64_t value);
    static void appendLengthPrefixed(std::string& out, const std::string& value);
    std::string canonicalRequestHashV1(
        const std::string& tokenID,
        const std::string& tokenType,
        uint64_t epochBefore,
        const std::string& providerName,
        const std::string& providerVersion,
        const std::string& modelID,
        const std::string& trigger,
        const std::string& inputMetadataHash,
        const std::string& systemPrompt,
        const std::string& userPrompt,
        uint64_t maxTokens,
        uint64_t temperatureMillis
    ) const;

    std::string buildPrompt(
        const std::string& tokenID,
        const std::string& tokenType,
        const nlohmann::json& normalizedMetadata,
        const std::string& trigger
    ) const;
};
