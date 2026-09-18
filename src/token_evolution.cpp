#include "token_evolution.h"

#include "ai_provider_interface.h"
#include "logging.h"
#include "vah_capabilities.h"

#include <openssl/sha.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

using nlohmann::json;

namespace {
constexpr std::size_t TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS = 256U;
constexpr std::size_t TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES = 65536U;
constexpr std::size_t TOKEN_EVOLUTION_MAX_QUEUE_ITEM_BYTES = 64U;
constexpr uint64_t TOKEN_EVOLUTION_MAX_VERIFY_EPOCHS = 100000U;

bool isLowerHex(const std::string& value, std::size_t expectedSize) {
    if (value.size() != expectedSize) return false;
    return std::all_of(
        value.begin(), value.end(),
        [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

bool isCanonicalEvolutionTokenID(const std::string& tokenID) {
    return isLowerHex(tokenID, 8U) || isLowerHex(tokenID, 16U);
}

void appendU32BEBytes(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

void appendU64BEBytes(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
    }
}

void appendLPBytes(std::vector<unsigned char>& out, const std::string& value) {
    appendU32BEBytes(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::string sha256BytesHex(const std::vector<unsigned char>& bytes) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes.data(), bytes.size(), hash);
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2U);
    for (unsigned char b : hash) {
        out.push_back(HEX[(b >> 4U) & 0x0fU]);
        out.push_back(HEX[b & 0x0fU]);
    }
    return out;
}

bool decodeLowerHex(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.empty() || (hex.size() % 2U) != 0U) return false;
    out.clear();
    out.reserve(hex.size() / 2U);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string deriveExternalWriterIdV1(const std::string& writerPubKeyHex) {
    std::vector<unsigned char> pubkey;
    if (!decodeLowerHex(writerPubKeyHex, pubkey) || pubkey.size() != 33U ||
        (pubkey[0] != 0x02U && pubkey[0] != 0x03U)) {
        return {};
    }
    std::vector<unsigned char> preimage;
    const std::string domain = "TRU_VAH_WRITER_ID_V1";
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BEBytes(preimage, static_cast<std::uint32_t>(pubkey.size()));
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    return sha256BytesHex(preimage);
}

std::string externalClaimDigestHexV1(
    const std::string& tokenID,
    const std::string& tokenType,
    std::uint64_t epoch,
    const std::string& previousMetadataHash,
    const std::string& newMetadataHash,
    const std::string& writerPubKeyHex,
    const std::string& writerID,
    const std::string& writerType,
    const std::vector<std::string>& changedFields)
{
    std::vector<unsigned char> preimage;
    const std::string domain = "TRU_VAH_EXTERNAL_WRITER_CLAIM_V1";
    preimage.insert(preimage.end(), domain.begin(), domain.end());
    appendU32BEBytes(preimage, 1U);
    appendLPBytes(preimage, tokenID);
    appendLPBytes(preimage, tokenType);
    appendU64BEBytes(preimage, epoch);
    appendLPBytes(preimage, previousMetadataHash);
    appendLPBytes(preimage, newMetadataHash);
    appendLPBytes(preimage, writerPubKeyHex);
    appendLPBytes(preimage, writerID);
    appendLPBytes(preimage, writerType);
    appendU32BEBytes(preimage, static_cast<std::uint32_t>(changedFields.size()));
    for (const auto& field : changedFields) appendLPBytes(preimage, field);
    return sha256BytesHex(preimage);
}

bool parseEvolutionQueueItem(
    const std::string& item,
    std::string& tokenID,
    uint64_t& epoch)
{
    if (item.empty() || item.size() > TOKEN_EVOLUTION_MAX_QUEUE_ITEM_BYTES) {
        return false;
    }

    const auto pos = item.rfind(':');
    if (pos == std::string::npos || pos == 0U || pos + 1U >= item.size()) {
        return false;
    }

    tokenID = item.substr(0, pos);
    const std::string epochText = item.substr(pos + 1U);

    if (!isCanonicalEvolutionTokenID(tokenID) ||
        !std::all_of(epochText.begin(), epochText.end(),
            [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return false;
    }

    try {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(epochText, &consumed, 10);
        if (consumed != epochText.size() || parsed == 0ULL) return false;
        epoch = static_cast<uint64_t>(parsed);
    } catch (...) {
        return false;
    }

    return true;
}
}

TokenEvolutionEngine::TokenEvolutionEngine(ContractStorage* storage)
    : storage_(storage) {}

std::string TokenEvolutionEngine::sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()),
           data.size(),
           hash);

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char b : hash) {
        out << std::setw(2) << static_cast<unsigned int>(b);
    }
    return out.str();
}

std::string TokenEvolutionEngine::evolutionSystemPrompt() {
    return
        "You are a constrained TRU token-evolution engine. "
        "Follow the requested JSON schema exactly and never modify "
        "financial, ownership, authorization, or consensus fields.";
}

void TokenEvolutionEngine::appendU32BE(std::string& out, uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xffU));
    out.push_back(static_cast<char>((value >> 16) & 0xffU));
    out.push_back(static_cast<char>((value >> 8) & 0xffU));
    out.push_back(static_cast<char>(value & 0xffU));
}

void TokenEvolutionEngine::appendU64BE(std::string& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xffULL));
    }
}

void TokenEvolutionEngine::appendLengthPrefixed(
    std::string& out,
    const std::string& value)
{
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::length_error("TRU evolution request field exceeds uint32 length");
    }
    appendU32BE(out, static_cast<uint32_t>(value.size()));
    out.append(value);
}

std::string TokenEvolutionEngine::canonicalRequestHashV1(
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
) const {
    // TRU_EVOLUTION_REQUEST_V1 canonical field order is part of the wire-
    // independent provenance specification. Do not derive this from struct
    // member order or JSON key order.
    std::string canonical;
    canonical.reserve(
        256U + tokenID.size() + tokenType.size() + providerName.size() +
        providerVersion.size() + modelID.size() + trigger.size() +
        inputMetadataHash.size() + systemPrompt.size() + userPrompt.size());

    // 1. domain/version tag
    appendLengthPrefixed(canonical, "TRU_EVOLUTION_REQUEST_V1");
    // 2. writer_type
    appendLengthPrefixed(canonical, "ai");
    // 3. token_id
    appendLengthPrefixed(canonical, tokenID);
    // 4. token_type
    appendLengthPrefixed(canonical, tokenType);
    // 5. epoch_before
    appendU64BE(canonical, epochBefore);
    // 6. provider
    appendLengthPrefixed(canonical, providerName);
    // 7. provider_version (zero-length when unavailable is forbidden here:
    //    every V1 provider adapter supplies its TRU adapter version)
    appendLengthPrefixed(canonical, providerVersion);
    // 8. model_id (zero-length means unavailable/unknown)
    appendLengthPrefixed(canonical, modelID);
    // 9. trigger
    appendLengthPrefixed(canonical, trigger);
    // 10. input_metadata_hash
    appendLengthPrefixed(canonical, inputMetadataHash);
    // 11. exact logical system prompt handed to provider adapter
    appendLengthPrefixed(canonical, systemPrompt);
    // 12. exact logical user prompt handed to provider adapter
    appendLengthPrefixed(canonical, userPrompt);
    // 13. max_tokens
    appendU64BE(canonical, maxTokens);
    // 14. temperature in thousandths (0.400 => 400)
    appendU64BE(canonical, temperatureMillis);

    return sha256Hex(canonical);
}

uint64_t TokenEvolutionEngine::parseEpoch(const json& meta) {
    try {
        if (!meta.contains("evolution_epoch")) return 0;
        const auto& v = meta["evolution_epoch"];

        if (v.is_number_unsigned()) return v.get<uint64_t>();
        if (v.is_number_integer()) {
            const auto n = v.get<int64_t>();
            return n < 0 ? 0 : static_cast<uint64_t>(n);
        }
        if (v.is_string()) {
            return static_cast<uint64_t>(std::stoull(v.get<std::string>()));
        }
    } catch (...) {
    }
    return 0;
}

json TokenEvolutionEngine::normalizeMetadata(
    const std::string& tokenType,
    const json& currentMetadata,
    const std::string& providerName
) const {
    json meta = currentMetadata.is_object()
        ? currentMetadata
        : json::object();

    if (tokenType == "SFT") {
        if (!meta.contains("ai_engine"))         meta["ai_engine"] = providerName;
        if (!meta.contains("ai_version"))        meta["ai_version"] = "1.0";
        if (!meta.contains("learning_mode"))     meta["learning_mode"] = "on-chain usage patterns";
        if (!meta.contains("growth_algorithm")) meta["growth_algorithm"] = "neural-adaptive";
        if (!meta.contains("adaptation_rate"))   meta["adaptation_rate"] = "0.05";
        if (!meta.contains("description_ai"))    meta["description_ai"] = "";
        if (!meta.contains("self_evolution"))    meta["self_evolution"] = "enabled";
        if (!meta.contains("last_evolution"))    meta["last_evolution"] = "None";
    } else if (tokenType == "NCFT") {
        if (!meta.contains("ai_engine"))          meta["ai_engine"] = providerName;
        if (!meta.contains("style_descriptor"))  meta["style_descriptor"] = "adaptive generative art";
        if (!meta.contains("dynamic_morph"))      meta["dynamic_morph"] = "manual evolution";
        if (!meta.contains("update_interval"))    meta["update_interval"] = "manual";
        if (!meta.contains("creator_signature")) meta["creator_signature"] = "";
        if (!meta.contains("description_ai"))     meta["description_ai"] = "";
        if (!meta.contains("self_evolution"))     meta["self_evolution"] = "enabled";
        if (!meta.contains("last_evolution"))     meta["last_evolution"] = "None";
    }

    meta["evolution_epoch"] = std::to_string(parseEpoch(meta));
    return meta;
}

std::string TokenEvolutionEngine::buildPrompt(
    const std::string& tokenID,
    const std::string& tokenType,
    const json& normalizedMetadata,
    const std::string& trigger
) const {
    std::ostringstream p;

    p << "You are evolving a TRU blockchain " << tokenType << " token.\n"
      << "Return ONLY one valid JSON object. No markdown and no explanation.\n"
      << "Token ID: " << tokenID << "\n"
      << "Evolution trigger: " << trigger << "\n"
      << "Current metadata:\n" << normalizedMetadata.dump(2) << "\n\n";

    if (tokenType == "SFT") {
        p << "You MAY return only these mutable keys:\n"
          << "description_ai, learning_mode, growth_algorithm, adaptation_rate, "
          << "ai_version.\n";
    } else {
        p << "You MAY return only these mutable keys:\n"
          << "description_ai, style_descriptor, dynamic_morph, "
          << "update_interval.\n";
    }

    p << "Never output or modify balances, amount, totalSupply, supply, owner, "
      << "ownership, tokenID, decimals, fee, script, spend rules, private keys, "
      << "oracle keys, consensus parameters, or evolution_epoch.\n"
      << "Keep values concise and deterministic enough to persist as token metadata.";

    return p.str();
}

std::string TokenEvolutionEngine::extractProviderText(const json& response) {
    if (response.contains("choices") &&
        response["choices"].is_array() &&
        !response["choices"].empty()) {
        try {
            return response["choices"][0]["message"]["content"].get<std::string>();
        } catch (...) {}
    }

    if (response.contains("content") && response["content"].is_array()) {
        std::string out;
        for (const auto& block : response["content"]) {
            if (block.is_object() &&
                block.value("type", "") == "text" &&
                block.contains("text") &&
                block["text"].is_string()) {
                if (!out.empty()) out.push_back(char(10));
                out += block["text"].get<std::string>();
            }
        }
        if (!out.empty()) return out;
    }

    if (response.contains("message") &&
        response["message"].is_object() &&
        response["message"].contains("content") &&
        response["message"]["content"].is_string()) {
        return response["message"]["content"].get<std::string>();
    }

    if (response.contains("response") && response["response"].is_string()) {
        return response["response"].get<std::string>();
    }

    if (response.contains("candidates") &&
        response["candidates"].is_array() &&
        !response["candidates"].empty()) {
        try {
            const auto& parts = response["candidates"][0]["content"]["parts"];
            std::string out;
            if (parts.is_array()) {
                for (const auto& part : parts) {
                    if (part.is_object() &&
                        part.contains("text") &&
                        part["text"].is_string()) {
                        if (!out.empty()) out.push_back(char(10));
                        out += part["text"].get<std::string>();
                    }
                }
            }
            if (!out.empty()) return out;
        } catch (...) {}
    }

    if (response.contains("content") && response["content"].is_string()) {
        return response["content"].get<std::string>();
    }

    return response.dump();
}

json TokenEvolutionEngine::parseJsonObject(const std::string& input) {
    std::string text = input;

    const std::string jsonFence = "```json";
    const std::string anyFence = "```";

    auto start = text.find(jsonFence);
    if (start != std::string::npos) {
        text = text.substr(start + jsonFence.size());
        auto end = text.find(anyFence);
        if (end != std::string::npos) text = text.substr(0, end);
    } else {
        start = text.find(anyFence);
        if (start != std::string::npos) {
            text = text.substr(start + anyFence.size());
            auto end = text.find(anyFence);
            if (end != std::string::npos) text = text.substr(0, end);
        }
    }

    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), notSpace));
    text.erase(std::find_if(text.rbegin(), text.rend(), notSpace).base(), text.end());

    try {
        json parsed = json::parse(text);
        return parsed.is_object() ? parsed : json::object();
    } catch (...) {
        auto first = text.find('{');
        auto last = text.rfind('}');
        if (first != std::string::npos &&
            last != std::string::npos &&
            last > first) {
            try {
                json parsed = json::parse(text.substr(first, last - first + 1));
                return parsed.is_object() ? parsed : json::object();
            } catch (...) {}
        }
    }

    return json::object();
}

json TokenEvolutionEngine::filterAllowedUpdates(
    const std::string& tokenType,
    const json& proposed
) {
    json filtered = json::object();

    if (!proposed.is_object()) return filtered;

    for (auto it = proposed.begin(); it != proposed.end(); ++it) {
        // VAH-01ABC: route the existing V1 AI allowlist through the typed
        // capability registry.  This does not activate any staged VAH fields
        // or any non-AI writer class.
        if (!VAHCapabilities::isEvolutionFieldCurrentlyWritable(
                tokenType, "ai", it.key())) {
            continue;
        }

        if (it.value().is_string()) {
            filtered[it.key()] = it.value();
        } else if (it.value().is_number() || it.value().is_boolean()) {
            filtered[it.key()] = it.value().dump();
        }
    }

    return filtered;
}

TokenEvolutionResult TokenEvolutionEngine::evolvePreview(
    const std::string& tokenID,
    const std::string& tokenType,
    const json& currentMetadata,
    const std::string& providerName,
    const std::string& trigger
) {
    TokenEvolutionResult result;

    if (tokenType != "SFT" && tokenType != "NCFT") {
        result.error = "Evolution is limited to SFT and NCFT";
        return result;
    }
    if (tokenID.empty()) {
        result.error = "tokenID is required";
        return result;
    }
    if (providerName.empty()) {
        result.error = "providerName is required";
        return result;
    }

    auto provider = AIProviderRegistry::getInstance().getProvider(providerName);
    if (!provider) {
        result.error = "Unknown AI provider: " + providerName;
        return result;
    }

    // FIX(TOKEN-AI-02D2): persisted TOKEN_EVOLUTION state owns the epoch
    // counter. Issuance metadata is descriptive input only and may contain a
    // user-supplied evolution_epoch field; that field must never advance the
    // local provenance chain before epoch 1 actually exists.
    json baseMetadata = currentMetadata;

    json latest = loadLatest(tokenID);
    if (!latest.empty()) {
        if (!latest.contains("metadata") || !latest["metadata"].is_object()) {
            result.error = "Latest evolution record is missing metadata";
            return result;
        }

        const json& latestMetadata = latest["metadata"];
        const std::string actualLatestHash = sha256Hex(latestMetadata.dump());
        const std::string recordedLatestHash = latest.value("new_metadata_hash", "");

        if (recordedLatestHash.empty() || actualLatestHash != recordedLatestHash) {
            result.error =
                "Latest evolution metadata hash mismatch; refusing to continue";
            return result;
        }

        uint64_t persistedEpoch = 0;
        try {
            persistedEpoch = latest.at("epoch_after").get<uint64_t>();
        } catch (...) {
            result.error = "Latest evolution record has invalid epoch_after";
            return result;
        }

        if (parseEpoch(latestMetadata) != persistedEpoch) {
            result.error =
                "Latest evolution epoch mismatch between record and metadata";
            return result;
        }

        baseMetadata = latestMetadata;

        Logger::log(
            "[TokenEvolution] Continuing token=" + tokenID +
            " from persisted epoch=" + std::to_string(persistedEpoch)
        );
    } else {
        // Root state is always epoch 0 regardless of any descriptive/custom
        // evolution_epoch value embedded in the issuance metadata.
        baseMetadata["evolution_epoch"] = "0";
        Logger::log(
            "[TokenEvolution] Starting persisted history for token=" +
            tokenID + " from canonical issuance root epoch=0"
        );
    }

    json normalized =
        normalizeMetadata(tokenType, baseMetadata, providerName);

    const uint64_t oldEpoch = parseEpoch(normalized);
    const uint64_t newEpoch = oldEpoch + 1;

    // TOKEN-AI-03A2: freeze the logical request provenance before the
    // provider call. This commits to the exact structured request handed to
    // the provider adapter. Provider-specific HTTP/wire transformations are
    // intentionally outside TRU_EVOLUTION_REQUEST_V1.
    const std::string effectiveTrigger =
        trigger.empty() ? "manual" : trigger;
    const std::string providerVersion = provider->getProviderVersion();
    const std::string modelID = provider->getModelId();
    const std::string inputMetadataHash = sha256Hex(normalized.dump());
    const std::string systemPrompt = evolutionSystemPrompt();
    const std::string userPrompt =
        buildPrompt(tokenID, tokenType, normalized, effectiveTrigger);
    constexpr uint64_t requestMaxTokens = 500U;
    constexpr uint64_t requestTemperatureMillis = 400U;

    if (providerVersion.empty()) {
        result.error = "AI provider adapter version is unavailable";
        return result;
    }

    const std::string requestHash = canonicalRequestHashV1(
        tokenID,
        tokenType,
        oldEpoch,
        providerName,
        providerVersion,
        modelID,
        effectiveTrigger,
        inputMetadataHash,
        systemPrompt,
        userPrompt,
        requestMaxTokens,
        requestTemperatureMillis
    );

    json aiRequest = {
        {"messages", {
            {
                {"role", "system"},
                {"content", systemPrompt}
            },
            {
                {"role", "user"},
                {"content", userPrompt}
            }
        }},
        {"max_tokens", requestMaxTokens},
        {"temperature",
            static_cast<double>(requestTemperatureMillis) / 1000.0}
    };

    Logger::log("[TokenEvolution] Requesting manual preview for " +
                tokenID + " via provider=" + providerName);

    json response = provider->sendRequest(aiRequest);

    if (response.contains("error")) {
        try {
            result.error = response["error"].is_string()
                ? response["error"].get<std::string>()
                : response["error"].dump();
        } catch (...) {
            result.error = "AI provider returned an error";
        }
        return result;
    }

    const std::string providerText = extractProviderText(response);
    const json proposed = parseJsonObject(providerText);
    const json updates = filterAllowedUpdates(tokenType, proposed);

    if (updates.empty()) {
        result.error =
            "Provider response did not contain valid allow-listed evolution fields";
        return result;
    }

    // TOKEN-AI-03A1: refuse provenance-noise epochs.  The no-op decision is
    // made AFTER allow-list filtering and AFTER merging the permitted values,
    // but BEFORE TRU adds provenance-only epoch/timestamp fields.  Counting
    // keys is insufficient because a provider may return an allowed key with
    // the value it already has.
    json evolved = normalized;
    for (auto it = updates.begin(); it != updates.end(); ++it) {
        evolved[it.key()] = it.value();
    }

    if (sha256Hex(evolved.dump()) == sha256Hex(normalized.dump())) {
        result.error =
            "AI proposed no permitted metadata changes; nothing committed.";
        return result;
    }

    evolved["ai_engine"] = providerName;
    evolved["evolution_epoch"] = std::to_string(newEpoch);

    // provenance time is set by TRU, not by the AI model.
    const uint64_t evolutionTimestamp =
        static_cast<uint64_t>(std::time(nullptr));

    evolved["last_evolution"] =
        "unix:" + std::to_string(evolutionTimestamp) +
        ";epoch:" + std::to_string(newEpoch);

    const std::string previousHash = sha256Hex(normalized.dump());
    const std::string newHash = sha256Hex(evolved.dump());

    json record = {
        // The anchor payload protocol remains TRU_TOKEN_EVOLVE_V1 for
        // backwards compatibility. record_format_version versions the durable
        // evolution record schema independently.
        {"format", "TRU_TOKEN_EVOLVE_V1"},
        {"record_format_version", 2U},
        {"status", "preview"},
        {"tokenID", tokenID},
        {"type", tokenType},
        {"writer_type", "ai"},
        {"provider", providerName},
        {"provider_version", providerVersion},
        {"model_id", modelID},
        {"request_hash", requestHash},
        {"input_metadata_hash", inputMetadataHash},
        {"trigger", effectiveTrigger},
        {"epoch_before", oldEpoch},
        {"epoch_after", newEpoch},
        {"previous_metadata_hash", previousHash},
        {"new_metadata_hash", newHash},
        {"timestamp", evolutionTimestamp},
        {"updated_fields", updates},
        {"metadata", evolved}
    };

    result.ok = true;
    result.metadata = evolved;
    result.record = record;
    return result;
}

bool TokenEvolutionEngine::persistPreview(const json& record) {
    if (!storage_ || !record.is_object()) return false;

    const std::string tokenID = record.value("tokenID", "");
    const std::string format = record.value("format", "");
    const std::string tokenType = record.value("type", "");
    const std::string provider = record.value("provider", "");
    const std::string status = record.value("status", "");
    uint64_t recordFormatVersion = 1U;
    try {
        if (record.contains("record_format_version")) {
            recordFormatVersion =
                record.at("record_format_version").get<uint64_t>();
        }
    } catch (...) {
        Logger::log("[TokenEvolution] Refusing invalid record_format_version");
        return false;
    }

    if (!isCanonicalEvolutionTokenID(tokenID) ||
        format != "TRU_TOKEN_EVOLVE_V1" ||
        status != "preview" ||
        (tokenType != "SFT" && tokenType != "NCFT") ||
        provider.empty() ||
        !record.contains("updated_fields") ||
        !record["updated_fields"].is_object() ||
        !record.contains("metadata") ||
        !record["metadata"].is_object())
    {
        Logger::log("[TokenEvolution] Refusing malformed persistence record");
        return false;
    }

    // TOKEN-AI-03A2: legacy records without record_format_version remain V1.
    // New previews are V2 and must carry complete logical-request provenance.
    if (recordFormatVersion != 1U && recordFormatVersion != 2U) {
        Logger::log("[TokenEvolution] Refusing unknown evolution record format version");
        return false;
    }

    if (recordFormatVersion == 2U) {
        const std::string writerType = record.value("writer_type", "");
        const std::string providerVersion = record.value("provider_version", "");
        const std::string modelID = record.value("model_id", "");
        const std::string requestHash = record.value("request_hash", "");
        const std::string inputMetadataHash =
            record.value("input_metadata_hash", "");

        if (writerType != "ai" ||
            providerVersion.empty() ||
            !record.contains("model_id") ||
            !record["model_id"].is_string() ||
            !isLowerHex(requestHash, 64U) ||
            !isLowerHex(inputMetadataHash, 64U))
        {
            Logger::log("[TokenEvolution] Refusing malformed V2 provenance record");
            return false;
        }

        (void)modelID; // Empty is the canonical "unknown/unavailable" encoding.
    }

    uint64_t epochBefore = 0;
    uint64_t epoch = 0;
    try {
        epochBefore = record.at("epoch_before").get<uint64_t>();
        epoch = record.at("epoch_after").get<uint64_t>();
    } catch (...) {
        return false;
    }

    if (epoch == 0U || epochBefore == std::numeric_limits<uint64_t>::max() ||
        epoch != epochBefore + 1U)
    {
        Logger::log("[TokenEvolution] Refusing non-sequential epoch record");
        return false;
    }

    const json& metadata = record["metadata"];
    if (parseEpoch(metadata) != epoch) {
        Logger::log("[TokenEvolution] Refusing metadata/record epoch mismatch");
        return false;
    }

    const std::string previousHash = record.value("previous_metadata_hash", "");
    const std::string newHash = record.value("new_metadata_hash", "");
    if (!isLowerHex(previousHash, 64U) || !isLowerHex(newHash, 64U) ||
        sha256Hex(metadata.dump()) != newHash)
    {
        Logger::log("[TokenEvolution] Refusing metadata hash mismatch");
        return false;
    }

    if (recordFormatVersion == 2U &&
        record.value("input_metadata_hash", "") != previousHash)
    {
        Logger::log(
            "[TokenEvolution] Refusing V2 input metadata hash/parent mismatch"
        );
        return false;
    }

    const std::string serialized = record.dump();
    const std::string epochKey =
        "epoch:" + tokenID + ":" + std::to_string(epoch);
    const std::string latestKey = "latest:" + tokenID;

    // Append-only epoch identity remains fail-closed.
    std::string existingEpoch;
    if (storage_->getContractData(
            "TOKEN_EVOLUTION",
            epochKey,
            existingEpoch))
    {
        Logger::log(
            "[TokenEvolution] Refusing duplicate epoch token=" +
            tokenID + " epoch=" + std::to_string(epoch)
        );
        return false;
    }

    // When a prior evolution exists, require exact hash/epoch continuity.
    std::string latestRaw;
    const bool hasLatest =
        storage_->getContractData("TOKEN_EVOLUTION", latestKey, latestRaw);

    if (hasLatest) {
        try {
            const json latest = json::parse(latestRaw);
            const uint64_t latestEpoch = latest.at("epoch_after").get<uint64_t>();
            const std::string latestHash = latest.value("new_metadata_hash", "");

            if (!latest.contains("metadata") ||
                !latest["metadata"].is_object() ||
                sha256Hex(latest["metadata"].dump()) != latestHash ||
                latestEpoch != epochBefore ||
                latestHash != previousHash) {
                Logger::log(
                    "[TokenEvolution] Refusing broken epoch/hash lineage token=" +
                    tokenID
                );
                return false;
            }
        } catch (...) {
            Logger::log(
                "[TokenEvolution] Refusing persistence over invalid latest record"
            );
            return false;
        }
    } else if (epochBefore != 0U) {
        Logger::log(
            "[TokenEvolution] First persisted evolution must begin at epoch 1"
        );
        return false;
    }

    const std::string queueItem =
        tokenID + ":" + std::to_string(epoch);

    json anchorQueue = json::array();
    std::string existingQueue;
    if (storage_->getContractData(
            "TOKEN_EVOLUTION",
            "anchor_queue",
            existingQueue))
    {
        if (existingQueue.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES) {
            Logger::log(
                "[TokenEvolution] Refusing oversized anchor_queue"
            );
            return false;
        }

        try {
            anchorQueue = json::parse(existingQueue);
        } catch (...) {
            Logger::log(
                "[TokenEvolution] Refusing invalid anchor_queue JSON"
            );
            return false;
        }

        if (!anchorQueue.is_array()) {
            Logger::log(
                "[TokenEvolution] Refusing non-array anchor_queue"
            );
            return false;
        }
    }

    // Canonicalize the queue, remove already-anchored entries and reject
    // malformed or duplicate state rather than silently rebuilding it.
    json compactQueue = json::array();
    std::set<std::string> seenQueueItems;
    bool alreadyQueued = false;

    for (const auto& item : anchorQueue) {
        if (!item.is_string()) {
            Logger::log("[TokenEvolution] Refusing non-string anchor queue item");
            return false;
        }

        const std::string queued = item.get<std::string>();
        std::string queuedTokenID;
        uint64_t queuedEpoch = 0;
        if (!parseEvolutionQueueItem(queued, queuedTokenID, queuedEpoch)) {
            Logger::log("[TokenEvolution] Refusing malformed anchor queue item");
            return false;
        }

        if (!seenQueueItems.insert(queued).second) {
            continue;
        }

        std::string anchoredTxid;
        if (storage_->getContractData(
                "TOKEN_EVOLUTION",
                "anchor_tx:" + queuedTokenID + ":" +
                    std::to_string(queuedEpoch),
                anchoredTxid))
        {
            continue;
        }

        if (queued == queueItem) alreadyQueued = true;
        compactQueue.push_back(queued);
    }

    if (!alreadyQueued) {
        if (compactQueue.size() >= TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS) {
            Logger::log(
                "[TokenEvolution] Anchor queue full; refusing unqueued epoch"
            );
            return false;
        }
        compactQueue.push_back(queueItem);
    }

    const std::string queueSerialized = compactQueue.dump();
    if (queueSerialized.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES) {
        Logger::log(
            "[TokenEvolution] Anchor queue byte limit exceeded"
        );
        return false;
    }

    // TOKEN-AI-02A: epoch, latest pointer and anchor queue are one synced,
    // checksummed LevelDB WriteBatch. No latest->missing-epoch window and no
    // persisted epoch can be acknowledged without also being queued.
    const std::vector<ContractStorage::BatchWrite> writes = {
        {"TOKEN_EVOLUTION", epochKey, serialized},
        {"TOKEN_EVOLUTION", latestKey, serialized},
        {"TOKEN_EVOLUTION", "anchor_queue", queueSerialized}
    };

    if (!storage_->storeContractDataBatch(writes)) {
        Logger::log(
            "[TokenEvolution] Atomic persistence batch failed token=" +
            tokenID + " epoch=" + std::to_string(epoch)
        );
        return false;
    }

    // Read-after-write verification makes a storage/checksum failure visible
    // to the caller instead of returning a false success.
    std::string verifyEpoch;
    std::string verifyLatest;
    std::string verifyQueue;
    if (!storage_->getContractData("TOKEN_EVOLUTION", epochKey, verifyEpoch) ||
        !storage_->getContractData("TOKEN_EVOLUTION", latestKey, verifyLatest) ||
        !storage_->getContractData("TOKEN_EVOLUTION", "anchor_queue", verifyQueue) ||
        verifyEpoch != serialized ||
        verifyLatest != serialized ||
        verifyQueue != queueSerialized)
    {
        Logger::log(
            "[TokenEvolution] Atomic persistence verification failed token=" +
            tokenID + " epoch=" + std::to_string(epoch)
        );
        return false;
    }

    Logger::log(
        "[TokenEvolution] Atomically persisted+queued token=" + tokenID +
        " epoch=" + std::to_string(epoch) +
        " queue_items=" + std::to_string(compactQueue.size())
    );
    return true;
}


json TokenEvolutionEngine::verifyHistory(
    const std::string& tokenID,
    const json& issuanceMetadata
) const {
    json report = {
        {"format", "TRU_TOKEN_EVOLUTION_VERIFY_V1"},
        {"tokenID", tokenID},
        {"ok", false},
        {"root_verified", false},
        {"fully_anchored", false},
        {"latest_epoch", 0ULL},
        {"verified_epochs", 0ULL},
        {"anchored_epochs", 0ULL},
        {"legacy_anchored_epochs", 0ULL},
        {"pending_epochs", 0ULL},
        {"prepared_pending_epochs", 0ULL},
        {"epochs", json::array()},
        {"errors", json::array()}
    };

    const auto addError = [&](const std::string& message) {
        report["errors"].push_back(message);
    };

    if (!storage_) {
        addError("ContractStorage is unavailable");
        return report;
    }

    if (!isCanonicalEvolutionTokenID(tokenID)) {
        addError("tokenID must be canonical lowercase 8-hex or 16-hex");
        return report;
    }

    if (!issuanceMetadata.is_object()) {
        addError("issuance metadata must be a JSON object");
        return report;
    }

    std::string latestRaw;
    if (!storage_->getContractData(
            "TOKEN_EVOLUTION",
            "latest:" + tokenID,
            latestRaw))
    {
        addError("no latest TOKEN_EVOLUTION record exists");
        return report;
    }

    json latest;
    uint64_t latestEpoch = 0;
    try {
        latest = json::parse(latestRaw);
        if (!latest.is_object()) {
            addError("latest TOKEN_EVOLUTION record is not an object");
            return report;
        }
        latestEpoch = latest.at("epoch_after").get<uint64_t>();
    } catch (const std::exception& e) {
        addError(std::string("invalid latest TOKEN_EVOLUTION record: ") + e.what());
        return report;
    }

    if (latestEpoch == 0U) {
        addError("latest TOKEN_EVOLUTION epoch must be >= 1");
        return report;
    }
    if (latestEpoch > TOKEN_EVOLUTION_MAX_VERIFY_EPOCHS) {
        addError("latest TOKEN_EVOLUTION epoch exceeds verifier safety bound");
        return report;
    }
    report["latest_epoch"] = latestEpoch;

    // Load and validate the global pending-anchor queue once. The queue may
    // contain epochs for other tokens, but every item must still be canonical.
    std::set<std::string> queueItems;
    std::string queueRaw;
    if (!storage_->getContractData(
            "TOKEN_EVOLUTION",
            "anchor_queue",
            queueRaw))
    {
        addError("anchor_queue is missing while evolution history exists");
        return report;
    }

    if (queueRaw.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_BYTES) {
        addError("anchor_queue exceeds the 65536-byte bound");
        return report;
    }

    try {
        const json queue = json::parse(queueRaw);
        if (!queue.is_array()) {
            addError("anchor_queue is not an array");
            return report;
        }
        if (queue.size() > TOKEN_EVOLUTION_MAX_ANCHOR_QUEUE_ITEMS) {
            addError("anchor_queue exceeds the 256-item bound");
            return report;
        }

        for (const auto& item : queue) {
            if (!item.is_string()) {
                addError("anchor_queue contains a non-string item");
                return report;
            }

            const std::string text = item.get<std::string>();
            std::string queuedTokenID;
            uint64_t queuedEpoch = 0;
            if (!parseEvolutionQueueItem(
                    text,
                    queuedTokenID,
                    queuedEpoch))
            {
                addError("anchor_queue contains malformed item: " + text);
                return report;
            }

            if (!queueItems.insert(text).second) {
                addError("anchor_queue contains duplicate item: " + text);
                return report;
            }
        }
    } catch (const std::exception& e) {
        addError(std::string("invalid anchor_queue JSON: ") + e.what());
        return report;
    }

    std::string previousNewHash;
    json previousMetadata = json::object();
    uint64_t previousTimestamp = 0;
    std::string historyType;
    std::string lastEpochRaw;
    bool rootVerified = false;
    uint64_t verifiedEpochs = 0;
    uint64_t anchoredEpochs = 0;
    uint64_t legacyAnchoredEpochs = 0;
    uint64_t pendingEpochs = 0;
    uint64_t preparedPendingEpochs = 0;

    for (uint64_t epoch = 1; epoch <= latestEpoch; ++epoch) {
        json epochReport = {
            {"epoch", epoch},
            {"integrity", false},
            {"anchor_status", "UNKNOWN"}
        };

        try {
        const std::string epochKey =
            "epoch:" + tokenID + ":" + std::to_string(epoch);

        std::string raw;
        if (!storage_->getContractData(
                "TOKEN_EVOLUTION",
                epochKey,
                raw))
        {
            addError("missing epoch record: " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        lastEpochRaw = raw;

        json record;
        try {
            record = json::parse(raw);
        } catch (const std::exception& e) {
            addError(
                "invalid JSON at " + epochKey + ": " + e.what()
            );
            report["epochs"].push_back(epochReport);
            break;
        }

        if (!record.is_object() ||
            record.value("format", "") != "TRU_TOKEN_EVOLVE_V1" ||
            record.value("tokenID", "") != tokenID)
        {
            addError("record identity mismatch at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        const std::string tokenType = record.value("type", "");
        const std::string provider = record.value("provider", "");
        const std::string trigger = record.value("trigger", "");
        const std::string status = record.value("status", "");
        const uint64_t recordFormatVersion =
            record.value("record_format_version", 1ULL);

        if (recordFormatVersion != 1U &&
            recordFormatVersion != 2U &&
            recordFormatVersion != 3U) {
            addError("unsupported record_format_version at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        const bool externalV3 = recordFormatVersion == 3U;
        if ((!externalV3 && status != "preview") ||
            (externalV3 && status != "materialized"))
        {
            addError("record status/version mismatch at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if ((tokenType != "SFT" && tokenType != "NCFT") ||
            provider.empty() ||
            trigger.empty() ||
            (externalV3 &&
             (provider != "external_writer" || trigger != "authorized_claim")))
        {
            addError("invalid type/provider/trigger at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if (epoch == 1U) {
            historyType = tokenType;
        } else if (tokenType != historyType) {
            addError("token type changed inside evolution history at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        uint64_t epochBefore = 0;
        uint64_t epochAfter = 0;
        uint64_t timestamp = 0;
        try {
            epochBefore = record.at("epoch_before").get<uint64_t>();
            epochAfter = record.at("epoch_after").get<uint64_t>();
            if (!externalV3) {
                timestamp = record.at("timestamp").get<uint64_t>();
            }
        } catch (const std::exception& e) {
            addError(
                "invalid epoch/provenance fields at " + epochKey +
                ": " + e.what()
            );
            report["epochs"].push_back(epochReport);
            break;
        }

        if (epochBefore != epoch - 1U || epochAfter != epoch) {
            addError("non-contiguous epoch numbering at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if (!externalV3 &&
            (timestamp == 0U ||
             (previousTimestamp != 0U && timestamp < previousTimestamp)))
        {
            addError("non-monotonic TRU timestamp at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if (!record.contains("metadata") ||
            !record["metadata"].is_object() ||
            !record.contains("updated_fields") ||
            !record["updated_fields"].is_object())
        {
            addError("metadata/updated_fields missing at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        const json& metadata = record["metadata"];
        const json& updates = record["updated_fields"];

        if (updates.empty()) {
            addError("updated_fields is empty at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        const std::string writerType =
            externalV3 ? record.value("writer_type", "") : "ai";
        bool updatesValid = true;
        for (auto it = updates.begin(); it != updates.end(); ++it) {
            const bool fieldAllowed = externalV3
                ? VAHCapabilities::writerClassMayHoldFieldCapability(
                    tokenType, writerType, it.key())
                : VAHCapabilities::isEvolutionFieldCurrentlyWritable(
                    tokenType, "ai", it.key());
            if (!fieldAllowed ||
                !it.value().is_string() ||
                !metadata.contains(it.key()) ||
                metadata[it.key()] != it.value())
            {
                updatesValid = false;
                break;
            }
        }

        if (!updatesValid) {
            addError("updated_fields violates the evolution allowlist at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if (parseEpoch(metadata) != epoch ||
            (!externalV3 &&
             (metadata.value("ai_engine", "") != provider ||
              metadata.value("last_evolution", "") !=
                  "unix:" + std::to_string(timestamp) +
                  ";epoch:" + std::to_string(epoch))))
        {
            addError("metadata provenance fields mismatch at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        const std::string previousHash =
            record.value("previous_metadata_hash", "");
        const std::string newHash =
            record.value("new_metadata_hash", "");

        if (!isLowerHex(previousHash, 64U) ||
            !isLowerHex(newHash, 64U) ||
            sha256Hex(metadata.dump()) != newHash)
        {
            addError("metadata hash mismatch at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        // Reconstruct the exact canonical parent metadata that evolvePreview
        // used for this epoch. This is also the input committed by
        // input_metadata_hash in Evolution Record V2.
        json requestInputMetadata;
        if (epoch == 1U) {
            // The persisted evolution namespace begins at epoch 1. A custom
            // evolution_epoch embedded in issuance metadata is descriptive and
            // must not redefine the provenance root counter.
            json issuanceRoot = issuanceMetadata;
            issuanceRoot["evolution_epoch"] = "0";
            requestInputMetadata =
                normalizeMetadata(tokenType, issuanceRoot, provider);

            if (parseEpoch(requestInputMetadata) != 0U ||
                sha256Hex(requestInputMetadata.dump()) != previousHash)
            {
                addError(
                    "epoch 1 previous_metadata_hash does not match normalized issuance metadata"
                );
                report["epochs"].push_back(epochReport);
                break;
            }
            rootVerified = true;
        } else {
            if (previousHash != previousNewHash) {
                addError("broken previous/new metadata hash link at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            requestInputMetadata =
                normalizeMetadata(tokenType, previousMetadata, provider);
            if (sha256Hex(requestInputMetadata.dump()) != previousHash) {
                addError("reconstructed request input hash mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }
        }

        if (recordFormatVersion == 2U) {
            const std::string writerType = record.value("writer_type", "");
            const std::string providerVersion =
                record.value("provider_version", "");
            const std::string modelID = record.value("model_id", "");
            const std::string requestHash =
                record.value("request_hash", "");
            const std::string inputMetadataHash =
                record.value("input_metadata_hash", "");

            if (writerType != "ai" ||
                providerVersion.empty() ||
                !record.contains("model_id") ||
                !record["model_id"].is_string() ||
                !isLowerHex(requestHash, 64U) ||
                !isLowerHex(inputMetadataHash, 64U) ||
                inputMetadataHash != previousHash)
            {
                addError("invalid V2 provenance fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            const std::string systemPrompt = evolutionSystemPrompt();
            const std::string userPrompt =
                buildPrompt(
                    tokenID,
                    tokenType,
                    requestInputMetadata,
                    trigger
                );
            const std::string expectedRequestHash =
                canonicalRequestHashV1(
                    tokenID,
                    tokenType,
                    epochBefore,
                    provider,
                    providerVersion,
                    modelID,
                    trigger,
                    inputMetadataHash,
                    systemPrompt,
                    userPrompt,
                    500U,
                    400U
                );

            if (requestHash != expectedRequestHash) {
                addError("V2 canonical request hash mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }
        }

        if (externalV3) {
            const std::string externalClaimHash =
                record.value("external_claim_hash", "");
            const std::string writerID = record.value("writer_id", "");
            const std::string writerPubKey =
                record.value("writer_pubkey_hex", "");

            if ((writerType != "human" && writerType != "sensor" &&
                 writerType != "device") ||
                !isLowerHex(externalClaimHash, 64U) ||
                externalClaimHash == std::string(64U, '0') ||
                !isLowerHex(writerID, 64U) ||
                !isLowerHex(writerPubKey, 66U) ||
                (writerPubKey.rfind("02", 0U) != 0U &&
                 writerPubKey.rfind("03", 0U) != 0U) ||
                !record.contains("changed_fields") ||
                !record["changed_fields"].is_array())
            {
                addError("invalid external-writer provenance fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            std::vector<std::string> changedFields;
            try {
                for (const auto& field : record["changed_fields"]) {
                    if (!field.is_string()) throw std::runtime_error("non-string field");
                    changedFields.push_back(field.get<std::string>());
                }
            } catch (...) {
                addError("invalid external changed_fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }
            if (changedFields.empty() || changedFields.size() > 16U ||
                !std::is_sorted(changedFields.begin(), changedFields.end()) ||
                std::adjacent_find(changedFields.begin(), changedFields.end()) !=
                    changedFields.end())
            {
                addError("non-canonical external changed_fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            if (deriveExternalWriterIdV1(writerPubKey) != writerID ||
                externalClaimDigestHexV1(
                    tokenID,
                    tokenType,
                    epoch,
                    previousHash,
                    newHash,
                    writerPubKey,
                    writerID,
                    writerType,
                    changedFields) != externalClaimHash)
            {
                addError("external writer identity/claim hash mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            std::set<std::string> claimed(changedFields.begin(), changedFields.end());
            std::set<std::string> updateKeys;
            for (auto it = updates.begin(); it != updates.end(); ++it) {
                updateKeys.insert(it.key());
            }
            if (claimed != updateKeys) {
                addError("external changed_fields/updated_fields mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            std::set<std::string> actualDelta;
            bool deltaValid = true;
            for (auto it = requestInputMetadata.begin();
                 it != requestInputMetadata.end(); ++it) {
                if (!metadata.contains(it.key())) {
                    deltaValid = false;
                    break;
                }
                if (metadata.at(it.key()) != it.value()) {
                    actualDelta.insert(it.key());
                }
            }
            if (deltaValid) {
                for (auto it = metadata.begin(); it != metadata.end(); ++it) {
                    if (!requestInputMetadata.contains(it.key())) {
                        actualDelta.insert(it.key());
                    }
                }
            }
            if (!deltaValid || actualDelta.erase("evolution_epoch") != 1U ||
                actualDelta != claimed)
            {
                addError("external metadata delta differs from signed fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            if (!isLowerHex(record.value("anchor_txid", ""), 64U) ||
                !isLowerHex(record.value("anchor_block_hash", ""), 64U) ||
                record.value("anchor_block_height", 0ULL) == 0U)
            {
                addError("invalid external confirmed-chain fields at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }
        }

        const std::string durableRecordHash = sha256Hex(record.dump());
        const std::string anchorRecordHash = externalV3
            ? record.value("external_claim_hash", "")
            : durableRecordHash;
        const std::string queueItem =
            tokenID + ":" + std::to_string(epoch);
        const bool queued =
            queueItems.count(queueItem) != 0U;

        const std::string anchorTxKey =
            "anchor_tx:" + tokenID + ":" + std::to_string(epoch);
        const std::string anchorReceiptKey =
            "anchor_receipt:" + tokenID + ":" + std::to_string(epoch);
        const std::string preparedKey =
            "anchor_prepared:" + tokenID + ":" + std::to_string(epoch);

        std::string anchorTxid;
        const bool hasAnchorTx =
            storage_->getContractData(
                "TOKEN_EVOLUTION",
                anchorTxKey,
                anchorTxid);

        if (hasAnchorTx && !isLowerHex(anchorTxid, 64U)) {
            addError("invalid anchor_tx txid at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        std::string preparedRaw;
        const bool hasPrepared =
            storage_->getContractData(
                "TOKEN_EVOLUTION",
                preparedKey,
                preparedRaw);

        std::string preparedTxid;
        if (hasPrepared) {
            try {
                const json prepared = json::parse(preparedRaw);
                const std::string txHex =
                    prepared.value("tx_hex", "");

                if (!prepared.is_object() ||
                    prepared.value("format", "") !=
                        "TRU_TOKEN_EVOLVE_ANCHOR_PREPARED_V1" ||
                    prepared.value("status", "") != "prepared" ||
                    prepared.value("tokenID", "") != tokenID ||
                    prepared.value("epoch", 0ULL) != epoch ||
                    prepared.value("new_metadata_hash", "") != newHash ||
                    prepared.value("record_hash", "") != anchorRecordHash ||
                    !isLowerHex(prepared.value("txid", ""), 64U) ||
                    txHex.empty() ||
                    txHex.size() > 20000U ||
                    (txHex.size() % 2U) != 0U ||
                    !std::all_of(
                        txHex.begin(), txHex.end(),
                        [](unsigned char c) {
                            return (c >= '0' && c <= '9') ||
                                   (c >= 'a' && c <= 'f');
                        }))
                {
                    throw std::runtime_error(
                        "prepared anchor identity/encoding mismatch"
                    );
                }

                preparedTxid = prepared.value("txid", "");
            } catch (const std::exception& e) {
                addError(
                    "invalid anchor_prepared at " + epochKey +
                    ": " + e.what()
                );
                report["epochs"].push_back(epochReport);
                break;
            }
        }

        std::string receiptRaw;
        const bool hasReceipt =
            storage_->getContractData(
                "TOKEN_EVOLUTION",
                anchorReceiptKey,
                receiptRaw);

        std::string receiptTxid;
        if (hasReceipt) {
            try {
                const json receipt = json::parse(receiptRaw);
                if (!receipt.is_object() ||
                    receipt.value("format", "") !=
                        "TRU_TOKEN_EVOLVE_ANCHOR_RECEIPT_V1" ||
                    receipt.value("status", "") != "submitted" ||
                    receipt.value("tokenID", "") != tokenID ||
                    receipt.value("epoch", 0ULL) != epoch ||
                    receipt.value("new_metadata_hash", "") != newHash ||
                    receipt.value("record_hash", "") != anchorRecordHash ||
                    !isLowerHex(receipt.value("txid", ""), 64U))
                {
                    throw std::runtime_error(
                        "anchor receipt identity mismatch"
                    );
                }
                receiptTxid = receipt.value("txid", "");
            } catch (const std::exception& e) {
                addError(
                    "invalid anchor_receipt at " + epochKey +
                    ": " + e.what()
                );
                report["epochs"].push_back(epochReport);
                break;
            }
        }

        if (externalV3 &&
            (!hasReceipt || !hasAnchorTx ||
             record.value("anchor_txid", "") != anchorTxid))
        {
            addError("external V3 materialization missing exact confirmed receipt at " + epochKey);
            report["epochs"].push_back(epochReport);
            break;
        }

        if (hasReceipt) {
            if (!hasAnchorTx ||
                anchorTxid != receiptTxid ||
                queued ||
                (hasPrepared && preparedTxid != receiptTxid))
            {
                addError("submitted receipt/queue identity mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            epochReport["anchor_status"] = "RECEIPT_SUBMITTED";
            epochReport["anchor_txid"] = receiptTxid;
            ++anchoredEpochs;
        } else if (hasAnchorTx) {
            // Pre-02B anchors did not have durable JSON receipts. They remain
            // readable as legacy-submitted state, but must not remain queued.
            if (queued ||
                (hasPrepared && preparedTxid != anchorTxid))
            {
                addError("legacy anchor/queue identity mismatch at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            epochReport["anchor_status"] = "LEGACY_SUBMITTED";
            epochReport["anchor_txid"] = anchorTxid;
            ++legacyAnchoredEpochs;
        } else {
            if (!queued) {
                addError("unanchored epoch is missing from anchor_queue at " + epochKey);
                report["epochs"].push_back(epochReport);
                break;
            }

            ++pendingEpochs;
            if (hasPrepared) {
                epochReport["anchor_status"] = "PREPARED_PENDING";
                epochReport["prepared_txid"] = preparedTxid;
                ++preparedPendingEpochs;
            } else {
                epochReport["anchor_status"] = "QUEUED_PENDING";
            }
        }

        epochReport["integrity"] = true;
        epochReport["provider"] = provider;
        epochReport["trigger"] = trigger;
        epochReport["timestamp"] = timestamp;
        epochReport["record_format_version"] = recordFormatVersion;
        epochReport["writer_type"] =
            recordFormatVersion >= 2U ? record.value("writer_type", "") : "legacy-ai";
        epochReport["provider_version"] =
            recordFormatVersion >= 2U ? record.value("provider_version", "") : "";
        epochReport["model_id"] =
            recordFormatVersion >= 2U ? record.value("model_id", "") : "";
        epochReport["request_hash"] =
            recordFormatVersion >= 2U ? record.value("request_hash", "") : "";
        epochReport["input_metadata_hash"] =
            recordFormatVersion == 2U ? record.value("input_metadata_hash", "") : "";
        epochReport["external_claim_hash"] =
            externalV3 ? record.value("external_claim_hash", "") : "";
        epochReport["writer_id"] =
            externalV3 ? record.value("writer_id", "") : "";
        epochReport["anchor_block_hash"] =
            externalV3 ? record.value("anchor_block_hash", "") : "";
        epochReport["anchor_block_height"] =
            externalV3 ? record.value("anchor_block_height", 0ULL) : 0ULL;
        epochReport["anchor_tx_index"] =
            externalV3 ? record.value("anchor_tx_index", 0ULL) : 0ULL;
        epochReport["previous_metadata_hash"] = previousHash;
        epochReport["new_metadata_hash"] = newHash;
        epochReport["record_hash"] = anchorRecordHash;
        epochReport["durable_record_hash"] = durableRecordHash;
        epochReport["queued"] = queued;
        epochReport["prepared"] = hasPrepared;
        epochReport["receipt"] = hasReceipt;

        report["epochs"].push_back(epochReport);

        previousNewHash = newHash;
        previousMetadata = metadata;
        if (!externalV3) previousTimestamp = timestamp;
        ++verifiedEpochs;
        } catch (const std::exception& e) {
            addError(
                "verification exception at epoch " +
                std::to_string(epoch) + ": " + e.what()
            );
            report["epochs"].push_back(epochReport);
            break;
        }
    }

    report["root_verified"] = rootVerified;
    report["verified_epochs"] = verifiedEpochs;
    report["anchored_epochs"] = anchoredEpochs;
    report["legacy_anchored_epochs"] = legacyAnchoredEpochs;
    report["pending_epochs"] = pendingEpochs;
    report["prepared_pending_epochs"] = preparedPendingEpochs;

    if (verifiedEpochs == latestEpoch &&
        lastEpochRaw == latestRaw)
    {
        // Check that this token has no queued epoch outside its verified
        // contiguous range.
        for (const auto& item : queueItems) {
            std::string queuedTokenID;
            uint64_t queuedEpoch = 0;
            if (!parseEvolutionQueueItem(
                    item,
                    queuedTokenID,
                    queuedEpoch))
            {
                addError("queue changed during verification");
                break;
            }

            if (queuedTokenID == tokenID &&
                (queuedEpoch == 0U || queuedEpoch > latestEpoch))
            {
                addError(
                    "anchor_queue contains out-of-range epoch for token: " +
                    item
                );
                break;
            }
        }
    } else if (verifiedEpochs == latestEpoch) {
        addError("latest:<token> is not byte-identical to final epoch record");
    }

    const bool ok =
        report["errors"].empty() &&
        rootVerified &&
        verifiedEpochs == latestEpoch;

    report["ok"] = ok;
    report["fully_anchored"] =
        ok &&
        pendingEpochs == 0U &&
        anchoredEpochs + legacyAnchoredEpochs == latestEpoch;

    return report;
}

json TokenEvolutionEngine::loadLatest(const std::string& tokenID) const {
    if (!storage_ || tokenID.empty()) return json::object();

    std::string raw;
    if (!storage_->getContractData(
            "TOKEN_EVOLUTION",
            "latest:" + tokenID,
            raw)) {
        return json::object();
    }

    try {
        return json::parse(raw);
    } catch (...) {
        return json::object();
    }
}
