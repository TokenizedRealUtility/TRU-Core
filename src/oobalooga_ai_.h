#pragma once
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

// Wallet interface.
#include "wallet.h"   // must provide Wallet with issueExtendedSFT / issueExtendedNCFT

// ---------- types ----------
struct OobaConfig {
    std::string baseUrl = "http://127.0.0.1:3002";
    std::string apiKey  = "878_878";   // Local provider API key.
    int maxNewTokens    = 256;         // maps to "max_tokens"
    double temperature  = 0.7;
    int top_k           = 40;
    double top_p        = 0.9;
    double min_p        = 0.02;
    double repetition_penalty = 1.08;
    int repetition_penalty_range = 1024;
    double encoder_repetition_penalty = 1.02;
    double presence_penalty = 0.0;
    double frequency_penalty = 0.1;
    double typical_p = 0.9;
    int no_repeat_ngram_size = 3;
    double guidance_scale = 1.0;
    bool stream = false;
    int n_ctx = 4096;
    int seed = -1;
};

// ---------- curl helpers ----------
inline size_t curlWriteStr(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    auto* s = static_cast<std::string*>(userp);
    s->append(static_cast<char*>(contents), realsize);
    return realsize;
}

// POST JSON to Oobabooga /api/v1/generate
inline std::string oobaGenerateRaw(const OobaConfig& cfg, const std::string& prompt) {
    nlohmann::json body = {
        {"model", "local"},
        {"messages", {{{"role", "user"}, {"content", prompt}}}},
        {"mode", "chat"},
        {"temperature", cfg.temperature},
        {"max_tokens", cfg.maxNewTokens},
        {"top_p", cfg.top_p},
        {"top_k", cfg.top_k},
        {"min_p", cfg.min_p},
        {"repetition_penalty", cfg.repetition_penalty},
        {"repetition_penalty_range", cfg.repetition_penalty_range},
        {"encoder_repetition_penalty", cfg.encoder_repetition_penalty},
        {"presence_penalty", cfg.presence_penalty},
        {"frequency_penalty", cfg.frequency_penalty},
        {"typical_p", cfg.typical_p},
        {"no_repeat_ngram_size", cfg.no_repeat_ngram_size},
        {"guidance_scale", cfg.guidance_scale},
        {"n_ctx", cfg.n_ctx},
        {"stream", cfg.stream},
        {"do_sample", true}
    };

    std::string url = cfg.baseUrl + "/v1/chat/completions";
    std::string resp;
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl init failed");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string auth = "Authorization: Bearer " + cfg.apiKey;
    headers = curl_slist_append(headers, auth.c_str());

    std::string bodyStr = body.dump();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bodyStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteStr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error(std::string("curl perform failed: ") + curl_easy_strerror(res));

    if (code < 200 || code >= 300)
        throw std::runtime_error("Ooba API HTTP " + std::to_string(code) + " body=" + resp);

    return resp;
}

inline std::string oobaGenerateText(const OobaConfig& cfg, const std::string& prompt) {
    std::string raw = oobaGenerateRaw(cfg, prompt);
    auto j = nlohmann::json::parse(raw);

    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty()) {
        const auto& choice = j["choices"][0];
        if (choice.contains("message") && choice["message"].contains("content")) {
            return choice["message"]["content"].get<std::string>();
        }
    }
    throw std::runtime_error("Unexpected Ooba response: " + raw);
}

// ---------- AI -> token metadata ----------
inline std::unordered_map<std::string, std::string>
buildAIEnhancedMeta(const std::string& baseName,
                    const std::string& aiDescription,
                    const std::string& aiVersion = "ooba-local")
{
    std::unordered_map<std::string, std::string> meta;
    meta["name"]               = baseName;
    meta["description_ai"]     = aiDescription;
    meta["ai_engine"]          = "oobabooga";
    meta["ai_version"]         = aiVersion;
    meta["learning_mode"]      = "on-chain usage patterns";
    meta["growth_algorithm"]   = "neural-adaptive";
    meta["behavior_model"]     = "adaptive_v3";
    meta["self_evolution"]     = "enabled";
    meta["context_aware_rule"] = "context_v1";
    return meta;
}

// Wallet-backed token issuers.
inline std::string createSFTWithOoba(
        Wallet& wallet,
        const OobaConfig& ooba,
        const std::string& tokenID,
        uint64_t totalSupply,
        const std::string& name,
        const std::string& symbol,
        const std::string& description,
        const std::string& imageUrl,
        uint32_t decimals)
{
    const std::string prompt =
        "You are writing a metadata description for a Sentient Fungible Token (SFT) "
        "on a Bitcoin-like UTXO chain (TRU). Keep it <280 chars, no quotes. "
        "Highlight adaptive/learning behavior and utility. Base name: " + name + ".";
    const std::string aiText = oobaGenerateText(ooba, prompt);

    auto addMeta = buildAIEnhancedMeta(name, aiText);
    addMeta["symbol"]   = symbol;
    addMeta["decimals"] = std::to_string(decimals);
    addMeta["image"]    = imageUrl;

    return wallet.issueExtendedSFT(
        tokenID, totalSupply, name, symbol, description, imageUrl, decimals, addMeta
    );
}

inline std::string createNCFTWithOoba(
        Wallet& wallet,
        const OobaConfig& ooba,
        const std::string& tokenID,
        uint64_t quantity,
        const std::string& name,
        const std::string& description,
        const std::string& imageOrMediaUrl)
{
    const std::string prompt =
        "Write a concise, evocative description (<240 chars, no quotes) for a Neural Canvas "
        "Fungible Token (NCFT) art series. Mention evolving style, narrative, or traits. "
        "Base name: " + name + ".";
    const std::string aiText = oobaGenerateText(ooba, prompt);

    auto addMeta = buildAIEnhancedMeta(name, aiText);
    addMeta["image"] = imageOrMediaUrl;

    return wallet.issueExtendedNCFT(
        tokenID, quantity, name, description, imageOrMediaUrl, addMeta
    );
}

