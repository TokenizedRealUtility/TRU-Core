// ai_providers.cpp
#include <curl/curl.h>
#include <cstdlib>
#include "ai_provider_interface.h"
#include "ai_providers.h"
#include "ai_oracle_service.h"
#include "blockchain.h"
#include "logging.h"

static std::string extractChatContent(const nlohmann::json& j) {
    // Handle oobabooga /v1/chat/completions style
    if (j.contains("choices") && j["choices"].is_array() && !j["choices"].empty()) {
        const auto& c = j["choices"][0];
        if (c.contains("message") && c["message"].contains("content"))
            return c["message"]["content"].get<std::string>();
        if (c.contains("text")) // some local servers return "text"
            return c["text"].get<std::string>();
    }
    // Anthropic Messages API: content is an array of typed blocks.
    if (j.contains("content") && j["content"].is_array()) {
        std::string text;

        for (const auto& block : j["content"]) {
            if (block.is_object() &&
                block.value("type", "") == "text" &&
                block.contains("text") &&
                block["text"].is_string())
            {
                if (!text.empty()) text.push_back(char(10));
                text += block["text"].get<std::string>();
            }
        }

        if (!text.empty()) return text;
    }

    // Fallback to a generic field if present
    if (j.contains("content") && j["content"].is_string())
        return j["content"].get<std::string>();

    // If we reach here, just dump the JSON
    return j.dump();
}

// ---------------------------------------------------------------------------
// shared HTTPS JSON POST transport for cloud AI providers.
// Keeps API keys out of logs and returns structured, parseable errors.
// ---------------------------------------------------------------------------
static size_t AIHttpWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    auto* out = static_cast<std::string*>(userp);
    out->append(static_cast<const char*>(contents), total);
    return total;
}

static nlohmann::json performJsonPost(
    const std::string& url,
    const std::string& bearerToken,
    const nlohmann::json& payload,
    const std::vector<std::string>& extraHeaders = {})
{
    CURL* curl = curl_easy_init();

    if (!curl) {
        return nlohmann::json{
            {"error", "Failed to initialize CURL"}
        };
    }

    std::string responseBody;
    const std::string requestBody = payload.dump();

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    if (!bearerToken.empty()) {
        const std::string authHeader =
            "Authorization: Bearer " + bearerToken;
        headers = curl_slist_append(headers, authHeader.c_str());
    }

    for (const auto& header : extraHeaders) {
        headers = curl_slist_append(headers, header.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBody.c_str());
    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDSIZE,
        static_cast<long>(requestBody.size())
    );

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AIHttpWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    // Production-safe network behavior.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "TRU-AI-Oracle/1.0");

    // TLS certificate verification remains ENABLED (libcurl default).
    CURLcode result = curl_easy_perform(curl);

    long httpStatus = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatus);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        return nlohmann::json{
            {
                "error",
                "HTTP transport failed: " +
                std::string(curl_easy_strerror(result))
            },
            {"http_status", httpStatus}
        };
    }

    nlohmann::json parsed;

    try {
        parsed = nlohmann::json::parse(responseBody);
    } catch (const std::exception& e) {
        std::string snippet = responseBody;

        if (snippet.size() > 500) {
            snippet.resize(500);
            snippet += "...";
        }

        return nlohmann::json{
            {
                "error",
                "Provider returned invalid JSON: " +
                std::string(e.what())
            },
            {"http_status", httpStatus},
            {"body_snippet", snippet}
        };
    }

    if (httpStatus < 200 || httpStatus >= 300) {
        std::string providerError;

        if (parsed.contains("error")) {
            if (parsed["error"].is_string()) {
                providerError = parsed["error"].get<std::string>();
            } else {
                providerError = parsed["error"].dump();
            }
        } else {
            providerError = parsed.dump();
        }

        return nlohmann::json{
            {
                "error",
                "Provider HTTP " +
                std::to_string(httpStatus) +
                ": " +
                providerError
            },
            {"http_status", httpStatus},
            {"provider_response", parsed}
        };
    }

    return parsed;
}

// Oobabooga TextGen Provider (DEFAULT)
class OobaboogaProvider : public IAIProvider {
private:
    std::string endpoint = "http://127.0.0.1:3002/v1/chat/completions";
    std::string apiKey = "";  // Optional for local
    bool configured = true;   // Default configured for local
    
public:
    std::string getName() const override { return "oobabooga"; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override { return configured; }
    
    void configure(const nlohmann::json& config) override {
        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }

        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("OOBABOOGA_API_KEY")) {
            apiKey = envKey;
        }

        configured = true;
    }
    
    // oracle credentials are loaded internally by
    // writeAIResponseOnChain() from tru.conf, so this helper no longer
    // carries oracleWIF/oracleAddress parameters.
    nlohmann::json sendRequestAndWrite(
        Blockchain& chain,
        const std::string& requestID,
        const nlohmann::json& request
    ) {
        nlohmann::json raw = sendRequest(request);

        // Extract content (handles /v1/chat/completions shapes)
        std::string modelText;
        if (raw.contains("error")) {
            modelText = std::string("provider_error: ") + raw["error"].get<std::string>();
        } else {
            modelText = extractChatContent(raw);
        }

        std::string txid;
        if (!writeAIResponseOnChain(
                chain,
                requestID,
                getName(), // "oobabooga"
                modelText,
                txid))
        {
            Logger::log("[AIOracle] Failed to write OP_RETURN response for " + requestID);
            return nlohmann::json{
                {"status","error"},
                {"requestID", requestID},
                {"message","Failed to write OP_RETURN (see node logs)"},
                {"provider", getName()}
            };
        }

        Logger::log("[AIOracle] Wrote OP_RETURN response txid=" + txid + " for " + requestID);
        return nlohmann::json{
            {"status","complete"},
            {"requestID", requestID},
            {"provider", getName()},
            {"txid", txid},
            {"content_snippet", modelText.substr(0,160)}
        };
    }

    nlohmann::json sendRequest(const nlohmann::json& request) override {
        // optional environment authentication for local Oobabooga.
        if (apiKey.empty()) {
            if (const char* envKey = std::getenv("OOBABOOGA_API_KEY")) {
                apiKey = envKey;
            }
        }

        try {
            CURL* curl = curl_easy_init();
            if (!curl) throw std::runtime_error("Failed to initialize CURL");
            
            std::string response;
            curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            
            // Prepare request
            nlohmann::json oobRequest = {
                {"mode", "chat"},
                {"messages", request["messages"]},
                {"max_tokens", request.value("max_tokens", 500)},
                {"temperature", request.value("temperature", 0.8)},
                {"top_p", request.value("top_p", 0.95)}
            };
            
            std::string jsonStr = oobRequest.dump();
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
            
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            if (!apiKey.empty()) {
                headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey).c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            
            // Capture response
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            
            CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            
            if (res != CURLE_OK) {
                throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
            }
            
            return nlohmann::json::parse(response);
        } catch (const std::exception& e) {
            return nlohmann::json({{"error", e.what()}});
        }
    }
    
private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
};

// OpenAI ChatGPT Provider
class OpenAIProvider : public IAIProvider {
private:
    std::string endpoint = "https://api.openai.com/v1/chat/completions";
    std::string apiKey;
    // current non-reasoning model with Chat Completions support.
    // Can still be overridden through provider configuration.
    std::string model = "gpt-4.1";
    bool configured = false;
    
public:
    std::string getName() const override { return "openai"; }
    std::string getModelId() const override { return model; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override { return configured && !apiKey.empty(); }
    
    void configure(const nlohmann::json& config) override {
        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("OPENAI_API_KEY")) {
            apiKey = envKey;
        }

        if (config.contains("model")) {
            model = config["model"];
        }

        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }

        configured = !apiKey.empty();
    }
    
    nlohmann::json sendRequest(const nlohmann::json& request) override {
        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({{"error", "OpenAI API key not configured"}});
        }
        
        nlohmann::json openaiRequest = {
            {"model", model},
            {"messages", request["messages"]},
            {"max_tokens", request.value("max_tokens", 500)},
            {"temperature", request.value("temperature", 0.8)}
        };
        
        // Similar CURL implementation as Oobabooga
        return performHttpRequest(endpoint, apiKey, openaiRequest);
    }
    
    nlohmann::json performHttpRequest(const std::string& url, 
                                      const std::string& key, 
                                      const nlohmann::json& payload) {
        // real HTTPS JSON transport.
        return performJsonPost(url, key, payload);
    }
};

// Anthropic Claude Provider
class AnthropicProvider : public IAIProvider {
private:
    std::string endpoint = "https://api.anthropic.com/v1/messages";
    std::string apiKey;
    std::string model = "claude-sonnet-4-20250514";
    bool configured = false;

public:
    std::string getName() const override { return "anthropic"; }
    std::string getModelId() const override { return model; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override {
        return configured && !apiKey.empty();
    }

    void configure(const nlohmann::json& config) override {
        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("ANTHROPIC_API_KEY")) {
            apiKey = envKey;
        }

        if (config.contains("model")) {
            model = config["model"];
        }

        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }

        configured = !apiKey.empty();
    }

    nlohmann::json sendRequest(const nlohmann::json& request) override {
        // Allow environment-only configuration even if configureProvider()
        // has not yet been called in this process.
        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({
                {"error", "Anthropic API key not configured"}
            });
        }

        nlohmann::json anthropicMessages = nlohmann::json::array();
        std::string systemPrompt;

        if (request.contains("messages") && request["messages"].is_array()) {
            for (const auto& message : request["messages"]) {
                if (!message.is_object()) continue;

                const std::string role = message.value("role", "");
                if (!message.contains("content")) continue;

                if (role == "system") {
                    if (message["content"].is_string()) {
                        if (!systemPrompt.empty()) systemPrompt.push_back(char(10));
                        systemPrompt += message["content"].get<std::string>();
                    }
                    continue;
                }

                if (role == "user" || role == "assistant") {
                    anthropicMessages.push_back({
                        {"role", role},
                        {"content", message["content"]}
                    });
                }
            }
        }

        nlohmann::json anthropicRequest = {
            {"model", model},
            {"max_tokens", request.value("max_tokens", 500)},
            {"temperature", request.value("temperature", 0.8)},
            {"messages", anthropicMessages}
        };

        if (!systemPrompt.empty()) {
            anthropicRequest["system"] = systemPrompt;
        }

        const std::vector<std::string> headers = {
            "x-api-key: " + apiKey,
            "anthropic-version: 2023-06-01"
        };

        // Anthropic uses x-api-key rather than Bearer auth.
        return performJsonPost(
            endpoint,
            "",
            anthropicRequest,
            headers
        );
    }
};

// First-class Nemotron harness provider.
//
// The local Nemotron server exposes an OpenAI-compatible
// /v1/chat/completions endpoint. Bearer authentication is optional for
// trusted loopback use and can be supplied through NEMOTRON_API_KEY for
// remote/non-loopback access.
class NemotronProvider : public IAIProvider {
private:
    std::string endpoint = "http://127.0.0.1:5051/v1/chat/completions";
    std::string apiKey;
    std::string model = "nemotron";
    bool configured = true;

public:
    std::string getName() const override { return "nemotron"; }
    std::string getModelId() const override { return model; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override {
        return configured && !endpoint.empty();
    }

    void configure(const nlohmann::json& config) override {
        // endpoint priority:
        // explicit provider config > NEMOTRON_ENDPOINT > default 5051.
        if (config.contains("endpoint") &&
            config["endpoint"].is_string() &&
            !config["endpoint"].get<std::string>().empty())
        {
            endpoint = config["endpoint"].get<std::string>();
        } else if (const char* envEndpoint = std::getenv("NEMOTRON_ENDPOINT")) {
            if (*envEndpoint != '\0') {
                endpoint = envEndpoint;
            }
        }

        if (config.contains("model") &&
            config["model"].is_string() &&
            !config["model"].get<std::string>().empty())
        {
            model = config["model"].get<std::string>();
        }

        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("NEMOTRON_API_KEY")) {
            apiKey = envKey;
        }

        configured = !endpoint.empty();
    }

    nlohmann::json sendRequest(const nlohmann::json& request) override {
        // process-level endpoint override.
        if (const char* envEndpoint = std::getenv("NEMOTRON_ENDPOINT")) {
            if (*envEndpoint != '\0') {
                endpoint = envEndpoint;
            }
        }

        // Pick up a process environment key even when the default local
        // endpoint is usable without any explicit configureProvider() call.
        if (apiKey.empty()) {
            if (const char* envKey = std::getenv("NEMOTRON_API_KEY")) {
                apiKey = envKey;
            }
        }

        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({
                {"error", "Nemotron provider endpoint not configured"}
            });
        }

        if (!request.contains("messages") || !request["messages"].is_array()) {
            return nlohmann::json({
                {"error", "Nemotron provider requires messages[]"}
            });
        }

        nlohmann::json nemotronRequest = {
            {"model", model},
            {"messages", request["messages"]},
            {"temperature", request.value("temperature", 0.8)},
            {"max_tokens", request.value("max_tokens", 500)},
            {"top_p", request.value("top_p", 0.9)},
            {"stream", false}
        };

        // The Nemotron AuthGate accepts Authorization: Bearer <key>.
        // An empty key intentionally sends no Authorization header, allowing
        // the harness' trusted-loopback policy to decide local access.
        return performJsonPost(endpoint, apiKey, nemotronRequest);
    }
};

// Ollama Provider
class OllamaProvider : public IAIProvider {
private:
    std::string endpoint = "http://127.0.0.1:11434/api/chat";
    std::string model = "llama3";
    bool configured = true;  // Default configured for local
    
public:
    std::string getName() const override { return "ollama"; }
    std::string getModelId() const override { return model; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override { return configured; }
    
    void configure(const nlohmann::json& config) override {
        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }
        if (config.contains("model")) {
            model = config["model"];
        }
        configured = true;
    }
    
    nlohmann::json sendRequest(const nlohmann::json& request) override {
        nlohmann::json ollamaRequest = {
            {"model", model},
            {"messages", request["messages"]},
            {"stream", false},
            {"options", {
                {"temperature", request.value("temperature", 0.8)},
                {"top_p", request.value("top_p", 0.95)},
                {"num_predict", request.value("max_tokens", 500)}
            }}
        };
        
        return performHttpRequest(endpoint, "", ollamaRequest);
    }
    
    nlohmann::json performHttpRequest(const std::string& url, 
                                      const std::string& key, 
                                      const nlohmann::json& payload) {
        // real local JSON transport.
        return performJsonPost(url, key, payload);
    }
};

// Grok Provider (X.AI)
class GrokProvider : public IAIProvider {
private:
    std::string endpoint = "https://api.x.ai/v1/chat/completions";
    std::string apiKey;
    // current xAI Chat Completions model.
    // Can still be overridden through provider configuration.
    std::string model = "grok-4.5";
    bool configured = false;
    
public:
    std::string getName() const override { return "grok"; }
    std::string getModelId() const override { return model; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override { return configured && !apiKey.empty(); }
    
    void configure(const nlohmann::json& config) override {
        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("XAI_API_KEY")) {
            apiKey = envKey;
        }

        if (config.contains("model")) {
            model = config["model"];
        }

        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }

        configured = !apiKey.empty();
    }
    
    nlohmann::json sendRequest(const nlohmann::json& request) override {
        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({{"error", "Grok API key not configured"}});
        }
        
        nlohmann::json grokRequest = {
            {"model", model},
            {"messages", request["messages"]},
            {"temperature", request.value("temperature", 0.8)},
            {"max_tokens", request.value("max_tokens", 500)}
        };
        
        return performHttpRequest(endpoint, apiKey, grokRequest);
    }
    
    nlohmann::json performHttpRequest(const std::string& url, 
                                      const std::string& key, 
                                      const nlohmann::json& payload) {
        // xAI uses Bearer auth and an OpenAI-compatible
        // Chat Completions request/response shape.
        return performJsonPost(url, key, payload);
    }
};

// Google Gemini provider.
//
// Uses Gemini's native generateContent REST API. The API key is sent in the
// x-goog-api-key header and is never placed in the request URL.
class GeminiProvider : public IAIProvider {
private:
    std::string endpointBase =
        "https://generativelanguage.googleapis.com/v1beta/models";
    std::string apiKey;
    std::string model = "gemini-3.6-flash";
    bool configured = false;

public:
    std::string getName() const override { return "gemini"; }
    std::string getModelId() const override { return model; }

    std::string getEndpoint() const override {
        return endpointBase + "/" + model + ":generateContent";
    }

    bool isConfigured() const override {
        return configured && !apiKey.empty() && !endpointBase.empty();
    }

    void configure(const nlohmann::json& config) override {
        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("GEMINI_API_KEY")) {
            apiKey = envKey;
        }

        if (config.contains("model") &&
            config["model"].is_string() &&
            !config["model"].get<std::string>().empty())
        {
            model = config["model"].get<std::string>();
        }

        // "endpoint" is treated as the Gemini models API base URL.
        if (config.contains("endpoint") &&
            config["endpoint"].is_string() &&
            !config["endpoint"].get<std::string>().empty())
        {
            endpointBase = config["endpoint"].get<std::string>();

            while (!endpointBase.empty() && endpointBase.back() == '/') {
                endpointBase.pop_back();
            }
        }

        configured = !apiKey.empty() && !endpointBase.empty();
    }

    nlohmann::json sendRequest(const nlohmann::json& request) override {
        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({
                {"error", "Gemini API key not configured"}
            });
        }

        if (!request.contains("messages") || !request["messages"].is_array()) {
            return nlohmann::json({
                {"error", "Gemini provider requires messages[]"}
            });
        }

        std::string systemPrompt;
        nlohmann::json contents = nlohmann::json::array();

        for (const auto& message : request["messages"]) {
            if (!message.is_object()) continue;

            const std::string role = message.value("role", "");
            if (!message.contains("content")) continue;

            std::string text;
            if (message["content"].is_string()) {
                text = message["content"].get<std::string>();
            } else {
                text = message["content"].dump();
            }

            if (role == "system") {
                if (!systemPrompt.empty()) systemPrompt.push_back(char(10));
                systemPrompt += text;
                continue;
            }

            std::string geminiRole = "user";
            if (role == "assistant" || role == "model") {
                geminiRole = "model";
            }

            nlohmann::json parts = nlohmann::json::array();
            parts.push_back({{"text", text}});

            contents.push_back({
                {"role", geminiRole},
                {"parts", parts}
            });
        }

        if (contents.empty()) {
            return nlohmann::json({
                {"error", "Gemini provider received no user/assistant content"}
            });
        }

        nlohmann::json geminiRequest = {
            {"contents", contents},
            {"generationConfig", {
                {"maxOutputTokens", request.value("max_tokens", 500)}
            }}
        };

        if (!systemPrompt.empty()) {
            nlohmann::json systemParts = nlohmann::json::array();
            systemParts.push_back({{"text", systemPrompt}});

            geminiRequest["systemInstruction"] = {
                {"parts", systemParts}
            };
        }

        const std::vector<std::string> headers = {
            "x-goog-api-key: " + apiKey
        };

        return performJsonPost(
            getEndpoint(),
            "",
            geminiRequest,
            headers
        );
    }
};

// Custom Provider for any API
class CustomProvider : public IAIProvider {
private:
    std::string endpoint;
    std::string apiKey;
    std::string authHeader = "Authorization";
    std::string authPrefix = "Bearer";
    bool configured = false;
    nlohmann::json requestTemplate;
    
public:
    std::string getName() const override { return "custom"; }
    std::string getEndpoint() const override { return endpoint; }
    bool isConfigured() const override { return configured && !endpoint.empty(); }
    
    void configure(const nlohmann::json& config) override {
        if (config.contains("endpoint")) {
            endpoint = config["endpoint"];
        }

        if (config.contains("api_key") &&
            config["api_key"].is_string() &&
            !config["api_key"].get<std::string>().empty())
        {
            apiKey = config["api_key"].get<std::string>();
        } else if (const char* envKey = std::getenv("CUSTOM_AI_API_KEY")) {
            apiKey = envKey;
        }

        if (config.contains("auth_header")) {
            authHeader = config["auth_header"];
        }

        if (config.contains("auth_prefix")) {
            authPrefix = config["auth_prefix"];
        }

        if (config.contains("request_template")) {
            requestTemplate = config["request_template"];
        }

        configured = !endpoint.empty();
    }
    
    nlohmann::json sendRequest(const nlohmann::json& request) override {
        if (!isConfigured()) {
            configure(nlohmann::json::object());
        }

        if (!isConfigured()) {
            return nlohmann::json({{"error", "Custom provider not configured"}});
        }
        
        // Merge request with template
        nlohmann::json finalRequest = requestTemplate;
        finalRequest.merge_patch(request);
        
        return performHttpRequest(endpoint, apiKey, finalRequest);
    }
    
    nlohmann::json performHttpRequest(const std::string& url, 
                                      const std::string& key, 
                                      const nlohmann::json& payload) {
        // real JSON transport with configurable authentication.
        std::vector<std::string> headers;

        if (!key.empty() && !authHeader.empty()) {
            std::string value = authHeader + ":";

            if (!authPrefix.empty()) {
                value += " " + authPrefix;
            }

            value += " " + key;
            headers.push_back(value);
        }

        return performJsonPost(url, "", payload, headers);
    }
};

std::shared_ptr<IAIProvider> makeOobaboogaProvider() { 
    return std::make_shared<OobaboogaProvider>(); 
}
std::shared_ptr<IAIProvider> makeOpenAIProvider() { 
    return std::make_shared<OpenAIProvider>(); 
}
std::shared_ptr<IAIProvider> makeAnthropicProvider() {
    return std::make_shared<AnthropicProvider>();
}

std::shared_ptr<IAIProvider> makeNemotronProvider() {
    return std::make_shared<NemotronProvider>();
}

std::shared_ptr<IAIProvider> makeOllamaProvider() { 
    return std::make_shared<OllamaProvider>(); 
}
std::shared_ptr<IAIProvider> makeGrokProvider() { 
    return std::make_shared<GrokProvider>(); 
}

std::shared_ptr<IAIProvider> makeGeminiProvider() {
    return std::make_shared<GeminiProvider>();
}

std::shared_ptr<IAIProvider> makeCustomProvider() { 
    return std::make_shared<CustomProvider>(); 
}

