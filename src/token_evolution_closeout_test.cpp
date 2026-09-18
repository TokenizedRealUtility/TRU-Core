#include "token_evolution.h"
#include "contract_storage.h"
#include "leveldb_storage.h"
#include "ai_provider_interface.h"

#include <openssl/sha.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using nlohmann::json;

namespace {
std::string sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2U);
    for (unsigned char b : hash) {
        out.push_back(hex[(b >> 4) & 0x0f]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

struct MockProvider final : IAIProvider {
    enum class Mode { TEXT_RESPONSE, ERROR_RESPONSE };

    std::string providerName;
    Mode mode;
    std::string payload;
    int calls{0};

    MockProvider(std::string name, Mode m, std::string p)
        : providerName(std::move(name)), mode(m), payload(std::move(p)) {}

    std::string getName() const override { return providerName; }
    std::string getProviderVersion() const override { return "TRU_CLOSEOUT_TEST_V1"; }
    std::string getModelId() const override { return "closeout-model"; }

    json sendRequest(const json&) override {
        ++calls;
        if (mode == Mode::ERROR_RESPONSE) {
            return json{{"error", payload}};
        }
        // Use the engine's explicit "response" string extraction path so this
        // harness tests evolution policy rather than provider-response nesting.
        return json{{"response", payload}};
    }

    void configure(const json&) override {}
    bool isConfigured() const override { return true; }
    std::string getEndpoint() const override { return "test://closeout"; }
};

json makeRecord(const std::string& tokenID, const std::string& description, char fill) {
    json metadata = {
        {"name", "Closeout Fixture"},
        {"symbol", "COT"},
        {"description_ai", description},
        {"evolution_epoch", "1"},
        {"ai_engine", "closeoutmock"},
        {"last_evolution", "unix:1;epoch:1"}
    };
    const std::string previousHash(64U, fill);
    return {
        {"format", "TRU_TOKEN_EVOLVE_V1"},
        {"record_format_version", 2U},
        {"status", "preview"},
        {"tokenID", tokenID},
        {"type", "SFT"},
        {"writer_type", "ai"},
        {"provider", "closeoutmock"},
        {"provider_version", "TRU_CLOSEOUT_TEST_V1"},
        {"model_id", "closeout-model"},
        {"request_hash", std::string(64U, 'a')},
        {"input_metadata_hash", previousHash},
        {"trigger", "closeout"},
        {"epoch_before", 0U},
        {"epoch_after", 1U},
        {"previous_metadata_hash", previousHash},
        {"new_metadata_hash", sha256Hex(metadata.dump())},
        {"timestamp", 1U},
        {"updated_fields", json{{"description_ai", description}}},
        {"metadata", metadata}
    };
}

struct Fixture {
    std::string path;
    std::unique_ptr<LevelDBStorage> db;
    std::unique_ptr<ContractStorage> storage;
    std::unique_ptr<TokenEvolutionEngine> engine;

    explicit Fixture(const std::string& name) {
        path = "/tmp/tru-ai-provenance-closeout-" + name;
        std::filesystem::remove_all(path);
        db = std::make_unique<LevelDBStorage>(path);
        storage = std::make_unique<ContractStorage>(db.get());
        engine = std::make_unique<TokenEvolutionEngine>(storage.get());
    }
    ~Fixture() {
        engine.reset(); storage.reset(); db.reset();
        std::filesystem::remove_all(path);
    }
};

bool has(ContractStorage& s, const std::string& key, std::string* value=nullptr) {
    std::string v;
    bool ok = s.getContractData("TOKEN_EVOLUTION", key, v);
    if (ok && value) *value = v;
    return ok;
}

void require(bool cond, const std::string& msg) {
    if (!cond) throw std::runtime_error(msg);
}

void requireNoEpochState(Fixture& f, const std::string& tokenID) {
    require(!has(*f.storage, "epoch:" + tokenID + ":1"), "epoch unexpectedly persisted");
    require(!has(*f.storage, "latest:" + tokenID), "latest unexpectedly persisted");
    require(!has(*f.storage, "anchor_queue"), "queue unexpectedly persisted");
}

void requireAllEpochState(Fixture& f, const std::string& tokenID) {
    require(has(*f.storage, "epoch:" + tokenID + ":1"), "epoch missing");
    require(has(*f.storage, "latest:" + tokenID), "latest missing");
    require(has(*f.storage, "anchor_queue"), "queue missing");
}
}

int main() {
    try {
        const std::string tokenID = "0123456789abcdef";

        {
            Fixture f("before");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::BEFORE_BATCH);
            require(!f.engine->persistPreview(makeRecord(tokenID, "before", '1')), "before-batch fault returned success");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  storage fault before batch: zero persistence\n";
        }
        {
            Fixture f("batchwrite");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::BATCH_WRITE_FAIL);
            require(!f.engine->persistPreview(makeRecord(tokenID, "batch", '2')), "batch-write fault returned success");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  atomic batch write refusal: zero partial persistence\n";
        }
        {
            Fixture f("afterbatch");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::AFTER_BATCH_BEFORE_READBACK);
            require(!f.engine->persistPreview(makeRecord(tokenID, "after", '3')), "after-batch fault returned success");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::NONE);
            requireAllEpochState(f, tokenID);
            std::cout << "PASS  post-batch/pre-readback fault: full batch durable, never partial\n";
        }
        {
            Fixture f("readback");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::READBACK_MISMATCH);
            require(!f.engine->persistPreview(makeRecord(tokenID, "readback", '4')), "readback mismatch returned success");
            f.storage->setTokenEvolutionTestFault(ContractStorage::TestFault::NONE);
            requireAllEpochState(f, tokenID);
            std::cout << "PASS  readback mismatch: false success prevented, full batch remains atomic\n";
        }
        {
            Fixture f("duplicate");
            auto a = makeRecord(tokenID, "winner", '5');
            auto b = makeRecord(tokenID, "loser", '6');
            require(f.engine->persistPreview(a), "first candidate failed");
            require(!f.engine->persistPreview(b), "competing same-epoch candidate was accepted");
            std::cout << "PASS  competing previews: one epoch wins, second refuses\n";
        }
        {
            Fixture f("mutated");
            auto r = makeRecord(tokenID, "valid", '7');
            r["metadata"]["description_ai"] = "mutated-after-preview";
            require(!f.engine->persistPreview(r), "mutated preview hash accepted");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  mutated exact preview hash refused with zero persistence\n";
        }
        {
            Fixture f("unknownversion");
            auto r = makeRecord(tokenID, "version", '8');
            r["record_format_version"] = 999U;
            require(!f.engine->persistPreview(r), "unknown record version accepted");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  unknown record format fails closed\n";
        }
        {
            Fixture f("noop");
            auto provider = std::make_shared<MockProvider>(
                "closeoutmock-noop",
                MockProvider::Mode::TEXT_RESPONSE,
                R"({"description_ai":"same"})"
            );
            AIProviderRegistry::getInstance().registerProvider("closeoutmock-noop", provider);
            json meta = {{"description_ai", "same"}, {"evolution_epoch", "0"}};
            auto p = f.engine->evolvePreview(tokenID, "SFT", meta, "closeoutmock-noop", "closeout");
            require(!p.ok, "no-op preview accepted");
            require(
                p.error == "AI proposed no permitted metadata changes; nothing committed.",
                "unexpected no-op error: [" + p.error + "]"
            );
            require(provider->calls == 1, "provider call count mismatch");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  allowed-but-unchanged AI proposal refused with zero persistence\n";
        }
        {
            Fixture f("providererror");
            auto provider = std::make_shared<MockProvider>(
                "closeoutmock-error",
                MockProvider::Mode::ERROR_RESPONSE,
                "injected provider failure"
            );
            AIProviderRegistry::getInstance().registerProvider("closeoutmock-error", provider);
            auto p = f.engine->evolvePreview(tokenID, "SFT", json::object(), "closeoutmock-error", "closeout");
            require(!p.ok, "provider exception path accepted");
            require(p.error == "injected provider failure",
                    "unexpected provider error: [" + p.error + "]");
            requireNoEpochState(f, tokenID);
            std::cout << "PASS  provider failure leaves zero evolution persistence\n";
        }

        std::cout << "TRU_AI_PROVENANCE_V1_CLOSEOUT_DEV_STORAGE_MATRIX=PASS\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL  " << e.what() << "\n";
        return 1;
    }
}
