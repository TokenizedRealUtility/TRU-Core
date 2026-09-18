#include "token_evolution.h"
#include "ai_providers.h"
#include "ai_provider_interface.h"
#include "leveldb_storage.h"
#include "contract_storage.h"
#include "logging.h"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using nlohmann::json;

static void printUsage(const char* exe) {
    std::cout
        << "TRU Living Token Evolution Tester\n\n"
        << "Usage:\n"
        << "  " << exe << " --token-id <ID> [options]\n\n"
        << "Options:\n"
        << "  --token-id <ID>       Existing TRU SFT/NCFT token ID (required)\n"
        << "  --type <SFT|NCFT>     Optional; auto-detected from token metadata\n"
        << "  --provider <name>     AI provider (default: nemotron)\n"
        << "  --trigger <text>      Evolution trigger (default: manual)\n"
        << "  --db <path>           LevelDB path (default: data/utxo)\n"
        << "  --metadata-json <j>   Optional override instead of loading token metadata\n"
        << "  --no-persist          Generate preview but do not store TOKEN_EVOLUTION state\n"
        << "  --show-latest         Print latest stored evolution preview and exit\n"
        << "  --verify-history      Verify full epoch/hash/anchor-receipt history and exit\n"
        << "  --help                Show this help\n\n"
        << "Examples:\n"
        << "  " << exe << " --token-id 1e262cd7 --provider nemotron\n"
        << "  " << exe << " --token-id f1916530 --provider grok --trigger transfer-test\n"
        << "  " << exe << " --token-id 1e262cd7 --show-latest\n"
        << "  " << exe << " --token-id 65c105c2bb40d774 --verify-history\n";
}

static std::string argValue(int argc, char** argv, const std::string& name) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (argv[i] == name) return argv[i + 1];
    }
    return "";
}

static bool hasArg(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == name) return true;
    }
    return false;
}

static void registerAllProviders() {
    auto& registry = AIProviderRegistry::getInstance();

    registry.registerProvider("oobabooga", makeOobaboogaProvider());
    registry.registerProvider("nemotron",  makeNemotronProvider());
    registry.registerProvider("ollama",    makeOllamaProvider());
    registry.registerProvider("openai",    makeOpenAIProvider());
    registry.registerProvider("anthropic", makeAnthropicProvider());
    registry.registerProvider("grok",      makeGrokProvider());
    registry.registerProvider("gemini",    makeGeminiProvider());
    registry.registerProvider("custom",    makeCustomProvider());
}

static bool loadExistingTokenMetadata(
    LevelDBStorage& db,
    const std::string& tokenID,
    std::string& tokenType,
    json& currentMeta,
    std::string& issuanceTxid,
    std::string& error)
{
    const auto loadMetadataRecord = [&](
        const std::string& metadataTxid,
        const std::string& raw,
        json& storedOut) -> bool
    {
        (void)metadataTxid;
        try {
            json stored = json::parse(raw);
            if (!stored.is_object()) return false;
            if (stored.value("tokenID", "") != tokenID) return false;

            const std::string storedType = stored.value("type", "");
            if (storedType != "SFT" && storedType != "NCFT") return false;
            if (!tokenType.empty() && storedType != tokenType) return false;

            storedOut = std::move(stored);
            return true;
        } catch (...) {
            return false;
        }
    };

    const auto publishMetadata = [&](
        const json& stored,
        const std::string& metadataTxid) -> bool
    {
        const std::string storedType = stored.value("type", "");
        if (tokenType.empty()) {
            tokenType = storedType;
        } else if (tokenType != storedType) {
            error =
                "Token type mismatch for tokenID=" + tokenID +
                " requested=" + tokenType +
                " stored=" + storedType;
            return false;
        }

        if (stored.contains("meta") && stored["meta"].is_object()) {
            currentMeta = stored["meta"];
        } else {
            currentMeta = json::object();
        }

        for (const char* key :
             {"name", "symbol", "description", "image", "imageUrl"}) {
            if (stored.contains(key) && !currentMeta.contains(key)) {
                currentMeta[key] = stored[key];
            }
        }

        issuanceTxid = metadataTxid;
        return true;
    };

    // Current path stays authoritative when tokenIssuance exists.
    std::string mappedIssuanceTxid;
    if (db.getWithDataChecksum(
            "tokenIssuance:" + tokenID, mappedIssuanceTxid)) {
        std::string raw;
        if (!db.getWithDataChecksum(
                "tokenMetadata:" + mappedIssuanceTxid, raw)) {
            error =
                "No tokenMetadata found for issuance txid=" +
                mappedIssuanceTxid;
            return false;
        }

        json stored;
        if (!loadMetadataRecord(mappedIssuanceTxid, raw, stored)) {
            error =
                "Mapped issuance metadata is malformed or mismatched for tokenID=" +
                tokenID;
            return false;
        }

        return publishMetadata(stored, mappedIssuanceTxid);
    }

    // TOKEN-AI-R1-HISTORICAL-FALLBACK:
    // Older confirmed SFT/NCFTs can predate tokenIssuance:<tokenID>.
    // This compatibility path is read-only. It first proves a live confirmed
    // controlling token UTXO, then requires exactly one historical metadata
    // record matching the same token ID/type. Any ambiguity fails closed.
    bool liveConfirmedTokenFound = false;
    bool liveTypeConflict = false;
    std::string liveTokenType;

    const std::string ownerPrefix = "tokenOwnerUTXO:" + tokenID + ":";
    db.iteratePrefix(
        ownerPrefix,
        [&](const std::string& keySansPrefix, const std::string&) {
            const std::size_t lastColon = keySansPrefix.rfind(':');
            if (lastColon == std::string::npos) return;

            const std::size_t secondLastColon =
                keySansPrefix.rfind(':', lastColon - 1);
            if (secondLastColon == std::string::npos) return;

            const std::string txid =
                keySansPrefix.substr(
                    secondLastColon + 1,
                    lastColon - secondLastColon - 1);
            const std::string vout =
                keySansPrefix.substr(lastColon + 1);

            if (txid.size() != 64 || vout.empty()) return;

            const std::string outpoint = txid + ":" + vout;
            if (!db.exists("utxo:" + outpoint)) return;

            std::string tokenRaw;
            if (!db.getWithDataChecksum(
                    "tokenUTXO:" + outpoint, tokenRaw)) {
                return;
            }

            try {
                const json tokenUtxo = json::parse(tokenRaw);
                if (!tokenUtxo.is_object()) return;
                if (tokenUtxo.value("tokenID", "") != tokenID) return;

                const std::string thisType =
                    tokenUtxo.value("type", "");
                if (thisType != "SFT" && thisType != "NCFT") return;

                if (!tokenType.empty() && thisType != tokenType) {
                    liveTypeConflict = true;
                    return;
                }

                if (liveTokenType.empty()) {
                    liveTokenType = thisType;
                } else if (liveTokenType != thisType) {
                    liveTypeConflict = true;
                    return;
                }

                liveConfirmedTokenFound = true;
            } catch (...) {
                return;
            }
        });

    if (liveTypeConflict) {
        error =
            "Historical token live-index type conflict for tokenID=" +
            tokenID;
        return false;
    }

    if (!liveConfirmedTokenFound) {
        error =
            "No live confirmed tokenOwnerUTXO/tokenUTXO proof found for historical tokenID=" +
            tokenID;
        return false;
    }

    if (tokenType.empty()) {
        tokenType = liveTokenType;
    }

    std::size_t candidateCount = 0;
    std::string candidateTxid;
    json candidateStored;

    db.iteratePrefix(
        "tokenMetadata:",
        [&](const std::string& txid, const std::string& raw) {
            if (txid.size() != 64) return;

            json stored;
            if (!loadMetadataRecord(txid, raw, stored)) return;

            ++candidateCount;
            if (candidateCount == 1) {
                candidateTxid = txid;
                candidateStored = std::move(stored);
            }
        });

    if (candidateCount == 0) {
        error =
            "Historical token is live/confirmed but no matching tokenMetadata record exists for tokenID=" +
            tokenID;
        return false;
    }

    if (candidateCount != 1) {
        error =
            "Historical token metadata is ambiguous for tokenID=" +
            tokenID +
            " matchingCandidates=" + std::to_string(candidateCount);
        return false;
    }

    if (!publishMetadata(candidateStored, candidateTxid)) {
        return false;
    }

    std::cout
        << "[TOKEN-AI-R1] HISTORICAL TOKEN METADATA FALLBACK"
        << " tokenID=" << tokenID
        << " type=" << tokenType
        << " metadataTxid=" << candidateTxid
        << " liveConfirmed=YES"
        << " tokenIssuance=ABSENT"
        << "\n";

    return true;
}

int main(int argc, char** argv) {
    if (hasArg(argc, argv, "--help") || argc == 1) {
        printUsage(argv[0]);
        return 0;
    }

    const std::string tokenID = argValue(argc, argv, "--token-id");
    std::string tokenType = argValue(argc, argv, "--type");
    const std::string provider = [&]() {
        const std::string v = argValue(argc, argv, "--provider");
        return v.empty() ? std::string("nemotron") : v;
    }();
    const std::string trigger = [&]() {
        const std::string v = argValue(argc, argv, "--trigger");
        return v.empty() ? std::string("manual") : v;
    }();
    const std::string dbPath = [&]() {
        const std::string v = argValue(argc, argv, "--db");
        return v.empty() ? std::string("data/utxo") : v;
    }();

    if (tokenID.empty()) {
        std::cerr << "ERROR: --token-id is required\n";
        return 2;
    }

    try {
        LevelDBStorage db(dbPath);
        ContractStorage storage(&db);
        TokenEvolutionEngine engine(&storage);

        if (hasArg(argc, argv, "--show-latest")) {
            json latest = engine.loadLatest(tokenID);

            if (latest.empty()) {
                std::cout << "No TOKEN_EVOLUTION preview stored for " << tokenID << "\n";
                return 3;
            }

            std::cout << latest.dump(2) << "\n";

            uint64_t epoch = latest.value("epoch_after", 0ULL);
            std::string anchorTxid;

            if (epoch > 0 &&
                storage.getContractData(
                    "TOKEN_EVOLUTION",
                    "anchor_tx:" + tokenID + ":" +
                        std::to_string(epoch),
                    anchorTxid))
            {
                std::cout
                    << "\nON-CHAIN ANCHOR: SUBMITTED\n"
                    << "anchor txid: " << anchorTxid << "\n";
            } else {
                std::cout
                    << "\nON-CHAIN ANCHOR: PENDING / NOT YET SUBMITTED\n";
            }

            return 0;
        }

        json currentMeta = json::object();
        std::string issuanceTxid;

        const std::string metadataOverride =
            argValue(argc, argv, "--metadata-json");

        if (!metadataOverride.empty()) {
            currentMeta = json::parse(metadataOverride);
            if (!currentMeta.is_object()) {
                throw std::runtime_error("--metadata-json must be a JSON object");
            }

            if (tokenType.empty()) {
                throw std::runtime_error(
                    "--type is required when using --metadata-json"
                );
            }
        } else {
            std::string loadError;
            if (!loadExistingTokenMetadata(
                    db,
                    tokenID,
                    tokenType,
                    currentMeta,
                    issuanceTxid,
                    loadError))
            {
                std::cerr << "ERROR: " << loadError << "\n";
                std::cerr << "DB path used: " << dbPath << "\n";
                return 4;
            }
        }

        if (tokenType != "SFT" && tokenType != "NCFT") {
            std::cerr
                << "ERROR: token type is '" << tokenType
                << "'. Patch 19 evolution supports only SFT and NCFT.\n";
            return 5;
        }

        if (hasArg(argc, argv, "--verify-history")) {
            const json verification =
                engine.verifyHistory(tokenID, currentMeta);

            std::cout
                << "\n============================================================\n"
                << " TRU TOKEN EVOLUTION HISTORY VERIFIER\n"
                << "============================================================\n"
                << verification.dump(2) << "\n";

            if (!verification.value("ok", false)) {
                std::cerr
                    << "\nVERIFY RESULT: FAIL\n";
                return 8;
            }

            std::cout
                << "\nVERIFY RESULT: PASS\n"
                << "verified epochs : "
                << verification.value("verified_epochs", 0ULL) << "\n"
                << "latest epoch    : "
                << verification.value("latest_epoch", 0ULL) << "\n"
                << "fully anchored  : "
                << (verification.value("fully_anchored", false)
                    ? "yes" : "no") << "\n"
                << "pending anchors : "
                << verification.value("pending_epochs", 0ULL) << "\n";

            return 0;
        }

        registerAllProviders();

        std::cout << "\n============================================================\n";
        std::cout << " TRU LIVING TOKEN EVOLUTION PREVIEW\n";
        std::cout << "============================================================\n";
        std::cout << "Token ID : " << tokenID << "\n";
        std::cout << "Type     : " << tokenType << "\n";
        std::cout << "Provider : " << provider << "\n";
        std::cout << "Trigger  : " << trigger << "\n";
        if (!issuanceTxid.empty()) {
            std::cout << "Issuance : " << issuanceTxid << "\n";
        }
        // show which state will actually be evolved.
        json latestState = engine.loadLatest(tokenID);

        if (!latestState.empty() &&
            latestState.contains("metadata") &&
            latestState["metadata"].is_object())
        {
            std::cout
                << "\nState source: latest persisted TOKEN_EVOLUTION record"
                << " (epoch "
                << latestState.value("epoch_after", 0ULL)
                << ")\n";

            std::cout << "Current evolution metadata:\n"
                      << latestState["metadata"].dump(2) << "\n";
        } else {
            std::cout << "\nState source: original issuance metadata\n";
            std::cout << "Current metadata:\n"
                      << currentMeta.dump(2) << "\n";
        }

        TokenEvolutionResult result = engine.evolvePreview(
            tokenID,
            tokenType,
            currentMeta,
            provider,
            trigger
        );

        if (!result.ok) {
            std::cerr << "\nEVOLUTION FAILED: " << result.error << "\n";
            return 6;
        }

        std::cout << "\nEvolution preview:\n"
                  << result.record.dump(2) << "\n";

        if (!hasArg(argc, argv, "--no-persist")) {
            if (!engine.persistPreview(result.record)) {
                std::cerr << "\nERROR: preview generated but persistence failed\n";
                return 7;
            }

            std::cout
                << "\nSUCCESS: preview persisted to TOKEN_EVOLUTION\n"
                << "  latest:" << tokenID << "\n"
                << "  epoch:" << tokenID << ":"
                << result.record.value("epoch_after", 0ULL) << "\n";
        } else {
            std::cout << "\nPreview generated; --no-persist requested.\n";
        }

        std::cout
            << "\nPATCH 22: evolution persisted and queued for on-chain anchoring.\n"
            << "The standalone CLI does not broadcast directly; start tru_advanced so\n"
            << "the oracle monitor can sign and submit the queued TRU_EVOLVE_V1 anchor.\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 10;
    }
}
