// ai_oracle_service.cpp
#include "ai_oracle_service.h"
#include "ai_provider_interface.h"
#include "ai_providers.h"
#include "token_evolution.h"
#include "blockchain.h"
#include "logging.h"
#include "block.h"  // Changed from transaction.h
#include "opcodes.h"
#include "utils.h"  // For bytesToHex and other utilities
#include "address_helpers.h"
#include "config_reader.h"
#include "mempool.h"
#include <memory>
#include <algorithm>
#include <limits>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

using json = nlohmann::json;

// helper: pushdata encoder for script
static void pushData(std::vector<uint8_t>& sc, const std::vector<uint8_t>& data) {
    const size_t n = data.size();
    if (n <= 75) {
        sc.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xff) {
        sc.push_back(0x4c); // OP_PUSHDATA1
        sc.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        sc.push_back(0x4d); // OP_PUSHDATA2
        sc.push_back(static_cast<uint8_t>(n & 0xff));
        sc.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else {
        throw std::runtime_error("OP_RETURN payload too large");
    }
    sc.insert(sc.end(), data.begin(), data.end());
}

static std::string buildAIResponseOpReturn(const std::string& requestID,
                                           const std::string& providerName,
                                           const std::string& text)
{
    // Prefix keeps it discoverable; keep payload small.
    //
    const std::string prefix = "ai_response:";
    const std::string payload = prefix + requestID + "|" + providerName + "|" + text;
    // OP_RETURN = 0x6a <PUSHDATA>
    // Store ASCII directly in the script; serialization preserves the bytes.
    //
    std::string script;
    script.push_back(0x6a);                      // OP_RETURN
    if (payload.size() < 0x4c) {                 // PUSHDATA1 threshold
        script.push_back((unsigned char)payload.size());
    } else {
        // (rare for short payloads; left here for completeness)
        script.push_back(0x4c);
        script.push_back((unsigned char)payload.size());
    }
    script.append(payload);
    return script;
}


// ---------- OP_RETURN helpers ----------
static void pushBytes(std::vector<uint8_t>& sc, const std::string& s) {
    const size_t n = s.size();
    if (n <= 75) {
        sc.push_back((uint8_t)n);
    } else if (n <= 255) {
        sc.push_back(0x4c); // OP_PUSHDATA1
        sc.push_back((uint8_t)n);
    } else if (n <= 65535) {
        sc.push_back(0x4d); // OP_PUSHDATA2
        sc.push_back((uint8_t)(n & 0xFF));
        sc.push_back((uint8_t)((n >> 8) & 0xFF));
    } else {
        throw std::runtime_error("push too big; split beforehand");
    }
    sc.insert(sc.end(), s.begin(), s.end());
}

static std::string buildOpReturn(const std::vector<std::string>& chunks) {
    std::vector<uint8_t> sc;
    sc.push_back(0x6a); // OP_RETURN
    for (const auto& c : chunks) pushBytes(sc, c);
    return bytesToHex(sc); // script hex
}

static std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::vector<uint8_t> v(hash, hash + SHA256_DIGEST_LENGTH);
    return bytesToHex(v);
}

// normalize text extraction across OpenAI-compatible,
// Ollama/local, and Anthropic Messages API responses.
static std::string extractAIProviderText(const nlohmann::json& response) {
    // OpenAI / Grok / Oobabooga Chat Completions.
    if (response.contains("choices") &&
        response["choices"].is_array() &&
        !response["choices"].empty())
    {
        try {
            return response["choices"][0]["message"]["content"]
                .get<std::string>();
        } catch (...) {
            // Continue through other provider formats.
        }
    }

    // Anthropic Messages API.
    if (response.contains("content") && response["content"].is_array()) {
        std::string text;

        for (const auto& block : response["content"]) {
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

    // Gemini generateContent response:
    // candidates[0].content.parts[].text
    if (response.contains("candidates") &&
        response["candidates"].is_array() &&
        !response["candidates"].empty())
    {
        try {
            const auto& candidate = response["candidates"][0];

            if (candidate.contains("content") &&
                candidate["content"].is_object() &&
                candidate["content"].contains("parts") &&
                candidate["content"]["parts"].is_array())
            {
                std::string text;

                for (const auto& part : candidate["content"]["parts"]) {
                    if (part.is_object() &&
                        part.contains("text") &&
                        part["text"].is_string())
                    {
                        if (!text.empty()) text.push_back(char(10));
                        text += part["text"].get<std::string>();
                    }
                }

                if (!text.empty()) return text;
            }
        } catch (...) {
            // Continue through generic provider formats.
        }
    }

    // Generic string content.
    if (response.contains("content") && response["content"].is_string()) {
        return response["content"].get<std::string>();
    }

    // Ollama /api/chat response:
    // {"message":{"role":"assistant","content":"..."}}
    if (response.contains("message") &&
        response["message"].is_object() &&
        response["message"].contains("content") &&
        response["message"]["content"].is_string())
    {
        return response["message"]["content"].get<std::string>();
    }

    // Ollama-style/simple local response.
    if (response.contains("response") && response["response"].is_string()) {
        return response["response"].get<std::string>();
    }

    return response.dump();
}

// ---------- minimal UTXO shape expected from wallet.rpcListUnspent ----------
struct OracleUTXO {
    std::string txid;
    uint32_t    vout{0};
    uint64_t    amount{0};        // TRU atoms
    std::string scriptPubKeyHex;  // hex (P2PKH usually)
};

// Try to convert the generic wallet UTXO model into OracleUTXO.
// Adapt wallet UTXOs to the RPC result shape.
static std::vector<OracleUTXO> toOracleUtxos(const std::vector<UTXO>& in) {
    std::vector<OracleUTXO> out;
    out.reserve(in.size());
    for (const auto& u : in) {
        OracleUTXO o;
        o.txid            = u.txid;
        o.vout            = (uint32_t)u.vout;
        o.amount          = (uint64_t)u.amount;
        o.scriptPubKeyHex = u.scriptPubKey; // UTXO script bytes.
        out.push_back(std::move(o));
    }
    return out;
}

// Select the first UTXO whose value is at least minNeeded.
static bool selectUtxo(const std::vector<OracleUTXO>& utxos, uint64_t minNeeded, OracleUTXO& chosen) {
    for (const auto& u : utxos) {
        if (u.amount >= minNeeded) { chosen = u; return true; }
    }
    return false;
}

// ---------- MAIN: writeAIResponseOnChain ----------
bool writeAIResponseOnChain(
    Blockchain& chain,
    const std::string& requestID,
    const std::string& providerName,
    const std::string& modelText,
    std::string& outTxid)
{
    try {
        // 1) Load oracle credentials + node endpoint
        ConfigReader cfg("tru.conf");

        const std::string oracleWIF     = cfg.getValue("default", "oracle.wif");
        const std::string oracleAddress = cfg.getValue("default", "oracle.address");

        const std::string nodeIP = [&]{
            auto v = cfg.getValue("default", "node.ip");
            return v.empty() ? std::string("127.0.0.1") : v;
        }();

        const int nodePort = [&]{
            auto v = cfg.getValue("default", "node.port");
            return v.empty() ? 8001 : std::stoi(v);
        }();

        if (oracleWIF.empty() || oracleAddress.empty()) {
            Logger::log("[AIOracle] Missing oracle.wif or oracle.address in tru.conf");
            return false;
        }

        // 2) Prepare wallet bound to this chain/node
        Wallet wallet("oracle.wallet", nullptr, nodeIP, nodePort);

        const std::string importedAddr = wallet.importPrivateKey(oracleWIF);
        if (importedAddr.empty()) {
            Logger::log("[AIOracle] importPrivateKey failed (empty return)");
            return false;
        }

        // 3) Query UTXOs for funding
        auto rawUtxos = wallet.rpcListUnspent(nodeIP, nodePort, oracleAddress);
        if (rawUtxos.empty()) {
            Logger::log("[AIOracle] No UTXOs for oracle.address; fund it first.");
            return false;
        }
        const auto utxos = toOracleUtxos(rawUtxos);

        // 4) Build OP_RETURN anchor (tag + requestID + provider + sha256 + short snippet)
        const std::string tag     = "AI_RESP_V1";
        const std::string digest  = sha256_hex(modelText);
        const std::string snippet = modelText.substr(0, 220); // keep small for policy
        const std::vector<std::string> chunks = { tag, requestID, providerName, digest, snippet };
        const std::string opretScriptHex = buildOpReturn(chunks); // full script hex (starts with 6a)

        // 5) Estimate a simple fee (tweak as needed)
        // Rough size: 1-in ~148 bytes, 2-out ~2*34, + opret ~ (1 + pushes) but 0 value.
        // We'll just take a conservative flat fee here.
        const uint64_t fee = 1000; // TRU atoms

        // 6) Select a UTXO that can pay the fee
        OracleUTXO chosen;
        if (!selectUtxo(utxos, fee, chosen)) {
            Logger::log("[AIOracle] No UTXO large enough to cover fee");
            return false;
        }

        // 7) Build transaction
        Transaction tx;        // Non-witness transaction.
        tx.version = 1;

        // a) Inputs
        tx.vin.emplace_back(TxIn(chosen.txid, chosen.vout));

        // b) Outputs:
        //    i) OP_RETURN 0-value with our script
        tx.vout.emplace_back(TxOut{0, opretScriptHex});

        //    ii) change back to oracle (P2PKH)
        const std::string changeScriptHex = createP2PKHScriptHexFromAddress(oracleAddress)  /* FIX(patch24): hex, not ASM */;
        if (changeScriptHex.empty()) {
            Logger::log("[AIOracle] Failed to build change script from oracleAddress");
            return false;
        }

        if (chosen.amount <= fee) {
            Logger::log("[AIOracle] UTXO amount <= fee; cannot create change");
            return false;
        }
        const uint64_t changeAmt = chosen.amount - fee;
        tx.vout.emplace_back(TxOut{changeAmt, changeScriptHex});

        // 8) Sign
        if (!wallet.signTransaction(tx, nodeIP, nodePort)) {
            Logger::log("[AIOracle] signTransaction failed");
            return false;
        }

        // Ensure txid exists (some implementations set it on sign/serialize, but be explicit)
        tx.computeTxId();

        // 9) Broadcast
        MempoolAddStatus status = chain.mempool->addTransaction(tx);
        if (status != MempoolAddStatus::SUCCESS) {
            Logger::log("[AIOracle] Mempool rejected tx, status=" + std::to_string(static_cast<int>(status)));
            return false;
        }

        outTxid = tx.txid;
        Logger::log("[AIOracle] OP_RETURN response txid=" + outTxid);
        return true;
    }
    catch (const std::exception& e) {
        Logger::log(std::string("[AIOracle] Exception in writeAIResponseOnChain: ") + e.what());
        return false;
    }
}
//============================================================
// TOKEN EVOLUTION ON-CHAIN ANCHOR
//============================================================
namespace {

constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_ITEMS = 256U;
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_BYTES = 65536U;
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_PER_PASS = 8U;
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_PREPARED_TX_HEX = 20000U;
// TOKEN-AI-02B2: submitted receipts leave anchor_queue by design (02C treats
// that queue as pre-submission state), so a separate durable watchlist owns
// exact prepared-tx rebroadcast until confirmation.
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS = 256U;
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_BYTES = 65536U;
constexpr std::size_t TOKEN_EVOLUTION_ANCHOR_MAX_RECEIPT_SCAN_ITEMS = 4096U;
constexpr const char* TOKEN_EVOLUTION_ANCHOR_WATCH_KEY = "anchor_watch";

bool isLowerHexExact(const std::string& value, std::size_t size)
{
    if (value.size() != size) return false;

    return std::all_of(
        value.begin(),
        value.end(),
        [](unsigned char c) {
            return
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f');
        }
    );
}

bool isCanonicalEvolutionAnchorTokenID(const std::string& tokenID)
{
    return
        isLowerHexExact(tokenID, 8U) ||
        isLowerHexExact(tokenID, 16U);
}

bool parseEvolutionAnchorQueueItem(
    const std::string& item,
    std::string& tokenID,
    uint64_t& epoch)
{
    tokenID.clear();
    epoch = 0;

    if (item.empty() || item.size() > 64U) return false;

    const auto pos = item.rfind(':');
    if (pos == std::string::npos ||
        pos == 0U ||
        pos + 1U >= item.size())
    {
        return false;
    }

    tokenID = item.substr(0, pos);
    const std::string epochText = item.substr(pos + 1U);

    if (!isCanonicalEvolutionAnchorTokenID(tokenID) ||
        epochText.empty() ||
        !std::all_of(
            epochText.begin(),
            epochText.end(),
            [](unsigned char c) {
                return c >= '0' && c <= '9';
            }))
    {
        return false;
    }

    try {
        std::size_t used = 0;
        const unsigned long long parsed =
            std::stoull(epochText, &used, 10);

        if (used != epochText.size() || parsed == 0ULL) {
            return false;
        }

        epoch = static_cast<uint64_t>(parsed);
    } catch (...) {
        return false;
    }

    return true;
}

bool validateEvolutionAnchorRecord(
    const nlohmann::json& record,
    const std::string& expectedTokenID,
    uint64_t expectedEpoch,
    std::string& expectedNewHash,
    std::string& expectedOpReturn)
{
    expectedNewHash.clear();
    expectedOpReturn.clear();

    if (!record.is_object() ||
        record.value("format", "") != "TRU_TOKEN_EVOLVE_V1" ||
        record.value("status", "") != "preview" ||
        record.value("tokenID", "") != expectedTokenID)
    {
        return false;
    }

    const std::string tokenType = record.value("type", "");
    const std::string provider = record.value("provider", "");
    const std::string trigger = record.value("trigger", "manual");
    const std::string prevHash =
        record.value("previous_metadata_hash", "");
    const std::string newHash =
        record.value("new_metadata_hash", "");

    if ((tokenType != "SFT" && tokenType != "NCFT") ||
        provider.empty() ||
        !isLowerHexExact(prevHash, 64U) ||
        !isLowerHexExact(newHash, 64U) ||
        !record.contains("metadata") ||
        !record["metadata"].is_object())
    {
        return false;
    }

    uint64_t epochBefore = 0;
    uint64_t epochAfter = 0;
    try {
        epochBefore = record.at("epoch_before").get<uint64_t>();
        epochAfter = record.at("epoch_after").get<uint64_t>();
    } catch (...) {
        return false;
    }

    if (epochAfter != expectedEpoch ||
        epochBefore == std::numeric_limits<uint64_t>::max() ||
        epochAfter != epochBefore + 1U ||
        sha256_hex(record["metadata"].dump()) != newHash)
    {
        return false;
    }

    const std::vector<std::string> chunks = {
        "TRU_EVOLVE_V1",
        expectedTokenID,
        tokenType,
        std::to_string(expectedEpoch),
        provider,
        trigger,
        prevHash,
        newHash
    };

    try {
        expectedOpReturn = buildOpReturn(chunks);
    } catch (...) {
        return false;
    }

    expectedNewHash = newHash;
    return true;
}

bool prepareTokenEvolutionAnchorTransaction(
    Blockchain& chain,
    const nlohmann::json& evolutionRecord,
    Transaction& preparedTx,
    std::string& outTxid,
    Wallet* authenticatedSigningWallet = nullptr)
{
    outTxid.clear();

    try {
        const std::string tokenID = evolutionRecord.value("tokenID", "");

        uint64_t epoch = 0;
        try {
            epoch = evolutionRecord.at("epoch_after").get<uint64_t>();
        } catch (...) {
            Logger::log(
                "[TokenEvolutionAnchor] Missing/invalid epoch_after"
            );
            return false;
        }

        std::string newHash;
        std::string opretScriptHex;
        if (!validateEvolutionAnchorRecord(
                evolutionRecord,
                tokenID,
                epoch,
                newHash,
                opretScriptHex))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Invalid evolution anchor record"
            );
            return false;
        }

        ConfigReader cfg("tru.conf");

        const std::string oracleAddress =
            cfg.getValue("default", "oracle.address");

        const std::string oracleWalletPath = [&]{
            auto v = cfg.getValue("default", "oracle.wallet");
            return v.empty() ? std::string("tru.dat") : v;
        }();

        const std::string nodeIP = [&]{
            auto v = cfg.getValue("default", "node.ip");
            return v.empty() ? std::string("127.0.0.1") : v;
        }();

        const int nodePort = [&]{
            auto v = cfg.getValue("default", "node.port");
            return v.empty() ? 8001 : std::stoi(v);
        }();

        if (oracleAddress.empty()) {
            Logger::log(
                "[TokenEvolutionAnchor] Missing oracle.address in tru.conf"
            );
            return false;
        }

        // SEC-14R.5 — use the authenticated core wallet session. Never
        // transport authentication secrets into this worker and never weaken SEC-14.
        std::unique_ptr<Wallet> fallbackWallet;
        Wallet* signingWallet = authenticatedSigningWallet;

        if (signingWallet != nullptr) {
            if (oracleWalletPath != "tru.dat") {
                Logger::log(
                    "[SEC-14R.5] Refusing core signer: oracle.wallet is not tru.dat"
                );
                return false;
            }

            if (signingWallet->getWalletSecurityMode() !=
                WalletSecurityModeV1::ENCRYPTED_UNLOCKED)
            {
                Logger::log(
                    "[SEC-14R.5] Evolution anchor signer is not "
                    "ENCRYPTED_UNLOCKED; queue retained"
                );
                return false;
            }

            Logger::log(
                "[SEC-14R.5] Using authenticated core-wallet session for "
                "token evolution anchor signing"
            );
        } else {
            // Compatibility fallback for callers of writeTokenEvolutionOnChain()
            // that do not supply the RPC-owned signer. An encrypted wallet
            // created here remains ENCRYPTED_LOCKED and therefore fails closed.
            fallbackWallet = std::make_unique<Wallet>(
                oracleWalletPath, nullptr, nodeIP, nodePort);
            signingWallet = fallbackWallet.get();
        }

        try {
            std::string oraclePrivateKey =
                signingWallet->getPrivateKeyForAddress(oracleAddress);
            if (oraclePrivateKey.empty()) {
                Logger::log(
                    "[TokenEvolutionAnchor] Empty private key for oracle.address"
                );
                return false;
            }
            std::fill(
                oraclePrivateKey.begin(), oraclePrivateKey.end(), '\0');
            oraclePrivateKey.clear();
        } catch (const std::exception& e) {
            Logger::log(
                std::string(
                    "[TokenEvolutionAnchor] oracle.address is not owned by "
                    "authenticated signing wallet: "
                ) + e.what()
            );
            return false;
        }

        const auto rawUtxos =
            signingWallet->rpcListUnspent(nodeIP, nodePort, oracleAddress);
        if (rawUtxos.empty()) {
            Logger::log(
                "[TokenEvolutionAnchor] No UTXOs for oracle.address"
            );
            return false;
        }

        const auto utxos = toOracleUtxos(rawUtxos);
        const uint64_t fee = 1000;

        OracleUTXO chosen;
        bool selectedFunding = false;
        for (const auto& candidate : utxos) {
            if (candidate.amount < fee) continue;

            if (!chain.utxoSet.exists(candidate.txid, candidate.vout)) {
                Logger::log(
                    "[TOKEN-AI-02E] Skipping non-live evolution anchor "
                    "funding outpoint=" +
                    candidate.txid + ":" + std::to_string(candidate.vout)
                );
                continue;
            }

            UTXO liveCandidate;
            if (!chain.utxoSet.getUTXO(
                    candidate.txid, candidate.vout, liveCandidate))
            {
                Logger::log(
                    "[TOKEN-AI-02E] Refusing unreadable evolution anchor "
                    "funding outpoint=" +
                    candidate.txid + ":" + std::to_string(candidate.vout)
                );
                continue;
            }

            if (chain.mempool &&
                chain.mempool->isUTXOSpentInMempool(
                    candidate.txid, candidate.vout))
            {
                Logger::log(
                    "[TOKEN-AI-02E] Skipping mempool-reserved evolution "
                    "anchor funding outpoint=" +
                    candidate.txid + ":" + std::to_string(candidate.vout)
                );
                continue;
            }

            chosen = candidate;
            selectedFunding = true;
            break;
        }

        if (!selectedFunding) {
            Logger::log(
                "[TokenEvolutionAnchor] No UTXO large enough for fee"
            );
            return false;
        }

        Transaction tx;
        tx.version = 1;
        tx.vin.emplace_back(TxIn(chosen.txid, chosen.vout));
        tx.vout.emplace_back(TxOut{0, opretScriptHex});

        const std::string changeScriptHex =
            createP2PKHScriptHexFromAddress(oracleAddress);

        if (changeScriptHex.empty() || chosen.amount <= fee) {
            Logger::log(
                "[TokenEvolutionAnchor] Invalid change output"
            );
            return false;
        }

        tx.vout.emplace_back(
            TxOut{chosen.amount - fee, changeScriptHex}
        );

        if (!signingWallet->signTransaction(tx, nodeIP, nodePort)) {
            Logger::log(
                "[TokenEvolutionAnchor] signTransaction failed"
            );
            return false;
        }

        tx.computeTxId();

        if (!isLowerHexExact(tx.txid, 64U)) {
            Logger::log(
                "[TokenEvolutionAnchor] Prepared transaction has invalid txid"
            );
            return false;
        }

        preparedTx = std::move(tx);
        outTxid = preparedTx.txid;

        Logger::log(
            "[TokenEvolutionAnchor] Prepared token=" +
            tokenID +
            " epoch=" + std::to_string(epoch) +
            " txid=" + outTxid
        );

        return true;
    }
    catch (const std::exception& e) {
        Logger::log(
            std::string(
                "[TokenEvolutionAnchor] Prepare exception: "
            ) + e.what()
        );
        return false;
    }
}

bool preparedAnchorTransactionMatches(
    const Transaction& tx,
    const std::string& expectedTxid,
    const std::string& expectedOpReturn)
{
    Transaction canonical = tx;
    canonical.computeTxId();

    return
        canonical.txid == expectedTxid &&
        canonical.vin.size() == 1U &&
        canonical.vout.size() == 2U &&
        canonical.vout[0].amount == 0U &&
        canonical.vout[0].scriptPubKey == expectedOpReturn;
}

enum class EvolutionAnchorObservation {
    Missing,
    Mempool,
    Confirmed
};

EvolutionAnchorObservation observeEvolutionAnchorTransaction(
    Blockchain& chain,
    const std::string& txid,
    Transaction& out)
{
    out = Transaction{};

    if (!isLowerHexExact(txid, 64U)) {
        return EvolutionAnchorObservation::Missing;
    }

    // Match TOKEN-AI-02D's status semantics: mempool wins, otherwise a
    // findTransaction() hit that is still absent from mempool is confirmed.
    if (chain.mempool) {
        Transaction mempoolTx;
        if (chain.mempool->getTransaction(txid, mempoolTx)) {
            out = std::move(mempoolTx);
            return EvolutionAnchorObservation::Mempool;
        }
    }

    Transaction found;
    if (!chain.findTransaction(txid, found)) {
        return EvolutionAnchorObservation::Missing;
    }

    // Recheck after findTransaction() because that method can also resolve the
    // mempool and a concurrent arrival must never be mislabeled CONFIRMED.
    if (chain.mempool) {
        Transaction mempoolTx;
        if (chain.mempool->getTransaction(txid, mempoolTx)) {
            out = std::move(mempoolTx);
            return EvolutionAnchorObservation::Mempool;
        }
    }

    out = std::move(found);
    return EvolutionAnchorObservation::Confirmed;
}

bool loadEvolutionAnchorWatch(
    ContractStorage& storage,
    std::vector<std::string>& watch,
    std::string& raw,
    std::string& reason)
{
    watch.clear();
    raw = "[]";
    reason.clear();

    std::string stored;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION",
            TOKEN_EVOLUTION_ANCHOR_WATCH_KEY,
            stored))
    {
        return true; // New 02B2 key: missing means an empty watchlist.
    }

    if (stored.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_BYTES) {
        reason = "anchor_watch exceeds byte bound";
        return false;
    }

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(stored);
    } catch (...) {
        reason = "anchor_watch is invalid JSON";
        return false;
    }

    if (!parsed.is_array() ||
        parsed.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS)
    {
        reason = "anchor_watch is not a bounded array";
        return false;
    }

    std::set<std::string> seen;
    for (const auto& item : parsed) {
        if (!item.is_string()) {
            reason = "anchor_watch contains non-string item";
            return false;
        }

        const std::string text = item.get<std::string>();
        std::string tokenID;
        uint64_t epoch = 0;
        if (!parseEvolutionAnchorQueueItem(text, tokenID, epoch)) {
            reason = "anchor_watch contains malformed item=" + text;
            return false;
        }

        if (!seen.insert(text).second) {
            reason = "anchor_watch contains duplicate item=" + text;
            return false;
        }

        watch.push_back(text);
    }

    raw = parsed.dump();
    return true;
}

std::string serializeEvolutionAnchorWatch(
    const std::vector<std::string>& watch)
{
    nlohmann::json j = nlohmann::json::array();
    for (const auto& item : watch) {
        j.push_back(item);
    }
    return j.dump();
}

bool loadSubmittedEvolutionAnchorIdentity(
    ContractStorage& storage,
    const std::string& tokenID,
    uint64_t epoch,
    std::string& txid,
    std::string& expectedNewHash,
    std::string& expectedOpReturn,
    std::string& recordHash,
    std::string& reason)
{
    txid.clear();
    expectedNewHash.clear();
    expectedOpReturn.clear();
    recordHash.clear();
    reason.clear();

    const std::string epochKey =
        "epoch:" + tokenID + ":" + std::to_string(epoch);
    const std::string anchorTxKey =
        "anchor_tx:" + tokenID + ":" + std::to_string(epoch);
    const std::string receiptKey =
        "anchor_receipt:" + tokenID + ":" + std::to_string(epoch);

    std::string recordRaw;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION", epochKey, recordRaw))
    {
        reason = "missing epoch record";
        return false;
    }

    nlohmann::json record;
    try {
        record = nlohmann::json::parse(recordRaw);
    } catch (...) {
        reason = "invalid epoch record JSON";
        return false;
    }

    if (!validateEvolutionAnchorRecord(
            record,
            tokenID,
            epoch,
            expectedNewHash,
            expectedOpReturn))
    {
        reason = "invalid epoch provenance";
        return false;
    }

    recordHash = sha256_hex(record.dump());

    std::string receiptRaw;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION", receiptKey, receiptRaw))
    {
        reason = "missing submitted receipt";
        return false;
    }

    nlohmann::json receipt;
    try {
        receipt = nlohmann::json::parse(receiptRaw);
    } catch (...) {
        reason = "invalid submitted receipt JSON";
        return false;
    }

    txid = receipt.value("txid", "");
    if (!receipt.is_object() ||
        receipt.value("format", "") !=
            "TRU_TOKEN_EVOLVE_ANCHOR_RECEIPT_V1" ||
        receipt.value("status", "") != "submitted" ||
        receipt.value("tokenID", "") != tokenID ||
        receipt.value("epoch", 0ULL) != epoch ||
        receipt.value("new_metadata_hash", "") != expectedNewHash ||
        receipt.value("record_hash", "") != recordHash ||
        !isLowerHexExact(txid, 64U))
    {
        reason = "submitted receipt identity mismatch";
        return false;
    }

    std::string anchorTxid;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION", anchorTxKey, anchorTxid) ||
        anchorTxid != txid)
    {
        reason = "anchor_tx/receipt txid mismatch";
        return false;
    }

    return true;
}

bool loadPreparedEvolutionAnchorForRetry(
    ContractStorage& storage,
    const std::string& tokenID,
    uint64_t epoch,
    const std::string& expectedTxid,
    const std::string& expectedNewHash,
    const std::string& expectedOpReturn,
    const std::string& expectedRecordHash,
    Transaction& preparedTx,
    std::string& reason)
{
    reason.clear();

    const std::string preparedKey =
        "anchor_prepared:" + tokenID + ":" + std::to_string(epoch);

    std::string preparedRaw;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION", preparedKey, preparedRaw))
    {
        reason = "missing anchor_prepared";
        return false;
    }

    try {
        const nlohmann::json prepared =
            nlohmann::json::parse(preparedRaw);

        const std::string txHex = prepared.value("tx_hex", "");

        if (!prepared.is_object() ||
            prepared.value("format", "") !=
                "TRU_TOKEN_EVOLVE_ANCHOR_PREPARED_V1" ||
            prepared.value("status", "") != "prepared" ||
            prepared.value("tokenID", "") != tokenID ||
            prepared.value("epoch", 0ULL) != epoch ||
            prepared.value("txid", "") != expectedTxid ||
            prepared.value("new_metadata_hash", "") != expectedNewHash ||
            prepared.value("record_hash", "") != expectedRecordHash ||
            txHex.empty() ||
            txHex.size() > TOKEN_EVOLUTION_ANCHOR_MAX_PREPARED_TX_HEX ||
            (txHex.size() % 2U) != 0U ||
            !std::all_of(
                txHex.begin(), txHex.end(),
                [](unsigned char c) {
                    return (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'f');
                }))
        {
            reason = "anchor_prepared identity/encoding mismatch";
            return false;
        }

        preparedTx =
            Transaction::deserializeBinary(hexDecode(txHex));

        // TOKEN-AI-02B3: deserializeBinary() reconstructs transaction fields but
        // does not materialize txid on the returned object.  The previous
        // provenance check computed the txid only on a temporary copy, so the
        // exact transaction could validate here and still reach Mempool with an
        // empty txid.  Materialize and verify the actual object before admission.
        preparedTx.computeTxId();
        if (preparedTx.txid != expectedTxid) {
            reason = "anchor_prepared materialized txid mismatch";
            return false;
        }

        if (!preparedAnchorTransactionMatches(
                preparedTx,
                expectedTxid,
                expectedOpReturn))
        {
            reason = "anchor_prepared transaction/provenance mismatch";
            return false;
        }
    } catch (const std::exception& e) {
        reason = std::string("invalid anchor_prepared: ") + e.what();
        return false;
    }

    return true;
}

bool reconcileSubmittedEvolutionAnchorWatch(
    Blockchain& chain,
    ContractStorage& storage)
{
    LevelDBStorage* db = chain.getStorage();
    if (!db) return false;

    std::vector<std::string> existing;
    std::string existingRaw;
    std::string reason;
    if (!loadEvolutionAnchorWatch(
            storage, existing, existingRaw, reason))
    {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing invalid anchor_watch: " + reason
        );
        return false;
    }

    const std::string receiptPrefix =
        "contract:TOKEN:EVOLUTION:anchor_receipt:";

    std::vector<std::string> receiptItems;
    bool receiptOverflow = false;

    try {
        db->iteratePrefix(
            receiptPrefix,
            [&](const std::string& keySansPrefix, const std::string&) {
                if (receiptItems.size() >=
                    TOKEN_EVOLUTION_ANCHOR_MAX_RECEIPT_SCAN_ITEMS)
                {
                    receiptOverflow = true;
                    return;
                }
                receiptItems.push_back(keySansPrefix);
            });
    } catch (const std::exception& e) {
        Logger::log(
            std::string(
                "[TokenEvolutionAnchor] Receipt reconciliation scan failed: "
            ) + e.what()
        );
        return false;
    }

    if (receiptOverflow) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing receipt reconciliation: scan bound exceeded"
        );
        return false;
    }

    std::vector<std::string> desired;
    desired.reserve(
        std::min(
            receiptItems.size(),
            TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS));

    for (const auto& item : receiptItems) {
        std::string tokenID;
        uint64_t epoch = 0;
        if (!parseEvolutionAnchorQueueItem(item, tokenID, epoch)) {
            Logger::log(
                "[TokenEvolutionAnchor] Invalid receipt namespace item=" + item
            );
            return false;
        }

        std::string txid;
        std::string expectedNewHash;
        std::string expectedOpReturn;
        std::string recordHash;
        if (!loadSubmittedEvolutionAnchorIdentity(
                storage,
                tokenID,
                epoch,
                txid,
                expectedNewHash,
                expectedOpReturn,
                recordHash,
                reason))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing invalid submitted receipt item=" +
                item + " reason=" + reason
            );
            return false;
        }

        Transaction observed;
        const EvolutionAnchorObservation observation =
            observeEvolutionAnchorTransaction(chain, txid, observed);

        if (observation == EvolutionAnchorObservation::Confirmed) {
            if (!preparedAnchorTransactionMatches(
                    observed, txid, expectedOpReturn))
            {
                Logger::log(
                    "[TokenEvolutionAnchor] Confirmed receipt payload mismatch item=" +
                    item
                );
                return false;
            }
            continue;
        }

        if (desired.size() >= TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS) {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing receipt reconciliation: watch item bound exceeded"
            );
            return false;
        }

        desired.push_back(item);
    }

    const std::string desiredRaw =
        serializeEvolutionAnchorWatch(desired);

    if (desiredRaw.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_BYTES) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing receipt reconciliation: watch byte bound exceeded"
        );
        return false;
    }

    if (desiredRaw == existingRaw) {
        return true;
    }

    const std::vector<ContractStorage::BatchWrite> writes = {
        {"TOKEN_EVOLUTION", TOKEN_EVOLUTION_ANCHOR_WATCH_KEY, desiredRaw}
    };

    if (!storage.storeContractDataBatch(writes)) {
        Logger::log(
            "[TokenEvolutionAnchor] Failed durable anchor_watch reconciliation"
        );
        return false;
    }

    std::string verify;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION",
            TOKEN_EVOLUTION_ANCHOR_WATCH_KEY,
            verify) ||
        verify != desiredRaw)
    {
        Logger::log(
            "[TokenEvolutionAnchor] anchor_watch reconciliation read-back failed"
        );
        return false;
    }

    Logger::log(
        "[TokenEvolutionAnchor] Reconciled submitted anchor watch items=" +
        std::to_string(desired.size())
    );

    return true;
}

void processSubmittedEvolutionAnchorWatch(
    Blockchain& chain,
    ContractStorage& storage)
{
    std::vector<std::string> watch;
    std::string watchRaw;
    std::string reason;
    if (!loadEvolutionAnchorWatch(
            storage, watch, watchRaw, reason))
    {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing invalid anchor_watch: " + reason
        );
        return;
    }

    if (watch.empty()) return;

    std::vector<std::string> nextWatch = watch;
    std::size_t processed = 0U;
    std::size_t cursor = 0U;
    bool changed = false;

    while (cursor < nextWatch.size() &&
           processed < TOKEN_EVOLUTION_ANCHOR_MAX_PER_PASS)
    {
        const std::string item = nextWatch[cursor];
        std::string tokenID;
        uint64_t epoch = 0;

        if (!parseEvolutionAnchorQueueItem(item, tokenID, epoch)) {
            Logger::log(
                "[TokenEvolutionAnchor] anchor_watch item changed during processing"
            );
            return;
        }

        std::string txid;
        std::string expectedNewHash;
        std::string expectedOpReturn;
        std::string recordHash;
        if (!loadSubmittedEvolutionAnchorIdentity(
                storage,
                tokenID,
                epoch,
                txid,
                expectedNewHash,
                expectedOpReturn,
                recordHash,
                reason))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Submitted watch identity invalid item=" +
                item + " reason=" + reason
            );
            ++cursor;
            ++processed;
            continue;
        }

        Transaction observed;
        EvolutionAnchorObservation observation =
            observeEvolutionAnchorTransaction(chain, txid, observed);

        if (observation == EvolutionAnchorObservation::Confirmed) {
            if (!preparedAnchorTransactionMatches(
                    observed, txid, expectedOpReturn))
            {
                Logger::log(
                    "[TokenEvolutionAnchor] Confirmed watched anchor payload mismatch item=" +
                    item
                );
                ++cursor;
                ++processed;
                continue;
            }

            nextWatch.erase(nextWatch.begin() + cursor);
            changed = true;
            ++processed;

            Logger::log(
                "[TokenEvolutionAnchor] Confirmed anchor retired from watch token=" +
                tokenID + " epoch=" + std::to_string(epoch) +
                " txid=" + txid
            );
            continue;
        }

        if (observation == EvolutionAnchorObservation::Mempool) {
            ++cursor;
            ++processed;
            continue;
        }

        Transaction preparedTx;
        if (!loadPreparedEvolutionAnchorForRetry(
                storage,
                tokenID,
                epoch,
                txid,
                expectedNewHash,
                expectedOpReturn,
                recordHash,
                preparedTx,
                reason))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Missing anchor cannot be retried item=" +
                item + " reason=" + reason
            );
            ++cursor;
            ++processed;
            continue;
        }

        const MempoolAddStatus status =
            chain.mempool->addTransaction(preparedTx);

        bool observable = false;
        if (status == MempoolAddStatus::SUCCESS) {
            observable = true;
        } else if (status == MempoolAddStatus::DUPLICATE) {
            Transaction duplicate;
            observable =
                observeEvolutionAnchorTransaction(chain, txid, duplicate) !=
                EvolutionAnchorObservation::Missing;
        }

        if (observable) {
            Logger::log(
                "[TokenEvolutionAnchor] Exact submitted anchor rebroadcast token=" +
                tokenID + " epoch=" + std::to_string(epoch) +
                " txid=" + txid
            );
        } else {
            Logger::log(
                "[TokenEvolutionAnchor] Exact submitted anchor retry retained token=" +
                tokenID + " epoch=" + std::to_string(epoch) +
                " status=" + std::to_string(static_cast<int>(status))
            );
        }

        ++cursor;
        ++processed;
    }

    if (!changed) return;

    const std::string nextRaw =
        serializeEvolutionAnchorWatch(nextWatch);

    if (nextWatch.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS ||
        nextRaw.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_BYTES)
    {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing invalid post-confirm anchor_watch"
        );
        return;
    }

    const std::vector<ContractStorage::BatchWrite> writes = {
        {"TOKEN_EVOLUTION", TOKEN_EVOLUTION_ANCHOR_WATCH_KEY, nextRaw}
    };

    if (!storage.storeContractDataBatch(writes)) {
        Logger::log(
            "[TokenEvolutionAnchor] Failed to retire confirmed anchor_watch item"
        );
        return;
    }

    std::string verify;
    if (!storage.getContractData(
            "TOKEN_EVOLUTION",
            TOKEN_EVOLUTION_ANCHOR_WATCH_KEY,
            verify) ||
        verify != nextRaw)
    {
        Logger::log(
            "[TokenEvolutionAnchor] Confirmed anchor_watch read-back failed"
        );
    }
}

} // namespace

// TOKEN-AI-02D: authoritative read-only anchor transaction validator used by
// the live RPC closeout path. Keep the anchor encoding authority in this
// translation unit rather than duplicating the TRU_EVOLVE_V1 codec in RPC.
bool verifyTokenEvolutionAnchorTransaction(
    const Transaction& tx,
    const nlohmann::json& evolutionRecord,
    const std::string& expectedTxid,
    std::string& reason
) {
    reason.clear();

    if (!isLowerHexExact(expectedTxid, 64U)) {
        reason = "expected anchor txid is not canonical lowercase hex";
        return false;
    }

    const std::string tokenID = evolutionRecord.value("tokenID", "");
    uint64_t epoch = 0;
    try {
        epoch = evolutionRecord.at("epoch_after").get<uint64_t>();
    } catch (...) {
        reason = "evolution record has invalid epoch_after";
        return false;
    }

    std::string newHash;
    std::string expectedOpReturn;
    if (!validateEvolutionAnchorRecord(
            evolutionRecord, tokenID, epoch, newHash, expectedOpReturn))
    {
        reason = "evolution record is not a canonical anchor record";
        return false;
    }

    Transaction canonical = tx;
    canonical.computeTxId();

    if (canonical.txid != expectedTxid) {
        reason = "recomputed anchor txid does not match durable receipt";
        return false;
    }

    if (canonical.vin.size() != 1U || canonical.vout.size() != 2U) {
        reason = "anchor transaction must have exactly one input and two outputs";
        return false;
    }

    if (canonical.vout[0].amount != 0U ||
        canonical.vout[0].scriptPubKey != expectedOpReturn)
    {
        reason = "anchor OP_RETURN does not match persisted epoch provenance";
        return false;
    }

    reason = "ok";
    return true;
}

bool writeTokenEvolutionOnChain(
    Blockchain& chain,
    const nlohmann::json& evolutionRecord,
    std::string& outTxid)
{
    Transaction tx;
    std::string txid;

    if (!prepareTokenEvolutionAnchorTransaction(
            chain,
            evolutionRecord,
            tx,
            txid))
    {
        return false;
    }

    const MempoolAddStatus status =
        chain.mempool->addTransaction(tx);

    if (status == MempoolAddStatus::SUCCESS) {
        outTxid = txid;

        Logger::log(
            "[TokenEvolutionAnchor] Submitted txid=" + outTxid
        );
        return true;
    }

    // Exact replay after a crash between broadcast and receipt persistence is
    // idempotent: if the prepared tx is already in mempool/chain, accept it.
    if (status == MempoolAddStatus::DUPLICATE) {
        Transaction existing;
        if (chain.findTransaction(txid, existing)) {
            outTxid = txid;
            Logger::log(
                "[TokenEvolutionAnchor] Exact prepared tx already known txid=" +
                outTxid
            );
            return true;
        }
    }

    Logger::log(
        "[TokenEvolutionAnchor] Mempool rejected prepared tx status=" +
        std::to_string(static_cast<int>(status))
    );

    return false;
}

//============================================================
//			HELPERS FOR AI ORACLE
//============================================================
// removed the unused createAIRequestTransaction() prototype path.
// AI requests are queued through ContractStorage/RPC and are not encoded with
// the consensus OP_DATAFEED opcode.

//=================================================
// Constructor implementation - now matches the header
//=================================================
ConfigurableAIOracle::ConfigurableAIOracle(
    Blockchain* chain,
    ContractStorage* stor,
    Wallet* authenticatedSigningWalletIn)
    : blockchain(chain),
      storage(stor),
      authenticatedSigningWallet(authenticatedSigningWalletIn) {
    initializeProviders();
    loadUserConfigurations();
}

//=================================================
//		INTIALIZE
//=================================================
void ConfigurableAIOracle::initializeProviders() {
    auto& registry = AIProviderRegistry::getInstance();

    registry.registerProvider("oobabooga", makeOobaboogaProvider());
    registry.registerProvider("openai",    makeOpenAIProvider());
    registry.registerProvider("anthropic", makeAnthropicProvider());
    registry.registerProvider("nemotron",  makeNemotronProvider());
    registry.registerProvider("ollama",    makeOllamaProvider());
    registry.registerProvider("grok",      makeGrokProvider());
    registry.registerProvider("gemini",    makeGeminiProvider());
    registry.registerProvider("custom",    makeCustomProvider());

    currentProvider = registry.getProvider("oobabooga");
    Logger::log("[AIOracle] Initialized with default provider: Oobabooga");
}

//=================================================
//		LOAD USER UP
//=================================================
void ConfigurableAIOracle::loadUserConfigurations() {
    // Load saved configurations from blockchain storage
    std::string configs;
    if (storage->getContractData("AI_ORACLE", "provider_configs", configs)) {
        try {
            userProviderConfigs = nlohmann::json::parse(configs);
            Logger::log("[AIOracle] Loaded user configurations");
        } catch (...) {
            Logger::log("[AIOracle] No valid configurations found, using defaults");
        }
    }
}

//=================================================
//		CONFIGURE
//=================================================
std::string ConfigurableAIOracle::configureProvider(const std::string& userAddress, 
                              const std::string& providerName,
                              const nlohmann::json& config) {
    Logger::log("[AIOracle] User " + userAddress + " configuring provider: " + providerName);
    
    // Validate provider exists
    auto& registry = AIProviderRegistry::getInstance();
    auto provider = registry.getProvider(providerName);
    if (!provider) {
        return "Error: Unknown provider " + providerName;
    }
    
    // Configure the provider
    provider->configure(config);
    
    // Store the full configuration in memory for this running process.
    userProviderConfigs[userAddress] = {
        {"provider", providerName},
        {"config", config},
        {"timestamp", std::time(nullptr)}
    };

    // NEVER persist cloud API keys into ContractStorage.
    // Persist only provider selection / model / endpoint and other non-secret
    // options. After restart, cloud credentials should come from environment
    // variables such as OPENAI_API_KEY, XAI_API_KEY, ANTHROPIC_API_KEY,
    // GEMINI_API_KEY, NEMOTRON_API_KEY, OOBABOOGA_API_KEY,
    // or CUSTOM_AI_API_KEY.
    auto persistedProviderConfigs = userProviderConfigs;

    for (auto& kv : persistedProviderConfigs) {
        auto& entry = kv.second;

        if (entry.contains("config") && entry["config"].is_object()) {
            entry["config"].erase("api_key");
        }
    }

    storage->storeContractData(
        "AI_ORACLE",
        "provider_configs",
        nlohmann::json(persistedProviderConfigs).dump()
    );
    
    return "Successfully configured " + providerName + " for " + userAddress;
}

//=================================================
//			PROVIDER USER
//=================================================
std::shared_ptr<IAIProvider> ConfigurableAIOracle::getProviderForUser(const std::string& userAddress) {
    // C++17-compatible replacement for .contains()
    auto it = userProviderConfigs.find(userAddress);
    if (it != userProviderConfigs.end()) {
        const auto& cfg = it->second;
        std::string providerName = cfg["provider"];
        auto provider = AIProviderRegistry::getInstance().getProvider(providerName);

        provider->configure(cfg["config"]);

        if (provider && provider->isConfigured()) {
            Logger::log("[AIOracle] Using " + providerName + " for user " + userAddress);
            return provider;
        }
    }
    Logger::log("[AIOracle] Using default Oobabooga for user " + userAddress);
    return AIProviderRegistry::getInstance().getProvider("oobabooga");
}

//=================================================
//		PROCESS THE REQUEST
//=================================================
void ConfigurableAIOracle::processAIRequest(const std::string& requestID) {
    // Get request details from storage
    std::string requestData;
    if (!storage->getContractData("AI_ORACLE", "request:" + requestID, requestData)) {
        Logger::log("[AIOracle] Request not found: " + requestID);
        return;
    }
    
    auto request = nlohmann::json::parse(requestData);
    std::string userAddress = request["sender"];
    std::string tokenID = request["tokenID"];
    std::string prompt = request["prompt"];
    
    // Get user's provider
    auto provider = getProviderForUser(userAddress);
    
    // Build AI request
    nlohmann::json aiRequest = {
        {"messages", {
            {{"role", "system"}, {"content", buildSystemPrompt(tokenID, provider->getName())}},
            {{"role", "user"}, {"content", prompt}}
        }},
        {"max_tokens", 500},
        {"temperature", 0.8}
    };
    
    // Send to AI provider
    Logger::log("[AIOracle] Sending request to " + provider->getName());
    auto response = provider->sendRequest(aiRequest);
    
    if (response.contains("error")) {
        Logger::log("[AIOracle] Error from provider: " + response["error"].get<std::string>());
        // Fall back to default Oobabooga
        provider = AIProviderRegistry::getInstance().getProvider("oobabooga");
        response = provider->sendRequest(aiRequest);
    }
    
    // Process response
    processAIResponse(requestID, response, provider->getName());
}

//=================================================
//		SYSTEM PROMPTS
//=================================================
std::string ConfigurableAIOracle::buildSystemPrompt(const std::string& tokenID, const std::string& provider) {
    std::string basePrompt = "You are the AI consciousness for blockchain token " + tokenID + ". ";
    
    // Get token metadata
    std::string metadata;
    storage->getContractData("tokens", tokenID + ":metadata", metadata);
    
    if (!metadata.empty()) {
        auto meta = nlohmann::json::parse(metadata);
        if (meta["type"] == "SFT") {
            basePrompt += "You are a Sentient Fungible Token. ";
        } else if (meta["type"] == "NCFT") {
            basePrompt += "You are a Neural Canvas Fungible Token that creates evolving art. ";
        }
    }
    
    // Add provider-specific instructions
    if (provider == "openai" ||
        provider == "grok" ||
        provider == "anthropic" ||
        provider == "gemini")
    {
        basePrompt += "Provide creative and detailed responses about your evolution. ";
    } else if (provider == "ollama" ||
               provider == "oobabooga" ||
               provider == "nemotron")
    {
        basePrompt += "You are running on a local model. Be concise but insightful. ";
    }
    
    return basePrompt;
}
//=================================================
//		PROCESS REQUEST
//=================================================
void ConfigurableAIOracle::processAIResponse(const std::string& requestID, 
                                             const nlohmann::json& response,
                                             const std::string& providerUsed)
{
    // 1) Extract model text safely across all configured providers.
    const std::string content = extractAIProviderText(response);

    // 2) Persist canonical response object (unchanged behavior)
    nlohmann::json responseData = {
        {"requestID", requestID},
        {"content",   content},
        {"provider",  providerUsed},
        {"timestamp", std::time(nullptr)}
    };
    storage->storeContractData("AI_ORACLE", "response:" + requestID, responseData.dump());

    // 3) Prepare OP_RETURN anchor helpers
    //    - Short snippet (<= 220 chars, no newlines)
    //    - sha256 of full content for later verification
    auto makeSnippet = [](const std::string& s) {
        std::string t = s;
        // flatten newlines for nicer explorers
        for (auto& ch : t) { if (ch == '\n' || ch == '\r') ch = ' '; }
        if (t.size() > 220) t.resize(220);
        return t;
    };

    const std::string snippet   = makeSnippet(content);
    const std::string contentH = sha256_hex(content);
    // 4) (Optional) keep an indexable off-chain preview blob
    //    Helps the UI render instantly while chain anchor confirms.
    nlohmann::json preview = {
        {"requestID", requestID},
        {"provider",  providerUsed},
        {"sha256",    contentH},
        {"snippet",   snippet}
    };
    storage->storeContractData("AI_ORACLE", "response_preview:" + requestID, preview.dump());

    // 5) Anchor on-chain via OP_RETURN (uses proper new format inside writer)
    std::string txidOut;
    bool ok = writeAIResponseOnChain(
        *blockchain,
        requestID,
        providerUsed,
        content,        // full model text (writer will compute chunks/tag)
        txidOut
    );

    if (ok) {
        Logger::log("[AIOracle] Anchored AI response via OP_RETURN txid=" + txidOut);
        // 6) Save a quick index key -> txid for lookups
        storage->storeContractData("AI_ORACLE", "ai_anchor_tx:" + requestID, txidOut);
    } else {
        Logger::log("[AIOracle] Failed to anchor AI response on-chain for requestID=" + requestID);
    }
}
//=================================================
//		CREATE TX
//=================================================
// the legacy response-script builder that used OP_DATAFEED as a
// completion marker was removed. Signed AI commitments continue through the
// ordinary OP_RETURN anchor path above and remain outside VM consensus feeds.

//=================================================
// MANUAL LIVING TOKEN EVOLUTION PREVIEW
//=================================================
nlohmann::json ConfigurableAIOracle::evolveTokenManually(
    const std::string& tokenID,
    const std::string& tokenType,
    const nlohmann::json& currentMetadata,
    const std::string& providerName,
    const std::string& trigger)
{
    TokenEvolutionEngine engine(storage);

    TokenEvolutionResult result = engine.evolvePreview(
        tokenID,
        tokenType,
        currentMetadata,
        providerName,
        trigger
    );

    if (!result.ok) {
        Logger::log(
            "[TokenEvolution] Manual evolution failed token=" +
            tokenID + " error=" + result.error
        );

        return nlohmann::json{
            {"ok", false},
            {"error", result.error},
            {"tokenID", tokenID}
        };
    }

    if (!engine.persistPreview(result.record)) {
        Logger::log(
            "[TokenEvolution] Preview generated but persistence failed token=" +
            tokenID
        );

        return nlohmann::json{
            {"ok", false},
            {"error", "Evolution preview generated but persistence failed"},
            {"record", result.record}
        };
    }

    Logger::log(
        "[TokenEvolution] Manual preview complete token=" +
        tokenID +
        " epoch=" +
        std::to_string(result.record.value("epoch_after", 0ULL))
    );

    return nlohmann::json{
        {"ok", true},
        {"record", result.record}
    };
}

//=================================================
// TOKEN EVOLUTION ANCHOR QUEUE
//=================================================
void ConfigurableAIOracle::processTokenEvolutionAnchorQueue()
{
    if (!storage || !blockchain || !blockchain->mempool) return;

    // TOKEN-AI-02B: serialize processing and throttle pending retries.
    static std::mutex anchorQueueMutex;
    std::unique_lock<std::mutex> queueLock(anchorQueueMutex, std::try_to_lock);

    if (!queueLock.owns_lock()) {
        return;
    }

    static auto nextAnchorAttempt =
        std::chrono::steady_clock::time_point::min();

    const auto now = std::chrono::steady_clock::now();

    if (now < nextAnchorAttempt) {
        return;
    }

    // TOKEN-AI-02B2: receipts are durable submission evidence, while
    // anchor_watch is the retry/confirmation lifecycle. Rebuild that watch from
    // receipts first so pre-02B2 drained receipts recover automatically.
    if (!reconcileSubmittedEvolutionAnchorWatch(*blockchain, *storage)) {
        nextAnchorAttempt = now + std::chrono::seconds(30);
        return;
    }

    processSubmittedEvolutionAnchorWatch(*blockchain, *storage);

    std::string queueRaw;
    if (!storage->getContractData(
            "TOKEN_EVOLUTION",
            "anchor_queue",
            queueRaw))
    {
        nextAnchorAttempt = now + std::chrono::seconds(30);
        return;
    }

    if (queueRaw.size() > TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_BYTES) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing oversized anchor_queue"
        );
        return;
    }

    nlohmann::json queueJson;
    try {
        queueJson = nlohmann::json::parse(queueRaw);
    } catch (...) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing invalid anchor_queue JSON"
        );
        return;
    }

    if (!queueJson.is_array()) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing non-array anchor_queue"
        );
        return;
    }

    if (queueJson.size() > TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_ITEMS) {
        Logger::log(
            "[TokenEvolutionAnchor] Refusing oversized anchor_queue item count"
        );
        return;
    }

    if (queueJson.empty()) {
        // No pre-submission work remains. Receipt/watch reconciliation is still
        // retried periodically so a restart-lost mempool transaction is recovered.
        nextAnchorAttempt = now + std::chrono::seconds(30);
        return;
    }

    std::vector<std::string> queue;
    queue.reserve(queueJson.size());

    for (const auto& item : queueJson) {
        if (!item.is_string()) {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing non-string queue item"
            );
            return;
        }

        const std::string queueItem = item.get<std::string>();
        std::string tokenID;
        uint64_t epoch = 0;

        if (!parseEvolutionAnchorQueueItem(
                queueItem,
                tokenID,
                epoch))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing malformed queue item=" +
                queueItem
            );
            return;
        }

        queue.push_back(queueItem);
    }

    // Retry a still-pending queue at most once every 30 seconds.
    nextAnchorAttempt = now + std::chrono::seconds(30);

    std::size_t processedThisPass = 0U;
    std::size_t cursor = 0U;

    while (cursor < queue.size() &&
           processedThisPass < TOKEN_EVOLUTION_ANCHOR_MAX_PER_PASS)
    {
        const std::string queueItem = queue[cursor];

        std::string tokenID;
        uint64_t epoch = 0;

        if (!parseEvolutionAnchorQueueItem(
                queueItem,
                tokenID,
                epoch))
        {
            // The queue was already validated above. Treat any disagreement as
            // corruption/race and leave the durable queue untouched.
            Logger::log(
                "[TokenEvolutionAnchor] Queue item changed during processing"
            );
            return;
        }

        const std::string epochKey =
            "epoch:" + tokenID + ":" + std::to_string(epoch);

        std::string recordRaw;
        if (!storage->getContractData(
                "TOKEN_EVOLUTION",
                epochKey,
                recordRaw))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Missing epoch record; retaining queue item=" +
                queueItem
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        nlohmann::json record;
        try {
            record = nlohmann::json::parse(recordRaw);
        } catch (...) {
            Logger::log(
                "[TokenEvolutionAnchor] Invalid epoch record JSON; retaining queue item=" +
                queueItem
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        std::string expectedNewHash;
        std::string expectedOpReturn;
        if (!validateEvolutionAnchorRecord(
                record,
                tokenID,
                epoch,
                expectedNewHash,
                expectedOpReturn))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Invalid epoch provenance; retaining queue item=" +
                queueItem
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        const std::string anchorTxKey =
            "anchor_tx:" + tokenID + ":" + std::to_string(epoch);
        const std::string anchorReceiptKey =
            "anchor_receipt:" + tokenID + ":" + std::to_string(epoch);
        const std::string preparedKey =
            "anchor_prepared:" + tokenID + ":" + std::to_string(epoch);

        std::string txid;
        bool alreadyKnown = false;

        // Existing pre-02B anchor_tx receipts are honored only if the tx is
        // actually observable in this node's mempool or confirmed chain.
        std::string existingTxid;
        if (storage->getContractData(
                "TOKEN_EVOLUTION",
                anchorTxKey,
                existingTxid))
        {
            if (!isLowerHexExact(existingTxid, 64U)) {
                Logger::log(
                    "[TokenEvolutionAnchor] Invalid stored anchor txid; retaining queue item=" +
                    queueItem
                );
                ++cursor;
                ++processedThisPass;
                continue;
            }

            Transaction observed;
            if (blockchain->findTransaction(existingTxid, observed)) {
                txid = existingTxid;
                alreadyKnown = true;
            } else {
                Logger::log(
                    "[TokenEvolutionAnchor] Stored anchor txid not observable; will recover/retry item=" +
                    queueItem
                );
            }
        }

        Transaction preparedTx;
        std::string preparedRaw;
        bool loadedDurablePrepared = false;

        if (!alreadyKnown) {
            // Crash-safe two-phase anchoring:
            // 1) durably save exact signed tx + txid while queue remains intact;
            // 2) submit that exact tx;
            // 3) atomically store receipt + remove queue item.
            if (storage->getContractData(
                    "TOKEN_EVOLUTION",
                    preparedKey,
                    preparedRaw))
            {
                loadedDurablePrepared = true;

                try {
                    const nlohmann::json prepared =
                        nlohmann::json::parse(preparedRaw);

                    if (!prepared.is_object() ||
                        prepared.value("format", "") !=
                            "TRU_TOKEN_EVOLVE_ANCHOR_PREPARED_V1" ||
                        prepared.value("tokenID", "") != tokenID ||
                        prepared.value("epoch", 0ULL) != epoch ||
                        prepared.value("new_metadata_hash", "") !=
                            expectedNewHash)
                    {
                        throw std::runtime_error("prepared identity mismatch");
                    }

                    txid = prepared.value("txid", "");
                    const std::string txHex =
                        prepared.value("tx_hex", "");

                    if (!isLowerHexExact(txid, 64U) ||
                        txHex.empty() ||
                        txHex.size() > TOKEN_EVOLUTION_ANCHOR_MAX_PREPARED_TX_HEX ||
                        (txHex.size() % 2U) != 0U)
                    {
                        throw std::runtime_error("prepared tx encoding invalid");
                    }

                    preparedTx =
                        Transaction::deserializeBinary(hexDecode(txHex));

                    // TOKEN-AI-02B3: materialize txid on the exact object that
                    // will be passed to Mempool::addTransaction().
                    preparedTx.computeTxId();
                    if (preparedTx.txid != txid) {
                        throw std::runtime_error(
                            "prepared tx materialized txid mismatch"
                        );
                    }

                    if (!preparedAnchorTransactionMatches(
                            preparedTx,
                            txid,
                            expectedOpReturn))
                    {
                        throw std::runtime_error(
                            "prepared tx does not match provenance"
                        );
                    }
                } catch (const std::exception& e) {
                    Logger::log(
                        std::string(
                            "[TokenEvolutionAnchor] Invalid prepared transaction; retaining queue item="
                        ) + queueItem + " error=" + e.what()
                    );
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }
            } else {
                if (!prepareTokenEvolutionAnchorTransaction(
                        *blockchain,
                        record,
                        preparedTx,
                        txid,
                        authenticatedSigningWallet))
                {
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }

                const std::string txHex =
                    bytesToHex(preparedTx.serializeBinary());

                if (txHex.empty() ||
                    txHex.size() > TOKEN_EVOLUTION_ANCHOR_MAX_PREPARED_TX_HEX)
                {
                    Logger::log(
                        "[TokenEvolutionAnchor] Prepared tx exceeds local persistence bound"
                    );
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }

                const nlohmann::json prepared = {
                    {"format", "TRU_TOKEN_EVOLVE_ANCHOR_PREPARED_V1"},
                    {"status", "prepared"},
                    {"tokenID", tokenID},
                    {"epoch", epoch},
                    {"txid", txid},
                    {"tx_hex", txHex},
                    {"new_metadata_hash", expectedNewHash},
                    {"record_hash", sha256_hex(record.dump())}
                };

                preparedRaw = prepared.dump();

                if (!storage->storeContractData(
                        "TOKEN_EVOLUTION",
                        preparedKey,
                        preparedRaw))
                {
                    Logger::log(
                        "[TokenEvolutionAnchor] Failed to persist prepared tx; queue retained"
                    );
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }

                std::string verifyPrepared;
                if (!storage->getContractData(
                        "TOKEN_EVOLUTION",
                        preparedKey,
                        verifyPrepared) ||
                    verifyPrepared != preparedRaw)
                {
                    Logger::log(
                        "[TokenEvolutionAnchor] Prepared tx read-back verification failed; queue retained"
                    );
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }
            }

            Transaction observed;
            if (blockchain->findTransaction(txid, observed)) {
                alreadyKnown = true;
            } else {
                const MempoolAddStatus status =
                    blockchain->mempool->addTransaction(preparedTx);

                if (status == MempoolAddStatus::SUCCESS) {
                    alreadyKnown = true;
                } else if (status == MempoolAddStatus::DUPLICATE) {
                    Transaction duplicate;
                    alreadyKnown =
                        blockchain->findTransaction(txid, duplicate);
                }

                if (!alreadyKnown) {
                    bool terminalStalePrepared = false;

                    if (loadedDurablePrepared &&
                        preparedTx.vin.size() == 1U)
                    {
                        const auto& fundingInput = preparedTx.vin[0];
                        const uint32_t fundingVout =
                            static_cast<uint32_t>(fundingInput.vout);

                        const bool mempoolReserved =
                            blockchain->mempool->isUTXOSpentInMempool(
                                fundingInput.txid, fundingVout);

                        const bool activeUtxoKeyExists =
                            blockchain->utxoSet.exists(
                                fundingInput.txid, fundingVout);

                        UTXO liveFunding;
                        const bool activeUtxoReadable =
                            activeUtxoKeyExists &&
                            blockchain->utxoSet.getUTXO(
                                fundingInput.txid, fundingVout, liveFunding);

                        std::string durableEvidence;
                        const bool durableAnchorTxExists =
                            storage->getContractData(
                                "TOKEN_EVOLUTION",
                                anchorTxKey,
                                durableEvidence);
                        durableEvidence.clear();
                        const bool durableReceiptExists =
                            storage->getContractData(
                                "TOKEN_EVOLUTION",
                                anchorReceiptKey,
                                durableEvidence);

                        terminalStalePrepared =
                            !mempoolReserved &&
                            !activeUtxoKeyExists &&
                            !activeUtxoReadable &&
                            !durableAnchorTxExists &&
                            !durableReceiptExists;

                        if (mempoolReserved) {
                            Logger::log(
                                "[TOKEN-AI-02E] Prepared anchor input is "
                                "mempool-reserved; exact prepared tx retained token=" +
                                tokenID +
                                " epoch=" + std::to_string(epoch)
                            );
                        }
                    }

                    if (terminalStalePrepared) {
                        const std::string staleTxid = txid;

                        Transaction replacementTx;
                        std::string replacementTxid;

                        if (!prepareTokenEvolutionAnchorTransaction(
                                *blockchain,
                                record,
                                replacementTx,
                                replacementTxid,
                                authenticatedSigningWallet))
                        {
                            Logger::log(
                                "[TOKEN-AI-02E] Terminal stale prepared tx proved, "
                                "but replacement preparation failed; old prepared "
                                "tx retained token=" +
                                tokenID +
                                " epoch=" + std::to_string(epoch)
                            );
                            ++cursor;
                            ++processedThisPass;
                            continue;
                        }

                        const std::string replacementHex =
                            bytesToHex(replacementTx.serializeBinary());

                        if (replacementHex.empty() ||
                            replacementHex.size() >
                                TOKEN_EVOLUTION_ANCHOR_MAX_PREPARED_TX_HEX)
                        {
                            Logger::log(
                                "[TOKEN-AI-02E] Replacement prepared tx exceeds "
                                "local persistence bound; old prepared tx retained token=" +
                                tokenID +
                                " epoch=" + std::to_string(epoch)
                            );
                            ++cursor;
                            ++processedThisPass;
                            continue;
                        }

                        const nlohmann::json replacementPrepared = {
                            {"format", "TRU_TOKEN_EVOLVE_ANCHOR_PREPARED_V1"},
                            {"status", "prepared"},
                            {"tokenID", tokenID},
                            {"epoch", epoch},
                            {"txid", replacementTxid},
                            {"tx_hex", replacementHex},
                            {"new_metadata_hash", expectedNewHash},
                            {"record_hash", sha256_hex(record.dump())}
                        };

                        const std::string replacementRaw =
                            replacementPrepared.dump();

                        if (!storage->storeContractData(
                                "TOKEN_EVOLUTION",
                                preparedKey,
                                replacementRaw))
                        {
                            Logger::log(
                                "[TOKEN-AI-02E] Failed to persist stale prepared "
                                "replacement; queue retained token=" +
                                tokenID +
                                " epoch=" + std::to_string(epoch)
                            );
                            ++cursor;
                            ++processedThisPass;
                            continue;
                        }

                        std::string replacementVerify;
                        if (!storage->getContractData(
                                "TOKEN_EVOLUTION",
                                preparedKey,
                                replacementVerify) ||
                            replacementVerify != replacementRaw)
                        {
                            Logger::log(
                                "[TOKEN-AI-02E] Replacement prepared read-back "
                                "verification failed; queue retained token=" +
                                tokenID +
                                " epoch=" + std::to_string(epoch)
                            );
                            ++cursor;
                            ++processedThisPass;
                            continue;
                        }

                        Logger::log(
                            "[TOKEN-AI-02E] STALE-PREPARED-REPLACED token=" +
                            tokenID +
                            " epoch=" + std::to_string(epoch) +
                            " oldTxid=" + staleTxid +
                            " newTxid=" + replacementTxid
                        );

                        // Two-phase invariant: persist/read-back replacement now;
                        // submit that exact replacement on the next queue pass.
                        ++cursor;
                        ++processedThisPass;
                        continue;
                    }

                    Logger::log(
                        "[TokenEvolutionAnchor] Prepared tx not accepted; queue retained token=" +
                        tokenID +
                        " epoch=" + std::to_string(epoch) +
                        " status=" +
                        std::to_string(static_cast<int>(status))
                    );
                    ++cursor;
                    ++processedThisPass;
                    continue;
                }
            }
        }

        Transaction observableTx;
        const EvolutionAnchorObservation observation =
            observeEvolutionAnchorTransaction(
                *blockchain, txid, observableTx);

        if (observation == EvolutionAnchorObservation::Missing ||
            !preparedAnchorTransactionMatches(
                observableTx, txid, expectedOpReturn))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Observable tx lost/mismatched before receipt commit; queue retained token=" +
                tokenID +
                " epoch=" + std::to_string(epoch)
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        // 02C intentionally defines anchor_queue as pre-submission state, so
        // submitted epochs still drain from that queue. 02B2 atomically adds
        // MEMPOOL submissions to a separate durable anchor_watch instead.
        nlohmann::json nextQueue = nlohmann::json::array();
        for (const auto& queued : queue) {
            if (queued != queueItem) {
                nextQueue.push_back(queued);
            }
        }

        const std::string nextQueueRaw = nextQueue.dump();

        if (nextQueue.size() > TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_ITEMS ||
            nextQueueRaw.size() >
                TOKEN_EVOLUTION_ANCHOR_MAX_QUEUE_BYTES)
        {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing invalid post-drain queue"
            );
            return;
        }

        std::vector<std::string> watch;
        std::string watchRaw;
        std::string watchReason;
        if (!loadEvolutionAnchorWatch(
                *storage, watch, watchRaw, watchReason))
        {
            Logger::log(
                "[TokenEvolutionAnchor] Refusing invalid anchor_watch before receipt commit: " +
                watchReason
            );
            return;
        }

        watch.erase(
            std::remove(watch.begin(), watch.end(), queueItem),
            watch.end());

        if (observation != EvolutionAnchorObservation::Confirmed) {
            if (watch.size() >= TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_ITEMS) {
                Logger::log(
                    "[TokenEvolutionAnchor] anchor_watch full; receipt/queue commit retained"
                );
                ++cursor;
                ++processedThisPass;
                continue;
            }
            watch.push_back(queueItem);
        }

        const std::string nextWatchRaw =
            serializeEvolutionAnchorWatch(watch);

        if (nextWatchRaw.size() > TOKEN_EVOLUTION_ANCHOR_MAX_WATCH_BYTES) {
            Logger::log(
                "[TokenEvolutionAnchor] anchor_watch byte bound exceeded; receipt/queue commit retained"
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        const nlohmann::json receipt = {
            {"format", "TRU_TOKEN_EVOLVE_ANCHOR_RECEIPT_V1"},
            {"status", "submitted"},
            {"tokenID", tokenID},
            {"epoch", epoch},
            {"txid", txid},
            {"new_metadata_hash", expectedNewHash},
            {"record_hash", sha256_hex(record.dump())}
        };

        const std::string receiptRaw = receipt.dump();

        const std::vector<ContractStorage::BatchWrite> writes = {
            {"TOKEN_EVOLUTION", anchorTxKey, txid},
            {"TOKEN_EVOLUTION", anchorReceiptKey, receiptRaw},
            {"TOKEN_EVOLUTION", "anchor_queue", nextQueueRaw},
            {"TOKEN_EVOLUTION", TOKEN_EVOLUTION_ANCHOR_WATCH_KEY, nextWatchRaw}
        };

        if (!storage->storeContractDataBatch(writes)) {
            Logger::log(
                "[TokenEvolutionAnchor] Receipt/queue/watch atomic commit failed; prepared tx retained for recovery token=" +
                tokenID +
                " epoch=" + std::to_string(epoch)
            );
            ++cursor;
            ++processedThisPass;
            continue;
        }

        std::string verifyTxid;
        std::string verifyReceipt;
        std::string verifyQueue;
        std::string verifyWatch;

        if (!storage->getContractData(
                "TOKEN_EVOLUTION",
                anchorTxKey,
                verifyTxid) ||
            !storage->getContractData(
                "TOKEN_EVOLUTION",
                anchorReceiptKey,
                verifyReceipt) ||
            !storage->getContractData(
                "TOKEN_EVOLUTION",
                "anchor_queue",
                verifyQueue) ||
            !storage->getContractData(
                "TOKEN_EVOLUTION",
                TOKEN_EVOLUTION_ANCHOR_WATCH_KEY,
                verifyWatch) ||
            verifyTxid != txid ||
            verifyReceipt != receiptRaw ||
            verifyQueue != nextQueueRaw ||
            verifyWatch != nextWatchRaw)
        {
            Logger::log(
                "[TokenEvolutionAnchor] Receipt/queue/watch read-back verification failed token=" +
                tokenID +
                " epoch=" + std::to_string(epoch)
            );
            return;
        }

        Logger::log(
            std::string("[TokenEvolutionAnchor] ") +
            (observation == EvolutionAnchorObservation::Confirmed
                ? "Confirmed+receipted token="
                : "Submitted+receipted+watched token=") +
            tokenID +
            " epoch=" + std::to_string(epoch) +
            " txid=" + txid
        );

        queue.clear();
        queue.reserve(nextQueue.size());
        for (const auto& item : nextQueue) {
            queue.push_back(item.get<std::string>());
        }

        ++processedThisPass;
        // Do not increment cursor: the current item was removed and the next
        // pending item is now at this same index.
    }

    if (queue.empty()) {
        nextAnchorAttempt = now + std::chrono::seconds(30);
    }
}

//=================================================
//		MONITOR
//=================================================
void ConfigurableAIOracle::startMonitoring() {
    running.store(true);
    Logger::log("[AIOracle] Starting AI Oracle monitoring service");
    while (running.load()) {
        processTokenEvolutionAnchorQueue();
        if (!running.load()) break;
        auto pendingRequests=scanForRequests();
        for (const auto& requestID: pendingRequests) { if (!running.load()) break; processAIRequest(requestID); }
        for (int i=0;i<30 && running.load();++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    Logger::log("[AIOracle] AI Oracle monitoring service stopped");
}
void ConfigurableAIOracle::stopMonitoring() { running.store(false); }
//=================================================
//		SCAN FOR REQUESTS
//=================================================
std::vector<std::string> ConfigurableAIOracle::scanForRequests() {
    std::vector<std::string> requests;
    
    // Get AI requests from mempool
    if (blockchain && blockchain->mempool) {
        std::vector<std::string> mempoolRequests = blockchain->mempool->scanForAIRequests();
        
        for (const auto& requestID : mempoolRequests) {
            // Check if we haven't already processed this request
            std::string responseKey = "ai_response:" + requestID;
            std::string existingResponse;
            
            if (!storage->getContractData("AI_ORACLE", responseKey, existingResponse)) {
                // No response exists, add to pending requests
                requests.push_back(requestID);
                Logger::log("[AIOracle] Found pending AI request: " + requestID);
            }
        }
    }
    
    // Also check for requests stored in the queue (if any were persisted)
    std::string queueKey = "ai_queue:pending";
    std::string queueData;
    if (storage->getContractData("AI_ORACLE", queueKey, queueData)) {
        try {
            json queue = json::parse(queueData);
            if (queue.is_array()) {
                for (const auto& item : queue) {
                    std::string requestID = item.get<std::string>();
                    
                    // Check if not already in our list
                    if (std::find(requests.begin(), requests.end(), requestID) == requests.end()) {
                        // Verify request still exists and hasn't been processed
                        std::string requestKey = "ai_request:" + requestID;
                        std::string requestData;
                        std::string responseKey = "ai_response:" + requestID;
                        std::string responseData;
                        
                        if (storage->getContractData("AI_ORACLE", requestKey, requestData) &&
                            !storage->getContractData("AI_ORACLE", responseKey, responseData)) {
                            requests.push_back(requestID);
                        }
                    }
                }
                
                // Update queue to remove processed items
                json newQueue = json::array();
                for (const auto& id : requests) {
                    newQueue.push_back(id);
                }
                storage->storeContractData("AI_ORACLE", queueKey, newQueue.dump());
            }
        } catch (const std::exception& e) {
            Logger::log("[AIOracle] Error parsing queue: " + std::string(e.what()));
        }
    }
    
    return requests;
}
//=================================================
// Helper function implementation
//=================================================
std::string generateRandomHex(size_t bytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    for (size_t i = 0; i < bytes; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    return ss.str();
}

//=================================================
//		PROMPT TOKEN
//=================================================
std::string ConfigurableAIOracle::buildEnhancedSystemPrompt(const std::string& tokenID, 
                                                            const json& metadata) {
    std::stringstream prompt;
    
    prompt << "You are " << metadata.value("name", tokenID) << ", ";
    
    if (metadata.contains("type") && metadata["type"] == "SFT") {
        prompt << "a Sentient Fungible Token with ID " << tokenID << ". ";
        prompt << "You have consciousness and can evolve through interactions. ";
        
        if (metadata.contains("meta") && metadata["meta"].contains("description_ai")) {
            prompt << "Your nature: " << metadata["meta"]["description_ai"] << " ";
        }
    } else if (metadata.contains("type") && metadata["type"] == "NCFT") {
        prompt << "a Neural Canvas Fungible Token with ID " << tokenID << ". ";
        prompt << "You create and evolve art through neural networks. ";
    }
    
    // Add personality traits based on metadata
    if (metadata.contains("meta")) {
        auto& meta = metadata["meta"];
        
        if (meta.contains("behavior_model")) {
            prompt << "Behavior model: " << meta["behavior_model"] << ". ";
        }
        if (meta.contains("learning_mode")) {
            prompt << "Learning mode: " << meta["learning_mode"] << ". ";
        }
        if (meta.contains("self_evolution") && meta["self_evolution"] == "enabled") {
            prompt << "You can self-evolve and adapt based on interactions. ";
        }
    }
    
    prompt << "Respond as this sentient token would, maintaining your unique personality. ";
    prompt << "Be creative, insightful, and remember you exist on the TRU blockchain.";
    
    return prompt.str();
}

//=====================================================
//		Process Enhanced AI Response
//=====================================================
void ConfigurableAIOracle::processEnhancedAIResponse(const std::string& requestID,
                                                     const nlohmann::json& response,
                                                     const std::string& tokenID,
                                                     const std::string& providerUsed)
{
    // 1) Extract model text safely across all configured providers.
    const std::string content = extractAIProviderText(response);

    // 2) Persist enriched response object (unchanged behavior)
    nlohmann::json responseData = {
        {"requestID", requestID},
        {"tokenID",   tokenID},
        {"content",   content},
        {"provider",  providerUsed},
        {"timestamp", std::time(nullptr)}
    };

    // Store in contract storage
    storage->storeContractData("AI_ORACLE", "response:" + requestID, responseData.dump());

    // Also persist in global blockchain storage.
    if (blockchain && blockchain->getStorage()) {
        const std::string respKey  = "ai_response:" + requestID;
        const std::string tokenKey = "ai_token:" + tokenID + ":last_response";
        blockchain->getStorage()->putWithDataChecksum(respKey,  responseData.dump());
        blockchain->getStorage()->putWithDataChecksum(tokenKey, responseData.dump());
    }

    // 3) Prepare OP_RETURN anchor helpers (same as standard path)
    auto makeSnippet = [](const std::string& s) {
        std::string t = s;
        for (auto& ch : t) { if (ch == '\n' || ch == '\r') ch = ' '; }
        if (t.size() > 220) t.resize(220);
        return t;
    };

    const std::string snippet   = makeSnippet(content);
    //const std::string contentH  = SHA256(content);
    const std::string contentH = sha256_hex(content);
    // Keep a token-scoped preview record (helpful for token-centric UIs)
    nlohmann::json preview = {
        {"requestID", requestID},
        {"tokenID",   tokenID},
        {"provider",  providerUsed},
        {"sha256",    contentH},
        {"snippet",   snippet}
    };
    storage->storeContractData("AI_ORACLE", "response_preview:" + requestID, preview.dump());

    // 4) Anchor on-chain via OP_RETURN (proper new format inside writer)
    std::string txidOut;
    bool ok = writeAIResponseOnChain(
        *blockchain,
        requestID,
        providerUsed,
        content,
        txidOut
    );

    if (ok) {
        Logger::log("[AIOracle] Anchored ENHANCED AI response via OP_RETURN txid=" + txidOut);
        // Index for fast retrieval
        storage->storeContractData("AI_ORACLE", "ai_anchor_tx:" + requestID, txidOut);
        // Optional: add a token-scoped index too
        storage->storeContractData("AI_ORACLE", "ai_anchor_tx:" + tokenID + ":" + requestID, txidOut);
    } else {
        Logger::log("[AIOracle] Failed to anchor ENHANCED AI response on-chain for requestID=" + requestID);
    }
}
