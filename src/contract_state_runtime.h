#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "contract_call_policy.h"
#include "contract_state_lineage.h"
#include "contract_state_limits.h"
#include "script_context_builder.h"
#include "script_interpreter.h"
#include "tx.h"

// confirmed state-domain loader +
// transaction-local Stateful K/V V1 execution.
//
// Consensus/mempool callers load only the CONFIRMED LevelDB snapshot keyed by
// the stable root domain. Execution occurs on a disposable in-memory copy.
// This helper never writes LevelDB. Durable writes remain the responsibility of
// applyBlock's atomic mainBatch after full block validation succeeds.

namespace tru_contract_state_runtime {

struct ConfirmedStateDomainSnapshot {
    std::string current;
    std::string root;
    std::string ownerHash160;
    std::string family; // empty = legacy/activated Stateful K/V V1
    tru_contract_state_limits::StateMap state;
    std::size_t accountedStateBytes{0};
};

inline bool IsCanonicalLowerHash160Hex(std::string_view value)
{
    if (value.size() != 40) return false;
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

inline bool DecodeCanonicalLogicalKeyHex(
    std::string_view encoded,
    std::string& logicalKeyOut)
{
    logicalKeyOut.clear();
    if (encoded.empty() || (encoded.size() & 1U) != 0) return false;
    if (encoded.size() / 2U >
        tru_contract_state_limits::MAX_LOGICAL_KEY_BYTES) {
        return false;
    }

    logicalKeyOut.reserve(encoded.size() / 2U);
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        const char hiCh = encoded[i];
        const char loCh = encoded[i + 1];
        if (!((hiCh >= '0' && hiCh <= '9') || (hiCh >= 'a' && hiCh <= 'f')) ||
            !((loCh >= '0' && loCh <= '9') || (loCh >= 'a' && loCh <= 'f'))) {
            return false;
        }
        const auto nibble = [](char ch) -> unsigned char {
            return static_cast<unsigned char>(
                ch <= '9' ? ch - '0' : ch - 'a' + 10);
        };
        logicalKeyOut.push_back(static_cast<char>(
            (nibble(hiCh) << 4) | nibble(loCh)));
    }

    return tru_contract_state_limits::IsLogicalKeyAllowed(logicalKeyOut) &&
           tru_contract_state::HexEncodeLogicalKey(logicalKeyOut) == encoded;
}

template <typename StorageLike>
inline bool LoadConfirmedStateDomain(
    StorageLike& storage,
    const std::string& currentOutpoint,
    ConfirmedStateDomainSnapshot& snapshotOut,
    std::string& reasonOut)
{
    snapshotOut = {};
    reasonOut.clear();

    if (!tru_contract_state::IsCanonicalContractOutpoint(currentOutpoint)) {
        reasonOut = "current state-anchor outpoint is not canonical";
        return false;
    }

    const std::string lineageKey =
        tru_contract_state::BuildContractLineageKey(currentOutpoint);
    if (lineageKey.empty()) {
        reasonOut = "unable to derive lineage key";
        return false;
    }

    std::string root;
    bool found = false;
    if (!storage.getRaw(lineageKey, root, found) || !found) {
        reasonOut = "missing confirmed contract lineage";
        return false;
    }
    if (!tru_contract_state::IsCanonicalContractOutpoint(root)) {
        reasonOut = "stored contract lineage root is non-canonical";
        return false;
    }

    const std::string liveKey =
        tru_contract_state::BuildContractLiveKey(root);
    const std::string ownerKey =
        tru_contract_state::BuildContractOwnerKey(root);
    const std::string familyKey =
        tru_contract_state::BuildContractFamilyKey(root);
    const std::string statePrefix =
        tru_contract_state::BuildContractStatePrefix(root);
    if (liveKey.empty() || ownerKey.empty() || familyKey.empty() ||
        statePrefix.empty()) {
        reasonOut = "unable to derive confirmed state-domain keys";
        return false;
    }

    std::string live;
    found = false;
    if (!storage.getRaw(liveKey, live, found) || !found) {
        reasonOut = "missing confirmed live-anchor registry";
        return false;
    }
    if (live != currentOutpoint) {
        reasonOut = "state-anchor is stale; contractlive does not point to vin[0]";
        return false;
    }

    std::string owner;
    found = false;
    if (!storage.getRaw(ownerKey, owner, found) || !found) {
        reasonOut = "missing confirmed contract owner binding";
        return false;
    }
    if (!IsCanonicalLowerHash160Hex(owner)) {
        reasonOut = "stored contract owner binding is malformed";
        return false;
    }

    // existing K/V roots predate the immutable family registry and
    // intentionally have no contractfamily key. Activated typed roots MUST carry
    // an exact known family id. Unknown future values fail closed.
    std::string family;
    found = false;
    if (!storage.getRaw(familyKey, family, found)) {
        reasonOut = "unable to read confirmed contract family registry";
        return false;
    }
    if (found &&
        family != "voting_v1" &&
        family != "token_issuer_v1") {
        reasonOut = "unsupported confirmed contract family";
        return false;
    }
    if (!found) family.clear();

    tru_contract_state_limits::StateMap state;
    bool scanOk = true;
    std::string scanReason;
    try {
        storage.iteratePrefix(
            statePrefix,
            [&](const std::string& encodedKey,
                const std::string& rawValue) {
                if (!scanOk) return;

                std::string logicalKey;
                if (!DecodeCanonicalLogicalKeyHex(encodedKey, logicalKey)) {
                    scanOk = false;
                    scanReason = "non-canonical durable contract state key";
                    return;
                }

                std::vector<unsigned char> value(
                    rawValue.begin(), rawValue.end());
                if (!tru_contract_state_limits::IsValueAllowed(value)) {
                    scanOk = false;
                    scanReason = "durable contract state value exceeds consensus limit";
                    return;
                }

                if (!state.emplace(logicalKey, std::move(value)).second) {
                    scanOk = false;
                    scanReason = "duplicate logical key in durable contract state";
                    return;
                }
            });
    } catch (const std::exception& e) {
        reasonOut = std::string("confirmed contract state scan failed: ") + e.what();
        return false;
    } catch (...) {
        reasonOut = "confirmed contract state scan failed";
        return false;
    }

    if (!scanOk) {
        reasonOut = scanReason;
        return false;
    }

    // Every activated V1 root is created with exactly one initial state entry
    // and V1 has no delete opcode. LevelDBStorage::iteratePrefix() suppresses
    // callbacks when its iterator reports an error, so an empty scan is a
    // fail-closed signal rather than a valid empty state domain.
    if (state.empty()) {
        reasonOut = "confirmed contract state domain is unexpectedly empty";
        return false;
    }

    std::size_t accounted = 0;
    if (!tru_contract_state_limits::MeasureStateBytes(state, accounted)) {
        reasonOut = "confirmed contract state exceeds consensus resource limits";
        return false;
    }

    snapshotOut.current = currentOutpoint;
    snapshotOut.root = root;
    snapshotOut.ownerHash160 = owner;
    snapshotOut.family = family;
    snapshotOut.state = std::move(state);
    snapshotOut.accountedStateBytes = accounted;
    return true;
}

struct KvCallExecutionResult {
    tru_contract_state_limits::StateMap state;
    std::uint64_t gasUsed{0};
};

inline bool ExecuteStatefulKvV1Call(
    const Transaction& tx,
    const tru_contract_call::StatefulCallShapeResult& callShape,
    const std::vector<unsigned char>& lockingScript,
    const ConfirmedStateDomainSnapshot& snapshot,
    const std::string& callerAddress,
    std::uint32_t blockTime,
    std::uint32_t execHeight,
    std::uint64_t gasLimit,
    const void* chainCtx,
    KvCallExecutionResult& resultOut,
    std::string& reasonOut)
{
    resultOut = {};
    reasonOut.clear();

    if (!callShape.valid || tx.vin.size() != 2 ||
        callShape.callerInputIndex != 1 ||
        callShape.continuationVout >= tx.vout.size() ||
        !tru_contract_call::IsCanonicalStatefulKvV1Script(lockingScript)) {
        reasonOut = "invalid Stateful K/V V1 execution parameters";
        return false;
    }
    if (snapshot.root.empty() || snapshot.current.empty() || callerAddress.empty()) {
        reasonOut = "missing confirmed state/caller execution context";
        return false;
    }
    if (callShape.callValue != 0) {
        reasonOut = "Stateful K/V V1 is non-payable";
        return false;
    }

    resultOut.state = snapshot.state;

    ScriptExecutionContextSpec ctxSpec;
    ctxSpec.gasLimit = gasLimit;
    ctxSpec.tx = &tx;
    ctxSpec.blockTime = blockTime;
    ctxSpec.inputIndex = 0;
    ctxSpec.scriptPubKey = &lockingScript;
    ctxSpec.chainCtx = chainCtx;
    ctxSpec.execHeight = execHeight;
    ctxSpec.sender = callerAddress;
    ctxSpec.state = &resultOut.state;
    ctxSpec.contractAddress = snapshot.root;
    ctxSpec.outputIndex = callShape.continuationVout;

    ScriptExecutionContext ctx = BuildScriptExecutionContext(ctxSpec);
    if (!VerifyScripts(tx.vin[0].scriptSig, lockingScript, ctx)) {
        reasonOut = "Stateful K/V V1 VM execution returned false";
        return false;
    }
    if (ctx.gasUsed > gasLimit) {
        reasonOut = "Stateful K/V V1 VM gas limit exceeded";
        return false;
    }

    const auto it = resultOut.state.find(callShape.logicalKey);
    if (it == resultOut.state.end() || it->second != callShape.value) {
        reasonOut = "Stateful K/V V1 VM result does not match committed call arguments";
        return false;
    }

    std::size_t accounted = 0;
    if (!tru_contract_state_limits::MeasureStateBytes(
            resultOut.state, accounted)) {
        reasonOut = "post-call state exceeds consensus resource limits";
        return false;
    }

    resultOut.gasUsed = ctx.gasUsed;
    return true;
}

inline bool ReadVotingU64(
    const tru_contract_state_limits::StateMap& state,
    const std::string& key,
    std::uint64_t& valueOut)
{
    const auto it = state.find(key);
    if (it == state.end() || it->second.size() != 8) return false;
    valueOut = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        valueOut |= static_cast<std::uint64_t>(it->second[i]) << (8U * i);
    }
    return true;
}

inline std::vector<unsigned char> EncodeVotingU64(std::uint64_t value)
{
    std::vector<unsigned char> out(8, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<unsigned char>((value >> (8U * i)) & 0xffU);
    }
    return out;
}

inline bool ParseCanonicalVotingCountKey(
    const std::string& logicalKey,
    std::size_t& choiceOut)
{
    choiceOut = 0;
    static const std::string prefix = "count";
    if (logicalKey.size() <= prefix.size() ||
        logicalKey.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::string suffix = logicalKey.substr(prefix.size());
    if (suffix.size() > 1 && suffix.front() == '0') return false;
    std::size_t value = 0;
    for (unsigned char c : suffix) {
        if (c < '0' || c > '9') return false;
        value = value * 10U + static_cast<std::size_t>(c - '0');
        if (value > 9U) return false;
    }
    choiceOut = value;
    return true;
}

inline bool ValidateVotingV1State(
    const tru_contract_state_limits::StateMap& state,
    std::size_t& numOptionsOut,
    std::uint64_t& endTimeOut,
    std::string& reasonOut)
{
    reasonOut.clear();
    numOptionsOut = 0;
    endTimeOut = 0;

    const auto proposalIt = state.find("proposal");
    const auto numIt = state.find("numoptions");
    const auto endIt = state.find("endtime");
    const auto totalIt = state.find("totalvotes");
    if (proposalIt == state.end() || proposalIt->second.empty() ||
        proposalIt->second.size() > 200 ||
        numIt == state.end() || numIt->second.size() != 1 ||
        endIt == state.end() || endIt->second.size() != 8 ||
        totalIt == state.end() || totalIt->second.size() != 8) {
        reasonOut = "Voting V1 confirmed state is missing/malformed core fields";
        return false;
    }

    numOptionsOut = numIt->second[0];
    if (numOptionsOut < 2 || numOptionsOut > 10) {
        reasonOut = "Voting V1 confirmed numoptions is outside 2..10";
        return false;
    }
    if (!ReadVotingU64(state, "endtime", endTimeOut) || endTimeOut == 0) {
        reasonOut = "Voting V1 confirmed endtime is malformed";
        return false;
    }

    std::uint64_t declaredTotal = 0;
    if (!ReadVotingU64(state, "totalvotes", declaredTotal)) {
        reasonOut = "Voting V1 confirmed totalvotes is malformed";
        return false;
    }

    std::array<std::uint64_t, 10> optionCounts{};
    std::uint64_t summedCounts = 0;
    for (std::size_t i = 0; i < numOptionsOut; ++i) {
        const auto optionIt = state.find("option" + std::to_string(i));
        const std::string countKey = "count" + std::to_string(i);
        const auto countIt = state.find(countKey);
        std::uint64_t count = 0;
        if (optionIt == state.end() || optionIt->second.empty() ||
            optionIt->second.size() > 50 ||
            countIt == state.end() || countIt->second.size() != 8 ||
            !ReadVotingU64(state, countKey, count)) {
            reasonOut = "Voting V1 confirmed option/count state is malformed";
            return false;
        }
        if (count > std::numeric_limits<std::uint64_t>::max() - summedCounts) {
            reasonOut = "Voting V1 option-count sum overflows uint64";
            return false;
        }
        optionCounts[i] = count;
        summedCounts += count;
    }
    if (summedCounts != declaredTotal) {
        reasonOut = "Voting V1 totalvotes does not equal the sum of option counts";
        return false;
    }

    // Fail closed on unknown mutable keys. The only dynamic keys activated by
    // 15A are voted:<40-lowercase-hash160>, containing one choice byte.
    std::array<std::uint64_t, 10> markerCounts{};
    std::uint64_t voterMarkers = 0;
    for (const auto& [key, value] : state) {
        if (key == "proposal" || key == "numoptions" || key == "endtime" ||
            key == "totalvotes") {
            continue;
        }
        bool known = false;
        for (std::size_t i = 0; i < numOptionsOut; ++i) {
            if (key == "option" + std::to_string(i) ||
                key == "count" + std::to_string(i)) {
                known = true;
                break;
            }
        }
        if (known) continue;

        static const std::string votedPrefix = "voted:";
        if (key.compare(0, votedPrefix.size(), votedPrefix) != 0 ||
            key.size() != votedPrefix.size() + 40 ||
            value.size() != 1 || value[0] >= numOptionsOut) {
            reasonOut = "Voting V1 confirmed state contains an unknown/malformed key";
            return false;
        }
        for (std::size_t j = votedPrefix.size(); j < key.size(); ++j) {
            const char c = key[j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                reasonOut = "Voting V1 voter marker is non-canonical";
                return false;
            }
        }

        const std::size_t choice = value[0];
        if (voterMarkers == std::numeric_limits<std::uint64_t>::max() ||
            markerCounts[choice] == std::numeric_limits<std::uint64_t>::max()) {
            reasonOut = "Voting V1 voter-marker tally overflows uint64";
            return false;
        }
        ++voterMarkers;
        ++markerCounts[choice];
    }

    if (voterMarkers != declaredTotal) {
        reasonOut = "Voting V1 totalvotes does not equal the voter-marker count";
        return false;
    }
    for (std::size_t i = 0; i < numOptionsOut; ++i) {
        if (markerCounts[i] != optionCounts[i]) {
            reasonOut = "Voting V1 voter markers do not match option counts";
            return false;
        }
    }

    return true;
}

struct VotingCallExecutionResult {
    tru_contract_state_limits::StateMap state;
    std::uint64_t gasUsed{0};
    std::size_t choice{0};
    std::string voterKey;
};

inline bool ExecuteVotingV1Call(
    const Transaction& tx,
    const tru_contract_call::StatefulCallShapeResult& callShape,
    const std::vector<unsigned char>& lockingScript,
    const ConfirmedStateDomainSnapshot& snapshot,
    const std::string& callerHash160,
    const std::string& callerAddress,
    std::uint32_t blockTime,
    std::uint32_t execHeight,
    std::uint64_t gasLimit,
    const void* chainCtx,
    VotingCallExecutionResult& resultOut,
    std::string& reasonOut)
{
    resultOut = {};
    reasonOut.clear();

    if (snapshot.family != "voting_v1") {
        reasonOut = "confirmed state root is not Voting V1";
        return false;
    }
    if (!IsCanonicalLowerHash160Hex(callerHash160) || callerAddress.empty()) {
        reasonOut = "Voting V1 requires a canonical signed P2PKH voter";
        return false;
    }
    if (callShape.callValue != 0) {
        reasonOut = "Voting V1 is non-payable";
        return false;
    }

    std::size_t numOptions = 0;
    std::uint64_t endTime = 0;
    if (!ValidateVotingV1State(
            snapshot.state, numOptions, endTime, reasonOut)) {
        return false;
    }
    if (static_cast<std::uint64_t>(blockTime) > endTime) {
        reasonOut = "Voting V1 ballot is closed at this block time";
        return false;
    }

    std::size_t choice = 0;
    if (!ParseCanonicalVotingCountKey(callShape.logicalKey, choice) ||
        choice >= numOptions) {
        reasonOut = "Voting V1 calldata must target canonical countN";
        return false;
    }

    std::uint64_t oldCount = 0;
    std::uint64_t oldTotal = 0;
    if (!ReadVotingU64(snapshot.state, callShape.logicalKey, oldCount) ||
        !ReadVotingU64(snapshot.state, "totalvotes", oldTotal) ||
        oldCount == std::numeric_limits<std::uint64_t>::max() ||
        oldTotal == std::numeric_limits<std::uint64_t>::max()) {
        reasonOut = "Voting V1 count arithmetic overflow/malformed state";
        return false;
    }

    const auto expectedCount = EncodeVotingU64(oldCount + 1U);
    if (callShape.value != expectedCount) {
        reasonOut = "Voting V1 committed count must equal confirmed count + 1";
        return false;
    }

    const std::string voterKey = "voted:" + callerHash160;
    if (snapshot.state.find(voterKey) != snapshot.state.end()) {
        reasonOut = "Voting V1 caller has already voted";
        return false;
    }

    resultOut.state = snapshot.state;

    ScriptExecutionContextSpec ctxSpec;
    ctxSpec.gasLimit = gasLimit;
    ctxSpec.tx = &tx;
    ctxSpec.blockTime = blockTime;
    ctxSpec.inputIndex = 0;
    ctxSpec.scriptPubKey = &lockingScript;
    ctxSpec.chainCtx = chainCtx;
    ctxSpec.execHeight = execHeight;
    ctxSpec.sender = callerAddress;
    ctxSpec.state = &resultOut.state;
    ctxSpec.contractAddress = snapshot.root;
    ctxSpec.outputIndex = callShape.continuationVout;

    ScriptExecutionContext ctx = BuildScriptExecutionContext(ctxSpec);
    if (!VerifyScripts(tx.vin[0].scriptSig, lockingScript, ctx)) {
        reasonOut = "Voting V1 VM execution returned false";
        return false;
    }

    const auto countIt = resultOut.state.find(callShape.logicalKey);
    if (countIt == resultOut.state.end() ||
        countIt->second != expectedCount) {
        reasonOut = "Voting V1 VM did not commit the expected count increment";
        return false;
    }

    const auto nextTotal = EncodeVotingU64(oldTotal + 1U);
    const std::vector<unsigned char> voterValue{
        static_cast<unsigned char>(choice)};

    std::uint64_t extraGasA = 0;
    std::uint64_t extraGasB = 0;
    if (!tru_contract_state_limits::CanApplyStateWrite(
            resultOut.state, "totalvotes", nextTotal) ||
        !tru_contract_state_limits::ComputeStoreGas(
            std::string("totalvotes").size(), nextTotal.size(), extraGasA)) {
        reasonOut = "Voting V1 totalvotes update exceeds state/gas limits";
        return false;
    }
    resultOut.state["totalvotes"] = nextTotal;

    if (!tru_contract_state_limits::CanApplyStateWrite(
            resultOut.state, voterKey, voterValue) ||
        !tru_contract_state_limits::ComputeStoreGas(
            voterKey.size(), voterValue.size(), extraGasB)) {
        reasonOut = "Voting V1 voter marker exceeds state/gas limits";
        return false;
    }
    if (ctx.gasUsed > gasLimit ||
        extraGasA > gasLimit - ctx.gasUsed ||
        extraGasB > gasLimit - ctx.gasUsed - extraGasA) {
        reasonOut = "Voting V1 deterministic state updates exceed gas limit";
        return false;
    }
    resultOut.state[voterKey] = voterValue;

    // bind countN, totalvotes and voted:<hash160> to the same
    // completed tally before mempool/block validation can accept the transition.
    std::size_t postNumOptions = 0;
    std::uint64_t postEndTime = 0;
    std::string invariantReason;
    if (!ValidateVotingV1State(
            resultOut.state, postNumOptions, postEndTime, invariantReason) ||
        postNumOptions != numOptions || postEndTime != endTime) {
        reasonOut =
            "Voting V1 post-call tally invariant failed: " + invariantReason;
        return false;
    }

    std::size_t accounted = 0;
    if (!tru_contract_state_limits::MeasureStateBytes(
            resultOut.state, accounted)) {
        reasonOut = "Voting V1 post-call state exceeds consensus resource limits";
        return false;
    }

    resultOut.gasUsed = ctx.gasUsed + extraGasA + extraGasB;
    resultOut.choice = choice;
    resultOut.voterKey = voterKey;
    return true;
}


inline bool ReadTokenIssuerU64(
    const tru_contract_state_limits::StateMap& state,
    const std::string& key,
    std::uint64_t& valueOut)
{
    return ReadVotingU64(state, key, valueOut);
}

inline std::vector<unsigned char> EncodeTokenIssuerU64(std::uint64_t value)
{
    return EncodeVotingU64(value);
}

inline bool IsCanonicalTokenBalanceKey(
    const std::string& key,
    std::string* hash160Out = nullptr)
{
    static const std::string prefix = "balance:";
    if (key.size() != prefix.size() + 40 ||
        key.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const std::string hash = key.substr(prefix.size());
    if (!IsCanonicalLowerHash160Hex(hash)) return false;
    if (hash160Out) *hash160Out = hash;
    return true;
}

// validate the complete authoritative Token Issuer V1 state.
// Until transfer semantics are activated, total_issued MUST equal the checked
// sum of all persisted buyer balances.
inline bool ValidateTokenIssuerV1State(
    const tru_contract_state_limits::StateMap& state,
    std::uint64_t& exchangeRateOut,
    std::uint64_t& maxSupplyOut,
    std::uint64_t& totalIssuedOut,
    std::string& reasonOut)
{
    reasonOut.clear();
    exchangeRateOut = 0;
    maxSupplyOut = 0;
    totalIssuedOut = 0;

    const auto nameIt = state.find("token_name");
    const auto rateIt = state.find("exchange_rate");
    const auto maxIt = state.find("max_supply");
    const auto issuedIt = state.find("total_issued");
    if (nameIt == state.end() || nameIt->second.empty() ||
        nameIt->second.size() > 10 ||
        rateIt == state.end() || rateIt->second.size() != 8 ||
        maxIt == state.end() || maxIt->second.size() != 8 ||
        issuedIt == state.end() || issuedIt->second.size() != 8) {
        reasonOut =
            "Token Issuer V1 confirmed state is missing/malformed core fields";
        return false;
    }

    for (const unsigned char c : nameIt->second) {
        const bool ok =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-';
        if (!ok) {
            reasonOut = "Token Issuer V1 token_name is non-canonical";
            return false;
        }
    }

    if (!ReadTokenIssuerU64(state, "exchange_rate", exchangeRateOut) ||
        exchangeRateOut == 0 ||
        !ReadTokenIssuerU64(state, "max_supply", maxSupplyOut) ||
        !ReadTokenIssuerU64(state, "total_issued", totalIssuedOut)) {
        reasonOut = "Token Issuer V1 numeric state is malformed";
        return false;
    }
    if (maxSupplyOut != 0 && totalIssuedOut > maxSupplyOut) {
        reasonOut = "Token Issuer V1 total_issued exceeds max_supply";
        return false;
    }

    std::uint64_t balanceSum = 0;
    for (const auto& [key, value] : state) {
        if (key == "token_name" || key == "exchange_rate" ||
            key == "max_supply" || key == "total_issued") {
            continue;
        }
        if (!IsCanonicalTokenBalanceKey(key) || value.size() != 8) {
            reasonOut =
                "Token Issuer V1 confirmed state contains unknown/malformed key";
            return false;
        }

        std::uint64_t balance = 0;
        if (!ReadTokenIssuerU64(state, key, balance) ||
            balance > std::numeric_limits<std::uint64_t>::max() - balanceSum) {
            reasonOut = "Token Issuer V1 balance sum overflow/malformed balance";
            return false;
        }
        balanceSum += balance;
    }

    if (balanceSum != totalIssuedOut) {
        reasonOut =
            "Token Issuer V1 total_issued does not equal persisted balance sum";
        return false;
    }

    return true;
}

// exact persistent issuance delta. A purchase may create a new
// buyer balance or accumulate an existing one, but it must mutate exactly two
// logical keys and may not delete state:
//   total_issued
//   balance:<signed-buyer-hash160>
inline bool ValidateTokenIssuerV1CallDelta(
    const tru_contract_state_limits::StateMap& before,
    const tru_contract_state_limits::StateMap& after,
    const std::string& balanceKey,
    const std::vector<unsigned char>& expectedTotal,
    const std::vector<unsigned char>& expectedBalance,
    std::string& reasonOut)
{
    reasonOut.clear();

    if (!IsCanonicalTokenBalanceKey(balanceKey) ||
        expectedTotal.size() != 8 ||
        expectedBalance.size() != 8) {
        reasonOut = "Token Issuer V1 delta expectation is malformed";
        return false;
    }

    const auto totalIt = after.find("total_issued");
    const auto balanceIt = after.find(balanceKey);
    if (totalIt == after.end() || totalIt->second != expectedTotal ||
        balanceIt == after.end() || balanceIt->second != expectedBalance) {
        reasonOut =
            "Token Issuer V1 exact total/balance delta values are missing";
        return false;
    }

    for (const auto& [key, value] : before) {
        (void)value;
        if (after.find(key) == after.end()) {
            reasonOut = "Token Issuer V1 state deletion is not permitted";
            return false;
        }
    }

    std::size_t changedKeys = 0;
    for (const auto& [key, value] : after) {
        const auto beforeIt = before.find(key);
        if (beforeIt != before.end() && beforeIt->second == value) {
            continue;
        }
        if (key != "total_issued" && key != balanceKey) {
            reasonOut =
                "Token Issuer V1 call changed a non-issuance state key";
            return false;
        }
        ++changedKeys;
    }

    if (changedKeys != 2) {
        reasonOut =
            "Token Issuer V1 call must change exactly total_issued and buyer balance";
        return false;
    }
    return true;
}

struct TokenIssuerCallExecutionResult {
    tru_contract_state_limits::StateMap state;
    std::uint64_t gasUsed{0};
    std::uint64_t callValue{0};
    std::uint64_t minted{0};
    std::uint64_t newTotalIssued{0};
    std::string balanceKey;
};

// A Token Issuer V1 purchase is a payable continuation. Economic call value is
// consensus-derived ONLY as continuation.amount - spentAnchor.amount. The VM
// commits the exact checked total_issued value through f751; the caller balance
// update is deterministic family logic applied only to scratch state here.
inline bool ExecuteTokenIssuerV1Call(
    const Transaction& tx,
    const tru_contract_call::StatefulCallShapeResult& callShape,
    const std::vector<unsigned char>& lockingScript,
    const ConfirmedStateDomainSnapshot& snapshot,
    const std::string& callerHash160,
    const std::string& callerAddress,
    std::uint32_t blockTime,
    std::uint32_t execHeight,
    std::uint64_t gasLimit,
    const void* chainCtx,
    TokenIssuerCallExecutionResult& resultOut,
    std::string& reasonOut)
{
    resultOut = {};
    reasonOut.clear();

    if (snapshot.family != "token_issuer_v1") {
        reasonOut = "confirmed state root is not Token Issuer V1";
        return false;
    }
    if (!IsCanonicalLowerHash160Hex(callerHash160) || callerAddress.empty()) {
        reasonOut = "Token Issuer V1 requires a canonical signed P2PKH buyer";
        return false;
    }
    if (callShape.callValue == 0) {
        reasonOut = "Token Issuer V1 requires positive economic call value";
        return false;
    }
    if (callShape.logicalKey != "total_issued") {
        reasonOut = "Token Issuer V1 calldata must target total_issued";
        return false;
    }

    std::uint64_t exchangeRate = 0;
    std::uint64_t maxSupply = 0;
    std::uint64_t oldTotal = 0;
    if (!ValidateTokenIssuerV1State(
            snapshot.state, exchangeRate, maxSupply, oldTotal, reasonOut)) {
        return false;
    }

    if (callShape.callValue >
        std::numeric_limits<std::uint64_t>::max() / exchangeRate) {
        reasonOut = "Token Issuer V1 callValue * exchange_rate overflow";
        return false;
    }
    const std::uint64_t minted = callShape.callValue * exchangeRate;
    if (minted == 0 ||
        minted > std::numeric_limits<std::uint64_t>::max() - oldTotal) {
        reasonOut = "Token Issuer V1 total_issued addition overflow";
        return false;
    }
    const std::uint64_t newTotal = oldTotal + minted;
    if (maxSupply != 0 && newTotal > maxSupply) {
        reasonOut = "Token Issuer V1 purchase exceeds max_supply";
        return false;
    }

    const auto expectedTotal = EncodeTokenIssuerU64(newTotal);
    if (callShape.value != expectedTotal) {
        reasonOut =
            "Token Issuer V1 committed total_issued must equal checked issuance result";
        return false;
    }

    const std::string balanceKey = "balance:" + callerHash160;
    std::uint64_t oldBalance = 0;
    const auto balanceIt = snapshot.state.find(balanceKey);
    if (balanceIt != snapshot.state.end()) {
        if (!ReadTokenIssuerU64(snapshot.state, balanceKey, oldBalance)) {
            reasonOut = "Token Issuer V1 existing buyer balance is malformed";
            return false;
        }
    }
    if (minted > std::numeric_limits<std::uint64_t>::max() - oldBalance) {
        reasonOut = "Token Issuer V1 buyer balance addition overflow";
        return false;
    }
    const std::uint64_t newBalance = oldBalance + minted;
    const auto newBalanceBytes = EncodeTokenIssuerU64(newBalance);

    resultOut.state = snapshot.state;

    ScriptExecutionContextSpec ctxSpec;
    ctxSpec.gasLimit = gasLimit;
    ctxSpec.tx = &tx;
    ctxSpec.blockTime = blockTime;
    ctxSpec.inputIndex = 0;
    ctxSpec.scriptPubKey = &lockingScript;
    ctxSpec.chainCtx = chainCtx;
    ctxSpec.execHeight = execHeight;
    ctxSpec.sender = callerAddress;
    ctxSpec.state = &resultOut.state;
    ctxSpec.contractAddress = snapshot.root;
    ctxSpec.outputIndex = callShape.continuationVout;

    ScriptExecutionContext ctx = BuildScriptExecutionContext(ctxSpec);
    if (!VerifyScripts(tx.vin[0].scriptSig, lockingScript, ctx)) {
        reasonOut = "Token Issuer V1 VM execution returned false";
        return false;
    }

    const auto totalIt = resultOut.state.find("total_issued");
    if (totalIt == resultOut.state.end() ||
        totalIt->second != expectedTotal) {
        reasonOut =
            "Token Issuer V1 VM did not commit the expected total_issued";
        return false;
    }

    std::uint64_t balanceGas = 0;
    if (!tru_contract_state_limits::CanApplyStateWrite(
            resultOut.state, balanceKey, newBalanceBytes) ||
        !tru_contract_state_limits::ComputeStoreGas(
            balanceKey.size(), newBalanceBytes.size(), balanceGas)) {
        reasonOut =
            "Token Issuer V1 buyer balance update exceeds state/gas limits";
        return false;
    }
    if (ctx.gasUsed > gasLimit ||
        balanceGas > gasLimit - ctx.gasUsed) {
        reasonOut =
            "Token Issuer V1 deterministic balance update exceeds gas limit";
        return false;
    }
    resultOut.state[balanceKey] = newBalanceBytes;

    if (!ValidateTokenIssuerV1CallDelta(
            snapshot.state, resultOut.state, balanceKey,
            expectedTotal, newBalanceBytes, reasonOut)) {
        reasonOut = "Token Issuer V1 delta invariant failed: " + reasonOut;
        return false;
    }

    std::uint64_t checkedRate = 0;
    std::uint64_t checkedMax = 0;
    std::uint64_t checkedTotal = 0;
    if (!ValidateTokenIssuerV1State(
            resultOut.state, checkedRate, checkedMax, checkedTotal, reasonOut)) {
        reasonOut = "Token Issuer V1 post-call invariant failed: " + reasonOut;
        return false;
    }
    if (checkedRate != exchangeRate ||
        checkedMax != maxSupply ||
        checkedTotal != newTotal) {
        reasonOut = "Token Issuer V1 immutable/numeric state changed unexpectedly";
        return false;
    }

    resultOut.gasUsed = ctx.gasUsed + balanceGas;
    resultOut.callValue = callShape.callValue;
    resultOut.minted = minted;
    resultOut.newTotalIssued = newTotal;
    resultOut.balanceKey = balanceKey;
    return true;
}

} // namespace tru_contract_state_runtime
