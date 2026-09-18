#pragma once

// TRU-SWAP-A — coordinator-facing canonical swap record + durable state machine.
// This layer is intentionally separate from the frozen TRU-SWAP-V1 HTLC bytes.
// It stores HASH160 commitments and public metadata only. It never persists
// atomic-swap preimages or private keys.

#include "leveldb_storage.h"

#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace tru_swap_v1 {

using json = nlohmann::json;

static constexpr std::uint32_t REFUND_TIME_MIN = 500000000U;
static constexpr std::uint32_t REFUND_TIME_MAX = 0x7fffffffU;
static constexpr const char* STORAGE_PREFIX = "swap:v1:";

inline std::string lowerHexStrict(
    const std::string& in,
    std::size_t expectedHexChars,
    const char* label)
{
    if (in.size() != expectedHexChars) {
        throw std::invalid_argument(
            std::string(label) + " must be exactly " +
            std::to_string(expectedHexChars) + " hex characters");
    }
    std::string out = in;
    for (char& c : out) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!std::isxdigit(u)) {
            throw std::invalid_argument(std::string(label) + " contains non-hex data");
        }
        c = static_cast<char>(std::tolower(u));
    }
    return out;
}

inline bool isCompressedPubkeyHex(const std::string& h) {
    return h.size() == 66U &&
           (h.rfind("02", 0) == 0 || h.rfind("03", 0) == 0);
}

inline void appendU32BE(std::vector<unsigned char>& out, std::uint32_t v) {
    out.push_back(static_cast<unsigned char>((v >> 24) & 0xffU));
    out.push_back(static_cast<unsigned char>((v >> 16) & 0xffU));
    out.push_back(static_cast<unsigned char>((v >> 8) & 0xffU));
    out.push_back(static_cast<unsigned char>(v & 0xffU));
}

inline void appendU64BE(std::vector<unsigned char>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>((v >> shift) & 0xffULL));
    }
}

inline void appendFramed(
    std::vector<unsigned char>& out,
    const std::string& field)
{
    if (field.size() > 0xffffffffULL) {
        throw std::invalid_argument("swap-id field exceeds uint32 framing limit");
    }
    appendU32BE(out, static_cast<std::uint32_t>(field.size()));
    out.insert(out.end(), field.begin(), field.end());
}

inline std::string sha256Hex(const std::vector<unsigned char>& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : digest) {
        oss << std::setw(2) << static_cast<unsigned int>(c);
    }
    return oss.str();
}

inline std::string canonicalSwapId(const json& r) {
    std::vector<unsigned char> preimage;
    appendFramed(preimage, "TRU-SWAP-RECORD-V1");
    appendFramed(preimage, "HASH160");
    appendFramed(preimage, r.at("truChainId").get<std::string>());
    appendFramed(preimage, r.at("bstyChainId").get<std::string>());
    appendFramed(preimage, r.at("fundingOrder").get<std::string>());
    appendFramed(preimage, r.at("secretHash160").get<std::string>());
    appendFramed(preimage, r.at("truClaimPubkey").get<std::string>());
    appendFramed(preimage, r.at("truRefundPubkey").get<std::string>());
    appendFramed(preimage, r.at("bstyClaimPubkey").get<std::string>());
    appendFramed(preimage, r.at("bstyRefundPubkey").get<std::string>());
    appendU64BE(preimage, r.at("truAmountAtoms").get<std::uint64_t>());
    appendU64BE(preimage, r.at("bstyAmountAtoms").get<std::uint64_t>());
    appendU32BE(preimage, r.at("truRefundTime").get<std::uint32_t>());
    appendU32BE(preimage, r.at("bstyRefundTime").get<std::uint32_t>());
    return sha256Hex(preimage);
}

inline std::string requireShortIdString(
    const json& p,
    const char* key)
{
    if (!p.contains(key) || !p.at(key).is_string()) {
        throw std::invalid_argument(std::string("missing/invalid ") + key);
    }
    const std::string v = p.at(key).get<std::string>();
    if (v.empty() || v.size() > 64U) {
        throw std::invalid_argument(std::string(key) + " must be 1..64 characters");
    }
    return v;
}

inline std::uint64_t requirePositiveU64(
    const json& p,
    const char* key)
{
    if (!p.contains(key) ||
        !(p.at(key).is_number_unsigned() || p.at(key).is_number_integer())) {
        throw std::invalid_argument(std::string("missing/invalid ") + key);
    }
    if (p.at(key).is_number_integer()) {
        const std::int64_t sv = p.at(key).get<std::int64_t>();
        if (sv <= 0) {
            throw std::invalid_argument(std::string(key) + " must be positive");
        }
    }
    const std::uint64_t v = p.at(key).get<std::uint64_t>();
    if (v == 0U) {
        throw std::invalid_argument(std::string(key) + " must be positive");
    }
    return v;
}

inline std::uint32_t requireRefundTime(
    const json& p,
    const char* key)
{
    if (!p.contains(key) ||
        !(p.at(key).is_number_unsigned() || p.at(key).is_number_integer())) {
        throw std::invalid_argument(std::string("missing/invalid ") + key);
    }
    const std::int64_t v64 = p.at(key).get<std::int64_t>();
    if (v64 < static_cast<std::int64_t>(REFUND_TIME_MIN) ||
        v64 > static_cast<std::int64_t>(REFUND_TIME_MAX)) {
        throw std::invalid_argument(
            std::string(key) +
            " must be within TRU-SWAP-V1 timestamp domain 500000000..2147483647");
    }
    return static_cast<std::uint32_t>(v64);
}

inline std::string requireFreshAllocationId(
    const json& p,
    const char* key)
{
    if (!p.contains(key) || !p.at(key).is_string()) {
        throw std::invalid_argument(std::string("missing/invalid ") + key);
    }
    const std::string v = p.at(key).get<std::string>();
    if (v.size() != 64U) {
        throw std::invalid_argument(
            std::string(key) + " must be exactly 64 lowercase hex characters");
    }
    bool anyNonZero = false;
    for (char c : v) {
        const bool digit = c >= '0' && c <= '9';
        const bool lowerHex = c >= 'a' && c <= 'f';
        if (!digit && !lowerHex) {
            throw std::invalid_argument(
                std::string(key) + " must be exactly 64 lowercase hex characters");
        }
        if (c != '0') anyNonZero = true;
    }
    if (!anyNonZero) {
        throw std::invalid_argument(
            std::string(key) + " must not be the all-zero sentinel");
    }
    return v;
}

inline json makeCanonicalRecord(const json& p) {
    json r;
    r["protocol"] = "TRU-SWAP-V1";
    r["recordVersion"] = 1;
    r["hashAlgorithm"] = "HASH160";

    r["truChainId"] = requireShortIdString(p, "truChainId");
    r["bstyChainId"] = requireShortIdString(p, "bstyChainId");

    if (!p.contains("fundingOrder") || !p.at("fundingOrder").is_string()) {
        throw std::invalid_argument("missing/invalid fundingOrder");
    }
    std::string fundingOrder = p.at("fundingOrder").get<std::string>();
    std::transform(
        fundingOrder.begin(), fundingOrder.end(), fundingOrder.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (fundingOrder != "TRU_FIRST" && fundingOrder != "BSTY_FIRST") {
        throw std::invalid_argument("fundingOrder must be TRU_FIRST or BSTY_FIRST");
    }
    r["fundingOrder"] = fundingOrder;

    if (!p.contains("secretHash160") || !p.at("secretHash160").is_string()) {
        throw std::invalid_argument("missing/invalid secretHash160");
    }
    r["secretHash160"] =
        lowerHexStrict(p.at("secretHash160").get<std::string>(), 40U, "secretHash160");

    auto pubkey = [&](const char* key) {
        if (!p.contains(key) || !p.at(key).is_string()) {
            throw std::invalid_argument(std::string("missing/invalid ") + key);
        }
        const std::string v =
            lowerHexStrict(p.at(key).get<std::string>(), 66U, key);
        if (!isCompressedPubkeyHex(v)) {
            throw std::invalid_argument(
                std::string(key) + " must be a compressed secp256k1 pubkey");
        }
        return v;
    };

    r["truClaimPubkey"] = pubkey("truClaimPubkey");
    r["truRefundPubkey"] = pubkey("truRefundPubkey");
    r["bstyClaimPubkey"] = pubkey("bstyClaimPubkey");
    r["bstyRefundPubkey"] = pubkey("bstyRefundPubkey");

    if (r["truClaimPubkey"] == r["truRefundPubkey"]) {
        throw std::invalid_argument("TRU claim/refund role pubkeys must be distinct");
    }
    if (r["bstyClaimPubkey"] == r["bstyRefundPubkey"]) {
        throw std::invalid_argument("BSTY claim/refund role pubkeys must be distinct");
    }

    const bool hasTruClaimAllocation = p.contains("truClaimAllocationId");
    const bool hasTruRefundAllocation = p.contains("truRefundAllocationId");
    if (hasTruClaimAllocation != hasTruRefundAllocation) {
        throw std::invalid_argument(
            "fresh TRU records require both truClaimAllocationId and truRefundAllocationId");
    }
    if (hasTruClaimAllocation) {
        r["freshDerivationScheme"] = "TRU-SWAP-FRESH-HD-V1";
        r["truClaimAllocationId"] =
            requireFreshAllocationId(p, "truClaimAllocationId");
        r["truRefundAllocationId"] =
            requireFreshAllocationId(p, "truRefundAllocationId");
    }

    r["truAmountAtoms"] = requirePositiveU64(p, "truAmountAtoms");
    r["bstyAmountAtoms"] = requirePositiveU64(p, "bstyAmountAtoms");
    r["truRefundTime"] = requireRefundTime(p, "truRefundTime");
    r["bstyRefundTime"] = requireRefundTime(p, "bstyRefundTime");

    const std::uint32_t truTime = r["truRefundTime"].get<std::uint32_t>();
    const std::uint32_t bstyTime = r["bstyRefundTime"].get<std::uint32_t>();
    if (fundingOrder == "TRU_FIRST" && truTime <= bstyTime) {
        throw std::invalid_argument(
            "TRU_FIRST requires truRefundTime > bstyRefundTime");
    }
    if (fundingOrder == "BSTY_FIRST" && bstyTime <= truTime) {
        throw std::invalid_argument(
            "BSTY_FIRST requires bstyRefundTime > truRefundTime");
    }

    r["swapId"] = canonicalSwapId(r);
    r["state"] = "CREATED";
    r["transitionSeq"] = 0U;
    r["createdAtUnix"] = static_cast<std::uint64_t>(std::time(nullptr));
    r["updatedAtUnix"] = r["createdAtUnix"];
    r["truFundingTxid"] = "";
    r["truFundingVout"] = 1U;
    r["bstyFundingTxid"] = "";
    r["bstyFundingVout"] = 0U;
    r["evidence"] = json::object();
    return r;
}

inline bool transitionAllowed(
    const std::string& from,
    const std::string& to)
{
    if (from == "CREATED")
        return to == "ONE_SIDE_FUNDED" || to == "FAILED";
    if (from == "ONE_SIDE_FUNDED")
        return to == "BOTH_FUNDED" || to == "REFUND_PENDING" || to == "FAILED";
    if (from == "BOTH_FUNDED")
        return to == "SECRET_OBSERVED" || to == "REFUND_PENDING" || to == "FAILED";
    if (from == "SECRET_OBSERVED")
        return to == "SECRET_OBSERVED" ||
               to == "SETTLED" ||
               to == "REFUND_PENDING" ||
               to == "RESOLVED_MIXED" ||
               to == "FAILED";
    if (from == "REFUND_PENDING")
        return to == "REFUND_PENDING" ||
               to == "SETTLED" ||
               to == "REFUNDED" ||
               to == "RESOLVED_MIXED" ||
               to == "FAILED";
    return false;
}

inline const std::array<const char*,9>& validStates() {
    static const std::array<const char*,9> states = {
        "CREATED",
        "ONE_SIDE_FUNDED",
        "BOTH_FUNDED",
        "SECRET_OBSERVED",
        "SETTLED",
        "REFUND_PENDING",
        "REFUNDED",
        "RESOLVED_MIXED",
        "FAILED"
    };
    return states;
}

inline bool isValidState(const std::string& s) {
    const auto& states = validStates();
    return std::find(states.begin(), states.end(), s) != states.end();
}

inline LevelDBStorage& requireStorage(LevelDBStorage* storage) {
    if (!storage) {
        throw std::runtime_error("TRU-SWAP durable storage is unavailable");
    }
    return *storage;
}

inline std::string storageKey(const std::string& swapId) {
    return std::string(STORAGE_PREFIX) + lowerHexStrict(swapId, 64U, "swapId");
}

inline bool loadRecord(
    LevelDBStorage* storage,
    const std::string& swapId,
    json& out)
{
    std::string raw;
    if (!requireStorage(storage).getWithDataChecksum(storageKey(swapId), raw)) {
        return false;
    }
    out = json::parse(raw);
    return true;
}

inline void saveRecord(
    LevelDBStorage* storage,
    const json& record)
{
    if (!record.contains("swapId") || !record.at("swapId").is_string()) {
        throw std::invalid_argument("swap record is missing swapId");
    }
    if (!requireStorage(storage).putWithDataChecksum(
            storageKey(record.at("swapId").get<std::string>()),
            record.dump())) {
        throw std::runtime_error("failed to durably persist TRU-SWAP record");
    }
}

inline json createRecord(
    LevelDBStorage* storage,
    const json& params,
    bool& created)
{
    json record = makeCanonicalRecord(params);
    json existing;
    if (loadRecord(storage, record.at("swapId").get<std::string>(), existing)) {
        created = false;
        return existing;
    }
    saveRecord(storage, record);
    created = true;
    return record;
}

inline json transitionRecord(
    LevelDBStorage* storage,
    const std::string& swapId,
    std::string nextState,
    const json& evidence)
{
    std::transform(
        nextState.begin(), nextState.end(), nextState.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (!isValidState(nextState)) {
        throw std::invalid_argument("invalid TRU-SWAP state");
    }
    if (!evidence.is_object()) {
        throw std::invalid_argument("transition evidence must be a JSON object");
    }

    json record;
    if (!loadRecord(storage, swapId, record)) {
        throw std::runtime_error("TRU-SWAP record not found");
    }
    const std::string current = record.value("state", "");
    if (!transitionAllowed(current, nextState)) {
        throw std::runtime_error(
            "illegal TRU-SWAP state transition " + current + " -> " + nextState);
    }

    record["state"] = nextState;
    record["transitionSeq"] =
        record.value("transitionSeq", static_cast<std::uint64_t>(0)) + 1U;
    record["updatedAtUnix"] = static_cast<std::uint64_t>(std::time(nullptr));

    if (!record.contains("evidence") || !record["evidence"].is_object()) {
        record["evidence"] = json::object();
    }
    for (auto it = evidence.begin(); it != evidence.end(); ++it) {
        std::string k = it.key();
        std::string kl = k;
        std::transform(
            kl.begin(), kl.end(), kl.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const bool forbiddenSecretField =
            kl == "secret" ||
            kl == "secrethex" ||
            kl == "secretpreimage" ||
            kl.find("preimage") != std::string::npos ||
            kl.find("privkey") != std::string::npos ||
            kl.find("privatekey") != std::string::npos;
        if (forbiddenSecretField) {
            throw std::invalid_argument(
                "transition evidence must not persist preimages or private-key material");
        }
        if (kl == "resolutionminconfirmations") {
            if (!it.value().is_number_integer() ||
                it.value().get<std::int64_t>() < 1) {
                throw std::invalid_argument(
                    "resolutionMinConfirmations must be a positive integer");
            }
            if (record["evidence"].contains(k) &&
                record["evidence"][k] != it.value()) {
                throw std::invalid_argument(
                    "resolutionMinConfirmations is immutable once persisted");
            }
        }

        const bool immutableResolutionTxid =
            kl == "truclaimtxid" ||
            kl == "bstyclaimtxid" ||
            kl == "trurefundtxid" ||
            kl == "bstyrefundtxid";
        if (immutableResolutionTxid &&
            record["evidence"].contains(k) &&
            record["evidence"][k] != it.value()) {
            throw std::invalid_argument(
                "resolution transaction identity is immutable once persisted");
        }

        const bool monotonicResolutionConfirmations =
            kl == "truclaimconfirmations" ||
            kl == "bstyclaimconfirmations" ||
            kl == "trurefundconfirmations" ||
            kl == "bstyrefundconfirmations";
        if (monotonicResolutionConfirmations) {
            if (!it.value().is_number_integer() ||
                it.value().get<std::int64_t>() < 0) {
                throw std::invalid_argument(
                    "resolution confirmations must be non-negative");
            }
            if (record["evidence"].contains(k)) {
                const json& oldValue = record["evidence"][k];
                if (!oldValue.is_number_integer() ||
                    it.value().get<std::int64_t>() <
                        oldValue.get<std::int64_t>()) {
                    throw std::invalid_argument(
                        "resolution confirmations must not decrease");
                }
            }
        }

        record["evidence"][k] = it.value();
    }

    // TRU-SWAP-B RESOLUTION FINALITY V2
    if (nextState == "SETTLED" ||
        nextState == "REFUNDED" ||
        nextState == "RESOLVED_MIXED") {
        if (!evidence.empty()) {
            throw std::runtime_error(
                "terminal resolution must use previously persisted evidence");
        }

        const json& ev = record["evidence"];

        const auto hasText =
            [&ev](const char* key) -> bool {
                const auto it = ev.find(key);
                return it != ev.end() &&
                       it->is_string() &&
                       !it->get<std::string>().empty();
            };

        const auto integerValue =
            [&ev](const char* key) -> std::int64_t {
                const auto it = ev.find(key);
                if (it == ev.end() || !it->is_number_integer()) {
                    return 0;
                }
                return it->get<std::int64_t>();
            };

        const std::int64_t required =
            integerValue("resolutionMinConfirmations");
        if (required < 1) {
            throw std::runtime_error(
                "terminal resolution requires persisted "
                "resolutionMinConfirmations >= 1");
        }

        struct Leg {
            bool funded{false};
            bool claim{false};
            bool refund{false};
        };

        const auto resolveLeg =
            [&hasText, &integerValue, required](
                const char* fundingTxid,
                const char* claimTxid,
                const char* claimConf,
                const char* refundTxid,
                const char* refundConf) -> Leg {
                Leg x;
                x.funded = hasText(fundingTxid);
                if (!x.funded) return x;
                x.claim =
                    hasText(claimTxid) &&
                    integerValue(claimConf) >= required;
                x.refund =
                    hasText(refundTxid) &&
                    integerValue(refundConf) >= required;
                if (x.claim && x.refund) {
                    throw std::runtime_error(
                        "one funded leg cannot be both claimed and refunded");
                }
                return x;
            };

        const Leg tru = resolveLeg(
            "truFundingTxid",
            "truClaimTxid", "truClaimConfirmations",
            "truRefundTxid", "truRefundConfirmations");
        const Leg bsty = resolveLeg(
            "bstyFundingTxid",
            "bstyClaimTxid", "bstyClaimConfirmations",
            "bstyRefundTxid", "bstyRefundConfirmations");

        const int funded =
            static_cast<int>(tru.funded) +
            static_cast<int>(bsty.funded);
        if (funded < 1) {
            throw std::runtime_error(
                "terminal resolution requires at least one funded leg");
        }

        const auto complete = [](const Leg& x) {
            return !x.funded || x.claim || x.refund;
        };
        if (!complete(tru) || !complete(bsty)) {
            throw std::runtime_error(
                "terminal resolution blocked: funded leg is under-confirmed "
                "or unresolved");
        }

        const int claims =
            static_cast<int>(tru.claim) +
            static_cast<int>(bsty.claim);
        const int refunds =
            static_cast<int>(tru.refund) +
            static_cast<int>(bsty.refund);

        if (nextState == "SETTLED") {
            if (funded != 2 || claims != 2 || refunds != 0) {
                throw std::runtime_error(
                    "SETTLED requires both funded legs confirmed-claimed");
            }
        } else if (nextState == "REFUNDED") {
            if (claims != 0 || refunds != funded) {
                throw std::runtime_error(
                    "REFUNDED requires every funded leg confirmed-refunded");
            }
        } else {
            if (funded != 2 ||
                claims < 1 ||
                refunds < 1 ||
                claims + refunds != funded) {
                throw std::runtime_error(
                    "RESOLVED_MIXED requires two funded legs, one confirmed "
                    "outcome per leg, and both claim/refund outcome types");
            }
        }
    }

    saveRecord(storage, record);
    return record;
}

inline json listRecords(LevelDBStorage* storage) {
    json out = json::array();
    requireStorage(storage).iteratePrefix(
        STORAGE_PREFIX,
        [&](const std::string&, const std::string& value) {
            try {
                out.push_back(json::parse(value));
            } catch (...) {
            }
        });
    return out;
}

} // namespace tru_swap_v1
