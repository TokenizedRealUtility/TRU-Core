#pragma once
// TRU-TOKEN-CONTINUATION-01: derived metadata indexing and wallet recovery only.
// These helpers do not validate blocks, alter UTXOs, or grant issuer authority.
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

namespace tru_token_continuation {
using json = nlohmann::json;
struct Branch {
    std::string tokenID, type, metaHash;
    uint64_t amount = 0;
};
inline bool hex(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
// Decode only the existing binary token format and its adjacent P2PKH control.
// No metadata fetch here: safe inside applyBlock's already-held chain lock.
template<class Tx> bool branch(const Tx& tx, uint32_t control, Branch& out) {
    if (control == 0 || control >= tx.vout.size()) return false;
    const auto& data = tx.vout[control - 1];
    const auto& pay = tx.vout[control];
    const std::string& s = data.scriptPubKey;
    if ((s.size() != 140 && s.size() != 132) || !hex(s) ||
        s.substr(0, 2) != "6a" || data.amount != 0 || pay.amount == 0) return false;
    const size_t idLen = s.size() == 140 ? 16 : 8;
    const std::string type = s.substr(2, 2);
    Branch b;
    if (type == "01") b.type = "FT";
    else if (type == "02") b.type = "NFT";
    else if (type == "03") b.type = "SFT";
    else if (type == "04") b.type = "NCFT";
    else return false;
    b.tokenID = s.substr(4, idLen);
    b.amount = std::stoull(s.substr(4 + idLen, 16), nullptr, 16);
    const size_t ownerPos = 4 + idLen + 16;
    if (pay.scriptPubKey != "76a914" + s.substr(ownerPos, 40) + "88ac") return false;
    b.metaHash = s.substr(ownerPos + 40, 64);
    out = b;
    return true;
}
template<class Hash> bool matches(const json& m, const Branch& b, Hash hash) {
    try {
        return m.is_object() && m.value("tokenID", "") == b.tokenID &&
            m.value("type", "") == b.type && m.contains("meta") &&
            m.at("meta").is_object() && hash(m.at("meta")) == b.metaHash;
    } catch (...) { return false; }
}
// Read-only: never backfill the DB or substitute issuance amount/owner as balance.
template<class Read, class Hash> bool resolve(
    Read read, Hash hash, const std::string& txid, const Branch& b, json& out) {
    try {
        std::string raw;
        if (read("tokenMetadata:" + txid, raw)) {
            auto m = json::parse(raw);
            if (!matches(m, b, hash)) return false; // corrupt/conflicting record
            out = std::move(m);
            return true;
        }
        std::string root;
        if (!read("tokenIssuance:" + b.tokenID, root) ||
            root.size() != 64 || !hex(root) || root == txid ||
            !read("tokenMetadata:" + root, raw)) return false;
        auto m = json::parse(raw);
        if (!matches(m, b, hash)) return false;
        // A root record's amount/owner are issuance facts, not this branch's.
        m.erase("owner");
        m.erase("controllingVout");
        m["amount"] = std::to_string(b.amount);
        out = std::move(m);
        return true;
    } catch (...) { return false; }
}
inline bool add(uint64_t value, uint64_t& sum) {
    if (value > std::numeric_limits<uint64_t>::max() - sum) return false;
    sum += value;
    return true;
}
// Classifies metadata only. ReadInput must require a confirmed live control UTXO
// and decode the corresponding confirmed parent transaction, never caller JSON.
template<class Tx, class ReadInput, class Hash> bool continuation(
    const Tx& tx, const json& m, ReadInput readInput, Hash hash) {
    try {
        const std::string id = m.at("tokenID").template get<std::string>();
        uint64_t incoming = 0, outgoing = 0;
        bool spent = false, created = false;
        for (const auto& in : tx.vin) {
            Branch b;
            if (!readInput(in, b) || b.tokenID != id) continue;
            if (!matches(m, b, hash) || !add(b.amount, incoming)) return false;
            spent = true;
        }
        for (uint32_t v = 1; v < tx.vout.size(); ++v) {
            Branch b;
            if (!branch(tx, v, b) || b.tokenID != id) continue;
            if (!matches(m, b, hash) || !add(b.amount, outgoing)) return false;
            created = true;
        }
        return spent && created && incoming > 0 && incoming == outgoing;
    } catch (...) { return false; }
}
} // namespace tru_token_continuation
