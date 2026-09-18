#include "vah_observation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <stdexcept>

namespace {

constexpr const char TRANSPORT_DOMAIN[] = "TRU_VAH_CANDIDATE_V1";
constexpr std::size_t TRANSPORT_DOMAIN_SIZE = sizeof(TRANSPORT_DOMAIN) - 1U;
constexpr std::size_t TRANSPORT_SIZE =
    TRANSPORT_DOMAIN_SIZE + 2U + 8U + 8U + (32U * 5U) + 8U + 8U;

bool isLowerHex(const std::string& s, std::size_t n) {
    if (s.size() != n) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isdigit(c) || (c >= 'a' && c <= 'f');
    });
}

int hexNibble(unsigned char c) {
    if (c >= '0' && c <= '9') return static_cast<int>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<int>(c - 'a') + 10;
    return -1;
}

bool decodeLowerHex(const std::string& hex, std::vector<unsigned char>& out) {
    out.clear();
    if ((hex.size() % 2U) != 0U) return false;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = hexNibble(static_cast<unsigned char>(hex[i]));
        const int lo = hexNibble(static_cast<unsigned char>(hex[i + 1U]));
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string encodeLowerHex(const unsigned char* data, std::size_t size) {
    static constexpr char table[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2U);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(table[(data[i] >> 4) & 0x0fU]);
        out.push_back(table[data[i] & 0x0fU]);
    }
    return out;
}

void appendU16BE(std::string& out, uint16_t value) {
    out.push_back(static_cast<char>((value >> 8) & 0xffU));
    out.push_back(static_cast<char>(value & 0xffU));
}

void appendU64BE(std::string& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xffU));
    }
}

bool readU64BE(const std::string& in, std::size_t& pos, uint64_t& value) {
    if (pos + 8U > in.size()) return false;
    value = 0U;
    for (std::size_t i = 0; i < 8U; ++i) {
        value = (value << 8) |
            static_cast<unsigned char>(in[pos++]);
    }
    return true;
}

bool appendHexBytes(
    std::string& out,
    const std::string& hex,
    std::size_t expectedBytes)
{
    std::vector<unsigned char> decoded;
    if (!decodeLowerHex(hex, decoded) || decoded.size() != expectedBytes) {
        return false;
    }
    out.append(
        reinterpret_cast<const char*>(decoded.data()),
        decoded.size());
    return true;
}

bool readHexBytes(
    const std::string& in,
    std::size_t& pos,
    std::size_t bytes,
    std::string& out)
{
    if (pos + bytes > in.size()) return false;
    out = encodeLowerHex(
        reinterpret_cast<const unsigned char*>(in.data() + pos),
        bytes);
    pos += bytes;
    return true;
}

bool structurallyValidCandidate(const VAHReconciliation::Candidate& c) {
    return
        isLowerHex(c.tokenID, 16U) &&
        c.epoch > 0U &&
        isLowerHex(c.previousMetadataHash, 64U) &&
        isLowerHex(c.newMetadataHash, 64U) &&
        isLowerHex(c.recordHash, 64U) &&
        isLowerHex(c.anchorTxid, 64U) &&
        isLowerHex(c.blockHash, 64U) &&
        c.blockHeight > 0U;
}

bool parseCanonicalEpoch(const std::string& text, uint64_t& epoch) {
    epoch = 0U;
    if (text.empty() || text.size() > 20U ||
        (text.size() > 1U && text.front() == '0'))
    {
        return false;
    }
    if (!std::all_of(text.begin(), text.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        }))
    {
        return false;
    }
    try {
        std::size_t used = 0U;
        const unsigned long long parsed = std::stoull(text, &used, 10);
        if (used != text.size() || parsed == 0ULL) return false;
        epoch = static_cast<uint64_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

enum class PushReadStatus { Ok, End, Malformed };

PushReadStatus readMinimalPush(
    const std::vector<unsigned char>& script,
    std::size_t& pos,
    std::string& out)
{
    out.clear();
    if (pos == script.size()) return PushReadStatus::End;
    if (pos > script.size()) return PushReadStatus::Malformed;

    const unsigned char opcode = script[pos++];
    std::size_t length = 0U;
    if (opcode <= 75U) {
        length = opcode;
    } else if (opcode == 0x4cU) {
        if (pos >= script.size()) return PushReadStatus::Malformed;
        length = script[pos++];
        if (length <= 75U) return PushReadStatus::Malformed;
    } else if (opcode == 0x4dU) {
        if (pos + 2U > script.size()) return PushReadStatus::Malformed;
        length = static_cast<std::size_t>(script[pos]) |
            (static_cast<std::size_t>(script[pos + 1U]) << 8U);
        pos += 2U;
        if (length <= 255U) return PushReadStatus::Malformed;
    } else {
        return PushReadStatus::Malformed;
    }

    if (pos + length > script.size()) return PushReadStatus::Malformed;
    out.assign(
        reinterpret_cast<const char*>(script.data() + pos),
        length);
    pos += length;
    return PushReadStatus::Ok;
}

void appendMinimalPush(std::vector<unsigned char>& script, const std::string& value) {
    const std::size_t length = value.size();
    if (length <= 75U) {
        script.push_back(static_cast<unsigned char>(length));
    } else if (length <= 255U) {
        script.push_back(0x4cU);
        script.push_back(static_cast<unsigned char>(length));
    } else if (length <= 65535U) {
        script.push_back(0x4dU);
        script.push_back(static_cast<unsigned char>(length & 0xffU));
        script.push_back(static_cast<unsigned char>((length >> 8U) & 0xffU));
    } else {
        throw std::invalid_argument("VAH anchor field exceeds PUSHDATA2 bound");
    }
    script.insert(script.end(), value.begin(), value.end());
}

bool isAllZeroHash(const std::string& value) {
    return value.size() == 64U &&
        std::all_of(value.begin(), value.end(), [](char c) { return c == '0'; });
}

bool structurallyValidAnchorV2(const VAHObservation::AnchorV2& anchor) {
    return isLowerHex(anchor.tokenID, 16U) &&
        (anchor.tokenType == "SFT" || anchor.tokenType == "NCFT") &&
        anchor.epoch > 0U &&
        !anchor.provider.empty() && !anchor.trigger.empty() &&
        isLowerHex(anchor.previousMetadataHash, 64U) &&
        isLowerHex(anchor.newMetadataHash, 64U) &&
        isLowerHex(anchor.recordHash, 64U) &&
        !isAllZeroHash(anchor.recordHash);
}

} // namespace

namespace VAHObservation {

const std::string& v1UncommittedRecordHash() {
    static const std::string value(64U, '0');
    return value;
}

AnchorParseStatus parseEvolutionAnchorV1(
    const std::string& scriptHex,
    AnchorV1& out,
    std::string& reason)
{
    out = AnchorV1{};
    reason.clear();

    if (scriptHex.size() < 4U || scriptHex.rfind("6a", 0U) != 0U) {
        return AnchorParseStatus::NotEvolutionAnchor;
    }
    if ((scriptHex.size() / 2U) > MAX_ANCHOR_SCRIPT_BYTES) {
        reason = "OP_RETURN script exceeds VAH observation bound";
        return AnchorParseStatus::Malformed;
    }

    std::vector<unsigned char> script;
    if (!decodeLowerHex(scriptHex, script) || script.empty() ||
        script.front() != 0x6aU)
    {
        reason = "OP_RETURN script is not canonical lowercase hex";
        return AnchorParseStatus::Malformed;
    }

    std::size_t pos = 1U;
    std::string marker;
    const PushReadStatus markerStatus = readMinimalPush(script, pos, marker);
    if (markerStatus != PushReadStatus::Ok || marker != "TRU_EVOLVE_V1") {
        return AnchorParseStatus::NotEvolutionAnchor;
    }

    std::array<std::string, 7U> fields;
    for (auto& field : fields) {
        if (readMinimalPush(script, pos, field) != PushReadStatus::Ok) {
            reason = "TRU_EVOLVE_V1 anchor has missing/non-minimal field push";
            return AnchorParseStatus::Malformed;
        }
    }
    if (pos != script.size()) {
        reason = "TRU_EVOLVE_V1 anchor has trailing or extra fields";
        return AnchorParseStatus::Malformed;
    }

    out.tokenID = fields[0];
    out.tokenType = fields[1];
    out.provider = fields[3];
    out.trigger = fields[4];
    out.previousMetadataHash = fields[5];
    out.newMetadataHash = fields[6];

    if (!isLowerHex(out.tokenID, 16U)) {
        reason = "TRU_EVOLVE_V1 token id is not canonical 16-hex";
        return AnchorParseStatus::Malformed;
    }
    if (out.tokenType != "SFT" && out.tokenType != "NCFT") {
        reason = "TRU_EVOLVE_V1 token type is invalid";
        return AnchorParseStatus::Malformed;
    }
    if (!parseCanonicalEpoch(fields[2], out.epoch)) {
        reason = "TRU_EVOLVE_V1 epoch is not canonical decimal";
        return AnchorParseStatus::Malformed;
    }
    if (out.provider.empty() || out.trigger.empty()) {
        reason = "TRU_EVOLVE_V1 provider/trigger is empty";
        return AnchorParseStatus::Malformed;
    }
    if (!isLowerHex(out.previousMetadataHash, 64U) ||
        !isLowerHex(out.newMetadataHash, 64U))
    {
        reason = "TRU_EVOLVE_V1 metadata hash is invalid";
        return AnchorParseStatus::Malformed;
    }

    return AnchorParseStatus::Valid;
}

std::string encodeEvolutionAnchorV2(const AnchorV2& anchor) {
    if (!structurallyValidAnchorV2(anchor)) {
        throw std::invalid_argument("TRU_EVOLVE_V2 anchor is not structurally canonical");
    }

    std::vector<unsigned char> script;
    script.reserve(512U);
    script.push_back(0x6aU);
    appendMinimalPush(script, "TRU_EVOLVE_V2");
    appendMinimalPush(script, anchor.tokenID);
    appendMinimalPush(script, anchor.tokenType);
    appendMinimalPush(script, std::to_string(anchor.epoch));
    appendMinimalPush(script, anchor.provider);
    appendMinimalPush(script, anchor.trigger);
    appendMinimalPush(script, anchor.previousMetadataHash);
    appendMinimalPush(script, anchor.newMetadataHash);
    appendMinimalPush(script, anchor.recordHash);
    if (script.size() > MAX_ANCHOR_SCRIPT_BYTES) {
        throw std::invalid_argument("TRU_EVOLVE_V2 anchor exceeds VAH observation bound");
    }
    return encodeLowerHex(script.data(), script.size());
}

AnchorParseStatus parseEvolutionAnchorV2(
    const std::string& scriptHex,
    AnchorV2& out,
    std::string& reason)
{
    out = AnchorV2{};
    reason.clear();

    if (scriptHex.size() < 4U || scriptHex.rfind("6a", 0U) != 0U) {
        return AnchorParseStatus::NotEvolutionAnchor;
    }
    if ((scriptHex.size() / 2U) > MAX_ANCHOR_SCRIPT_BYTES) {
        reason = "OP_RETURN script exceeds VAH observation bound";
        return AnchorParseStatus::Malformed;
    }

    std::vector<unsigned char> script;
    if (!decodeLowerHex(scriptHex, script) || script.empty() ||
        script.front() != 0x6aU)
    {
        reason = "OP_RETURN script is not canonical lowercase hex";
        return AnchorParseStatus::Malformed;
    }

    std::size_t pos = 1U;
    std::string marker;
    const PushReadStatus markerStatus = readMinimalPush(script, pos, marker);
    if (markerStatus != PushReadStatus::Ok || marker != "TRU_EVOLVE_V2") {
        return AnchorParseStatus::NotEvolutionAnchor;
    }

    std::array<std::string, 8U> fields;
    for (auto& field : fields) {
        if (readMinimalPush(script, pos, field) != PushReadStatus::Ok) {
            reason = "TRU_EVOLVE_V2 anchor has missing/non-minimal field push";
            return AnchorParseStatus::Malformed;
        }
    }
    if (pos != script.size()) {
        reason = "TRU_EVOLVE_V2 anchor has trailing or extra fields";
        return AnchorParseStatus::Malformed;
    }

    out.tokenID = fields[0];
    out.tokenType = fields[1];
    out.provider = fields[3];
    out.trigger = fields[4];
    out.previousMetadataHash = fields[5];
    out.newMetadataHash = fields[6];
    out.recordHash = fields[7];

    if (!isLowerHex(out.tokenID, 16U)) {
        reason = "TRU_EVOLVE_V2 token id is not canonical 16-hex";
        return AnchorParseStatus::Malformed;
    }
    if (out.tokenType != "SFT" && out.tokenType != "NCFT") {
        reason = "TRU_EVOLVE_V2 token type is invalid";
        return AnchorParseStatus::Malformed;
    }
    if (!parseCanonicalEpoch(fields[2], out.epoch)) {
        reason = "TRU_EVOLVE_V2 epoch is not canonical decimal";
        return AnchorParseStatus::Malformed;
    }
    if (out.provider.empty() || out.trigger.empty()) {
        reason = "TRU_EVOLVE_V2 provider/trigger is empty";
        return AnchorParseStatus::Malformed;
    }
    if (!isLowerHex(out.previousMetadataHash, 64U) ||
        !isLowerHex(out.newMetadataHash, 64U) ||
        !isLowerHex(out.recordHash, 64U))
    {
        reason = "TRU_EVOLVE_V2 metadata/record hash is invalid";
        return AnchorParseStatus::Malformed;
    }
    if (isAllZeroHash(out.recordHash)) {
        reason = "TRU_EVOLVE_V2 record hash must be chain-committed non-zero";
        return AnchorParseStatus::Malformed;
    }

    return AnchorParseStatus::Valid;
}

std::string encodeCandidateTransportV1(
    const VAHReconciliation::Candidate& c)
{
    if (!structurallyValidCandidate(c)) {
        throw std::invalid_argument("candidate is not structurally canonical");
    }

    std::string out;
    out.reserve(TRANSPORT_SIZE);
    out.append(TRANSPORT_DOMAIN, TRANSPORT_DOMAIN_SIZE);
    appendU16BE(out, 1U);
    if (!appendHexBytes(out, c.tokenID, 8U)) throw std::logic_error("token id");
    appendU64BE(out, c.epoch);
    if (!appendHexBytes(out, c.previousMetadataHash, 32U) ||
        !appendHexBytes(out, c.newMetadataHash, 32U) ||
        !appendHexBytes(out, c.recordHash, 32U) ||
        !appendHexBytes(out, c.anchorTxid, 32U) ||
        !appendHexBytes(out, c.blockHash, 32U))
    {
        throw std::logic_error("candidate hash encoding");
    }
    appendU64BE(out, c.blockHeight);
    appendU64BE(out, c.txIndex);
    if (out.size() != TRANSPORT_SIZE) {
        throw std::logic_error("candidate transport size mismatch");
    }
    return out;
}

bool decodeCandidateTransportV1(
    const std::string& encoded,
    VAHReconciliation::Candidate& c,
    std::string& reason)
{
    c = VAHReconciliation::Candidate{};
    reason.clear();
    if (encoded.size() != TRANSPORT_SIZE) {
        reason = "candidate transport has non-canonical size";
        return false;
    }
    if (encoded.compare(0U, TRANSPORT_DOMAIN_SIZE, TRANSPORT_DOMAIN) != 0) {
        reason = "candidate transport domain mismatch";
        return false;
    }

    std::size_t pos = TRANSPORT_DOMAIN_SIZE;
    if (static_cast<unsigned char>(encoded[pos++]) != 0U ||
        static_cast<unsigned char>(encoded[pos++]) != 1U)
    {
        reason = "candidate transport version mismatch";
        return false;
    }
    if (!readHexBytes(encoded, pos, 8U, c.tokenID) ||
        !readU64BE(encoded, pos, c.epoch) ||
        !readHexBytes(encoded, pos, 32U, c.previousMetadataHash) ||
        !readHexBytes(encoded, pos, 32U, c.newMetadataHash) ||
        !readHexBytes(encoded, pos, 32U, c.recordHash) ||
        !readHexBytes(encoded, pos, 32U, c.anchorTxid) ||
        !readHexBytes(encoded, pos, 32U, c.blockHash) ||
        !readU64BE(encoded, pos, c.blockHeight) ||
        !readU64BE(encoded, pos, c.txIndex) ||
        pos != encoded.size() ||
        !structurallyValidCandidate(c))
    {
        reason = "candidate transport contains invalid canonical fields";
        c = VAHReconciliation::Candidate{};
        return false;
    }
    return true;
}

ObservationResult observeConfirmedActiveRange(
    const ObservationRequest& request,
    const std::vector<BlockSnapshot>& blocks)
{
    ObservationResult out;
    if (!isLowerHex(request.expectedTokenID, 16U) ||
        request.expectedEpoch == 0U ||
        !isLowerHex(request.expectedPreviousMetadataHash, 64U) ||
        request.view.finalizedHeight == 0U ||
        !isLowerHex(request.view.finalizedBlockHash, 64U))
    {
        out.error = "invalid observation request/finalized view";
        return out;
    }
    if (blocks.empty() || blocks.size() > MAX_OBSERVATION_BLOCKS) {
        out.error = "active-chain observation range is empty or exceeds bound";
        return out;
    }

    std::size_t totalTransactions = 0U;
    for (std::size_t i = 0U; i < blocks.size(); ++i) {
        const BlockSnapshot& block = blocks[i];
        if (!isLowerHex(block.blockHash, 64U) || block.height == 0U ||
            block.height > request.view.finalizedHeight)
        {
            out.error = "active-chain block snapshot is invalid/outside finalized prefix";
            return out;
        }
        if (i > 0U) {
            const BlockSnapshot& previous = blocks[i - 1U];
            if (previous.height == std::numeric_limits<uint64_t>::max() ||
                block.height != previous.height + 1U ||
                block.previousBlockHash != previous.blockHash)
            {
                out.error = "active-chain observation range is not contiguous";
                return out;
            }
        }

        if (block.transactions.size() >
            MAX_OBSERVATION_TRANSACTIONS - totalTransactions)
        {
            out.error = "active-chain transaction observation bound exceeded";
            return out;
        }
        totalTransactions += block.transactions.size();

        for (std::size_t txIndex = 0U;
             txIndex < block.transactions.size();
             ++txIndex)
        {
            const TransactionSnapshot& tx = block.transactions[txIndex];
            if (!isLowerHex(tx.txid, 64U)) {
                out.error = "active-chain transaction has invalid txid";
                return out;
            }

            for (const OutputSnapshot& txout : tx.outputs) {
                if (txout.amount != 0U) continue;

                std::string reason;
                std::string tokenID;
                uint64_t epoch = 0U;
                std::string previousMetadataHash;
                std::string newMetadataHash;
                std::string recordHash;

                AnchorV2 anchorV2;
                const AnchorParseStatus statusV2 =
                    parseEvolutionAnchorV2(txout.scriptPubKey, anchorV2, reason);
                if (statusV2 == AnchorParseStatus::Malformed) {
                    ++out.malformedEvolutionAnchors;
                    continue;
                }
                if (statusV2 == AnchorParseStatus::Valid) {
                    tokenID = anchorV2.tokenID;
                    epoch = anchorV2.epoch;
                    previousMetadataHash = anchorV2.previousMetadataHash;
                    newMetadataHash = anchorV2.newMetadataHash;
                    recordHash = anchorV2.recordHash;
                } else {
                    AnchorV1 anchorV1;
                    const AnchorParseStatus statusV1 =
                        parseEvolutionAnchorV1(txout.scriptPubKey, anchorV1, reason);
                    if (statusV1 == AnchorParseStatus::NotEvolutionAnchor) continue;
                    if (statusV1 == AnchorParseStatus::Malformed) {
                        ++out.malformedEvolutionAnchors;
                        continue;
                    }
                    tokenID = anchorV1.tokenID;
                    epoch = anchorV1.epoch;
                    previousMetadataHash = anchorV1.previousMetadataHash;
                    newMetadataHash = anchorV1.newMetadataHash;
                    recordHash = v1UncommittedRecordHash();
                }

                if (tokenID != request.expectedTokenID ||
                    epoch != request.expectedEpoch ||
                    previousMetadataHash != request.expectedPreviousMetadataHash)
                {
                    ++out.ignoredOtherEvolutionAnchors;
                    continue;
                }

                VAHReconciliation::Candidate candidate;
                candidate.tokenID = tokenID;
                candidate.epoch = epoch;
                candidate.previousMetadataHash = previousMetadataHash;
                candidate.newMetadataHash = newMetadataHash;
                candidate.recordHash = recordHash;
                candidate.anchorTxid = tx.txid;
                candidate.blockHash = block.blockHash;
                candidate.blockHeight = block.height;
                candidate.txIndex = static_cast<uint64_t>(txIndex);

                std::string candidateReason;
                if (!VAHReconciliation::validateCandidate(
                        candidate,
                        request.expectedTokenID,
                        request.expectedEpoch,
                        request.expectedPreviousMetadataHash,
                        request.view,
                        candidateReason))
                {
                    out.error = "chain-derived candidate failed election gate: " +
                        candidateReason;
                    return out;
                }
                if (out.candidates.size() >=
                    VAHReconciliation::MAX_CANDIDATES_PER_EPOCH)
                {
                    out.error = "confirmed candidate observation bound exceeded";
                    return out;
                }
                out.candidates.push_back(std::move(candidate));
            }
        }
    }

    const BlockSnapshot& last = blocks.back();
    if (last.height != request.view.finalizedHeight ||
        last.blockHash != request.view.finalizedBlockHash)
    {
        out.error = "observation range does not end at finalized view";
        return out;
    }

    out.ok = true;
    return out;
}

} // namespace VAHObservation
