#include "vah_observation.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

using namespace VAHObservation;
using namespace VAHReconciliation;

static std::string hx(char c, std::size_t n) {
    return std::string(n, c);
}

static std::string hexEncode(const std::string& bytes) {
    static constexpr char table[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : bytes) {
        out.push_back(table[(c >> 4) & 0x0fU]);
        out.push_back(table[c & 0x0fU]);
    }
    return out;
}

static void push(std::string& script, const std::string& value) {
    const std::size_t n = value.size();
    if (n <= 75U) {
        script.push_back(static_cast<char>(n));
    } else if (n <= 255U) {
        script.push_back(static_cast<char>(0x4c));
        script.push_back(static_cast<char>(n));
    } else if (n <= 65535U) {
        script.push_back(static_cast<char>(0x4d));
        script.push_back(static_cast<char>(n & 0xffU));
        script.push_back(static_cast<char>((n >> 8U) & 0xffU));
    } else {
        throw std::runtime_error("test push too large");
    }
    script += value;
}

static std::string anchorScript(
    const std::string& token,
    uint64_t epoch,
    const std::string& previousHash,
    const std::string& newHash,
    const std::string& trigger = "inspection")
{
    std::string script(1U, static_cast<char>(0x6a));
    for (const std::string& value : std::vector<std::string>{
             "TRU_EVOLVE_V1", token, "SFT", std::to_string(epoch),
             "openai", trigger, previousHash, newHash})
    {
        push(script, value);
    }
    return hexEncode(script);
}

static Candidate candidate() {
    Candidate c;
    c.tokenID = "2df1363f156c50b8";
    c.epoch = 2U;
    c.previousMetadataHash = hx('a', 64U);
    c.newMetadataHash = hx('b', 64U);
    c.recordHash = hx('c', 64U);
    c.anchorTxid = hx('d', 64U);
    c.blockHash = hx('e', 64U);
    c.blockHeight = 100U;
    c.txIndex = 7U;
    return c;
}

static BlockSnapshot block(
    uint64_t height,
    char blockHash,
    char previousBlockHash,
    std::vector<TransactionSnapshot> transactions)
{
    BlockSnapshot b;
    b.blockHash = hx(blockHash, 64U);
    b.previousBlockHash = hx(previousBlockHash, 64U);
    b.height = height;
    b.transactions = std::move(transactions);
    return b;
}

int main() {
    const std::string token = "2df1363f156c50b8";
    const std::string parent = hx('a', 64U);

    // Exact anchor parse, including a PUSHDATA1 trigger.
    {
        AnchorV1 anchor;
        std::string reason;
        const std::string longTrigger(100U, 't');
        assert(parseEvolutionAnchorV1(
            anchorScript(token, 2U, parent, hx('b', 64U), longTrigger),
            anchor,
            reason) == AnchorParseStatus::Valid);
        assert(anchor.tokenID == token);
        assert(anchor.epoch == 2U);
        assert(anchor.trigger == longTrigger);
    }

    // Unrelated OP_RETURN is not a VAH claim.
    {
        std::string raw(1U, static_cast<char>(0x6a));
        push(raw, "OTHER_PROTOCOL");
        AnchorV1 anchor;
        std::string reason;
        assert(parseEvolutionAnchorV1(
            hexEncode(raw), anchor, reason) ==
            AnchorParseStatus::NotEvolutionAnchor);
    }

    // Once the marker is present, truncation, extra fields and non-minimal
    // pushes fail closed as malformed anchors.
    {
        const std::string valid =
            anchorScript(token, 2U, parent, hx('b', 64U));
        AnchorV1 anchor;
        std::string reason;
        assert(parseEvolutionAnchorV1(
            valid.substr(0U, valid.size() - 2U), anchor, reason) ==
            AnchorParseStatus::Malformed);

        std::string extra = valid;
        extra += "0178";
        assert(parseEvolutionAnchorV1(
            extra, anchor, reason) == AnchorParseStatus::Malformed);

        std::string nonMinimal(1U, static_cast<char>(0x6a));
        nonMinimal.push_back(static_cast<char>(0x4c));
        nonMinimal.push_back(static_cast<char>(13));
        nonMinimal += "TRU_EVOLVE_V1";
        assert(parseEvolutionAnchorV1(
            hexEncode(nonMinimal), anchor, reason) ==
            AnchorParseStatus::NotEvolutionAnchor);
    }

    // Canonical candidate transport is fixed-size and round-trips exactly.
    {
        const Candidate input = candidate();
        const std::string encoded = encodeCandidateTransportV1(input);
        Candidate decoded;
        std::string reason;
        assert(decodeCandidateTransportV1(encoded, decoded, reason));
        assert(sameCanonicalIdentity(input, decoded));

        std::string truncated = encoded.substr(0U, encoded.size() - 1U);
        assert(!decodeCandidateTransportV1(truncated, decoded, reason));

        std::string wrongDomain = encoded;
        wrongDomain[0] = 'X';
        assert(!decodeCandidateTransportV1(wrongDomain, decoded, reason));
    }

    // The confirmed active-chain snapshot, not peer arrival order, supplies
    // block height/index/txid.  Two anchors in one block elect by tx index.
    {
        ObservationRequest request;
        request.expectedTokenID = token;
        request.expectedEpoch = 2U;
        request.expectedPreviousMetadataHash = parent;
        request.view = CanonicalView{101U, hx('e', 64U)};

        TransactionSnapshot unrelated{
            hx('1', 64U),
            {{0U, anchorScript(token, 7U, hx('0', 64U), hx('f', 64U))}}
        };
        TransactionSnapshot later{
            hx('3', 64U),
            {{0U, anchorScript(token, 2U, parent, hx('d', 64U))}}
        };
        TransactionSnapshot earlier{
            hx('2', 64U),
            {{0U, anchorScript(token, 2U, parent, hx('c', 64U))}}
        };

        const std::vector<BlockSnapshot> blocks = {
            block(100U, 'd', 'c', {}),
            block(101U, 'e', 'd', {unrelated, earlier, later})
        };
        const ObservationResult observed =
            observeConfirmedActiveRange(request, blocks);
        assert(observed.ok);
        assert(observed.candidates.size() == 2U);
        assert(observed.ignoredOtherEvolutionAnchors == 1U);
        assert(observed.candidates[0].recordHash ==
            v1UncommittedRecordHash());

        const ElectionResult elected = electCanonicalCandidate(
            token, 2U, parent, request.view, observed.candidates);
        assert(elected.ok && elected.hasWinner);
        assert(elected.winner.anchorTxid == hx('2', 64U));
        assert(elected.winner.txIndex == 1U);
    }

    // Arrival permutations after fixed-size transport all converge.
    {
        Candidate a = candidate();
        Candidate b = a;
        b.anchorTxid = hx('1', 64U);
        b.txIndex = 3U;
        Candidate c = a;
        c.anchorTxid = hx('2', 64U);
        c.txIndex = 3U;
        std::vector<std::string> wire = {
            encodeCandidateTransportV1(a),
            encodeCandidateTransportV1(b),
            encodeCandidateTransportV1(c)
        };
        std::mt19937 rng(0x545255U);
        for (int round = 0; round < 64; ++round) {
            std::shuffle(wire.begin(), wire.end(), rng);
            std::vector<Candidate> decoded;
            for (const std::string& item : wire) {
                Candidate value;
                std::string reason;
                assert(decodeCandidateTransportV1(item, value, reason));
                decoded.push_back(value);
            }
            const ElectionResult result = electCanonicalCandidate(
                a.tokenID,
                a.epoch,
                a.previousMetadataHash,
                CanonicalView{100U, hx('f', 64U)},
                decoded);
            assert(result.ok && result.hasWinner);
            assert(result.winner.anchorTxid == hx('1', 64U));
        }
    }

    // Non-contiguous ranges and finalized-view mismatches fail closed.
    {
        ObservationRequest request{
            token, 2U, parent, CanonicalView{101U, hx('e', 64U)}};
        auto gap = observeConfirmedActiveRange(
            request,
            {block(99U, 'c', 'b', {}), block(101U, 'e', 'd', {})});
        assert(!gap.ok);

        auto wrongFinal = observeConfirmedActiveRange(
            request,
            {block(100U, 'd', 'c', {})});
        assert(!wrongFinal.ok);
    }

    // Bounded decoders tolerate arbitrary hostile bytes without accepting
    // non-canonical transport or crashing.
    {
        std::mt19937 rng(0x56414802U);
        std::uniform_int_distribution<int> lengthDistribution(0, 300);
        std::uniform_int_distribution<int> byteDistribution(0, 255);
        for (int round = 0; round < 1024; ++round) {
            const int length = lengthDistribution(rng);
            std::string hostile(static_cast<std::size_t>(length), '\0');
            for (char& c : hostile) {
                c = static_cast<char>(byteDistribution(rng));
            }
            Candidate decoded;
            std::string reason;
            (void)decodeCandidateTransportV1(hostile, decoded, reason);

            AnchorV1 anchor;
            (void)parseEvolutionAnchorV1(
                hexEncode(hostile), anchor, reason);
        }
    }

    // The 257th matching confirmed observation fails the epoch candidate
    // bound instead of creating an attacker-sized election set.
    {
        ObservationRequest request{
            token, 2U, parent, CanonicalView{100U, hx('d', 64U)}};
        std::vector<TransactionSnapshot> transactions;
        for (std::size_t i = 0U;
             i < MAX_CANDIDATES_PER_EPOCH + 1U;
             ++i)
        {
            std::string txid = hx('0', 64U);
            const std::string suffix = std::to_string(i);
            std::copy(
                suffix.begin(), suffix.end(),
                txid.end() - static_cast<std::ptrdiff_t>(suffix.size()));
            transactions.push_back(TransactionSnapshot{
                txid,
                {{0U, anchorScript(token, 2U, parent, hx('b', 64U))}}
            });
        }
        const ObservationResult bounded = observeConfirmedActiveRange(
            request,
            {block(100U, 'd', 'c', std::move(transactions))});
        assert(!bounded.ok);
    }

    std::cout << "TRU_VAH_02B_TRANSPORT_ACTIVE_CHAIN_OBSERVATION_MATRIX=PASS\n";
    return 0;
}
