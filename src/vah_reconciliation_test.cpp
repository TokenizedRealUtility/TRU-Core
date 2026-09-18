#include "vah_reconciliation.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace VAHReconciliation;

static std::string hx(char c, std::size_t n) {
    return std::string(n, c);
}

static Candidate cand(
    uint64_t height,
    uint64_t txIndex,
    char tx,
    char newHash,
    char recordHash)
{
    Candidate c;
    c.tokenID = "2df1363f156c50b8";
    c.epoch = 2;
    c.previousMetadataHash = hx('a', 64);
    c.newMetadataHash = hx(newHash, 64);
    c.recordHash = hx(recordHash, 64);
    c.anchorTxid = hx(tx, 64);
    c.blockHash = hx(height == 100 ? 'b' : 'c', 64);
    c.blockHeight = height;
    c.txIndex = txIndex;
    return c;
}

int main() {
    const CanonicalView view{101, hx('d', 64)};

    const Candidate early = cand(100, 7, '2', 'e', 'f');
    const Candidate late  = cand(101, 0, '1', '1', '2');

    // Arrival order cannot affect the winner.
    {
        auto a = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, {early, late});
        auto b = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, {late, early});
        assert(a.ok && a.hasWinner);
        assert(b.ok && b.hasWinner);
        assert(sameCanonicalIdentity(a.winner, early));
        assert(sameCanonicalIdentity(b.winner, early));
    }

    // Simulated independent peer arrival permutations all converge.
    {
        std::vector<Candidate> base = {
            cand(100, 9, '9', '9', '9'),
            cand(100, 3, '8', '8', '8'),
            cand(100, 3, '7', '7', '7'),
            cand(101, 0, '1', '1', '1')
        };
        const Candidate expected = base[2]; // same block/index, lower txid

        std::mt19937 rng(0x545255U);
        for (int i = 0; i < 128; ++i) {
            std::shuffle(base.begin(), base.end(), rng);
            auto r = electCanonicalCandidate(
                "2df1363f156c50b8", 2, hx('a', 64), view, base);
            assert(r.ok && r.hasWinner);
            assert(sameCanonicalIdentity(r.winner, expected));
        }
    }

    // Exact duplicate observation cannot create ambiguity.
    {
        auto r = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view,
            {early, early, late});
        assert(r.ok && r.hasWinner);
        assert(sameCanonicalIdentity(r.winner, early));
    }

    // Parent mismatch is ineligible.
    {
        Candidate wrong = early;
        wrong.previousMetadataHash = hx('0', 64);
        auto r = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, {wrong});
        assert(r.ok && !r.hasWinner);
        assert(r.rejected.size() == 1);
    }

    // Future/unfinalized observation is ineligible.
    {
        Candidate future = early;
        future.blockHeight = 102;
        auto r = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, {future});
        assert(r.ok && !r.hasWinner);
    }

    // Malformed identity fails closed.
    {
        Candidate bad = early;
        bad.anchorTxid = "ABC";
        auto r = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, {bad});
        assert(r.ok && !r.hasWinner);
    }

    // Bound prevents attacker-sized election sets.
    {
        std::vector<Candidate> many(MAX_CANDIDATES_PER_EPOCH + 1, early);
        auto r = electCanonicalCandidate(
            early.tokenID, 2, hx('a', 64), view, many);
        assert(!r.ok);
    }

    // Tie-breakers are deterministic all the way to record hash.
    {
        Candidate a = cand(100, 3, '7', '5', '8');
        Candidate b = a;
        b.recordHash = hx('7', 64);
        auto r = electCanonicalCandidate(
            a.tokenID, 2, hx('a', 64), view, {a, b});
        assert(r.ok && r.hasWinner);
        assert(r.winner.recordHash == hx('7', 64));
    }

    std::cout << "TRU_VAH_02A_CANONICAL_EPOCH_ELECTION_MATRIX=PASS\n";
    return 0;
}
