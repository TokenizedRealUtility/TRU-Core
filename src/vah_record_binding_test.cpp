#include "vah_observation.h"
#include "vah_reconciliation.h"
#include "vah_reconciliation_store.h"
#include "leveldb_storage.h"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace VAHObservation;
using namespace VAHReconciliation;
using namespace VAHDurableReconciliation;

namespace {
std::string hx(char c, std::size_t n) { return std::string(n, c); }

std::string hexEncode(const std::string& bytes) {
    static constexpr char table[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (unsigned char c : bytes) {
        out.push_back(table[(c >> 4U) & 0x0fU]);
        out.push_back(table[c & 0x0fU]);
    }
    return out;
}

void appendPush(std::string& script, const std::string& value) {
    const std::size_t n = value.size();
    assert(n <= 75U);
    script.push_back(static_cast<char>(n));
    script += value;
}

std::string v1Script(
    const std::string& token,
    uint64_t epoch,
    const std::string& parent,
    const std::string& next)
{
    std::string script(1U, static_cast<char>(0x6a));
    appendPush(script, "TRU_EVOLVE_V1");
    appendPush(script, token);
    appendPush(script, "SFT");
    appendPush(script, std::to_string(epoch));
    appendPush(script, "sensor");
    appendPush(script, "measurement");
    appendPush(script, parent);
    appendPush(script, next);
    return hexEncode(script);
}

BlockSnapshot block(
    uint64_t height,
    char hash,
    char previous,
    std::vector<TransactionSnapshot> txs)
{
    BlockSnapshot b;
    b.height = height;
    b.blockHash = hx(hash, 64U);
    b.previousBlockHash = hx(previous, 64U);
    b.transactions = std::move(txs);
    return b;
}

TransactionSnapshot tx(char txid, const std::string& script) {
    TransactionSnapshot t;
    t.txid = hx(txid, 64U);
    t.outputs.push_back(OutputSnapshot{0U, script});
    return t;
}
}

int main() {
    const std::string token = "2df1363f156c50b8";
    const uint64_t epoch = 7U;
    const std::string parent = hx('a', 64U);
    const std::string newHash = hx('b', 64U);
    const std::string recordHash = hx('c', 64U);
    const CanonicalView view{120U, hx('f', 64U)};

    AnchorV2 anchor;
    anchor.tokenID = token;
    anchor.tokenType = "SFT";
    anchor.epoch = epoch;
    anchor.provider = "sensor";
    anchor.trigger = "measurement";
    anchor.previousMetadataHash = parent;
    anchor.newMetadataHash = newHash;
    anchor.recordHash = recordHash;

    // Canonical strong anchor round-trip: exact record hash is on-chain data.
    const std::string strongScript = encodeEvolutionAnchorV2(anchor);
    AnchorV2 decoded;
    std::string reason;
    assert(parseEvolutionAnchorV2(strongScript, decoded, reason) == AnchorParseStatus::Valid);
    assert(reason.empty());
    assert(decoded.tokenID == token);
    assert(decoded.epoch == epoch);
    assert(decoded.previousMetadataHash == parent);
    assert(decoded.newMetadataHash == newHash);
    assert(decoded.recordHash == recordHash);

    // V2 refuses the V1 all-zero record-hash sentinel.
    AnchorV2 zero = anchor;
    zero.recordHash = v1UncommittedRecordHash();
    bool threw = false;
    try { (void)encodeEvolutionAnchorV2(zero); }
    catch (const std::invalid_argument&) { threw = true; }
    assert(threw);

    // Local active-chain derivation preserves exact V2 record identity.
    ObservationRequest request{token, epoch, parent, view};
    const std::vector<BlockSnapshot> strongBlocks = {
        block(119U, 'e', 'd', {tx('2', strongScript)}),
        block(120U, 'f', 'e', {})
    };
    const ObservationResult observed = observeConfirmedActiveRange(request, strongBlocks);
    assert(observed.ok);
    assert(observed.candidates.size() == 1U);
    const Candidate strongCandidate = observed.candidates.front();
    assert(strongCandidate.recordHash == recordHash);
    assert(validateStronglyBoundCandidate(strongCandidate, token, epoch, parent, view, reason));
    assert(verifyCommittedRecordHash(strongCandidate, recordHash, reason));

    // A different durable record cannot claim this anchor binding.
    assert(!verifyCommittedRecordHash(strongCandidate, hx('d', 64U), reason));
    assert(reason == "candidate committed record hash mismatch");

    // Legacy V1 remains observable for compatibility, but its all-zero
    // sentinel is explicitly ineligible for a closed reconciliation.
    const std::string weakScript = v1Script(token, epoch, parent, hx('9', 64U));
    const std::vector<BlockSnapshot> weakBlocks = {
        block(119U, 'e', 'd', {tx('1', weakScript)}),
        block(120U, 'f', 'e', {})
    };
    const ObservationResult weakObserved = observeConfirmedActiveRange(request, weakBlocks);
    assert(weakObserved.ok && weakObserved.candidates.size() == 1U);
    assert(weakObserved.candidates.front().recordHash == v1UncommittedRecordHash());
    assert(!validateStronglyBoundCandidate(
        weakObserved.candidates.front(), token, epoch, parent, view, reason));
    assert(reason == "candidate record hash is not chain-committed");

    // Even if an earlier V1 claim would win the legacy election, the closed
    // election rejects it and elects the later locally-observed V2 claim.
    Candidate weakEarlier = weakObserved.candidates.front();
    weakEarlier.blockHeight = 118U;
    weakEarlier.blockHash = hx('d', 64U);
    weakEarlier.anchorTxid = hx('1', 64U);
    Candidate strongLater = strongCandidate;
    strongLater.blockHeight = 119U;
    strongLater.blockHash = hx('e', 64U);
    strongLater.anchorTxid = hx('2', 64U);

    ElectionResult legacyElection = electCanonicalCandidate(
        token, epoch, parent, view, {strongLater, weakEarlier});
    assert(legacyElection.ok && legacyElection.hasWinner);
    assert(legacyElection.winner.recordHash == v1UncommittedRecordHash());

    ElectionResult closedElection = electStronglyBoundCanonicalCandidate(
        token, epoch, parent, view, {strongLater, weakEarlier});
    assert(closedElection.ok && closedElection.hasWinner);
    assert(sameCanonicalIdentity(closedElection.winner, strongLater));
    assert(closedElection.rejected.size() == 1U);

    // Tampering only record_hash keeps a structurally valid V2 anchor, but it
    // binds a different durable record and therefore fails exact record proof.
    AnchorV2 tamperedAnchor = anchor;
    tamperedAnchor.recordHash = hx('d', 64U);
    const ObservationResult tamperedObserved = observeConfirmedActiveRange(
        request,
        {block(119U, 'e', 'd', {tx('3', encodeEvolutionAnchorV2(tamperedAnchor))}),
         block(120U, 'f', 'e', {})});
    assert(tamperedObserved.ok && tamperedObserved.candidates.size() == 1U);
    assert(!verifyCommittedRecordHash(
        tamperedObserved.candidates.front(), recordHash, reason));
    assert(reason == "candidate committed record hash mismatch");

    // End-to-end closure: local V2 observation -> strong election -> durable
    // checkpoint -> real LevelDB close/reopen -> exact reconstruction.
    const std::string dbPath = "/tmp/truq-vah02d-closure-" +
        std::to_string(static_cast<long long>(::getpid()));
    std::filesystem::remove_all(dbPath);
    DurableResult beforeRestart;
    {
        LevelDBStorage storage(dbPath);
        assert(persistCanonicalResult(
            storage, token, epoch, parent, view, closedElection, reason));
        assert(loadCanonicalResult(
            storage, token, epoch, parent, beforeRestart, reason));
        assert(verifyCommittedRecordHash(beforeRestart.winner, recordHash, reason));
    }
    {
        LevelDBStorage storage(dbPath);
        DurableResult afterRestart;
        assert(loadCanonicalResult(
            storage, token, epoch, parent, afterRestart, reason));
        assert(sameDurableIdentity(beforeRestart, afterRestart));
        assert(verifyCommittedRecordHash(afterRestart.winner, recordHash, reason));
    }
    std::filesystem::remove_all(dbPath);

    std::cout << "TRU_VAH_02D_STRONG_RECORD_BINDING_RECONCILIATION_CLOSURE_MATRIX=PASS\n";
    return 0;
}
