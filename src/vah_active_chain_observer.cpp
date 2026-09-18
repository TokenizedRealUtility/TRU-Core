#include "vah_observation.h"

#include "blockchain.h"
#include "block.h"
#include "tx.h"

#include <limits>
#include <optional>
#include <utility>

namespace VAHObservation {

ObservationResult observeLocalActiveChain(
    const Blockchain& chain,
    const ObservationRequest& request,
    uint64_t firstHeight)
{
    ObservationResult failure;
    if (firstHeight == 0U ||
        firstHeight > request.view.finalizedHeight ||
        request.view.finalizedHeight - firstHeight + 1U >
            MAX_OBSERVATION_BLOCKS)
    {
        failure.error = "requested active-chain range is invalid or exceeds bound";
        return failure;
    }

    std::string tipHashBefore;
    int tipHeightBefore = 0;
    chain.getBestTipSnapshot(tipHashBefore, tipHeightBefore);
    if (tipHeightBefore < 0 ||
        request.view.finalizedHeight >
            static_cast<uint64_t>(tipHeightBefore))
    {
        failure.error = "finalized view is above local active-chain tip";
        return failure;
    }

    std::vector<BlockSnapshot> snapshots;
    snapshots.reserve(static_cast<std::size_t>(
        request.view.finalizedHeight - firstHeight + 1U));

    for (uint64_t height = firstHeight;
         height <= request.view.finalizedHeight;
         ++height)
    {
        const std::optional<Block> block = chain.getBlockByHeight(height);
        if (!block.has_value() || block->height < 0 ||
            static_cast<uint64_t>(block->height) != height)
        {
            failure.error = "local active-chain block lookup failed";
            return failure;
        }

        BlockSnapshot snapshot;
        snapshot.blockHash = block->blockHash;
        snapshot.previousBlockHash = block->header.prevHash;
        snapshot.height = height;
        snapshot.transactions.reserve(block->transactions.size());

        for (const Transaction& storedTx : block->transactions) {
            Transaction canonicalTx = storedTx;
            canonicalTx.computeTxId();
            if (storedTx.txid != canonicalTx.txid) {
                failure.error = "active-chain transaction txid recomputation mismatch";
                return failure;
            }

            TransactionSnapshot tx;
            tx.txid = storedTx.txid;
            tx.outputs.reserve(storedTx.vout.size());
            for (const TxOut& storedOutput : storedTx.vout) {
                tx.outputs.push_back(OutputSnapshot{
                    storedOutput.amount,
                    storedOutput.scriptPubKey
                });
            }
            snapshot.transactions.push_back(std::move(tx));
        }
        snapshots.push_back(std::move(snapshot));

        if (height == std::numeric_limits<uint64_t>::max()) break;
    }

    std::string tipHashAfter;
    int tipHeightAfter = 0;
    chain.getBestTipSnapshot(tipHashAfter, tipHeightAfter);
    if (tipHashBefore != tipHashAfter || tipHeightBefore != tipHeightAfter) {
        failure.error = "local active-chain tip moved during observation; retry";
        return failure;
    }

    return observeConfirmedActiveRange(request, snapshots);
}

} // namespace VAHObservation
