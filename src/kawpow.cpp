#include "kawpow.h"
#include <iostream>
#include <stdexcept>
#include <mutex>
#include <ethash/ethash.hpp>

static KawpowCache cachedKawpowCache;
static uint64_t cachedEpoch = UINT64_MAX;
static std::mutex cacheMutex;

KawpowCache getKawpowCache(uint64_t blockHeight)
{
    // Typically 7500 blocks per epoch for KawPow
    uint64_t epoch = blockHeight / 7500;

    std::lock_guard<std::mutex> lock(cacheMutex);

    if (epoch == cachedEpoch) {
        return cachedKawpowCache;
    }

    KawpowCache temp;
    temp.epoch = epoch;

    try {
        // THIS is the correct "light" approach in chfast/ethash
        ethash::epoch_context_ptr uniqueCtx = ethash::create_epoch_context(epoch);

        if (!uniqueCtx) {
            throw std::runtime_error("create_epoch_context() returned null pointer.");
        }

        // Convert unique_ptr -> shared_ptr
        std::shared_ptr<ethash_epoch_context> sharedCtx(
            uniqueCtx.release(),
            uniqueCtx.get_deleter()
        );

        temp.contextPtr = sharedCtx;

        // Update global cache
        cachedKawpowCache = temp;
        cachedEpoch = epoch;

        std::cout << "[Kawpow] Created new *light* epoch_context for epoch " << epoch << "\n";
    }
    catch (const std::exception &ex) {
        throw std::runtime_error(std::string("Failed to build KawpowCache: ") + ex.what());
    }

    return cachedKawpowCache; 
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kawpowHash(const std::vector<uint8_t> &headerWithoutNonce,
           uint64_t nonce,
           const KawpowCache &cache)
{
    if (!cache.contextPtr) {
        throw std::runtime_error("[kawpowHash] KawpowCache has a null contextPtr");
    }

    ethash::hash256 header_hash = ethash::keccak256(
        headerWithoutNonce.data(),
        headerWithoutNonce.size()
    );

    ethash::result result = ethash::hash(*cache.contextPtr, header_hash, nonce);

    std::vector<uint8_t> mixHash(sizeof(result.mix_hash.bytes));
    std::memcpy(mixHash.data(), result.mix_hash.bytes, mixHash.size());

    std::vector<uint8_t> finalHash(sizeof(result.final_hash.bytes));
    std::memcpy(finalHash.data(), result.final_hash.bytes, finalHash.size());

    return {mixHash, finalHash};
}
