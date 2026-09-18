#ifndef KAWPOW_H
#define KAWPOW_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <memory>                  // For std::shared_ptr
#include <ethash/keccak.hpp>
#include <ethash/ethash.hpp>

/**
 * @brief Holds the epoch context for Kawpow (Ravencoin/ETC style).
 *
 * We store a std::shared_ptr to ethash_epoch_context so that
 * KawpowCache can be copied or assigned. If we used a unique_ptr,
 * the struct would be non-copyable.
 */
struct KawpowCache
{
    uint64_t epoch;
    // We store a *shared_ptr* to allow copying/assignment of KawpowCache.
    std::shared_ptr<ethash_epoch_context> contextPtr;

    // Optional: a default constructor is handy if you have static objects
    KawpowCache()
        : epoch(0)
        , contextPtr(nullptr)
    {}
};

/**
 * @brief Retrieves or builds the KawpowCache for a given block height.
 *
 * Determines the epoch from `blockHeight`, then creates (or returns a cached)
 * epoch context. Under the hood, we convert the unique_ptr from
 * ethash::create_epoch_context() to a std::shared_ptr.
 *
 * @param blockHeight The height of the block
 * @return A KawpowCache struct with (epoch, shared_ptr to epoch_context)
 */
KawpowCache getKawpowCache(uint64_t blockHeight);

/**
 * @brief Computes the Kawpow hash (mixHash, finalHash) for a block header.
 *
 * @param headerWithoutNonce The serialized block header bytes, excluding the nonce
 * @param nonce A 64-bit nonce
 * @param cache The KawpowCache (with epoch context) for this block’s epoch
 * @return A pair of (mixHash, finalHash), both 32 bytes
 */
std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kawpowHash(const std::vector<uint8_t> &headerWithoutNonce,
           uint64_t nonce,
           const KawpowCache &cache);

#endif // KAWPOW_H
