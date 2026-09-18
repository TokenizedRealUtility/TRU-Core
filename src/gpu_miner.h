#ifndef GPU_MINER_H
#define GPU_MINER_H

#include <cstdint>
#include <vector>
#include <string>

/**
 * @brief mineBlockOpenCLAdvanced
 * 
 * Tries to find a valid nonce for “SHA-256 + 21E8” using GPU (OpenCL).
 *
 * @param header80         80-byte block header (excluding nonce)
 * @param targetBE         32-byte big-endian target
 * @param startNonce       Starting nonce
 * @param maxNonce         If nonzero, the highest nonce to try
 * @param globalWorkSize   Number of GPU threads
 * @param localWorkSize    Local group size
 * @param numPipelines     (unused or optional)
 * @param numRoundsPerThread (unused or optional)
 * @param foundNonce       [out] winning nonce if found
 * @param finalHash        [out] final 32-byte solution
 * @return true if a solution is found, else false
 */
bool mineBlockOpenCLAdvanced(
    const std::vector<unsigned char>& header80,
    const std::vector<unsigned char>& targetBE,
    uint64_t startNonce,
    uint64_t maxNonce,
    size_t   globalWorkSize,
    size_t   localWorkSize,
    int      numPipelines,
    int      numRoundsPerThread,
    uint64_t &foundNonce,
    std::vector<unsigned char> &finalHash
);

#endif // GPU_MINER_H
