#ifndef SHA256_21E8_H
#define SHA256_21E8_H

#include <openssl/sha.h>
#include <cstdint>
#include <vector>
#include <cstring>
#include <stdexcept>

// Helper: read 4 bytes in big-endian from 'buf' into a 32-bit integer
static inline uint32_t read_be32(const unsigned char* buf)
{
    return (uint32_t(buf[0]) << 24) |
           (uint32_t(buf[1]) << 16) |
           (uint32_t(buf[2]) <<  8) |
            uint32_t(buf[3]);
}

// Helper: write 'val' as 4 big-endian bytes into 'buf'
static inline void write_be32(unsigned char* buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >>  8) & 0xff;
    buf[3] =  val        & 0xff;
}

/**
 * @brief sha256_21e8
 *
 * Computes "double SHA-256" on the given data, then
 * injects the constant 0x21E8 into the final 4 bytes (big-endian).
 * 
 * @param data The bytes to be hashed (header, nonce, etc.)
 * @return 32-byte final hash
 */
inline std::vector<unsigned char> sha256_21e8(const std::vector<unsigned char>& data)
{
    // 1) First SHA-256
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx1;
    SHA256_Init(&ctx1);
    SHA256_Update(&ctx1, data.data(), data.size());
    SHA256_Final(hash1, &ctx1);

    // 2) Second SHA-256
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx2;
    SHA256_Init(&ctx2);
    SHA256_Update(&ctx2, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &ctx2);

    // 3) Inject 0x21E8 into last 4 bytes (big-endian)
    uint32_t last32 = read_be32(&hash2[28]);
    last32 = (last32 + 0x21E8) & 0xffffffff;
    write_be32(&hash2[28], last32);

    return std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
}

#endif // SHA256_21E8_H
