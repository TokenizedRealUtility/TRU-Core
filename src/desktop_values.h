#pragma once
#include <cstdint>
#include <limits>
#include <string>
namespace tru_desktop {
inline bool positiveUnits(const std::string& s, std::uint64_t& out) {
    out = 0;
    if (s.empty()) return false;
    for (const unsigned char c : s) {
        if (c < '0' || c > '9' || out > (std::numeric_limits<std::uint64_t>::max() - (c-'0'))/10) return false;
        out = out*10 + (c-'0');
    }
    return out != 0;
}
inline std::string littleEndianHex(std::uint64_t v, unsigned bytes) {
    const char* digits = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < bytes; ++i) {
        const auto byte = static_cast<unsigned>((v >> (8*i)) & 255);
        out.push_back(digits[byte >> 4]); out.push_back(digits[byte & 15]);
    }
    return out;
}
}
