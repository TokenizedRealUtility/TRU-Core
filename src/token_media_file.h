#pragma once
#include "token_media_v4.h"
#include <openssl/sha.h>
#include <array>
#include <fstream>
#include <filesystem>

namespace tru_media_v4 {
// Local UI helper only. Local paths and raw image bytes never enter the record.
inline json importLocalInputs(json in) {
    require(in.is_object(), "Media JSON must be an object");
    if (in.contains("image")) {
        require(in.contains("artwork_file") && in["artwork_file"].is_string(),
                "Local UI image upgrade requires artwork_file pointing to the uploaded raster file");
        const auto path = in["artwork_file"].get<std::string>();
        require(std::filesystem::is_regular_file(path), "Artwork must be a regular file");
        std::ifstream f(path, std::ios::binary);
        require(bool(f), "Cannot read artwork_file");
        std::array<unsigned char, 65536> buffer{};
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        std::size_t total = 0;
        bool first = true;
        while (f) {
            f.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            const auto n = static_cast<std::size_t>(f.gcount());
            if (first) {
                const bool png = n >= 8 && buffer[0] == 137 && buffer[1] == 'P' && buffer[2] == 'N' && buffer[3] == 'G'
                    && buffer[4] == 13 && buffer[5] == 10 && buffer[6] == 26 && buffer[7] == 10;
                const bool jpeg = n >= 3 && buffer[0] == 255 && buffer[1] == 216 && buffer[2] == 255;
                const bool webp = n >= 12 && std::string(reinterpret_cast<char*>(buffer.data()),4) == "RIFF"
                    && std::string(reinterpret_cast<char*>(buffer.data()+8),4) == "WEBP";
                const bool gif = n >= 13 &&
                    (std::string(reinterpret_cast<char*>(buffer.data()), 6) == "GIF87a" ||
                     std::string(reinterpret_cast<char*>(buffer.data()), 6) == "GIF89a");
                require(png || jpeg || webp || gif, "Use a PNG, JPEG, WebP or GIF raster image");
                first = false;
            }
            total += n;
            require(total <= 64U * 1024U * 1024U, "Artwork exceeds 64 MiB");
            SHA256_Update(&ctx, buffer.data(), n);
        }
        require(f.eof() && total > 0, "Artwork read failed");
        unsigned char bytes[32]; SHA256_Final(bytes, &ctx);
        const char* hex = "0123456789abcdef";
        std::string hash;
        for (auto c : bytes) { hash += hex[c >> 4]; hash += hex[c & 15]; }
        require(!in.contains("artwork_sha256") || in["artwork_sha256"] == hash, "Supplied image hash does not match local file");
        in["artwork_sha256"] = hash;
        in.erase("artwork_file");
    }
    validateInputs(in);
    return in;
}
} // namespace tru_media_v4
