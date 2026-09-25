#pragma once
// ARTWORK-UI-01: local client helper, never a public RPC fetch facility.
#include <curl/curl.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace tru_artwork {
constexpr size_t MaxBytes = 64U * 1024U * 1024U;
inline void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
inline bool supportedImage(const unsigned char* p, size_t n) {
    return (n >= 8 && std::memcmp(p, "\x89PNG\r\n\x1a\n", 8) == 0) ||
           (n >= 3 && p[0] == 255 && p[1] == 216 && p[2] == 255) ||
           (n >= 12 && std::memcmp(p, "RIFF", 4) == 0 && std::memcmp(p + 8, "WEBP", 4) == 0) ||
           (n >= 13 && (std::memcmp(p, "GIF87a", 6) == 0 || std::memcmp(p, "GIF89a", 6) == 0));
}
// Conservative public IPv4 policy. IPv6 is disabled rather than allowing
// mapped, translated or tunneled addresses to evade the destination check.
inline bool publicIPv4(uint32_t ip) {
    const auto subnet = [ip](uint32_t net, uint32_t mask) { return (ip & mask) == net; };
    return !subnet(0x00000000U, 0xff000000U) &&
           !subnet(0x0a000000U, 0xff000000U) &&
           !subnet(0x64400000U, 0xffc00000U) &&
           !subnet(0x7f000000U, 0xff000000U) &&
           !subnet(0xa9fe0000U, 0xffff0000U) &&
           !subnet(0xac100000U, 0xfff00000U) &&
           !subnet(0xc0000000U, 0xffffff00U) &&
           !subnet(0xc0000200U, 0xffffff00U) &&
           !subnet(0xc0586300U, 0xffffff00U) &&
           !subnet(0xc0a80000U, 0xffff0000U) &&
           !subnet(0xc6120000U, 0xfffe0000U) &&
           !subnet(0xc6336400U, 0xffffff00U) &&
           !subnet(0xcb007100U, 0xffffff00U) &&
           ip < 0xe0000000U;
}
inline curl_socket_t openPublicSocket(void*, curlsocktype purpose, struct curl_sockaddr* address) noexcept {
    if (!address || purpose != CURLSOCKTYPE_IPCXN || address->family != AF_INET ||
        address->socktype != SOCK_STREAM || address->addrlen < sizeof(sockaddr_in)) return CURL_SOCKET_BAD;
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address->addr);
    if (ntohs(ipv4->sin_port) != 443 || !publicIPv4(ntohl(ipv4->sin_addr.s_addr))) return CURL_SOCKET_BAD;
    return ::socket(address->family, address->socktype, address->protocol);
}
using Url = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>;
inline std::string part(CURLU* url, CURLUPart key, unsigned flags = 0) {
    char* value = nullptr;
    if (curl_url_get(url, key, &value, flags) != CURLUE_OK) return {};
    std::unique_ptr<char, decltype(&curl_free)> owner(value, curl_free);
    return value ? value : "";
}
inline std::string checkedUrl(const std::string& input, const std::string& base = {}) {
    check(!input.empty() && input.size() <= 2048, "Image URL must be 1..2048 bytes");
    for (unsigned char c : input) check(c > 32 && c != 127 && c != '\\', "Image URL contains invalid characters");
    Url url(curl_url(), curl_url_cleanup);
    check(bool(url), "Cannot allocate image URL parser");
    if (!base.empty()) check(curl_url_set(url.get(), CURLUPART_URL, base.c_str(), 0) == CURLUE_OK, "Invalid redirect base");
    check(curl_url_set(url.get(), CURLUPART_URL, input.c_str(), 0) == CURLUE_OK, "Invalid image URL");
    check(part(url.get(), CURLUPART_SCHEME) == "https" && !part(url.get(), CURLUPART_HOST).empty(), "Use a public HTTPS image URL");
    check(part(url.get(), CURLUPART_PORT, CURLU_DEFAULT_PORT) == "443", "Image URL must use HTTPS port 443");
    for (auto key : {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_OPTIONS, CURLUPART_FRAGMENT})
        check(part(url.get(), key).empty(), "Image URLs cannot contain credentials or fragments");
    return part(url.get(), CURLUPART_URL);
}
inline std::string transportUrl(const std::string& reference) {
    if (reference.rfind("ipfs://", 0) == 0) {
        const auto path = reference.substr(7);
        check(!path.empty() && path[0] != '/' && path.find("..") == std::string::npos,
              "Use ipfs://CID/path for IPFS artwork");
        return checkedUrl("https://ipfs.io/ipfs/" + path);
    }
    return checkedUrl(reference);
}
struct Stream {
    SHA256_CTX hash{};
    std::array<unsigned char, 13> prefix{};
    size_t prefixBytes{0}, bytes{0}, headers{0};
    size_t* budget;
    std::string location;
    bool failed{false};
    explicit Stream(size_t& total) : budget(&total) { check(SHA256_Init(&hash) == 1, "Cannot initialize image hash"); }
};
inline size_t body(char* data, size_t size, size_t count, void* opaque) noexcept {
    auto& s = *static_cast<Stream*>(opaque);
    if (size && count > MaxBytes / size) { s.failed = true; return 0; }
    const size_t n = size * count;
    if (*s.budget > MaxBytes || n > MaxBytes - *s.budget) { s.failed = true; return 0; }
    const auto take = std::min(n, s.prefix.size() - s.prefixBytes);
    if (take) std::memcpy(s.prefix.data() + s.prefixBytes, data, take);
    s.prefixBytes += take; s.bytes += n; *s.budget += n;
    if (SHA256_Update(&s.hash, data, n) != 1) { s.failed = true; return 0; }
    return n;
}
inline size_t header(char* data, size_t size, size_t count, void* opaque) noexcept {
    auto& s = *static_cast<Stream*>(opaque);
    if (size && count > 32768U / size) return 0;
    const size_t n = size * count;
    if (n > 32768U - s.headers) return 0;
    s.headers += n;
    try {
        std::string line(data, n);
        if (line.rfind("HTTP/", 0) == 0) s.location.clear();
        std::string key = line.substr(0, 9);
        for (auto& c : key) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (key == "location:") {
            check(s.location.empty(), "Duplicate image redirect");
            const auto begin = line.find_first_not_of(" \t", 9);
            const auto end = line.find_last_not_of(" \t\r\n");
            check(begin != std::string::npos && end >= begin && end - begin < 2048, "Invalid redirect");
            s.location = line.substr(begin, end - begin + 1);
        }
        return n;
    } catch (...) { return 0; }
}
struct Download { std::string sha256; size_t bytes; };
inline Download fetch(const std::string& reference) {
    static std::once_flag once;
    static CURLcode init = CURLE_FAILED_INIT;
    std::call_once(once, [] { init = curl_global_init(CURL_GLOBAL_DEFAULT); });
    check(init == CURLE_OK, "Cannot initialize image downloader");
    const auto* version = curl_version_info(CURLVERSION_NOW);
    check(version && (version->features & CURL_VERSION_ASYNCHDNS),
          "Bounded image downloads require libcurl with asynchronous DNS support");
    std::string url = transportUrl(reference);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
    size_t budget = 0;
    for (unsigned hop = 0; hop <= 3; ++hop) {
        Stream stream(budget);
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
        check(bool(curl), "Cannot initialize HTTPS request");
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        check(remaining > 0, "Image download timed out");
        const auto set = [&](CURLoption option, auto value) {
            check(curl_easy_setopt(curl.get(), option, value) == CURLE_OK, "Cannot configure protected image download");
        };
        set(CURLOPT_URL, url.c_str());
        set(CURLOPT_PROXY, ""); // Do not route around the destination check through environment proxies.
        set(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
        set(CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS));
        set(CURLOPT_FOLLOWLOCATION, 0L); // Each redirect is parsed and connected independently.
        set(CURLOPT_SSL_VERIFYPEER, 1L); set(CURLOPT_SSL_VERIFYHOST, 2L);
        set(CURLOPT_IPRESOLVE, static_cast<long>(CURL_IPRESOLVE_V4));
        set(CURLOPT_OPENSOCKETFUNCTION, &openPublicSocket);
        set(CURLOPT_CONNECTTIMEOUT_MS, std::min(10000L, static_cast<long>(remaining)));
        set(CURLOPT_TIMEOUT_MS, static_cast<long>(remaining)); set(CURLOPT_NOSIGNAL, 1L);
        set(CURLOPT_LOW_SPEED_LIMIT, 1024L); set(CURLOPT_LOW_SPEED_TIME, 10L);
        set(CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(MaxBytes));
        set(CURLOPT_ACCEPT_ENCODING, "identity"); set(CURLOPT_USERAGENT, "TRU-Artwork/1");
        set(CURLOPT_WRITEFUNCTION, &body); set(CURLOPT_WRITEDATA, &stream);
        set(CURLOPT_HEADERFUNCTION, &header); set(CURLOPT_HEADERDATA, &stream);
        const auto result = curl_easy_perform(curl.get());
        if (result != CURLE_OK)
            throw std::runtime_error(std::string("Image download failed (requires public IPv4 HTTPS; 64 MiB/45s limit): ") + curl_easy_strerror(result));
        long status = 0;
        check(curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, "Cannot read image response");
        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            check(hop < 3 && !stream.location.empty(), "Image redirect limit or missing Location");
            url = checkedUrl(stream.location, url);
            continue;
        }
        check(status == 200, "Image host did not return HTTP 200; use a direct image URL");
        check(!stream.failed && supportedImage(stream.prefix.data(), stream.prefixBytes), "Downloaded file is not PNG, JPEG, WebP or GIF");
        unsigned char digest[32];
        check(SHA256_Final(digest, &stream.hash) == 1, "Cannot finish image hash");
        std::string hex; const char* digits = "0123456789abcdef";
        for (auto c : digest) { hex += digits[c >> 4]; hex += digits[c & 15]; }
        return {hex, stream.bytes};
    }
    throw std::runtime_error("Image redirect limit");
}
} // namespace tru_artwork
