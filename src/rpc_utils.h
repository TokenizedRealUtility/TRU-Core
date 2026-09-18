#ifndef RPC_UTILS_H
#define RPC_UTILS_H

#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <vector>
#include <system_error>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <openssl/rand.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace tru_rpc {

inline std::string trim(const std::string& in) {
    const auto first = in.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = in.find_last_not_of(" \t\r\n");
    return in.substr(first, last - first + 1);
}

inline bool constantTimeEqual(const std::string& a, const std::string& b) {
    const std::size_t maxLen = a.size() > b.size() ? a.size() : b.size();
    unsigned int diff = static_cast<unsigned int>(a.size() ^ b.size());
    for (std::size_t i = 0; i < maxLen; ++i) {
        const unsigned char av = i < a.size() ? static_cast<unsigned char>(a[i]) : 0U;
        const unsigned char bv = i < b.size() ? static_cast<unsigned char>(b[i]) : 0U;
        diff |= static_cast<unsigned int>(av ^ bv);
    }
    return diff == 0U;
}

inline bool isLoopbackBind(std::string bind) {
    for (char& c : bind) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return bind == "127.0.0.1" || bind == "::1" || bind == "localhost";
}

inline std::filesystem::path defaultCookiePath(int port) {
    if (const char* overridePath = std::getenv("TRU_RPC_COOKIE_FILE")) {
        const std::string v = trim(overridePath);
        if (!v.empty()) return std::filesystem::path(v);
    }
#ifdef _WIN32
    const char* base = std::getenv("LOCALAPPDATA");
    std::filesystem::path home = base && *base ? base : ".";
    return home / "TRU" / ("rpc-cookie-" + std::to_string(port));
#else
    const char* base = std::getenv("HOME");
    std::filesystem::path home = base && *base ? base : ".";
    return home / ".tru" / ("rpc-cookie-" + std::to_string(port));
#endif
}

inline void ensurePrivateParent(const std::filesystem::path& file) {
    std::error_code ec;
    const auto parent = file.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) throw std::runtime_error("cannot create RPC cookie directory: " + ec.message());
#ifndef _WIN32
        if (::chmod(parent.c_str(), 0700) != 0) {
            throw std::runtime_error("cannot chmod RPC cookie directory to 0700");
        }
#endif
    }
}

inline void enforcePrivateCookie(const std::filesystem::path& file) {
#ifndef _WIN32
    if (::chmod(file.c_str(), 0600) != 0) {
        throw std::runtime_error("cannot chmod RPC cookie to 0600");
    }
#else
    std::error_code ec;
    std::filesystem::permissions(
        file,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
    if (ec) throw std::runtime_error("cannot restrict RPC cookie permissions: " + ec.message());
#endif
}

inline std::string readTokenFile(const std::filesystem::path& file) {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(file, ec);
    if (ec) throw std::runtime_error("cannot stat RPC cookie: " + ec.message());
    if (std::filesystem::is_symlink(st) || !std::filesystem::is_regular_file(st)) {
        throw std::runtime_error("RPC cookie must be a regular non-symlink file");
    }
    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open RPC cookie");
    std::string token;
    std::getline(in, token);
    token = trim(token);
    if (token.size() < 32U || token.size() > 512U) {
        throw std::runtime_error("RPC cookie token length is invalid");
    }
    return token;
}

inline std::string randomTokenHex() {
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed while generating RPC token");
    }
    static const char* HEX = "0123456789abcdef";
    std::string out;
    out.resize(sizeof(raw) * 2U);
    for (std::size_t i = 0; i < sizeof(raw); ++i) {
        out[2U * i] = HEX[(raw[i] >> 4U) & 0x0fU];
        out[2U * i + 1U] = HEX[raw[i] & 0x0fU];
    }
    return out;
}

inline std::string loadOrCreateServerToken(int port) {
    if (const char* env = std::getenv("TRU_RPC_TOKEN")) {
        const std::string token = trim(env);
        if (token.size() < 32U || token.size() > 512U) {
            throw std::runtime_error("TRU_RPC_TOKEN must be 32..512 characters");
        }
        return token;
    }

    const auto file = defaultCookiePath(port);
    ensurePrivateParent(file);
    if (std::filesystem::exists(file)) {
        enforcePrivateCookie(file);
        return readTokenFile(file);
    }

    const std::string token = randomTokenHex();
    const auto tmp = std::filesystem::path(file.string() + ".tmp." + std::to_string(
#ifdef _WIN32
        static_cast<unsigned long>(GetCurrentProcessId())
#else
        static_cast<unsigned long>(::getpid())
#endif
    ));
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create RPC cookie temp file");
        out << token << "\n";
        out.flush();
        if (!out) throw std::runtime_error("cannot flush RPC cookie temp file");
    }
    enforcePrivateCookie(tmp);
    std::error_code ec;
    std::filesystem::rename(tmp, file, ec);
    if (ec) {
        std::filesystem::remove(tmp);
        if (std::filesystem::exists(file)) return readTokenFile(file);
        throw std::runtime_error("cannot atomically install RPC cookie: " + ec.message());
    }
    enforcePrivateCookie(file);
    return token;
}

inline std::string loadClientToken(int port) {
    if (const char* env = std::getenv("TRU_RPC_TOKEN")) {
        const std::string token = trim(env);
        if (token.size() < 32U || token.size() > 512U) {
            throw std::runtime_error("TRU_RPC_TOKEN must be 32..512 characters");
        }
        return token;
    }
    const auto file = defaultCookiePath(port);
    if (!std::filesystem::exists(file)) {
        throw std::runtime_error(
            "RPC authentication required; set TRU_RPC_TOKEN or provide the node cookie via TRU_RPC_COOKIE_FILE (expected " +
            file.string() + ")");
    }
    return readTokenFile(file);
}

inline httplib::Headers authorizationHeaders(const std::string& token) {
    return httplib::Headers{{"Authorization", "Bearer " + token}};
}

inline httplib::Headers clientAuthorizationHeaders(int port) {
    return authorizationHeaders(loadClientToken(port));
}

template <typename Client>
inline auto post(Client& cli, const std::string& body, int port) {
    return cli.Post("/rpc", clientAuthorizationHeaders(port), body, "application/json");
}

} // namespace tru_rpc

nlohmann::json rpcCall(const std::string& method, const nlohmann::json& params,
                       const std::string& nodeIP, int nodePort, int retries = 3, int delay = 2);

#endif
