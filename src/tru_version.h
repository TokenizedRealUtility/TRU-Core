#ifndef TRU_VERSION_H
#define TRU_VERSION_H

// NETWORK-VERSION-01
// Non-consensus software release identity for observability only.
// The release version comes from TRU_CORE_VERSION or a nearby VERSION file.
// It is advertised through the existing VERSION.userAgent string and MUST NOT
// be used for block validity, fork choice, PoW, transaction validity or any
// other consensus decision.

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

namespace tru_version {

inline std::string trim(std::string s) {
    auto notSpace=[](unsigned char c){ return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

inline bool validRelease(const std::string& s) {
    if (s.empty() || s.size() > 32) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isalnum(c) || c=='.' || c=='-' || c=='_' || c=='+';
    });
}

inline std::string readVersionFile(const std::filesystem::path& p) {
    std::ifstream in(p);
    if (!in) return {};
    std::string line;
    std::getline(in, line);
    line=trim(line);
    return validRelease(line) ? line : std::string{};
}

inline std::string discoverCoreVersion() {
    if (const char* env=std::getenv("TRU_CORE_VERSION")) {
        const std::string v=trim(env);
        if (validRelease(v)) return v;
    }

    std::vector<std::filesystem::path> candidates = {
        "VERSION", "../VERSION", "../../VERSION", "../../../VERSION"
    };

#if defined(__linux__)
    char buf[4096];
    const ssize_t n=::readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n]='\0';
        std::filesystem::path p(buf);
        p=p.parent_path();
        for (int i=0; i<6 && !p.empty(); ++i) {
            candidates.push_back(p / "VERSION");
            p=p.parent_path();
        }
    }
#endif

    for (const auto& p : candidates) {
        const std::string v=readVersionFile(p);
        if (!v.empty()) return v;
    }
    return "unreported";
}

inline const std::string& coreReleaseVersion() {
    static const std::string v=discoverCoreVersion();
    return v;
}

inline std::string userAgent() {
    return "/TRU-Core:" + coreReleaseVersion() + "/";
}

inline std::string parseCoreVersionFromUserAgent(const std::string& ua) {
    static const std::string prefix="/TRU-Core:";
    if (ua.rfind(prefix, 0) != 0 || ua.size() <= prefix.size()+1 || ua.back()!='/') {
        return "legacy/unreported";
    }
    const std::string v=ua.substr(prefix.size(), ua.size()-prefix.size()-1);
    return validRelease(v) ? v : std::string("legacy/unreported");
}

inline std::string boundedUserAgent(const std::string& ua) {
    if (ua.size() <= 96) return ua;
    return ua.substr(0, 96);
}

} // namespace tru_version

#endif // TRU_VERSION_H
