#ifndef TRU_NETWORK_IDENTITY_H
#define TRU_NETWORK_IDENTITY_H

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <set>
#include <string>

namespace tru_network_identity {

inline std::string normalizeIpv4(const std::string& input) {
    in_addr addr{};
    if (::inet_pton(AF_INET, input.c_str(), &addr) != 1) {
        return {};
    }
    char buf[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
        return {};
    }
    return std::string(buf);
}

inline std::set<std::string> localIpv4Addresses() {
    std::set<std::string> out;
    out.insert("127.0.0.1");

    ifaddrs* head = nullptr;
    if (::getifaddrs(&head) != 0 || head == nullptr) {
        return out;
    }

    for (ifaddrs* it = head; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr || it->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
        char buf[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) {
            out.insert(std::string(buf));
        }
    }

    ::freeifaddrs(head);
    return out;
}

inline bool isLocalAddress(const std::string& ip) {
    if (ip.empty() || ip == "0.0.0.0" || ip == "::" ||
        ip == "localhost" || ip == "::1") {
        return true;
    }

    const std::string normalized = normalizeIpv4(ip);
    if (normalized.empty()) {
        return false;
    }

    if (normalized.rfind("127.", 0) == 0) {
        return true;
    }

    const auto locals = localIpv4Addresses();
    return locals.find(normalized) != locals.end();
}

inline bool sameIpv4(const std::string& a, const std::string& b) {
    const std::string na = normalizeIpv4(a);
    const std::string nb = normalizeIpv4(b);
    return !na.empty() && !nb.empty() && na == nb;
}

inline bool isSelfPeerEndpoint(const std::string& ip,
                               int port,
                               int canonicalP2PPort,
                               const std::string& externalIp = std::string()) {
    if (canonicalP2PPort <= 0 || port != canonicalP2PPort) {
        return false;
    }
    if (isLocalAddress(ip)) {
        return true;
    }
    if (!externalIp.empty() && (ip == externalIp || sameIpv4(ip, externalIp))) {
        return true;
    }
    return false;
}

}  // namespace tru_network_identity

#endif  // TRU_NETWORK_IDENTITY_H
