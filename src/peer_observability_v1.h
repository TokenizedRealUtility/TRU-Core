#pragma once
#include "p2p.h"
#include "tru_version.h"
#include <nlohmann/json.hpp>
#include <map>
#include <set>

namespace tru_peer_observability {
// Exceptions can contain quotes, control bytes, paths, and invalid UTF-8.
// Encode a JSON string and replace invalid UTF-8 rather than throwing in catch.
inline std::string errorJson(const std::string& message) {
    return nlohmann::json{{"error", message}}.dump(
        -1, ' ', false, nlohmann::json::error_handler_t::replace);
}
// PEER-COMMS-01: one snapshot contract for REST and RPC. No chain-state writes.
inline nlohmann::json snapshot(P2PNode& node) {
    using nlohmann::json;
    const auto known = node.getKnownPeers();
    const auto sessions = node.getPeersList();
    json rows = json::array(), endpoints = json::array(), versions = json::array();
    std::set<std::string> represented;
    std::map<std::string, std::size_t> counts;
    std::size_t connected = 0, reporting = 0, pending = 0;
    for (const auto& peer : sessions) {
        const int service = peer->getServicePort();
        if (service > 0) represented.insert(peer->getIp() + ":" + std::to_string(service));
        const bool ready = peer->isReady();
        const bool handshaken = peer->networkHandshakeComplete();
        const auto version = peer->getPeerCoreVersion();
        if (ready) {
            ++connected;
            ++counts[version];
            if (tru_version::isReportedVersion(version)) ++reporting;
        } else ++pending;
        rows.push_back({
            {"peerKind", "session"}, {"sessionId", std::to_string(peer->getSessionId())},
            {"ip", peer->getIp()}, {"port", peer->getPort()},
            {"transportPort", peer->getPort()}, {"servicePort", service},
            {"direction", peer->isInbound() ? "inbound" : "outbound"},
            {"isConnected", ready}, {"handshakeComplete", handshaken},
            {"connectionState", ready ? "connected" : (handshaken ? "unresponsive" : "handshaking")},
            {"lastActive", peer->getLastReceivedAt()},
            {"peerHeight", peer->getPeerHeight()}, {"height", peer->getPeerHeight()},
            {"heightUpdatedAt", peer->getHeightUpdatedAt()}, {"heightFresh", peer->hasFreshHeight()},
            {"coreVersion", version}, {"userAgent", peer->getPeerUserAgent()}
        });
    }
    for (const auto& p : known) {
        const std::string key = p.ip + ":" + std::to_string(p.port);
        endpoints.push_back({{"ip", p.ip}, {"port", p.port}, {"lastActive", p.lastActive}});
        if (represented.count(key)) continue;
        rows.push_back({
            {"peerKind", "known"}, {"sessionId", ""}, {"ip", p.ip}, {"port", p.port},
            {"transportPort", 0}, {"servicePort", p.port}, {"direction", "none"},
            {"isConnected", false}, {"handshakeComplete", false}, {"connectionState", "disconnected"},
            {"lastActive", p.lastActive}, {"peerHeight", 0}, {"height", 0},
            {"heightUpdatedAt", 0}, {"heightFresh", false},
            {"coreVersion", "legacy/unreported"}, {"userAgent", ""}
        });
    }
    for (const auto& entry : counts) versions.push_back({{"version", entry.first}, {"count", entry.second}});
    return {{"peers", rows}, {"total", rows.size()}, {"connected", connected},
        {"knownPeers", endpoints}, {"knownTotal", endpoints.size()},
        {"liveSessions", sessions.size()}, {"pendingSessions", pending},
        {"localCoreVersion", tru_version::coreReleaseVersion()},
        {"versionReportingCount", reporting}, {"versionSummary", versions},
        {"versionScope", "local node + directly connected, handshaken, responsive sessions only"},
        {"schema", "TRU-PEER-OBSERVABILITY-V2"}};
}
} // namespace tru_peer_observability
