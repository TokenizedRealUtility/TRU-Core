#ifndef P2P_H
#define P2P_H

#include "blockchain.h"
#include "miner_telemetry_v1.h"
#include "peer_manager.h"
#include "peer_connection.h"
#include "logging.h"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <memory>
#include <atomic>
#include <chrono>
#include <cstdint>

class P2PNode {
public:
    P2PNode();
    ~P2PNode();

    void startListening(int port, Blockchain* chain);
    bool connectToPeer(const std::string& ip, int port, int timeoutSec = 5);
    void broadcastBlock(const Block& block);
    void broadcastTransaction(const Transaction& tx);
    void broadcastMessage(const blockchain::BaseMessage& msg);
    void stop();
    // MINER-NETWORK-01: observation only, never consensus authority.
    void publishMinerReport(const std::string& address, double rate);
    void receiveMinerReport(const std::string& wire, PeerConnection* sender);
    std::vector<tru_miner_telemetry::Report> minerReports() const { return minerReports_.snapshot(); }
    std::string minerReporterId() const { return minerReports_.source(); }
    void updatePeerHeights();
    std::vector<std::shared_ptr<PeerConnection>> getPeersList();
    PeerManager* getPeerManager();
    void bootstrapFromSeeds();
    Block requestBlock(uint64_t height);
    void updatePeerHeight(uint64_t height);
    std::vector<std::pair<std::string, int>> getSeedsFromConfig() const;
    uint64_t getHighestPeerHeight();  // Removed const
    void setBlockchain(Blockchain* chain);
    void listPeers();  // Removed const
    void sendMessageToPeer(const std::string& ip, int port, const std::string& message);
    void setExternalIp(const std::string& ip);
    // MULTINODE-01E: connectToPeer already rejects self before opening a
    // socket, but the ADDR handler admitted the address to the peer book
    // first. Expose the same predicate so gossip can skip it outright.
    bool isSelfEndpoint(const std::string& ip, int port) const;
    std::vector<PeerInfo> getKnownPeers() const;
    int getActivePeerCount() const { return activePeerCount_.load(); }
    bool isNetworkConnected() const { 
        return activePeerCount_.load() > 0; 
    }
    void announceBlock(const Block& block);
    bool isRunning() const { return running_.load(); }
    bool isStopping() const { return stopping_.load(); }
    void releasePeerConnectionSlot(const std::string& ip);
    bool reportPeerViolation(const std::string& ip, std::uint32_t points, const std::string& reason);
private:
    void acceptLoop();
    void relayMinerReport(const std::string& wire, PeerConnection* sender);
    tru_miner_telemetry::Registry minerReports_;
    void cleanupPeers();

    Blockchain* blockchain_;
    int listenPort_;
    int listenSock_;
    std::vector<std::shared_ptr<PeerConnection>> peers_;
    std::mutex peersMutex_;
    std::thread acceptThread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> acceptLoopExited_{true};
    PeerManager peerManager_;
    std::string externalIp_;
    std::atomic<int> activePeerCount_{0};
    std::chrono::steady_clock::time_point lastPeerActivity_;
};

#endif // P2P_H
