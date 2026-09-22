#ifndef PEER_CONNECTION_H
#define PEER_CONNECTION_H

#include "blockchain.h"
#include "message_handler.h"
#include <string>
#include <thread>
#include <mutex>
#include <future>
#include <map>
#include <sys/socket.h>
#include <chrono>
#include <atomic>
#include <cstdint>

class P2PNode;

class PeerConnection {
public:
    PeerConnection(int sock, const std::string &ip, int port, Blockchain *chain,
                   P2PNode *parent, bool inbound);
    ~PeerConnection();

    void start();
    void stop();
    void sendData(const std::string &data);
    void sendMinerReport(const std::string& data);
    bool supportsMinerIPReports() const { return supportsMinerReports() && minerIPReportsSupported_.load(); }
    bool supportsMinerReports() const { return minerReportsSupported_.load() && networkHandshakeComplete_.load(); }
    std::future<Block> requestBlock(uint64_t height);
    bool cancelBlockRequest(uint64_t height);
    void sendChatMessage(const std::string &message);
    void requestHeight();
    void sendTransaction(const Transaction &tx);
    void sendBlock(const Block &block);
    std::string getIp() const { return ip_; }
    int getPort() const { return port_; }
    uint64_t getPeerHeight() const { return peerHeight_; }
    std::string getPeerCoreVersion() const {
        std::lock_guard<std::mutex> lock(peerMetadataMutex_);
        return peerCoreVersion_;
    }
    std::string getPeerUserAgent() const {
        std::lock_guard<std::mutex> lock(peerMetadataMutex_);
        return peerUserAgent_;
    }
    bool networkHandshakeComplete() const { return networkHandshakeComplete_.load(); }
    bool isRunning() const { return running_; }
    void updateLastActivity() {
        lastActivity = std::chrono::steady_clock::now();
    }

    bool isConnectionAlive() const {
        return std::chrono::steady_clock::now() - lastActivity < CONNECTION_TIMEOUT;
    }

    void sendPing();

private:
    void readLoop();
    void sendDataUnlocked(const std::string& data);
    std::mutex sendMutex_;
    std::atomic<bool> minerReportsSupported_{false};
    std::atomic<bool> minerIPReportsSupported_{false};
    std::int64_t minerBudgetSecond_=-1;
    unsigned minerBudgetUsed_=0;
    void refillInboundBudgets();
    bool throttleInboundBytes(std::size_t bytes);
    bool throttleInboundMessage(blockchain::BaseMessage::MessageType type);
    void reportAbuse(std::uint32_t points, const std::string& reason);
    void releaseConnectionSlotOnce();
    void failAllBlockRequests();
    int sock_;
    std::string ip_;
    int port_;
    Blockchain *blockchain_;
    P2PNode *parent_;
    // PEER-ENDPOINT-02: inbound port_ is a transport/source port; outbound
    // port_ is the endpoint we successfully dialed.
    bool inbound_;
    std::thread readThread_;
    std::mutex promiseMutex_;
    std::map<uint64_t, std::promise<Block>> blockPromises_;
    std::string buffer_;
    std::atomic<bool> running_{false};
    // application messages are forbidden until this peer
    // proves the exact TRU mainnet VERSION identity.
    std::atomic<bool> networkHandshakeComplete_{false};
    uint64_t peerHeight_;
    // NETWORK-VERSION-01: observational metadata learned from the validated
    // VERSION message. Never consulted by consensus or connection admission.
    mutable std::mutex peerMetadataMutex_;
    std::string peerCoreVersion_{"legacy/unreported"};
    std::string peerUserAgent_;
    int pipeFds_[2];
    void sendBlockNotFoundResponse(uint64_t height);
    std::chrono::steady_clock::time_point lastActivity;
    std::chrono::steady_clock::time_point lastPing;
    static constexpr std::chrono::seconds PING_INTERVAL{30};
    static constexpr std::chrono::seconds CONNECTION_TIMEOUT{90};
    double inboundByteTokens_;
    double inboundMessageTokens_;
    double inboundRequestTokens_;
    std::chrono::steady_clock::time_point lastRateRefill_;
    std::atomic<bool> connectionSlotHeld_{true};
};


#endif // PEER_CONNECTION_H
