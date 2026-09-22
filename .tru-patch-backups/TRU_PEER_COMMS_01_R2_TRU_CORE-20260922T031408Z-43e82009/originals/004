#include "p2p.h"
#include "message_handler.h"
#include "config_reader.h"
#include "network_identity.h"  // MULTINODE-01D local-endpoint self-peer guard
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   // TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <random>
#include <sstream>
#include <algorithm>

P2PNode::P2PNode() : blockchain_(nullptr), listenPort_(0), listenSock_(-1), running_(false), stopping_(false), acceptLoopExited_(true), externalIp_("") {}

P2PNode::~P2PNode() {
    stop();
}

void P2PNode::startListening(int port, Blockchain* chain) {
    stopping_.store(false);
    acceptLoopExited_.store(false);
    blockchain_ = chain;
    listenPort_ = port;
    listenSock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock_ < 0) {
        throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
    }

    int opt = 1;
    setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int bufferSize = 65536;
    setsockopt(listenSock_, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(listenSock_, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listenSock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listenSock_);
        throw std::runtime_error("Bind failed: " + std::string(strerror(errno)));
    }

    if (listen(listenSock_, 10) < 0) {
        close(listenSock_);
        throw std::runtime_error("Listen failed: " + std::string(strerror(errno)));
    }

    Logger::log("[P2PNode] Started listening on port " + std::to_string(port));
    running_ = true;
    ensureReconnectLoopStarted();
    acceptThread_ = std::thread(&P2PNode::acceptLoop, this);
}
//================================================================================
//                      PEER-REDIAL-01
//================================================================================
void P2PNode::ensureReconnectLoopStarted() {
    if (stopping_.load()) {
        return;
    }

    std::lock_guard<std::mutex> lock(reconnectStartMutex_);
    if (reconnectThread_.joinable() || stopping_.load()) {
        return;
    }

    reconnectLoopExited_.store(false);
    reconnectThread_ = std::thread(&P2PNode::reconnectLoop, this);
    Logger::log("[PEER-REDIAL-01] Verified-peer reconnect loop started");
}

void P2PNode::reconnectLoop() {
    reconnectLoopExited_.store(false);

    auto waitInterruptibly = [&](int milliseconds) {
        const int slices = std::max(1, milliseconds / 100);
        for (int i = 0; i < slices && !stopping_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    };

    while (!stopping_.load()) {
        cleanupPeers();

        const auto candidates = peerManager_.claimReconnectCandidates(2);
        for (const auto& peer : candidates) {
            if (stopping_.load()) {
                break;
            }

            if (isSelfEndpoint(peer.ip, peer.port)) {
                Logger::log(
                    "[PEER-REDIAL-01] Skipping self endpoint " + peer.ip + ":" +
                    std::to_string(peer.port));
                peerManager_.noteReconnectFailure(peer.ip);
                continue;
            }

            Logger::log(
                "[PEER-REDIAL-01] Attempting verified-peer redial " +
                peer.ip + ":" + std::to_string(peer.port));

            if (!connectToPeer(peer.ip, peer.port, 5)) {
                peerManager_.noteReconnectFailure(peer.ip);
            } else {
                Logger::log(
                    "[PEER-REDIAL-01] TCP redial established to " + peer.ip + ":" +
                    std::to_string(peer.port) + "; awaiting verified VERSION");
            }
        }

        waitInterruptibly(1000);
    }

    reconnectLoopExited_.store(true);
    Logger::log("[PEER-REDIAL-01] Verified-peer reconnect loop exiting");
}

//================================================================================
//                      P2PNode::ACCEPTLOOP
//================================================================================
void P2PNode::acceptLoop() {
    acceptLoopExited_.store(false);
    Logger::log("[P2PNode] Starting accept loop on port " + std::to_string(listenPort_));
    
    // Set socket to non-blocking mode so we can check for shutdown
    int flags = fcntl(listenSock_, F_GETFL, 0);
    fcntl(listenSock_, F_SETFL, flags | O_NONBLOCK);

    auto lastPeerReap = std::chrono::steady_clock::now();
    
    while (running_) {
        // Use select with timeout to check for incoming connections
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listenSock_, &readSet);
        
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms timeout
        
        int selectResult = select(listenSock_ + 1, &readSet, NULL, NULL, &timeout);
        
        // Check for shutdown
        if (!running_) {
            Logger::log("[P2PNode] Shutdown detected in accept loop");
            break;
        }
        
        if (selectResult < 0) {
            if (errno != EINTR) {
                Logger::log("[P2PNode] Select error: " + std::string(strerror(errno)));
            }
            continue;
        } else if (selectResult == 0) {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastPeerReap >=
                std::chrono::seconds(tru_limits::P2P_PEER_REAP_INTERVAL_SECONDS)) {
                cleanupPeers();
                lastPeerReap = now;
            }
            continue;
        }
        
        // Accept new connection
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(listenSock_, (struct sockaddr*)&clientAddr, &clientLen);
        
        if (clientSock < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                Logger::log("[P2PNode] Accept error: " + std::string(strerror(errno)));
            }
            continue;
        }
        
        if (!running_.load() || stopping_.load()) {
            close(clientSock);
            Logger::log("[P2PNode] Closing inbound socket accepted during shutdown");
            break;
        }

        // Reclaim disconnected peer objects before admitting another thread.
        cleanupPeers();

        // Set client socket back to blocking mode
        int clientFlags = fcntl(clientSock, F_GETFL, 0);
        fcntl(clientSock, F_SETFL, clientFlags & ~O_NONBLOCK);
        
        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        const std::string clientIpString(clientIp);
        int clientPort = ntohs(clientAddr.sin_port);

        // MULTINODE-01D: never admit a TCP connection whose remote address is
        // assigned to this same host. This catches an outbound self-dial even
        // if it somehow bypasses the pre-connect guard.
        if (tru_network_identity::isLocalAddress(clientIpString)) {
            Logger::log(
                "[MULTINODE-01D] Rejecting inbound self-peer from local interface " +
                clientIpString + ":" + std::to_string(clientPort));
            close(clientSock);
            continue;
        }

        std::string admissionReason;
        if (!peerManager_.tryAcquireConnectionSlot(
                clientIpString, true, admissionReason)) {
            Logger::log(
                "[P2PNode] Rejecting inbound peer " + clientIpString + ":" +
                std::to_string(clientPort) + " before thread creation: " +
                admissionReason);
            close(clientSock);
            continue;
        }
        Logger::log(
            "[P2PNode] Accepted connection from " + clientIpString + ":" +
            std::to_string(clientPort));
        int bufferSize = 65536;
        setsockopt(clientSock, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
        setsockopt(clientSock, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
        std::shared_ptr<PeerConnection> peer;
        try {
            peer = std::make_shared<PeerConnection>(
                clientSock, clientIpString, clientPort, blockchain_, this, true);
            // PEER-ENDPOINT-02: clientPort is the remote TCP source port.
            // Never admit it to the persistent/gossiped peer book.  The reader
            // promotes an observed-IP + advertised service-port endpoint only
            // after a valid TRU VERSION handshake.

            bool admitted = false;
            {
                std::lock_guard<std::mutex> lock(peersMutex_);
                if (running_.load() && !stopping_.load()) {
                    Logger::log("[P2PNode] Starting peer connection handler");
                    peer->start();
                    peers_.emplace_back(peer);
                    admitted = true;
                }
            }

            if (!admitted) {
                Logger::log(
                    "[P2PNode] Rejecting inbound peer because shutdown began: " +
                    clientIpString + ":" + std::to_string(clientPort));
                peer.reset();
            }
        } catch (const std::exception& e) {
            if (peer) {
                peer->stop();
                peer.reset(); // destructor releases the connection slot once
            } else {
                peerManager_.releaseConnectionSlot(clientIpString);
                close(clientSock);
            }
            Logger::log(
                "[P2PNode] Failed to construct/start inbound peer " +
                clientIpString + ":" + std::to_string(clientPort) +
                ": " + e.what());
        }
    }
    
    acceptLoopExited_.store(true);
    Logger::log("[P2PNode] Accept loop exiting cleanly");
}

bool P2PNode::connectToPeer(const std::string& ip, int port, int timeoutSec) {
    // PEER-REDIAL-01: explicit outbound use also enables recovery for
    // outbound-only nodes. The helper is idempotent.
    ensureReconnectLoopStarted();

    // PEER-ENDPOINT-02: reject malformed endpoints before htons()/dial policy.
    if (ip.empty() || port <= 0 || port > 65535) {
        Logger::log(
            "[PEER-ENDPOINT-02] Refusing invalid outbound endpoint " +
            ip + ":" + std::to_string(port));
        return false;
    }

    if (stopping_.load()) {
        Logger::log(
            "[P2PNode] Outbound connection suppressed during shutdown: " +
            ip + ":" + std::to_string(port));
        return false;
    }

    // MULTINODE-01D: the service endpoint of any address assigned to this
    // host is self. Reject it before socket creation. externalIp is also self
    // when it resolves to the configured service endpoint.
    const int selfPort = listenPort_ > 0 ? listenPort_ : port;
    if (tru_network_identity::isSelfPeerEndpoint(
            ip, port, selfPort, externalIp_)) {
        Logger::log(
            "[MULTINODE-01D] Outbound self-peer rejected before connect: " +
            ip + ":" + std::to_string(port));
        return false;
    }

    Logger::log("[P2PNode] Connecting to " + ip + ":" + std::to_string(port));
    cleanupPeers();

    if (stopping_.load()) {
        Logger::log(
            "[P2PNode] Outbound connection cancelled after peer cleanup: " +
            ip + ":" + std::to_string(port));
        return false;
    }
    
    // Check if connection already exists
    {
        std::lock_guard<std::mutex> lock(peersMutex_);
        for (const auto& peer : peers_) {
            if (peer->getIp() == ip && peer->getPort() == port && peer->isRunning()) {
                Logger::log("[P2PNode] Already connected to " + ip + ":" + std::to_string(port));
                return true;
            }
        }
    }
    
    if (!peerManager_.canConnect(ip)) {
        Logger::log("[P2PNode] Outbound connection blocked by peer policy for " + ip + ":" + std::to_string(port));
        return false;
    }

    // Create socket with error handling
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        Logger::log("[P2PNode] Failed to create socket: " + std::string(strerror(errno)));
        return false;
    }
    
    // Set socket options
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Convert IP address
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        Logger::log("[P2PNode] Invalid IP address: " + ip);
        close(sock);
        return false;
    }
    
    // Set socket options for better performance
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // TCP keepalive so a silently-dropped NAT/CGNAT connection
    // (Starlink) is detected in ~30-45s instead of ~2h. Without this, sends to a
    // dead socket black-hole and the chain appears stuck at the last propagated
    // height.
    {
        int ka = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
        int idle = 30, intvl = 10, cnt = 3;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
    }
    
    // Set timeout values
    struct timeval timeout;
    timeout.tv_sec = timeoutSec;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Set buffer sizes
    int bufferSize = 65536;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    
    // Set socket to non-blocking for connect with timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Connect with timeout
    int connectResult = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (connectResult < 0) {
        if (errno != EINPROGRESS) {
            Logger::log("[P2PNode] Connect failed: " + std::string(strerror(errno)));
            close(sock);
            return false;
        }
        
        // Wait in short slices so shutdown can cancel an in-flight dial.
        const auto connectDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
        bool connectReady = false;

        while (!stopping_.load()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= connectDeadline) break;

            const auto remaining =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    connectDeadline - now);
            const auto slice =
                std::min(remaining, std::chrono::microseconds(100000));

            struct timeval pollTimeout;
            pollTimeout.tv_sec =
                static_cast<time_t>(slice.count() / 1000000);
            pollTimeout.tv_usec =
                static_cast<suseconds_t>(slice.count() % 1000000);

            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(sock, &writeSet);

            const int selectResult =
                select(sock + 1, NULL, &writeSet, NULL, &pollTimeout);

            if (selectResult > 0) {
                connectReady = true;
                break;
            }
            if (selectResult < 0 && errno != EINTR) {
                Logger::log(
                    "[P2PNode] Connect select error: " +
                    std::string(strerror(errno)));
                close(sock);
                return false;
            }
        }

        if (stopping_.load()) {
            Logger::log(
                "[P2PNode] Cancelling in-flight outbound connect during shutdown: " +
                ip + ":" + std::to_string(port));
            close(sock);
            return false;
        }

        if (!connectReady) {
            Logger::log(
                "[P2PNode] Connect timeout to " +
                ip + ":" + std::to_string(port));
            close(sock);
            return false;
        }

        // Check if connection was successful
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            Logger::log("[P2PNode] Connect failed after select: " + std::string(strerror(error)));
            close(sock);
            return false;
        }
    }
    
    // Set socket back to blocking mode
    fcntl(sock, F_SETFL, flags);
    
    if (stopping_.load()) {
        Logger::log(
            "[P2PNode] Closing newly connected outbound socket because shutdown began: " +
            ip + ":" + std::to_string(port));
        close(sock);
        return false;
    }

    // Log connection success
    Logger::log("[P2PNode] Connection established to " + ip + ":" + std::to_string(port));
    std::string admissionReason;
    if (!peerManager_.tryAcquireConnectionSlot(ip, false, admissionReason)) {
        Logger::log(
            "[P2PNode] Closing outbound socket after policy rejection for " +
            ip + ":" + std::to_string(port) + ": " + admissionReason);
        close(sock);
        return false;
    }
    if (stopping_.load()) {
        peerManager_.releaseConnectionSlot(ip);
        close(sock);
        Logger::log(
            "[P2PNode] Outbound admission cancelled because shutdown began: " +
            ip + ":" + std::to_string(port));
        return false;
    }

    std::shared_ptr<PeerConnection> peer;
    try {
        peer = std::make_shared<PeerConnection>(
            sock, ip, port, blockchain_, this, false);
        // PEER-ENDPOINT-02: even an outbound TCP connect is not peer-book
        // authority until the remote side proves a valid TRU VERSION.  The
        // PeerConnection promotes this already-dialed endpoint after handshake.

        bool admitted = false;
        {
            std::lock_guard<std::mutex> lock(peersMutex_);
            if (!stopping_.load()) {
                peer->start();
                peers_.push_back(peer);
                admitted = true;
            }
        }

        if (!admitted) {
            Logger::log(
                "[P2PNode] Outbound peer start suppressed during shutdown: " +
                ip + ":" + std::to_string(port));
            peer.reset();
            return false;
        }
    } catch (const std::exception& e) {
        if (peer) {
            peer->stop();
            peer.reset(); // destructor releases the connection slot once
        } else {
            peerManager_.releaseConnectionSlot(ip);
            close(sock);
        }
        Logger::log(
            "[P2PNode] Failed to construct/start outbound peer " + ip + ":" +
            std::to_string(port) + ": " + e.what());
        return false;
    }

    return true;
}
void P2PNode::broadcastBlock(const Block& block) {
    announceBlock(block);
    std::lock_guard<std::mutex> lock(peersMutex_);
    for (auto& peer : peers_) {
        peer->sendBlock(block);
    }
}

void P2PNode::broadcastTransaction(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    for (auto& peer : peers_) {
        peer->sendTransaction(tx);
    }
}

void P2PNode::broadcastMessage(const blockchain::BaseMessage& msg) {
    cleanupPeers();

    std::string serialized;
    if (MessageHandler::serializeMessage(msg, serialized) > 0) {
        std::lock_guard<std::mutex> lock(peersMutex_);
        for (auto& peer : peers_) {
            peer->sendData(serialized);
        }
        Logger::log("[P2PNode] Broadcasted message type: " + std::to_string(msg.type()));
    } else {
        Logger::log("[P2PNode] Failed to serialize message for broadcast");
    }
}

//================================================================================
//                      P2PNode::stop()
//================================================================================
void P2PNode::stop() {
    Logger::log("[P2PNode] Stopping P2P node...");

    stopping_.store(true);
    running_.store(false);
    Logger::log("[P2PNode] Set stopping_=true and running_=false");

    if (reconnectThread_.joinable()) {
        const auto warnDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!reconnectLoopExited_.load() &&
               std::chrono::steady_clock::now() < warnDeadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!reconnectLoopExited_.load()) {
            Logger::log(
                "[PEER-REDIAL-01] WARNING: reconnect loop exceeded 2s shutdown "
                "watchdog; joining safely");
        }
        reconnectThread_.join();
        Logger::log("[PEER-REDIAL-01] Reconnect thread terminated");
    }

    if (listenSock_ >= 0) {
        Logger::log(
            "[P2PNode] Closing listening socket (fd=" +
            std::to_string(listenSock_) + ")...");
        shutdown(listenSock_, SHUT_RDWR);
        const int result = close(listenSock_);
        if (result < 0) {
            Logger::log(
                "[P2PNode] WARNING: Error closing listen socket: " +
                std::string(strerror(errno)));
        } else {
            Logger::log("[P2PNode] Listening socket closed successfully");
        }
        listenSock_ = -1;
    }

    if (acceptThread_.joinable()) {
        Logger::log("[P2PNode] Waiting for accept thread to terminate...");

        const auto warnDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!acceptLoopExited_.load() &&
               std::chrono::steady_clock::now() < warnDeadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (!acceptLoopExited_.load()) {
            // Detaching here would be unsafe because acceptLoop() still uses
            // this P2PNode. Keep the watchdog warning, then join safely.
            Logger::log(
                "[P2PNode] WARNING: Accept thread exceeded 2s shutdown watchdog; "
                "joining safely (not detaching)");
        }

        acceptThread_.join();
        Logger::log("[P2PNode] Accept thread terminated");
    } else {
        Logger::log("[P2PNode] Accept thread was not joinable");
    }

    // Never wait on a PeerConnection while peersMutex_ is held.
    std::vector<std::shared_ptr<PeerConnection>> peersToStop;
    {
        std::lock_guard<std::mutex> lock(peersMutex_);
        Logger::log(
            "[P2PNode] Disconnecting " +
            std::to_string(peers_.size()) + " peers...");
        peersToStop.swap(peers_);
    }

    for (size_t i = 0; i < peersToStop.size(); ++i) {
        if (!peersToStop[i]) continue;
        try {
            Logger::log(
                "[P2PNode] Stopping peer " +
                std::to_string(i) + "...");
            peersToStop[i]->stop();
        } catch (const std::exception& e) {
            Logger::log(
                "[P2PNode] Error stopping peer " +
                std::to_string(i) + ": " + e.what());
        } catch (...) {
            Logger::log(
                "[P2PNode] Unknown error stopping peer " +
                std::to_string(i));
        }
    }

    peersToStop.clear();
    activePeerCount_.store(0);
    Logger::log("[P2PNode] All peers disconnected and cleared");
    Logger::log("[P2PNode] P2P node stopped successfully");
}


void P2PNode::updatePeerHeights() {
    std::lock_guard<std::mutex> lock(peersMutex_);
    for (auto& peer : peers_) {
        peer->requestHeight();
    }
}

std::vector<std::shared_ptr<PeerConnection>> P2PNode::getPeersList() {
    cleanupPeers();
    std::lock_guard<std::mutex> lock(peersMutex_);

    // Count active peers
    int activeCount = 0;
    for (const auto& peer : peers_) {
        if (peer->isRunning() && peer->isConnectionAlive()) {
            activeCount++;
        }
    }
    activePeerCount_.store(activeCount);

    return peers_;
}

PeerManager* P2PNode::getPeerManager() {
    return &peerManager_;
}

std::vector<std::pair<std::string, int>> P2PNode::getSeedsFromConfig() const {
    ConfigReader config("tru.conf");
    std::vector<std::pair<std::string, int>> seeds;
    
    std::string seedsStr = config.getValue("network", "seeds");
    if (!seedsStr.empty()) {
        Logger::log("[P2PNode] Found seeds in config: " + seedsStr);
        std::istringstream iss(seedsStr);
        std::string seed;
        while (std::getline(iss, seed, ',')) {
            size_t colonPos = seed.find(':');
            if (colonPos != std::string::npos) {
                std::string ip = seed.substr(0, colonPos);
                try {
                    int port = std::stoi(seed.substr(colonPos + 1));
                    seeds.emplace_back(ip, port);
                    Logger::log("[P2PNode] Added seed: " + ip + ":" + std::to_string(port));
                } catch (const std::exception& e) {
                    Logger::log("[P2PNode] Invalid seed: " + seed + " - " + e.what());
                }
            }
        }
    }

    std::string addnodeStr = config.getValue("network", "addnode");
    if (!addnodeStr.empty()) {
        Logger::log("[P2PNode] Found addnode in config: " + addnodeStr);
        std::istringstream iss(addnodeStr);
        std::string node;
        while (std::getline(iss, node, ',')) {
            size_t colonPos = node.find(':');
            if (colonPos != std::string::npos) {
                std::string ip = node.substr(0, colonPos);
                try {
                    int port = std::stoi(node.substr(colonPos + 1));
                    seeds.emplace_back(ip, port);
                    Logger::log("[P2PNode] Added addnode: " + ip + ":" + std::to_string(port));
                } catch (const std::exception& e) {
                    Logger::log("[P2PNode] Invalid addnode: " + node + " - " + e.what());
                }
            }
        }
    }
    
    return seeds;
}

void P2PNode::bootstrapFromSeeds() {
    std::vector<std::pair<std::string, int>> seeds = getSeedsFromConfig();
    if (seeds.empty()) {
        Logger::log("[P2PNode] No seed nodes defined in config, skipping bootstrap");
        return;
    }
    for (const auto& [ip, port] : seeds) {
        Logger::log("[P2PNode] Bootstrapping with seed: " + ip + ":" + std::to_string(port));
        connectToPeer(ip, port);
    }
}

Block P2PNode::requestBlock(uint64_t height) {
    Logger::log("[P2PNode] Requesting block at height " + std::to_string(height));
    
    const int maxAttempts = 3;
    const std::chrono::seconds retryDelay(2);
    const std::chrono::seconds timeout(30);
    
    // First, filter peers that have this height or greater
    std::vector<std::shared_ptr<PeerConnection>> eligiblePeers;
    {
        std::lock_guard<std::mutex> lock(peersMutex_);
        for (const auto& peer : peers_) {
            if (peer->getPeerHeight() >= height) {
                eligiblePeers.push_back(peer);
            }
        }
    }
    
    if (eligiblePeers.empty()) {
        Logger::log("[P2PNode] No peers available with height >= " + std::to_string(height));
        throw std::runtime_error("No eligible peers available for height " + std::to_string(height));
    }
    
    // Shuffle peers to distribute load
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(eligiblePeers.begin(), eligiblePeers.end(), g);
    
    // Try each peer until successful or all peers fail
    for (const auto& peer : eligiblePeers) {
        for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
            try {
                Logger::log("[P2PNode] Attempting to get block height " + std::to_string(height) + 
                           " from peer " + peer->getIp() + ":" + std::to_string(peer->getPort()) + 
                           ", attempt " + std::to_string(attempt));
                
                auto future = peer->requestBlock(height);
                auto status = future.wait_for(timeout);
                
                if (status == std::future_status::ready) {
                    Block block = future.get();
                    if (block.blockHash.empty() || block.height != height) {
                        Logger::log("[P2PNode] Received empty or invalid block from peer");
                        continue;
                    }
                    
                    Logger::log("[P2PNode] Successfully received block at height " + std::to_string(height) + 
                               " with hash " + block.blockHash + " from peer " + 
                               peer->getIp() + ":" + std::to_string(peer->getPort()));
                    
                    return block;
                } else {
                    peer->cancelBlockRequest(height);
                    Logger::log("[P2PNode] Timeout waiting for block from peer " + 
                               peer->getIp() + ":" + std::to_string(peer->getPort()));
                }
            } catch (const std::exception& e) {
                peer->cancelBlockRequest(height);
                Logger::log("[P2PNode] Error requesting block from peer: " + std::string(e.what()));
            }
            
            if (attempt < maxAttempts) {
                std::this_thread::sleep_for(retryDelay);
            }
        }
    }
    
    // If we get here, all peers failed
    Logger::log("[P2PNode] Failed to retrieve block at height " + std::to_string(height) + 
               " after trying all eligible peers");
    throw std::runtime_error("Failed to retrieve block after trying all eligible peers");
}

void P2PNode::updatePeerHeight(uint64_t height) {
    Logger::log("[P2PNode] Updating peer height to " + std::to_string(height));
    // Store height locally or in PeerManager as needed
}


uint64_t P2PNode::getHighestPeerHeight() {
    uint64_t maxHeight = 0;
    std::lock_guard<std::mutex> lock(peersMutex_);
    for (const auto& peer : peers_) {
        maxHeight = std::max(maxHeight, peer->getPeerHeight());
    }
    return maxHeight;
}

void P2PNode::listPeers() {
    std::lock_guard<std::mutex> lock(peersMutex_);
    Logger::log("[P2PNode] Listing peers:");
    for (const auto& peer : peers_) {
        Logger::log("[P2PNode] Peer: " + peer->getIp() + ":" + std::to_string(peer->getPort()) + ", Height: " + std::to_string(peer->getPeerHeight()));
    }
}

void P2PNode::setBlockchain(Blockchain* chain) {
    blockchain_ = chain;
}

void P2PNode::sendMessageToPeer(const std::string& ip, int port, const std::string& message) {
    std::lock_guard<std::mutex> lock(peersMutex_);
    for (auto& peer : peers_) {
        if (peer->getIp() == ip && peer->getPort() == port) {
            peer->sendChatMessage(message);
            Logger::log("[P2PNode] Sent message to peer: " + ip + ":" + std::to_string(port));
            return;
        }
    }
    Logger::log("[P2PNode] Peer not found: " + ip + ":" + std::to_string(port));
}

void P2PNode::setExternalIp(const std::string& ip) {
    externalIp_ = ip;
    minerReports_.setAdvertisedIP(ip); // MINER-IP-01: config-owned, signed advertised address
    Logger::log("[P2PNode] Set external IP: " + externalIp_);
}

bool P2PNode::isSelfEndpoint(const std::string& ip, int port) const {
    const int selfPort = listenPort_ > 0 ? listenPort_ : port;
    return tru_network_identity::isSelfPeerEndpoint(
        ip, port, selfPort, externalIp_);
}

std::vector<PeerInfo> P2PNode::getKnownPeers() const {
    return peerManager_.getPeers();
}

void P2PNode::releasePeerConnectionSlot(const std::string& ip) {
    peerManager_.releaseConnectionSlot(ip);
}

bool P2PNode::reportPeerViolation(
    const std::string& ip,
    std::uint32_t points,
    const std::string& reason) {
    return peerManager_.recordViolation(ip, points, reason);
}

void P2PNode::cleanupPeers() {
    // Two-phase cleanup: never destroy/join a PeerConnection while holding
    // peersMutex_, because a read thread may still be unwinding through a path
    // that needs the same mutex (for example broadcastMessage()).
    std::vector<std::shared_ptr<PeerConnection>> retired;
    {
        std::lock_guard<std::mutex> lock(peersMutex_);
        auto it = peers_.begin();
        while (it != peers_.end()) {
            if (!(*it)->isRunning()) {
                retired.push_back(std::move(*it));
                it = peers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    retired.clear(); // destructor/join happens outside peersMutex_
}

void P2PNode::announceBlock(const Block& block) {
    // Create INV message for the new block
    blockchain::Inv invMsg;
    invMsg.add_inventory("b:" + block.blockHash);
    
    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::INV);
    baseMsg.set_payload(invMsg.SerializeAsString());
    
    // Broadcast to all peers
    broadcastMessage(baseMsg);
    
    Logger::log("[P2PNode] Announced new block: " + block.blockHash);
}

// MINER-NETWORK-01: signed self-reports over negotiated application envelopes.
void P2PNode::relayMinerReport(const std::string& wire, PeerConnection* sender) {
    if (stopping_.load() || wire.empty()) return;
    blockchain::ChatMessage chat;chat.set_text(wire);
    blockchain::BaseMessage msg;msg.set_type(blockchain::BaseMessage::CHAT);
    msg.set_payload(chat.SerializeAsString());
    std::string frame;if(!MessageHandler::serializeMessage(msg,frame))return;
    const auto peers=getPeersList();
    for(const auto& peer:peers) {
        if(stopping_.load())break;
        if(peer && peer.get()!=sender && peer->supportsMinerReports() &&
           (!tru_miner_telemetry::ipWire(wire)||peer->supportsMinerIPReports()))peer->sendMinerReport(frame);
    }
}
void P2PNode::publishMinerReport(const std::string& address,double rate) {
    // Reporting errors must never fail a miner RPC or a block-processing path.
    try {
        const auto reports=minerReports_.publishReports(address,rate);
        relayMinerReport(reports.first,nullptr);relayMinerReport(reports.second,nullptr);
    }
    catch(const std::exception&) {Logger::log("[MINER-NETWORK-01] Local telemetry unavailable");}
}
void P2PNode::receiveMinerReport(const std::string& wire,PeerConnection* sender) {
    try {if(tru_miner_telemetry::enabled() && minerReports_.accept(wire))relayMinerReport(wire,sender);}
    catch(const std::exception&) {Logger::log("[MINER-NETWORK-01] Remote telemetry rejected");}
}
