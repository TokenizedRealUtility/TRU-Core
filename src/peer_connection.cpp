#include "peer_connection.h"
#include "message_handler.h"
#include "p2p.h"
#include "tru_version.h"  // NETWORK-VERSION-01
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <optional>
#include <algorithm>

namespace {
// PEER-ENDPOINT-02: VERSION addrFrom is currently IPv4-style text.  For
// inbound sessions we deliberately ignore its host portion (the socket gives
// us the observed IP) and consume only a syntactically valid service port.
std::optional<int> peerAdvertisedServicePort(const std::string& endpoint) {
    const std::size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon + 1 >= endpoint.size()) {
        return std::nullopt;
    }

    const std::string text = endpoint.substr(colon + 1);
    try {
        std::size_t used = 0;
        const int port = std::stoi(text, &used);
        if (used != text.size() || port <= 0 || port > 65535) {
            return std::nullopt;
        }
        return port;
    } catch (...) {
        return std::nullopt;
    }
}
} // namespace


PeerConnection::PeerConnection(int sock, const std::string &ip, int port,
                               Blockchain *chain, P2PNode *parent, bool inbound)
    : sock_(sock), ip_(ip), port_(port), blockchain_(chain), parent_(parent),
      inbound_(inbound), running_(false), peerHeight_(0),
      lastActivity(std::chrono::steady_clock::now()),
      lastPing(std::chrono::steady_clock::now()),
      inboundByteTokens_(static_cast<double>(tru_limits::P2P_INBOUND_BYTE_BURST)),
      inboundMessageTokens_(static_cast<double>(tru_limits::P2P_INBOUND_MESSAGE_BURST)),
      inboundRequestTokens_(static_cast<double>(tru_limits::P2P_INBOUND_REQUEST_BURST)),
      lastRateRefill_(std::chrono::steady_clock::now()) {
    if (pipe(pipeFds_) < 0) {
        throw std::runtime_error("Failed to create pipe: " + std::string(strerror(errno)));
    }
}

PeerConnection::~PeerConnection() {
    stop();

    // Ensure thread is properly cleaned up even if stop() didn't work
    if (readThread_.joinable()) {
        Logger::log("[PeerConnection] WARNING: Thread still joinable in destructor, forcing cleanup");
        running_ = false;

        // Signal the thread to wake up
        if (pipeFds_[1] >= 0) {
            char buf = 0;
            write(pipeFds_[1], &buf, 1);
        }

        // Try to join with a timeout
        auto future = std::async(std::launch::async, [this]() { 
            readThread_.join(); 
        });

        if (future.wait_for(std::chrono::seconds(2)) == std::future_status::timeout) {
            Logger::log("[PeerConnection] ERROR: Thread join timed out, detaching");
            readThread_.detach();
        }
    }

    if (sock_ >= 0) {
        close(sock_);
    }
    if (pipeFds_[0] >= 0) close(pipeFds_[0]);
    if (pipeFds_[1] >= 0) close(pipeFds_[1]);
    releaseConnectionSlotOnce();
}

/*
PeerConnection::~PeerConnection() {
    stop();
    if (sock_ >= 0) {
        close(sock_);
    }
    close(pipeFds_[0]);
    close(pipeFds_[1]);
}
*/

void PeerConnection::releaseConnectionSlotOnce() {
    bool expected = true;
    if (!connectionSlotHeld_.compare_exchange_strong(expected, false)) {
        return;
    }
    if (parent_ != nullptr) {
        parent_->releasePeerConnectionSlot(ip_);
    }
}

void PeerConnection::reportAbuse(
    std::uint32_t points,
    const std::string& reason) {

    const bool banned =
        parent_ != nullptr &&
        parent_->reportPeerViolation(ip_, points, reason);

    Logger::log(
        "[PeerConnection] Peer abuse ip=" + ip_ +
        " points=" + std::to_string(points) +
        " reason=" + reason +
        (banned ? " => IP BANNED" : ""));
}

void PeerConnection::refillInboundBudgets() {
    const auto now = std::chrono::steady_clock::now();
    const double elapsed =
        std::chrono::duration<double>(now - lastRateRefill_).count();
    if (elapsed <= 0.0) {
        return;
    }

    inboundByteTokens_ = std::min(
        static_cast<double>(tru_limits::P2P_INBOUND_BYTE_BURST),
        inboundByteTokens_ +
            elapsed * static_cast<double>(
                tru_limits::P2P_INBOUND_BYTE_RATE_PER_SECOND));

    inboundMessageTokens_ = std::min(
        static_cast<double>(tru_limits::P2P_INBOUND_MESSAGE_BURST),
        inboundMessageTokens_ +
            elapsed * static_cast<double>(
                tru_limits::P2P_INBOUND_MESSAGE_RATE_PER_SECOND));

    inboundRequestTokens_ = std::min(
        static_cast<double>(tru_limits::P2P_INBOUND_REQUEST_BURST),
        inboundRequestTokens_ +
            elapsed * static_cast<double>(
                tru_limits::P2P_INBOUND_REQUEST_RATE_PER_SECOND));

    lastRateRefill_ = now;
}

bool PeerConnection::throttleInboundBytes(std::size_t bytes) {
    const double cost = static_cast<double>(bytes);

    while (running_) {
        refillInboundBudgets();
        if (cost <= inboundByteTokens_) {
            inboundByteTokens_ -= cost;
            return true;
        }

        const double deficit = cost - inboundByteTokens_;
        const double waitSeconds =
            deficit / static_cast<double>(
                tru_limits::P2P_INBOUND_BYTE_RATE_PER_SECOND);

        // Backpressure: stop reading this socket briefly and let TCP's receive
        // window apply pressure to the sender. Rate alone is not abuse.
        std::this_thread::sleep_for(
            std::chrono::duration<double>(std::max(0.0005, waitSeconds)));
    }

    return false;
}

bool PeerConnection::throttleInboundMessage(
    blockchain::BaseMessage::MessageType type) {

    const bool expensiveRequest =
        type == blockchain::BaseMessage::GET_BLOCK ||
        type == blockchain::BaseMessage::GETDATA;

    while (running_) {
        refillInboundBudgets();

        const bool messageReady = inboundMessageTokens_ >= 1.0;
        const bool requestReady =
            !expensiveRequest || inboundRequestTokens_ >= 1.0;

        if (messageReady && requestReady) {
            // Commit both token decrements only after every required budget
            // passes, so a request that has to wait is not double-charged.
            inboundMessageTokens_ -= 1.0;
            if (expensiveRequest) {
                inboundRequestTokens_ -= 1.0;
            }
            return true;
        }

        double waitSeconds = 0.0;
        if (!messageReady) {
            waitSeconds = std::max(
                waitSeconds,
                (1.0 - inboundMessageTokens_) /
                    static_cast<double>(
                        tru_limits::P2P_INBOUND_MESSAGE_RATE_PER_SECOND));
        }
        if (!requestReady) {
            waitSeconds = std::max(
                waitSeconds,
                (1.0 - inboundRequestTokens_) /
                    static_cast<double>(
                        tru_limits::P2P_INBOUND_REQUEST_RATE_PER_SECOND));
        }

        // Same policy as bytes: throttle honest/fast peers rather than
        // disconnecting or assigning ban score for congestion.
        std::this_thread::sleep_for(
            std::chrono::duration<double>(std::max(0.0005, waitSeconds)));
    }

    return false;
}

void PeerConnection::start() {
    if (running_) {
        Logger::log("[PeerConnection] WARNING: Already running");
        return;
    }

    Logger::log("[PeerConnection] Starting connection to " + ip_ + ":" + std::to_string(port_));
    running_ = true;
    readThread_ = std::thread(&PeerConnection::readLoop, this);

    blockchain::BaseMessage msg = MessageHandler::createVersionMessage();
    std::string serializedMsg;
    if (MessageHandler::serializeMessage(msg, serializedMsg) > 0) {
        sendData(serializedMsg);
        Logger::log("[PeerConnection] Sent VERSION message to " + ip_ + ":" + std::to_string(port_));
    } else {
        Logger::log("[PeerConnection] Failed to serialize VERSION message");
    }
}

void PeerConnection::stop() {
    const bool wasRunning = running_.exchange(false);
    failAllBlockRequests();

    if (wasRunning) {
        Logger::log(
            "[PeerConnection] Stopping connection to " +
            ip_ + ":" + std::to_string(port_));
    }

    if (readThread_.joinable()) {
        if (pipeFds_[1] >= 0) {
            char buf = 0;
            (void)write(pipeFds_[1], &buf, 1);
        }
        readThread_.join();
    }

    // A peer can be constructed and then rejected before start() is called.
    // Close that socket here too instead of relying on readLoop() to do it.
    if (sock_ >= 0) {
        shutdown(sock_, SHUT_RDWR);
        close(sock_);
        sock_ = -1;
    }
}
/*
void PeerConnection::stop() {
    if (running_) {
        Logger::log("[PeerConnection] Stopping connection to " + ip_ + ":" + std::to_string(port_));
        running_ = false;
        char buf = 0;
        write(pipeFds_[1], &buf, 1);
        if (readThread_.joinable()) {
            readThread_.join();
        }
        close(sock_);
        sock_ = -1;
    }
}
*/
void PeerConnection::sendData(const std::string &data) {
    // Serialize complete frames across block, transaction and telemetry senders.
    std::lock_guard<std::mutex> guard(sendMutex_);
    sendDataUnlocked(data);
}

void PeerConnection::sendMinerReport(const std::string& data) {
    if (!supportsMinerReports() || data.size()>1024) return;
    // Telemetry never waits for a busy block/transaction sender.
    std::unique_lock<std::mutex> guard(sendMutex_,std::try_to_lock);
    if (guard.owns_lock()) sendDataUnlocked(data);
}

void PeerConnection::sendDataUnlocked(const std::string &data) {
    if (!running_) {
        Logger::log("[PeerConnection] Cannot send data: connection not running");
        return;
    }

    // send() is allowed to write only part of a buffer.  That was
    // easy to miss with small messages but becomes a real block-relay failure
    // mode once TRU permits tens of MiB per block.  Keep sending until the full
    // framed message is on the socket or a real error occurs.
    size_t totalSent = 0;
    while (running_ && totalSent < data.size()) {
        ssize_t sent = send(sock_, data.data() + totalSent, data.size() - totalSent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            Logger::log("[PeerConnection] Send error to " + ip_ + ":" +
                        std::to_string(port_) + ": " + strerror(errno) +
                        " after " + std::to_string(totalSent) + "/" +
                        std::to_string(data.size()) + " bytes");
            running_ = false;
            return;
        }
        if (sent == 0) {
            Logger::log("[PeerConnection] Send returned 0 to " + ip_ + ":" +
                        std::to_string(port_) + " after " +
                        std::to_string(totalSent) + "/" +
                        std::to_string(data.size()) + " bytes");
            running_ = false;
            return;
        }
        totalSent += static_cast<size_t>(sent);
    }

    if (totalSent == data.size()) {
        Logger::log("[PeerConnection] Sent " + std::to_string(totalSent) +
                    " bytes to " + ip_ + ":" + std::to_string(port_));
    }
}

std::future<Block> PeerConnection::requestBlock(uint64_t height) {
    std::promise<Block> promise;
    auto future = promise.get_future();

    if (!running_.load()) {
        Logger::log("[PeerConnection::requestBlock] Cannot request block: connection not running");
        promise.set_value(Block());
        return future;
    }

    {
        std::lock_guard<std::mutex> lock(promiseMutex_);
        if (blockPromises_.count(height) != 0) {
            Logger::log("[PeerConnection::requestBlock] Duplicate in-flight request rejected for height " +
                        std::to_string(height) + " from " + ip_ + ":" + std::to_string(port_));
            promise.set_value(Block());
            return future;
        }
        if (blockPromises_.size() >= tru_limits::MAX_P2P_INFLIGHT_BLOCK_REQUESTS_PER_PEER) {
            Logger::log("[PeerConnection::requestBlock] In-flight request cap reached for " +
                        ip_ + ":" + std::to_string(port_) + ", pending=" +
                        std::to_string(blockPromises_.size()));
            promise.set_value(Block());
            return future;
        }
        blockPromises_.emplace(height, std::move(promise));
    }

    blockchain::BaseMessage msg = MessageHandler::createGetBlockRequest(height);
    std::string request;
    if (MessageHandler::serializeMessage(msg, request) > 0) {
        Logger::log("[PeerConnection::requestBlock] Sending GET_BLOCK request for height " +
                    std::to_string(height) + " to " + ip_ + ":" + std::to_string(port_));
        sendData(request);
    } else {
        Logger::log("[PeerConnection::requestBlock] Failed to serialize GET_BLOCK request for height " +
                    std::to_string(height));
        cancelBlockRequest(height);
    }
    return future;
}

bool PeerConnection::cancelBlockRequest(uint64_t height) {
    std::promise<Block> pending;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(promiseMutex_);
        auto it = blockPromises_.find(height);
        if (it != blockPromises_.end()) {
            pending = std::move(it->second);
            blockPromises_.erase(it);
            found = true;
        }
    }
    if (!found) return false;
    try {
        pending.set_value(Block());
    } catch (const std::future_error& e) {
        Logger::log("[PeerConnection::cancelBlockRequest] Promise completion error for height " +
                    std::to_string(height) + ": " + e.what());
    }
    Logger::log("[PeerConnection::cancelBlockRequest] Cleared in-flight block request height " +
                std::to_string(height) + " for " + ip_ + ":" + std::to_string(port_));
    return true;
}

void PeerConnection::failAllBlockRequests() {
    std::map<uint64_t, std::promise<Block>> pending;
    {
        std::lock_guard<std::mutex> lock(promiseMutex_);
        pending.swap(blockPromises_);
    }
    for (auto& entry : pending) {
        try {
            entry.second.set_value(Block());
        } catch (const std::future_error& e) {
            Logger::log("[PeerConnection::failAllBlockRequests] Promise completion error for height " +
                        std::to_string(entry.first) + ": " + e.what());
        }
    }
    if (!pending.empty()) {
        Logger::log("[PeerConnection::failAllBlockRequests] Released " +
                    std::to_string(pending.size()) + " pending block request(s) for " +
                    ip_ + ":" + std::to_string(port_));
    }
}

void PeerConnection::sendChatMessage(const std::string &message) {
    blockchain::BaseMessage baseMsg = MessageHandler::createChatMessage(message);
    std::string data;
    if (MessageHandler::serializeMessage(baseMsg, data) > 0) {
        sendData(data);
        Logger::log("[PeerConnection] Sent CHAT message to " + ip_ + ":" + std::to_string(port_));
    } else {
        Logger::log("[PeerConnection] Failed to serialize CHAT message");
    }
}

void PeerConnection::requestHeight() {
    blockchain::BaseMessage msg = MessageHandler::createGetHeightRequest();
    std::string data;
    if (MessageHandler::serializeMessage(msg, data) > 0) {
        sendData(data);
        Logger::log("[PeerConnection] Sent GET_HEIGHT request to " + ip_ + ":" + std::to_string(port_));
    } else {
        Logger::log("[PeerConnection] Failed to serialize GET_HEIGHT request");
    }
}

void PeerConnection::sendTransaction(const Transaction &tx) {
    blockchain::TxProto txProto;
    txProto.set_txid(tx.txid);
    txProto.set_raw(tx.serialize());

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::TX);
    baseMsg.set_payload(txProto.SerializeAsString());

    std::string data;
    if (MessageHandler::serializeMessage(baseMsg, data) > 0) {
        sendData(data);
        Logger::log("[PeerConnection] Sent TX with txid: " + txProto.txid() + " to " + ip_ + ":" + std::to_string(port_));
    } else {
        Logger::log("[PeerConnection] Failed to serialize TX message");
    }
}

void PeerConnection::sendBlock(const Block &block) {
    blockchain::BlockProto bproto;
    bproto.set_hash(block.blockHash);
    bproto.set_height(block.height);
    bproto.set_chain_work(block.chainWork);
    bproto.set_header(block.header.serialize());
    for (const auto &tx : block.transactions) {
        bproto.add_transactions(tx.serialize());
    }

    if (!block.tokenMetadata.empty()) {
        bproto.set_token_metadata(block.serializeMetadata());
    }

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::BLOCK);
    baseMsg.set_payload(bproto.SerializeAsString());

    std::string data;
    if (MessageHandler::serializeMessage(baseMsg, data) > 0) {
        sendData(data);
        Logger::log("[PeerConnection] Sent BLOCK for height " + std::to_string(block.height) + " to " + ip_ + ":" + std::to_string(port_));
    } else {
        Logger::log("[PeerConnection] Failed to serialize BLOCK message");
    }
}

void PeerConnection::readLoop() {
    Logger::log("[PeerConnection::readLoop] Entering readLoop for " + ip_ + ":" + std::to_string(port_));
    std::vector<char> readBuffer(16384); // 16KB buffer for incoming data

    // AUDIT-HARDENING-01B / Track 09: an outbound TCP connection is not a
    // usable peer until it completes the validated TRU VERSION handshake.
    // Bound that pre-handshake state so a silent/slow endpoint cannot retain
    // an outbound connection slot indefinitely. Inbound sessions retain the
    // existing transport policy; this closes the verified-peer redial case.
    static constexpr std::int64_t OUTBOUND_VERSION_DEADLINE_MS = 10000;
    const auto outboundVersionDeadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(OUTBOUND_VERSION_DEADLINE_MS);

    // AUDIT-HARDENING-01A / Track 07: a peer may fragment a valid frame,
    // but it may not keep one incomplete frame alive forever by trickling
    // bytes. This is transport policy only; it does not change wire format.
    static constexpr std::int64_t FRAME_READ_TIMEOUT_MS = 30000;
    bool partialFramePending = false;
    std::chrono::steady_clock::time_point partialFrameSince{};

    // Set socket options for reliability
    int yes = 1;
    if (setsockopt(sock_, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0) {
        Logger::log("[PeerConnection::readLoop] Warning: Failed to set SO_KEEPALIVE: " + std::string(strerror(errno)));
    }
    
    struct timeval tv;
    tv.tv_sec = 30; // 30-second timeout
    tv.tv_usec = 0;
    if (setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        Logger::log("[PeerConnection::readLoop] Warning: Failed to set SO_RCVTIMEO: " + std::string(strerror(errno)));
    }
    if (setsockopt(sock_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        Logger::log("[PeerConnection::readLoop] Warning: Failed to set SO_SNDTIMEO: " + std::string(strerror(errno)));
    }

    while (running_) {
        if (!inbound_ && !networkHandshakeComplete_.load() &&
            std::chrono::steady_clock::now() >= outboundVersionDeadline) {
            Logger::log(
                "[PeerConnection::readLoop][AUDIT-HARDENING-01B] "
                "Disconnecting outbound peer for VERSION handshake deadline: " +
                ip_ + ":" + std::to_string(port_));
            running_ = false;
            buffer_.clear();
            break;
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock_, &readSet);
        FD_SET(pipeFds_[0], &readSet); // For shutdown signal
        int maxFd = std::max(sock_, pipeFds_[0]) + 1;

        // Before outbound VERSION validation, wake at least once per second so
        // the 10-second application deadline is enforced independently of TCP
        // keepalive and of whether the remote endpoint sends any bytes.
        struct timeval timeout = {15, 0};
        if (!inbound_ && !networkHandshakeComplete_.load()) {
            timeout.tv_sec = 1;
        }

        int selectResult = select(maxFd, &readSet, nullptr, nullptr, &timeout);

        if (!running_) {
            Logger::log("[PeerConnection::readLoop] Shutdown signal detected, exiting loop for " + ip_ + ":" + std::to_string(port_));
            break;
        }

        if (selectResult < 0) {
            if (errno == EINTR) {
                continue; // Interrupted, retry
            }
            Logger::log("[PeerConnection::readLoop] Select error: " + std::string(strerror(errno)));
            running_ = false;
            break;
        } else if (selectResult == 0) {
            // The one-second pre-handshake poll exists only to enforce the
            // outbound VERSION deadline. Do not send application PING traffic
            // before network identity has been validated.
            if (!inbound_ && !networkHandshakeComplete_.load()) {
                continue;
            }
            if (partialFramePending) {
                const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - partialFrameSince).count();
                if (ageMs >= FRAME_READ_TIMEOUT_MS) {
                    Logger::log("[PeerConnection::readLoop][AUDIT-HARDENING-01A] "
                                "Disconnecting peer for incomplete-frame deadline: " +
                                ip_ + ":" + std::to_string(port_));
                    reportAbuse(tru_limits::P2P_MALFORMED_FRAME_SCORE,
                                "incomplete frame deadline");
                    running_ = false;
                    buffer_.clear();
                    break;
                }
            }
            // Timeout: Send a ping to keep the connection alive
            try {
                blockchain::BaseMessage pingMsg = MessageHandler::createPingMessage();
                std::string serialized;
                if (MessageHandler::serializeMessage(pingMsg, serialized) > 0) {
                    sendData(serialized);
                    Logger::log("[PeerConnection::readLoop] Sent PING to " + ip_ + ":" + std::to_string(port_));
                }
            } catch (const std::exception& e) {
                Logger::log("[PeerConnection::readLoop] Error sending PING: " + std::string(e.what()));
            }
            continue;
        }

        // Check for shutdown signal
        if (FD_ISSET(pipeFds_[0], &readSet)) {
            char pipe_buf;
            read(pipeFds_[0], &pipe_buf, 1);
            Logger::log("[PeerConnection::readLoop] Pipe signal received, exiting loop for " + ip_ + ":" + std::to_string(port_));
            running_ = false;
            break;
        }

        // Handle incoming data
        if (FD_ISSET(sock_, &readSet)) {
            ssize_t bytesRead = recv(sock_, readBuffer.data(), readBuffer.size(), 0);

            if (bytesRead < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    continue; // Recoverable, retry
                }
                Logger::log("[PeerConnection::readLoop] Receive error: " + std::string(strerror(errno)));
                running_ = false;
                break;
            } else if (bytesRead == 0) {
                Logger::log("[PeerConnection::readLoop] Connection closed by peer " + ip_ + ":" + std::to_string(port_));
                running_ = false;
                break;
            }

            const size_t incomingBytes = static_cast<size_t>(bytesRead);
            if (incomingBytes > tru_limits::MAX_P2P_RECEIVE_BUFFER_BYTES ||
                buffer_.size() >
                    tru_limits::MAX_P2P_RECEIVE_BUFFER_BYTES - incomingBytes) {
                Logger::log(
                    "[PeerConnection::readLoop] Disconnecting peer for receive "
                    "buffer overflow: " + ip_ + ":" + std::to_string(port_) +
                    ", buffered=" + std::to_string(buffer_.size()) +
                    ", incoming=" + std::to_string(incomingBytes));
                reportAbuse(
                    tru_limits::P2P_MALFORMED_FRAME_SCORE,
                    "receive buffer overflow");
                running_ = false;
                buffer_.clear();
                break;
            }
            if (!throttleInboundBytes(incomingBytes)) {
                break; // shutdown while applying transport backpressure
            }

            buffer_.append(readBuffer.data(), incomingBytes);
            updateLastActivity();
            Logger::log("[PeerConnection::readLoop] Received " + std::to_string(bytesRead) + " bytes from " + ip_ + ":" + std::to_string(port_));

            // Process all complete messages in the buffer
            while (!buffer_.empty() && running_) {
                blockchain::BaseMessage msg;
                size_t consumed = MessageHandler::deserializeMessage(buffer_, msg);

                if (consumed == static_cast<size_t>(-1)) {
                    Logger::log(
                        "[PeerConnection::readLoop] Invalid framed message; "
                        "disconnecting peer " + ip_ + ":" +
                        std::to_string(port_));
                    reportAbuse(
                        tru_limits::P2P_MALFORMED_FRAME_SCORE,
                        "malformed framed message");
                    running_ = false;
                    buffer_.clear();
                    break;
                } else if (consumed == 0) {
                    const auto now = std::chrono::steady_clock::now();
                    if (!partialFramePending) {
                        partialFramePending = true;
                        partialFrameSince = now;
                    } else {
                        const auto ageMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - partialFrameSince).count();
                        if (ageMs >= FRAME_READ_TIMEOUT_MS) {
                            Logger::log("[PeerConnection::readLoop][AUDIT-HARDENING-01A] "
                                        "Disconnecting slow-drip incomplete frame from " +
                                        ip_ + ":" + std::to_string(port_));
                            reportAbuse(tru_limits::P2P_MALFORMED_FRAME_SCORE,
                                        "slow-drip incomplete frame");
                            running_ = false;
                            buffer_.clear();
                        }
                    }
                    break; // Incomplete but size-valid frame; wait within deadline
                }

                // A complete frame was consumed. Any remaining bytes begin a new
                // frame and receive a fresh deadline only if they prove incomplete.
                partialFramePending = false;

                if (!throttleInboundMessage(msg.type())) {
                    break; // shutdown while applying message/request backpressure
                }
                buffer_.erase(0, consumed);
                Logger::log("[PeerConnection::readLoop] Processing message type " + std::to_string(msg.type()) + " from " + ip_ + ":" + std::to_string(port_));

                try {
                    // magic is checked by deserializeMessage().
                    // At the application layer, no peer may send chain traffic
                    // until it proves the exact tru-mainnet VERSION identity.
                    if (!networkHandshakeComplete_.load() &&
                        msg.type() != blockchain::BaseMessage::VERSION) {
                        Logger::log(
                            "[PeerConnection::readLoop][Patch15B.1] "
                            "Disconnecting peer that sent message type " +
                            std::to_string(msg.type()) +
                            " before valid tru-mainnet VERSION: " +
                            ip_ + ":" + std::to_string(port_));
                        running_ = false;
                        buffer_.clear();
                        break;
                    }

                    // A negotiated CHAT application envelope avoids changing protobuf
                    // framing and is never sent to legacy peers. Ordinary chat is unchanged.
                    if (msg.type()==blockchain::BaseMessage::CHAT) {
                        blockchain::ChatMessage chat;
                        if (chat.ParseFromString(msg.payload()) &&
                            tru_miner_telemetry::reportWire(chat.text())) {
                            const auto second=tru_miner_telemetry::monoNow();
                            if(second!=minerBudgetSecond_) {minerBudgetSecond_=second;minerBudgetUsed_=0;}
                            if(supportsMinerReports() && (!tru_miner_telemetry::ipWire(chat.text())||supportsMinerIPReports()) && ++minerBudgetUsed_<=4 && chat.text().size()<=512 && parent_)
                                parent_->receiveMinerReport(chat.text(),this);
                            continue;
                        }
                    }
                    switch (msg.type()) {
                        case blockchain::BaseMessage::VERSION: {
                            blockchain::Version versionMsg;
                            if (!versionMsg.ParseFromString(msg.payload()) ||
                                !MessageHandler::validateVersionMessage(versionMsg)) {
                                Logger::log(
                                    "[PeerConnection::readLoop][Patch15B.1] "
                                    "Disconnecting peer for invalid/wrong-network VERSION: " +
                                    ip_ + ":" + std::to_string(port_));
                                running_ = false;
                                buffer_.clear();
                                break;
                            }

                            minerIPReportsSupported_.store((versionMsg.services() & tru_miner_telemetry::SERVICE_IP) != 0);
                            minerReportsSupported_.store((versionMsg.services() & tru_miner_telemetry::SERVICE) != 0);

                            {
                                std::lock_guard<std::mutex> metaLock(peerMetadataMutex_);
                                peerUserAgent_ = tru_version::boundedUserAgent(versionMsg.useragent());
                                peerCoreVersion_ = tru_version::parseCoreVersionFromUserAgent(versionMsg.useragent());
                            }

                            // PEER-ENDPOINT-02: promote only a VERIFIED TRU peer.
                            // For outbound sessions, port_ is the endpoint that we
                            // actually dialed successfully.  For inbound sessions,
                            // port_ is only the remote TCP source port, so pair the
                            // observed socket IP with the service port advertised in
                            // the validated VERSION addrFrom field.
                            std::optional<int> bookPort;
                            if (inbound_) {
                                bookPort = peerAdvertisedServicePort(versionMsg.addrfrom());
                            } else if (port_ > 0 && port_ <= 65535) {
                                bookPort = port_;
                            }

                            if (bookPort && parent_ &&
                                !parent_->isSelfEndpoint(ip_, *bookPort)) {
                                parent_->getPeerManager()->addPeer(ip_, *bookPort);
                                Logger::log(
                                    "[PEER-ENDPOINT-02] Promoted verified peer endpoint " +
                                    ip_ + ":" + std::to_string(*bookPort) +
                                    (inbound_ ? " from inbound VERSION" : " from successful outbound dial"));
                            } else if (inbound_) {
                                Logger::log(
                                    "[PEER-ENDPOINT-02] Valid TRU VERSION from " + ip_ +
                                    " but no valid advertised service port; live session retained, "
                                    "peer-book promotion skipped");
                            }

                            networkHandshakeComplete_.store(true);
                            Logger::log(
                                "[PeerConnection::readLoop][Patch15B.1] "
                                "TRU mainnet network handshake accepted from " +
                                ip_ + ":" + std::to_string(port_));

                            // Preserve existing VERSION response behavior only
                            // after the per-peer network identity has passed.
                            MessageHandler::handleMessage(
                                msg, blockchain_, parent_);
                            break;
                        }
                        case blockchain::BaseMessage::HEIGHT: {
                            blockchain::HeightMessage heightMsg;
                            if (heightMsg.ParseFromString(msg.payload())) {
                                peerHeight_ = heightMsg.height();
                                Logger::log("[PeerConnection::readLoop] Updated peer height to " + std::to_string(peerHeight_));
                            } else {
                                Logger::log("[PeerConnection::readLoop] Failed to parse HEIGHT payload");
                            }
                            break;
                        }
                        case blockchain::BaseMessage::GET_HEIGHT: {
                            uint64_t currentHeight = blockchain_->getBestTipHeight();
                            blockchain::BaseMessage heightMsg = MessageHandler::createHeightMessage(currentHeight);
                            std::string serialized;
                            if (MessageHandler::serializeMessage(heightMsg, serialized) > 0) {
                                sendData(serialized);
                                Logger::log("[PeerConnection::readLoop] Responded to GET_HEIGHT with height " + std::to_string(currentHeight));
                            }
                            break;
                        }
                        case blockchain::BaseMessage::GET_BLOCK:
                        {
                            blockchain::GetBlockRequest req;
                            if (req.ParseFromString(msg.payload()))
                            {
                                uint64_t reqHeight = req.height();
                                try
                                {
                                    auto optionalBlock = blockchain_->getBlockByHeight(static_cast<int>(reqHeight));
                                    if (optionalBlock.has_value())
                                    {
                                        Block block = optionalBlock.value();
                                        sendBlock(block);
                                        Logger::log("[PeerConnection::readLoop] Sent block for height " + std::to_string(reqHeight));
                                    }
                                    else
                                    {
                                        sendBlockNotFoundResponse(reqHeight);
                                        Logger::log("[PeerConnection::readLoop] Block not found for height " + std::to_string(reqHeight));
                                    }
                                }
                                catch (const std::exception &e)
                                {
                                    Logger::log("[PeerConnection::readLoop] Error fetching block at height " + std::to_string(reqHeight) + ": " + e.what());
                                    sendBlockNotFoundResponse(reqHeight);
                                }
                            }
                            break;
                        }
                        case blockchain::BaseMessage::BLOCK: {
                            blockchain::BlockProto bproto;
                            if (bproto.ParseFromString(msg.payload())) {
                                Block block;
                                block.fromProto(bproto);
                                if (!block.blockHash.empty() && block.height > 0) {
                                    std::promise<Block> pending;
                                    bool fulfilledRequest = false;
                                    {
                                        std::lock_guard<std::mutex> lock(promiseMutex_);
                                        auto it = blockPromises_.find(block.height);
                                        if (it != blockPromises_.end()) {
                                            pending = std::move(it->second);
                                            blockPromises_.erase(it);
                                            fulfilledRequest = true;
                                        }
                                    }
                                    if (fulfilledRequest) {
                                        try {
                                            pending.set_value(block);
                                            Logger::log("[PeerConnection::readLoop] Fulfilled block promise for height " +
                                                        std::to_string(block.height));
                                        } catch (const std::future_error& e) {
                                            Logger::log("[PeerConnection::readLoop] Promise completion error for height " +
                                                        std::to_string(block.height) + ": " + e.what());
                                        }
                                    } else if (running_.load()) {
                                        // Never hold promiseMutex_ across block validation/indexing.
                                        if (!blockchain_->submitBlockFromNetwork(
                                                block, "peer:" + ip_)) {
                                            Logger::log("[PeerConnection::readLoop] Failed to submit block at height " +
                                                        std::to_string(block.height));
                                        }
                                    } else {
                                        Logger::log(
                                            "[PeerConnection::readLoop] Dropping unsolicited/late block during shutdown at height " +
                                            std::to_string(block.height));
                                    }
                                }
                            }
                            break;
                        }
                        case blockchain::BaseMessage::BLOCK_NOT_FOUND: {
                            blockchain::BlockNotFoundResponse notFound;
                            if (notFound.ParseFromString(msg.payload())) {
                                const uint64_t height = notFound.height();
                                if (cancelBlockRequest(height)) {
                                    Logger::log("[PeerConnection::readLoop] BLOCK_NOT_FOUND resolved request for height " +
                                                std::to_string(height));
                                }
                            } else {
                                Logger::log("[PeerConnection::readLoop] Failed to parse BLOCK_NOT_FOUND payload");
                            }
                            break;
                        }
                        default: {
                            Logger::log("[PeerConnection::readLoop] Unknown message type " + std::to_string(msg.type()) + ", skipping");
                            // Gracefully skip unknown types instead of failing
                            MessageHandler::handleMessage(msg, blockchain_, parent_); // Still attempt to handle it
                            break;
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::log("[PeerConnection::readLoop] Error processing message type " + std::to_string(msg.type()) + ": " + e.what());
                }
            }
        }
    }

    Logger::log("[PeerConnection::readLoop] Exiting readLoop for " + ip_ + ":" + std::to_string(port_));
    failAllBlockRequests();
    releaseConnectionSlotOnce();
    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }
}
// Helper method to send a block-not-found response
void PeerConnection::sendBlockNotFoundResponse(uint64_t height) {
    // Create a block-not-found response message
    blockchain::BlockNotFoundResponse notFoundMsg;
    notFoundMsg.set_height(height);
    notFoundMsg.set_error_message("Block at height " + std::to_string(height) + " not found");
    
    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::BLOCK_NOT_FOUND);
    baseMsg.set_payload(notFoundMsg.SerializeAsString());
    
    std::string serialized;
    if (MessageHandler::serializeMessage(baseMsg, serialized) > 0) {
        sendData(serialized);
        Logger::log("[PeerConnection::readLoop] Sent BLOCK_NOT_FOUND response for height " + std::to_string(height));
    } else {
        Logger::log("[PeerConnection::readLoop] Failed to serialize BLOCK_NOT_FOUND response");
    }
}

void PeerConnection::sendPing() {
    if (std::chrono::steady_clock::now() - lastPing > PING_INTERVAL) {
        blockchain::BaseMessage pingMsg = MessageHandler::createPingMessage();
        std::string serialized;
        if (MessageHandler::serializeMessage(pingMsg, serialized) > 0) {
            sendData(serialized);
            lastPing = std::chrono::steady_clock::now();
        }
    }
}
