#include "message_handler.h"
#include "miner_telemetry_v1.h"
#include "tru_network_params.h"
#include "tru_version.h"  // NETWORK-VERSION-01: release identity only
#include <random>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <openssl/sha.h>
#include <optional>
#include <cctype>
#include <chrono>          // ADDR-DIAL-01
#include <deque>           // ADDR-DIAL-01
#include <mutex>           // ADDR-DIAL-01
#include <unordered_map>   // ADDR-DIAL-01
#include <iterator>        // ADDR-DIAL-01 (std::next)

namespace {
// Patch 15B.1 wire integers are explicit little-endian, independent of host ABI.
void appendLE32(std::string& out, std::uint32_t v) {
    char b[4];
    b[0] = static_cast<char>(v & 0xffu);
    b[1] = static_cast<char>((v >> 8) & 0xffu);
    b[2] = static_cast<char>((v >> 16) & 0xffu);
    b[3] = static_cast<char>((v >> 24) & 0xffu);
    out.append(b, sizeof(b));
}

std::uint32_t readLE32(const char* p) {
    const auto* b = reinterpret_cast<const unsigned char*>(p);
    return static_cast<std::uint32_t>(b[0]) |
           (static_cast<std::uint32_t>(b[1]) << 8) |
           (static_cast<std::uint32_t>(b[2]) << 16) |
           (static_cast<std::uint32_t>(b[3]) << 24);
}

// Helper to convert bytes to hex string
std::string bytesToHex(const std::string& bytes) {
    std::stringstream ss;
    for (unsigned char c : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

size_t maxFramePayloadForType(uint32_t rawType) {
    using MT = blockchain::BaseMessage::MessageType;
    switch (static_cast<MT>(rawType)) {
        case blockchain::BaseMessage::BLOCK:
            return tru_limits::MAX_P2P_MESSAGE_BYTES;
        case blockchain::BaseMessage::TX:
            return tru_limits::MAX_P2P_TX_MESSAGE_BYTES;
        case blockchain::BaseMessage::VERSION:
        case blockchain::BaseMessage::VERACK:
        case blockchain::BaseMessage::ADDR:
        case blockchain::BaseMessage::INV:
        case blockchain::BaseMessage::GETDATA:
        case blockchain::BaseMessage::PING:
        case blockchain::BaseMessage::PONG:
        case blockchain::BaseMessage::CHAT:
        case blockchain::BaseMessage::HEIGHT:
        case blockchain::BaseMessage::GET_BLOCK:
        case blockchain::BaseMessage::GET_HEIGHT:
        case blockchain::BaseMessage::BLOCK_NOT_FOUND:
            return tru_limits::MAX_P2P_CONTROL_MESSAGE_BYTES;
        default:
            return 0;
    }
}

bool isValidInventoryItem(const std::string& item) {
    if (item.size() != tru_limits::MAX_P2P_INVENTORY_ITEM_BYTES) {
        return false;
    }
    if ((item[0] != 'b' && item[0] != 't') || item[1] != ':') {
        return false;
    }
    return std::all_of(
        item.begin() + 2,
        item.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; });
}
}

// Serialize a BaseMessage to string
size_t MessageHandler::serializeMessage(const blockchain::BaseMessage& msg, std::string& out) {
    std::string payload;
    if (!msg.SerializeToString(&payload)) {
        Logger::log("[MessageHandler] Failed to serialize BaseMessage type: " + std::to_string(msg.type()));
        return 0;
    }

    const uint32_t type = static_cast<uint32_t>(msg.type());
    const size_t typeLimit = maxFramePayloadForType(type);
    if (typeLimit == 0) {
        Logger::log(
            "[MessageHandler] Refusing to serialize unknown message type: " +
            std::to_string(type));
        return 0;
    }

    if (payload.size() > typeLimit) {
        Logger::log(
            "[MessageHandler] Payload too large for message type " +
            std::to_string(type) + ": " + std::to_string(payload.size()) +
            " bytes, max: " + std::to_string(typeLimit));
        return 0;
    }

    uint32_t length = static_cast<uint32_t>(payload.size());

    // Compute checksum of payload
    std::string checksum = computeChecksum(payload);

    out.clear();

    // Patch 15B.1 frame:
    // [4-byte TRU magic][u32 LE type][u32 LE length][32-byte SHA256][payload]
    for (const auto b : tru_network::MAINNET_P2P_MAGIC) {
        out.push_back(static_cast<char>(b));
    }
    appendLE32(out, type);
    appendLE32(out, length);
    out.append(checksum); // 32 bytes for SHA-256
    out.append(payload);

    // Log serialized data
    std::string hexData = bytesToHex(out.substr(0, std::min(out.size(), size_t(64))));
    Logger::log("[MessageHandler] Serialized message type: " + std::to_string(type) + 
                ", length: " + std::to_string(length) + 
                ", checksum: " + bytesToHex(checksum) + 
                ", first 64 bytes (hex): " + hexData);

    return out.size();
}

// Deserialize string to BaseMessage.
// Return 0 only for a genuinely incomplete frame. Return size_t(-1) for a
// malformed/oversized frame so the peer connection can fail closed instead of
// buffering forever or byte-resynchronizing through attacker-controlled data.
size_t MessageHandler::deserializeMessage(const std::string& data, blockchain::BaseMessage& msg) {
    constexpr size_t magicSize = tru_network::MAINNET_P2P_MAGIC.size();
    const size_t headerSize =
        magicSize + sizeof(uint32_t) * 2 + SHA256_DIGEST_LENGTH;

    // Do not attempt type/length/checksum/protobuf parsing until the complete
    // 4-byte network magic is available.
    if (data.size() < magicSize) {
        return 0;
    }

    for (size_t i = 0; i < magicSize; ++i) {
        if (static_cast<unsigned char>(data[i]) !=
            tru_network::MAINNET_P2P_MAGIC[i]) {
            Logger::log(
                "[MessageHandler][Patch15B.1] Rejecting frame: wrong TRU "
                "mainnet magic before protobuf parsing");
            return static_cast<size_t>(-1);
        }
    }

    if (data.size() < headerSize) {
        return 0; // correct magic, incomplete remaining header
    }

    const uint32_t type = readLE32(data.data() + magicSize);
    const uint32_t length =
        readLE32(data.data() + magicSize + sizeof(uint32_t));

    const size_t typeLimit = maxFramePayloadForType(type);
    if (typeLimit == 0) {
        Logger::log(
            "[MessageHandler] Deserialization failed: unknown message type " +
            std::to_string(type));
        return static_cast<size_t>(-1);
    }

    if (static_cast<size_t>(length) > typeLimit) {
        Logger::log(
            "[MessageHandler] Deserialization failed: message type " +
            std::to_string(type) + " declared " + std::to_string(length) +
            " bytes, max: " + std::to_string(typeLimit));
        return static_cast<size_t>(-1);
    }

    if (data.size() < headerSize + static_cast<size_t>(length)) {
        return 0; // incomplete but size-valid frame
    }

    std::string receivedChecksum =
        data.substr(
            magicSize + sizeof(uint32_t) * 2,
            SHA256_DIGEST_LENGTH);
    std::string payload = data.substr(headerSize, length);
    std::string computedChecksum = computeChecksum(payload);
    if (receivedChecksum != computedChecksum) {
        Logger::log(
            "[MessageHandler] Deserialization failed: checksum mismatch "
            "for message type " + std::to_string(type));
        return static_cast<size_t>(-1);
    }

    std::string hexData =
        bytesToHex(data.substr(0, std::min(data.size(), size_t(16))));
    Logger::log(
        "[MessageHandler] Deserializing message type: " +
        std::to_string(type) + ", length: " + std::to_string(length) +
        ", checksum: " + bytesToHex(receivedChecksum) +
        ", first 16 bytes (hex): " + hexData);

    if (!msg.ParseFromString(payload)) {
        Logger::log(
            "[MessageHandler] Failed to parse framed BaseMessage type: " +
            std::to_string(type));
        return static_cast<size_t>(-1);
    }

    if (static_cast<uint32_t>(msg.type()) != type) {
        Logger::log(
            "[MessageHandler] Deserialization failed: frame/BaseMessage type "
            "mismatch, frame=" + std::to_string(type) +
            ", inner=" +
            std::to_string(static_cast<uint32_t>(msg.type())));
        return static_cast<size_t>(-1);
    }

    Logger::log(
        "[MessageHandler] Successfully deserialized message type: " +
        std::to_string(type));
    return headerSize + static_cast<size_t>(length);
}

// Create Version message
blockchain::BaseMessage MessageHandler::createVersionMessage() {
    blockchain::Version versionMsg;
    versionMsg.set_version(2025);
    versionMsg.set_subversion("/TruChain:2.5.0-NewAge2025/");
    versionMsg.set_services(tru_miner_telemetry::enabled() ? (tru_miner_telemetry::SERVICE | tru_miner_telemetry::SERVICE_IP) : 0); // Optional MINER-NETWORK-01 telemetry
    versionMsg.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    versionMsg.set_addrrecv("0.0.0.0:" + std::to_string(tru_network::MAINNET_P2P_PORT)); // Configurable in production
    versionMsg.set_addrfrom("0.0.0.0:" + std::to_string(tru_network::MAINNET_P2P_PORT)); // Configurable in production
    std::random_device rd;
    std::mt19937_64 gen(rd());
    versionMsg.set_nonce(gen());
    versionMsg.set_useragent(tru_version::userAgent()); // NETWORK-VERSION-01
    versionMsg.set_startheight(0); // Updated dynamically in production
    versionMsg.set_futureflag("QuantumEncrypted=Yes;AIIntegration=High");
    versionMsg.set_networkid(std::string(tru_network::MAINNET_NETWORK_ID));

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::VERSION);
    baseMsg.set_payload(versionMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created VERSION message, version: " +
                std::to_string(versionMsg.version()) +
                ", networkId=" + versionMsg.networkid() +
                ", coreVersion=" + tru_version::coreReleaseVersion());
    return baseMsg;
}

// Create VerAck message
blockchain::BaseMessage MessageHandler::createVerAckMessage() {
    blockchain::VerAck verAckMsg;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t ephemeral = dist(gen);
    std::ostringstream oss;
    oss << "Ephemeral_" << std::hex << ephemeral;
    verAckMsg.set_quantum_ack(oss.str());

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::VERACK);
    baseMsg.set_payload(verAckMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created VERACK message, quantum_ack: " + verAckMsg.quantum_ack());
    return baseMsg;
}

// Create Ping message
blockchain::BaseMessage MessageHandler::createPingMessage() {
    blockchain::Ping pingMsg;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    pingMsg.set_nonce(gen());

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::PING);
    baseMsg.set_payload(pingMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created PING message, nonce: " + std::to_string(pingMsg.nonce()));
    return baseMsg;
}

// Create Pong message
blockchain::BaseMessage MessageHandler::createPongMessage(uint64_t nonce) {
    blockchain::Pong pongMsg;
    pongMsg.set_nonce(nonce);

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::PONG);
    baseMsg.set_payload(pongMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created PONG message, nonce: " + std::to_string(nonce));
    return baseMsg;
}

// Create Chat message
blockchain::BaseMessage MessageHandler::createChatMessage(const std::string& text) {
    blockchain::ChatMessage chatMsg;
    std::string sanitizedText = sanitizeString(text);
    if (sanitizedText.empty() || sanitizedText.size() > 1024) {
        Logger::log("[MessageHandler] Invalid chat message text, length: " + std::to_string(sanitizedText.size()));
        throw std::invalid_argument("Invalid chat message text");
    }
    chatMsg.set_text(sanitizedText);

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::CHAT);
    baseMsg.set_payload(chatMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created CHAT message, text: " + sanitizedText);
    return baseMsg;
}

// Create Height message
blockchain::BaseMessage MessageHandler::createHeightMessage(uint64_t height) {
    blockchain::HeightMessage heightMsg;
    heightMsg.set_height(height);

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::HEIGHT);
    baseMsg.set_payload(heightMsg.SerializeAsString());
    Logger::log("[MessageHandler] Created HEIGHT message, height: " + std::to_string(height));
    return baseMsg;
}

// Create GetBlockRequest message
blockchain::BaseMessage MessageHandler::createGetBlockRequest(uint64_t height) {
    blockchain::GetBlockRequest req;
    req.set_height(height);

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::GET_BLOCK);
    baseMsg.set_payload(req.SerializeAsString());
    Logger::log("[MessageHandler] Created GET_BLOCK message, height: " + std::to_string(height));
    return baseMsg;
}

// Create GetHeightRequest message
blockchain::BaseMessage MessageHandler::createGetHeightRequest() {
    blockchain::GetHeightRequest req;
    req.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::ostringstream oss;
    oss << "Peer_" << std::hex << gen();
    req.set_requester_id(oss.str());

    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::GET_HEIGHT);
    baseMsg.set_payload(req.SerializeAsString());
    Logger::log("[MessageHandler] Created GET_HEIGHT message, requester_id: " + req.requester_id());
    return baseMsg;
}

// Handle received messages

// ===========================================================================
// ADDR-DIAL-01
//
// The ADDR handler runs on the PeerConnection reader thread
// (peer_connection.cpp: readThread_ -> readLoop -> handleMessage). Dialling a
// peer from here blocks that thread for the whole connect timeout, during
// which the socket is not read, so GET_HEIGHT and block traffic stall.
//
// The previous code counted only SUCCESSFUL dials against its cap:
//
//     if (newConnectionCount < MAX_NEW_CONNECTIONS)
//         if (node->connectToPeer(ip, port))
//             newConnectionCount++;
//
// so unreachable addresses cost the default 5s each and never consumed the
// budget. A 50-address ADDR from an unreachable network could hold the reader
// for over four minutes. The cap was loosest exactly when the network was
// worst.
//
// Those counters were also function-static, i.e. shared by every reader
// thread with no synchronisation - a data race, and "per message" was untrue.
//
// This governor replaces them with mutex-guarded shared state that bounds the
// reader-thread cost absolutely:
//
//   - attempts are counted, not successes
//   - at most ADDR_DIAL_MAX_PER_MESSAGE dials per ADDR message
//   - at most ADDR_DIAL_MAX_PER_MINUTE dials across ALL connections
//   - a failed endpoint is not retried for ADDR_DIAL_COOLDOWN_SECONDS
//   - dials use a short timeout instead of the 5s default
//
// Worst case reader stall: ADDR_DIAL_MAX_PER_MESSAGE * ADDR_DIAL_TIMEOUT_SECONDS
// = 2 seconds, versus 250 seconds before.
// ===========================================================================
namespace {

constexpr int         ADDR_DIAL_TIMEOUT_SECONDS   = 1;
constexpr int         ADDR_DIAL_MAX_PER_MESSAGE   = 2;
constexpr std::size_t ADDR_DIAL_MAX_PER_MINUTE    = 6;
constexpr int         ADDR_DIAL_COOLDOWN_SECONDS  = 900;
constexpr std::size_t ADDR_DIAL_MAX_COOLDOWN_KEYS = 512;

class AddrDialGovernor {
public:
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    // Permitted only if the endpoint is not cooling down AND the global
    // per-minute attempt budget has room. Records the attempt on success.
    bool tryReserve(const std::string& key) {
        const TimePoint now = Clock::now();
        std::lock_guard<std::mutex> lock(mutex_);

        while (!attempts_.empty() &&
               now - attempts_.front() >= std::chrono::minutes(1)) {
            attempts_.pop_front();
        }

        const auto it = cooldown_.find(key);
        if (it != cooldown_.end()) {
            if (now < it->second) {
                return false;
            }
            cooldown_.erase(it);
        }

        if (attempts_.size() >= ADDR_DIAL_MAX_PER_MINUTE) {
            return false;
        }

        attempts_.push_back(now);
        return true;
    }

    // A dial that failed: suppress this endpoint for a while.
    void penalize(const std::string& key) {
        const TimePoint now = Clock::now();
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto it = cooldown_.begin(); it != cooldown_.end();) {
            it = (now >= it->second) ? cooldown_.erase(it) : std::next(it);
        }

        // Hard ceiling so a hostile ADDR flood cannot grow this map.
        if (cooldown_.size() >= ADDR_DIAL_MAX_COOLDOWN_KEYS) {
            return;
        }

        cooldown_[key] =
            now + std::chrono::seconds(ADDR_DIAL_COOLDOWN_SECONDS);
    }

    // A dial that succeeded: clear any suppression.
    void clear(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cooldown_.erase(key);
    }

private:
    std::mutex mutex_;
    std::deque<TimePoint> attempts_;
    std::unordered_map<std::string, TimePoint> cooldown_;
};

AddrDialGovernor& addrDialGovernor() {
    static AddrDialGovernor governor;
    return governor;
}

} // namespace


void MessageHandler::handleMessage(const blockchain::BaseMessage& msg, Blockchain* chain, P2PNode* node) {
    if (!chain || !node) {
        Logger::log("[MessageHandler] Error: Null chain or node pointer");
        return;
    }
    
    try {
        switch (msg.type()) {
            case blockchain::BaseMessage::VERSION: {
                blockchain::Version versionMsg;
                if (versionMsg.ParseFromString(msg.payload()) && validateVersionMessage(versionMsg)) {
                    Logger::log("[MessageHandler] Received VERSION: version=" + std::to_string(versionMsg.version()) +
                                ", subVersion=" + versionMsg.subversion() +
                                ", userAgent=" + versionMsg.useragent() +
                                ", networkId=" + versionMsg.networkid() +
                                ", startHeight=" + std::to_string(versionMsg.startheight()));
                    
                    // Respond with VERACK
                    auto verAck = createVerAckMessage();
                    std::string serialized;
                    if (serializeMessage(verAck, serialized) > 0) {
                        node->broadcastMessage(verAck);
                    }
                    
                    // Also send ADDR message with known peers
                    auto peers = node->getKnownPeers();
                    if (!peers.empty()) {
                        blockchain::Addr addrMsg;
                        size_t addrCount = 0;
                        for (const auto& peer : peers) {
                            if (addrCount >= tru_limits::MAX_P2P_ADDR_ITEMS) {
                                break;
                            }
                            addrMsg.add_addresses(
                                peer.ip + ":" + std::to_string(peer.port));
                            ++addrCount;
                        }
                        blockchain::BaseMessage baseMsg;
                        baseMsg.set_type(blockchain::BaseMessage::ADDR);
                        baseMsg.set_payload(addrMsg.SerializeAsString());
                        
                        std::string addrSerialized;
                        if (serializeMessage(baseMsg, addrSerialized) > 0) {
                            node->broadcastMessage(baseMsg);
                        }
                    }
                    
                    // Send our height too
                    auto heightMsg = createHeightMessage(chain->getBestTipHeight());
                    std::string heightSerialized;
                    if (serializeMessage(heightMsg, heightSerialized) > 0) {
                        node->broadcastMessage(heightMsg);
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse or validate VERSION payload");
                }
                break;
            }
            case blockchain::BaseMessage::VERACK: {
                blockchain::VerAck verAck;
                if (verAck.ParseFromString(msg.payload())) {
                    if (verAck.quantum_ack().size() > 256) {
                        Logger::log(
                            "[MessageHandler] Rejecting VERACK: quantum_ack too long");
                        break;
                    }
                    Logger::log("[MessageHandler] Received VERACK, quantum_ack=" + verAck.quantum_ack());
                    
                    // Request the peer's height after handshake
                    auto getHeightMsg = createGetHeightRequest();
                    std::string serialized;
                    if (serializeMessage(getHeightMsg, serialized) > 0) {
                        node->broadcastMessage(getHeightMsg);
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse VERACK payload");
                }
                break;
            }
            case blockchain::BaseMessage::ADDR: {
                blockchain::Addr addrMsg;
                if (addrMsg.ParseFromString(msg.payload())) {
                    if (addrMsg.addresses_size() >
                        static_cast<int>(tru_limits::MAX_P2P_ADDR_ITEMS)) {
                        Logger::log(
                            "[MessageHandler] Rejecting ADDR: too many addresses (" +
                            std::to_string(addrMsg.addresses_size()) + ")");
                        break;
                    }
                    bool invalidAddress = false;
                    for (const auto& addr : addrMsg.addresses()) {
                        if (addr.empty() ||
                            addr.size() > tru_limits::MAX_P2P_ADDRESS_STRING_BYTES) {
                            invalidAddress = true;
                            break;
                        }
                    }
                    if (invalidAddress) {
                        Logger::log(
                            "[MessageHandler] Rejecting ADDR: invalid address string length");
                        break;
                    }

                    Logger::log("[MessageHandler] Received ADDR with " + std::to_string(addrMsg.addresses_size()) + " addresses");
                    
                    int dialsThisMessage = 0;

                    for (const auto& addr : addrMsg.addresses()) {
                        size_t colonPos = addr.find(':');
                        if (colonPos != std::string::npos) {
                            std::string ip = addr.substr(0, colonPos);
                            try {
                                int port = std::stoi(addr.substr(colonPos + 1));

                                // MULTINODE-01E: an ADDR from a peer routinely
                                // carries the address that peer dialled, which
                                // is this node. connectToPeer refuses it, but
                                // it was still entered in the peer book and
                                // then showed as a permanently disconnected
                                // peer. Drop it before admission.
                                if (node->isSelfEndpoint(ip, port)) {
                                    Logger::log(
                                        "[MULTINODE-01E] ADDR self endpoint "
                                        "ignored: " + ip + ":" +
                                        std::to_string(port));
                                    continue;
                                }

                                // PEER-ENDPOINT-02: ADDR is discovery input, not
                                // peer-book authority.  Do not persist/gossip this
                                // endpoint merely because another peer mentioned it.
                                // connectToPeer() may attempt it under ADDR-DIAL-01;
                                // only a valid TRU VERSION promotes it into the book.
                                if (port <= 0 || port > 65535) {
                                    Logger::log(
                                        "[PEER-ENDPOINT-02] ADDR invalid port ignored: " +
                                        ip + ":" + std::to_string(port));
                                    continue;
                                }

                                // ADDR-DIAL-01: bounded, attempt-counted dial.
                                // dialsThisMessage is a local, so the cap is
                                // genuinely per message; the governor bounds
                                // the global rate across all reader threads.
                                if (dialsThisMessage < ADDR_DIAL_MAX_PER_MESSAGE) {
                                    const std::string dialKey =
                                        ip + ":" + std::to_string(port);

                                    if (addrDialGovernor().tryReserve(dialKey)) {
                                        ++dialsThisMessage;   // count the ATTEMPT
                                        if (node->connectToPeer(
                                                ip, port,
                                                ADDR_DIAL_TIMEOUT_SECONDS)) {
                                            addrDialGovernor().clear(dialKey);
                                        } else {
                                            addrDialGovernor().penalize(dialKey);
                                            Logger::log(
                                                "[ADDR-DIAL-01] dial failed, "
                                                "cooling down " + dialKey);
                                        }
                                    }
                                }
                            } catch (const std::exception& e) {
                                Logger::log("[MessageHandler] Invalid port in address: " + addr);
                            }
                        }
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse ADDR payload");
                }
                break;
            }
            case blockchain::BaseMessage::INV: {
                blockchain::Inv invMsg;
                if (invMsg.ParseFromString(msg.payload())) {
                    if (invMsg.inventory_size() >
                        static_cast<int>(tru_limits::MAX_P2P_INV_ITEMS)) {
                        Logger::log(
                            "[MessageHandler] Rejecting INV: too many items (" +
                            std::to_string(invMsg.inventory_size()) + ")");
                        break;
                    }
                    bool invalidInventory = false;
                    for (const auto& item : invMsg.inventory()) {
                        if (!isValidInventoryItem(item)) {
                            invalidInventory = true;
                            break;
                        }
                    }
                    if (invalidInventory) {
                        Logger::log(
                            "[MessageHandler] Rejecting INV: malformed inventory item");
                        break;
                    }

                    Logger::log("[MessageHandler] Received INV with " + std::to_string(invMsg.inventory_size()) + " items");
                    
                    // Process inventory items
                    std::vector<std::string> blockHashes;
                    std::vector<std::string> txHashes;
                    
                    for (const auto& item : invMsg.inventory()) {
                        // Determine if item is block or transaction based on prefix
                        if (item.substr(0, 2) == "b:") {
                            blockHashes.push_back(item.substr(2));
                        } else if (item.substr(0, 2) == "t:") {
                            txHashes.push_back(item.substr(2));
                        }
                    }
                    
                    // Request blocks we don't have
                    for (const auto& hash : blockHashes) {
                        try {
                            // Check if we already have this block
                            chain->getBlock(hash);
                            // If no exception, we have the block
                        } catch (const std::exception&) {
                            // Request the block by hash
                            blockchain::GetData getDataMsg;
                            getDataMsg.add_inventory("b:" + hash);
                            
                            blockchain::BaseMessage baseMsg;
                            baseMsg.set_type(blockchain::BaseMessage::GETDATA);
                            baseMsg.set_payload(getDataMsg.SerializeAsString());
                            
                            std::string serialized;
                            if (serializeMessage(baseMsg, serialized) > 0) {
                                node->broadcastMessage(baseMsg);
                            }
                        }
                    }
                    
                    // Request transactions we don't have
                    for (const auto& hash : txHashes) {
                        Transaction tx;
                        if (!chain->findTransaction(hash, tx)) {
                            blockchain::GetData getDataMsg;
                            getDataMsg.add_inventory("t:" + hash);
                            
                            blockchain::BaseMessage baseMsg;
                            baseMsg.set_type(blockchain::BaseMessage::GETDATA);
                            baseMsg.set_payload(getDataMsg.SerializeAsString());
                            
                            std::string serialized;
                            if (serializeMessage(baseMsg, serialized) > 0) {
                                node->broadcastMessage(baseMsg);
                            }
                        }
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse INV payload");
                }
                break;
            }
            case blockchain::BaseMessage::GETDATA:
            {
                blockchain::GetData getDataMsg;
                if (getDataMsg.ParseFromString(msg.payload()))
                {
                    if (getDataMsg.inventory_size() >
                        static_cast<int>(tru_limits::MAX_P2P_GETDATA_ITEMS)) {
                        Logger::log(
                            "[MessageHandler] Rejecting GETDATA: too many items (" +
                            std::to_string(getDataMsg.inventory_size()) + ")");
                        break;
                    }
                    bool invalidInventory = false;
                    for (const auto& item : getDataMsg.inventory()) {
                        if (!isValidInventoryItem(item)) {
                            invalidInventory = true;
                            break;
                        }
                    }
                    if (invalidInventory) {
                        Logger::log(
                            "[MessageHandler] Rejecting GETDATA: malformed inventory item");
                        break;
                    }

                    Logger::log("[MessageHandler] Received GETDATA with " + std::to_string(getDataMsg.inventory_size()) + " items");

                    for (const auto &item : getDataMsg.inventory())
                    {
                        // Handle block requests
                        if (item.substr(0, 2) == "b:")
                        {
                            std::string hash = item.substr(2);
                            try
                            {
                                Block block = chain->getBlock(hash);

                                // Use the new toProto method for consistent serialization
                                blockchain::BlockProto blockProto;
                                block.toProto(blockProto);

                                blockchain::BaseMessage baseMsg;
                                baseMsg.set_type(blockchain::BaseMessage::BLOCK);
                                baseMsg.set_payload(blockProto.SerializeAsString());

                                std::string serialized;
                                if (serializeMessage(baseMsg, serialized) > 0)
                                {
                                    node->broadcastMessage(baseMsg);
                                    Logger::log("[MessageHandler] Sent BLOCK for hash: " + hash);
                                }
                            }
                            catch (const std::exception &e)
                            {
                                Logger::log("[MessageHandler] Failed to get block for hash: " + hash + ", error: " + e.what());

                                // Send BLOCK_NOT_FOUND response
                                blockchain::BlockNotFoundResponse notFoundMsg;
                                notFoundMsg.set_height(0); // We don't have height from hash lookup
                                notFoundMsg.set_error_message("Block with hash " + hash + " not found");

                                blockchain::BaseMessage baseMsg;
                                baseMsg.set_type(blockchain::BaseMessage::BLOCK_NOT_FOUND);
                                baseMsg.set_payload(notFoundMsg.SerializeAsString());

                                std::string serialized;
                                if (serializeMessage(baseMsg, serialized) > 0)
                                {
                                    node->broadcastMessage(baseMsg);
                                    Logger::log("[MessageHandler] Sent BLOCK_NOT_FOUND for hash: " + hash);
                                }
                            }
                        }
                        // Handle transaction requests
                        else if (item.substr(0, 2) == "t:")
                        {
                            std::string hash = item.substr(2);
                            Transaction tx;
                            if (chain->findTransaction(hash, tx))
                            {
                                blockchain::TxProto txProto;
                                txProto.set_txid(tx.txid);

                                // Serialize transaction data
                                std::string txSerialized = tx.serialize();
                                txProto.set_raw(txSerialized);

                                // Log transaction details for debugging
                                Logger::log("[MessageHandler] Sending TX: " + tx.txid +
                                            ", serialized length: " + std::to_string(txSerialized.length()));

                                blockchain::BaseMessage baseMsg;
                                baseMsg.set_type(blockchain::BaseMessage::TX);
                                baseMsg.set_payload(txProto.SerializeAsString());

                                std::string serialized;
                                if (serializeMessage(baseMsg, serialized) > 0)
                                {
                                    node->broadcastMessage(baseMsg);
                                    Logger::log("[MessageHandler] Sent TX for hash: " + hash);
                                }
                            }
                            else
                            {
                                Logger::log("[MessageHandler] Transaction not found for hash: " + hash);

                                // Optionally send a NOT_FOUND message for transactions too
                                // This helps the requesting peer know the transaction doesn't exist
                                // rather than waiting for a timeout
                            }
                        }
                        // Handle unknown inventory types
                        else
                        {
                            Logger::log("[MessageHandler] Unknown inventory type in GETDATA: " + item);
                        }
                    }
                }
                else
                {
                    Logger::log("[MessageHandler] Failed to parse GETDATA payload");
                }
                break;
            }
            case blockchain::BaseMessage::BLOCK:
            {
                blockchain::BlockProto blockProto;
                if (blockProto.ParseFromString(msg.payload()))
                {
                    Logger::log("[MessageHandler] Received BLOCK, hash=" + blockProto.hash() +
                                ", height=" + std::to_string(blockProto.height()));

                    try
                    {
                        Block block;
                        block.fromProto(blockProto);

                        //
                        // Every P2P block enters the authoritative submitBlock()
                        // pipeline. No direct confirmed-state mutation here.
                        if (chain->submitBlockFromNetwork(
                                block, "p2p-legacy"))
                        {
                            Logger::log("[MessageHandler] Successfully accepted block: " + block.blockHash);

                            // Do not separately persist block.tokenMetadata here.
                            // applyBlock() owns confirmed metadata/state writes.

                            // Notify peers about our new height
                            auto heightMsg = createHeightMessage(chain->getBestTipHeight());
                            std::string serialized;
                            if (serializeMessage(heightMsg, serialized) > 0)
                            {
                                node->broadcastMessage(heightMsg);
                            }
                        }
                        else
                        {
                            Logger::log("[MessageHandler] Failed to add block: " + block.blockHash);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        Logger::log("[MessageHandler] Error processing BLOCK: " + std::string(e.what()));
                    }
                }
                else
                {
                    Logger::log("[MessageHandler] Failed to parse BLOCK payload");
                }
                break;
            }
            case blockchain::BaseMessage::TX: {
                blockchain::TxProto txProto;
                if (txProto.ParseFromString(msg.payload()))
                {
                    Logger::log("[MessageHandler] Received TX, txid=" + txProto.txid());

                    try
                    {
                        Transaction tx = Transaction::deserialize(txProto.raw());

                        // FIX(security): never trust the peer-supplied txid. Recompute
                        // it from the deserialized transaction bytes; the hash of the
                        // content is the only authoritative id. A mismatch means the
                        // peer lied or the bytes are corrupt -> drop it.
                        {
                            std::string claimed = txProto.txid();
                            tx.computeTxId();
                            if (!claimed.empty() && claimed != tx.txid) {
                                Logger::log("[MessageHandler] Dropping TX: peer txid " + claimed +
                                            " != computed " + tx.txid);
                                break;
                            }
                        }

                        // queue admission is bounded and
                        // mempool validation is asynchronous behind that bounded queue.
                        if (chain->addTransaction(tx)) {
                            Logger::log(
                                "[MessageHandler] Queued transaction for mempool validation: " +
                                tx.txid);
                        } else {
                            Logger::log(
                                "[MessageHandler] Rejected transaction at bounded ingress queue: " +
                                tx.txid);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        Logger::log("[MessageHandler] Error processing TX: " + std::string(e.what()));
                    }
                }
                else
                {
                    Logger::log("[MessageHandler] Failed to parse TX payload");
                }
                break;
            }
            case blockchain::BaseMessage::PING: {
                blockchain::Ping pingMsg;
                if (pingMsg.ParseFromString(msg.payload())) {
                    Logger::log("[MessageHandler] Received PING, nonce=" + std::to_string(pingMsg.nonce()));

                    // Respond with PONG
                    auto pongMsg = createPongMessage(pingMsg.nonce());
                    std::string serialized;
                    if (serializeMessage(pongMsg, serialized) > 0) {
                        node->broadcastMessage(pongMsg);
                        Logger::log("[MessageHandler] Sent PONG response");
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse PING payload");
                }
                break;
            }
            case blockchain::BaseMessage::PONG: {
                blockchain::Pong pongMsg;
                if (pongMsg.ParseFromString(msg.payload())) {
                    Logger::log("[MessageHandler] Received PONG, nonce=" + std::to_string(pongMsg.nonce()));
                    // Update peer's last activity time
                } else {
                    Logger::log("[MessageHandler] Failed to parse PONG payload");
                }
                break;
            }
            case blockchain::BaseMessage::CHAT: {
                blockchain::ChatMessage chatMsg;
                if (chatMsg.ParseFromString(msg.payload()) && validateChatMessage(chatMsg)) {
                    Logger::log("[MessageHandler] Received CHAT, text=" + chatMsg.text());
                    // Process chat message if needed
                } else {
                    Logger::log("[MessageHandler] Failed to parse or validate CHAT payload");
                }
                break;
            }
            case blockchain::BaseMessage::HEIGHT: {
                blockchain::HeightMessage heightMsg;
                if (heightMsg.ParseFromString(msg.payload())) {
                    uint64_t peerHeight = heightMsg.height();
                    Logger::log("[MessageHandler] Received HEIGHT, height=" + std::to_string(peerHeight));

                    // Update peer's height information
                    node->updatePeerHeight(peerHeight);

                    // Check if we need to sync
                    uint64_t localHeight = chain->getBestTipHeight();
                    if (peerHeight > localHeight) {
                        Logger::log("[MessageHandler] Peer has higher chain: " + 
                                    std::to_string(peerHeight) + " > " + std::to_string(localHeight) + 
                                    ". Requesting sync.");
                        // The sync is handled by the syncWithPeers method in Blockchain class
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse HEIGHT payload");
                }
                break;
            }
            case blockchain::BaseMessage::GET_BLOCK:
            {
                blockchain::GetBlockRequest req;
                if (req.ParseFromString(msg.payload()))
                {
                    uint64_t reqHeight = req.height();
                    Logger::log("[MessageHandler] Received GET_BLOCK request for height " + std::to_string(reqHeight));

                    try
                    {
                        auto optionalBlock = chain->getBlockByHeight(reqHeight);
                        if (optionalBlock.has_value())
                        {
                            Block block = optionalBlock.value();
                            blockchain::BlockProto blockProto;

                            // Use the new toProto method
                            block.toProto(blockProto);

                            blockchain::BaseMessage baseMsg;
                            baseMsg.set_type(blockchain::BaseMessage::BLOCK);
                            baseMsg.set_payload(blockProto.SerializeAsString());

                            std::string serialized;
                            if (serializeMessage(baseMsg, serialized) > 0)
                            {
                                node->broadcastMessage(baseMsg);
                                Logger::log("[MessageHandler] Sent BLOCK for height " + std::to_string(reqHeight));
                            }
                        }
                        else
                        {
                            Logger::log("[MessageHandler] Block at height " + std::to_string(reqHeight) + " not found");
                        }
                    }
                    catch (const std::exception &e)
                    {
                        Logger::log("[MessageHandler] Error retrieving block: " + std::string(e.what()));
                    }
                }
                else
                {
                    Logger::log("[MessageHandler] Failed to parse GET_BLOCK payload");
                }
                break;
            }
            case blockchain::BaseMessage::GET_HEIGHT: {
                blockchain::GetHeightRequest req;
                if (req.ParseFromString(msg.payload())) {
                    Logger::log("[MessageHandler] Received GET_HEIGHT request from " + req.requester_id());

                    // Respond with our current height
                    auto heightMsg = createHeightMessage(chain->getBestTipHeight());
                    std::string serialized;
                    if (serializeMessage(heightMsg, serialized) > 0) {
                        node->broadcastMessage(heightMsg);
                        Logger::log("[MessageHandler] Sent HEIGHT response: " + std::to_string(chain->getBestTipHeight()));
                    }
                } else {
                    Logger::log("[MessageHandler] Failed to parse GET_HEIGHT payload");
                }
                break;
            }
            default:
                Logger::log("[MessageHandler] Received unknown message type: " + std::to_string(msg.type()));
                break;
        }
    } catch (const std::exception& e) {
        Logger::log("[MessageHandler] Exception handling message: " + std::string(e.what()));
    }
}

// Compute SHA-256 checksum
std::string MessageHandler::computeChecksum(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

// Sanitize string inputs
std::string MessageHandler::sanitizeString(const std::string& input) {
    std::string sanitized;
    sanitized.reserve(input.size());
    for (char c : input) {
        if (std::isprint(static_cast<unsigned char>(c)) && c != ';' && c != '|' && c != '&') {
            sanitized += c;
        }
    }
    return sanitized;
}

// Validate Version message
bool MessageHandler::validateVersionMessage(const blockchain::Version& version) {
    if (version.networkid() != std::string(tru_network::MAINNET_NETWORK_ID)) {
        Logger::log(
            "[MessageHandler][Patch15B.1] Rejecting VERSION for wrong networkId: " +
            version.networkid());
        return false;
    }
    if (version.version() < 2025 || version.version() > 3000) {
        Logger::log("[MessageHandler] Invalid version number: " + std::to_string(version.version()));
        return false;
    }
    if (version.subversion().size() > 256 ||
        version.useragent().size() > 256 ||
        version.addrrecv().size() > tru_limits::MAX_P2P_ADDRESS_STRING_BYTES ||
        version.addrfrom().size() > tru_limits::MAX_P2P_ADDRESS_STRING_BYTES ||
        version.futureflag().size() > 512) {
        Logger::log("[MessageHandler] Version strings too long");
        return false;
    }
    if (version.timestamp() > static_cast<uint64_t>(std::time(nullptr)) + 3600) {
        Logger::log("[MessageHandler] Invalid timestamp: " + std::to_string(version.timestamp()));
        return false;
    }
    return true;
}

// Validate Chat message
bool MessageHandler::validateChatMessage(const blockchain::ChatMessage& chat) {
    if (chat.text().empty() || chat.text().size() > 1024) {
        Logger::log("[MessageHandler] Invalid chat message length: " + std::to_string(chat.text().size()));
        return false;
    }
    return true;
}

static blockchain::BaseMessage createBlockNotFoundMessage(uint64_t height, const std::string& errorMsg = "") {
    blockchain::BlockNotFoundResponse notFoundMsg;
    notFoundMsg.set_height(height);
    if (!errorMsg.empty()) {
        notFoundMsg.set_error_message(errorMsg);
    } else {
        notFoundMsg.set_error_message("Block at height " + std::to_string(height) + " not found");
    }
    
    blockchain::BaseMessage baseMsg;
    baseMsg.set_type(blockchain::BaseMessage::BLOCK_NOT_FOUND);
    baseMsg.set_payload(notFoundMsg.SerializeAsString());
    
    Logger::log("[MessageHandler] Created BLOCK_NOT_FOUND message for height: " + std::to_string(height));
    return baseMsg;
}
