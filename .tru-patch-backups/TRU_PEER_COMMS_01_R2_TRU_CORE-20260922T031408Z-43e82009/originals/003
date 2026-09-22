#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <string>
#include "tru_limits.h"  // shared P2P payload ceiling
#include "message.pb.h"
#include "blockchain.h"
#include "logging.h"
#include <openssl/sha.h> // For SHA-256 checksum

// Forward declaration of P2PNode to avoid circular dependencies
class P2PNode;

#pragma once

class MessageHandler {
public:
    // receive/send ceilings are per message type.
    // BLOCK retains the large relay envelope; TX/control messages use smaller
    // limits from tru_limits.h. There is intentionally no single catch-all
    // MAX_MESSAGE_SIZE public constant anymore.

    // Serialize BaseMessage to string, returning the size of the serialized data
    static size_t serializeMessage(const blockchain::BaseMessage& msg, std::string& out);

    // Deserialize string to BaseMessage, returning the number of bytes consumed
    static size_t deserializeMessage(const std::string& data, blockchain::BaseMessage& msg);

    // Create specific messages
    static blockchain::BaseMessage createVersionMessage();
    static blockchain::BaseMessage createVerAckMessage();
    static blockchain::BaseMessage createPingMessage();
    static blockchain::BaseMessage createPongMessage(uint64_t nonce);
    static blockchain::BaseMessage createChatMessage(const std::string& text);
    static blockchain::BaseMessage createHeightMessage(uint64_t height);
    static blockchain::BaseMessage createGetBlockRequest(uint64_t height);
    static blockchain::BaseMessage createGetHeightRequest();
    static blockchain::BaseMessage createBlockNotFoundMessage(uint64_t height, const std::string& errorMsg = "");

    // per-connection fail-closed network handshake validation.
    static bool validateVersionMessage(const blockchain::Version& version);
    // Handle received messages
    static void handleMessage(const blockchain::BaseMessage& msg, Blockchain* chain, P2PNode* node);

private:
    // Compute SHA-256 checksum of data
    static std::string computeChecksum(const std::string& data);

    // Sanitize string inputs to prevent injection attacks
    static std::string sanitizeString(const std::string& input);

    // Validate message fields
    static bool validateChatMessage(const blockchain::ChatMessage& chat);
};

#endif // MESSAGE_HANDLER_H
