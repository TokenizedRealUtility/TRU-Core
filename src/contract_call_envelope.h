#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "contract_state_init_envelope.h"
#include "opcodes.h"

// canonical state-call commitment envelope.
//
// The state-anchor input's scriptSig will carry PUSH-ONLY call arguments.
// A caller-controlled P2PKH vin[1] signs the transaction with SIGHASH_ALL.
// This zero-value OP_RETURN output commits that signed transaction to the exact
// anchor scriptSig via SHA256(scriptSig), preventing third-party mutation of
// contract call arguments while avoiding a new VM calldata opcode.
//
// Canonical payload:
//   magic[7]              = "TRUCALL"
//   version[1]            = 0x01
//   targetInput[4]        = little-endian (V1 requires 0)
//   continuationVout[4]   = little-endian
//   unlockScriptSha256[32]
//
// Total payload size is exactly 48 bytes, therefore its canonical OP_RETURN
// encoding is: OP_RETURN 0x30 <48-byte payload>.
//
// This header defines format only. It does NOT activate stateful spends,
// persistence, caller semantics, or lineage mutation.

namespace tru_contract_call_envelope {

inline constexpr unsigned char CALL_VERSION = 0x01;
inline constexpr size_t CALL_MAGIC_BYTES = 7;
inline constexpr size_t CALL_HASH_BYTES = 32;
inline constexpr size_t CALL_PAYLOAD_BYTES =
    CALL_MAGIC_BYTES + 1 + 4 + 4 + CALL_HASH_BYTES;
inline constexpr char CALL_MAGIC[CALL_MAGIC_BYTES + 1] = "TRUCALL";

struct StateCallEnvelope {
    uint32_t targetInput{0};
    uint32_t continuationVout{0};
    std::array<unsigned char, CALL_HASH_BYTES> unlockScriptSha256{};
};

inline void AppendU32LE(std::vector<unsigned char>& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xffU));
    }
}

inline bool ReadU32LE(
    const std::vector<unsigned char>& in,
    size_t& pc,
    uint32_t& out)
{
    if (in.size() - pc < 4) return false;
    out =
        static_cast<uint32_t>(in[pc]) |
        (static_cast<uint32_t>(in[pc + 1]) << 8) |
        (static_cast<uint32_t>(in[pc + 2]) << 16) |
        (static_cast<uint32_t>(in[pc + 3]) << 24);
    pc += 4;
    return true;
}

inline bool BuildPayload(
    const StateCallEnvelope& envelope,
    std::vector<unsigned char>& payloadOut)
{
    payloadOut.clear();
    payloadOut.reserve(CALL_PAYLOAD_BYTES);

    payloadOut.insert(
        payloadOut.end(),
        reinterpret_cast<const unsigned char*>(CALL_MAGIC),
        reinterpret_cast<const unsigned char*>(CALL_MAGIC) + CALL_MAGIC_BYTES);
    payloadOut.push_back(CALL_VERSION);
    AppendU32LE(payloadOut, envelope.targetInput);
    AppendU32LE(payloadOut, envelope.continuationVout);
    payloadOut.insert(
        payloadOut.end(),
        envelope.unlockScriptSha256.begin(),
        envelope.unlockScriptSha256.end());

    return payloadOut.size() == CALL_PAYLOAD_BYTES;
}

inline bool ParsePayload(
    const std::vector<unsigned char>& payload,
    StateCallEnvelope& envelopeOut)
{
    envelopeOut = {};
    if (payload.size() != CALL_PAYLOAD_BYTES) return false;

    size_t pc = 0;
    for (size_t i = 0; i < CALL_MAGIC_BYTES; ++i) {
        if (payload[pc++] != static_cast<unsigned char>(CALL_MAGIC[i])) {
            return false;
        }
    }

    if (payload[pc++] != CALL_VERSION) return false;
    if (!ReadU32LE(payload, pc, envelopeOut.targetInput)) return false;
    if (!ReadU32LE(payload, pc, envelopeOut.continuationVout)) return false;

    if (payload.size() - pc != CALL_HASH_BYTES) return false;
    for (size_t i = 0; i < CALL_HASH_BYTES; ++i) {
        envelopeOut.unlockScriptSha256[i] = payload[pc++];
    }

    return pc == payload.size();
}

inline bool BuildOpReturnScript(
    const StateCallEnvelope& envelope,
    std::vector<unsigned char>& scriptOut)
{
    std::vector<unsigned char> payload;
    if (!BuildPayload(envelope, payload)) return false;

    scriptOut.clear();
    scriptOut.reserve(CALL_PAYLOAD_BYTES + 2);
    scriptOut.push_back(OP_RETURN);

    // CALL_PAYLOAD_BYTES is 48 (0x30), so canonical encoding is direct push.
    if (CALL_PAYLOAD_BYTES == 0 || CALL_PAYLOAD_BYTES > 0x4b) return false;
    scriptOut.push_back(static_cast<unsigned char>(CALL_PAYLOAD_BYTES));
    scriptOut.insert(scriptOut.end(), payload.begin(), payload.end());
    return true;
}

inline bool ParseOpReturnScript(
    const std::vector<unsigned char>& script,
    StateCallEnvelope& envelopeOut)
{
    std::vector<unsigned char> payload;
    if (!tru_contract_state_init::ExtractCanonicalSinglePush(script, payload)) {
        return false;
    }
    return ParsePayload(payload, envelopeOut);
}

inline bool IsStateCallEnvelopeScript(const std::vector<unsigned char>& script)
{
    StateCallEnvelope ignored;
    return ParseOpReturnScript(script, ignored);
}

} // namespace tru_contract_call_envelope
