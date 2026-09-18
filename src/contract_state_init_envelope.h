#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "contract_state_limits.h"
#include "opcodes.h"

// canonical state-init envelope primitives.
//
// Stateful locking scripts must contain CALL logic only. Creation-time state is
// carried separately in a zero-value OP_RETURN output so initialization is
// committed exactly once with the root contract outpoint.
//
// Canonical payload (all integer fields little-endian):
//   magic[8]      = "TRUSTATE"
//   version[1]    = 0x01
//   targetVout[4]
//   entryCount[2]
//   repeated entryCount times:
//     keyLen[1]       (1..128)
//     key[keyLen]
//     valueLen[2]     (0..4096)
//     value[valueLen]
//
// Entries MUST be strictly ascending by raw key bytes. Duplicate keys, trailing
// bytes, non-canonical push encodings, state-limit violations, and oversized
// payloads fail closed.
//
// This header does NOT activate creation, persistence, spending, or lineage.

namespace tru_contract_state_init {

inline constexpr unsigned char INIT_VERSION = 0x01;
inline constexpr size_t INIT_MAGIC_BYTES = 8;
inline constexpr size_t MAX_INIT_PAYLOAD_BYTES = 8192;
inline constexpr char INIT_MAGIC[INIT_MAGIC_BYTES + 1] = "TRUSTATE";

struct StateInitEnvelope {
    uint32_t targetVout{0};
    std::vector<std::pair<std::string, std::vector<unsigned char>>> entries;
};

inline void AppendU16LE(std::vector<unsigned char>& out, uint16_t v)
{
    out.push_back(static_cast<unsigned char>(v & 0xffU));
    out.push_back(static_cast<unsigned char>((v >> 8) & 0xffU));
}

inline void AppendU32LE(std::vector<unsigned char>& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xffU));
    }
}

inline bool ReadU16LE(
    const std::vector<unsigned char>& in,
    size_t& pc,
    uint16_t& out)
{
    if (in.size() - pc < 2) return false;
    out =
        static_cast<uint16_t>(in[pc]) |
        static_cast<uint16_t>(static_cast<uint16_t>(in[pc + 1]) << 8);
    pc += 2;
    return true;
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

inline bool IsStrictlySortedUnique(
    const std::vector<std::pair<std::string, std::vector<unsigned char>>>& entries)
{
    for (size_t i = 1; i < entries.size(); ++i) {
        if (!(entries[i - 1].first < entries[i].first)) return false;
    }
    return true;
}

inline bool ValidateEntries(
    const std::vector<std::pair<std::string, std::vector<unsigned char>>>& entries)
{
    if (entries.size() > tru_contract_state_limits::MAX_KEYS_PER_DOMAIN) {
        return false;
    }
    if (!IsStrictlySortedUnique(entries)) return false;

    tru_contract_state_limits::StateMap scratch;
    scratch.reserve(entries.size());

    for (const auto& [key, value] : entries) {
        if (!tru_contract_state_limits::CanApplyStateWrite(scratch, key, value)) {
            return false;
        }
        scratch.emplace(key, value);
    }
    return true;
}

inline bool BuildPayload(
    const StateInitEnvelope& envelope,
    std::vector<unsigned char>& payloadOut)
{
    payloadOut.clear();

    if (envelope.entries.size() > UINT16_MAX) return false;
    if (!ValidateEntries(envelope.entries)) return false;

    payloadOut.reserve(32);
    payloadOut.insert(
        payloadOut.end(),
        reinterpret_cast<const unsigned char*>(INIT_MAGIC),
        reinterpret_cast<const unsigned char*>(INIT_MAGIC) + INIT_MAGIC_BYTES);
    payloadOut.push_back(INIT_VERSION);
    AppendU32LE(payloadOut, envelope.targetVout);
    AppendU16LE(payloadOut, static_cast<uint16_t>(envelope.entries.size()));

    for (const auto& [key, value] : envelope.entries) {
        if (key.size() > UINT8_MAX || value.size() > UINT16_MAX) return false;

        payloadOut.push_back(static_cast<unsigned char>(key.size()));
        payloadOut.insert(payloadOut.end(), key.begin(), key.end());
        AppendU16LE(payloadOut, static_cast<uint16_t>(value.size()));
        payloadOut.insert(payloadOut.end(), value.begin(), value.end());

        if (payloadOut.size() > MAX_INIT_PAYLOAD_BYTES) {
            payloadOut.clear();
            return false;
        }
    }

    return payloadOut.size() <= MAX_INIT_PAYLOAD_BYTES;
}

inline bool ParsePayload(
    const std::vector<unsigned char>& payload,
    StateInitEnvelope& envelopeOut)
{
    envelopeOut = {};

    if (payload.size() < INIT_MAGIC_BYTES + 1 + 4 + 2 ||
        payload.size() > MAX_INIT_PAYLOAD_BYTES) {
        return false;
    }

    size_t pc = 0;
    for (size_t i = 0; i < INIT_MAGIC_BYTES; ++i) {
        if (payload[pc++] != static_cast<unsigned char>(INIT_MAGIC[i])) return false;
    }
    if (payload[pc++] != INIT_VERSION) return false;

    if (!ReadU32LE(payload, pc, envelopeOut.targetVout)) return false;

    uint16_t entryCount = 0;
    if (!ReadU16LE(payload, pc, entryCount)) return false;
    if (entryCount > tru_contract_state_limits::MAX_KEYS_PER_DOMAIN) {
        return false;
    }

    envelopeOut.entries.reserve(entryCount);
    for (uint16_t i = 0; i < entryCount; ++i) {
        if (pc >= payload.size()) return false;

        const size_t keyLen = payload[pc++];
        if (keyLen == 0 ||
            keyLen > tru_contract_state_limits::MAX_LOGICAL_KEY_BYTES ||
            keyLen > payload.size() - pc) {
            return false;
        }

        std::string key(
            reinterpret_cast<const char*>(payload.data() + pc),
            keyLen);
        pc += keyLen;

        uint16_t valueLen = 0;
        if (!ReadU16LE(payload, pc, valueLen)) return false;
        if (valueLen > tru_contract_state_limits::MAX_VALUE_BYTES ||
            valueLen > payload.size() - pc) {
            return false;
        }

        std::vector<unsigned char> value(
            payload.begin() + static_cast<std::ptrdiff_t>(pc),
            payload.begin() + static_cast<std::ptrdiff_t>(pc + valueLen));
        pc += valueLen;

        envelopeOut.entries.emplace_back(std::move(key), std::move(value));
    }

    if (pc != payload.size()) return false;
    return ValidateEntries(envelopeOut.entries);
}

inline void AppendCanonicalPush(
    std::vector<unsigned char>& script,
    const std::vector<unsigned char>& payload)
{
    const size_t n = payload.size();

    if (n <= 0x4b) {
        script.push_back(static_cast<unsigned char>(n));
    } else if (n <= UINT8_MAX) {
        script.push_back(OP_PUSHDATA1);
        script.push_back(static_cast<unsigned char>(n));
    } else {
        script.push_back(OP_PUSHDATA2);
        AppendU16LE(script, static_cast<uint16_t>(n));
    }

    script.insert(script.end(), payload.begin(), payload.end());
}

inline bool BuildOpReturnScript(
    const StateInitEnvelope& envelope,
    std::vector<unsigned char>& scriptOut)
{
    std::vector<unsigned char> payload;
    if (!BuildPayload(envelope, payload)) return false;

    scriptOut.clear();
    scriptOut.reserve(payload.size() + 4);
    scriptOut.push_back(OP_RETURN);
    AppendCanonicalPush(scriptOut, payload);
    return true;
}

inline bool ExtractCanonicalSinglePush(
    const std::vector<unsigned char>& script,
    std::vector<unsigned char>& payloadOut)
{
    payloadOut.clear();
    if (script.size() < 2 || script[0] != OP_RETURN) return false;

    size_t pc = 1;
    const unsigned char opcode = script[pc++];
    size_t pushLen = 0;

    if (opcode > OP_0 && opcode <= 0x4b) {
        pushLen = opcode;
    } else if (opcode == OP_PUSHDATA1) {
        if (pc >= script.size()) return false;
        pushLen = script[pc++];
        if (pushLen <= 0x4b) return false;
    } else if (opcode == OP_PUSHDATA2) {
        uint16_t n = 0;
        if (!ReadU16LE(script, pc, n)) return false;
        pushLen = n;
        if (pushLen <= UINT8_MAX) return false;
    } else {
        return false;
    }

    if (pushLen == 0 ||
        pushLen > MAX_INIT_PAYLOAD_BYTES ||
        pushLen != script.size() - pc) {
        return false;
    }

    payloadOut.assign(
        script.begin() + static_cast<std::ptrdiff_t>(pc),
        script.end());
    return true;
}

inline bool ParseOpReturnScript(
    const std::vector<unsigned char>& script,
    StateInitEnvelope& envelopeOut)
{
    std::vector<unsigned char> payload;
    if (!ExtractCanonicalSinglePush(script, payload)) return false;
    return ParsePayload(payload, envelopeOut);
}

inline bool IsStateInitEnvelopeScript(const std::vector<unsigned char>& script)
{
    StateInitEnvelope ignored;
    return ParseOpReturnScript(script, ignored);
}

} // namespace tru_contract_state_init
