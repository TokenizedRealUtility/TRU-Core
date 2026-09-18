#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <openssl/sha.h>

#include "opcodes.h"
#include "contract_state_init_envelope.h"  // creation init envelope primitives
#include "contract_call_envelope.h"  // signed call-argument commitment

// canonical state-anchor call policy.
//
// This file defines the pre-genesis transaction SHAPE for any locking script
// that touches the future persistent contract-state domain.
//
// V1 canonical call shape:
//   vin[0]  = current state-anchor UTXO
//   vin[1]  = exactly one caller-controlled standard P2PKH funding input
//   vout[*] = exactly one continuation output with byte-identical locking script
//             and amount >= the consumed state anchor
//
// Economic call value is the non-negative delta:
//   continuation.amount - anchor.amount
//
// Other outputs may carry one zero-value TRUCALL commitment envelope and caller
// change. Patch 14D2D pins the commitment format; activation remains deferred.
//
// IMPORTANT: Patch 14D2 keeps stateful spends consensus/relay FAIL-CLOSED even
// after they satisfy this shape. Patch 14D3 may remove that final activation
// gate only together with confirmed-state loading, mempool overlay, atomic state
// commit, lineage writes, and undo/recovery parity.

namespace tru_contract_call {

struct StatefulScriptScanResult {
    bool valid{true};
    bool usesStateDomain{false};
    bool usesStoreOrLoad{false};
    bool usesMintToken{false};

    // Contract Vault classification uses the same push-aware walk.
    // Bridge opcode bytes inside pushed data are data, not executable bridge ops.
    bool usesBridgeOpcode{false};

    // SC-22 relay-policy classification. These flags are path-independent:
    // bytes inside canonical data pushes are never interpreted as opcodes.
    bool usesExternalData{false};
    bool usesDataFeed{false};
    bool usesDelegateCheck{false};
    bool usesUpgradeNop{false};

    // MS-01B: bare CHECKMULTISIG opcodes are standard only through the exact
    // canonical 2-of-3 escrow family. The scanner is push-aware, so opcode
    // bytes inside pushed data never set this flag.
    bool usesMultisigOpcode{false};
};

inline bool ReadPushLength(
    const std::vector<unsigned char>& script,
    size_t& pc,
    unsigned char opcode,
    size_t& pushLen)
{
    pushLen = 0;

    if (opcode > OP_0 && opcode <= 0x4b) {
        pushLen = static_cast<size_t>(opcode);
    } else if (opcode == OP_PUSHDATA1) {
        if (pc >= script.size()) return false;
        pushLen = static_cast<size_t>(script[pc++]);
    } else if (opcode == OP_PUSHDATA2) {
        if (script.size() - pc < 2) return false;
        pushLen =
            static_cast<size_t>(script[pc]) |
            (static_cast<size_t>(script[pc + 1]) << 8);
        pc += 2;
    } else if (opcode == OP_PUSHDATA4) {
        if (script.size() - pc < 4) return false;
        const uint32_t len =
            static_cast<uint32_t>(script[pc]) |
            (static_cast<uint32_t>(script[pc + 1]) << 8) |
            (static_cast<uint32_t>(script[pc + 2]) << 16) |
            (static_cast<uint32_t>(script[pc + 3]) << 24);
        pc += 4;
        pushLen = static_cast<size_t>(len);
    } else {
        return true; // not a push opcode
    }

    if (pushLen > script.size() - pc) return false;
    pc += pushLen;
    return true;
}

// V1 contract-call arguments live in vin[0].scriptSig, but scriptSig is DATA
// only. Stateful VM opcodes or arbitrary executable opcodes are never permitted
// in the unlocking script. Requiring canonical pushes also removes redundant
// encodings from the call-commitment surface.
inline bool IsCanonicalPushOnlyUnlockScript(
    const std::vector<unsigned char>& script)
{
    size_t pc = 0;

    while (pc < script.size()) {
        const unsigned char opcode = script[pc++];

        if (opcode == OP_0) {
            continue;
        }

        size_t pushLen = 0;
        if (opcode > OP_0 && opcode <= 0x4b) {
            pushLen = static_cast<size_t>(opcode);
        } else if (opcode == OP_PUSHDATA1) {
            if (pc >= script.size()) return false;
            pushLen = static_cast<size_t>(script[pc++]);
            if (pushLen <= 0x4b) return false; // non-minimal
        } else if (opcode == OP_PUSHDATA2) {
            if (script.size() - pc < 2) return false;
            pushLen =
                static_cast<size_t>(script[pc]) |
                (static_cast<size_t>(script[pc + 1]) << 8);
            pc += 2;
            if (pushLen <= UINT8_MAX) return false; // non-minimal
        } else if (opcode == OP_PUSHDATA4) {
            if (script.size() - pc < 4) return false;
            const uint32_t len =
                static_cast<uint32_t>(script[pc]) |
                (static_cast<uint32_t>(script[pc + 1]) << 8) |
                (static_cast<uint32_t>(script[pc + 2]) << 16) |
                (static_cast<uint32_t>(script[pc + 3]) << 24);
            pc += 4;
            pushLen = static_cast<size_t>(len);
            if (pushLen <= UINT16_MAX) return false; // non-minimal
        } else {
            return false;
        }

        if (pushLen > script.size() - pc) return false;
        pc += pushLen;
    }

    return true;
}

inline bool AppendCanonicalDataPush(
    std::vector<unsigned char>& scriptOut,
    const std::vector<unsigned char>& data)
{
    const std::size_t n = data.size();
    if (n == 0) {
        scriptOut.push_back(OP_0);
    } else if (n <= 0x4b) {
        scriptOut.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xff) {
        scriptOut.push_back(OP_PUSHDATA1);
        scriptOut.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xffff) {
        scriptOut.push_back(OP_PUSHDATA2);
        scriptOut.push_back(static_cast<unsigned char>(n & 0xffU));
        scriptOut.push_back(static_cast<unsigned char>((n >> 8) & 0xffU));
    } else {
        return false;
    }
    scriptOut.insert(scriptOut.end(), data.begin(), data.end());
    return true;
}

inline bool ReadCanonicalDataPush(
    const std::vector<unsigned char>& script,
    std::size_t& pc,
    std::vector<unsigned char>& itemOut)
{
    itemOut.clear();
    if (pc >= script.size()) return false;

    const unsigned char opcode = script[pc++];
    std::size_t pushLen = 0;
    if (opcode == OP_0) {
        return true;
    }
    if (opcode > OP_0 && opcode <= 0x4b) {
        pushLen = static_cast<std::size_t>(opcode);
    } else if (opcode == OP_PUSHDATA1) {
        if (pc >= script.size()) return false;
        pushLen = static_cast<std::size_t>(script[pc++]);
        if (pushLen <= 0x4b) return false;
    } else if (opcode == OP_PUSHDATA2) {
        if (script.size() - pc < 2) return false;
        pushLen = static_cast<std::size_t>(script[pc]) |
            (static_cast<std::size_t>(script[pc + 1]) << 8);
        pc += 2;
        if (pushLen <= 0xff) return false;
    } else {
        return false;
    }

    if (pushLen > script.size() - pc) return false;
    itemOut.assign(script.begin() + static_cast<std::ptrdiff_t>(pc),
                   script.begin() + static_cast<std::ptrdiff_t>(pc + pushLen));
    pc += pushLen;
    return true;
}

inline bool BuildStatefulKvV1UnlockScript(
    const std::string& logicalKey,
    const std::vector<unsigned char>& value,
    std::vector<unsigned char>& scriptOut)
{
    scriptOut.clear();
    if (!tru_contract_state_limits::IsLogicalKeyAllowed(logicalKey) ||
        !tru_contract_state_limits::IsValueAllowed(value)) {
        return false;
    }

    const std::vector<unsigned char> keyBytes(logicalKey.begin(), logicalKey.end());
    return AppendCanonicalDataPush(scriptOut, keyBytes) &&
           AppendCanonicalDataPush(scriptOut, value) &&
           IsCanonicalPushOnlyUnlockScript(scriptOut);
}

inline bool DecodeStatefulKvV1UnlockScript(
    const std::vector<unsigned char>& script,
    std::string& logicalKeyOut,
    std::vector<unsigned char>& valueOut)
{
    logicalKeyOut.clear();
    valueOut.clear();
    if (!IsCanonicalPushOnlyUnlockScript(script)) return false;

    std::size_t pc = 0;
    std::vector<unsigned char> keyBytes;
    if (!ReadCanonicalDataPush(script, pc, keyBytes) ||
        !ReadCanonicalDataPush(script, pc, valueOut) ||
        pc != script.size()) {
        return false;
    }

    logicalKeyOut.assign(keyBytes.begin(), keyBytes.end());
    return tru_contract_state_limits::IsLogicalKeyAllowed(logicalKeyOut) &&
           tru_contract_state_limits::IsValueAllowed(valueOut);
}

inline bool ComputeUnlockScriptSha256(
    const std::vector<unsigned char>& script,
    std::array<unsigned char, 32>& hashOut)
{
    const unsigned char* ptr = script.empty() ? nullptr : script.data();
    unsigned char* digest = SHA256(ptr, script.size(), hashOut.data());
    return digest == hashOut.data();
}

inline StatefulScriptScanResult ScanStatefulContractScript(
    const std::vector<unsigned char>& script)
{
    StatefulScriptScanResult result;
    size_t pc = 0;

    while (pc < script.size()) {
        const unsigned char opcode = script[pc++];

        if ((opcode > OP_0 && opcode <= 0x4b) ||
            opcode == OP_PUSHDATA1 ||
            opcode == OP_PUSHDATA2 ||
            opcode == OP_PUSHDATA4) {
            size_t ignored = 0;
            if (!ReadPushLength(script, pc, opcode, ignored)) {
                result.valid = false;
                return result;
            }
            continue;
        }

        if (opcode == OP_STORE || opcode == OP_LOAD) {
            result.usesStateDomain = true;
            result.usesStoreOrLoad = true;
        } else if (opcode == OP_MINT_TOKEN) {
            result.usesStateDomain = true;
            result.usesMintToken = true;
        } else if (opcode == OP_EXTERNALDATA) {
            result.usesExternalData = true;
        } else if (opcode == OP_DATAFEED) {
            result.usesDataFeed = true;
        } else if (opcode == OP_DELEGATECHECK) {
            result.usesDelegateCheck = true;
        } else if (opcode == OP_CHECKMULTISIG ||
                   opcode == OP_CHECKMULTISIGVERIFY) {
            result.usesMultisigOpcode = true;
        } else if (opcode == OP_NOVO_GENADDR ||
                   opcode == OP_NOVO_DEPOSIT ||
                   opcode == OP_NOVO_REDEEM ||
                   opcode == OP_NOVO_VERIFY ||
                   opcode == OP_BSTY_GENADDR ||
                   opcode == OP_BSTY_DEPOSIT ||
                   opcode == OP_BSTY_REDEEM ||
                   opcode == OP_BSTY_VERIFY) {
            result.usesBridgeOpcode = true;
        } else if (opcode == OP_UPGRADE_NOP1 ||
                   opcode == OP_UPGRADE_NOP2 ||
                   opcode == OP_UPGRADE_NOP3 ||
                   opcode == OP_UPGRADE_NOP4 ||
                   opcode == OP_UPGRADE_NOP5 ||
                   opcode == OP_UPGRADE_NOP6 ||
                   opcode == OP_UPGRADE_NOP7 ||
                   opcode == OP_UPGRADE_NOP8) {
            result.usesUpgradeNop = true;
        }
    }

    return result;
}


// first activated stateful family: Stateful K/V V1.
//
// The locking script contains CALL logic only. Initial state is supplied by a
// TRUSTATE envelope and committed once at root creation. Patch 14D3A2 also
// requires exactly one standard P2PKH creator input so future calls can be
// owner-authorized without guessing identity. Spending remains disabled.
inline constexpr size_t MAX_BLOCK_STATE_INIT_ACCOUNTED_BYTES =
    200ULL * 1024ULL; // align creation growth with the durable-state gas budget

inline bool DecodeScriptHexStrict(
    const std::string& hex,
    std::vector<unsigned char>& bytesOut)
{
    bytesOut.clear();
    if (hex.empty() || (hex.size() & 1U) != 0) return false;

    bytesOut.reserve(hex.size() / 2U);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const auto nibble = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        bytesOut.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// MS-01B — Canonical Multisig / Escrow V1 structural family.
//
// V1 deliberately activates one bare multisig locking shape only:
//
//   OP_2 <33-byte compressed pubkey A>
//        <33-byte compressed pubkey B>
//        <33-byte compressed pubkey C>
//   OP_3 OP_CHECKMULTISIG
//
// The three compressed SEC1 encodings must be strictly lexicographically
// increasing. That simultaneously makes the participant set deterministic and
// rejects duplicate keys. This is RELAY / classification policy only; existing
// consensus CHECKMULTISIG semantics are unchanged.
struct CanonicalMultisig2of3V1Info {
    std::array<std::array<unsigned char, 33>, 3> pubkeys{};
};

inline bool IsCanonicalCompressedSecp256k1Encoding(
    const std::array<unsigned char, 33>& pubkey)
{
    return pubkey[0] == 0x02 || pubkey[0] == 0x03;
}

inline bool ParseCanonicalMultisig2of3V1Script(
    const std::vector<unsigned char>& script,
    CanonicalMultisig2of3V1Info& infoOut)
{
    // 1 + 3*(1+33) + 1 + 1 = 105 bytes.
    static constexpr std::size_t EXPECTED_SIZE = 105U;
    if (script.size() != EXPECTED_SIZE ||
        script[0] != static_cast<unsigned char>(OP_2) ||
        script[1] != 0x21 ||
        script[35] != 0x21 ||
        script[69] != 0x21 ||
        script[103] != static_cast<unsigned char>(OP_3) ||
        script[104] != static_cast<unsigned char>(OP_CHECKMULTISIG)) {
        return false;
    }

    CanonicalMultisig2of3V1Info parsed;
    const std::array<std::size_t, 3> starts{{2U, 36U, 70U}};
    for (std::size_t i = 0; i < starts.size(); ++i) {
        std::copy_n(
            script.begin() + static_cast<std::ptrdiff_t>(starts[i]),
            parsed.pubkeys[i].size(),
            parsed.pubkeys[i].begin());
        if (!IsCanonicalCompressedSecp256k1Encoding(parsed.pubkeys[i])) {
            return false;
        }
    }

    if (!(parsed.pubkeys[0] < parsed.pubkeys[1] &&
          parsed.pubkeys[1] < parsed.pubkeys[2])) {
        return false;
    }

    infoOut = parsed;
    return true;
}

inline bool ParseCanonicalMultisig2of3V1ScriptHex(
    const std::string& scriptHex,
    CanonicalMultisig2of3V1Info& infoOut)
{
    std::vector<unsigned char> script;
    return DecodeScriptHexStrict(scriptHex, script) &&
           ParseCanonicalMultisig2of3V1Script(script, infoOut);
}

// MS-01C — one canonical builder shared by wallet/CLI today and RPC later.
// Caller order is not consensus-significant: V1 canonicalizes the participant
// set by sorting compressed SEC1 encodings before serializing the lock.
inline bool BuildCanonicalMultisig2of3V1Script(
    const std::array<std::array<unsigned char, 33>, 3>& participantKeys,
    std::vector<unsigned char>& scriptOut,
    CanonicalMultisig2of3V1Info* infoOut = nullptr)
{
    auto sorted = participantKeys;
    std::sort(sorted.begin(), sorted.end());

    for (const auto& key : sorted) {
        if (!IsCanonicalCompressedSecp256k1Encoding(key)) {
            scriptOut.clear();
            return false;
        }
    }
    if (!(sorted[0] < sorted[1] && sorted[1] < sorted[2])) {
        scriptOut.clear();
        return false; // duplicate participant key
    }

    scriptOut.clear();
    scriptOut.reserve(105U);
    scriptOut.push_back(static_cast<unsigned char>(OP_2));
    for (const auto& key : sorted) {
        scriptOut.push_back(0x21);
        scriptOut.insert(scriptOut.end(), key.begin(), key.end());
    }
    scriptOut.push_back(static_cast<unsigned char>(OP_3));
    scriptOut.push_back(static_cast<unsigned char>(OP_CHECKMULTISIG));

    CanonicalMultisig2of3V1Info parsed;
    if (!ParseCanonicalMultisig2of3V1Script(scriptOut, parsed)) {
        scriptOut.clear();
        return false;
    }
    if (infoOut) *infoOut = parsed;
    return true;
}

// HTLC-01B — Canonical Hashed Timelock Contract / Atomic Swap V1.
//
// V1 deliberately pins one Bitcoin-compatible two-branch locking shape:
//
//   OP_IF
//       OP_HASH160 <20-byte secret HASH160> OP_EQUALVERIFY
//       <33-byte compressed claim pubkey> OP_CHECKSIG
//   OP_ELSE
//       <4-byte little-endian Unix timestamp> OP_CHECKLOCKTIMEVERIFY OP_DROP
//       <33-byte compressed refund pubkey> OP_CHECKSIG
//   OP_ENDIF
//
// Claim unlock shape (validated later by HTLC-01D wallet code):
//   <claim signature+SIGHASH_ALL> <secret preimage> OP_1
//
// Refund unlock shape:
//   <refund signature+SIGHASH_ALL> OP_0
//
// IMPORTANT: claim remains valid after timeout until one branch spends the UTXO.
// Timeout activates the refund branch; it is not an upper-bound opcode. This is
// the conventional atomic-swap race model and keeps the TRU contract portable
// to Bitcoin-style HTLC peers.
//
// This helper is relay/classification structure only. Existing VM, CHECKSIG,
// HASH160 and CLTV consensus semantics are unchanged.
struct CanonicalHtlcAtomicSwapV1Info {
    std::array<unsigned char, 20> secretHash160{};
    std::array<unsigned char, 33> claimPubkey{};
    std::uint32_t refundLockTime{0};
    std::array<unsigned char, 33> refundPubkey{};
};

inline bool ParseCanonicalHtlcAtomicSwapV1Script(
    const std::vector<unsigned char>& script,
    CanonicalHtlcAtomicSwapV1Info& infoOut)
{
    infoOut = {};

    // Exact byte layout, 103 bytes total:
    // 00  OP_IF
    // 01  OP_HASH160
    // 02  PUSH20
    // 03..22 secret HASH160
    // 23  OP_EQUALVERIFY
    // 24  PUSH33
    // 25..57 claim pubkey
    // 58  OP_CHECKSIG
    // 59  OP_ELSE
    // 60  PUSH4
    // 61..64 refund Unix time, uint32 LE
    // 65  OP_CHECKLOCKTIMEVERIFY
    // 66  OP_DROP
    // 67  PUSH33
    // 68..100 refund pubkey
    // 101 OP_CHECKSIG
    // 102 OP_ENDIF
    static constexpr std::size_t EXPECTED_SIZE = 103U;
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;
    // V1 pins a 4-byte positive ScriptNum timestamp. Values with bit 31 set
    // would be interpreted as negative by Bitcoin-style CLTV semantics.
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_MAX = 0x7fffffffU;

    if (script.size() != EXPECTED_SIZE ||
        script[0] != static_cast<unsigned char>(OP_IF) ||
        script[1] != static_cast<unsigned char>(OP_HASH160) ||
        script[2] != 0x14 ||
        script[23] != static_cast<unsigned char>(OP_EQUALVERIFY) ||
        script[24] != 0x21 ||
        script[58] != static_cast<unsigned char>(OP_CHECKSIG) ||
        script[59] != static_cast<unsigned char>(OP_ELSE) ||
        script[60] != 0x04 ||
        script[65] != static_cast<unsigned char>(OP_CHECKLOCKTIMEVERIFY) ||
        script[66] != static_cast<unsigned char>(OP_DROP) ||
        script[67] != 0x21 ||
        script[101] != static_cast<unsigned char>(OP_CHECKSIG) ||
        script[102] != static_cast<unsigned char>(OP_ENDIF)) {
        return false;
    }

    CanonicalHtlcAtomicSwapV1Info parsed;
    std::copy_n(script.begin() + 3, parsed.secretHash160.size(),
                parsed.secretHash160.begin());
    std::copy_n(script.begin() + 25, parsed.claimPubkey.size(),
                parsed.claimPubkey.begin());
    std::copy_n(script.begin() + 68, parsed.refundPubkey.size(),
                parsed.refundPubkey.begin());

    parsed.refundLockTime =
        static_cast<std::uint32_t>(script[61]) |
        (static_cast<std::uint32_t>(script[62]) << 8) |
        (static_cast<std::uint32_t>(script[63]) << 16) |
        (static_cast<std::uint32_t>(script[64]) << 24);

    if (parsed.refundLockTime < TRU_CLTV_TIMESTAMP_THRESHOLD ||
        parsed.refundLockTime > TRU_CLTV_TIMESTAMP_MAX ||
        !IsCanonicalCompressedSecp256k1Encoding(parsed.claimPubkey) ||
        !IsCanonicalCompressedSecp256k1Encoding(parsed.refundPubkey) ||
        parsed.claimPubkey == parsed.refundPubkey) {
        return false;
    }

    infoOut = parsed;
    return true;
}

inline bool ParseCanonicalHtlcAtomicSwapV1ScriptHex(
    const std::string& scriptHex,
    CanonicalHtlcAtomicSwapV1Info& infoOut)
{
    std::vector<unsigned char> script;
    return DecodeScriptHexStrict(scriptHex, script) &&
           ParseCanonicalHtlcAtomicSwapV1Script(script, infoOut);
}

// HTLC-01B also freezes the canonical serializer so later wallet/RPC creation
// cannot drift from relay classification. Claim/refund roles are semantic and
// therefore MUST NOT be sorted.
inline bool BuildCanonicalHtlcAtomicSwapV1Script(
    const std::array<unsigned char, 20>& secretHash160,
    const std::array<unsigned char, 33>& claimPubkey,
    const std::array<unsigned char, 33>& refundPubkey,
    std::uint32_t refundLockTime,
    std::vector<unsigned char>& scriptOut,
    CanonicalHtlcAtomicSwapV1Info* infoOut = nullptr)
{
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;
    // V1 pins a 4-byte positive ScriptNum timestamp. Values with bit 31 set
    // would be interpreted as negative by Bitcoin-style CLTV semantics.
    static constexpr std::uint32_t TRU_CLTV_TIMESTAMP_MAX = 0x7fffffffU;
    if (refundLockTime < TRU_CLTV_TIMESTAMP_THRESHOLD ||
        refundLockTime > TRU_CLTV_TIMESTAMP_MAX ||
        !IsCanonicalCompressedSecp256k1Encoding(claimPubkey) ||
        !IsCanonicalCompressedSecp256k1Encoding(refundPubkey) ||
        claimPubkey == refundPubkey) {
        scriptOut.clear();
        return false;
    }

    scriptOut.clear();
    scriptOut.reserve(103U);
    scriptOut.push_back(static_cast<unsigned char>(OP_IF));
    scriptOut.push_back(static_cast<unsigned char>(OP_HASH160));
    scriptOut.push_back(0x14);
    scriptOut.insert(scriptOut.end(), secretHash160.begin(), secretHash160.end());
    scriptOut.push_back(static_cast<unsigned char>(OP_EQUALVERIFY));
    scriptOut.push_back(0x21);
    scriptOut.insert(scriptOut.end(), claimPubkey.begin(), claimPubkey.end());
    scriptOut.push_back(static_cast<unsigned char>(OP_CHECKSIG));
    scriptOut.push_back(static_cast<unsigned char>(OP_ELSE));
    scriptOut.push_back(0x04);
    scriptOut.push_back(static_cast<unsigned char>(refundLockTime & 0xffU));
    scriptOut.push_back(static_cast<unsigned char>((refundLockTime >> 8) & 0xffU));
    scriptOut.push_back(static_cast<unsigned char>((refundLockTime >> 16) & 0xffU));
    scriptOut.push_back(static_cast<unsigned char>((refundLockTime >> 24) & 0xffU));
    scriptOut.push_back(static_cast<unsigned char>(OP_CHECKLOCKTIMEVERIFY));
    scriptOut.push_back(static_cast<unsigned char>(OP_DROP));
    scriptOut.push_back(0x21);
    scriptOut.insert(scriptOut.end(), refundPubkey.begin(), refundPubkey.end());
    scriptOut.push_back(static_cast<unsigned char>(OP_CHECKSIG));
    scriptOut.push_back(static_cast<unsigned char>(OP_ENDIF));

    CanonicalHtlcAtomicSwapV1Info parsed;
    if (!ParseCanonicalHtlcAtomicSwapV1Script(scriptOut, parsed)) {
        scriptOut.clear();
        return false;
    }
    if (infoOut) *infoOut = parsed;
    return true;
}

// shared structural classifiers for read-side/explorer identity.
// These helpers are deliberately byte-exact and never search inside pushed data.
// They do not alter VM, mempool, or consensus policy.
struct CanonicalTimeLockV1Info {
    std::uint32_t lockTime{0};
    std::string ownerHash160;
};

struct CanonicalOracleLockV1Info {
    std::string feed;
    std::uint64_t threshold{0};
    std::string comparator;
    std::string ownerHash160;
};

inline std::string HexLowerExact(
    const unsigned char* data,
    std::size_t size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2U);
    for (std::size_t i = 0; i < size; ++i) {
        const unsigned char b = data[i];
        out.push_back(kHex[(b >> 4) & 0x0fU]);
        out.push_back(kHex[b & 0x0fU]);
    }
    return out;
}

inline bool ParseCanonicalTimeLockV1Script(
    const std::vector<unsigned char>& script,
    CanonicalTimeLockV1Info& infoOut)
{
    infoOut = {};
    if (script.size() != 32 ||
        script[0] != 0x04 ||
        script[5] != static_cast<unsigned char>(OP_CHECKLOCKTIMEVERIFY) ||
        script[6] != static_cast<unsigned char>(OP_DROP) ||
        script[7] != static_cast<unsigned char>(OP_DUP) ||
        script[8] != static_cast<unsigned char>(OP_HASH160) ||
        script[9] != 0x14 ||
        script[30] != static_cast<unsigned char>(OP_EQUALVERIFY) ||
        script[31] != static_cast<unsigned char>(OP_CHECKSIG)) {
        return false;
    }

    infoOut.lockTime =
        static_cast<std::uint32_t>(script[1]) |
        (static_cast<std::uint32_t>(script[2]) << 8) |
        (static_cast<std::uint32_t>(script[3]) << 16) |
        (static_cast<std::uint32_t>(script[4]) << 24);
    infoOut.ownerHash160 = HexLowerExact(script.data() + 10, 20);
    return true;
}

inline bool ParseCanonicalTimeLockV1ScriptHex(
    const std::string& scriptHex,
    CanonicalTimeLockV1Info& infoOut)
{
    std::vector<unsigned char> script;
    return DecodeScriptHexStrict(scriptHex, script) &&
           ParseCanonicalTimeLockV1Script(script, infoOut);
}

inline bool ParseCanonicalHashLockV1ScriptHex(
    const std::string& scriptHex,
    std::string& hash160Out)
{
    hash160Out.clear();
    std::vector<unsigned char> script;
    if (!DecodeScriptHexStrict(scriptHex, script) ||
        script.size() != 23 ||
        script[0] != static_cast<unsigned char>(OP_HASH160) ||
        script[1] != 0x14 ||
        script[22] != static_cast<unsigned char>(OP_EQUAL)) {
        return false;
    }
    hash160Out = HexLowerExact(script.data() + 2, 20);
    return true;
}

// SC-22 — canonical MagicLock V1 relay parser.
//
// The current wallet creator emits exactly:
//   OP_SWAP OP_HASH256 <target-length> OP_LEFT <target> OP_EQUALVERIFY
//   OP_DUP OP_HASH160 <owner20> OP_EQUALVERIFY OP_CHECKSIG
//
// target-length uses OP_1..OP_16 for 1..16 bytes and a canonical one-byte
// push for 17..75. Historical pre-canonical MagicLock variants remain
// spendable if already confirmed, but new relay accepts only this creator shape.
struct CanonicalMagicLockV1Info {
    std::string targetPrefix;
    std::string ownerHash160;
};

inline bool ParseCanonicalMagicLockV1Script(
    const std::vector<unsigned char>& script,
    CanonicalMagicLockV1Info& infoOut)
{
    infoOut = {};
    if (script.size() < 2 + 1 + 1 + 1 + 1 + 26) return false;

    std::size_t pc = 0;
    if (script[pc++] != static_cast<unsigned char>(OP_SWAP) ||
        script[pc++] != static_cast<unsigned char>(OP_HASH256)) {
        return false;
    }

    std::size_t targetLen = 0;
    if (pc >= script.size()) return false;
    const unsigned char lenOp = script[pc++];
    if (lenOp >= static_cast<unsigned char>(OP_1) &&
        lenOp <= static_cast<unsigned char>(OP_16)) {
        targetLen =
            static_cast<std::size_t>(
                lenOp - static_cast<unsigned char>(OP_1)) + 1U;
    } else if (lenOp == 0x01) {
        if (pc >= script.size()) return false;
        targetLen = static_cast<std::size_t>(script[pc++]);
        if (targetLen <= 16U || targetLen > 0x4bU) return false;
    } else {
        return false;
    }

    if (pc >= script.size() ||
        script[pc++] != static_cast<unsigned char>(OP_LEFT) ||
        pc >= script.size()) {
        return false;
    }

    // createMagicLockScript() uses the direct-push opcode whose byte value is
    // exactly the target length. Relay requires that byte to agree with the
    // length operand above; malformed/mismatched encodings fail closed.
    if (script[pc++] != static_cast<unsigned char>(targetLen) ||
        targetLen == 0 ||
        targetLen > 0x4bU ||
        targetLen > script.size() - pc) {
        return false;
    }

    const std::size_t targetStart = pc;
    pc += targetLen;

    if (script.size() - pc != 26U ||
        script[pc++] != static_cast<unsigned char>(OP_EQUALVERIFY) ||
        script[pc++] != static_cast<unsigned char>(OP_DUP) ||
        script[pc++] != static_cast<unsigned char>(OP_HASH160) ||
        script[pc++] != 0x14) {
        return false;
    }

    if (script.size() - pc != 22U) return false;
    const std::size_t ownerStart = pc;
    pc += 20U;

    if (script[pc++] != static_cast<unsigned char>(OP_EQUALVERIFY) ||
        script[pc++] != static_cast<unsigned char>(OP_CHECKSIG) ||
        pc != script.size()) {
        return false;
    }

    infoOut.targetPrefix =
        HexLowerExact(script.data() + targetStart, targetLen);
    infoOut.ownerHash160 =
        HexLowerExact(script.data() + ownerStart, 20U);
    return true;
}

inline bool ParseCanonicalMagicLockV1ScriptHex(
    const std::string& scriptHex,
    CanonicalMagicLockV1Info& infoOut)
{
    std::vector<unsigned char> script;
    return DecodeScriptHexStrict(scriptHex, script) &&
           ParseCanonicalMagicLockV1Script(script, infoOut);
}

inline bool ParseCanonicalOracleLockV1Script(
    const std::vector<unsigned char>& script,
    CanonicalOracleLockV1Info& infoOut)
{
    infoOut = {};

    // Patch 18 canonical Oracle Feed V1 currently compiles exactly as:
    //   12 <18-byte deterministic chain:* key> OP_DATAFEED
    //   08 <uint64 threshold LE> (OP_LESSTHANOREQUAL|OP_GREATERTHANOREQUAL)
    //   OP_VERIFY OP_DUP OP_HASH160 14 <owner20> OP_EQUALVERIFY OP_CHECKSIG
    //
    // Do NOT use the older 9f/a0 (< or >) reviewer sketch here: the live
    // Patch-18 creator + mempool canonical rule use a1/a2 (<= / >=).
    if (script.size() != 56 ||
        script[0] != 0x12 ||
        script[19] != static_cast<unsigned char>(OP_DATAFEED) ||
        script[20] != 0x08 ||
        (script[29] != static_cast<unsigned char>(OP_LESSTHANOREQUAL) &&
         script[29] != static_cast<unsigned char>(OP_GREATERTHANOREQUAL)) ||
        script[30] != static_cast<unsigned char>(OP_VERIFY) ||
        script[31] != static_cast<unsigned char>(OP_DUP) ||
        script[32] != static_cast<unsigned char>(OP_HASH160) ||
        script[33] != 0x14 ||
        script[54] != static_cast<unsigned char>(OP_EQUALVERIFY) ||
        script[55] != static_cast<unsigned char>(OP_CHECKSIG)) {
        return false;
    }

    const std::string feed(
        reinterpret_cast<const char*>(script.data() + 1), 18);
    if (feed != "chain:block_height" &&
        feed != "chain:total_supply" &&
        feed != "chain:block_reward") {
        return false;
    }

    std::uint64_t threshold = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        threshold |= static_cast<std::uint64_t>(script[21 + i]) << (8U * i);
    }

    infoOut.feed = feed;
    infoOut.threshold = threshold;
    infoOut.comparator =
        script[29] == static_cast<unsigned char>(OP_GREATERTHANOREQUAL)
            ? ">=" : "<=";
    infoOut.ownerHash160 = HexLowerExact(script.data() + 34, 20);
    return true;
}

inline bool ParseCanonicalOracleLockV1ScriptHex(
    const std::string& scriptHex,
    CanonicalOracleLockV1Info& infoOut)
{
    std::vector<unsigned char> script;
    return DecodeScriptHexStrict(scriptHex, script) &&
           ParseCanonicalOracleLockV1Script(script, infoOut);
}

inline bool IsCanonicalStatefulKvV1Script(
    const std::vector<unsigned char>& script)
{
    return script.size() == 2 &&
           script[0] == static_cast<unsigned char>(OP_STORE) &&
           script[1] == static_cast<unsigned char>(OP_1);
}

enum class StatefulCreationFamily {
    None = 0,
    KvV1,
    VotingV1,
    TokenIssuerV1
};

inline bool DecodeU64LEExact(
    const std::vector<unsigned char>& value,
    std::uint64_t& out)
{
    if (value.size() != 8) return false;
    out = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(value[i]) << (8U * i);
    }
    return true;
}

inline bool IsAllZeroU64(const std::vector<unsigned char>& value)
{
    std::uint64_t n = 0;
    return DecodeU64LEExact(value, n) && n == 0;
}

inline const std::vector<unsigned char>* FindInitValue(
    const tru_contract_state_init::StateInitEnvelope& envelope,
    const std::string& key)
{
    for (const auto& entry : envelope.entries) {
        if (entry.first == key) return &entry.second;
    }
    return nullptr;
}

// canonical Voting V1 initialization schema.
//
// proposal     1..200 bytes
// numoptions   exactly 1 byte, value 2..10
// endtime      exactly 8-byte little-endian uint64, non-zero
// optionN      1..50 bytes for every N
// countN       exactly uint64 LE zero for every N
// totalvotes   exactly uint64 LE zero
//
// No extra initialization keys are accepted. Per-voter "voted:<hash160>"
// markers are added only by confirmed Voting V1 calls.
inline bool IsCanonicalVotingV1InitEnvelope(
    const tru_contract_state_init::StateInitEnvelope& envelope,
    std::string& reasonOut)
{
    reasonOut.clear();

    const auto* proposal = FindInitValue(envelope, "proposal");
    const auto* numOptions = FindInitValue(envelope, "numoptions");
    const auto* endTime = FindInitValue(envelope, "endtime");
    const auto* totalVotes = FindInitValue(envelope, "totalvotes");
    if (!proposal || !numOptions || !endTime || !totalVotes) {
        reasonOut = "Voting V1 init missing required proposal/numoptions/endtime/totalvotes";
        return false;
    }
    if (proposal->empty() || proposal->size() > 200) {
        reasonOut = "Voting V1 proposal must be 1..200 bytes";
        return false;
    }
    if (numOptions->size() != 1 ||
        (*numOptions)[0] < 2 || (*numOptions)[0] > 10) {
        reasonOut = "Voting V1 numoptions must be one byte in range 2..10";
        return false;
    }

    std::uint64_t end = 0;
    if (!DecodeU64LEExact(*endTime, end) || end == 0) {
        reasonOut = "Voting V1 endtime must be non-zero uint64 LE";
        return false;
    }
    if (!IsAllZeroU64(*totalVotes)) {
        reasonOut = "Voting V1 totalvotes must initialize to uint64 zero";
        return false;
    }

    const std::size_t n = (*numOptions)[0];
    const std::size_t expectedEntries = 4U + 2U * n;
    if (envelope.entries.size() != expectedEntries) {
        reasonOut = "Voting V1 init contains missing or extra keys";
        return false;
    }

    for (std::size_t i = 0; i < n; ++i) {
        const std::string optionKey = "option" + std::to_string(i);
        const std::string countKey = "count" + std::to_string(i);
        const auto* option = FindInitValue(envelope, optionKey);
        const auto* count = FindInitValue(envelope, countKey);
        if (!option || option->empty() || option->size() > 50) {
            reasonOut = "Voting V1 option text must be present and 1..50 bytes";
            return false;
        }
        if (!count || !IsAllZeroU64(*count)) {
            reasonOut = "Voting V1 option counts must initialize to uint64 zero";
            return false;
        }
    }
    return true;
}

// canonical Token Issuer V1 initialization schema.
//
// token_name      1..10 canonical ASCII bytes [A-Za-z0-9_-]
// exchange_rate   uint64 LE, > 0 tokens per TRU atom
// max_supply      uint64 LE; zero means uncapped
// total_issued    uint64 LE zero
//
// Buyer balance keys are not legal creation fields. A payable continuation
// adds/updates only balance:<40-lowercase-hash160> after checked arithmetic.
inline bool IsCanonicalTokenIssuerV1InitEnvelope(
    const tru_contract_state_init::StateInitEnvelope& envelope,
    std::string& reasonOut)
{
    reasonOut.clear();

    if (envelope.entries.size() != 4) {
        reasonOut = "Token Issuer V1 init must contain exactly four fields";
        return false;
    }

    // pin the family-level serialization order in addition to the
    // generic TRUSTATE sorted/unique requirement. This keeps Token Issuer V1
    // initialization single-encoding even if the generic envelope evolves.
    static constexpr std::array<const char*, 4> EXPECTED_INIT_KEYS = {
        "exchange_rate",
        "max_supply",
        "token_name",
        "total_issued"
    };
    for (std::size_t i = 0; i < EXPECTED_INIT_KEYS.size(); ++i) {
        if (envelope.entries[i].first != EXPECTED_INIT_KEYS[i]) {
            reasonOut =
                "Token Issuer V1 init fields are not in canonical key order";
            return false;
        }
    }

    const auto* tokenName = FindInitValue(envelope, "token_name");
    const auto* exchangeRate = FindInitValue(envelope, "exchange_rate");
    const auto* maxSupply = FindInitValue(envelope, "max_supply");
    const auto* totalIssued = FindInitValue(envelope, "total_issued");
    if (!tokenName || !exchangeRate || !maxSupply || !totalIssued) {
        reasonOut = "Token Issuer V1 init is missing a required field";
        return false;
    }

    if (tokenName->empty() || tokenName->size() > 10) {
        reasonOut = "Token Issuer V1 token_name must be 1..10 bytes";
        return false;
    }
    for (const unsigned char c : *tokenName) {
        const bool ok =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-';
        if (!ok) {
            reasonOut =
                "Token Issuer V1 token_name must use only A-Z a-z 0-9 _ -";
            return false;
        }
    }

    std::uint64_t rate = 0;
    std::uint64_t ignoredMax = 0;
    if (!DecodeU64LEExact(*exchangeRate, rate) || rate == 0) {
        reasonOut =
            "Token Issuer V1 exchange_rate must be non-zero uint64 LE";
        return false;
    }
    if (!DecodeU64LEExact(*maxSupply, ignoredMax)) {
        reasonOut = "Token Issuer V1 max_supply must be uint64 LE";
        return false;
    }
    if (!IsAllZeroU64(*totalIssued)) {
        reasonOut =
            "Token Issuer V1 total_issued must initialize to uint64 zero";
        return false;
    }

    return true;
}

struct StatefulCreationShapeResult {
    bool valid{true};
    bool hasCreation{false};
    bool hasCallCandidate{false};
    StatefulCreationFamily family{StatefulCreationFamily::None};
    size_t targetVout{size_t(-1)};
    size_t initEnvelopeVout{size_t(-1)};
    size_t accountedStateBytes{0};
    tru_contract_state_init::StateInitEnvelope initEnvelope;
    std::string reason;
};

template <typename TxLike>
inline StatefulCreationShapeResult ValidateStatefulCreationShape(
    const TxLike& tx)
{
    StatefulCreationShapeResult result;

    size_t statefulOutputs = 0;
    size_t initEnvelopes = 0;
    size_t callEnvelopes = 0;

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        std::vector<unsigned char> script;
        if (!DecodeScriptHexStrict(tx.vout[i].scriptPubKey, script)) {
            result.valid = false;
            result.reason = "malformed output script hex";
            return result;
        }

        if (!script.empty() &&
            script.front() == static_cast<unsigned char>(OP_RETURN)) {
            tru_contract_state_init::StateInitEnvelope envelope;
            if (tru_contract_state_init::ParseOpReturnScript(script, envelope)) {
                ++initEnvelopes;
                if (initEnvelopes > 1) {
                    result.valid = false;
                    result.reason = "exactly one TRUSTATE envelope is allowed";
                    return result;
                }
                if (tx.vout[i].amount != 0) {
                    result.valid = false;
                    result.reason = "TRUSTATE envelope output must have zero value";
                    return result;
                }
                result.initEnvelopeVout = i;
                result.initEnvelope = std::move(envelope);
            }

            tru_contract_call_envelope::StateCallEnvelope callEnvelope;
            if (tru_contract_call_envelope::ParseOpReturnScript(
                    script, callEnvelope)) {
                ++callEnvelopes;
                if (callEnvelopes > 1) {
                    result.valid = false;
                    result.reason = "exactly one TRUCALL envelope is allowed";
                    return result;
                }
                if (tx.vout[i].amount != 0) {
                    result.valid = false;
                    result.reason = "TRUCALL envelope output must have zero value";
                    return result;
                }
            }
            continue;
        }

        const auto scan = ScanStatefulContractScript(script);
        if (!scan.valid) {
            result.valid = false;
            result.reason = "malformed stateful locking script";
            return result;
        }
        if (!scan.usesStateDomain) continue;

        ++statefulOutputs;
        if (statefulOutputs > 1) {
            result.valid = false;
            result.reason = "one stateful contract creation per transaction";
            return result;
        }

        if (!IsCanonicalStatefulKvV1Script(script)) {
            result.valid = false;
            result.reason =
                "only canonical f751 state-anchor creation is activated";
            return result;
        }

        if (tx.vout[i].amount == 0) {
            result.valid = false;
            result.reason = "Stateful K/V V1 requires a non-zero state anchor";
            return result;
        }

        result.targetVout = i;
    }

    if (statefulOutputs == 0) {
        if (initEnvelopes != 0) {
            result.valid = false;
            result.reason = "orphan TRUSTATE envelope without stateful output";
        } else if (callEnvelopes != 0) {
            result.valid = false;
            result.reason = "orphan TRUCALL envelope without stateful output";
        }
        return result;
    }

    // a continuation call also creates one canonical f751 output,
    // but it is NOT a new state root. Presence of exactly one TRUCALL envelope
    // distinguishes that transaction-level shape. The input loop must still
    // prove that vin[0] spends the currently registered live state anchor.
    if (callEnvelopes != 0) {
        if (callEnvelopes != 1 || initEnvelopes != 0) {
            result.valid = false;
            result.reason = "stateful continuation requires one TRUCALL and no TRUSTATE";
            return result;
        }
        result.hasCallCandidate = true;
        return result;
    }

    // owner identity is bound to the sole funding input.
    // Multi-input creation is deliberately deferred so there is no ambiguity
    // about which signer owns the state root.
    if (tx.vin.size() != 1) {
        result.valid = false;
        result.reason =
            "Stateful K/V V1 creation requires exactly one creator funding input";
        return result;
    }

    if (initEnvelopes != 1) {
        result.valid = false;
        result.reason = "Stateful K/V V1 requires exactly one TRUSTATE envelope";
        return result;
    }

    if (result.initEnvelope.targetVout != result.targetVout) {
        result.valid = false;
        result.reason = "TRUSTATE targetVout does not match state anchor";
        return result;
    }

    if (result.initEnvelope.entries.size() == 1) {
        result.family = StatefulCreationFamily::KvV1;
    } else {
        std::string votingReason;
        if (IsCanonicalVotingV1InitEnvelope(
                result.initEnvelope, votingReason)) {
            result.family = StatefulCreationFamily::VotingV1;
        } else {
            std::string tokenReason;
            if (IsCanonicalTokenIssuerV1InitEnvelope(
                    result.initEnvelope, tokenReason)) {
                result.family = StatefulCreationFamily::TokenIssuerV1;
            } else {
                result.valid = false;
                result.reason =
                    "unsupported stateful creation schema; voting=" +
                    votingReason + "; token_issuer=" + tokenReason;
                return result;
            }
        }
    }

    tru_contract_state_limits::StateMap initialState;
    for (const auto& [key, value] : result.initEnvelope.entries) {
        initialState.emplace(key, value);
    }

    if (!tru_contract_state_limits::MeasureStateBytes(
            initialState, result.accountedStateBytes)) {
        result.valid = false;
        result.reason = "TRUSTATE initial state exceeds consensus limits";
        return result;
    }

    result.hasCreation = true;
    return result;
}

inline int HexNibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

inline bool ScriptHexEqual(const std::string& a, const std::string& b)
{
    if (a.size() != b.size() || (a.size() & 1U) != 0) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const int an = HexNibble(a[i]);
        const int bn = HexNibble(b[i]);
        if (an < 0 || bn < 0 || an != bn) return false;
    }
    return true;
}

inline bool IsCanonicalP2PKHScriptHex(const std::string& scriptHex)
{
    if (scriptHex.size() != 50) return false;
    for (const char ch : scriptHex) {
        if (HexNibble(ch) < 0) return false;
    }

    static const std::string prefix = "76a914";
    static const std::string suffix = "88ac";

    for (size_t i = 0; i < prefix.size(); ++i) {
        if (HexNibble(scriptHex[i]) != HexNibble(prefix[i])) return false;
    }
    const size_t suffixPos = scriptHex.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (HexNibble(scriptHex[suffixPos + i]) != HexNibble(suffix[i])) return false;
    }
    return true;
}

// canonical owner identity extracted from a standard P2PKH
// locking script. Persisting only the 20-byte hash160 (as lowercase hex) avoids
// Base58/network-display ambiguity while preserving exact ownership semantics.
inline bool ExtractCanonicalP2PKHHash160Hex(
    const std::string& scriptHex,
    std::string& hash160HexOut)
{
    hash160HexOut.clear();
    if (!IsCanonicalP2PKHScriptHex(scriptHex)) return false;

    hash160HexOut.reserve(40);
    for (size_t i = 6; i < 46; ++i) {
        const int nibble = HexNibble(scriptHex[i]);
        if (nibble < 0) return false;
        static constexpr char HEX[] = "0123456789abcdef";
        hash160HexOut.push_back(HEX[nibble]);
    }
    return hash160HexOut.size() == 40;
}

struct StatefulCallShapeResult {
    bool valid{false};
    size_t callerInputIndex{1};
    size_t continuationVout{size_t(-1)};
    size_t callEnvelopeVout{size_t(-1)};
    uint64_t callValue{0};
    std::string logicalKey;
    std::vector<unsigned char> value;
    tru_contract_call_envelope::StateCallEnvelope callEnvelope;
    std::string reason;
};

template <typename TxLike>
inline StatefulCallShapeResult ValidateStatefulCallShape(
    const TxLike& tx,
    size_t statefulInputIndex,
    const std::string& lockingScriptHex,
    uint64_t lockedAmount)
{
    StatefulCallShapeResult result;

    if (statefulInputIndex != 0) {
        result.reason = "state-anchor must be vin[0]";
        return result;
    }

    if (tx.vin.size() != 2) {
        result.reason = "stateful V1 call requires exactly two inputs";
        return result;
    }

    if (tx.vin[0].txid == tx.vin[1].txid &&
        tx.vin[0].vout == tx.vin[1].vout) {
        result.reason = "caller input duplicates state-anchor input";
        return result;
    }

    std::vector<unsigned char> lockingScript;
    if (!DecodeScriptHexStrict(lockingScriptHex, lockingScript) ||
        !IsCanonicalStatefulKvV1Script(lockingScript)) {
        result.reason = "only canonical Stateful K/V V1 continuation calls are activated";
        return result;
    }

    if (!DecodeStatefulKvV1UnlockScript(
            tx.vin[0].scriptSig, result.logicalKey, result.value)) {
        result.reason = "Stateful K/V V1 vin[0] must contain exactly two canonical pushes: key, value";
        return result;
    }

    size_t matches = 0;
    size_t matchIndex = size_t(-1);
    uint64_t continuationAmount = 0;
    size_t callEnvelopes = 0;

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (ScriptHexEqual(tx.vout[i].scriptPubKey, lockingScriptHex)) {
            ++matches;
            matchIndex = i;
            continuationAmount = tx.vout[i].amount;
        }

        std::vector<unsigned char> outputScript;
        if (!DecodeScriptHexStrict(tx.vout[i].scriptPubKey, outputScript)) {
            result.reason = "malformed output script hex in stateful call";
            return result;
        }
        if (outputScript.empty() ||
            outputScript.front() != static_cast<unsigned char>(OP_RETURN)) {
            continue;
        }

        tru_contract_call_envelope::StateCallEnvelope envelope;
        if (!tru_contract_call_envelope::ParseOpReturnScript(
                outputScript, envelope)) {
            continue;
        }

        ++callEnvelopes;
        if (callEnvelopes > 1) {
            result.reason = "stateful V1 call requires exactly one TRUCALL envelope";
            return result;
        }
        if (tx.vout[i].amount != 0) {
            result.reason = "TRUCALL envelope output must have zero value";
            return result;
        }
        result.callEnvelopeVout = i;
        result.callEnvelope = envelope;
    }

    if (matches != 1) {
        result.reason = "stateful V1 call requires exactly one continuation output";
        return result;
    }

    // structural economic-call-value rule. No activated V1
    // continuation may reduce its state anchor. Family execution decides whether
    // the exact delta must be zero (K/V, Voting) or positive (Token Issuer).
    if (continuationAmount < lockedAmount) {
        result.reason = "stateful V1 continuation cannot decrease anchor amount";
        return result;
    }

    if (callEnvelopes != 1) {
        result.reason = "stateful V1 call requires exactly one TRUCALL envelope";
        return result;
    }
    if (result.callEnvelope.targetInput != 0) {
        result.reason = "TRUCALL targetInput must be vin[0]";
        return result;
    }
    if (result.callEnvelope.continuationVout != matchIndex) {
        result.reason = "TRUCALL continuationVout does not match continuation output";
        return result;
    }

    std::array<unsigned char, 32> expectedHash{};
    if (!ComputeUnlockScriptSha256(tx.vin[0].scriptSig, expectedHash) ||
        expectedHash != result.callEnvelope.unlockScriptSha256) {
        result.reason = "TRUCALL unlockScriptSha256 does not bind vin[0].scriptSig";
        return result;
    }

    result.valid = true;
    result.continuationVout = matchIndex;
    result.callValue = continuationAmount - lockedAmount;
    return result;
}

} // namespace tru_contract_call
