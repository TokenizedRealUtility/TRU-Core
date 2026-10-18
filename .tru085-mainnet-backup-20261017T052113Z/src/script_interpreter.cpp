#include "script_interpreter.h"
#include "tru_limits.h"  // TRU Security Patch 12A resource ceilings
#include "opcodes.h"
#include "logging.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <sstream>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <cstring>
#include "tx.h"
#include "address_helpers.h"
#include "tokens.h"
#include "utils.h"
#include "mempool.h"
#include <openssl/sha.h> // For SHA3
//#include <blake2.h>// For BLAKE2b
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/evp.h> // For SHA3
#include "crypto_ecdsa.h"
#include "blockchain.h"
#include "master_bridge.h"
#include <openssl/rand.h>
#include <openssl/ripemd.h>
#include "contract_storage.h"
#include "contract_call_policy.h"  // stateful creation activation gate
#include "contract_state_limits.h" // consensus state resource bounds
#include "contract_state_lineage.h" // canonical state-domain identity
#include <mutex>
//==================================================================
// Helper function for SHA3-256 hashing
//==================================================================
std::vector<unsigned char> computeSHA3(const std::vector<unsigned char>& input) {
    Logger::log("[computeSHA3] Computing SHA3-256 for input size=" + std::to_string(input.size()));
    unsigned char hash[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx || !EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr) ||
        !EVP_DigestUpdate(mdctx, input.data(), input.size()) ||
        !EVP_DigestFinal_ex(mdctx, hash, nullptr)) {
        Logger::log("[computeSHA3] ERROR: SHA3 computation failed");
        EVP_MD_CTX_free(mdctx);
        return std::vector<unsigned char>();
    }
    EVP_MD_CTX_free(mdctx);
    return std::vector<unsigned char>(hash, hash + 32);
}
//==================================================================
// Helper function for BLAKE2b-256 hashing
//==================================================================
std::vector<unsigned char> computeBlake2b(const std::vector<unsigned char>& input) {
    Logger::log("[computeBlake2b] Computing BLAKE2b-256 for input size=" + std::to_string(input.size()));
    unsigned char hash[32];
    if (crypto_generichash_blake2b(hash, 32, input.data(), input.size(), nullptr, 0) != 0) {
        Logger::log("[computeBlake2b] ERROR: BLAKE2b computation failed");
        return std::vector<unsigned char>();
    }
    return std::vector<unsigned char>(hash, hash + 32);
}
//==================================================================
// external/off-chain data is never a consensus input.
// OP_EXTERNALDATA therefore fails closed unless a future protocol defines a
// deterministic, authenticated representation. AI inference remains outside
// Proof-of-Work consensus and is anchored separately by ordinary transactions.
//==================================================================

//============================================================
//   Deterministic on-chain state for OP_CHAINSTATECHECK
//   Only values identical on every node at a given height.
//============================================================
static std::vector<unsigned char> u64le(uint64_t v) {
    std::vector<unsigned char> out(8);
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    return out;
}

// TRU numeric VM convention for unsigned arithmetic:
// numeric stack items are interpreted as 0..8 byte little-endian uint64 values.
// Arithmetic results are emitted as canonical 8-byte little-endian values.
static bool decodeU64LE(const std::vector<unsigned char>& bytes, uint64_t& out) {
    if (bytes.size() > sizeof(uint64_t)) return false;
    out = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        out |= (static_cast<uint64_t>(bytes[i]) << (8 * i));
    }
    return true;
}

std::vector<unsigned char> chainStateDeterministic(const std::string& key,
                                                   const ScriptExecutionContext& ctx) {
    const Blockchain* chain = static_cast<const Blockchain*>(ctx.chainCtx);
    if (!chain) {
        // No chain context (simulation / mempool) -> caller fails closed.
        return {};
    }
    // execHeight is an explicit execution-context field. Height 0
    // is genesis and must never be mistaken for "unset" and replaced by the
    // node's live tip. Every live chain-backed execution path sets execHeight.
    const uint64_t h = static_cast<uint64_t>(ctx.execHeight);

    if (key == "block_height") {
        return u64le(h);
    }
    if (key == "total_supply" || key == "total_issued") {
        // Patch 14B/14B1: derive issued supply from the explicit execution
        // height, never from mutable live-tip metadata. Semantics are inclusive:
        // total_supply at height H includes the subsidy assigned through block H.
        // TRU genesis is height 1; each 210,000-block era halves the 50-TRU subsidy.
        uint64_t remaining = h;
        uint64_t reward = 50ULL * 100000000ULL;
        uint64_t total = 0;
        static constexpr uint64_t HALVING_INTERVAL = 210000ULL;
        while (remaining != 0 && reward != 0) {
            const uint64_t blocks = std::min(remaining, HALVING_INTERVAL);
            if (blocks > UINT64_MAX / reward) return {};
            const uint64_t eraIssued = blocks * reward;
            if (total > UINT64_MAX - eraIssued) return {};
            total += eraIssued;
            remaining -= blocks;
            reward >>= 1;
        }
        return u64le(total);
    }
    if (key == "block_reward" || key == "subsidy") {
        return u64le(chain->calculateSubsidy((int)h));
    }
    // Unknown / non-deterministic key -> empty (caller fails closed).
    Logger::log("[chainStateDeterministic] unsupported key=" + key);
    return {};
}

//============================================================
// canonical deterministic Oracle Feed V1.
//
// Consensus MUST NOT fetch HTTP/API/AI/local-config data during script
// execution. Oracle Feed V1 therefore exposes only values derived from the
// explicit consensus execution context. Every value is canonical 8-byte
// little-endian uint64 and unknown keys fail closed.
//
// Canonical keys (no aliases):
//   chain:block_height
//   chain:total_supply
//   chain:block_reward
//============================================================
static std::vector<unsigned char> oracleFeedDeterministic(
    const std::string& key,
    const ScriptExecutionContext& ctx)
{
    if (key == "chain:block_height")
        return chainStateDeterministic("block_height", ctx);
    if (key == "chain:total_supply")
        return chainStateDeterministic("total_supply", ctx);
    if (key == "chain:block_reward")
        return chainStateDeterministic("block_reward", ctx);

    Logger::log("[oracleFeedDeterministic] unsupported/non-consensus key=" + key);
    return {};
}

//============================================================
//		Helper functions for NOVO / GLOBALBOOST
//============================================================
static inline bool consumeGas(ScriptExecutionContext& ctx, uint64_t amount) {
    // overflow guard
    if (UINT64_MAX - ctx.gasUsed < amount) {
        Logger::log("[gas] overflow while adding gas");
        return false;
    }
    const uint64_t newUsed = ctx.gasUsed + amount;

    if (newUsed > ctx.gasLimit) {
        Logger::log("[gas] out of gas: requested " + std::to_string(amount) +
                    ", used " + std::to_string(ctx.gasUsed) +
                    ", limit " + std::to_string(ctx.gasLimit));
        return false;
    }

    ctx.gasUsed = newUsed;
    return true;
}

// TRU Smart Contract Patch 11D-R1 — authoritative opcode support policy.
//
// Script validity is path-independent: every opcode byte must be supported
// even when it appears inside a branch that will not execute. Direct pushes
// (0x01..0x4b) and PUSHDATA opcodes are supported as data encodings.
//
// TRU arithmetic is unsigned-only at genesis. OP_1NEGATE is therefore
// intentionally unsupported rather than being misread as uint64 value 255.
// OP_RESERVED is also intentionally unsupported everywhere in a script.
// Reserved upgrade NOPs 0xbb..0xc2 are supported consensus no-ops.
static bool IsSupportedOpcode(unsigned char opcode)
{
    if (opcode >= 0x01 && opcode <= 0x4b) return true;

    switch (opcode) {
        // Push/data encodings and small integers.
        case OP_0:
        case OP_PUSHDATA1:
        case OP_PUSHDATA2:
        case OP_PUSHDATA4:
        case OP_1: case OP_2: case OP_3: case OP_4:
        case OP_5: case OP_6: case OP_7: case OP_8:
        case OP_9: case OP_10: case OP_11: case OP_12:
        case OP_13: case OP_14: case OP_15: case OP_16:

        // Flow control.
        case OP_NOP:
        case OP_IF:
        case OP_NOTIF:
        case OP_ELSE:
        case OP_ENDIF:
        case OP_VERIFY:
        case OP_RETURN:
        case OP_CHECKLOCKTIMEVERIFY:

        // Stack / splice.
        case OP_2DUP:
        case OP_DROP:
        case OP_DUP:
        case OP_NIP:
        case OP_OVER:
        case OP_SWAP:
        case OP_CAT:
        case OP_LEFT:
        case OP_SIZE:

        // Equality / unsigned arithmetic.
        case OP_EQUAL:
        case OP_EQUALVERIFY:
        case OP_ADD:
        case OP_MUL:
        case OP_LESSTHAN:
        case OP_GREATERTHAN:
        case OP_LESSTHANOREQUAL:
        case OP_GREATERTHANOREQUAL:

        // Crypto / signatures.
        case OP_HASH160:
        case OP_HASH256:
        case OP_CHECKSIG:
        case OP_CHECKSIGVERIFY:
        case OP_CHECKMULTISIG:
        case OP_CHECKMULTISIGVERIFY:

        // TRU contract opcodes.
        // OP_MINT_TOKEN remains byte-reserved but unsupported.
        // Token Issuer V1 uses the checked family transition and economic
        // continuation delta instead of the legacy output-value opcode path.
        case OP_BLOCKTIME:
        case OP_EXTERNALDATA:
        case OP_DATAFEED:
        case OP_DELEGATECHECK:
        case OP_CHAINSTATECHECK:
        case OP_HASHBLAKE2B:
        case OP_SHA3:
        case OP_STORE:
        case OP_LOAD:
        case OP_CALLER:
        case OP_CONTRACT_ADDR:
        case OP_GAS:
        case OP_HALT:
        case OP_REVERT:
        case OP_OUTPUTAMOUNT:

        // legacy bridge containment.
        //
        // OP_NOVO_* / OP_BSTY_* are intentionally NOT supported at genesis.
        // Their legacy implementations generate fresh random key material during
        // script execution and write it into contract state, which cannot be made
        // consensus-persistent deterministically. The byte assignments remain
        // reserved for the redesigned BTC / GlobalBoost-Y bridge framework, but
        // creation, relay, and consensus preflight must reject them until that
        // deterministic framework is activated.

        // Genesis-reserved upgrade NOP space.
        case OP_UPGRADE_NOP1:
        case OP_UPGRADE_NOP2:
        case OP_UPGRADE_NOP3:
        case OP_UPGRADE_NOP4:
        case OP_UPGRADE_NOP5:
        case OP_UPGRADE_NOP6:
        case OP_UPGRADE_NOP7:
        case OP_UPGRADE_NOP8:
            return true;

        // Deliberately unsupported: OP_1NEGATE, OP_RESERVED, OP_SUBSTR,
        // unimplemented legacy opcodes, and all unknown/unassigned bytes.
        default:
            return false;
    }
}

// TRU Security Patch 12A ------------------------------------------------------
// Deterministic parser/resource accounting shared by mempool + consensus.
bool AnalyzeScriptResources(const std::vector<unsigned char>& script,
                            ScriptResourceMetrics& metrics)
{
    metrics = {};
    if (script.size() > tru_limits::MAX_SCRIPT_BYTES) {
        Logger::log("[AnalyzeScriptResources] script exceeds MAX_SCRIPT_BYTES");
        return false;
    }

    size_t pc = 0;
    while (pc < script.size()) {
        const unsigned char opcode = script[pc++];
        size_t pushLen = 0;
        bool isPush = false;

        if (opcode > OP_0 && opcode <= 0x4B) {
            pushLen = opcode;
            isPush = true;
        } else if (opcode == OP_PUSHDATA1) {
            if (pc + 1 > script.size()) return false;
            pushLen = script[pc++];
            isPush = true;
        } else if (opcode == OP_PUSHDATA2) {
            if (pc + 2 > script.size()) return false;
            pushLen = static_cast<size_t>(script[pc]) |
                      (static_cast<size_t>(script[pc + 1]) << 8);
            pc += 2;
            isPush = true;
        } else if (opcode == OP_PUSHDATA4) {
            if (pc + 4 > script.size()) return false;
            const uint64_t len =
                static_cast<uint64_t>(script[pc]) |
                (static_cast<uint64_t>(script[pc + 1]) << 8) |
                (static_cast<uint64_t>(script[pc + 2]) << 16) |
                (static_cast<uint64_t>(script[pc + 3]) << 24);
            pc += 4;
            if (len > static_cast<uint64_t>(script.size() - pc)) return false;
            pushLen = static_cast<size_t>(len);
            isPush = true;
        }

        if (isPush) {
            if (pushLen > script.size() - pc) return false;
            pc += pushLen;
            continue;
        }

        // TRU Smart Contract Patch 11D-R1 — path-independent opcode validity.
        // AnalyzeScriptResources scans every opcode byte regardless of branch
        // execution, so unsupported opcodes are invalid even in dead branches.
        if (!IsSupportedOpcode(opcode)) {
            Logger::log("[AnalyzeScriptResources] unsupported opcode byte=" +
                        std::to_string(static_cast<unsigned int>(opcode)));
            return false;
        }

        if (metrics.opCount >= tru_limits::MAX_SCRIPT_OPS) {
            Logger::log("[AnalyzeScriptResources] script opcode limit exceeded");
            return false;
        }
        ++metrics.opCount;

        uint64_t sigCost = 0;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY) {
            sigCost = 1;
        } else if (opcode == OP_CHECKMULTISIG ||
                   opcode == OP_CHECKMULTISIGVERIFY) {
            sigCost = 20; // interpreter permits n <= 20
        }
        if (sigCost > UINT64_MAX - metrics.sigOpCost) return false;
        metrics.sigOpCost += sigCost;
    }
    return true;
}

static bool measureInitialStackBytes(
    const std::vector<std::vector<unsigned char>>& stack,
    size_t& totalBytes)
{
    // scan inherited stack exactly once.
    // Every later mutation is accounted incrementally in O(1).
    if (stack.size() > tru_limits::MAX_STACK_ITEMS) {
        Logger::log("[EvaluateScript] stack item-count limit exceeded");
        return false;
    }

    totalBytes = 0;
    for (const auto& item : stack) {
        if (item.size() > tru_limits::MAX_STACK_ITEM_BYTES) {
            Logger::log("[EvaluateScript] stack item byte limit exceeded");
            return false;
        }
        if (item.size() > tru_limits::MAX_STACK_BYTES - totalBytes) {
            Logger::log("[EvaluateScript] total stack byte limit exceeded");
            return false;
        }
        totalBytes += item.size();
    }
    return true;
}

// canonical per-contract state namespace.
// ctx.state always points at the state map for ctx.contractAddress, whose
// canonical identity is the locking outpoint "<txid>:<vout>". Therefore the
// inner map stores raw logical keys exactly once; never prefix them again.
static inline bool hasContractStateContext(const ScriptExecutionContext& ctx)
{
    // A state view is admissible only for a canonical current contract outpoint.
    return ctx.state != nullptr &&
           tru_contract_state::IsCanonicalContractOutpoint(ctx.contractAddress);
}

static inline bool statePut(ScriptExecutionContext& ctx,
                            const std::string& logicalKey,
                            const std::string& jsonStr)
{
    if (!hasContractStateContext(ctx)) return false;
    const std::vector<unsigned char> value(jsonStr.begin(), jsonStr.end());
    if (!tru_contract_state_limits::CanApplyStateWrite(
            *ctx.state, logicalKey, value)) {
        Logger::log("[statePut] ERROR: contract state resource limit exceeded");
        return false;
    }
    (*ctx.state)[logicalKey] = value;
    return true;
}

static inline bool stateGet(ScriptExecutionContext& ctx,
                            const std::string& logicalKey,
                            std::string& outJson)
{
    if (!hasContractStateContext(ctx) ||
        !tru_contract_state_limits::IsLogicalKeyAllowed(logicalKey)) {
        return false;
    }
    auto it = ctx.state->find(logicalKey);
    if (it == ctx.state->end()) return false;
    outJson.assign(it->second.begin(), it->second.end());
    return true;
}

static struct SodiumOnce {
    SodiumOnce() {
        const int rc = sodium_init();    // 0 or 1 on success; -1 on failure
        if (rc == -1) {
            // Prefer your logger if available
            Logger::log("[libsodium] ERROR: sodium_init failed");
            throw std::runtime_error("libsodium initialization failed");
        }
    }
} _sodiumOnce_;

// =========== includes you likely already have somewhere ===========
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>

#include <cassert>
#include <string>
#include <vector>
#include <algorithm>

// ======================================================
// Minimal helpers (hashing, Base58Check, Bech32 segwit)
// ======================================================
namespace tru_addr_local {

// --- SHA256 helper (local name to avoid conflicts) ---
static std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& v) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(v.data(), v.size(), out.data());
    return out;
}

// ----------------------- Base58Check -------------------
static const char* kB58Alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string b58check(uint8_t version, const std::vector<unsigned char>& payload) {
    // Build: [version][payload][4-byte checksum(SHA256d)]
    std::vector<unsigned char> data;
    data.reserve(1 + payload.size() + 4);
    data.push_back(version);
    data.insert(data.end(), payload.begin(), payload.end());

    auto c = sha256_bytes(sha256_bytes(data));        // checksum = first 4 bytes
    data.insert(data.end(), c.begin(), c.begin() + 4);

    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == 0) zeros++;

    // Big integer base58 encode (in-place division)
    std::vector<unsigned char> bn = data;
    std::string out;
    out.reserve(data.size() * 138 / 100 + 1);

    size_t start = zeros;
    while (start < bn.size()) {
        int carry = 0;
        for (size_t i = start; i < bn.size(); ++i) {
            int x = (int)bn[i] + carry * 256;
            bn[i] = (unsigned char)(x / 58);
            carry = x % 58;
        }
        out.push_back(kB58Alphabet[carry]);
        while (start < bn.size() && bn[start] == 0) start++;
    }

    for (size_t i = 0; i < zeros; ++i) out.push_back('1');
    std::reverse(out.begin(), out.end());
    return out;
}

// ----------------------- Bech32 ------------------------
static const char* kBech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod_local(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    static const uint32_t GEN[5] = {0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
    for (uint8_t v : values) {
        uint8_t b = (chk >> 25) & 0xff;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((b >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

static std::vector<uint8_t> bech32_hrp_expand_local(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size()*2 + 1);
    for (char c : hrp) ret.push_back((uint8_t)(c >> 5));
    ret.push_back(0);
    for (char c : hrp) ret.push_back((uint8_t)(c & 31));
    return ret;
}

static bool convert_bits_local(std::vector<uint8_t>& out, int outbits,
                               const std::vector<uint8_t>& in, int inbits,
                               bool pad = true) {
    uint32_t acc = 0;
    int bits = 0;
    uint32_t maxv = (1u << outbits) - 1u;
    for (uint8_t value : in) {
        if (value >> inbits) return false;
        acc = (acc << inbits) | value;
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad && bits) {
        out.push_back((acc << (outbits - bits)) & maxv);
    } else if (bits >= inbits || ((acc << (outbits - bits)) & maxv)) {
        return false;
    }
    return true;
}

static std::string bech32_encode_local(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = bech32_hrp_expand_local(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), {0,0,0,0,0,0}); // 6-char checksum placeholder
    uint32_t mod = bech32_polymod_local(values) ^ 1;
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; ++i) {
        checksum[5 - i] = (mod >> (5 * i)) & 31;
    }

    std::string out = hrp + "1";
    for (uint8_t v : data) out.push_back(kBech32Alphabet[v]);
    for (uint8_t v : checksum) out.push_back(kBech32Alphabet[v]);
    return out;
}

// Build segwit v0 P2WPKH with given HRP
static std::string segwit_v0_p2wpkh_bech32(const std::string& hrp,
                                           const std::vector<unsigned char>& pubkeyHash20) {
    std::vector<uint8_t> prog8(pubkeyHash20.begin(), pubkeyHash20.end());
    std::vector<uint8_t> prog5;
    if (!convert_bits_local(prog5, 5, prog8, 8, true)) return "";
    std::vector<uint8_t> payload;
    payload.push_back(0); // witness version 0
    payload.insert(payload.end(), prog5.begin(), prog5.end());
    return bech32_encode_local(hrp, payload);
}

// ------------------- secp256k1 keygen -----------------
static bool generate_secp256k1_keypair(std::vector<unsigned char>& priv32,
                                       std::vector<unsigned char>& pub33) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return false;

    if (EC_KEY_generate_key(key) != 1) { EC_KEY_free(key); return false; }
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

    const BIGNUM* bn = EC_KEY_get0_private_key(key);
    if (!bn) { EC_KEY_free(key); return false; }
    priv32.resize(32);
    if (BN_bn2binpad(bn, priv32.data(), 32) != 32) { EC_KEY_free(key); return false; }

    int len = i2o_ECPublicKey(key, nullptr);
    if (len <= 0) { EC_KEY_free(key); return false; }
    std::vector<unsigned char> tmp(len);
    unsigned char* p = tmp.data();
    if (i2o_ECPublicKey(key, &p) != len) { EC_KEY_free(key); return false; }

    if (tmp.size() != 33 || (tmp[0] != 0x02 && tmp[0] != 0x03)) {
        EC_KEY_free(key);
        return false;
    }
    pub33 = std::move(tmp);
    EC_KEY_free(key);
    return true;
}

} // namespace tru_addr_local

// ======================================================
// NOVO Bridge (P2PKH Base58Check, version 0x00)
// ======================================================
namespace NOVOBridge {

bool generateNOVOAddress(ScriptExecutionContext& ctx,
                         std::vector<std::vector<unsigned char>>& stack)
{
    Logger::log("[NOVO] Generating deposit address (P2PKH Base58)");

    if (stack.empty()) {
        Logger::log("[NOVO] ERROR: No commitment on stack");
        return false;
    }
    auto commitment = stack.back(); stack.pop_back();
    if (commitment.size() != 32) {
        Logger::log("[NOVO] ERROR: Commitment must be 32 bytes");
        return false;
    }

    // 1) fresh keypair
    std::vector<unsigned char> priv32, pub33;
    if (!tru_addr_local::generate_secp256k1_keypair(priv32, pub33)) {
        Logger::log("[NOVO] ERROR: keypair generation failed");
        return false;
    }

    // 2) P2PKH hash of compressed pubkey
    auto h160 = ::hash160(pub33); // use the global util (already declared in utils.h)

    // 3) NOVO legacy mainnet version = 0x00
    std::string address = tru_addr_local::b58check(0x00, h160);

    // 4) Persist record bound to sender (consider encrypting privkey at rest)
    nlohmann::json rec = {
        {"commitment",  hexEncode(commitment)},
        {"pubkey_hex",  hexEncode(pub33)},
        {"privkey_hex", hexEncode(priv32)},
        {"addr",        address},
        {"format",      "p2pkh"},
        {"version",     0},
        {"timestamp",   ctx.blockTime},
        {"sender",      ctx.sender}
    };
    statePut(ctx, "novo:deposit:" + ctx.sender, rec.dump());

    // 5) Return address on stack
    stack.emplace_back(address.begin(), address.end());
    Logger::log("[NOVO] Address -> " + address);
    return true;
}

bool confirmNOVODeposit(ScriptExecutionContext& ctx,
                        std::vector<std::vector<unsigned char>>& stack)
{
    if (stack.size() < 2) {
        Logger::log("[NOVO] ERROR: Need amount(8b LE) and proof");
        return false;
    }
    auto proof = stack.back(); stack.pop_back();
    auto amountBytes = stack.back(); stack.pop_back();

    uint64_t amount = 0;
    for (size_t i = 0; i < std::min<size_t>(8, amountBytes.size()); ++i)
        amount |= (uint64_t)amountBytes[i] << (8 * i);

    std::string depJson; std::string addr;
    if (stateGet(ctx, "novo:deposit:" + ctx.sender, depJson)) {
        try { addr = nlohmann::json::parse(depJson).value("addr", ""); } catch (...) {}
    }

    nlohmann::json dep = {
        {"addr",       addr},
        {"proof_hex",  hexEncode(proof)},
        {"amount",     amount},
        {"confirmed",  true},
        {"timestamp",  ctx.blockTime},
        {"sender",     ctx.sender}
    };
    statePut(ctx, "novo:confirm:" + ctx.sender, dep.dump());

    stack.push_back(std::vector<unsigned char>{0x01});
    return true;
}

bool redeemNOVO(ScriptExecutionContext& ctx,
                std::vector<std::vector<unsigned char>>& stack)
{
    if (stack.empty()) {
        Logger::log("[NOVO] ERROR: Need secret on stack");
        return false;
    }
    auto secret = stack.back(); stack.pop_back();

    nlohmann::json red = {
        {"secret_hex", hexEncode(secret)},
        {"redeemed",   true},
        {"timestamp",  ctx.blockTime},
        {"sender",     ctx.sender}
    };
    statePut(ctx, "novo:redeem:" + ctx.sender, red.dump());

    // Keep production behavior: do not leak privkey back out
    stack.push_back(std::vector<unsigned char>{});
    return true;
}

bool verifyNOVO(ScriptExecutionContext&, std::vector<std::vector<unsigned char>>& stack)
{
    stack.push_back(stack.empty() ? std::vector<unsigned char>{0x00}
                                  : std::vector<unsigned char>{0x01});
    return true;
}

} // namespace NOVOBridge

// ======================================================
// BSTY Bridge (Bech32 P2WPKH, HRP = "gb")
// ======================================================
namespace BSTYBridge {

bool generateBSTYAddress(ScriptExecutionContext& ctx,
                         std::vector<std::vector<unsigned char>>& stack)
{
    Logger::log("[BSTY] Generating deposit address (P2WPKH Bech32 gb1...)");

    if (stack.empty()) {
        Logger::log("[BSTY] ERROR: No commitment on stack");
        return false;
    }
    auto commitment = stack.back(); stack.pop_back();
    if (commitment.size() != 32) {
        Logger::log("[BSTY] ERROR: Commitment must be 32 bytes");
        return false;
    }

    std::vector<unsigned char> priv32, pub33;
    if (!tru_addr_local::generate_secp256k1_keypair(priv32, pub33)) {
        Logger::log("[BSTY] ERROR: keypair generation failed");
        return false;
    }

    auto h160 = ::hash160(pub33);
    std::string address = tru_addr_local::segwit_v0_p2wpkh_bech32("gb", h160);
    if (address.empty()) {
        Logger::log("[BSTY] ERROR: bech32 encode failed");
        return false;
    }

    nlohmann::json rec = {
        {"commitment",  hexEncode(commitment)},
        {"pubkey_hex",  hexEncode(pub33)},
        {"privkey_hex", hexEncode(priv32)},
        {"addr",        address},
        {"format",      "p2wpkh"},
        {"hrp",         "gb"},
        {"timestamp",   ctx.blockTime},
        {"sender",      ctx.sender}
    };
    statePut(ctx, "bsty:deposit:" + ctx.sender, rec.dump());

    stack.emplace_back(address.begin(), address.end());
    Logger::log("[BSTY] Address -> " + address);
    return true;
}

bool confirmBSTYDeposit(ScriptExecutionContext& ctx,
                        std::vector<std::vector<unsigned char>>& stack)
{
    if (stack.size() < 2) {
        Logger::log("[BSTY] ERROR: Need amount(8b LE) and proof");
        return false;
    }
    auto proof = stack.back(); stack.pop_back();
    auto amountBytes = stack.back(); stack.pop_back();

    uint64_t amount = 0;
    for (size_t i = 0; i < std::min<size_t>(8, amountBytes.size()); ++i)
        amount |= (uint64_t)amountBytes[i] << (8 * i);

    std::string depJson; std::string addr;
    if (stateGet(ctx, "bsty:deposit:" + ctx.sender, depJson)) {
        try { addr = nlohmann::json::parse(depJson).value("addr", ""); } catch (...) {}
    }

    nlohmann::json dep = {
        {"addr",       addr},
        {"proof_hex",  hexEncode(proof)},
        {"amount",     amount},
        {"confirmed",  true},
        {"timestamp",  ctx.blockTime},
        {"sender",     ctx.sender}
    };
    statePut(ctx, "bsty:confirm:" + ctx.sender, dep.dump());

    stack.push_back(std::vector<unsigned char>{0x01});
    return true;
}

bool redeemBSTY(ScriptExecutionContext& ctx,
                std::vector<std::vector<unsigned char>>& stack)
{
    if (stack.empty()) {
        Logger::log("[BSTY] ERROR: Need secret on stack");
        return false;
    }
    auto secret = stack.back(); stack.pop_back();

    nlohmann::json red = {
        {"secret_hex", hexEncode(secret)},
        {"redeemed",   true},
        {"timestamp",  ctx.blockTime},
        {"sender",     ctx.sender}
    };
    statePut(ctx, "bsty:redeem:" + ctx.sender, red.dump());

    // Production: do not leak privkey
    stack.push_back(std::vector<unsigned char>{});
    return true;
}

bool verifyBSTY(ScriptExecutionContext&, std::vector<std::vector<unsigned char>>& stack)
{
    stack.push_back(stack.empty() ? std::vector<unsigned char>{0x00}
                                  : std::vector<unsigned char>{0x01});
    return true;
}

} // namespace BSTYBridge

// --------------------------------------------------------------------
// Helper: toUpper
// --------------------------------------------------------------------
static std::string toUpper(const std::string &s)
{
    std::string r;
    r.reserve(s.size());
    for (char c : s) {
        r.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return r;
}


//==================================================================
// ScriptExecutionContext constructor + default lambdas
//==================================================================
ScriptExecutionContext::ScriptExecutionContext(uint64_t gasLimit, const Transaction* transaction, uint32_t currentBlockTime)
    : blockTime(currentBlockTime), medianTimePast(0), tx(transaction), inputIndex(0), scriptPubKey(nullptr),
      sender(""), outputIndex(size_t(-1)), state(nullptr), chainCtx(nullptr), execHeight(0),
      gasLimit(gasLimit), gasUsed(0), contractAddress(""), execStack(1, true)
{
    if (this->gasLimit == 0) {
        Logger::log("[ScriptExecutionContext] WARNING: Gas limit set to 0, resetting to default 1000000");
        this->gasLimit = 1000000;
    }

    signatureCheckFunc = [](const std::vector<unsigned char> &pubkey,
                            const std::vector<unsigned char> &signature,
                            const std::string &message)
    {
        try
        {
            if (signature.size() < 2)
            {
                Logger::log("[signatureCheckFunc] ERROR: Signature too short");
                return false;
            }

            // TRU currently supports SIGHASH_ALL only.
            if (signature.back() != 0x01)
            {
                Logger::log(
                    "[signatureCheckFunc] ERROR: Unsupported sighash type: " +
                    std::to_string(signature.back()));
                return false;
            }

            std::vector<unsigned char> messageBytes(message.begin(), message.end());

            if (messageBytes.size() != 32) {
                Logger::log("[signatureCheckFunc] ERROR: Invalid sighash length: " + std::to_string(messageBytes.size()) + ", expected 32");
                Logger::log("[signatureCheckFunc] Sighash hex: " + hexEncode(messageBytes));
                return false;
            }

            const std::vector<unsigned char> derSignature(
                signature.begin(), signature.end() - 1);
            const std::string binaryMessage(
                messageBytes.begin(), messageBytes.end());

            bool result = ECDSAKey::verifyCanonicalTransactionSignature(
                pubkey, binaryMessage, derSignature);
            if (!result)
            {
                Logger::log("[signatureCheckFunc] Signature verification failed");
                Logger::log("[signatureCheckFunc] Public key: " + hexEncode(pubkey));
                Logger::log("[signatureCheckFunc] DER signature: " + hexEncode(derSignature));
                Logger::log("[signatureCheckFunc] Sighash: " + hexEncode(messageBytes));
            }
            else
            {
                Logger::log("[signatureCheckFunc] Signature verification successful");
            }
            return result;
        }
        catch (const std::exception &e)
        {
            Logger::log("[signatureCheckFunc] ERROR: " + std::string(e.what()));
            return false;
        }
    };

    // OP_DATAFEED is consensus-owned and is resolved directly from
    // ctx.chainCtx/ctx.execHeight; no callback can substitute local data.

    delegateCheckFunc = [](const std::vector<unsigned char>& sig) {
        Logger::log("[ScriptExecutionContext] TODO: Implement delegateCheckFunc");
        return false;
    };

    chainStateFunc = []() {
        Logger::log("[ScriptExecutionContext] chainStateFunc called, but not used directly in OP_CHAINSTATECHECK");
        return std::vector<unsigned char>(8, 0);
    };

    blake2bFunc = [](const std::vector<unsigned char>& in) {
        return computeBlake2b(in);
    };

    sha3Func = [](const std::vector<unsigned char>& in) {
        return computeSHA3(in);
    };

    // OP_EXTERNALDATA has no pluggable consensus callback.
}

//==================================================================
// 		    EvaluateScript Magic Script
//==================================================================

//==================================================================
// 		    EvaluateScript
//==================================================================
bool EvaluateScript(const std::vector<unsigned char>& script,
                    std::vector<std::vector<unsigned char>>& stack,
                    ScriptExecutionContext& ctx)
{

    ScriptResourceMetrics preflightMetrics;
    if (!AnalyzeScriptResources(script, preflightMetrics)) {
        Logger::log("[EvaluateScript] script resource preflight failed");
        return false;
    }

    // PATCH12A_V2_STACK_HELPERS_BEGIN
    size_t stackBytes = 0;
    if (!measureInitialStackBytes(stack, stackBytes)) return false;

    auto pushStack = [&](std::vector<unsigned char> item) -> bool {
        if (item.size() > tru_limits::MAX_STACK_ITEM_BYTES) {
            Logger::log("[EvaluateScript] stack item byte limit exceeded");
            return false;
        }
        if (stack.size() >= tru_limits::MAX_STACK_ITEMS) {
            Logger::log("[EvaluateScript] stack item-count limit exceeded");
            return false;
        }
        if (item.size() > tru_limits::MAX_STACK_BYTES - stackBytes) {
            Logger::log("[EvaluateScript] total stack byte limit exceeded");
            return false;
        }
        stackBytes += item.size();
        stack.push_back(std::move(item));
        return true;
    };

    auto popStack = [&]() -> std::vector<unsigned char> {
        if (stack.empty()) {
            throw std::runtime_error(
                "[EvaluateScript] internal stack invariant: pop on empty stack");
        }
        std::vector<unsigned char> item = std::move(stack.back());
        stackBytes -= item.size();
        stack.pop_back();
        return item;
    };

    auto dropStack = [&]() {
        if (stack.empty()) {
            throw std::runtime_error(
                "[EvaluateScript] internal stack invariant: drop on empty stack");
        }
        stackBytes -= stack.back().size();
        stack.pop_back();
    };

    auto replaceTop = [&](std::vector<unsigned char> item) -> bool {
        if (stack.empty()) {
            Logger::log(
                "[EvaluateScript] internal stack invariant: replaceTop on empty stack");
            return false;
        }
        if (item.size() > tru_limits::MAX_STACK_ITEM_BYTES) {
            Logger::log("[EvaluateScript] replacement stack item too large");
            return false;
        }
        const size_t oldBytes = stack.back().size();
        const size_t withoutOld = stackBytes - oldBytes;
        if (item.size() > tru_limits::MAX_STACK_BYTES - withoutOld) {
            Logger::log("[EvaluateScript] replacement exceeds total stack byte limit");
            return false;
        }
        stackBytes = withoutOld + item.size();
        stack.back() = std::move(item);
        return true;
    };

    auto eraseStackIndex = [&](size_t index) {
        if (index >= stack.size()) {
            throw std::runtime_error(
                "[EvaluateScript] internal stack invariant: erase index out of range");
        }
        stackBytes -= stack[index].size();
        stack.erase(stack.begin() + static_cast<std::ptrdiff_t>(index));
    };
    // PATCH12A_V2_STACK_HELPERS_END

    if (ctx.execStack.size() != 1 || !ctx.execStack.front()) {
        Logger::log(
            "[EvaluateScript] ERROR: invalid conditional execution state at entry");
        return false;
    }

    size_t pc = 0; // Program counter
    Logger::log("[EvaluateScript] Starting execution, script size=" + std::to_string(script.size()) +
                ", gasLimit=" + std::to_string(ctx.gasLimit));

    try {
        while (pc < script.size()) {
            if (!consumeGas(ctx, 1)) return false;

            unsigned char opcode = script[pc++];
            bool execute = !ctx.execStack.empty() && ctx.execStack.back();

            if (opcode == OP_IF || opcode == OP_NOTIF || opcode == OP_ELSE || opcode == OP_ENDIF) {
                switch (opcode) {
                    case OP_IF:
                    {
                        // In a dead parent branch, conditionals are parsed but
                        // MUST NOT consume the data stack. Push a cumulative
                        // false execution state so nested ELSE cannot escape
                        // the dead parent.
                        if (!execute) {
                            ctx.execStack.push_back(false);
                            if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                            Logger::log("[EvaluateScript] OP_IF: skipped in dead parent branch");
                            break;
                        }

                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_IF needs 1 item");
                            return false;
                        }
                        auto condition = popStack();
                        const bool condTrue =
                            !condition.empty() && condition[0] != 0;
                        ctx.execStack.push_back(condTrue);

                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log(
                            "[EvaluateScript] OP_IF: condition=" +
                            std::to_string(condTrue));
                        break;
                    }
                    case OP_NOTIF:
                    {
                        if (!execute) {
                            ctx.execStack.push_back(false);
                            if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                            Logger::log("[EvaluateScript] OP_NOTIF: skipped in dead parent branch");
                            break;
                        }

                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_NOTIF needs 1 item");
                            return false;
                        }
                        auto condition = popStack();
                        const bool condFalse =
                            condition.empty() || condition[0] == 0;
                        ctx.execStack.push_back(condFalse);

                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log(
                            "[EvaluateScript] OP_NOTIF: condition=" +
                            std::to_string(condFalse));
                        break;
                    }
                    case OP_ELSE:
                    {
                        if (ctx.execStack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_ELSE without OP_IF");
                            return false;
                        }

                        // execStack stores cumulative execution state. An ELSE
                        // can toggle only when its parent branch is executing.
                        // A nested ELSE inside a dead parent must remain dead.
                        const bool parentExecute =
                            ctx.execStack[ctx.execStack.size() - 2];
                        ctx.execStack.back() =
                            parentExecute && !ctx.execStack.back();

                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log(
                            "[EvaluateScript] OP_ELSE: parentExecute=" +
                            std::to_string(parentExecute) +
                            ", execute=" +
                            std::to_string(ctx.execStack.back()));
                        break;
                    }
                    case OP_ENDIF:
                    {
                        if (ctx.execStack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_ENDIF without OP_IF");
                            return false;
                        }
                        ctx.execStack.pop_back();
                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log("[EvaluateScript] OP_ENDIF");
                        break;
                    }
                }
            }
            else if (execute) {
                if (opcode > 0x00 && opcode <= 0x4B) {
                    unsigned int pushSize = opcode;
                    if (pc + pushSize > script.size()) {
                        Logger::log("[EvaluateScript] ERROR: small PUSHDATA out of bounds; need=" +
                                    std::to_string(pushSize) + ", have=" + std::to_string(script.size() - pc));
                        return false;
                    }
                    std::vector<unsigned char> data(script.begin() + pc, script.begin() + pc + pushSize);
                    if (!pushStack(data)) return false;
                    pc += pushSize;
                    if (!consumeGas(ctx, static_cast<uint64_t>(pushSize))) return false;
                    Logger::log("[EvaluateScript] Pushed " + std::to_string(pushSize) + " bytes");
                    continue;
                }

                // TRU SCRIPT CONSENSUS BOOLEAN ENCODING:
                // Boolean-producing opcodes MUST push exactly one byte:
                // false = 0x00, true = 0x01.
                // Boolean-consuming opcodes use the same truth test as OP_IF/OP_NOTIF:
                // empty or first byte 0x00 = false; first byte non-zero = true.
                switch (opcode) {
                    case OP_DUP:
                    if (stack.empty()) {
                        if (ctx.isSimulationMode()) {
                            Logger::log("[EvaluateScript] OP_DUP: Empty stack in simulation, pushing dummy item");
                            if (!pushStack(std::vector<unsigned char>(1, 0))) return false;
                        } else {
                            Logger::log("[EvaluateScript] ERROR: OP_DUP on empty stack");
                            return false;
                        }
                    } else {
                        if (!pushStack(stack.back())) return false;
                    }
                    if (!consumeGas(ctx, static_cast<uint64_t>(2))) return false;
                    Logger::log("[EvaluateScript] OP_DUP: Duplicated top item");
                    break;

                    case OP_PUSHDATA1:
                    {
                        if (pc + 1 > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA1 missing length byte");
                            return false;
                        }
                        unsigned char lenByte = script[pc++];
                        size_t length = static_cast<size_t>(lenByte);
                        if (pc + length > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA1 out of bounds; need=" +
                                        std::to_string(length) + ", have=" + std::to_string(script.size() - pc));
                            return false;
                        }
                        std::vector<unsigned char> data(script.begin() + pc, script.begin() + pc + length);
                        pc += length;
                        if (!pushStack(data)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(length))) return false;
                        Logger::log("[EvaluateScript] OP_PUSHDATA1: Pushed " + std::to_string(length) + " bytes");
                        break;
                    }
                    case OP_PUSHDATA2:
                    {
                        if (pc + 2 > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA2 missing 2 length bytes");
                            return false;
                        }
                        unsigned int lenLo = script[pc++];
                        unsigned int lenHi = script[pc++];
                        size_t length = (static_cast<size_t>(lenHi) << 8) | lenLo;
                        if (pc + length > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA2 out of bounds; need=" +
                                        std::to_string(length) + ", have=" + std::to_string(script.size() - pc));
                            return false;
                        }
                        std::vector<unsigned char> data(script.begin() + pc, script.begin() + pc + length);
                        pc += length;
                        if (!pushStack(data)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(length))) return false;
                        Logger::log("[EvaluateScript] OP_PUSHDATA2: Pushed " + std::to_string(length) + " bytes");
                        break;
                    }
                    case OP_PUSHDATA4:
                    {
                        if (pc + 4 > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA4 missing 4 length bytes");
                            return false;
                        }
                        unsigned int b0 = script[pc++];
                        unsigned int b1 = script[pc++];
                        unsigned int b2 = script[pc++];
                        unsigned int b3 = script[pc++];
                        size_t length = (static_cast<size_t>(b3) << 24) |
                                        (static_cast<size_t>(b2) << 16) |
                                        (static_cast<size_t>(b1) << 8) | b0;
                        if (pc + length > script.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA4 out of bounds; need=" +
                                        std::to_string(length) + ", have=" + std::to_string(script.size() - pc));
                            return false;
                        }
                        std::vector<unsigned char> data(script.begin() + pc, script.begin() + pc + length);
                        pc += length;
                        if (!pushStack(data)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(length))) return false;
                        Logger::log("[EvaluateScript] OP_PUSHDATA4: Pushed " + std::to_string(length) + " bytes");
                        break;
                    }

                    // OP_0 / OP_FALSE.
                    // Pushes the canonical empty vector. Under TRU truth semantics,
                    // an empty vector is false. OP_FALSE aliases OP_0 at 0x00.
                    case OP_0:
                    {
                        if (!pushStack(std::vector<unsigned char>())) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(1))) return false;
                        Logger::log("[EvaluateScript] OP_0: Pushed empty vector (false)");
                        break;
                    }

                    case OP_1: case OP_2: case OP_3: case OP_4: case OP_5:
                    case OP_6: case OP_7: case OP_8: case OP_9: case OP_10:
                    case OP_11: case OP_12: case OP_13: case OP_14: case OP_15:
                    case OP_16:
                    {
                        int val = (int)opcode - (int)OP_1 + 1;
                        if (!pushStack(std::vector<unsigned char>(1, (unsigned char)val))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(1))) return false;
                        Logger::log("[EvaluateScript] Pushed small int: " + std::to_string(val));
                        break;
                    }

                    // TRU Smart Contract Patch 11D-R1 — unsigned-only VM.
                    // OP_1NEGATE has no valid meaning under TRU's uint64 numeric
                    // convention. Preflight rejects it everywhere; this case is
                    // defense-in-depth if execution is ever reached directly.
                    case OP_1NEGATE:
                    {
                        Logger::log("[EvaluateScript] ERROR: OP_1NEGATE is unsupported in unsigned-only VM");
                        return false;
                    }

                    // OP_RESERVED is invalid.
                    // Defense-in-depth: execution fails immediately. Patch 11D will also
                    // reject OP_RESERVED during path-independent script preflight, including dead branches.
                    case OP_RESERVED:
                    {
                        Logger::log("[EvaluateScript] ERROR: OP_RESERVED is invalid");
                        return false;
                    }

                    case OP_NOP:
                    {
                        Logger::log("[EvaluateScript] OP_NOP: No effect");
                        break;
                    }

                    case OP_CHECKLOCKTIMEVERIFY: // 0xb1
                    {
                        if (stack.size() < 1) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY needs at least 1 stack item");
                            return false;
                        }

                        auto locktimeBytes = stack.back();
                        if (locktimeBytes.size() != 4) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY expects a 4-byte locktime");
                            return false;
                        }

                        // Convert the top stack item (4 bytes) to a uint32_t locktime value
                        uint32_t locktimeValue = (uint32_t)locktimeBytes[0] |
                                                 ((uint32_t)locktimeBytes[1] << 8) |
                                                 ((uint32_t)locktimeBytes[2] << 16) |
                                                 ((uint32_t)locktimeBytes[3] << 24);

                        if (!ctx.tx) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY requires transaction context");
                            return false;
                        }

                        // TRU Time Lock V1 is timestamp-only.
                        // Values below 500,000,000 are height-domain values in
                        // Bitcoin-style locktime semantics. TRU does not expose a
                        // height-lock family, so accepting them here would turn a
                        // custom CLTV script into a silent no-op. Fail closed.
                        static constexpr uint32_t TRU_CLTV_TIMESTAMP_THRESHOLD = 500000000U;
                        if (locktimeValue < TRU_CLTV_TIMESTAMP_THRESHOLD) {
                            Logger::log(
                                "[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY height-domain value is unsupported: " +
                                std::to_string(locktimeValue));
                            return false;
                        }

                        // BIP113-style clock discipline for TRU: use the median
                        // timestamp of the candidate's PARENT chain, not the
                        // candidate header timestamp and not local wall clock. A
                        // single miner therefore cannot move CLTV maturity forward
                        // by exploiting the allowed future-header drift window.
                        if (ctx.medianTimePast < locktimeValue) {
                            Logger::log(
                                "[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY failed: parent MTP=" +
                                std::to_string(ctx.medianTimePast) + " < " +
                                std::to_string(locktimeValue));
                            return false;
                        }

                        if (ctx.tx->lockTime < locktimeValue) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY failed: tx lockTime=" +
                                        std::to_string(ctx.tx->lockTime) + " < " + std::to_string(locktimeValue));
                            return false;
                        }

                        if (ctx.inputIndex >= ctx.tx->vin.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY input index out of range");
                            return false;
                        }
                        if (ctx.tx->vin[ctx.inputIndex].sequence == 0xffffffffU) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY requires non-final input sequence");
                            return false;
                        }

                        Logger::log("[EvaluateScript] OP_CHECKLOCKTIMEVERIFY passed: parent MTP=" +
                                    std::to_string(ctx.medianTimePast) +
                                    ", tx lockTime=" + std::to_string(ctx.tx->lockTime) +
                                    ", required=" + std::to_string(locktimeValue));
                        if (!consumeGas(ctx, static_cast<uint64_t>(10))) return false;
                        break;
                    }

/*				OLD CODE
                    case OP_CHECKLOCKTIMEVERIFY:
                    {
                        if (stack.size() < 1) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY needs 1 item");
                            return false;
                        }
                        auto locktimeBytes = stack.back();
                        if (locktimeBytes.size() != 4) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY expects 4-byte locktime");
                            return false;
                        }
                        uint32_t locktimeValue = (uint32_t)locktimeBytes[0] |
                                                 ((uint32_t)locktimeBytes[1] << 8) |
                                                 ((uint32_t)locktimeBytes[2] << 16) |
                                                 ((uint32_t)locktimeBytes[3] << 24);

                        if (!ctx.tx) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY requires transaction context");
                            return false;
                        }
                        if (ctx.tx->lockTime < locktimeValue) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKLOCKTIMEVERIFY failed: tx lockTime=" +
                                        std::to_string(ctx.tx->lockTime) + " < " + std::to_string(locktimeValue));
                            return false;
                        }
                        Logger::log("[EvaluateScript] OP_CHECKLOCKTIMEVERIFY: tx lockTime=" +
                                    std::to_string(ctx.tx->lockTime) + " >= " + std::to_string(locktimeValue));
                        if (!consumeGas(ctx, static_cast<uint64_t>(10))) return false;
                        break;
                    }
*/
                    case OP_RETURN:
                    {
                        Logger::log("[EvaluateScript] OP_RETURN: Ending script (success)");
                        return true;
                    }

                    case OP_DROP:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_DROP on empty stack");
                            return false;
                        }
                        dropStack();
                        if (!consumeGas(ctx, static_cast<uint64_t>(1))) return false;
                        Logger::log("[EvaluateScript] OP_DROP: Dropped top item");
                        break;
                    }

                    case OP_OVER:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_OVER needs at least 2 items");
                            return false;
                        }
                        auto second = stack[stack.size() - 2];
                        if (!pushStack(second)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(2))) return false;
                        Logger::log("[EvaluateScript] OP_OVER: Duplicated second item");
                        break;
                    }

                    // OP_ADD uint64 normalization
                    // Unsigned 64-bit little-endian addition with deterministic overflow failure.
                    case OP_ADD:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_ADD needs 2 items");
                            return false;
                        }

                        const auto rhsBytes = popStack();
                        const auto lhsBytes = popStack();

                        uint64_t lhs = 0;
                        uint64_t rhs = 0;
                        if (!decodeU64LE(lhsBytes, lhs) || !decodeU64LE(rhsBytes, rhs)) {
                            Logger::log("[EvaluateScript] ERROR: OP_ADD operands must be <= 8-byte little-endian integers");
                            return false;
                        }

                        if (rhs > UINT64_MAX - lhs) {
                            Logger::log("[EvaluateScript] ERROR: OP_ADD uint64 overflow");
                            return false;
                        }

                        const uint64_t sum = lhs + rhs;
                        if (!pushStack(u64le(sum)))
                            return false;

                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log("[EvaluateScript] OP_ADD: " +
                                    std::to_string(lhs) + " + " +
                                    std::to_string(rhs) + " = " +
                                    std::to_string(sum));
                        break;
                    }

                    // OP_MUL
                    // Unsigned 64-bit little-endian multiplication with deterministic overflow failure.
                    case OP_MUL:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_MUL needs 2 items");
                            return false;
                        }

                        const auto rhsBytes = popStack();
                        const auto lhsBytes = popStack();

                        uint64_t lhs = 0;
                        uint64_t rhs = 0;
                        if (!decodeU64LE(lhsBytes, lhs) || !decodeU64LE(rhsBytes, rhs)) {
                            Logger::log("[EvaluateScript] ERROR: OP_MUL operands must be <= 8-byte little-endian integers");
                            return false;
                        }

                        if (lhs != 0 && rhs > UINT64_MAX / lhs) {
                            Logger::log("[EvaluateScript] ERROR: OP_MUL uint64 overflow");
                            return false;
                        }

                        const uint64_t product = lhs * rhs;
                        if (!pushStack(u64le(product)))
                            return false;

                        if (!consumeGas(ctx, static_cast<uint64_t>(10)))
                            return false;

                        Logger::log("[EvaluateScript] OP_MUL: " +
                                    std::to_string(lhs) + " * " +
                                    std::to_string(rhs) + " = " +
                                    std::to_string(product));
                        break;
                    }

                    // OP_LESSTHAN
                    // Unsigned numeric comparison using the shared 0..8 byte little-endian uint64 convention.
                    // Stack order is [lhs, rhs] with rhs on top; result is canonical 0x01 / 0x00.
                    case OP_LESSTHAN:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_LESSTHAN needs 2 items");
                            return false;
                        }

                        const auto rhsBytes = popStack();
                        const auto lhsBytes = popStack();

                        uint64_t lhs = 0;
                        uint64_t rhs = 0;
                        if (!decodeU64LE(lhsBytes, lhs) || !decodeU64LE(rhsBytes, rhs)) {
                            Logger::log("[EvaluateScript] ERROR: OP_LESSTHAN operands must be <= 8-byte little-endian integers");
                            return false;
                        }

                        const bool result = lhs < rhs;
                        if (!pushStack(std::vector<unsigned char>(1, result ? 1 : 0)))
                            return false;

                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log("[EvaluateScript] OP_LESSTHAN: " +
                                    std::to_string(lhs) + " < " +
                                    std::to_string(rhs) + " => " +
                                    (result ? "true" : "false"));
                        break;
                    }

                    // OP_GREATERTHAN
                    // Unsigned numeric comparison using the shared 0..8 byte little-endian uint64 convention.
                    // Stack order is [lhs, rhs] with rhs on top; result is canonical 0x01 / 0x00.
                    case OP_GREATERTHAN:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_GREATERTHAN needs 2 items");
                            return false;
                        }

                        const auto rhsBytes = popStack();
                        const auto lhsBytes = popStack();

                        uint64_t lhs = 0;
                        uint64_t rhs = 0;
                        if (!decodeU64LE(lhsBytes, lhs) || !decodeU64LE(rhsBytes, rhs)) {
                            Logger::log("[EvaluateScript] ERROR: OP_GREATERTHAN operands must be <= 8-byte little-endian integers");
                            return false;
                        }

                        const bool result = lhs > rhs;
                        if (!pushStack(std::vector<unsigned char>(1, result ? 1 : 0)))
                            return false;

                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log("[EvaluateScript] OP_GREATERTHAN: " +
                                    std::to_string(lhs) + " > " +
                                    std::to_string(rhs) + " => " +
                                    (result ? "true" : "false"));
                        break;
                    }

                    // inclusive numeric comparisons.
                    // Same uint64 LE convention and [lhs,rhs] stack order as
                    // OP_LESSTHAN / OP_GREATERTHAN.
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: inclusive comparison needs 2 items");
                            return false;
                        }

                        const auto rhsBytes = popStack();
                        const auto lhsBytes = popStack();

                        uint64_t lhs = 0;
                        uint64_t rhs = 0;
                        if (!decodeU64LE(lhsBytes, lhs) || !decodeU64LE(rhsBytes, rhs)) {
                            Logger::log("[EvaluateScript] ERROR: inclusive comparison operands must be <= 8-byte little-endian integers");
                            return false;
                        }

                        const bool isLE = (opcode == OP_LESSTHANOREQUAL);
                        const bool result = isLE ? (lhs <= rhs) : (lhs >= rhs);
                        if (!pushStack(std::vector<unsigned char>(1, result ? 1 : 0)))
                            return false;

                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log(std::string("[EvaluateScript] ") +
                                    (isLE ? "OP_LESSTHANOREQUAL: " : "OP_GREATERTHANOREQUAL: ") +
                                    std::to_string(lhs) +
                                    (isLE ? " <= " : " >= ") +
                                    std::to_string(rhs) + " => " +
                                    (result ? "true" : "false"));
                        break;
                    }

                    // OP_VERIFY
                    // Pops one item and fails the script when it is false.
                    // Truth semantics intentionally match OP_IF/OP_NOTIF.
                    case OP_VERIFY:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_VERIFY needs 1 item");
                            return false;
                        }

                        const auto value = popStack();
                        const bool verified =
                            !value.empty() && value[0] != 0;

                        if (!verified) {
                            Logger::log("[EvaluateScript] OP_VERIFY failed");
                            return false;
                        }

                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log("[EvaluateScript] OP_VERIFY: success");
                        break;
                    }

                    // OP_EQUAL
                    // Pops the top two byte-vectors and pushes a canonical
                    // boolean result: 0x01 when equal, 0x00 when unequal.
                    case OP_EQUAL:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_EQUAL needs 2 items");
                            return false;
                        }

                        const auto a = popStack();
                        const auto b = popStack();
                        const bool equal = (a == b);

                        if (!pushStack(std::vector<unsigned char>(1, equal ? 1 : 0)))
                            return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(5)))
                            return false;

                        Logger::log(std::string("[EvaluateScript] OP_EQUAL: ") +
                                    (equal ? "equal" : "not equal"));
                        break;
                    }

                    case OP_EQUALVERIFY:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_EQUALVERIFY needs 2 items");
                            return false;
                        }
                        auto a = popStack();
                        auto b = popStack();
                        if (a != b) {
                            Logger::log("[EvaluateScript] OP_EQUALVERIFY failed: " +
                                        hexEncode(a) + " != " + hexEncode(b));
                            return false;
                        }
                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log("[EvaluateScript] OP_EQUALVERIFY: Hashes match");
                        break;
                    }

                    case OP_CHECKSIG:
                        if (stack.size() < 2)
                        {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKSIG needs 2 items");
                            return false;
                        }
                        if (ctx.isSimulationMode())
                        {
                            dropStack();
                            dropStack();
                            if (!pushStack(std::vector<unsigned char>(1, 1))) return false;
                            Logger::log("[EvaluateScript] OP_CHECKSIG: Simulation mode, assuming success");
                        }
                        else
                        {
                            if (!ctx.tx || !ctx.scriptPubKey)
                            {
                                Logger::log("[EvaluateScript] ERROR: OP_CHECKSIG context invalid");
                                return false;
                            }
                            auto pubkey = stack.back();
                            dropStack();
                            auto signature = stack.back();
                            dropStack();

                            // Strip SIGHASH_ALL byte from signature for ECDSA verification
                            std::string sighashBinary(ctx.sighash.begin(), ctx.sighash.end());
                            bool ok = ctx.signatureCheckFunc(pubkey, signature, sighashBinary);

                            if (!pushStack(std::vector<unsigned char>(1, ok ? 1 : 0))) return false;
                            if (!consumeGas(ctx, static_cast<uint64_t>(100))) return false;
                            Logger::log("[EvaluateScript] OP_CHECKSIG: pubkey=" + hexEncode(pubkey) +
                                        ", signature=" + hexEncode(signature) + ", result=" + std::to_string(ok));
                        }
                        break;

                    case OP_CHECKSIGVERIFY:
                    {
                        // FIX(critical): was stubbed to always succeed, so any script
                        // using OP_CHECKSIGVERIFY bypassed signature checking. Now it
                        // performs the same real verification as OP_CHECKSIG and
                        // fails the script (VERIFY semantics) on an invalid signature.
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKSIGVERIFY needs 2 items");
                            return false;
                        }
                        if (ctx.isSimulationMode()) {
                            // In simulation (no tx context) accept, as OP_CHECKSIG does.
                            dropStack();
                            dropStack();
                            if (!consumeGas(ctx, static_cast<uint64_t>(100))) return false;
                            Logger::log("[EvaluateScript] OP_CHECKSIGVERIFY: simulation, accepted");
                            break;
                        }
                        if (!ctx.tx || !ctx.scriptPubKey || !ctx.signatureCheckFunc) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKSIGVERIFY context invalid");
                            return false;
                        }
                        {
                            auto pubkey = popStack();
                            auto signature = popStack();
                            std::string sighashBinary(ctx.sighash.begin(), ctx.sighash.end());
                            bool ok = ctx.signatureCheckFunc(pubkey, signature, sighashBinary);
                            if (!consumeGas(ctx, static_cast<uint64_t>(100))) return false;
                            if (!ok) {
                                Logger::log("[EvaluateScript] OP_CHECKSIGVERIFY: signature INVALID -> fail");
                                return false;   // VERIFY: abort script on failure
                            }
                            Logger::log("[EvaluateScript] OP_CHECKSIGVERIFY: signature valid");
                        }
                        break;
                    }

                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:
                    {
                        // Stack layout (top -> bottom), Bitcoin convention:
                        //   <n> <pub_1..pub_n> <m> <sig_1..sig_m> <dummy>
                        // We verify that the m signatures are a valid ordered
                        // subset of the n public keys against the input sighash.
                        bool isVerify = (opcode == OP_CHECKMULTISIGVERIFY);

                        auto popCount = [&](long& out) -> bool {
                            if (stack.empty()) return false;
                            auto v = popStack();
                            long n = 0;
                            for (size_t i = 0; i < v.size() && i < 8; ++i)
                                n |= (long)v[i] << (8 * i);
                            out = n;
                            return true;
                        };

                        long n = 0;
                        if (!popCount(n) || n < 0 || n > 20) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKMULTISIG bad n");
                            return false;
                        }
                        if ((long)stack.size() < n) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKMULTISIG missing pubkeys");
                            return false;
                        }
                        std::vector<std::vector<unsigned char>> pubkeys;
                        pubkeys.reserve(n);
                        for (long i = 0; i < n; ++i) { pubkeys.push_back(popStack()); }
                        // pubkeys are now in reverse stack order; restore natural order
                        std::reverse(pubkeys.begin(), pubkeys.end());

                        long m = 0;
                        if (!popCount(m) || m < 0 || m > n) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKMULTISIG bad m");
                            return false;
                        }
                        if ((long)stack.size() < m) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKMULTISIG missing sigs");
                            return false;
                        }
                        std::vector<std::vector<unsigned char>> sigs;
                        sigs.reserve(m);
                        for (long i = 0; i < m; ++i) { sigs.push_back(popStack()); }
                        std::reverse(sigs.begin(), sigs.end());

                        // Historical Bitcoin off-by-one: one extra element is popped.
                        if (!stack.empty()) dropStack();

                        if (!consumeGas(ctx, static_cast<uint64_t>(100 * (uint64_t)(n > 0 ? n : 1)))) return false;

                        bool ok = true;
                        if (ctx.isSimulationMode()) {
                            ok = true; // accept in simulation, matching OP_CHECKSIG
                        } else if (!ctx.tx || !ctx.scriptPubKey || !ctx.signatureCheckFunc) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHECKMULTISIG context invalid");
                            return false;
                        } else {
                            std::string sighashBinary(ctx.sighash.begin(), ctx.sighash.end());
                            // Ordered M-of-N: each signature must match a pubkey,
                            // consuming pubkeys left-to-right (no reuse).
                            size_t ki = 0;
                            size_t matched = 0;
                            for (size_t si = 0; si < sigs.size(); ++si) {
                                bool thisMatched = false;
                                while (ki < pubkeys.size()) {
                                    bool good = ctx.signatureCheckFunc(pubkeys[ki], sigs[si], sighashBinary);
                                    ki++;
                                    if (good) { thisMatched = true; matched++; break; }
                                }
                                // If we run out of pubkeys before matching this sig, fail.
                                if (!thisMatched && ki >= pubkeys.size()) break;
                            }
                            ok = (matched == (size_t)m);
                        }

                        Logger::log(std::string("[EvaluateScript] OP_CHECKMULTISIG: ") +
                                    std::to_string(m) + "-of-" + std::to_string(n) +
                                    " -> " + (ok ? "true" : "false"));

                        if (isVerify) {
                            if (!ok) return false;   // VERIFY: abort script on failure
                        } else {
                            if (!pushStack(std::vector<unsigned char>(1, ok ? 1 : 0))) return false;
                        }
                        break;
                    }


                    case OP_STORE:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_STORE requires key and value, stack size=" + std::to_string(stack.size()));
                            return false;
                        }
                        if (!hasContractStateContext(ctx)) {
                            Logger::log("[EvaluateScript] ERROR: No contract-scoped state context available");
                            return false;
                        }
                        auto value = stack.back();
                        dropStack();
                        auto key = stack.back();
                        dropStack();
                        std::string keyStr(key.begin(), key.end());
                        if (!tru_contract_state_limits::CanApplyStateWrite(
                                *ctx.state, keyStr, value)) {
                            Logger::log("[EvaluateScript] ERROR: OP_STORE state resource limit exceeded");
                            return false;
                        }

                        uint64_t storeGas = 0;
                        if (!tru_contract_state_limits::ComputeStoreGas(
                                key.size(), value.size(), storeGas)) {
                            Logger::log("[EvaluateScript] ERROR: OP_STORE gas calculation rejected state write");
                            return false;
                        }
                        // Charge before mutation so a gas failure cannot modify
                        // a failed script's scratch/overlay state.
                        if (!consumeGas(ctx, storeGas)) return false;

                        // ctx.state is already scoped to ctx.contractAddress.
                        (*ctx.state)[keyStr] = value;
                        Logger::log("[EvaluateScript] OP_STORE: contract=" + ctx.contractAddress +
                                    " key=" + keyStr + ", value=" + hexEncode(value));
                        break;
                    }

                    case OP_LOAD:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_LOAD needs key");
                            return false;
                        }
                        if (!hasContractStateContext(ctx)) {
                            Logger::log("[EvaluateScript] ERROR: No contract-scoped state context available");
                            return false;
                        }
                        auto key = stack.back();
                        dropStack();
                        std::string keyStr(key.begin(), key.end());
                        if (!tru_contract_state_limits::IsLogicalKeyAllowed(keyStr)) {
                            Logger::log("[EvaluateScript] ERROR: OP_LOAD key outside state limits");
                            return false;
                        }
                        auto it = ctx.state->find(keyStr);
                        if (it != ctx.state->end()) {
                            if (!pushStack(it->second)) return false;
                            Logger::log("[EvaluateScript] OP_LOAD: contract=" + ctx.contractAddress +
                                        " key=" + keyStr + ", value=" + hexEncode(it->second));
                        } else {
                            if (!pushStack(std::vector<unsigned char>())) return false;
                            Logger::log("[EvaluateScript] OP_LOAD: contract=" + ctx.contractAddress +
                                        " no value for key=" + keyStr + ", pushed empty");
                        }
                        if (!consumeGas(ctx, static_cast<uint64_t>(20 + key.size()))) return false; // Base cost + key size
                        break;
                    }

                    case OP_CALLER:
                    {
                        if (ctx.sender.empty()) {
                            Logger::log("[EvaluateScript] ERROR: No sender available for OP_CALLER");
                            return false;
                        }
                        if (!pushStack(std::vector<unsigned char>(ctx.sender.begin(), ctx.sender.end()))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(10))) return false;
                        Logger::log("[EvaluateScript] OP_CALLER: Pushed sender=" + ctx.sender);
                        break;
                    }

                    case OP_CONTRACT_ADDR:
                    {
                        if (ctx.contractAddress.empty()) {
                            Logger::log("[EvaluateScript] ERROR: No contract address set for OP_CONTRACT_ADDR");
                            return false;
                        }
                        if (!pushStack(std::vector<unsigned char>(ctx.contractAddress.begin(), ctx.contractAddress.end()))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(10))) return false;
                        Logger::log("[EvaluateScript] OP_CONTRACT_ADDR: Pushed address=" + ctx.contractAddress);
                        break;
                    }

                    case OP_GAS:
                    {
                        uint64_t remainingGas = ctx.gasLimit - ctx.gasUsed;
                        std::vector<unsigned char> gasBytes(8);
                        for (int i = 0; i < 8; ++i) {
                            gasBytes[i] = static_cast<unsigned char>((remainingGas >> (i * 8)) & 0xff);
                        }
                        if (!pushStack(gasBytes)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log("[EvaluateScript] OP_GAS: Pushed remaining gas=" + std::to_string(remainingGas));
                        break;
                    }

                    case OP_HALT:
                    {
                        Logger::log("[EvaluateScript] OP_HALT: Execution halted");
                        return true;
                    }

                    case OP_REVERT:
                    {
                        Logger::log("[EvaluateScript] OP_REVERT: Reverting execution");
                        throw std::runtime_error("Transaction reverted");
                    }

                    case OP_OUTPUTAMOUNT:
                    {
                        if (ctx.outputIndex == size_t(-1) || !ctx.tx || ctx.outputIndex >= ctx.tx->vout.size()) {
                            Logger::log("[EvaluateScript] ERROR: OP_OUTPUTAMOUNT invalid context");
                            return false;
                        }
                        uint64_t amount = ctx.tx->vout[ctx.outputIndex].amount;
                        std::vector<unsigned char> amountBytes(8);
                        for (int i = 0; i < 8; ++i) {
                            amountBytes[i] = static_cast<unsigned char>((amount >> (i * 8)) & 0xff);
                        }
                        if (!pushStack(amountBytes)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log("[EvaluateScript] OP_OUTPUTAMOUNT: Pushed amount=" + std::to_string(amount));
                        break;
                    }
                    case OP_BLOCKTIME:
                    {
                        uint32_t t = ctx.blockTime;
                        std::vector<unsigned char> b(4);
                        b[0] = (unsigned char)(t & 0xff);
                        b[1] = (unsigned char)((t >> 8) & 0xff);
                        b[2] = (unsigned char)((t >> 16) & 0xff);
                        b[3] = (unsigned char)((t >> 24) & 0xff);
                        if (!pushStack(b)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(5))) return false;
                        Logger::log("[EvaluateScript] OP_BLOCKTIME: Pushed block time=" + std::to_string(t));
                        break;
                    }

                    case OP_EXTERNALDATA:
                    {
                        // external/off-chain values are not deterministic
                        // consensus inputs. This opcode is reserved but fails closed.
                        Logger::log("[EvaluateScript] ERROR: OP_EXTERNALDATA is not active in deterministic consensus");
                        return false;
                    }
                    case OP_DATAFEED:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_DATAFEED needs a key on the stack");
                            return false;
                        }
                        auto key = stack.back();
                        dropStack();
                        std::string keyStr(key.begin(), key.end());
                        Logger::log("[EvaluateScript] OP_DATAFEED: Fetching data for key=" + keyStr);

                        // one deterministic consensus feed path.
                        // Never consult HTTP, AI providers, local config, wall clock,
                        // process memory, or a replaceable callback here.
                        auto data = oracleFeedDeterministic(keyStr, ctx);

                        if (data.empty()) {
                            // Missing/unsupported feed data fails closed and must
                            // never be interpreted as numeric zero.
                            Logger::log("[EvaluateScript] ERROR: No deterministic feed data for key=" + keyStr);
                            return false;
                        }
                        if (data.size() != sizeof(uint64_t)) {
                            Logger::log("[EvaluateScript] ERROR: Oracle Feed V1 value is not canonical 8-byte uint64 LE");
                            return false;
                        }
                        if (!pushStack(data)) return false;
                        Logger::log("[EvaluateScript] OP_DATAFEED: Pushed deterministic data=" + hexEncode(data));
                        if (!consumeGas(ctx, static_cast<uint64_t>(50))) return false; // Gas cost for oracle lookup
                        break;
                    }
                    case OP_DELEGATECHECK:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_DELEGATECHECK needs signature");
                            return false;
                        }
                        auto sig = stack.back();
                        dropStack();
                        bool ok = ctx.delegateCheckFunc(sig);
                        if (!pushStack(std::vector<unsigned char>(1, ok ? 1 : 0))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(50))) return false;
                        Logger::log("[EvaluateScript] OP_DELEGATECHECK: Result=" + std::to_string(ok));
                        break;
                    }
                    case OP_CHAINSTATECHECK:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_CHAINSTATECHECK needs a key on the stack");
                            return false;
                        }
                        auto key = stack.back();
                        dropStack();
                        std::string keyStr(key.begin(), key.end());
                        Logger::log("[EvaluateScript] OP_CHAINSTATECHECK: Fetching chain state for key=" + keyStr);

                        // FIX: real, DETERMINISTIC on-chain state. Only values that
                        // are identical on every node at this height are exposed.
                        // Requires a chain context; without one (e.g. mempool
                        // simulation) we fail closed rather than fabricate data.
                        auto value = chainStateDeterministic(keyStr, ctx);
                        if (value.empty()) {
                            Logger::log("[EvaluateScript] OP_CHAINSTATECHECK: no deterministic value for key=" + keyStr);
                            return false;   // fail closed: unknown/unsupported key
                        }
                        if (!pushStack(value)) return false;
                        Logger::log("[EvaluateScript] OP_CHAINSTATECHECK: pushed " + keyStr + "=" + hexEncode(value));
                        if (!consumeGas(ctx, static_cast<uint64_t>(20))) return false;
                        break;
                    }

                    case OP_HASHBLAKE2B:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_HASHBLAKE2B needs input");
                            return false;
                        }
                        auto inItem = stack.back();
                        dropStack();
                        auto out = ctx.blake2bFunc(inItem);
                        if (!pushStack(out)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(20))) return false;
                        Logger::log("[EvaluateScript] OP_HASHBLAKE2B: Hashed input");
                        break;
                    }

                    case OP_HASH160:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_HASH160 on empty stack");
                            return false;
                        }
                        if (!replaceTop(computeHash160(stack.back()))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(15))) return false;
                        Logger::log("[EvaluateScript] OP_HASH160: Computed hash160=" + hexEncode(stack.back()));
                        break;
                    }

                    case OP_SHA3:
                    {
                        if (stack.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_SHA3 needs input");
                            return false;
                        }
                        auto inItem = stack.back();
                        dropStack();
                        auto out = ctx.sha3Func(inItem);
                        if (out.empty()) {
                            Logger::log("[EvaluateScript] ERROR: OP_SHA3 failed to compute hash");
                            return false;
                        }
                        if (!pushStack(out)) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(20 + inItem.size() / 10))) return false; // Base cost + input size factor
                        Logger::log("[EvaluateScript] OP_SHA3: Hashed input, result=" + hexEncode(out));
                        break;
                    }

                    // defense-in-depth bridge kill switch.
                    // 14C1 removes these bytes from IsSupportedOpcode, so normal script
                    // preflight rejects them path-independently. Keep an explicit execution
                    // failure as a second containment layer: if a future refactor ever
                    // bypasses or reorders preflight, legacy random-key bridge code must
                    // still never execute in consensus or relay.
                    case OP_NOVO_GENADDR:
                    case OP_NOVO_DEPOSIT:
                    case OP_NOVO_REDEEM:
                    case OP_NOVO_VERIFY:
                    case OP_BSTY_GENADDR:
                    case OP_BSTY_DEPOSIT:
                    case OP_BSTY_REDEEM:
                    case OP_BSTY_VERIFY:
                    {
                        Logger::log(
                            "[EvaluateScript] ERROR: legacy NOVO/BSTY bridge opcode disabled pending deterministic bridge redesign");
                        return false;
                    }

#if 0
                    // Legacy bridge implementation retained only as redesign reference.
                    // DO NOT reactivate directly: these paths generate nondeterministic
                    // key material during script execution and are not consensus-safe.
                    case OP_NOVO_GENADDR:
                    {
                        Logger::log("[executeScript] OP_NOVO_GENADDR");
                        if (!NOVOBridge::generateNOVOAddress(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 50000))
                            return false;
                        break;
                    }
                    case OP_NOVO_DEPOSIT:
                    {
                        Logger::log("[executeScript] OP_NOVO_DEPOSIT");
                        if (!NOVOBridge::confirmNOVODeposit(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 30000))
                            return false;
                        break;
                    }
                    case OP_NOVO_REDEEM:
                    {
                        Logger::log("[executeScript] OP_NOVO_REDEEM");
                        if (!NOVOBridge::redeemNOVO(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 40000))
                            return false;
                        break;
                    }
                    case OP_NOVO_VERIFY:
                    {
                        Logger::log("[executeScript] OP_NOVO_VERIFY");
                        if (!NOVOBridge::verifyNOVO(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 10000))
                            return false;
                        break;
                    }
                    case OP_BSTY_GENADDR:
                    {
                        Logger::log("[executeScript] OP_BSTY_GENADDR");
                        if (!BSTYBridge::generateBSTYAddress(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 50000))
                            return false;
                        break;
                    }
                    case OP_BSTY_DEPOSIT:
                    {
                        Logger::log("[executeScript] OP_BSTY_DEPOSIT");
                        if (!BSTYBridge::confirmBSTYDeposit(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 30000))
                            return false;
                        break;
                    }
                    case OP_BSTY_REDEEM:
                    {
                        Logger::log("[executeScript] OP_BSTY_REDEEM");
                        if (!BSTYBridge::redeemBSTY(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 40000))
                            return false;
                        break;
                    }
                    case OP_BSTY_VERIFY:
                    {
                        Logger::log("[executeScript] OP_BSTY_VERIFY");
                        if (!BSTYBridge::verifyBSTY(ctx, stack))
                            return false;
                        if (!consumeGas(ctx, 10000))
                            return false;
                        break;
                    }

#endif

                    // reserved upgrade NOP space.
                    // 0xbb..0xc2 are consensus-valid no-ops at genesis. Future
                    // upgrades may assign stricter semantics without first making
                    // previously-invalid bytecode valid. These are intentionally
                    // not exposed by compileTextScript yet.
                    case OP_UPGRADE_NOP1:
                    case OP_UPGRADE_NOP2:
                    case OP_UPGRADE_NOP3:
                    case OP_UPGRADE_NOP4:
                    case OP_UPGRADE_NOP5:
                    case OP_UPGRADE_NOP6:
                    case OP_UPGRADE_NOP7:
                    case OP_UPGRADE_NOP8:
                    {
                        if (!consumeGas(ctx, static_cast<uint64_t>(1))) return false;
                        Logger::log("[EvaluateScript] Reserved upgrade NOP executed");
                        break;
                    }

                    case 0x82:
                    { // OP_SIZE
                        if (stack.empty())
                        {
                            Logger::log("[EvaluateScript] OP_SIZE: Stack underflow");
                            return false;
                        }
                        std::vector<unsigned char> top = stack.back();
                        std::vector<unsigned char> size_bytes;
                        uint32_t size = top.size();
                        if (size <= 252)
                        {
                            size_bytes.push_back(static_cast<unsigned char>(size));
                        }
                        else
                        {
                            // For larger sizes, encode properly (not needed for signatures)
                            size_bytes.push_back(static_cast<unsigned char>(size));
                        }
                        if (!pushStack(size_bytes)) return false;
                        if (!consumeGas(ctx, 1)) return false;
                        Logger::log("[EvaluateScript] OP_SIZE: Pushed size " + std::to_string(size));
                        break;
                    }

                    case 0x77:
                    { // OP_NIP
                        if (stack.size() < 2)
                        {
                            Logger::log("[EvaluateScript] OP_NIP: Stack underflow");
                            return false;
                        }
                        // Remove second-to-top item
                        eraseStackIndex(stack.size() - 2);
                        if (!consumeGas(ctx, 1)) return false;
                        Logger::log("[EvaluateScript] OP_NIP: Removed second item");
                        break;
                    }

                    case 0xaa:
                    { // OP_HASH256 (double SHA256)
                        if (stack.empty())
                        {
                            Logger::log("[EvaluateScript] OP_HASH256: Stack underflow");
                            return false;
                        }
                        std::vector<unsigned char> data = stack.back();
                        dropStack();

                        unsigned char hash1[SHA256_DIGEST_LENGTH];
                        unsigned char hash2[SHA256_DIGEST_LENGTH];
                        SHA256(data.data(), data.size(), hash1);
                        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

                        if (!pushStack(std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH))) return false;
                        if (!consumeGas(ctx, static_cast<uint64_t>(100))) return false; // Hash operations are expensive
                        Logger::log("[EvaluateScript] OP_HASH256: Computed double SHA256");
                        break;
                    }

                    // OP_CAT
                    // Concatenates the second stack item with the top item: [A, B] -> [A || B].
                    // Result size is bounded by the consensus stack-item ceiling before allocation.
                    case OP_CAT:
                    {
                        if (stack.size() < 2) {
                            Logger::log("[EvaluateScript] ERROR: OP_CAT needs 2 items");
                            return false;
                        }

                        const size_t lhsSize = stack[stack.size() - 2].size();
                        const size_t rhsSize = stack.back().size();
                        if (lhsSize > tru_limits::MAX_STACK_ITEM_BYTES ||
                            rhsSize > tru_limits::MAX_STACK_ITEM_BYTES - lhsSize) {
                            Logger::log("[EvaluateScript] ERROR: OP_CAT result exceeds stack-item byte limit");
                            return false;
                        }
                        const size_t resultSize = lhsSize + rhsSize;

                        const auto rhs = popStack();
                        const auto lhs = popStack();

                        std::vector<unsigned char> out;
                        out.reserve(resultSize);
                        out.insert(out.end(), lhs.begin(), lhs.end());
                        out.insert(out.end(), rhs.begin(), rhs.end());

                        if (!pushStack(std::move(out)))
                            return false;

                        const uint64_t gasCost = 5 + static_cast<uint64_t>(resultSize);
                        if (!consumeGas(ctx, gasCost))
                            return false;

                        Logger::log("[EvaluateScript] OP_CAT: concatenated " +
                                    std::to_string(lhsSize) + " + " +
                                    std::to_string(rhsSize) + " bytes");
                        break;
                    }

                    // correct OP_LEFT opcode binding.
                    // opcodes.h defines OP_SUBSTR=0x7f and OP_LEFT=0x80; this implementation
                    // performs left-N-bytes semantics, so it belongs to OP_LEFT. OP_SUBSTR
                    // remains unsupported until it receives its own explicit implementation.
                    case OP_LEFT:
                    {
                        if (stack.size() < 2)
                        {
                            Logger::log("[EvaluateScript] OP_LEFT: Stack underflow");
                            return false;
                        }

                        // Get the size (number of bytes to take)
                        std::vector<unsigned char> size_data = stack.back();
                        dropStack();

                        // Convert size to integer
                        int size = 0;
                        if (size_data.size() == 1)
                        {
                            size = size_data[0];
                        }
                        else if (size_data.size() <= 4)
                        {
                            for (size_t i = 0; i < size_data.size(); i++)
                            {
                                size |= (size_data[i] << (8 * i));
                            }
                        }

                        // Get the data
                        std::vector<unsigned char> data = stack.back();
                        dropStack();

                        // Take left N bytes
                        if (size > 0 && size <= (int)data.size())
                        {
                            if (!pushStack(std::vector<unsigned char>(data.begin(), data.begin() + size))) return false;
                            Logger::log("[EvaluateScript] OP_LEFT: Took " + std::to_string(size) + " bytes");
                        }
                        else
                        {
                            Logger::log("[EvaluateScript] OP_LEFT: Invalid size " + std::to_string(size));
                            return false;
                        }
                        if (!consumeGas(ctx, 1)) return false;
                        break;
                    }

                    case 0x7c: // OP_SWAP
                    {
                        if (stack.size() < 2)
                        {
                            Logger::log("[EvaluateScript] OP_SWAP: Stack underflow");
                            return false;
                        }
                        std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
                        if (!consumeGas(ctx, 1)) return false;
                        Logger::log("[EvaluateScript] OP_SWAP: Swapped top two items");
                        break;
                    }

                    case 0x6e: // OP_2DUP
                    {
                        if (stack.size() < 2)
                        {
                            Logger::log("[EvaluateScript] OP_2DUP: Stack underflow");
                            return false;
                        }

                        // preflight both duplicated items before any
                        // stack mutation. This keeps stackBytes/item-count
                        // accounting atomic at the resource boundary.
                        if (stack.size() >
                            tru_limits::MAX_STACK_ITEMS - static_cast<size_t>(2)) {
                            Logger::log(
                                "[EvaluateScript] OP_2DUP: Stack item-count limit exceeded");
                            return false;
                        }

                        const auto first = stack[stack.size() - 1];
                        const auto second = stack[stack.size() - 2];

                        if (second.size() >
                            tru_limits::MAX_STACK_BYTES - stackBytes) {
                            Logger::log(
                                "[EvaluateScript] OP_2DUP: Total stack byte limit exceeded");
                            return false;
                        }
                        const size_t afterSecondBytes =
                            stackBytes + second.size();
                        if (first.size() >
                            tru_limits::MAX_STACK_BYTES - afterSecondBytes) {
                            Logger::log(
                                "[EvaluateScript] OP_2DUP: Total stack byte limit exceeded");
                            return false;
                        }

                        if (!pushStack(second) || !pushStack(first)) {
                            Logger::log(
                                "[EvaluateScript] OP_2DUP: Internal preflight/push mismatch");
                            return false;
                        }
                        if (!consumeGas(ctx, static_cast<uint64_t>(2))) return false;
                        Logger::log(
                            "[EvaluateScript] OP_2DUP: Atomically duplicated top two items");
                        break;
                    }

                    case OP_MINT_TOKEN:
                    {
                        // fail closed. The legacy opcode used
                        // ctx.tx->vout[ctx.outputIndex].amount and a
                        // "tokens:<address>" namespace. Neither is Token Issuer
                        // V1 consensus truth.
                        //
                        // Canonical V1 issuance is exclusively:
                        //   callValue = continuation.amount - spentAnchor.amount
                        //   balance:<signed-caller-hash160>
                        // with checked arithmetic in ExecuteTokenIssuerV1Call().
                        Logger::log(
                            "[OP_MINT_TOKEN] DISABLED: use Token Issuer V1 checked family transition");
                        return false;
                    }

                    default:
                    {
                        // TRU Smart Contract Patch 11D-R1 — defense-in-depth.
                        // Preflight should already reject unsupported opcodes,
                        // but execution must never silently continue if one
                        // reaches this switch.
                        Logger::log("[EvaluateScript] ERROR: unsupported opcode byte=" +
                                    std::to_string(static_cast<unsigned int>(opcode)));
                        return false;
                    }
                }
            }
            else {
                if (opcode > 0x00 && opcode <= 0x4B) {
                    unsigned int pushSize = opcode;
                    if (pc + pushSize > script.size()) {
                        Logger::log("[EvaluateScript] ERROR: small PUSHDATA out of bounds");
                        return false;
                    }
                    pc += pushSize;
                } else if (opcode == OP_PUSHDATA1) {
                    if (pc + 1 > script.size()) {
                        Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA1 missing length byte");
                        return false;
                    }
                    const size_t length = script[pc++];
                    if (length > script.size() - pc) return false;
                    pc += length;
                } else if (opcode == OP_PUSHDATA2) {
                    if (pc + 2 > script.size()) {
                        Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA2 missing 2 length bytes");
                        return false;
                    }
                    const size_t length = static_cast<size_t>(script[pc]) |
                                          (static_cast<size_t>(script[pc + 1]) << 8);
                    pc += 2;
                    if (length > script.size() - pc) return false;
                    pc += length;
                } else if (opcode == OP_PUSHDATA4) {
                    if (pc + 4 > script.size()) {
                        Logger::log("[EvaluateScript] ERROR: OP_PUSHDATA4 missing 4 length bytes");
                        return false;
                    }
                    const uint64_t length =
                        static_cast<uint64_t>(script[pc]) |
                        (static_cast<uint64_t>(script[pc + 1]) << 8) |
                        (static_cast<uint64_t>(script[pc + 2]) << 16) |
                        (static_cast<uint64_t>(script[pc + 3]) << 24);
                    pc += 4;
                    if (length > static_cast<uint64_t>(script.size() - pc)) return false;
                    pc += static_cast<size_t>(length);
                }
            }
        }

        if (ctx.execStack.size() != 1) {
            Logger::log(
                "[EvaluateScript] ERROR: unterminated conditional block at script end");
            return false;
        }

        Logger::log("[EvaluateScript] Script completed successfully, gas used=" + std::to_string(ctx.gasUsed));
        return true;
    }
    catch (const std::exception& ex) {
        Logger::log("[EvaluateScript] Exception => " + std::string(ex.what()));
        return false;
    }
    catch (...) {
        Logger::log("[EvaluateScript] Unknown exception");
        return false;
    }
}

// --------------------------------------------------------------------
// VerifyScripts
// --------------------------------------------------------------------
bool VerifyScripts(const std::vector<unsigned char>& scriptSig,
                   const std::vector<unsigned char>& scriptPubKey,
                   ScriptExecutionContext& ctx)
{
    std::vector<std::vector<unsigned char>> stack;

    if (!EvaluateScript(scriptSig, stack, ctx)) {
        Logger::log("[VerifyScripts] scriptSig failed.");
        return false;
    }

    if (!EvaluateScript(scriptPubKey, stack, ctx)) {
        Logger::log("[VerifyScripts] scriptPubKey failed.");
        return false;
    }

    if (stack.empty()) {
        Logger::log("[VerifyScripts] Empty stack => fail.");
        return false;
    }

    // canonical final truth test.
    // Consensus truth semantics match OP_IF / OP_VERIFY:
    // empty or first byte 0x00 => false; first byte non-zero => true.
    const bool isTrue = !stack.back().empty() && stack.back()[0] != 0;
    Logger::log("[VerifyScripts] Script result: " + std::string(isTrue ? "true" : "false"));
    return isTrue;
}

// --------------------------------------------------------------------
// compileTextScript
// --------------------------------------------------------------------
std::vector<unsigned char> compileTextScript(const std::string &scriptText)
{
    static const std::unordered_map<std::string, unsigned char> opcodeMap = {
        {"OP_0", OP_0}, {"OP_FALSE", OP_FALSE},
        {"OP_1NEGATE", OP_1NEGATE}, {"OP_RESERVED", OP_RESERVED},
        {"OP_1", OP_1}, {"OP_TRUE", OP_TRUE},
        {"OP_2", OP_2}, {"OP_3", OP_3}, {"OP_4", OP_4},
        {"OP_5", OP_5}, {"OP_6", OP_6}, {"OP_7", OP_7},
        {"OP_8", OP_8}, {"OP_9", OP_9}, {"OP_10", OP_10},
        {"OP_11", OP_11}, {"OP_12", OP_12}, {"OP_13", OP_13},
        {"OP_14", OP_14}, {"OP_15", OP_15}, {"OP_16", OP_16},
        {"OP_NOP", OP_NOP}, {"OP_VER", OP_VER}, {"OP_IF", OP_IF},
        {"OP_NOTIF", OP_NOTIF}, {"OP_VERIF", OP_VERIF}, {"OP_VERNOTIF", OP_VERNOTIF},
        {"OP_ELSE", OP_ELSE}, {"OP_ENDIF", OP_ENDIF}, {"OP_VERIFY", OP_VERIFY},
        {"OP_RETURN", OP_RETURN},
        {"OP_TOALTSTACK", OP_TOALTSTACK}, {"OP_FROMALTSTACK", OP_FROMALTSTACK},
        {"OP_2DROP", OP_2DROP}, {"OP_2DUP", OP_2DUP}, {"OP_3DUP", OP_3DUP},
        {"OP_2OVER", OP_2OVER}, {"OP_2ROT", OP_2ROT}, {"OP_2SWAP", OP_2SWAP},
        {"OP_IFDUP", OP_IFDUP}, {"OP_DEPTH", OP_DEPTH}, {"OP_DROP", OP_DROP},
        {"OP_DUP", OP_DUP}, {"OP_NIP", OP_NIP}, {"OP_OVER", OP_OVER},
        {"OP_PICK", OP_PICK}, {"OP_ROLL", OP_ROLL}, {"OP_ROT", OP_ROT},
        {"OP_SWAP", OP_SWAP}, {"OP_TUCK", OP_TUCK},
        {"OP_CAT", OP_CAT}, {"OP_SUBSTR", OP_SUBSTR}, {"OP_LEFT", OP_LEFT},
        {"OP_RIGHT", OP_RIGHT}, {"OP_SIZE", OP_SIZE},
        {"OP_INVERT", OP_INVERT}, {"OP_AND", OP_AND}, {"OP_OR", OP_OR},
        {"OP_XOR", OP_XOR}, {"OP_EQUAL", OP_EQUAL}, {"OP_EQUALVERIFY", OP_EQUALVERIFY},
        {"OP_1ADD", OP_1ADD}, {"OP_1SUB", OP_1SUB}, {"OP_2MUL", OP_2MUL},
        {"OP_2DIV", OP_2DIV}, {"OP_NEGATE", OP_NEGATE}, {"OP_ABS", OP_ABS},
        {"OP_NOT", OP_NOT}, {"OP_0NOTEQUAL", OP_0NOTEQUAL}, {"OP_ADD", OP_ADD},
        {"OP_SUB", OP_SUB}, {"OP_MUL", OP_MUL}, {"OP_DIV", OP_DIV},
        {"OP_MOD", OP_MOD}, {"OP_LSHIFT", OP_LSHIFT}, {"OP_RSHIFT", OP_RSHIFT},
        {"OP_BOOLAND", OP_BOOLAND}, {"OP_BOOLOR", OP_BOOLOR},
        {"OP_NUMEQUAL", OP_NUMEQUAL}, {"OP_NUMEQUALVERIFY", OP_NUMEQUALVERIFY},
        {"OP_NUMNOTEQUAL", OP_NUMNOTEQUAL}, {"OP_LESSTHAN", OP_LESSTHAN},
        {"OP_GREATERTHAN", OP_GREATERTHAN}, {"OP_LESSTHANOREQUAL", OP_LESSTHANOREQUAL},
        {"OP_GREATERTHANOREQUAL", OP_GREATERTHANOREQUAL}, {"OP_MIN", OP_MIN},
        {"OP_MAX", OP_MAX}, {"OP_WITHIN", OP_WITHIN},
        {"OP_RIPEMD160", OP_RIPEMD160}, {"OP_SHA1", OP_SHA1}, {"OP_SHA256", OP_SHA256},
        {"OP_HASH160", OP_HASH160}, {"OP_HASH256", OP_HASH256},
        {"OP_CODESEPARATOR", OP_CODESEPARATOR},
        {"OP_CHECKSIG", OP_CHECKSIG}, {"OP_CHECKSIGVERIFY", OP_CHECKSIGVERIFY},
        {"OP_CHECKMULTISIG", OP_CHECKMULTISIG},
        {"OP_CHECKMULTISIGVERIFY", OP_CHECKMULTISIGVERIFY},
        // compiler/VM parity.
        // Legacy OP_NOP1 and OP_NOP4..OP_NOP10 text aliases are intentionally
        // not exposed. OP_NOP4..OP_NOP10 alias live bridge opcodes and must
        // never masquerade as harmless no-ops in user-authored scripts.
        {"OP_CHECKLOCKTIMEVERIFY", OP_CHECKLOCKTIMEVERIFY},
        {"OP_CHECKSEQUENCEVERIFY", OP_CHECKSEQUENCEVERIFY},
        {"OP_BLOCKTIME", OP_BLOCKTIME},
        {"OP_EXTERNALDATA", OP_EXTERNALDATA},
        {"OP_DATAFEED", OP_DATAFEED},
        {"OP_DELEGATECHECK", OP_DELEGATECHECK},
        {"OP_CHAINSTATECHECK", OP_CHAINSTATECHECK},
        {"OP_HASHBLAKE2B", OP_HASHBLAKE2B},
        {"OP_SHA3", OP_SHA3},
        {"OP_STORE", OP_STORE},
        {"OP_LOAD", OP_LOAD},
        {"OP_CALLER", OP_CALLER},
        {"OP_CONTRACT_ADDR", OP_CONTRACT_ADDR},
        {"OP_GAS", OP_GAS},
        {"OP_HALT", OP_HALT},
        {"OP_REVERT", OP_REVERT},
        // OP_MINT_TOKEN is byte-reserved but not text-compilable.
        {"OP_TOKEN_BALANCE", OP_TOKEN_BALANCE},
        {"OP_BURN_TOKEN", OP_BURN_TOKEN},
        {"OP_OUTPUTAMOUNT", OP_OUTPUTAMOUNT},
        // --- Bridge opcodes (NOVO / BSTY) ---
        {"OP_NOVO_GENADDR", OP_NOVO_GENADDR},
        {"OP_NOVO_DEPOSIT", OP_NOVO_DEPOSIT},
        {"OP_NOVO_REDEEM", OP_NOVO_REDEEM},
        {"OP_NOVO_VERIFY", OP_NOVO_VERIFY},

        {"OP_BSTY_GENADDR", OP_BSTY_GENADDR},
        {"OP_BSTY_DEPOSIT", OP_BSTY_DEPOSIT},
        {"OP_BSTY_REDEEM", OP_BSTY_REDEEM},
        {"OP_BSTY_VERIFY", OP_BSTY_VERIFY},
        {"OP_NOVO_ADDR", OP_NOVO_GENADDR},
        {"OP_BSTY_ADDR", OP_BSTY_GENADDR},
        {"OP_NOVO_CONFIRM", OP_NOVO_DEPOSIT},
        {"OP_BSTY_CONFIRM", OP_BSTY_DEPOSIT}
    };

    std::istringstream iss(scriptText);
    std::string token;
    std::vector<unsigned char> result;

    while (iss >> token) {
        if (token.empty()) continue;

        std::string upper = toUpper(token);

        auto it = opcodeMap.find(upper);
        if (it != opcodeMap.end()) {
            const unsigned char opcode = it->second;
            if (!IsSupportedOpcode(opcode)) {
                throw std::runtime_error(
                    "[compileTextScript] Unsupported opcode for current TRU VM => " + token);
            }
            result.push_back(opcode);
            continue;
        }

        if (upper.rfind("OP_", 0) == 0) {
            throw std::runtime_error(
                "[compileTextScript] Unrecognized opcode => " + token);
        }

        if (token.size() % 2 != 0) {
            throw std::runtime_error("[compileTextScript] Hex data token has odd length => " + token);
        }
        std::vector<unsigned char> data;
        data.reserve(token.size()/2);
        for (size_t i = 0; i < token.size(); i += 2) {
            unsigned int byteVal = 0;
            std::istringstream ss(token.substr(i,2));
            ss >> std::hex >> byteVal;
            data.push_back(static_cast<unsigned char>(byteVal));
        }

        size_t dataLen = data.size();
        if (dataLen <= 0x4B) {
            result.push_back((unsigned char)dataLen);
            result.insert(result.end(), data.begin(), data.end());
        }
        else if (dataLen <= 0xFF) {
            result.push_back(OP_PUSHDATA1);
            result.push_back((unsigned char)dataLen);
            result.insert(result.end(), data.begin(), data.end());
        }
        else if (dataLen <= 0xFFFF) {
            result.push_back(OP_PUSHDATA2);
            unsigned char l0 = (unsigned char)(dataLen & 0xff);
            unsigned char l1 = (unsigned char)((dataLen >> 8) & 0xff);
            result.push_back(l0);
            result.push_back(l1);
            result.insert(result.end(), data.begin(), data.end());
        }
        else {
            result.push_back(OP_PUSHDATA4);
            unsigned char b0 = (unsigned char)(dataLen & 0xff);
            unsigned char b1 = (unsigned char)((dataLen >> 8) & 0xff);
            unsigned char b2 = (unsigned char)((dataLen >> 16) & 0xff);
            unsigned char b3 = (unsigned char)((dataLen >> 24) & 0xff);
            result.push_back(b0);
            result.push_back(b1);
            result.push_back(b2);
            result.push_back(b3);
            result.insert(result.end(), data.begin(), data.end());
        }
    }

    // creation-time consensus parity.
    // Never return bytecode that consensus preflight would reject. This also
    // applies the same script size/opcount/sigop ceilings before contract
    // creation, preventing users from funding an unusable custom script.
    ScriptResourceMetrics metrics;
    if (!AnalyzeScriptResources(result, metrics)) {
        throw std::runtime_error(
            "[compileTextScript] Compiled script rejected by TRU VM preflight");
    }

    // creation/spend activation parity.
    // Patch 14D2 deliberately keeps stateful spends fail-closed. Do not let
    // native/CLI creation fund an output that cannot yet be spent. 14D3 lifts
    // this gate only together with durable state + lineage activation.
    const auto statefulScan =
        tru_contract_call::ScanStatefulContractScript(result);
    if (!statefulScan.valid) {
        throw std::runtime_error(
            "[compileTextScript] Stateful-script scan failed");
    }
    if (statefulScan.usesStateDomain &&
        !tru_contract_call::IsCanonicalStatefulKvV1Script(result)) {
        throw std::runtime_error(
            "[compileTextScript] Only canonical Stateful K/V V1 call script is activated for creation");
    }

    return result;
}
