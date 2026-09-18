#pragma once

#include <string>

// TRU TOKEN-BURN-01
//
// This module defines a conventional, non-consensus token retirement sink.
// Token burn transactions remain ordinary, already-valid token transfers.
// Upgraded software recognizes this destination for wallet/explorer UX only.
//
// IMPORTANT: this is an effectively unspendable P2PKH sink whose HASH160 is
// all zeroes. No private key is known for it; finding one would require a
// cryptographic preimage break. It is not an OP_RETURN/provably-unspendable
// consensus output and therefore does not alter TRU consensus rules.
namespace tru_token_burn_v1 {

inline constexpr const char* VERSION = "TRU-TOKEN-BURN-01";
inline constexpr const char* BURN_ADDRESS =
    "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
inline constexpr const char* BURN_HASH160_HEX =
    "0000000000000000000000000000000000000000";

inline bool isBurnAddress(const std::string& address) noexcept {
    return address == BURN_ADDRESS;
}

}  // namespace tru_token_burn_v1
