#pragma once
#ifndef TRU_NETWORK_PARAMS_H
#define TRU_NETWORK_PARAMS_H

#include <cstdint>
#include <array>
#include <string_view>

namespace tru_network {

// immutable mainnet wire identity.
// Byte order on the wire is exactly EC 7C 8F B9.
inline constexpr std::array<std::uint8_t, 4> MAINNET_P2P_MAGIC = {
    0xec, 0x7c, 0x8f, 0xb9
};
inline constexpr std::string_view MAINNET_NETWORK_ID = "tru-mainnet";

// canonical TRU mainnet service defaults.
inline constexpr std::uint16_t MAINNET_RPC_PORT = 21832;
inline constexpr std::uint16_t MAINNET_P2P_PORT = 21833;

// TRU-specific Base58Check P2PKH namespace.
// Version 0x41 yields 34-character mainnet addresses beginning with 'T'.
inline constexpr std::uint8_t MAINNET_P2PKH_VERSION = 0x41;

// Reserved for future TRU testnet.
inline constexpr std::uint8_t TESTNET_P2PKH_VERSION = 0x7f;

inline constexpr char MAINNET_BASE58_PREFIX_CHAR = 'T';
inline constexpr char TESTNET_BASE58_PREFIX_CHAR = 't';

inline constexpr std::string_view MAINNET_BECH32_HRP = "tru";
inline constexpr std::string_view TESTNET_BECH32_HRP = "ttru";

// Project-local BIP44 identity. This is NOT claimed to be SLIP-0044 registered.
inline constexpr std::uint32_t TRU_BIP44_COIN_TYPE = 0x00545255u;

// Fresh TRU mainnet genesis identity generated under a project-controlled key.
inline constexpr std::string_view GENESIS_ADDRESS =
    "TCtVWvC1JtsKXWoEDueN2aNEkpVbjAftQM";
inline constexpr std::string_view GENESIS_HASH160 =
    "2004155a5d7120f6d3c792a9c881544f86ae4a7c";
inline constexpr std::string_view GENESIS_P2PKH_SCRIPT_HEX =
    "76a9142004155a5d7120f6d3c792a9c881544f86ae4a7c88ac";

inline constexpr std::uint32_t GENESIS_TIMESTAMP = 1745982427u;
inline constexpr std::uint32_t GENESIS_BITS = 0x1e00ffffu;
inline constexpr std::uint32_t GENESIS_NONCE = 46045855u;

inline constexpr std::string_view GENESIS_COINBASE_TXID =
    "daca4ceae9b5f0ee1bd30eaa93522666bcf37560b6a7310657eb1f7cac7ec139";
inline constexpr std::string_view GENESIS_MERKLE_ROOT =
    "daca4ceae9b5f0ee1bd30eaa93522666bcf37560b6a7310657eb1f7cac7ec139";
inline constexpr std::string_view GENESIS_BLOCK_HASH =
    "b62fba2600030d97a06916b17694bec8d97ca14c1db682b2e57b424bd6000000";

} // namespace tru_network

#endif // TRU_NETWORK_PARAMS_H
