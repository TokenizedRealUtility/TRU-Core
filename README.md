# TRU — Tokenized Real Utility

> **A UTXO-based Proof-of-Work Layer 1 combining Bitcoin-style ownership, stateful smart contracts, native tokenization, WOTS+ protected transactions, marketplace settlement, AI-oracle anchoring, Living Tokens, CPU/GPU mining, and a complete node / wallet / CLI / explorer stack.**

TRU is an independent Layer-1 blockchain written in C++17. The chain is internally known as **TRU**, its native asset is **TRU**, and the project is focused on **Tokenized Real Utility**: bringing ownership, programmable assets, verifiable state, real-world data workflows, and AI-assisted applications together on one UTXO-based network.

TRU is not an ERC-20 token, sidechain, or cosmetic Bitcoin fork. It implements its own blockchain node, Proof-of-Work validation, UTXO ledger, mempool, P2P networking, mining, wallet, script interpreter, token layer, AI-oracle subsystem, JSON-RPC API, command-line tools, and block explorer.

## TRU — PUBLIC SOFTWARE AND NETWORK NOTICE

TRU is blockchain software for operating and participating in the
Tokenized Real Utility network.

This initial release is provided free of charge.

The TRU project is not selling TRU, conducting an ICO, presale,
SAFT, crowdfunding token sale, or soliciting investment in TRU.

No purchase from the project is required to operate a node,
participate in the network, or mine according to the protocol.

TRU does not provide equity, ownership in a company, dividends,
revenue sharing, guaranteed yield, redemption rights, or contractual
rights to business profits.

Initial distribution:

Genesis premine:        NONE
Founder allocation:     NONE
Treasury allocation:    NONE
Investor allocation:    NONE
ICO / presale:          NONE
Protocol distribution:  PROOF-OF-WORK

Native TRU units are created according to the protocol-defined
Proof-of-Work block reward.

Following public network activation, the project's developer may
participate in mining using the same publicly available software,
Proof-of-Work algorithm, difficulty rules, and block rewards available
to other network participants.

The project makes no promise or representation regarding future
monetary value, market price, exchange listing, liquidity, or
investment return.

TRU is provided for software development, computation, network
participation, tokenization, smart-contract, and other technical uses.

Users are responsible for compliance with laws applicable to them
and their jurisdiction.

---

### Historical Public Launch Record

Public announcement: 9-12-2026
Network activation:  9-12-2026

Historical launch image (not a current upgrade recommendation):
ghcr.io/agreatopportunity/tru-node:2.0.2

Immutable image digest:
sha256:b2d0dc79b4f690fd8d65a5bb8ee9647120d66023474e1d82c7af134d1345e3ac

Genesis hash: not recorded in this README; verify against the source/network before publishing one.


Initial block reward:
50 TRU

Mining:
Public Proof-of-Work
No reserved founder or project mining reward

## Current Version and Upgrade Status

**Documentation target: TRU Core 0.08.8 (QUANTUM-RECOVERY-02 candidate).**

The 0.08.5 mainnet consensus upgrade activated at **block 50,000, inclusive**.
Versions 0.08.6–0.08.8 retain that activation and the existing WOTS+ parameters.
They address recovery, maintenance, and wallet behavior without scheduling a new
consensus activation.

| Version | Main changes |
|---|---|
| **0.08.5** | Activated PQ01 WOTS+ verification, marketplace lock/fill/refund validation, canonical `OP_SIZE` behavior, and TR09 block-payload commitments at height 50,000. Added dedicated quantum transaction functions alongside ordinary sends. |
| **0.08.6** | Corrected confirmed-parent lookup during isolated fork validation; added logarithmic ancestor discovery, 4,096-block disconnect/connect windows, expanded side-storage limits and future undo retention to 8,192 blocks, and `getchaininfo.fork_recovery` status. |
| **0.08.7** | Addressed height lookup/locking, automatic reorg defaults, rollback balance-cache work, canonical quantum address display, and admission limits for expensive peer transaction work. |
| **0.08.8 candidate** | Adds a second encrypted quantum state copy, conservative replica repair, explicit encrypted backup/recovery-only import, and persistent destination-use reservations. Preserves existing signing-intent and exact-byte retry safeguards. |

**Qualification:** both 0.08.8 candidate cores passed full node/client builds,
native wallet-state regression tests, and the controlled live P2P/reorg/crash
suite. A throwaway-wallet RPC workflow check remains before recommending
funded-wallet deployment or public release. Qt GUI runtime and the independent
browser wallet/SDK require separate integration qualification. Passing these
tests is not an independent security audit or proof of universal recovery.

Check the running node rather than relying only on its source `VERSION` file:

```bash
./build-native/bin/tru-cli raw getconsensus09info '{}'
./build-native/bin/tru-cli raw getchaininfo '{}'
```

`getconsensus09info` reports the running Core version, activation height,
`active` status, opcode map, market capabilities, and WOTS parameters. Candidate
height is the next block height; it is not the current tip height.

---

## Highlights

- **UTXO-based Layer 1** with Bitcoin-style inputs, outputs, P2PKH/P2SH, transaction IDs, Merkle roots, and cumulative-work fork choice.
- **Nakamoto Proof-of-Work** using TRU's `SHA256d + 21E8` puzzle.
- **60-second target block time** with deterministic difficulty calculation derived from the parent chain.
- **CPU and OpenCL GPU mining** using the same consensus puzzle as the node validator.
- **Large-block architecture** with size-aware block assembly, P2P headroom, and a reusable block-size configurator.
- **Stateful UTXO smart contracts** with persistent contract storage and gas metering.
- **Real ECDSA single-signature and multisignature verification** over secp256k1.
- **Dedicated PQ01 WOTS+ transactions**, separate from legacy sends, with one-time descriptors and explicit signing/broadcast steps.
- **On-chain marketplace locks** with partial/full fills, TRU purchases, token swaps, and seller refunds after expiry.
- **Bounded automatic fork recovery** with cumulative-work validation, recovery diagnostics, and crash-recovery safeguards.
- **Four native token classes**: FT, NFT, SFT, and NCFT.
- **TRUSCRIPT inscriptions** for on-chain text/data ownership.
- **Living Token Evolution** with cryptographically linked AI-generated metadata epochs.
- **Provider-agnostic AI oracle** supporting local, private, cloud, and custom AI backends.
- **AI responses and evolution proofs anchored on-chain** without making nondeterministic AI execution part of consensus.
- **Interactive terminal UI** with responsive full/compact menus and live mining information.
- **Standalone `tru-cli`** with Bitcoin-style commands plus raw access to the full JSON-RPC API.
- **HD/BIP32 wallet core**, terminal wallet functionality, and Qt desktop GUI support.
- **HTTP block explorer** and a broad JSON-RPC interface.
- **Docker deployment** for nodes and miners.

---

## Table of Contents

1. [Current Version and Upgrade Status](#current-version-and-upgrade-status)
2. [Chain Parameters](#chain-parameters)
3. [Architecture](#architecture)
4. [Consensus and Proof-of-Work](#consensus-and-proof-of-work)
5. [Large-Block Architecture](#large-block-architecture)
6. [Transactions and UTXOs](#transactions-and-utxos)
7. [Smart Contracts and Opcodes](#smart-contracts-and-opcodes)
8. [Native Token System](#native-token-system)
9. [TRUSCRIPT Inscriptions](#truscript-inscriptions)
10. [MagicMiner and MagicLock](#magicminer-and-magiclock)
11. [AI Oracle](#ai-oracle)
12. [Living Token Evolution](#living-token-evolution)
13. [Interactive Node CLI](#interactive-node-cli)
14. [`tru-cli`](#tru-cli)
15. [Wallets](#wallets)
16. [Quantum Transactions](#quantum-transactions)
17. [Marketplace Locks and Atomic Settlement](#marketplace-locks-and-atomic-settlement)
18. [Mining](#mining)
19. [P2P Networking](#p2p-networking)
20. [Storage](#storage)
21. [JSON-RPC API](#json-rpc-api)
22. [Prefer authenticated tru-cli for ordinary use:](#prefer-authenticated-tru-cli-for-ordinary-use)
23. [For direct curl, use a protected token source; never paste the token publicly.](#for-direct-curl-use-a-protected-token-source-never-paste-the-token-publicly)
24. [The default cookie path for port 21832 is usually ~/.tru/rpc-cookie-21832.](#the-default-cookie-path-for-port-21832-is-usually-trurpc-cookie-21832)
25. [Block Explorer](#block-explorer)
26. [Building and Running](#building-and-running)
27. [Docker](#docker)
28. [Configuration](#configuration)
29. [TRU MAINNET EXAMPLE — review values for your own machine](#tru-mainnet-example--review-values-for-your-own-machine)
30. [Bootstrap peers. Comma-separated IP:port pairs; no spaces after commas.](#bootstrap-peers-comma-separated-ipport-pairs-no-spaces-after-commas)
31. [Automatic cumulative-work recovery: enabled by default in current builds.](#automatic-cumulative-work-recovery-enabled-by-default-in-current-builds)
32. [Optional privileged RPC wallet-send feature, DISABLED by default.](#optional-privileged-rpc-wallet-send-feature-disabled-by-default)
33. [Keys may be set here in [network] or [default], but not twice.](#keys-may-be-set-here-in-network-or-default-but-not-twice)
34. [Alternative equivalent names recognized by this build:](#alternative-equivalent-names-recognized-by-this-build)
35. [AI oracle funding / wallet options (only configure when needed).](#ai-oracle-funding--wallet-options-only-configure-when-needed)
36. [Enable only after installing and reviewing the private policy file.](#enable-only-after-installing-and-reviewing-the-private-policy-file)
37. [Documentary example: see notes below about which fields are consumed.](#documentary-example-see-notes-below-about-which-fields-are-consumed)
38. [Implementation Status](#implementation-status)
39. [Testing and Qualification](#testing-and-qualification)
40. [Security Notes](#security-notes)
41. [Scaling Direction](#scaling-direction)
42. [Additional Documentation](#additional-documentation)
43. [Project Direction](#project-direction)
44. [Links](#links)

---

# Chain Parameters

| Parameter | Current design |
|---|---|
| Chain | Tokenized Real Utility |
| Native asset | TRU |
| Model | UTXO |
| Consensus | Nakamoto Proof-of-Work |
| PoW | `SHA256d + 21E8` |
| Base unit | 1 TRU = 100,000,000 Atoms |
| Initial block subsidy | 50 TRU |
| Halving interval | 210,000 blocks |
| Target block time | 60 seconds |
| Difficulty retarget interval | 60 blocks |
| Retarget adjustment clamp | 0.5× to 2× target movement per interval |
| Coinbase maturity | 100 blocks |
| Maximum supply | 21,000,000 TRU |
| Ordinary address format | Base58Check P2PKH |
| Quantum descriptor format | Canonical `truq1:…` PQ01 script descriptor with checksum; one payment per descriptor |
| PQ01 / market activation | Block **50,000**, inclusive |
| Automatic recovery window | Up to **4,096** blocks disconnected and **4,096** connected, subject to required state availability |
| Future undo retention target | **8,192** blocks; previously pruned undo is not recreated |
| Default RPC port | 21832 |
| Default P2P port | 21833 |
| Default explorer port | 8001 |

### Configured large-block profile

The large-block infrastructure centralizes block and network sizing so miners, validation, templates, and P2P transport stay aligned.

| Limit | Configured value |
|---|---:|
| Hard consensus block cap | **64 MiB** |
| Miner/template assembly budget | **56 MiB** |
| P2P framed payload cap | **80 MiB** |

The assembly budget intentionally sits below the consensus cap so the block builder has room for block-level metadata and serialization overhead.

TRU also includes a reusable `Block_Size_Increaser_or_Decreaser_Patch.py` utility for future controlled size changes. Under the current 32-bit P2P Frame V1 design, the utility supports configurations up to **3 GiB** while preserving transport headroom.

> **Consensus note:** the maximum accepted block size is a consensus rule. All participating nodes should be upgraded before miners begin producing blocks larger than the previous limit. Lowering the limit also requires care if historical blocks already exceed the proposed new cap.

A future P2P Frame V2 / streamed-block architecture is required before safely moving to true 4 GiB+ or effectively unbounded blocks.

---

# Architecture

TRU runs as a complete blockchain stack rather than depending on another chain for settlement.

```text
                         +----------------------+
                         |  Interactive CLI     |
                         |  Qt GUI / tru-cli    |
                         +----------+-----------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
+---------v---------+                              +----------v---------+
| CPU / GPU Miners |                              | JSON-RPC Clients   |
+---------+---------+                              +----------+---------+
          |                                                   |
          +--------------------+------------------------------+
                               |
                     +---------v----------+
                     |      TRU NODE      |
                     |    tru_advanced    |
                     +---------+----------+
                               |
        +----------------------+----------------------+
        |                      |                      |
+-------v-------+      +-------v-------+      +-------v-------+
| Blockchain / |      |    Mempool    |      |  Script VM /  |
| Fork Choice  |      | TX Admission  |      | Smart Contract|
+-------+-------+      +-------+-------+      +-------+-------+
        |                      |                      |
        +----------------------+----------------------+
                               |
                +--------------+--------------+
                |                             |
        +-------v-------+             +-------v-------+
        | UTXO / State |             |   AI Oracle   |
        |   LevelDB    |             | Provider Hub  |
        +-------+-------+             +-------+-------+
                |                             |
                +--------------+--------------+
                               |
                        +------v------+
                        | P2P Network |
                        |  Protobuf   |
                        +-------------+
```

Major modules include:

- `blockchain` — validation, cumulative work, reorganization, difficulty, subsidy, UTXO application.
- `mempool` — transaction admission, conflict handling, double-spend protection, relay policy.
- `script_interpreter` — Bitcoin-style stack execution plus TRU's extended opcodes.
- `utxo` / storage — persistent UTXOs, contract state, token metadata, integrity checks.
- `tx` — transaction structures, serialization, signing, and sighash.
- `p2p`, `peer_connection`, `message_handler` — peer networking and message transport.
- `wallet` — HD keys, addresses, balances, transaction construction, token issuance and transfer.
- `rpc_server` — JSON-RPC control and application interface.
- `ai_oracle_service`, `ai_providers` — provider-neutral AI requests and on-chain commitments.
- `blockexplorer` — HTTP blockchain explorer.
- `tru-cli` — standalone RPC command-line client.

---

# Consensus and Proof-of-Work

TRU follows Nakamoto consensus: the valid chain with the **greatest cumulative Proof-of-Work** wins.

## SHA256d + 21E8

The TRU block header is double-SHA256 hashed. TRU's `21E8` rule is then applied consistently by:

- the node validator,
- the CPU miner,
- the OpenCL GPU miner.

A block hash must satisfy the compact target encoded in the block header's `bits` field.

## Block validation

Before a block is committed, TRU validates areas including:

- block/header structure,
- Proof-of-Work,
- parent block and height,
- timestamp and Median Time Past rules,
- Merkle root,
- coinbase placement and reward,
- transaction inputs and referenced UTXOs,
- same-block double spends,
- coinbase maturity,
- script execution,
- output/value bounds,
- expected difficulty,
- maximum serialized block size.

## Difficulty

Difficulty is derived deterministically from the parent chain so miners and validators calculate the same expected value.

The active retarget path uses:

```text
Target spacing:    60 seconds
Retarget interval: 60 blocks
```

Retarget movement is clamped to avoid sudden extreme changes. The compact-target calculation preserves the full 256-bit target scale used by mining and validation.

## Fork choice

Each indexed block carries cumulative chain work. A competing branch must pass
full state validation and contain **strictly greater cumulative work** before
activation. Height alone, a peer's version string, accepted mining shares, or a
local hash/PoW audit does not establish which competing branch should win.

Current recovery behavior includes:

- Logarithmic common-ancestor discovery rather than walking every height over the network.
- Up to 4,096 blocks disconnected and 4,096 connected per recovery, subject to available undo and branch state.
- Expanded side-storage limits and an 8,192-block future undo-retention target. The upgrade cannot recreate already pruned undo.
- Confirmed-parent lookup that works in the isolated reorg sandbox even when its active chain vector is empty.
- Recovery markers and restart handling for interrupted branch activation. Missing undo, corrupt markers, or conflicting state fail closed.
- Automatic recovery enabled by default unless explicitly disabled. An explicit `automaticReorg` configuration takes precedence over the supported environment fallback.

Inspect effective status:

```bash
./tru-cli raw getchaininfo '{}'
./tru-cli getpeerinfo
./tru-cli getblockbyheight 51035
```

`fork_recovery` reports the policy version, configured windows, whether execution
is halted, recovery state/reason, and event-specific heights when available.
`idle` is not proof that a particular fork was resolved. Compare block hashes at
the **same height** across nodes, then inspect recovery state and logs if they
disagree. Peers reporting the same height can still be on different branches.

### What `chainValid` means

`chainValid: true` means the last explicit **in-memory block hash / proof-of-work
walk** passed at the current tip. `null` means there is no applicable audit at
that tip; a new block makes an earlier audit stale. This audit is not historical
transaction replay or a UTXO database audit. Inspect `chain_audit.scope`,
`same_tip`, and `transaction_replay` before describing its result.

---

# Large-Block Architecture

TRU's scaling direction is **larger L1 capacity without abandoning deterministic validation**.

The large-block path coordinates three separate limits:

```text
Mempool
   |
   v
Size-aware transaction selection
   |
   v
Miner/template budget
   |
   v
Candidate block
   |
   v
Hard consensus block-size validation
   |
   v
P2P payload / relay capacity
   |
   v
Network peers
```

The block builder does not blindly copy an arbitrarily large mempool into a candidate block. Transaction selection stops at the configured assembly budget, leaving remaining transactions in the mempool for later blocks.

The P2P limit is kept above the consensus block cap so a valid large block is not accepted locally but rejected by the network transport layer.

---

# Transactions and UTXOs

TRU transactions use the familiar Bitcoin-style model:

```text
Inputs
  -> previous txid + output index
  -> unlocking script

Outputs
  -> amount
  -> locking script
```

Standard spending uses compressed secp256k1 public keys and P2PKH-style scripts.

Supported relay/output patterns include:

- P2PKH
- P2SH
- `OP_RETURN`
- token outputs
- TRUSCRIPT data
- allow-listed smart-contract patterns

Transaction IDs are calculated from serialized transaction bytes using double SHA-256. Transactions received from peers are independently re-hashed and validated rather than trusting a peer-supplied transaction ID.

---

# Smart Contracts and Opcodes

TRU extends Bitcoin-style scripting with persistent state, gas accounting, deterministic chain-state access, modern hashes, and token/bridge primitives.

## Signature operations

The live interpreter supports real ECDSA validation for:

- `OP_CHECKSIG`
- `OP_CHECKSIGVERIFY`
- `OP_CHECKMULTISIG`
- `OP_CHECKMULTISIGVERIFY`
- `OP_CHECKWOTSVERIFY` (`0xbb`), activated at height 50,000 for PQ01 WOTS+ verification

Multisig enforces signature/public-key bounds and performs ordered M-of-N verification.

## Stateful execution

TRU's contract execution context can include:

- transaction and input context,
- sender/caller,
- contract address,
- execution height,
- gas limit and gas used,
- persistent contract state,
- deterministic chain context,
- callback hooks.

Important state and control opcodes include:

| Opcode | Purpose | Status |
|---|---|---|
| `OP_BLOCKTIME` | Current block time | Implemented |
| `OP_CHAINSTATECHECK` | Deterministic chain-state read | Implemented |
| `OP_HASHBLAKE2B` | BLAKE2b-256 | Implemented |
| `OP_SHA3` | SHA3-256 | Implemented |
| `OP_STORE` | Persist contract key/value | Implemented |
| `OP_LOAD` | Read contract key/value | Implemented |
| `OP_CALLER` | Push sender address | Implemented |
| `OP_CONTRACT_ADDR` | Push contract address | Implemented |
| `OP_GAS` | Remaining execution gas | Implemented |
| `OP_HALT` | Halt execution | Implemented |
| `OP_REVERT` | Revert execution/state | Implemented |
| `OP_OUTPUTAMOUNT` | Current output amount | Implemented |
| `OP_MINT_TOKEN` | Mint contract tokens | Implemented |
| `OP_TOKEN_BALANCE` | Contract token balance | Partial |
| `OP_BURN_TOKEN` | Burn contract tokens | Partial |
| `OP_EXTERNALDATA` | Generic external-data opcode | Placeholder |
| `OP_DATAFEED` | Generic keyed data-feed opcode | Placeholder |
| `OP_DELEGATECHECK` | Delegate/trusted signature | Stub |
| NOVO bridge opcodes | Wrapped NOVO bridge path | Scaffold |
| BSTY bridge opcodes | Wrapped BSTY bridge path | Scaffold |

### Activated 0.08.5 opcode map

| Opcode | Byte | Activated behavior |
|---|---|---|
| `OP_SIZE` | `0x82` | Canonical stack-item byte-size behavior |
| `OP_CHECKWOTSVERIFY` | `0xbb` | PQ01 WOTS+ signature verification |
| `OP_MARKETVERIFY` | `0xbc` | Marketplace lock/fill/refund validation |

The reported WOTS suite is **WOTS+ SHA2 n32 w16 len67 L-tree**, version 1:
2,144 signature bytes, 125,000 gas, and a sigop cost of 256. These are protocol
parameters, not a claim that ordinary ECDSA outputs became quantum resistant.

### Gas

Contract execution is metered. Operations consume different amounts of gas based on complexity, protecting the interpreter from unbounded script execution.

### Deterministic chain state

`OP_CHAINSTATECHECK` reads deterministic values relative to the block being validated, including values such as:

- block height,
- total issued supply,
- block subsidy.

It fails closed when deterministic chain context is unavailable.

---

# Native Token System

TRU provides four first-class token categories.

| Type | Name | Characteristics | Example use |
|---|---|---|---|
| **FT** | Fungible Token | Divisible, configurable supply | currency, rewards, utility |
| **NFT** | Non-Fungible Token | Unique, amount = 1 | ownership, collectibles, real assets |
| **SFT** | Sentient Fungible Token | Fungible/evolving AI-oriented metadata | AI-assisted assets, limited editions |
| **NCFT** | Neural Canvas Fungible Token | Dynamic media / AI-oriented metadata | evolving art, media, digital experiences |

Token transactions combine:

- UTXO funding,
- an ownership script,
- structured token metadata,
- transaction signing,
- mempool/network relay,
- persistent metadata and ownership tracking.

Wallet issuance functions include:

```text
issueExtendedFT
issueExtendedNFT
issueExtendedSFT
issueExtendedNCFT
```

Token metadata can include names, symbols, descriptions, media URLs, divisibility, unique IDs, dynamic visual information, and AI-oriented fields depending on token type.

---

# TRUSCRIPT Inscriptions

TRUSCRIPT provides ordinal-style text/data inscriptions on TRU.

The system tracks information such as:

- inscription identity,
- inscription index,
- sat number,
- timestamp,
- current ownership,
- transfers.

Wallet and RPC functionality can create, list, inspect, and transfer TRUSCRIPT assets.

---

# MagicMiner and MagicLock

TRU includes a native **MagicLock** transaction type and a companion **MagicMiner** tool. MagicLock combines ordinary UTXO ownership with a second computational condition: before the locked TRU can be spent, the owner must produce a valid ECDSA signature whose double-SHA256 hash begins with a chosen hexadecimal prefix.

This is separate from TRU block mining. **MagicMiner does not mine blocks or change chain difficulty.** It performs *signature grinding* for a specific MagicLock UTXO while normal TRU Proof-of-Work continues independently.

## How a MagicLock works

When a MagicLock is created, the wallet constructs a locking script with two requirements:

```text
                    MAGICLOCK UTXO
                         |
          +--------------+--------------+
          |                             |
          v                             v
  HASH256(signature)             Standard P2PKH
  must begin with                ownership check
  target prefix                  + ECDSA CHECKSIG
          |                             |
          +--------------+--------------+
                         |
                         v
                  UTXO may be spent
```

The canonical locking script is built as:

```text
OP_SWAP
OP_HASH256
<N>
OP_LEFT
<TARGET_PREFIX>
OP_EQUALVERIFY
OP_DUP
OP_HASH160
<OWNER_PUBKEY_HASH>
OP_EQUALVERIFY
OP_CHECKSIG
```

The first half checks the computational target. The second half preserves normal P2PKH ownership, meaning the spender must still possess the private key belonging to the address that created the MagicLock.

A MagicLock therefore does **not** turn the locked TRU into a public bounty that anyone can claim simply by finding a matching hash. The matching signature must also be a valid ECDSA signature from the lock owner's key.

## Creating a MagicLock

The `createmagiclock` RPC accepts:

```text
amount
targetPrefix
address          optional
secretData       optional
dataType         optional
```

The target must be a non-empty hexadecimal string with an even number of characters.

Example conceptual targets:

| Target | Prefix bytes | Expected signature attempts |
|---|---:|---:|
| `00` | 1 | ~256 |
| `21e8` | 2 | ~65,536 |
| `000000` | 3 | ~16.8 million |
| `00000000` | 4 | ~4.29 billion |

Each additional target byte increases expected work by approximately **256×**.

The wallet funds the MagicLock from a spendable TRU UTXO, creates the special locking output, returns change when appropriate, signs the creation transaction, places it in the mempool, and broadcasts it to peers.

## Unlocking: real signature grinding

To unlock a MagicLock, TRU:

1. Loads the locked UTXO.
2. Extracts the target prefix and the owner's public-key hash from the locking script.
3. Builds a spending transaction to the requested recipient.
4. Calculates the transaction sighash using the full MagicLock locking script.
5. Loads the private key belonging to the lock owner.
6. Repeatedly generates a random ECDSA nonce (`K`) and creates a valid signature.
7. Appends `SIGHASH_ALL`.
8. Computes `SHA256(SHA256(signature))`.
9. Checks whether the resulting hash begins with the MagicLock target prefix.
10. When a match is found, constructs the unlocking `scriptSig`, validates the transaction, adds it to the mempool, and broadcasts it.

The unlock script supplies the matching signature twice plus the public key:

```text
<signature>
<signature>
<public-key>
```

One signature copy is consumed by the prefix-hash condition and the other by the final `OP_CHECKSIG`.

The current C++ grinding routine is bounded to **1,000,000 attempts per unlock call**. As a result, one- and two-byte targets are practical with the present implementation, while targets whose expected search space is substantially larger than one million attempts may require additional engineering or repeated attempts.

## MagicMiner tool

The companion Node.js utility, currently implemented as:

```text
tru_magic_miner_new.js
```

provides an interactive interface for:

```text
1) Create MagicLock
2) Search MagicLocks
3) Unlock MagicLock
4) Change wallet address
5) Exit
```

It connects to the TRU node through JSON-RPC, normally on:

```text
127.0.0.1:21832
```

and uses the node RPC methods:

```text
createmagiclock
listmagiclocks
unlockmagiclock
listaddresses
```

`listmagiclocks` scans confirmed blocks and the mempool, identifies canonical and supported legacy MagicLock script patterns, and reports information including:

```text
txid
vout
amount
targetPrefix
owner address
block height
spent / unspent status
```

### Important implementation detail

The animated **"Mining & Flipping Hashes"** display in the JavaScript MagicMiner is a user-interface animation. The actual cryptographic signature grinding is performed by the TRU C++ wallet/node inside `unlockMagicLock()`.

The node extracts the real target from the UTXO and performs the ECDSA grind against that target before the spend can pass script validation.

## Optional attached data

A MagicLock creation request can optionally include small metadata or data in an `OP_RETURN` output. The current RPC path supports text or encoded file data and associates it with `MAGIC_SECRET` metadata.

This feature is presently best treated as **experimental attached-data functionality, not secure secret storage**.

The current RPC implementation derives the data key deterministically from the MagicLock target prefix and the owner's public-key hash and uses a simple XOR transformation for this path. Because both the target and public-key hash are visible in the MagicLock script, this mechanism should not be relied upon to keep sensitive information confidential until the unlock occurs.

A future hardened MagicLock secret system should use a true unlock-dependent secret, authenticated encryption, or another construction in which the decryption key cannot be derived solely from public on-chain values.

For larger documents or media, store the content externally and place only a cryptographic hash, content identifier, or encrypted reference on-chain.

## RPC examples

Use the authenticated local client with the appropriate wallet authorization:

```bash
./tru-cli raw createmagiclock '{"amount":0.001,"targetPrefix":"21e8"}'
./tru-cli raw listmagiclocks '{}'
./tru-cli raw unlockmagiclock '{"txid":"MAGICLOCK_TXID","vout":0,"recipient":"YOUR_TRU_ADDRESS"}'
```

## Why MagicLock is different

A normal P2PKH TRU output asks one primary question:

```text
Can you prove ownership of this private key?
```

A MagicLock asks two:

```text
Can you prove ownership of this private key?

AND

Can you produce a valid transaction signature
whose HASH256 begins with the required target?
```

That gives TRU a native **proof-conditioned UTXO** primitive that can be used for experiments with computational locks, puzzles, delayed-effort spends, game mechanics, proof challenges, and other applications that combine ownership with configurable computational work.

---
# AI Oracle

TRU includes a **provider-agnostic AI oracle system**.

The important architectural decision is that **AI inference is not part of Proof-of-Work consensus**.

Different LLMs can produce different text. Requiring every validator to independently run an AI model would therefore make deterministic consensus unsafe.

TRU separates the two:

```text
AI request
   |
   v
Configured AI provider
   |
   v
AI computation off-chain
   |
   +----------------------+
   |                      |
   v                      v
Full response          SHA-256 commitment
storage                   |
                           v
                    OP_RETURN anchor
                           |
                           v
                     TRU blockchain
```

The blockchain validates the resulting TRU transaction normally. Nodes do not need access to the model that produced the response.

## Supported provider layer

The current provider abstraction includes:

### Local / private

- Nemotron
- Oobabooga
- Ollama
- custom JSON/OpenAI-compatible endpoints

### Cloud

- OpenAI
- Anthropic / Claude
- xAI / Grok
- Google Gemini

Provider selection can change without changing TRU consensus or the on-chain commitment format.

Secrets belong in environment variables or protected local configuration and should never be committed to the blockchain.

> The generic `OP_EXTERNALDATA` and `OP_DATAFEED` interpreter opcodes remain placeholders. They are separate from the implemented AI-oracle service and must not be confused with live deterministic consensus data feeds.

---

# Living Token Evolution

TRU's SFT and NCFT token evolution preserves a locally persisted sequence of epochs and uses signed, hash-linked records plus on-chain anchor transactions. **AI inference is off-chain; validators do not run the AI model.** The latest code contains separate flows for provider-generated evolution, media updates, AI-assistant declarations, and explicit agent-memory checkpoint commitments.

## Evolution and provenance

- Epoch numbering is derived from **persisted evolution records**, not a token issuer's arbitrary `evolution_epoch` metadata input. The issuance root is epoch 0.
- Each proposed change is previewed and checked before signing/persistence. No-op metadata proposals should not consume an epoch.
- Evolution records include previous/new metadata hashes and issuer/editor authorization proof. The normal evolution path is tied to the **original issuance owner's** verified signature by `token_editor_authority.h` (`TRU_ORIGINAL_ISSUANCE_OWNER_V1`).
- A locally prepared evolution record, submitted anchor, and confirmed on-chain anchor are **different states**. Verify receipt/history and block confirmation before describing an epoch as confirmed.
- The independent `token_evolution_cli` supports `--verify-history`; consult its current `--help` and the agent guide for the exact workflow. The published README should not promise automatic epoch creation merely because a model or token exists.

## NCFT agent memory checkpointing

Core contains `tru_agent_checkpoint_v5.h`: a distinct **issuer-approved checkpoint** writer for NCFTs, not a general on-chain memory store or consensus-rule change. It validates an explicit public checkpoint request containing token ID, checkpoint/manifest SHA-256 commitments, bounded byte size, and `explicit_memories_only` scope. The private memory itself remains off-chain. A duplicate checkpoint hash is rejected.

Enable checkpoint processing through the separately protected `[agent_checkpoint]` policy setting documented in [Configuration](#configuration). A supervised watcher may export **public requests** for a human to review. Core requires the supported policy and exact approval; it does not grant a model access to private wallet keys, automatically unlock an encrypted wallet, or sign arbitrary requests. `NCFT-Ai-Agents-main/SERVICE.md` documents an optional Linux user service **for the watcher only**, not a Core or model service. Run its supervised trial before enabling automation.

## NCFT transfer and agent handover: current boundary

**Do not advertise an NCFT transfer as a complete AI-agent handover.** The current reviewed `token_editor_authority.h` still binds evolution/editor proof to the confirmed **original issuance owner**, not automatically to the recipient of the latest token transfer. Transfer changes token ownership; it does not by itself transfer this signer authority. Nor does an on-chain transfer migrate private memories, running processes, API credentials, or service ownership. A secure authenticated export/import and replacement-authority design would need separate implementation and verification before claiming this is seamless.

`tru://axon/fund/...` wallet handoff in Core is a **NEROMESH funding-intent workflow**, not NCFT agent/editor handover; keep the two terms distinct. The supplied source should not be described as a completed automatic transfer-of-agent-authority patch.

**Security scope:** evolution proofs, hash commitments, and confirmed anchors demonstrate provenance of submitted records. They do not prove the accuracy of AI-generated content, custody of off-chain data, or a quantum-resistant signature scheme.

---


# Interactive Node CLI

Start the operator CLI with `./tru_advanced --cli` from the active build directory. The current `main.cpp` includes **TRU CLI UX PATCH 30A5**: the **visible menu uses sequential choices 1–36**, mapped internally to older handler codes. The old 4a/12a/13a aliases remain accepted but are **not** the public menu numbering. Press `M` / `m` to toggle full/compact views.

| Public choice | Operation (mapped legacy handler) |
|---|---|
| 1–3 | Create address/wallet, load wallet, save wallet (`1`, `2`, `3`) |
| 4–9 | Generate address, private key view, send TRU, check balance, list addresses, show pubkey hash (`4`, `4a`, `5`, `6`, `14`, `18a`) |
| **10** | **Token List** (`12`) |
| 11–12 | Token contract views (`12a`, `12b`) |
| 13–17 | Issue FT/NFT/SFT/NCFT, create/list/send TRUSCRIPT, token AI tools (`13`, `13a`, `13b`, `13c`, `13f`) |
| 18–20 | Send token, create smart contract, bridge options (`15`, `18`, `18b`) |
| 21–27 | Query/list/update contracts, voting, voting results, mint, token supply (`20`, `20a`, `20u`, `21`, `22`, `23`, `24`) |
| 28–33 | Chain information, peers, block lookup, mempool, connect peer, peer message (`8`, `9`, `10`, `19`, `16`, `17`) |
| 34–36 | CPU mine, GPU mine, exit (`7`, `7a`, `11`) |

These are **source-code mappings**, not a guarantee that each feature is available or enabled in every build/runtime. The legacy `13d` AI-token creation and `13e` AI communication handlers also exist in source but are not listed in this 36-choice public mapping; use the advertised Token AI tools entry and check the exact live menu. Do not publish the old menu table as though it matches v0.07.7/v0.07.8.

---


# `tru-cli`

TRU also includes a standalone **Bitcoin-style RPC command-line client**.

The interactive `--cli` menu and `tru-cli` serve different purposes:

```text
tru_advanced --cli
    -> operator-friendly interactive node interface

tru-cli
    -> scriptable command-line RPC client
```

Typical usage:

```bash
cd build-native/bin

./tru-cli getinfo
./tru-cli getbalance
./tru-cli getblockcount
./tru-cli getchaininfo
./tru-cli getconnectioncount
./tru-cli getpeerinfo
./tru-cli getrawmempool
```

Query another address:

```bash
./tru-cli getbalance <TRU_ADDRESS>
```

Remote node:

```bash
./tru-cli -rpcconnect=<NODE_IP> -rpcport=21832 getinfo
```

Read connection settings from a TRU config file:

```bash
./tru-cli -conf=./tru.conf getinfo
```

## Raw RPC passthrough

Friendly wrappers cover common commands, but `raw` can call any RPC method exposed by the node:

```bash
./tru-cli raw getblocktemplate
./tru-cli raw gettokenmetadata '{"tokenID":"example"}'
./tru-cli raw listunspent '{"address":"<TRU_ADDRESS>"}'
./tru-cli raw verifytokenbalance '{"address":"<TRU_ADDRESS>","tokenID":"example"}'
```

The dedicated quantum namespace is:

```text
quantum <receive|list|status|backup|restore|fund|send|exit|retry|input|submit> [JSON]
```

`status`, `backup`, and `restore` are new in the 0.08.8 candidate. See
[Quantum Transactions](#quantum-transactions) for access requirements and safety
boundaries. `sendtoaddress` remains the separate ordinary TRU send command.

Useful options include:

```text
-rpcconnect=<ip>
-rpcport=<port>
-conf=<file>
-json
-timeout=<seconds>
-h / --help
```

---

# Wallets

TRU uses an HD wallet core with BIP32-style key derivation.

Wallet functionality includes:

- seed-derived addresses,
- Base58Check P2PKH addresses,
- balance and UTXO discovery,
- transaction construction,
- ECDSA transaction signing,
- local or RPC operation,
- token issuance and transfer,
- TRUSCRIPT creation and transfer,
- smart-contract creation,
- MagicLock create/unlock,
- external private-key import.

User interfaces include:

- the node's interactive CLI,
- wallet CLI functionality,
- a Qt desktop GUI,
- RPC access,
- `tru-cli` for node/RPC operations.

Protect wallet files and WIF/private-key material carefully. PQ01 keys require the additional quantum state files described in [Quantum Transactions](#quantum-transactions); ordinary HD seed recovery does not cover them.

---

# Quantum Transactions

PQ01 is a separate **WOTS+ protected plain-TRU transaction path**. Legacy TRU,
token, TRUSCRIPT, and contract sending functions retain their existing roles.
The dedicated wallet path currently uses **one confirmed input and one output**,
spending the whole selected input minus its fee. It has no amount field or change
output and does not carry token metadata.

## Protection and boundaries

- `fund` uses the ordinary input's ECDSA key to move TRU into a fresh PQ01 output.
- `send` spends a PQ01 output with WOTS+ into another fresh PQ01 descriptor.
- `exit` spends with WOTS+ into an ordinary address and requires `confirm_exit: true`; the resulting output has ordinary ECDSA protection.
- A `truq1:…` value is a checksummed locking-script descriptor. It is not a reusable account or a Base58 ordinary address. Copy it in full; aliases or renamed labels do not change the underlying script.
- WOTS+ keys are **one-time signing keys**. Use **one payment per descriptor**, never send change back to a used descriptor, and never run cloned signers.
- `unused` means no signing history is recorded locally. It does **not** prove that a descriptor has never received a payment or was never used by another copy of the wallet.

This provides a hash-based signature spending condition for the protected output.
It does not replace all ECDSA keys throughout TRU, prove every application quantum
resistant, or remove normal network, implementation, custody, and chain-reorg risks.

## Access and command map

Use your authenticated local `tru-cli` and an unlocked wallet. Wallet actions
require loopback RPC and the operator's existing wallet-send opt-in. Ordinary
remote/public endpoints must not be turned into a quantum signing service.

```bash
cd "$HOME/TRU-Core/build-native/bin"
TRUCLI="$PWD/tru-cli"
"$TRUCLI" raw getconsensus09info '{}'
"$TRUCLI" quantum list
```

Confirm `active: true` before funding or spending. For a checkout named `NEW_TRU`,
use that checkout's `build-native/bin` instead.

| CLI action | Purpose | RPC mapping |
|---|---|---|
| `quantum receive` | Create a fresh receiving descriptor | `quantumwallet`, action `receive` |
| `quantum list` | List local descriptors and signing state | `quantumwallet`, action `list` |
| `quantum input` | Inspect a confirmed, unspent input | `getquantuminput` |
| `quantum fund` | Sign ordinary TRU → PQ01 funding | `quantumwallet`, action `fund` |
| `quantum send` | Sign PQ01 → fresh PQ01 | `quantumwallet`, action `send` |
| `quantum exit` | Sign PQ01 → ordinary TRU | `quantumwallet`, action `exit` |
| `quantum retry` | Retrieve saved signed bytes; no new signature | `quantumwallet`, action `retry` |
| `quantum submit` | Explicitly submit saved transaction bytes | `sendquantumtransaction` |
| `quantum status` | Inspect quantum state/recovery information; new in 0.08.8 | `quantumwallet`, action `status` |
| `quantum backup` | Export an encrypted backup; new in 0.08.8 | `quantumwallet`, action `backup` |
| `quantum restore` | Import in recovery-only mode; new in 0.08.8 | `quantumwallet`, action `restore` |

The interactive node command is **`qr`**, labelled Quantum Transactions. It is
separate from `tru-cli quantum …`. The native desktop wallet has a separate
quantum transaction flow. This maintenance package does **not** update the
independent website/browser signer or the SDK automatically.

## Funding and sending: example sequence

The following are templates. Replace every placeholder and inspect every result;
do not paste all steps as an unattended script. Start with a small confirmed
ordinary output you own, such as 0.01 TRU (1,000,000 atoms). Never choose a token
or control output. Inspect the actual output index and amount:

```bash
"$TRUCLI" listunspent YOUR_ORDINARY_ADDRESS
"$TRUCLI" quantum input '{"txid":"ORDINARY_TXID","vout":0}'
"$TRUCLI" quantum receive
```

Save the returned descriptor as A. **Make a consistent backup of the wallet and
current quantum state before funding.** Then sign the funding transaction:

```bash
"$TRUCLI" quantum fund \
  '{"txid":"ORDINARY_TXID","vout":0,"fee_atoms":10000,"destination":"DESCRIPTOR_A"}'
```

Inspect `signed: true`, `broadcast: false`, `input_atoms`, `send_atoms`,
`fee_atoms`, and `rawHex`. The implementation requires at least 10,000 fee atoms
and also enforces wallet fee policy; the chosen fee must satisfy both. The
selected-input cap is controlled by the operator's wallet-send configuration.

Decode the returned bytes, verify A's output script and value, then explicitly
submit those same bytes:

```bash
"$TRUCLI" decoderawtransaction FUND_RAW_HEX
"$TRUCLI" quantum submit '{"txHex":"FUND_RAW_HEX"}'
"$TRUCLI" gettransaction FUND_TXID
"$TRUCLI" quantum input '{"txid":"FUND_TXID","vout":0}'
```

A successful submission or transaction ID is not confirmation. Wait until the
funding output is confirmed and unspent. An early `Input must be confirmed and
unspent` response can simply mean it is still in the mempool.

Create a fresh destination B (or obtain a fresh descriptor from the recipient),
back up the updated local wallet state, and sign the protected spend:

```bash
"$TRUCLI" quantum receive
"$TRUCLI" quantum send \
  '{"txid":"FUND_TXID","vout":0,"fee_atoms":10000,"source":"DESCRIPTOR_A","destination":"DESCRIPTOR_B"}'
"$TRUCLI" decoderawtransaction SEND_RAW_HEX
"$TRUCLI" quantum submit '{"txHex":"SEND_RAW_HEX"}'
"$TRUCLI" gettransaction SEND_TXID
"$TRUCLI" quantum input '{"txid":"SEND_TXID","vout":0}'
"$TRUCLI" quantum list
```

Verify the decoded destination and amount before submitting. **Do not create a
different signature with A after signing.** If signing times out or the response
is lost, retrieve the saved bytes:

```bash
"$TRUCLI" quantum retry '{"source":"DESCRIPTOR_A"}'
```

Check transaction status before resubmitting the exact saved bytes. Never clear
signing state, restore stale files, or reset A to unused to work around a failure.

## Recorded mainnet example

The following results were observed on the operator's node; verify current chain
membership and confirmations independently before treating them as current:

| Step | Transaction / result |
|---|---|
| Ordinary funding output | `e53e542ca52f1083a1caea93602e9c1c14d4038fcc195578b7464f3a80bd7ce6:0`, 1,000,000 atoms |
| Funding A | `75450982cb6a094e5ccbfc977bb154908576c0f04ccc32a6124f0ea5188a9f78:0`, 990,000 atoms; observed confirmed at height 52,690 |
| WOTS+ spend A → B | `14ec11a1a75c4a9eb62e451a7d63489c85bba2ddaff06274523f1e59858d71ac:0`, 980,000 atoms; observed confirmed at height 52,696 |

Each step paid 10,000 atoms. The final 0.0098 TRU remained in **B's PQ01 output**,
not an ordinary TRU address. A was recorded as `reserved_or_signed` with saved
transaction bytes; B appeared locally unused because it had not signed a spend.

## 0.08.8 backup and recovery behavior

Quantum state is stored alongside the wallet, typically `tru.dat.pq01`. The
candidate adds `tru.dat.pq01.recovery`, written durably before the primary copy.
Both are authenticated and encrypted. A missing replica can be rebuilt from its
surviving authentic counterpart; inconsistent signing histories or failed
authentication stop the operation rather than silently discarding evidence.

The first quantum operation on an existing v1 sidecar without a recovery replica
migrates it to state format 2. **Older binaries reject that format.** Back up the
wallet and its current quantum state together before migration; do not downgrade
by restoring stale signer files.

For the new actions, choose a private existing directory and a fresh filename:

```bash
"$TRUCLI" quantum status
"$TRUCLI" quantum backup \
  '{"backup_file":"/absolute/private/path/quantum-current-UNIQUE.pqbackup"}'
```

Backup export refuses an existing destination. Keep a current encrypted backup
off the signing machine; the local recovery copy is not an off-machine backup.
Recovery requires the matching wallet master as well as the quantum state.

**External backup import is recovery-only, not normal replica repair.** It merges
history and quarantines all imported keys, including matching local records.
Saved completed transaction bytes can be retrieved, but imported keys cannot
create new signatures. There is no quarantine override. An imported funded key
without saved spending bytes may remain unspendable through this recovery path.
Test import only on a disposable wallet before considering actual recovery:

```bash
"$TRUCLI" quantum restore \
  '{"backup_file":"/absolute/private/path/current.pqbackup","confirm_recovery_only":true}'
```

**Limits:** ordinary seed recovery alone cannot reconstruct existing random
quantum descriptors. Rolling back both replicas or running cloned signers can
defeat local history protection. Destination reservations cover this wallet's
own operations; other wallets and raw builders can still pay a reused script.
No consensus-level prohibition of WOTS key reuse is introduced by 0.08.8.

---

# Marketplace Locks and Atomic Settlement

At activation height 50,000, `OP_MARKETVERIFY` enabled validated marketplace
locks for native token sales and swaps. Supported asset classes reported by Core
include TRU, FT, SFT, NFT, and NCFT; market version 1 uses 8-byte token IDs.

- A seller authorizes an on-chain asset lock before settlement.
- Full or partial fills must satisfy the lock's price, asset, and payment rules.
- TRU purchases and token-for-token swaps are supported by the validated paths.
- Seller-authorized refunds are allowed at/after expiry; early or forged refunds fail validation.
- Conflicting fills and duplicate lock spends are rejected.

Inspect capabilities and holdings through authenticated RPC:

```bash
./tru-cli raw getconsensus09info '{}'
./tru-cli raw getmarketportfolio '{"address":"YOUR_TRU_ADDRESS"}'
```

`buildmarkettransaction09` is the dedicated transaction-builder RPC. Use the
current marketplace integration/API schema for lock, fill, and refund requests;
do not treat a portfolio entry or off-chain listing as a confirmed escrow.
Builders, signatures, broadcast, and confirmation are distinct steps.

Core support does not automatically upgrade an external marketplace website,
matching service, pool engine, browser wallet, or SDK. Each must use the activated
formats and be qualified for its own workflow. No TRUSCRIPT marketplace support
is implied by the native token asset list above.

---

# Mining

TRU supports both CPU and GPU Proof-of-Work mining.

## CPU

Example standalone CPU miner:

```bash
./tru_miner_cpu \
  --node-ip 127.0.0.1 \
  --node-port 21832 \
  --mineraddr <TRU_ADDRESS> \
  --threads 4
```

## GPU

TRU includes OpenCL GPU mining using the same SHA256d + 21E8 consensus puzzle validated by the node.

GPU mining requires:

- a compatible GPU,
- OpenCL runtime/headers,
- appropriate vendor drivers.

## Mining flow

```text
Node
  |
  | getblocktemplate
  v
Miner
  |
  | nonce search
  v
Valid PoW
  |
  | submitblock
  v
Node validation
  |
  v
P2P relay
```

Miners can report activity and hashrate to the node, allowing the interactive interface to show live mining information.

## Pool and independent miner compatibility after height 50,000

Upgrading the node alone is insufficient if an external pool hardcodes the
coinbase layout or discards block metadata. Its block builder must consume the
current template, including:

- `coinbase_required_outputs`: include **every** required output, including the zero-value `TR09` commitment output; do not hardcode one coinbase output.
- `required_token_metadata`: preserve and serialize the template's required metadata in the submitted block's supported format.
- `previousblockhash`, height, bits, and the exact selected transaction payload that the commitment covers.

Rebuild work when the template changes. A commitment taken from a different
transaction/metadata payload is not valid merely because it starts with `TR09`.
The node validates these fields on submission. Accepted shares do not establish
that a complete block was accepted or retained on the active chain.

```bash
./tru-cli raw getblocktemplate '{}'
./tru-cli raw getchaininfo '{}'
./tru-cli getblockbyheight BLOCK_HEIGHT
```

Record the full candidate hash, height, and exact `submitblock` result. Confirm
the hash at that height on other independently connected nodes. Block intervals
vary with luck, effective hash rate, and difficulty; a slow interval by itself
does not prove a validation stall.

---

# P2P Networking

TRU peers communicate over TCP using checksummed, length-prefixed Protobuf messages.

Message families include:

- `VERSION` / `VERACK`
- `ADDR`
- `INV`
- `GETDATA`
- `BLOCK`
- `TX`
- `PING` / `PONG`
- `HEIGHT`
- `GET_BLOCK`
- `GET_HEIGHT`
- `BLOCK_NOT_FOUND`

The network layer includes:

- peer handshakes,
- block and transaction relay,
- height gossip and synchronization,
- local revalidation of incoming transactions,
- stale-peer timeouts,
- per-IP connection controls,
- blacklist/Sybil-protection facilities,
- checksummed payloads.

Large-message sending retries partial TCP `send()` results rather than assuming a single write transmits an entire large block.

The current P2P Frame V1 uses a 32-bit payload-length field. This is why 4 GiB+ block transport requires a future framing/streaming upgrade rather than only increasing a numeric block limit.

---

# Storage

TRU persists chain and application state in LevelDB.

Storage functionality includes:

- Snappy compression,
- LRU block caching,
- thread-safe database access,
- batched writes,
- prefix iteration,
- compaction,
- repair,
- integrity verification,
- per-value checksums.

UTXO records include the creation height and coinbase status needed to enforce maturity rules.

Contract state, token metadata, ownership data, inscriptions, and evolution records are stored through the same persistent storage layer where appropriate.

---

# JSON-RPC API

The node exposes JSON-RPC at:

```text
http://127.0.0.1:21832/rpc
```

Example:

```bash
# Prefer authenticated tru-cli for ordinary use:
./build-native/bin/tru-cli raw getchaininfo '{}'

# For direct curl, use a protected token source; never paste the token publicly.
# The default cookie path for port 21832 is usually ~/.tru/rpc-cookie-21832.
RPC_COOKIE="${TRU_RPC_COOKIE_FILE:-$HOME/.tru/rpc-cookie-21832}"
TOKEN="$(cat "$RPC_COOKIE")"
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":{}}' \
  http://127.0.0.1:21832/rpc
unset TOKEN
```

TRU exposes a broad RPC surface. Representative groups include:

## Chain and blocks

```text
getinfo
getchaininfo
getblockcount
getblock
getblockbyheight
getblocktemplate
submitblock
getconsensus09info
```

## Transactions and UTXOs

```text
sendrawtransaction
createrawtransaction
signrawtransactionwithkey
gettransaction
getrawtransaction
decoderawtransaction
gettxout
listtransactions
listunspent
getrawmempool
getmempooltransactions
```

## Wallet and addresses

```text
getbalance
getnewaddress
listaddresses
getaddresstransactions
```

## Quantum wallet and marketplace

```text
quantumwallet               # action-based private wallet operations
getquantuminput             # confirmed unspent input inspection
sendquantumtransaction      # submit saved one-input/one-output PQ01-related tx
buildmarkettransaction09    # dedicated market builder
getmarketportfolio          # holdings/index inspection
```

For example:

```bash
./tru-cli raw quantumwallet '{"action":"list"}'
./tru-cli raw getquantuminput '{"txid":"FUND_TXID","vout":0}'
```

## Tokens and inscriptions

```text
issuetoken
sendtoken
gettokenutxo
gettokenmetadata
verifytokenbalance
inscribeTRUScript
transferTRUScript
getTRUScripts
getTRUScriptDetails
```

## Contracts

```text
createcontracttransaction  # canonical contract creation; legacy createsmartcontract removed
getcontracts
createmagiclock
unlockmagiclock
listmagiclocks
```

## Mining

```text
startmining
registerminer
unregisterminer
getminerstatus
getallminers
reportmineractivity
```

## AI

```text
configureAIProvider
getAIProviders
createAIToken
interactWithAIToken
getAIResponse
getAITokenState
trainAIToken
```

## Identity / social

```text
createDID
createsocialpost
getDIDMapping
registerDIDSigned
```

## Network

```text
getpeerinfo
```

`tru-cli raw` can access methods that do not yet have a friendly CLI wrapper.

> **Security (reviewed source):** Privileged `/rpc` requires a locally generated **Bearer token**. Core creates/loads its per-port token using `tru_rpc::loadOrCreateServerToken()`, records the private cookie path in startup logs, and rejects missing or incorrect `Authorization: Bearer …` headers (401, with rate-limited failures). Browser-Origin/Fetch-Site requests to privileged RPC are rejected (403), and `GET /rpc` is disabled (405). Default `rpcbind` is loopback. Non-loopback binding requires explicit `[network] rpcAllowRemote=1`; RPC spending must not be exposed on a non-loopback bind. Authentication does **not** replace firewall isolation. Do not embed token/cookie contents in websites, logs, screenshots, or public configs.

---

# Block Explorer

TRU includes an HTTP block explorer, normally on port:

```text
8001
```

Representative endpoints include:

```text
/api/stats
/api/blocks
/block/<hash>
/api/addresses
/api/transactions
/api/address/<address>
/api/transaction/<txid>
/api/tokens
/api/contracts
/api/miners
```

The explorer can run with the node or as a standalone explorer process against the configured TRU data environment.

---

# Building and Running

## Dependencies

Linux with a C++17 toolchain and sufficient RAM, swap, and disk for the selected build. Build duration and peak memory depend on configuration and parallelism.

```bash
./install-deps.sh          # once per machine
```

Installs the C++17 toolchain, CMake, OpenSSL, libsodium, LevelDB, Protobuf,
Boost, libcurl, libfmt, jsoncpp — then builds crc32c, ethash, libwally-core
and cxxopts from source. OpenCL is needed only for GPU mining; Qt only for
the desktop GUI.

Check without installing anything:

```bash
./install-deps.sh --check
```

**Deactivate conda first.** TRU's C++ build uses system packages only. An
active conda environment puts its own cmake, protobuf, leveldb and libstdc++
ahead of the system ones, producing link errors or a binary that runs on that
machine and nowhere else. Both scripts refuse to run while one is active.

## Build

```bash
cd ~/NEW_TRU
./agnostic_rebuild.sh
```

Binaries land in:

```text
build-native/bin/
```

**Protect runtime files before rebuilding.** In common installations,
`build-native/bin/` contains the wallet and chain data as well as executables.
Do not delete that directory or assume a helper script preserves newly added
quantum files. Review the exact script before using it.

For an already configured build, an incremental update is:

```bash
cmake --build build-native --target tru_advanced tru-cli --parallel 2
```

Before switching running binaries, cleanly stop Core and wallet activity and
make a consistent private backup of the ordinary wallet files (including
`tru.dat.enc`, `tru.dat.public`, and `wallet_seed.dat.enc` where used), the
current `*.pq01` state, and any `*.pq01.recovery` replica. Include any other
wallet files used by your actual configuration. Keep the current set together
and off-machine; never restore stale quantum state into an active signer.
Chain databases must also be stopped or copied through a supported consistent
snapshot mechanism. An installer source backup is not a wallet backup.

Binaries are produced under the native build output, typically:

```text
build-native/bin/
```

## Run the node

```bash
cd ~/NEW_TRU/build-native/bin

./tru_advanced \
  --datadir data/utxo \
  --cli \
  --rpcport 21832
```

With the explorer:

```bash
./tru_advanced \
  --datadir data/utxo \
  --cli \
  --rpcport 21832 \
  --enable-explorer \
  --explorer-port 8001
```

Useful node flags include options for:

- CLI / GUI mode,
- P2P enable/disable,
- seed behavior,
- explicit peers,
- config file,
- RPC bind address,
- explorer.

---

# Docker

TRU can run in containers with its dependencies packaged into the image.

The Docker documentation defines separate roles for:

| Image | Purpose |
|---|---|
| `tru-node` | TRU node |
| `tru-miner-cpu` | standalone CPU miner |
| `tru-miner-gpu` | OpenCL GPU miner |

Basic local-image node example (build and verify the intended source version first):

```bash
docker run -it --name tru-node \
  -p 21833:21833 \
  -v tru-data:/app/data \
  -v "$(pwd)/tru.conf:/app/tru.conf:ro" \
  tru-node:local-verified --cli
```

P2P port `21833` is the public peer port.

RPC port `21832` should **not** be exposed publicly.

When RPC must be reachable from the Docker host, bind the service appropriately inside the container but publish it only to host loopback, for example:

```text
127.0.0.1:21832:21832
```

Docker Compose profiles can run:

- node only,
- node + CPU miner,
- node + GPU miner.

See `README_DOCKER.md` for the full deployment and persistence guide.

The current project CPU image repository is
`ghcr.io/tokenizedrealutility/tru-node`. Use an explicitly published, verified
version tag or immutable digest. This README does not assert that a 0.08.8 image
has been published. Container status `Up` alone does not establish that RPC is
listening, synchronization completed, or a branch was fully validated.

When replacing a container, retain its named data volume and all wallet mounts.
Quantum users must also persist the actual `.pq01` and `.pq01.recovery` paths;
mounting only the ordinary encrypted wallet files is insufficient. Never run two
containers signing from cloned wallet state. Building or pulling a new image
does not update an existing container until it is deliberately recreated.

---

# Configuration

TRU reads INI-style settings from `tru.conf`. Sections and key spelling matter. This reference was checked against the supplied `NEW_TRU` and `TRU-Core` source snapshots and the NCFT agent configuration package (October 2026). **Merge changes into your existing working `tru.conf`; never replace a live node's wallet, peer, or oracle settings wholesale.**

## Annotated `tru.conf` example

```ini
# TRU MAINNET EXAMPLE — review values for your own machine
[network]
rpcport=21832
p2pPort=21833
listen=1
rpcbind=127.0.0.1
rpcAllowRemote=0
rpcMaxConnections=32

# Bootstrap peers. Comma-separated IP:port pairs; no spaces after commas.
addnode=137.184.68.43:21833
#seeds=137.184.68.43:21833
#externalip=YOUR_PUBLIC_IP

# Automatic cumulative-work recovery: enabled by default in current builds.
+# An explicit setting overrides the supported environment fallback.
automaticReorg=1

# Optional privileged RPC wallet-send feature, DISABLED by default.
# Keys may be set here in [network] or [default], but not twice.
#rpcWalletSend=0
#rpcWalletSendMaxAtoms=1000000
# Alternative equivalent names recognized by this build:
#TRU_RPC_WALLET_SEND_ENABLE=0
#TRU_RPC_WALLET_SEND_MAX_ATOMS=1000000

[default]
node.ip=127.0.0.1
node.port=21832
#peers=137.184.68.43:21833

# AI oracle funding / wallet options (only configure when needed).
#oracle.address=YOUR_TRU_ORACLE_ADDRESS
#oracle.wallet=tru.dat
#oracle.wif=YOUR_PRIVATE_WIF_DO_NOT_COMMIT

[agent_checkpoint]
# Enable only after installing and reviewing the private policy file.
enabled=0
#policy_file=/home/YOUR_USER/tru-agent-policies/axona/policy.json

[chain]
# Documentary example: see notes below about which fields are consumed.
chainName=TRUMain
networkType=mainnet
```

## Verified settings and usage

| Section | Key | Purpose / validated behavior |
|---|---|---|
| `[network]` | `rpcport` | Privileged Core JSON-RPC port (default 21832). |
| `[network]` | `p2pPort` | P2P listening port (default 21833). |
| `[network]` | `listen` | Enable/disable inbound peer listening (`0` or `1`). |
| `[network]` | `rpcbind` | Bind address. Keep `127.0.0.1` for ordinary deployments. |
| `[network]` | `rpcAllowRemote` | Explicit approval required before privileged RPC can bind to a non-loopback address. Do not expose RPC publicly. |
| `[network]` | `rpcMaxConnections` | Positive value up to 256; default 32. |
| `[network]` | `addnode` | Comma-separated bootstrap `IP:port` peers. |
| `[network]` | `seeds` | Alternative/additional bootstrap peer list parsed by P2P initialization. |
| `[network]` | `externalip` | Advertised external IP where supported by the node startup logic. |
| `[network]` | `automaticReorg` | Explicit enable/disable of automatic cumulative-work recovery. Current default is enabled; explicit configuration takes precedence over the supported environment fallback. Inspect effective `fork_recovery` status. |
| `[network]` or `[default]` | `rpcWalletSend` / `TRU_RPC_WALLET_SEND_ENABLE` | Optional local RPC wallet sending (strict `0`/`1`). Default disabled. Use only one spelling/section. |
| `[network]` or `[default]` | `rpcWalletSendMaxAtoms` / `TRU_RPC_WALLET_SEND_MAX_ATOMS` | Spending cap as a positive number of atoms, or explicitly `unlimited`; do not duplicate. |
| `[default]` | `node.ip` | RPC host used by the legacy AI oracle service. |
| `[default]` | `node.port` | RPC port used by the legacy AI oracle service. Set explicitly; a code path otherwise defaults to 8001, which may not be the RPC port. |
| `[default]` | `peers` | Additional explicit peer argument read by Core startup. |
| `[default]` | `oracle.address` | Funding identity used by AI-oracle anchoring flows. |
| `[default]` | `oracle.wallet` | Oracle wallet file/path selector, used by a wallet-backed oracle flow. |
| `[default]` | `oracle.wif` | Private-key oracle path used by a separate oracle flow. Sensitive; do not publish this in a shared config. |
| `[agent_checkpoint]` | `enabled` | `0` or `1`; approval policy is disabled by default. |
| `[agent_checkpoint]` | `policy_file` | Absolute private path to checkpoint authorization/budget policy JSON; required when enabled. |

**`[chain]` caveat:** The supplied source snapshot defines `chainName` and `networkType` on its blockchain object, but the inspected node-startup configuration path did not establish that changing `[chain] chainName` or `networkType` switches the active consensus network. These are retained as existing example entries, **not** as a verified way to switch safely between mainnet, testnet, and regtest.

## AI agents, NCFT transfer, and automatic checkpoints

An NCFT can identify an AI agent, but its runtime is separate from its on-chain identity. The new editor/holder handover capabilities are enforced through token authority, RPC workflows, local manifests, and agent runtime controls: **there is no standalone `tru.conf` switch named `agentTransfer`, `handover`, or `autoEpoch` in the supplied Core source**.

The only verified `[agent_checkpoint]` entries are `enabled` and `policy_file`. The code rejects other keys in that section. Automatic checkpoint timing, per-day usage limits, and total fee budget are enforced by the external **policy JSON** (`min_interval_seconds`, `max_per_day`, `total_budget_atoms`, etc.), not directly by `tru.conf`.

Set up each agent's private identity, memory, token authority, and automatic watcher according to the separate `NCFT-Ai-Agents-main/README.md` and `SERVICE.md`. The optional `tru-agent-auto@.service` starts a watcher, **not** TRU Core or an AI inference model. Enabling checkpoint approval by itself does not run a watcher or cause an epoch automatically. Transfer of an NCFT is not equivalent to automatically moving off-chain private memories, service credentials, or running infrastructure. The receiving owner must receive those separately under an authenticated handover process.

The checkpoint implementation also supports environment fallbacks when the INI entries are absent:

```bash
TRU_AGENT_CHECKPOINT_ENABLE=0
TRU_AGENT_CHECKPOINT_POLICY_FILE=/absolute/private/path/policy.json
```

The runtime and model provider environment is separate from `tru.conf`. Recognized Core provider credential names include `OPENAI_API_KEY`, `XAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `NEMOTRON_API_KEY`, `NEMOTRON_ENDPOINT`, `OOBABOOGA_API_KEY`, and `CUSTOM_AI_API_KEY`. Loading provider credentials does **not** confer token ownership or issuer/editor authorization. Never place API keys, wallet passwords, or private memory files in a GitHub README or public agent image directory.

## Configuration, environment, and CLI are different

- `TRU_RPC_WALLET_SEND_ENABLE` and `TRU_RPC_WALLET_SEND_MAX_ATOMS` are **both** actual environment variable names **and** explicitly supported `tru.conf` aliases in this build. Normal operators should prefer `rpcWalletSend` and `rpcWalletSendMaxAtoms` in the INI file, with spending disabled unless needed.
- `TRU_RPC_TOKEN`, `TRU_RPC_COOKIE_FILE`, and relevant RPC credential settings are RPC authentication/runtime mechanisms, not interchangeable with the `rpcbind` line. Privileged RPC uses authenticated transport in the supplied source; keep its port on loopback and protect cookie/token files.
- `--conf`, `--rpcport`, `--rpcbind`, `--enable-explorer`, and `--explorer-port` are node launch options; do not assume writing those option names in an INI section enables identical behavior.
- Agent worker inputs such as `TRU_AGENT_CODE`, `TRU_AGENT_HOME`, and `TRU_CORE_CLI` belong in the separately protected watcher service environment file, **not** in `[agent_checkpoint]`.
- Environment-only testing/recovery switches discovered in the Core should not be published as ordinary user configuration without separate review.

## Operational notes

1. Keep comments on separate lines and avoid spaces inside comma-separated peer entries.
2. Some peer configuration paths expect literal IP addresses instead of DNS hostnames.
3. `automaticReorg=1` affects how a node responds to competing cumulative-work branches; do not change it casually on production nodes.
4. Keep privileged RPC bound to `127.0.0.1`. Even with authentication, avoid remote direct exposure; in particular the Core refuses remote binding when RPC wallet spending is enabled.
5. Keep `tru.conf` and private policy files readable only by the relevant operating-system account. An actual WIF and API secrets should live in tightly protected private credential storage rather than any distributed example file.
6. Source-level feature support does not guarantee the running executable was rebuilt from that exact source revision. Restart with the intended build and validate the effective configuration before running a funded agent automation.


---

# Implementation Status

TRU is a working independent blockchain, but the project intentionally distinguishes implemented functionality from incomplete scaffolding.

## Implemented core

- Proof-of-Work consensus
- UTXO validation and persistence
- cumulative-work fork choice and reorganizations
- deterministic difficulty validation
- CPU mining
- OpenCL GPU mining
- mempool admission and double-spend handling
- P2P transaction/block transport
- ECDSA signatures
- ECDSA multisig
- activated PQ01 WOTS+ and market validation at height 50,000
- dedicated quantum funding, signing, explicit submission, and saved-byte retry
- recovery status and bounded automatic cumulative-work reorganization
- stateful contract storage
- gas metering
- deterministic chain-state reads
- SHA-256 / SHA3 / BLAKE2b-related script functionality
- FT / NFT / SFT / NCFT token issuance
- token ownership/metadata tracking
- TRUSCRIPT inscriptions and transfers
- AI provider registry
- AI request/response anchoring
- Living Token Evolution and evolution commitments
- HD wallet functionality
- interactive responsive node CLI
- standalone `tru-cli`
- JSON-RPC server
- block explorer
- Docker deployment support
- size-aware large-block assembly/relay infrastructure

## Partial / intentionally incomplete

- `OP_EXTERNALDATA` — placeholder generic external data
- `OP_DATAFEED` — placeholder generic data-feed values
- `OP_DELEGATECHECK` — stub
- `OP_TOKEN_BALANCE` — partial
- `OP_BURN_TOKEN` — partial
- NOVO/BSTY bridge opcodes — bridge scaffolding, not a live production bridge

These items should not be represented as completed production capabilities until their validation and trust models are finished.

---

# Testing and Qualification

Test outcomes describe the supplied source revisions and fixtures, not every
future deployment. Keep the run logs, source provenance, and machine-readable
qualification results with release records.

| Test area | Observed evidence and scope |
|---|---|
| 0.08.5 regressions / isolated chain | Mainnet-dormant and test-height build guards; real-PoW maturity prefix; preactivation behavior; invalid WOTS/payload mutation rejection; market purchase, partial fill, swap, refund, and journal/restart paths passed. |
| Historical replay | Supplied historical snapshot replay through height 45,837 and restart checks passed. This is bounded snapshot evidence, not an ongoing audit of every later mainnet block or equivalence of all local auxiliary records. |
| 0.08.5 network/template | Mixed-version preactivation synchronization, activated template outputs/submission, upgraded relay, fresh IBD across activation, higher-work reorg, and restart tests passed. External pool software was a separate integration requirement. |
| 0.08.7 maintenance | Focused regressions and both full builds passed. |
| 0.08.8 wallet candidate | Both full node/client builds, version/help checks, installer checks, and native quantum-state regressions passed. Native tests cover v1 migration, replica repair, conflicting history rejection, signing-intent persistence through failure/crash, saved-byte retry, backup authentication, and recovery quarantine. |
| 0.08.8 controlled live suite | Both candidate source variants verified; signed WOTS/market/OP_SIZE real-PoW fixture; 128-block disconnect; shorter/heavier winner; fresh IBD; mixed 0.08.6 serving; ledger-state comparison; prepared retry; deliberate crash/restart; corrupt marker and missing undo refusal all passed. |
| Remaining 0.08.8 release checks | Throwaway-wallet RPC backup/restore/sign/retry integration remains pending. Qt GUI runtime and independent SDK/browser signer are not qualified by these results. |

The **4,096-block policy boundaries** were checked; the live fixture exercised
**128 blocks disconnected**, not a 4,096-block live reorg. Controlled loopback
P2P tests do not reproduce every WAN, CGNAT/Starlink, remote pool, hostile-load,
power-loss, or filesystem failure condition. A passing recovery suite does not
mean competing branches can never occur.

The supplied qualification package uses isolated source copies, throwaway wallet
material, private test activation, loopback peers, and test databases. Never run
fault injection, intentional state corruption, or restore experiments on a
funded production wallet. Production activation remains height 50,000.

---

# Security Notes

TRU is still an evolving independent chain and should be treated accordingly.

Current considerations include:

- WOTS+ one-time key state and current quantum backups are essential; local replicas are not rollback-proof and seed-only recovery is not provided.
- A protected PQ01 output does not convert legacy ECDSA addresses, token ownership, or every application into a quantum-resistant system.
- Fork recovery has finite windows and requires undo/state availability; upgrading does not reconstruct historical undo that was already pruned.

- The chain is primarily enforced by one codebase.
- It has not yet had the years of adversarial exposure of mature public blockchains.
- Independent security review and consensus reimplementation would strengthen production readiness.
- Consensus changes should be tested across multiple nodes before real value depends on them.
- Large-block settings must be coordinated network-wide.
- AI-provider API keys should never be written to chain state or committed to Git.
- Bridges require substantially more security review before production use.
- Very large configured block limits must not be confused with benchmarked sustainable throughput.

For public deployments:

```text
21833/tcp  P2P   -> may be public
21832/tcp  RPC   -> keep private / authenticated
8001/tcp  Explorer -> expose only as intended
```

Privileged Core JSON-RPC requires transport authentication.

Default RPC bind: 127.0.0.1
Default RPC port: 21832
Public P2P port: 21833

Direct browser access to privileged Core RPC is forbidden.
Browser applications use the restricted same-origin web gateway.
Core RPC credentials are never exposed to browser JavaScript.

Remote Core RPC requires explicit configuration and should be
protected by network/firewall controls in addition to RPC authentication.

---

# Scaling Direction

TRU's present architecture provides a foundation for substantially larger L1 blocks, but block size alone is not the end of scaling.

The next major performance areas are:

1. parallel validation of independent UTXO transactions,
2. more efficient signature-verification batching,
3. indexed mempool dependency/conflict handling,
4. streamed/chunked large-block propagation,
5. incremental decoding rather than giant in-memory payloads,
6. storage and state-access benchmarking,
7. multi-node propagation testing,
8. block validation benchmarks at progressively larger sizes,
9. P2P Frame V2 for 4 GiB+ transport,
10. continued fuzzing and adversarial testnet work.

TRU's UTXO model creates a natural path toward parallel validation because independent transactions that consume different UTXOs can be checked concurrently and committed deterministically.

The project should measure real throughput rather than advertise configured block capacity as TPS.

---

# Additional Documentation

Use the reviewed build instructions above. Do not run a destructive rebuild or
fresh-chain helper against a live wallet/database. A resync changes chain state,
not private keys, but confirmed balances and mining rewards still depend on the
validated active branch; recovery cannot guarantee that rewards from a losing
branch remain spendable.

More focused documentation is available in the repository:

| File | Purpose |
|---|---|
| `README_API.md` | JSON-RPC API reference |
| `README_DOCKER.md` | Docker/node/miner deployment |
| `README_OPCODES.md` | Script and opcode reference |
| `README_TOKENS.md` | FT/NFT/SFT/NCFT token documentation |
| `TRU_CLI_README.md` | `tru-cli`, `getinfo`, `getbalance`, raw RPC usage |

The top-level README is intended to describe the **current TRU system as a whole**. Feature-specific READMEs should be kept synchronized with the implementation as the protocol evolves.

---

# Project Direction

TRU is being developed around a specific idea:

> **Use a deterministic UTXO Proof-of-Work blockchain as the ownership and settlement layer for programmable real-world utility, native digital assets, and verifiable AI-assisted state.**

The objective is not to make AI itself determine consensus. Instead, TRU provides a deterministic chain where AI-generated activity, evolving token state, ownership, smart-contract execution, and cryptographic commitments can coexist without requiring every validating node to trust or reproduce the same model output.

That combination is the core of **Tokenized Real Utility**.

---

# Links

### Source and deployment

- Core source: [TokenizedRealUtility/TRU-Core](https://github.com/TokenizedRealUtility/TRU-Core)
- SDK: [TokenizedRealUtility/TRU-SDK](https://github.com/TokenizedRealUtility/TRU-SDK)
- CPU container repository: `ghcr.io/tokenizedrealutility/tru-node`
- Deployment guide: `README_DOCKER.md` in the matching source release.

Check release/tag availability and the running binary's version before an
upgrade. Historical `agreatopportunity` launch image references above document
the launch; they are not current deployment recommendations. Independent miner,
SDK, marketplace, and browser-wallet releases have their own compatibility scope.

### Network

| | |
|---|---|
| Block explorer | [tokenizedrealutility.com](https://tokenizedrealutility.com/) |
| Web wallet | [tokenizedrealutility.com/wallet.html](https://tokenizedrealutility.com/wallet.html) |

### Community

| | |
|---|---|
| Telegram | [t.me/TRUBLOC](https://t.me/TRUBLOC) |
| X | [@TRUBLOCKCHAIN](https://x.com/TRUBLOCKCHAIN) |
| Reddit | [r/TRUBLOC](https://www.reddit.com/r/TRUBLOC/) |
| Discord | [discord.gg/utFCQdSdC](https://discord.gg/utFCQdSdC) |
| Signal | [Join group](https://signal.group/#CjQKIIenthb40lSmT47CstsKTwKkNua3ecYfcD2Ajqw3N5A4EhC1thDa8b4Cw9MofM2OT9tv) |

Issues and pull requests are welcome on this repository.

---

**TRU — Tokenized Real Utility**
*UTXO ownership. Proof-of-Work settlement. Stateful contracts. Native assets. Verifiable AI evolution.*
