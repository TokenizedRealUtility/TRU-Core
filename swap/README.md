# TRU-SWAP-B — TRU ↔ BSTY Cross-Chain Engine

This directory is the coordinator/adapter layer above the already-frozen
`TRU-SWAP-V1` HTLC.

## What it does

- TRU adapter through the native TRU CLI (`truam-cli` preferred, `tru-cli` fallback) and SWAP-A RPC.
- BSTY adapter through `globalboost-cli`.
- Exact 103-byte HASH160/timestamp HTLC construction.
- BSTY P2SH wrapping.
- TRU/BSTY funding helpers.
- TRU/BSTY claim and refund helpers.
- BSTY spend watcher and HASH160 preimage extraction.
- TRU transaction preimage observation helper.
- SWAP-A durable-state transitions.
- BSTY signing isolated into a short-lived helper process.

## What it does not do

- It does not modify consensus.
- It does not change the frozen HTLC bytes.
- It does not store a preimage in the SWAP-A LevelDB record.
- It does not put BSTY private keys into the coordinator state.
- It does not make meaningful mainnet funds safe by itself. SWAP-C remains the
  full E2E/failure/restart/mainnet hardening gate.

## Default paths

- TRU CLI: auto-detects `~/NEW_TRU/build-native/bin/truam-cli`, then `tru-cli`
- TRU conf: `~/NEW_TRU/tru.conf`
- BSTY CLI: `~/globalboost/src/globalboost-cli`
- BSTY wallet: `bsty_mining`

Override with:
`TRU_SWAP_TRU_CLI`, `TRU_SWAP_TRU_CONF`, `TRU_SWAP_BSTY_CLI`,
`TRU_SWAP_BSTY_WALLET`.

`TRU_SWAP_RPC_TOKEN` must be present in the environment.

## First commands

```bash
cd ~/NEW_TRU
python3 swap/tru_bsty_swap_engine.py selftest
python3 swap/tru_bsty_swap_engine.py doctor
```

To inspect a live SWAP-A record:

```bash
python3 swap/tru_bsty_swap_engine.py status --swap-id <SWAP_ID>
```

To derive the exact BSTY P2SH contract from that record:

```bash
python3 swap/tru_bsty_swap_engine.py bsty-contract --swap-id <SWAP_ID>
```

## Secret custody

Use:

```bash
python3 swap/tru_bsty_swap_engine.py new-secret \
  --output ~/.tru/swap-secrets/<name>.json
```

The secret file is written mode 0600. The preimage is never printed. Do not
paste, commit, or sync the secret file.

## Funding

The engine enforces `TRU_FIRST` / `BSTY_FIRST`.

```bash
python3 swap/tru_bsty_swap_engine.py fund-tru --swap-id <SWAP_ID> --wait
python3 swap/tru_bsty_swap_engine.py fund-bsty --swap-id <SWAP_ID> --wait
```

Only run the chain appropriate to the current swap state/participant.

## BSTY claim/refund signing

The coordinator delegates signing to `bsty_wallet_signer.py`. The signer calls
the local BSTY wallet's `dumpprivkey` internally and returns only a signature.
The coordinator never receives the WIF/private key. If the BSTY wallet is
encrypted, unlock it locally first; do not place its passphrase in this engine.

## Mainnet note

SWAP-B is the engine layer. SWAP-C will exercise:
- two-party E2E,
- restart recovery,
- adverse timing,
- reorg/confirmation policy,
- both claim directions,
- both refund directions,
- timeout safety margins,
- final mainnet gate.

Use only tiny test value until SWAP-C closes.

## V2 state progression fix

The first successful claim moves `BOTH_FUNDED -> SECRET_OBSERVED`; the opposite-chain claim moves `SECRET_OBSERVED -> SETTLED`.
