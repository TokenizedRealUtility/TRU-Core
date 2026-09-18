# TRU-SWAP-AGENT-01A — Local HTTP Adapter Foundation

Status: foundation / fail-closed on unproven mutating swap operations.

## Security boundary

- Binds only `127.0.0.1:8645`.
- Exact-origin CORS allowlist from `TRU_SWAP_AGENT_ORIGINS`; never `*`.
- `/v1/health` issues an ephemeral in-memory `X-Swap-Pairing` token to an allowed browser origin.
- Every other `/v1/*` endpoint requires that pairing token.
- `TRU_SWAP_RPC_TOKEN` is inherited by the agent process and is never returned to the browser.
- No private-key, WIF, passphrase, RPC-password, or preimage endpoint exists.
- SQLite state is mode 0600 under `swap/runtime/local-agent.sqlite3`.

## Real in 01A

- `POST /v1/health`
- `POST /v1/board/list`
- `POST /v1/board/post`
- `POST /v1/board/withdraw`
- `POST /v1/record` for a locally registered swap view
- `POST /v1/contracts` with typed `address` vs `script` funding targets
- `POST /v1/verify`
- live BSTY P2SH derivation
- TRU bare-script descriptor with no synthetic contract address

## Deliberately fail-closed in 01A

- `/v1/offer/create`: blocked until fresh per-swap TRU role-key allocation exists.
- `/v1/offer/import`: blocked until the direct-offer envelope carries complete public contract parameters.
- `/v1/fund`: blocked until asynchronous confirmation/restart reconciliation exists.
- `/v1/exits/lodge` and `/v1/exits/disarm`: blocked until the persistent exit watcher is proven.
- `/v1/board/take`: blocked until reservation can atomically mint a fresh-key swap.

This patch does not modify the current SWAP-B funded E2E path.

## Start

```bash
cd ~/NEW_TRU
bash swap/agent/run_agent.sh
```

Optional exact origins override:

```bash
export TRU_SWAP_AGENT_ORIGINS='https://tokenizedrealutility.com,https://www.tokenizedrealutility.com'
```

## Safe readiness check

```bash
cd ~/NEW_TRU
python3 swap/agent/tru_swap_agent.py check
```

The output reports readiness only and never prints the RPC token.

## Register an existing swap for read-only web inspection

```bash
python3 swap/agent/tru_swap_agent.py register-view   --swap-id <SWAP_ID>   --give-chain tru   --get-chain bsty   --min-conf 1
```

Then `/swap.html?swap=<SWAP_ID>` can read the record and derive typed contract descriptors through the agent.

## Web pairing glue

The helper adds one missing line to each live browser adapter: capture the `X-Swap-Pairing` response header from `/v1/health`.

It is not applied automatically:

```bash
python3 ~/NEW_TRU/swap/agent/apply_web_pairing_glue.py ~/NEW_TRU/web
```

Point it at the actual web root if your latest files live elsewhere.
