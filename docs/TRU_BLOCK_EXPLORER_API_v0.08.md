# TRU v0.08.1 — Block Explorer HTTP API reference

> **Source-audited reference** from `NEW_TRU/src/blockchain.cpp` (inside `startExplorerServer()`) plus its included `tru_data_provider_v1_routes.inc`; cross-compared with cleaned `TRI-Core/blockchain.cpp`. This documents **registered routes**, not a live-site availability guarantee.

**Registered routes:** 33 GET, 3 POST, plus 2 `OPTIONS` handlers that deliberately return 405 for the two JSON-RPC gateway paths. `GET /api/submitblock` is informational, not a submission operation.

## Base URL and requests

The public production hostname used for TRU is `https://tokenizedrealutility.com`. These routes are registered on the **Explorer server port**; they will appear on the public hostname only if your web server/reverse proxy forwards them. Check actual deployment for status and any path rewriting.

```bash
curl -fsS https://tokenizedrealutility.com/api/health
curl -fsS https://tokenizedrealutility.com/api/supply
curl -fsS https://tokenizedrealutility.com/api/chain
curl -fsS "https://tokenizedrealutility.com/api/blocks"
curl -fsS "https://tokenizedrealutility.com/api/tokens?start=0&limit=20"
curl -fsS "https://tokenizedrealutility.com/api/hashrate_history?blocks=100"
```

### URL placeholders

- `<address>` is a TRU mainnet Base58 address beginning with `T` and matching the route’s regex.
- `<txid>` is a 64-character hexadecimal transaction identifier.
- `<blockhash>` is a hexadecimal block identifier (the `/block/...` route matches hexadecimal lengths permissively, with validity checked by the implementation).
- `<did>` matches the limited `[a-zA-Z0-9:]+` path form used in this source, not arbitrary URL-encoded DID documents.
- `<ip>/<port>` under `/api/peer/...` is restricted by the path regex to IPv4-like dotted characters and decimal port.

## All registered GET routes

### Data provider

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/chain` | Chain metadata for discovery/indexers | none |
| `GET /api/health` | Health/status; returns 503 when unhealthy | none |
| `GET /api/supply` | Structured supply snapshot; may be unavailable | none |
| `GET /api/supply/<total|circulating|max>` | Plain-text supply amount for selected category | `total`, `circulating` or `max` in path |

### Chain and activity

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/stats` | Dashboard chain, peer, miner, health and activity statistics (tip cached) | none |
| `GET /api/blocks` | Latest up to ten active-chain blocks; includes cadence/observed timestamp metrics | none |
| `GET /block/<blockhash>` | Block lookup by hexadecimal path identifier | hex block hash in path |
| `GET /api/price/tru` | TRU price endpoint; explicit unavailable when no verified USD source | none |

### Address and transactions

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/addresses` | Active address listing from address cache | `start=0`, `limit=50` (1..200), `search`, `sort=balance_desc|balance_asc|txCount_desc|txCount_asc` |
| `GET /api/address/<address>` | Address balance, activity, tokens and TRUScripts | TRU mainnet address in path |
| `GET /api/transactions` | Paginated transaction listing, optionally restricted to address | `start=0`, `limit=10` (max 100), optional `address` |
| `GET /api/transaction/<txid>` | Transaction detail by 64-hex txid | txid in path |

### Tokens and contracts

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/token-burn` | Burn / retirement information | none |
| `GET /api/tokens` | Paginated live token holdings, optional owner filter | `start=0`, `limit=10` (max 100), optional `address` |
| `GET /api/contracts` | Indexed smart-contract summaries | none |
| `GET /api/contracts/<address>/txs` | Contract-related transactions by contract address | contract address in path |

### Wallet data

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/wallet/tokens/<address>` | Confirmed token holdings for one address | TRU mainnet address in path |
| `GET /api/wallet/token-transactions/<address>` | Per-address token transaction history | TRU mainnet address in path |

### TRUScripts and social

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/truscripts` | Paginated TRUScript/inscription list | `page=1`, `limit=50` (cap 100) |
| `GET /api/truscripts/<txid>` | One TRUScript by inscription transaction ID | txid in path |
| `GET /api/debug/truscripts` | Diagnostics for inscription discovery | none; debug/diagnostic endpoint |
| `GET /api/did/<did>/posts/count` | Number of posts for DID | DID in path |
| `GET /api/feed/<did>` | DID-related social feed | DID in path |
| `GET /api/did/<did>` | Resolve DID record | DID in path |

### Mining and peers

| Endpoint | Purpose | Path/query arguments |
|---|---|---|
| `GET /api/miner-reports` | P2P-reported miner telemetry: unverified advertisements | none |
| `GET /api/miners` | Miner list, active producer and recent block statistics | `timeout=2` min (clamped 1..10), `recent=50` blocks (1..500) |
| `GET /api/hashrate_history` | Per-block hashrate estimates | `blocks=100`, clamped 10..500 |
| `GET /api/difficulty_history` | Difficulty history | none |
| `GET /api/uptime` | Explorer/node uptime | none |
| `GET /api/peers` | Peer list/snapshot | none |
| `GET /api/peer/<ip>/<port>` | Peer detail by IPv4 and port | IPv4, port in path; optional `session` |
| `GET /api/hashrate` | Current/derived network hashrate summary | none |
| `GET /api/submitblock` | GET explains that mining submission requires POST | none |

## All registered POST routes

| Endpoint | Purpose | Request |
|---|---|---|
| `POST /api/wallet/rpc` | Selected self-custody read/build/signed-submit methods | JSON-RPC object `{jsonrpc,method,params,id}`; allowlisted methods only |
| `POST /api/mining/rpc` | Selected mining/read methods through Core | JSON-RPC object `{jsonrpc,method,params,id}`; allowlisted methods only |
| `POST /api/submitblock` | Submit block through explorer mining gateway | JSON object with `blockHex` or `hex` containing serialized block hex |

The explicit `OPTIONS /api/wallet/rpc` and `OPTIONS /api/mining/rpc` routes respond **405** (`Allow: POST`). This means the web gateway is **not** an unrestricted cross-origin RPC endpoint. Browsers, same-origin deployments and CORS behavior depend on the actual frontend/proxy setup.

### Example: public allowlisted Core method

```bash
curl -sS https://tokenizedrealutility.com/api/wallet/rpc \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getblockcount","params":{},"id":1}'
```

The wallet and mining gateways are **two restricted forwarding paths**: method names are checked against explicit server-side allowlists; requests face per-client rate limits, body limits, concurrent submission caps, and separate Core authentication. The public gateway does not grant Core private-key access just because a method is callable.

**Wallet gateway methods (declared: 45):**

`committokenevolutionsigned`, `createTransferTRUScriptTransaction`, `createburntokentransaction`, `createcontracttransaction`, `createrawtransaction`, `createsendtokentransaction`, `decoderawtransaction`, `getAIProviders`, `getAITokenState`, `getDIDMapping`, `getTRUScriptDetails`, `getTRUScripts`, `getaddresstransactions`, `getallminers`, `getblockcount`, `getblocktemplate`, `getchaininfo`, `getcontracts`, `getdesktopinfo`, `getmagicsecret`, `getmempooltransactions`, `getminingleaderboard`, `getpeerinfo`, `getrawmempool`, `gettokenmetadata`, `gettokenutxo`, `gettransaction`, `gettxout`, `inscribeTRUScriptSigned`, `issuetokensigned`, `listmagiclocks`, `listmempooltransactions`, `listtransactions`, `listunspentWeb`, `preparemagicsecret`, `previewtokenevolution`, `registerDIDSigned`, `reportmineractivity`, `sendrawtransaction`, `sendrawtransactionWeb`, `submitblock`, `testAIProvider`, `tokenmetadisplay`, `verifytokenevolution`, `verifytokenmetadata`

**Mining gateway methods (declared: 8):**

`decoderawtransaction`, `getblockcount`, `getblocktemplate`, `getchaininfo`, `getmempooltransactions`, `getrawmempool`, `reportmineractivity`, `submitblock`

**Warning:** `getminingleaderboard` appears in the wallet gateway allowlist but **is not registered** in `rpc_server.cpp`; currently expect a JSON-RPC method-not-found error.

## Data semantics and limitations

- `/api/miner-reports` and `p2pReportedHashrate` reflect **advertised observational telemetry**; the source explicitly says reported work and mining address ownership are not cryptographically verified. Do not use reports as authoritative consensus hashrate.
- `/api/hashrate_history` returns sampled/derived rates from active-chain observations. Difficulty, block-header timestamp and observer timestamp are separate values.
- `/api/blocks` provides a recent ten-block window with `timestamp`, `observedAt`, `clockSkewSeconds`, cadence and provenance fields where available. Do not interpret every reported cadence as a final wall-clock interblock interval.
- `/api/price/tru` does **not** constitute a verified USD price feed; the handler currently responds with a not-configured/unavailable explanation. Do not display an invented market price.
- `/api/tokens` iterates confirmed `tokenUTXO:` entries, not all historical issuance transactions. An address filter is applied before pagination; an exhausted balance may not appear as a current holding.
- `/api/wallet/tokens/<address>` is a **read-only public holdings view**. Its implementation may perform a bounded derived-index repair on first access, so a request can be more expensive than a simple map lookup. It does not grant signing authority.
- `/api/supply/<circulating>` may return **503** if the circulating-supply policy has not been reviewed; `/api/supply` can be 503 if the snapshot is unavailable. Watch status codes, not only JSON.
- Some endpoints expose internal/debug/peer information. Before promoting a public API, audit the payloads, response caching, privacy and rate limits. Consider restricting `/api/debug/truscripts` and peer-detail routes to operators if unnecessary for users.
- `GET /api/submitblock` is an explanatory message; actual mining submission is **POST** with a JSON `blockHex` (or `hex`) string, validation, rate limiting and payload limits. The other route `/api/mining/rpc` allows `submitblock` as JSON-RPC.
- CORS is not universal. Some GET handlers add `Access-Control-Allow-Origin: *`; others do not. Do not promise that every route works in cross-origin browser JavaScript without reverse-proxy configuration.

