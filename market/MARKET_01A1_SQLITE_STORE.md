# MARKET-01A.1 — Durable Public SQLite Intent Store

Status: **IMPLEMENTED / LOCAL STORE FOUNDATION**

This patch builds the persistence layer beneath the future public market API.

It deliberately has **no HTTP listener** and cannot create/reserve/take/fund a
swap.

## Durable database

Default production path initialized by the installer:

`~/NEW_TRU/market/data/market_intents.sqlite3`

Directory mode: `0700`

Database mode: `0600`

SQLite settings:

- WAL journal
- `synchronous=FULL`
- foreign keys enabled
- 10 second busy timeout

## Atomic operations

The store implements:

- `post(intent)`
- `list_active(pair_id=None)`
- `get_public(advert_id)`
- `withdraw(advert_id, owner_token)`
- `counts()`

Write paths use `BEGIN IMMEDIATE`.

## Cancellation ownership

Every post creates:

- public random `advertId`
- private random `ownerToken`

Only `SHA256(ownerToken)` is persisted.

The plaintext owner token is returned only to the caller that created the
advert and is not present in public serialization.

MARKET-01A.2 will decide how the HTTP client stores that capability safely.

## Duplicate rule

An identical canonical `intentHash` may have only one `ACTIVE` advert.

This prevents accidental duplicate visible liquidity from retries.

Once the original advert is `WITHDRAWN` or `EXPIRED`, the same intent may be
posted again and receives a fresh `advertId`.

## Expiration

Expiration is materialized durably:

`ACTIVE -> EXPIRED`

when the store is read or written at/after `expiresAt`.

There is no background thread in 01A.1.

## Pair activation

All posts pass through MARKET-01A.0 validation.

Current posting state:

- `TRU_BSTY` — active
- `TRU_BTC` — planned / rejected
- `TRU_BSV` — planned / rejected

Future chains are activated only by an explicit registry/adapter patch.

## Public/private boundary

Public advert output contains no:

- owner token
- owner-token hash
- preimage
- secret hash
- role keys
- destinations
- swap ID
- wallet/RPC credential
- pairing credential

## Still intentionally absent

- HTTP server
- public hostname
- rate limiting
- abuse controls
- reservation
- taker workflow
- swap minting
- wallet calls
- chain calls
- funding
- trade tape

## Next

`MARKET-01A.2 — Public Intent HTTP API`

The next patch should expose only the store operations needed for:

- health
- pair registry
- list
- post
- withdraw

and should remain incapable of reservation/take or coin movement.
