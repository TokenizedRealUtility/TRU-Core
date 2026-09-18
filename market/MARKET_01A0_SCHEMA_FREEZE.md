# MARKET-01A.0 — Multi-Chain Public Intent Schema Freeze

Status: **FOUNDATION FREEZE**

Schema: `TRU-MARKET-INTENT-V1`

## Goal

Freeze one small public advert shape that can serve TRU/BSTY now and later add
TRU/BTC, TRU/BSV, or another explicitly registered pair without redesigning
the public market protocol.

This patch creates schema/validation artifacts only. It does **not** create a
public server, open a port, alter the swap agent, create a swap, reserve an
advert, move coins, or modify consensus/wallet behavior.

## Registry model

Assets and pairs are explicit registries.

Current state:

- `TRU` — active
- `BSTY` — active
- `BTC` — planned
- `BSV` — planned
- `TRU_BSTY` — active
- `TRU_BTC` — planned
- `TRU_BSV` — planned

`planned` is only schema registration. It is **not** a claim that an atomic
swap adapter for that chain is implemented or production-ready.

A future chain is added by registering:

1. asset identity,
2. chain identity,
3. decimals,
4. adapter identity/state,
5. one or more explicit pair entries.

The V1 advert structure does not change.

## Canonical pair convention

Every pair is:

`BASE_QUOTE`

For `TRU_BSTY`:

- base = `TRU`
- quote = `BSTY`
- displayed price = BSTY per 1 TRU

The same rule applies to future pairs:

- `TRU_BTC` = BTC per 1 TRU
- `TRU_BSV` = BSV per 1 TRU

## Quantity encoding

Amounts are unsigned base-10 **atom strings**, never binary floats.

Example with 8 decimals:

- `100000000` atoms = `1.00000000` coin
- `10000000000` atoms = `100.00000000` coins

Each asset registry entry supplies its decimal count.

This avoids float rounding and keeps one schema usable across chains with
different precision rules.

## Client intent fields

Required fields:

- `schemaVersion`
- `pairId`
- `side`
- `baseAtoms`
- `quoteAtoms`
- `baseMinConfirmations`
- `quoteMinConfirmations`
- `fundingOrder`
- `makerRefundSeconds`
- `takerRefundSeconds`
- `lifeSeconds`

Sides:

- `SELL_BASE`
- `BUY_BASE`

Funding order:

- `MAKER_FIRST`
- `TAKER_FIRST`

The first-funded leg must have at least six hours more refund time in V1.

## Public server-added fields

A public advert adds:

- `advertId`
- `intentHash`
- `createdAt`
- `expiresAt`
- `status`

`intentHash` is:

`SHA256(canonical JSON of the validated client intent)`

Canonical JSON is UTF-8, sorted keys, compact separators, and no optional
fields.

## Owner/cancellation capability

MARKET-01A.1 will use a separate random owner token.

Rules frozen here:

- `advertId` is public.
- owner token is private and returned only to the poster.
- the server stores only `SHA256(ownerToken)`.
- withdraw requires the owner token.
- owner token never appears in list/ticker/order-book responses.
- adverts are immutable; change = withdraw + repost.

This does not identify a wallet and does not grant wallet control.

## Public-intent exclusion rule

A public intent must never contain:

- preimage/secret
- live swap secret hash
- private key / WIF / seed / mnemonic
- claim/refund role public keys
- claim/refund destinations
- pairing credentials
- `TRU_SWAP_RPC_TOKEN`
- wallet/RPC passwords
- live `swapId`

Those belong to the private swap/session layer after a future reservation
successfully creates a fresh swap.

## Market authority rule

**ADVERT != TRADE**

Posted adverts may later contribute to:

- best bid
- best ask
- displayed depth

They do not contribute to:

- LAST
- executed volume
- OHLC
- VWAP
- candles
- settled trade history

Only confirmed atomic-swap settlements may feed authoritative executed-market
statistics.

## MARKET-01A.0 invariants

1. One generic schema for all explicitly registered UTXO-style pair adapters.
2. Only explicitly `active` pairs may be posted.
3. Planned pairs fail closed.
4. No arbitrary chain/ticker supplied by the browser becomes trusted.
5. No floats in monetary quantities.
6. Price is quote/base and is derived from exact quantities.
7. Advert ID is separate from canonical intent hash.
8. Public advert is not a swap and carries no live swap material.
9. No advert reservation in MARKET-01A.0.
10. No coin movement in MARKET-01A.0.

## Next patch

`MARKET-01A.1 — Public SQLite Intent Store`

It should implement:

- durable SQLite schema,
- atomic post/list/withdraw,
- expiration pruning,
- hashed owner-token cancellation capability,
- active-pair enforcement using this module,
- no HTTP listener yet,
- no reservation/take path yet.
