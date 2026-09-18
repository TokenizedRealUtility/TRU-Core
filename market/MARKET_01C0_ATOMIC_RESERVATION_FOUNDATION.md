# MARKET-01C0 — Atomic Reservation Foundation

Status: **IMPLEMENTED / PUBLIC TAKE STILL FAIL-CLOSED**

This patch adds the durable reservation substrate required before MARKET-01C can
create a fresh atomic swap from a public advert.

## What is implemented

- SQLite `reservations` table with WAL/FULL durability inherited from the market store.
- Exactly one open reservation (`HELD` or `BOUND`) per advert.
- Reservation token returned once; only SHA256(token) is persisted.
- Short hold window: 30..300 seconds, default 120 seconds.
- `HELD` adverts disappear from the visible intent book.
- Expired/released reservations reopen the advert automatically.
- Maker withdrawal is rejected while a reservation is `HELD` or `BOUND`.
- `BOUND` reservations are tied to exactly one 64-hex fresh swap ID.
- Deterministic handoff terms map maker/taker chain directions and exact atom amounts.

## Fresh-swap handoff rule

The handoff says:

- `freshSwapRequired = true`
- `preexistingSwapIdAllowed = false`

It contains no private key, role key, destination, preimage, wallet credential, RPC
credential, pairing credential, owner token, or reservation token.

## Still deliberately disabled

The public MARKET-01B HTTP API is not modified by this patch. Therefore:

- `POST /v1/market/take` remains absent / 404
- `reservationEnabled` remains `false`
- `swapCreationEnabled` remains `false`
- browser take remains fail-closed
- no wallet/RPC call is added
- no funding, claim, refund, or coin movement occurs

Reservation write methods default to disabled in `MarketStore`. They are exercised only
by the isolated self-test until a later activation patch explicitly enables the route.

## Why activation remains gated

The current swap agent still does not expose production offer creation, and fresh
per-swap key/destination allocation remains a prerequisite. MARKET-01C activation must
not bind public reservations to reused role keys or reused TRU destinations.

## Next

`SWAP-FRESH-01 — Per-Swap Key + Destination Allocator / Agent Offer Creation`

Then:

`MARKET-01C1 — Public Take Activation + Atomic Fresh Swap Binding`
