# MARKET-01A.5 — Public Write / Owner Capability / Multi-Browser Closeout

Status: **IMPLEMENTED — LIVE MULTI-BROWSER PROOF REQUIRED BEFORE CLOSE**

MARKET-01A.5 turns the shared TRU/BSTY intent book into a real public
post/list/withdraw board while keeping atomic reservation and all coin movement
disabled.

## Public write model

The public API still binds only:

`127.0.0.1:8650`

Cloudflare Tunnel publishes:

`https://market-api.tokenizedrealutility.com`

Public writes remain controlled by:

`TRU_MARKET_API_PUBLIC_WRITES`

Default is still `0`.

Enable only after this patch is installed and the API restarts cleanly.

## Browser owner capability

On a successful public advert post the API returns:

- public `advertId`
- private `ownerToken`

SQLite stores only:

`SHA256(ownerToken)`

The browser stores the cancellation-only owner token under:

`tru_market_owner_tokens_v1`

in localStorage on the marketplace origin.

This capability can withdraw that advert. It is **not**:

- a TRU private key
- a BSTY private key
- a swap preimage
- a live swap hash
- a wallet password
- a pairing token
- `TRU_SWAP_RPC_TOKEN`

An XSS on the marketplace could therefore cancel a browser-owned advert, but
this capability cannot spend wallet funds. General website XSS prevention
remains important.

## Public browser actions

Enabled when the API health response reports `publicWritesEnabled=true`:

- list shared TRU/BSTY intents
- post a shared TRU/BSTY intent
- mark adverts owned by this browser
- withdraw an advert using its browser-local cancellation capability

Still disabled:

- reserve
- take
- swap creation
- funding
- claim
- refund

## Exact monetary conversion

The browser converts decimal UI amounts to integer atom strings without using
floating-point arithmetic for the canonical amount.

Pair convention stays:

`TRU_BSTY`

- base = TRU
- quote = BSTY
- `SELL_BASE` = maker gives TRU
- `BUY_BASE` = maker gives BSTY and wants TRU

The V1 browser uses:

`fundingOrder = MAKER_FIRST`

The six-hour minimum timelock gap is now enforced by the UI as well as the
server schema.

## Abuse controls

MARKET-01A.5 adds an origin-side in-memory sliding-window write limiter.

Defaults:

- 6 advert posts / minute / client IP
- 30 withdrawals / minute / client IP
- 1,000 active adverts maximum

Environment overrides:

- `TRU_MARKET_POSTS_PER_MINUTE`
- `TRU_MARKET_WITHDRAWS_PER_MINUTE`
- `TRU_MARKET_MAX_ACTIVE_ADVERTS`

For Cloudflare-routed requests the validated `CF-Connecting-IP` value is used
as an ephemeral rate-limit key. Client IPs are not persisted to SQLite.

Cloudflare edge rate limiting/WAF can be added later as another layer; this
patch does not require a Cloudflare API credential.

## Market authority remains unchanged

An advert is **not** a trade.

Public post/list/withdraw does not create:

- LAST
- executed volume
- OHLC
- VWAP
- candles

Only confirmed atomic settlements may feed those later metrics.

## Live closeout test

After enabling public writes, run:

`python3 ~/NEW_TRU/market/live_public_write_probe.py`

The probe:

1. creates one temporary intent;
2. confirms it appears through the public hostname;
3. verifies the owner token is absent from public list data;
4. withdraws it with the owner capability;
5. confirms it disappears;
6. never prints the owner token.

Then prove multi-browser behavior:

1. Browser A posts an advert.
2. Browser B/device sees the same advert.
3. Browser B cannot withdraw it because it lacks the owner capability.
4. Browser A can withdraw it.
5. Both browsers observe the removal.

No funds move during this proof.

## Next after closeout

`MARKET-01B — Bid / Ask / Canonical Pair Pricing`

Reservation/take remains owned by `MARKET-01C`.
