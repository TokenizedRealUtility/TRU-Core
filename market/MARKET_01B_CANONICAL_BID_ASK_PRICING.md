# MARKET-01B — Bid / Ask / Canonical TRU/BSTY Pricing

Status: **IMPLEMENTED**

## Canonical pair

`TRU_BSTY`

- base = `TRU`
- quote = `BSTY`
- price = **BSTY per 1 TRU**

The price convention never reverses when maker direction reverses.

## Sides

`SELL_BASE` = ask.

The maker sells TRU and wants BSTY.

`BUY_BASE` = bid.

The maker wants TRU and offers BSTY.

Best bid = highest BSTY-per-TRU quote.

Best ask = lowest BSTY-per-TRU quote.

## Exact arithmetic

Price ordering is based on the exact integer ratio:

`quoteAtoms * 10^baseDecimals / (baseAtoms * 10^quoteDecimals)`

Binary floating point is not used to choose the best bid or best ask.

The API exposes both a decimal display string and the exact numerator and
denominator for each best quote.

## Endpoint

`GET /v1/market/quote?pair=TRU_BSTY`

It reports:

- best bid
- best ask
- bid count
- ask count
- spread
- indicative midpoint
- crossed-book status
- canonical price convention

## Authority rule

The quote is explicitly marked:

`INDICATIVE_INTENT_BOOK`

MARKET-01C reservation/take remains absent.

Therefore:

- advert != trade
- quoted bid/ask != LAST
- midpoint is indicative only
- adverts create no executed volume
- adverts create no OHLC
- adverts create no VWAP
- adverts create no candles

`last` stays `null`.

Only confirmed atomic-swap settlements may later create authoritative LAST and
executed-market statistics.

## Crossed book

If best bid is greater than or equal to best ask:

`crossed = true`

MARKET-01B does not match the orders and does not pretend a trade happened.

## Browser

The marketplace status strip displays canonical pricing such as:

`Quoted bid 0.09 · Quoted ask 0.10 BSTY/TRU`

When both sides exist, it also displays the spread.

The UI always states that LAST is unavailable until confirmed atomic
settlements.

## Multi-chain design

The ratio engine reads asset decimal precision from the registry.

The calculation therefore remains suitable for future activated TRU/BTC,
TRU/BSV, and other registered pairs.

Only TRU/BSTY is active now.

## Still disabled

- reservation/take
- automatic matching
- swap creation
- funding
- claim/refund
- coin movement
- executed trade tape
- LAST
- executed volume
- OHLC
- VWAP
- candles

## Next

`MARKET-01C — Atomic Reservation + Fresh Swap Creation`

Live taking should remain gated by the swap roadmap's funded SWAP-C/adversarial
closeout and production per-swap key/destination work.
