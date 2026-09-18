# MARKET-01A.2 — Public Intent HTTP API

Status: **LOCAL HTTP API IMPLEMENTED**

This patch exposes the MARKET-01A.0 schema and MARKET-01A.1 durable store over a
narrow localhost-only HTTP API.

## Bind

Default:

`127.0.0.1:8650`

There is no `0.0.0.0` mode in MARKET-01A.2.

Cloudflare publication is intentionally deferred to MARKET-01A.3.

## Routes

Public read:

- `GET /v1/market/health`
- `GET /v1/market/registry`
- `GET /v1/market/adverts`
- `GET /v1/market/adverts?pair=TRU_BSTY`

Public write:

- `POST /v1/market/adverts`
- `POST /v1/market/adverts/<advertId>/withdraw`

Not present:

- take
- reserve
- swap creation
- fund
- claim
- refund

## SQLite concurrency

The HTTP server is threaded, but SQLite connections are never shared between
HTTP threads. Each request opens its own MARKET-01A.1 store connection and
closes it after the operation.

## CORS

Exact-origin allowlist only.

Default allowed browser origins:

- `https://tokenizedrealutility.com`
- `https://www.tokenizedrealutility.com`
- `http://127.0.0.1:8080`
- `http://localhost:8080`

Override with `TRU_MARKET_API_ORIGINS`.

Wildcard origins are rejected.

## Advert creation

`POST /v1/market/adverts` accepts the canonical
`TRU-MARKET-INTENT-V1` client intent.

On success it returns:

- the public advert
- a private `ownerToken` cancellation capability

The owner token must be stored privately by the client. It is not recoverable
from the public advert and the SQLite store persists only its SHA256 digest.

## Advert withdrawal

`POST /v1/market/adverts/<advertId>/withdraw`

Body:

`{"ownerToken":"..."}`

The token is body-only. The HTTP logger never logs request bodies.

## Multi-chain behavior

Registry:

- `TRU_BSTY` active
- `TRU_BTC` planned
- `TRU_BSV` planned

Planned pairs are visible in the registry but cannot be posted.

## Market authority

Posting/listing remains intent only.

MARKET-01A.2 still does not generate:

- LAST
- executed volume
- OHLC
- VWAP
- candles
- settled trade history

Those require confirmed atomic settlements in later patches.

## Next

`MARKET-01A.3 — Cloudflare Public Market Route + Edge Gate`

Expected work:

- publish `market-api.tokenizedrealutility.com`
- Cloudflare Tunnel -> `127.0.0.1:8650`
- TLS-only public surface
- edge rate limiting / abuse controls
- direct-origin port remains closed
- live remote health/list/post/withdraw test
- no reservation/take path
