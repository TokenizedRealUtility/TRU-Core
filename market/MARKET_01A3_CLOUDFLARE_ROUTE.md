# MARKET-01A.3 — Cloudflare Public Market Route

Status: **ROUTE FOUNDATION / PUBLIC READ FAIL-CLOSED WRITE MODE**

## Goal

Publish the public market-data service through Cloudflare while keeping the
origin service loopback-only.

Target:

`https://market-api.tokenizedrealutility.com`
→ Cloudflare Tunnel
→ `http://127.0.0.1:8650`

The market API is separate from the private wallet-control swap agent.

## Security split

Private:

`swap-agent.tokenizedrealutility.com`
- Cloudflare Access protected
- wallet-control boundary
- pairing/session controls

Public:

`market-api.tokenizedrealutility.com`
- public market-data service
- no wallet keys
- no RPC credentials
- no swap creation
- no funding
- no take/reserve

## Public-write gate

MARKET-01A.3 introduces:

`TRU_MARKET_API_PUBLIC_WRITES`

Default:

`0`

Therefore remote `POST` operations fail closed until explicitly enabled.

Public GET endpoints remain available for:

- health
- registry
- advert list

Posting and withdrawal can be enabled only after edge abuse/rate-limit controls
are confirmed:

`export TRU_MARKET_API_PUBLIC_WRITES=1`

This gate does not create a swap or move coins.

## Cloudflare helper

The installer creates:

`~/NEW_TRU/market/apply_cloudflare_market_route.sh`

It:

1. refuses duplicate market-api ingress;
2. requires exactly one final `http_status:404` catch-all;
3. backs up `/etc/cloudflared/config.yml`;
4. inserts the market-api rule immediately before the catch-all;
5. validates the full ingress config;
6. rolls back on validation failure;
7. restarts cloudflared;
8. rolls back if cloudflared does not return active.

Ingress:

```yaml
- hostname: market-api.tokenizedrealutility.com
  service: http://127.0.0.1:8650
```

There is intentionally no Access block on the public market hostname.

## Runtime helper

The installer creates:

`~/NEW_TRU/market/start_market_api_screen.sh`

Default startup is read-only:

`TRU_MARKET_API_PUBLIC_WRITES=0`

The screen name is:

`market_api`

## DNS

The ingress rule does not itself guarantee that the public hostname has DNS.

Create/confirm a proxied Cloudflare DNS/Tunnel hostname:

`market-api.tokenizedrealutility.com`

pointing to the same tunnel used by the site.

## Still absent

- reservation/take
- live swap creation
- funding
- trade tape
- LAST
- executed volume
- OHLC/VWAP/candles

## Next

`MARKET-01A.4 — HostedBoard Browser Integration`

That patch should make `market.html` consume the public market API while the
private swap agent remains a separate local/Access-protected wallet-control
surface.
