# MARKET-01A.4 — HostedBoard Browser Integration

Status: **PUBLIC READ INTEGRATION**

`market.html` now reads the shared public intent book from
`https://market-api.tokenizedrealutility.com`.

The public market board is separated from the private swap-agent wallet-control
surface.

This patch is read-only in the browser:
- public list: enabled
- public health: enabled
- browser post: fail-closed
- browser withdraw: fail-closed
- take/reserve: fail-closed
- trade tape: empty until confirmed settlement exists

No fake advert board is substituted if the public market API is unavailable.

`TRU_BTC` and `TRU_BSV` stay registry-planned; the current UI renders only the
active `TRU_BSTY` pair.

Next: MARKET-01A.5 — public write/owner capability/multi-browser closeout.

