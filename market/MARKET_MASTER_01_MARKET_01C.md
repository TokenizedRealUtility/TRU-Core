# TRU MARKET-MASTER-01 — MARKET-01C

Status after installation: installed, public Take remains separately runtime-gated until the Market API is restarted with `TRU_MARKET_RESERVATION_ENABLE=1`.

## Scope

This patch closes MARKET-01C's software activation boundary:

- atomic public Take / HELD reservation
- short-lived reservation capability token stored only as a hash server-side
- maker-browser polling for owned held reservations
- local maker Agent creates fresh V2 offer and fresh per-swap role material
- public Market API relays only public TRUSWAP2 / TRUSWAP2A / TRUSWAP2F blobs
- taker local Agent creates acceptance
- `FINALIZATION_STARTED` is persisted before maker canonical record creation
- maker finalization produces the canonical fresh TRU swap record
- taker independently finalizes/reads the same canonical record
- reservation becomes `BOUND` only when maker and taker report the exact same 64-hex `swapId`
- conflicting handshake replays and swap IDs are rejected
- post-finalization expiry/release cannot reopen the advert

## Custody boundary

The public market service never receives or stores:

- wallet private keys
- WIF/private-key exports
- preimages
- wallet passphrases
- TRU RPC credentials

The Market API is reservation + public-handshake relay only.

## Explicitly NOT activated

MARKET-MASTER-01 does not fund either chain and does not claim/refund anything.

```text
FUNDING=NO
CLAIM=NO
REFUND=NO
TX_BROADCAST=NO
COIN_MOVEMENT=NO
```

## Runtime activation

After installation, start the Market API with:

```bash
cd ~/NEW_TRU

export TRU_MARKET_API_PUBLIC_WRITES=1
export TRU_MARKET_RESERVATION_ENABLE=1

bash market/run_market_api.sh
```

Expected health fields:

```text
version = TRU-MARKET-API-01C1
reservationEnabled = true
swapCreationEnabled = true
handshakeRelayV2 = true
coinMovementEnabled = false
```

The Swap Agent must be running and paired before a browser can post/take an advert while Take is enabled.

## Post hashes

```text
market/market_store_v1.py
fd5a406a4c48a9b9866ee0a4184be923aab6085b2f903462b592c0645e6b9545

market/market_http_api_v1.py
7521c7d6a2fa77ebc4b3fd717a5d4cb69290757ec40cc611e03bc7a262f37bac

/var/www/tokenizedrealutility.com/market.js
343ee27299df47eeaf0abc7be17b2651e8484efed209b2ff850953b0ea8ecabb

/var/www/tokenizedrealutility.com/ws.js
38e23526511c84c4aee585466fe4cbd47afb17502b1b9594187b5cd8add91799
```
