#!/usr/bin/env python3
"""
TRU MARKET-MASTER-01 / MARKET-01C1 — public atomic take + V2 handshake relay API.

Public market-data surface only.

Exposes the existing public intent/quote API plus MARKET-01C1:
  POST /v1/market/take
  POST /v1/market/reservations/<id>/status
  POST /v1/market/reservations/<id>/accept
  POST /v1/market/reservations/<id>/release
  POST /v1/market/reservations/<id>/taker-bind
  POST /v1/market/adverts/<advertId>/reservation
  POST /v1/market/adverts/<advertId>/reservation/offer
  POST /v1/market/adverts/<advertId>/reservation/finalize-start
  POST /v1/market/adverts/<advertId>/reservation/final

The public market remains a reservation/relay service only:
- no wallet/RPC access
- no private keys/preimages
- no funding / claim / refund / transaction broadcast
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

API_VERSION = "TRU-MARKET-API-01C1"
HOST = "127.0.0.1"
DEFAULT_PORT = 8650
MAX_BODY = 64 * 1024

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "market_schema_v1.py"
STORE_PATH = ROOT / "market_store_v1.py"
DEFAULT_DB = ROOT / "data" / "market_intents.sqlite3"

DEFAULT_ORIGINS = (
    "https://tokenizedrealutility.com,"
    "https://www.tokenizedrealutility.com,"
    "http://127.0.0.1:8080,"
    "http://localhost:8080"
)


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_module(name: str, path: Path):
    if not path.is_file():
        fail(f"missing required module: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        fail(f"could not load module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SCHEMA = load_module("tru_market_schema_v1", SCHEMA_PATH)
STORE = load_module("tru_market_store_v1", STORE_PATH)


def parse_origins() -> set[str]:
    raw = os.environ.get("TRU_MARKET_API_ORIGINS", DEFAULT_ORIGINS)
    out = {x.strip().rstrip("/") for x in raw.split(",") if x.strip()}
    if not out:
        fail("TRU_MARKET_API_ORIGINS resolved to an empty allowlist")
    if "*" in out:
        fail("TRU_MARKET_API_ORIGINS must never contain '*'")
    return out


def safe_error_message(exc: Exception) -> str:
    text = str(exc).strip()
    return (text or type(exc).__name__)[:300]


def _price_ratio(advert: Dict[str, Any], pair: Dict[str, Any]) -> tuple[int, int]:
    """
    Exact quote-units-per-base-unit ratio.

    price = (quoteAtoms / 10^quoteDecimals) / (baseAtoms / 10^baseDecimals)
          = quoteAtoms * 10^baseDecimals / (baseAtoms * 10^quoteDecimals)
    """
    base = SCHEMA.ASSETS[pair["base"]]
    quote = SCHEMA.ASSETS[pair["quote"]]
    numerator = int(advert["quoteAtoms"]) * (10 ** int(base["decimals"]))
    denominator = int(advert["baseAtoms"]) * (10 ** int(quote["decimals"]))
    if numerator <= 0 or denominator <= 0:
        fail("invalid advert amount for price")
    return numerator, denominator


def _ratio_cmp(a: tuple[int, int], b: tuple[int, int]) -> int:
    left = a[0] * b[1]
    right = b[0] * a[1]
    return (left > right) - (left < right)


def _ratio_decimal(numerator: int, denominator: int, places: int = 18) -> str:
    """Deterministic decimal rendering without binary floating point."""
    if numerator < 0 or denominator <= 0:
        fail("invalid ratio")
    whole, rem = divmod(numerator, denominator)
    if places <= 0 or rem == 0:
        return str(whole)
    digits = []
    for _ in range(places):
        rem *= 10
        digit, rem = divmod(rem, denominator)
        digits.append(str(digit))
        if rem == 0:
            break
    frac = "".join(digits).rstrip("0")
    return f"{whole}.{frac}" if frac else str(whole)


def _quote_entry(advert: Dict[str, Any], pair: Dict[str, Any]) -> Dict[str, Any]:
    n, d = _price_ratio(advert, pair)
    return {
        "advertId": advert["advertId"],
        "intentHash": advert["intentHash"],
        "side": advert["side"],
        "baseAtoms": advert["baseAtoms"],
        "quoteAtoms": advert["quoteAtoms"],
        "price": _ratio_decimal(n, d),
        "priceNumerator": str(n),
        "priceDenominator": str(d),
        "createdAt": advert["createdAt"],
        "expiresAt": advert["expiresAt"],
    }


def build_quote(pair_id: str, adverts: list[Dict[str, Any]]) -> Dict[str, Any]:
    pair = SCHEMA.pair_spec(pair_id, require_active=True)

    bids = [a for a in adverts if a.get("side") == "BUY_BASE"]
    asks = [a for a in adverts if a.get("side") == "SELL_BASE"]

    def choose(items, want_max: bool):
        chosen = None
        chosen_ratio = None
        for advert in items:
            ratio = _price_ratio(advert, pair)
            if chosen is None:
                chosen, chosen_ratio = advert, ratio
                continue
            cmp = _ratio_cmp(ratio, chosen_ratio)
            better = (cmp > 0) if want_max else (cmp < 0)
            if better:
                chosen, chosen_ratio = advert, ratio
            elif cmp == 0:
                ka = (int(advert["createdAt"]), str(advert["advertId"]))
                kc = (int(chosen["createdAt"]), str(chosen["advertId"]))
                if ka < kc:
                    chosen, chosen_ratio = advert, ratio
        return chosen, chosen_ratio

    best_bid, bid_ratio = choose(bids, True)
    best_ask, ask_ratio = choose(asks, False)

    spread = None
    midpoint = None
    crossed = False

    if best_bid is not None and best_ask is not None:
        an, ad = ask_ratio
        bn, bd = bid_ratio

        # exact signed spread = ask - bid
        sn = an * bd - bn * ad
        sd = ad * bd
        crossed = sn <= 0

        # exact indicative midpoint = (ask + bid) / 2
        mn = an * bd + bn * ad
        md = 2 * ad * bd

        midpoint = {
            "price": _ratio_decimal(mn, md),
            "priceNumerator": str(mn),
            "priceDenominator": str(md),
            "label": "indicative midpoint of active intents; not an executed price",
        }

        if mn > 0:
            # spread / midpoint * 100 and * 10000
            pn = sn * md * 100
            pd = sd * mn
            bpn = sn * md * 10000
            bpd = sd * mn
            spread = {
                "price": _ratio_decimal(abs(sn), sd),
                "signedPrice": ("-" if sn < 0 else "") + _ratio_decimal(abs(sn), sd),
                "percent": ("-" if pn < 0 else "") + _ratio_decimal(abs(pn), pd, 8),
                "bps": ("-" if bpn < 0 else "") + _ratio_decimal(abs(bpn), bpd, 4),
            }

    return {
        "pairId": pair["pairId"],
        "base": pair["base"],
        "quote": pair["quote"],
        "priceConvention": f'{pair["quote"]} per 1 {pair["base"]}',
        "pricingStatus": "INDICATIVE_INTENT_BOOK",
        "takeReservationEnabled": False,
        "bidCount": len(bids),
        "askCount": len(asks),
        "bestBid": None if best_bid is None else _quote_entry(best_bid, pair),
        "bestAsk": None if best_ask is None else _quote_entry(best_ask, pair),
        "spread": spread,
        "midpointIndicative": midpoint,
        "crossed": crossed,
        "last": None,
        "lastAvailable": False,
        "executedVolumeAvailable": False,
        "authority": {
            "quotedBidAskSource": "active public intents",
            "lastSource": "confirmed atomic settlements only",
            "note": "Quoted bid/ask are not executed trades. LAST remains unavailable until confirmed settlement history exists.",
        },
    }


def quote_selftest() -> None:
    base = {
        "schemaVersion": SCHEMA.SCHEMA_VERSION,
        "pairId": "TRU_BSTY",
        "baseMinConfirmations": 6,
        "quoteMinConfirmations": 6,
        "fundingOrder": "MAKER_FIRST",
        "makerRefundSeconds": 86400,
        "takerRefundSeconds": 43200,
        "lifeSeconds": 21600,
        "intentHash": "1" * 64,
        "createdAt": 2_000_000_000,
        "expiresAt": 2_000_021_600,
        "status": "ACTIVE",
    }
    bid = {
        **base,
        "advertId": "1" * 32,
        "side": "BUY_BASE",
        "baseAtoms": "10000000000",
        "quoteAtoms": "900000000",
    }
    ask = {
        **base,
        "advertId": "2" * 32,
        "intentHash": "2" * 64,
        "createdAt": 2_000_000_001,
        "side": "SELL_BASE",
        "baseAtoms": "10000000000",
        "quoteAtoms": "1000000000",
    }

    q = build_quote("TRU_BSTY", [bid, ask])
    assert q["priceConvention"] == "BSTY per 1 TRU"
    assert q["pricingStatus"] == "INDICATIVE_INTENT_BOOK"
    assert q["bestBid"]["price"] == "0.09"
    assert q["bestAsk"]["price"] == "0.1"
    assert q["spread"]["price"] == "0.01"
    assert q["crossed"] is False
    assert q["last"] is None
    assert q["lastAvailable"] is False
    assert q["executedVolumeAvailable"] is False
    assert q["takeReservationEnabled"] is False

    bid2 = {
        **bid,
        "advertId": "3" * 32,
        "intentHash": "3" * 64,
        "quoteAtoms": "950000000",
        "createdAt": 2_000_000_002,
    }
    q2 = build_quote("TRU_BSTY", [bid, bid2, ask])
    assert q2["bestBid"]["advertId"] == bid2["advertId"]
    assert q2["bestBid"]["price"] == "0.095"

    ask2 = {
        **ask,
        "advertId": "4" * 32,
        "intentHash": "4" * 64,
        "quoteAtoms": "980000000",
        "createdAt": 2_000_000_003,
    }
    q3 = build_quote("TRU_BSTY", [bid2, ask, ask2])
    assert q3["bestAsk"]["advertId"] == ask2["advertId"]
    assert q3["bestAsk"]["price"] == "0.098"

    crossed_ask = {**ask2, "quoteAtoms": "900000000"}
    q4 = build_quote("TRU_BSTY", [bid2, crossed_ask])
    assert q4["crossed"] is True
    assert q4["last"] is None

    print("MARKET_01B_QUOTE_SELFTEST=PASS")
    print("BEST_BID_EXACT_ORDERING=PASS")
    print("BEST_ASK_EXACT_ORDERING=PASS")
    print("SPREAD_EXACT_RATIONAL=PASS")
    print("CROSSED_BOOK_DETECTION=PASS")
    print("LAST_FROM_ADVERTS=NO")


class SlidingWindowLimiter:
    """Small in-memory abuse gate. No IP addresses are persisted."""
    def __init__(self):
        self._lock = threading.Lock()
        self._events: Dict[tuple[str, str], list[float]] = {}

    def allow(self, bucket: str, client: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        key = (bucket, client)
        with self._lock:
            events = [t for t in self._events.get(key, []) if t > cutoff]
            if len(events) >= limit:
                self._events[key] = events
                return False
            events.append(now)
            self._events[key] = events
            # Opportunistic bounded cleanup.
            if len(self._events) > 10000:
                for stale_key in list(self._events)[:1000]:
                    vals = [t for t in self._events[stale_key] if t > cutoff]
                    if vals:
                        self._events[stale_key] = vals
                    else:
                        self._events.pop(stale_key, None)
            return True


class Handler(BaseHTTPRequestHandler):
    server_version = "TruMarket/" + API_VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Owner tokens are body-only; request bodies are never logged.
        sys.stderr.write(f"[market-http] {self.client_address[0]} - {fmt % args}\n")

    def _origin(self) -> str:
        return (self.headers.get("Origin") or "").rstrip("/")

    def _origin_allowed(self) -> bool:
        origin = self._origin()
        return not origin or origin in self.server.allowed_origins

    def _client_key(self) -> str:
        # The origin only listens on loopback and public traffic arrives through
        # local cloudflared, so CF-Connecting-IP is usable as an ephemeral abuse
        # key. It is validated and never persisted to SQLite.
        candidate = (self.headers.get("CF-Connecting-IP") or "").strip()
        if candidate:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
        return str(self.client_address[0])

    def _write_rate_allowed(self, bucket: str, limit: int) -> bool:
        return self.server.rate_limiter.allow(bucket, self._client_key(), limit, 60)

    def _cors(self):
        origin = self._origin()
        if origin and origin in self.server.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")

    def _reply(self, code: int, payload: Dict[str, Any]):
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> Dict[str, Any]:
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/json"):
            raise ValueError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            raise ValueError("invalid Content-Length")
        if length <= 0:
            raise ValueError("JSON body required")
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("body is not valid JSON")
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def _with_store(self, fn):
        # Each request owns its SQLite connection. This keeps ThreadingHTTPServer
        # concurrency correct without sharing sqlite3.Connection across threads.
        store = STORE.MarketStore(
            self.server.db_path,
            reservation_write_enabled=bool(self.server.reservation_enabled),
        )
        try:
            return fn(store)
        finally:
            store.close()

    def do_OPTIONS(self):
        if not self._origin_allowed():
            return self._reply(403, {"ok": False, "error": "origin not allowed"})
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        if not self._origin_allowed():
            return self._reply(403, {"ok": False, "error": "origin not allowed"})

        u = urlsplit(self.path)
        path = u.path

        try:
            if path == "/v1/market/health":
                counts = self._with_store(lambda s: s.counts())
                return self._reply(200, {
                    "ok": True,
                    "version": API_VERSION,
                    "schemaVersion": SCHEMA.SCHEMA_VERSION,
                    "storeVersion": STORE.STORE_VERSION,
                    "bindScope": "loopback-only",
                    "activePairs": sorted(
                        p["pairId"] for p in SCHEMA.PAIRS.values()
                        if p["state"] == "active"
                    ),
                    "counts": counts,
                    "reservationEnabled": bool(self.server.reservation_enabled),
                    "swapCreationEnabled": bool(self.server.reservation_enabled),
                    "handshakeRelayV2": bool(self.server.reservation_enabled),
                    "durableCapabilities": True,
                    "coinMovementEnabled": False,
                    "publicWritesEnabled": bool(self.server.public_writes),
                    "canonicalQuoteEnabled": True,
                    "pricingStatus": "INDICATIVE_INTENT_BOOK",
                    "writeProtection": {
                        "postPerMinute": int(self.server.post_per_minute),
                        "withdrawPerMinute": int(self.server.withdraw_per_minute),
                        "takePerMinute": int(self.server.take_per_minute),
                        "maxActiveAdverts": int(self.server.max_active_adverts),
                        "clientAddressPersistence": False,
                    },
                })

            if path == "/v1/market/registry":
                return self._reply(200, {
                    "ok": True,
                    "registry": SCHEMA.registry_document(),
                })

            if path == "/v1/market/quote":
                qs = parse_qs(u.query, keep_blank_values=False)
                pair = qs.get("pair", ["TRU_BSTY"])[0]
                SCHEMA.pair_spec(pair, require_active=True)
                adverts = self._with_store(lambda s: s.list_active(pair_id=pair))
                return self._reply(200, {
                    "ok": True,
                    "quote": build_quote(pair, adverts),
                })

            if path.startswith("/v1/market/adverts/"):
                advert_id = path[len("/v1/market/adverts/"):]
                if not re.fullmatch(r"[0-9a-f]{32}", advert_id):
                    return self._reply(404, {"ok": False, "error": "advert not found"})
                advert = self._with_store(lambda st: st.get_public(advert_id))
                if advert is None:
                    return self._reply(404, {"ok": False, "error": "advert not found"})
                return self._reply(200, {"ok": True, "advert": advert})

            if path == "/v1/market/adverts":
                qs = parse_qs(u.query, keep_blank_values=False)
                pair = qs.get("pair", [None])[0]
                if pair is not None:
                    SCHEMA.pair_spec(pair, require_active=False)
                adverts = self._with_store(lambda s: s.list_active(pair_id=pair))
                return self._reply(200, {
                    "ok": True,
                    "pair": pair,
                    "adverts": adverts,
                    "count": len(adverts),
                })

            return self._reply(404, {"ok": False, "error": "endpoint not found"})
        except ValueError as exc:
            return self._reply(400, {"ok": False, "error": safe_error_message(exc)})
        except RuntimeError as exc:
            return self._reply(409, {"ok": False, "error": safe_error_message(exc)})
        except Exception:
            return self._reply(500, {"ok": False, "error": "internal market API error"})

    def do_POST(self):
        if not self._origin_allowed():
            return self._reply(403, {"ok": False, "error": "origin not allowed"})

        if not self.server.public_writes:
            return self._reply(503, {
                "ok": False,
                "error": "public market writes are temporarily disabled",
                "code": "PUBLIC_WRITES_DISABLED",
            })

        path = urlsplit(self.path).path

        try:
            if path == "/v1/market/take":
                if not self.server.reservation_enabled:
                    return self._reply(503, {
                        "ok": False,
                        "error": "atomic reservation/take is disabled",
                        "code": "RESERVATION_DISABLED",
                    })
                if not self._write_rate_allowed("take", self.server.take_per_minute):
                    return self._reply(429, {"ok": False, "error": "public take rate limit exceeded", "code": "RATE_LIMITED"})
                body = self._read_json()
                advert_id = body.get("advertId")
                if not isinstance(advert_id, str) or not advert_id:
                    return self._reply(400, {"ok": False, "error": "advertId required"})
                hold = body.get("holdSeconds", STORE.DEFAULT_RESERVATION_SECONDS)
                try:
                    hold = int(hold)
                except Exception:
                    return self._reply(400, {"ok": False, "error": "holdSeconds must be an integer"})
                result = self._with_store(lambda st: st.reserve(advert_id, hold_seconds=hold, reservation_token=body.get("durableReservationToken")))
                return self._reply(201, {
                    "ok": True,
                    **result,
                    "coinMovement": False,
                    "fundingStarted": False,
                })

            rprefix = "/v1/market/reservations/"
            if path.startswith(rprefix):
                if not self.server.reservation_enabled:
                    return self._reply(503, {"ok": False, "error": "atomic reservation/take is disabled", "code": "RESERVATION_DISABLED"})
                tail = path[len(rprefix):]
                parts = tail.split("/")
                if len(parts) != 2 or not parts[0] or not parts[1]:
                    return self._reply(404, {"ok": False, "error": "endpoint not found"})
                reservation_id, action = parts
                body = self._read_json()
                reservation_token = body.get("reservationToken")
                if not isinstance(reservation_token, str) or not reservation_token:
                    return self._reply(400, {"ok": False, "error": "reservationToken required"})
                if action == "status":
                    result = self._with_store(lambda st: st.reservation_status(reservation_id, reservation_token))
                    return self._reply(200, {"ok": True, **result})
                if action == "accept":
                    acceptance = body.get("acceptance")
                    result = self._with_store(lambda st: st.submit_taker_accept(reservation_id, reservation_token, acceptance))
                    return self._reply(200, {"ok": True, "reservation": result})
                if action == "release":
                    result = self._with_store(lambda st: st.release_reservation(reservation_id, reservation_token))
                    return self._reply(200, {"ok": True, "reservation": result})
                if action == "taker-bind":
                    swap_id = body.get("swapId")
                    result = self._with_store(lambda st: st.acknowledge_taker_and_bind(reservation_id, reservation_token, swap_id))
                    return self._reply(200, {"ok": True, "reservation": result, "swapId": result.get("swapId")})
                return self._reply(404, {"ok": False, "error": "endpoint not found"})

            aprefix = "/v1/market/adverts/"
            if path.startswith(aprefix) and "/reservation" in path:
                if not self.server.reservation_enabled:
                    return self._reply(503, {"ok": False, "error": "atomic reservation/take is disabled", "code": "RESERVATION_DISABLED"})
                tail = path[len(aprefix):]
                parts = tail.split("/")
                if len(parts) < 2 or parts[1] != "reservation":
                    return self._reply(404, {"ok": False, "error": "endpoint not found"})
                advert_id = parts[0]
                action = parts[2] if len(parts) == 3 else ("status" if len(parts) == 2 else "")
                body = self._read_json()
                owner_token = body.get("ownerToken")
                if not isinstance(owner_token, str) or not owner_token:
                    return self._reply(400, {"ok": False, "error": "ownerToken required"})
                if action == "status":
                    result = self._with_store(lambda st: st.owner_reservation(advert_id, owner_token))
                    return self._reply(200, {"ok": True, **result})
                reservation_id = body.get("reservationId")
                if not isinstance(reservation_id, str) or not reservation_id:
                    return self._reply(400, {"ok": False, "error": "reservationId required"})
                if action == "offer":
                    result = self._with_store(lambda st: st.submit_maker_offer(advert_id, owner_token, reservation_id, body.get("offer")))
                    return self._reply(200, {"ok": True, "reservation": result})
                if action == "finalize-start":
                    result = self._with_store(lambda st: st.mark_finalization_started(advert_id, owner_token, reservation_id))
                    return self._reply(200, {"ok": True, "reservation": result})
                if action == "final":
                    result = self._with_store(lambda st: st.submit_maker_final(advert_id, owner_token, reservation_id, body.get("final"), body.get("swapId")))
                    return self._reply(200, {"ok": True, "reservation": result})
                return self._reply(404, {"ok": False, "error": "endpoint not found"})

            if path == "/v1/market/adverts":
                if not self._write_rate_allowed("post", self.server.post_per_minute):
                    return self._reply(429, {
                        "ok": False,
                        "error": "public advert post rate limit exceeded",
                        "code": "RATE_LIMITED",
                    })
                body = self._read_json()
                capability = body.pop("durableOwnerToken", None)
                result = self._with_store(lambda s: s.post(body, owner_token=capability, max_active=self.server.max_active_adverts))
                return self._reply(201, {
                    "ok": True,
                    "advert": result["advert"],
                    "ownerToken": result["ownerToken"],
                    "ownerTokenNotice": "Store this cancellation capability privately; it is not recoverable from the public advert.",
                })

            prefix = "/v1/market/adverts/"
            suffix = "/withdraw"
            if path.startswith(prefix) and path.endswith(suffix):
                if not self._write_rate_allowed("withdraw", self.server.withdraw_per_minute):
                    return self._reply(429, {
                        "ok": False,
                        "error": "public advert withdraw rate limit exceeded",
                        "code": "RATE_LIMITED",
                    })
                advert_id = path[len(prefix):-len(suffix)]
                if "/" in advert_id or not advert_id:
                    return self._reply(404, {"ok": False, "error": "endpoint not found"})
                body = self._read_json()
                owner_token = body.get("ownerToken")
                if not isinstance(owner_token, str) or not owner_token:
                    return self._reply(400, {"ok": False, "error": "ownerToken required"})
                try:
                    advert = self._with_store(lambda s: s.withdraw(advert_id, owner_token))
                except RuntimeError as exc:
                    msg = safe_error_message(exc)
                    if "owner token rejected" in msg:
                        return self._reply(403, {"ok": False, "error": "owner token rejected"})
                    if "advert not found" in msg:
                        return self._reply(404, {"ok": False, "error": "advert not found"})
                    return self._reply(409, {"ok": False, "error": msg})
                return self._reply(200, {"ok": True, "advert": advert})

            return self._reply(404, {"ok": False, "error": "endpoint not found"})

        except ValueError as exc:
            return self._reply(400, {"ok": False, "error": safe_error_message(exc)})
        except RuntimeError as exc:
            msg = safe_error_message(exc)
            if msg == "public intent book active-advert cap reached":
                return self._reply(503, {"ok": False, "error": msg, "code": "ACTIVE_ADVERT_CAP"})
            if "token rejected" in msg:
                code = 403
            elif "not found" in msg or "missing" in msg and "reserved advert" in msg:
                code = 404
            elif any(x in msg for x in (
                "already", "not held", "not active", "cannot be released",
                "mismatch", "required before", "not available yet", "inconsistent",
                "open reservation", "finalization", "atomicity",
            )):
                code = 409
            else:
                code = 400
            return self._reply(code, {"ok": False, "error": msg})
        except Exception:
            return self._reply(500, {"ok": False, "error": "internal market API error"})


class MarketHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler_cls, db_path: Path, allowed_origins):
        super().__init__(address, handler_cls)
        self.db_path = Path(db_path)
        self.allowed_origins = allowed_origins
        self.public_writes = False
        self.rate_limiter = SlidingWindowLimiter()
        self.post_per_minute = 6
        self.withdraw_per_minute = 30
        self.take_per_minute = 30
        self.max_active_adverts = 1000
        self.reservation_enabled = False


def sample_intent(**overrides):
    d = {
        "schemaVersion": SCHEMA.SCHEMA_VERSION,
        "pairId": "TRU_BSTY",
        "side": "SELL_BASE",
        "baseAtoms": "10000000000",
        "quoteAtoms": "1000000000000",
        "baseMinConfirmations": 6,
        "quoteMinConfirmations": 6,
        "fundingOrder": "MAKER_FIRST",
        "makerRefundSeconds": 86400,
        "takerRefundSeconds": 43200,
        "lifeSeconds": 21600,
    }
    d.update(overrides)
    return d


def http_json(url: str, method="GET", body=None, origin="https://tokenizedrealutility.com"):
    data = None
    headers = {}
    if origin:
        headers["Origin"] = origin
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers.items()), json.loads(r.read().decode("utf-8"))
    except HTTPError as e:
        raw = e.read().decode("utf-8")
        return e.code, dict(e.headers.items()), json.loads(raw)


def selftest():
    quote_selftest()
    with tempfile.TemporaryDirectory(prefix="tru-market-http-01b-") as td:
        db = Path(td) / "market.sqlite3"
        # Initialize once; request handlers then open their own connections.
        init = STORE.MarketStore(db)
        init.close()

        server = MarketHTTPServer(
            ("127.0.0.1", 0),
            Handler,
            db,
            {"https://tokenizedrealutility.com"},
        )
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"

        try:
            code, headers, health = http_json(base + "/v1/market/health")
            assert code == 200 and health["ok"] is True
            assert health["activePairs"] == ["TRU_BSTY"]
            assert health["reservationEnabled"] is False
            assert health["swapCreationEnabled"] is False
            assert health["handshakeRelayV2"] is False
            assert health["coinMovementEnabled"] is False
            assert headers.get("Access-Control-Allow-Origin") == "https://tokenizedrealutility.com"

            code, _, reg = http_json(base + "/v1/market/registry")
            assert code == 200
            assert reg["registry"]["pairs"]["TRU_BTC"]["state"] == "planned"
            assert reg["registry"]["pairs"]["TRU_BSV"]["state"] == "planned"

            code, _, closed = http_json(
                base + "/v1/market/adverts",
                method="POST",
                body=sample_intent(),
            )
            assert code == 503 and closed["code"] == "PUBLIC_WRITES_DISABLED"
            server.public_writes = True
            server.post_per_minute = 10
            server.withdraw_per_minute = 10
            server.max_active_adverts = 100

            code, _, created = http_json(
                base + "/v1/market/adverts",
                method="POST",
                body=sample_intent(),
            )
            assert code == 201
            owner = created["ownerToken"]
            advert = created["advert"]
            assert owner and "ownerToken" not in advert
            advert_id = advert["advertId"]

            code, _, listed = http_json(base + "/v1/market/adverts?pair=TRU_BSTY")
            assert code == 200 and listed["count"] == 1
            blob = json.dumps(listed)
            assert owner not in blob
            assert "owner_token_hash" not in blob

            code, _, dup = http_json(
                base + "/v1/market/adverts",
                method="POST",
                body=sample_intent(),
            )
            assert code == 409

            code, _, planned = http_json(
                base + "/v1/market/adverts",
                method="POST",
                body=sample_intent(pairId="TRU_BTC"),
            )
            assert code == 400

            code, _, wrong = http_json(
                base + f"/v1/market/adverts/{advert_id}/withdraw",
                method="POST",
                body={"ownerToken": "x" * 43},
            )
            assert code == 403

            code, _, withdrawn = http_json(
                base + f"/v1/market/adverts/{advert_id}/withdraw",
                method="POST",
                body={"ownerToken": owner},
            )
            assert code == 200
            assert withdrawn["advert"]["status"] == "WITHDRAWN"

            code, _, listed2 = http_json(base + "/v1/market/adverts")
            assert code == 200 and listed2["count"] == 0

            server.max_active_adverts = 0
            code, _, capped = http_json(
                base + "/v1/market/adverts",
                method="POST",
                body=sample_intent(baseAtoms="11000000000"),
            )
            assert code == 503 and capped["code"] == "ACTIVE_ADVERT_CAP"
            server.max_active_adverts = 100

            code, _, denied = http_json(
                base + "/v1/market/health",
                origin="https://evil.example",
            )
            assert code == 403

            # MARKET-01C1 is separately fail-closed until reservation activation.
            code, _, no_take = http_json(
                base + "/v1/market/take", method="POST", body={"advertId": "00" * 16}
            )
            assert code == 503 and no_take["code"] == "RESERVATION_DISABLED"

            server.reservation_enabled = True
            # Create a fresh advert for the relay flow.
            code, _, created_take = http_json(
                base + "/v1/market/adverts", method="POST",
                body=sample_intent(baseAtoms="12000000000"),
            )
            assert code == 201
            ta = created_take["advert"]; towner = created_take["ownerToken"]
            aid = ta["advertId"]
            code, _, taken = http_json(base + "/v1/market/take", method="POST", body={"advertId": aid, "holdSeconds": 120})
            assert code == 201 and taken["reservation"]["status"] == "HELD"
            rid = taken["reservation"]["reservationId"]; rtok = taken["reservationToken"]
            assert taken["coinMovement"] is False and taken["fundingStarted"] is False

            import base64
            def hb(prefix, obj):
                return prefix + base64.b64encode(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).decode()
            offer = hb("TRUSWAP2:", {"offerId": "11"*32, "secretHash160": "22"*20})
            accept = hb("TRUSWAP2A:", {"offerId": "11"*32, "acceptId": "33"*32})
            final = hb("TRUSWAP2F:", {"offerId": "11"*32, "acceptId": "33"*32, "recordParams": {"pairId": "TRU_BSTY"}})
            sid = "44" * 32

            code, _, owner_view = http_json(
                base + f"/v1/market/adverts/{aid}/reservation", method="POST", body={"ownerToken": towner}
            )
            assert code == 200 and owner_view["reservation"]["reservationId"] == rid

            code, _, offered = http_json(
                base + f"/v1/market/adverts/{aid}/reservation/offer", method="POST",
                body={"ownerToken": towner, "reservationId": rid, "offer": offer},
            )
            assert code == 200 and offered["reservation"]["makerOffer"] == offer

            code, _, status = http_json(
                base + f"/v1/market/reservations/{rid}/status", method="POST", body={"reservationToken": rtok}
            )
            assert code == 200 and status["reservation"]["makerOffer"] == offer

            code, _, accepted = http_json(
                base + f"/v1/market/reservations/{rid}/accept", method="POST",
                body={"reservationToken": rtok, "acceptance": accept},
            )
            assert code == 200

            code, _, started = http_json(
                base + f"/v1/market/adverts/{aid}/reservation/finalize-start", method="POST",
                body={"ownerToken": towner, "reservationId": rid},
            )
            assert code == 200 and started["reservation"]["finalizationStartedAt"] is not None

            code, _, rel = http_json(
                base + f"/v1/market/reservations/{rid}/release", method="POST", body={"reservationToken": rtok}
            )
            assert code == 409

            code, _, finalized = http_json(
                base + f"/v1/market/adverts/{aid}/reservation/final", method="POST",
                body={"ownerToken": towner, "reservationId": rid, "final": final, "swapId": sid},
            )
            assert code == 200 and finalized["reservation"]["makerSwapId"] == sid

            code, _, mismatch = http_json(
                base + f"/v1/market/reservations/{rid}/taker-bind", method="POST",
                body={"reservationToken": rtok, "swapId": "55"*32},
            )
            assert code == 409
            code, _, bound = http_json(
                base + f"/v1/market/reservations/{rid}/taker-bind", method="POST",
                body={"reservationToken": rtok, "swapId": sid},
            )
            assert code == 200 and bound["reservation"]["status"] == "BOUND" and bound["swapId"] == sid
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    limiter = SlidingWindowLimiter()
    assert limiter.allow("test", "127.0.0.1", 2, 60) is True
    assert limiter.allow("test", "127.0.0.1", 2, 60) is True
    assert limiter.allow("test", "127.0.0.1", 2, 60) is False

    print("MARKET_01B_HTTP_SELFTEST=PASS")
    print("HEALTH_ENDPOINT=PASS")
    print("REGISTRY_ENDPOINT=PASS")
    print("LIST_ENDPOINT=PASS")
    print("PUBLIC_WRITE_DEFAULT_FAIL_CLOSED=PASS")
    print("PUBLIC_WRITE_RATE_LIMITER=PASS")
    print("PUBLIC_ACTIVE_ADVERT_CAP=PASS")
    print("CLIENT_ADDRESS_PERSISTENCE=NO")
    print("POST_ENDPOINT_WHEN_EXPLICITLY_ENABLED=PASS")
    print("WITHDRAW_ENDPOINT=PASS")
    print("PER_REQUEST_SQLITE_CONNECTION=PASS")
    print("EXACT_ORIGIN_CORS=PASS")
    print("OWNER_TOKEN_PUBLIC_LIST_LEAK=NO")
    print("PLANNED_PAIR_POST=REJECTED")
    print("TAKE_ROUTE=INSTALLED_SEPARATE_ENV_GATE")
    print("ATOMIC_RESERVATION_HTTP=PASS")
    print("V2_HANDSHAKE_RELAY_HTTP=PASS")
    print("FINALIZATION_START_BARRIER_HTTP=PASS")
    print("MAKER_TAKER_SWAP_ID_BIND_HTTP=PASS")
    print("SWAP_CREATION=LOCAL_AGENT_ONLY")
    print("COIN_MOVEMENT=NONE")


def check(db_path: Path):
    store = STORE.MarketStore(db_path)
    try:
        counts = store.counts()
    finally:
        store.close()
    print(json.dumps({
        "ok": True,
        "version": API_VERSION,
        "schemaVersion": SCHEMA.SCHEMA_VERSION,
        "storeVersion": STORE.STORE_VERSION,
        "db": str(db_path),
        "counts": counts,
        "activePairs": sorted(
            p["pairId"] for p in SCHEMA.PAIRS.values()
            if p["state"] == "active"
        ),
        "plannedPairs": sorted(
            p["pairId"] for p in SCHEMA.PAIRS.values()
            if p["state"] == "planned"
        ),
        "reservationEnabled": False,
        "swapCreationEnabled": False,
        "handshakeRelayV2": False,
        "coinMovementEnabled": False,
    }, indent=2, sort_keys=True))


def main() -> int:
    ap = argparse.ArgumentParser(description="TRU public market intent API")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    db_path = Path(args.db).expanduser()

    if args.check:
        check(db_path)
        return 0

    if args.port < 1 or args.port > 65535:
        fail("port must be between 1 and 65535")

    origins = parse_origins()
    # Prove the DB is usable before binding.
    probe = STORE.MarketStore(db_path)
    probe.close()

    server = MarketHTTPServer((HOST, args.port), Handler, db_path, origins)
    raw_writes = os.environ.get("TRU_MARKET_API_PUBLIC_WRITES", "0").strip().lower()
    if raw_writes not in {"0", "1", "false", "true", "no", "yes", "off", "on"}:
        fail("TRU_MARKET_API_PUBLIC_WRITES must be 0/1, false/true, no/yes, or off/on")
    server.public_writes = raw_writes in {"1", "true", "yes", "on"}

    raw_reservation = os.environ.get("TRU_MARKET_RESERVATION_ENABLE", "0").strip().lower()
    if raw_reservation not in {"0", "1", "false", "true", "no", "yes", "off", "on"}:
        fail("TRU_MARKET_RESERVATION_ENABLE must be 0/1, false/true, no/yes, or off/on")
    server.reservation_enabled = raw_reservation in {"1", "true", "yes", "on"}

    def env_int(name: str, default: int, lo: int, hi: int) -> int:
        raw = os.environ.get(name, str(default)).strip()
        try:
            value = int(raw)
        except ValueError:
            fail(f"{name} must be an integer")
        if value < lo or value > hi:
            fail(f"{name} must be between {lo} and {hi}")
        return value

    server.post_per_minute = env_int("TRU_MARKET_POSTS_PER_MINUTE", 6, 1, 120)
    server.withdraw_per_minute = env_int("TRU_MARKET_WITHDRAWS_PER_MINUTE", 30, 1, 240)
    server.take_per_minute = env_int("TRU_MARKET_TAKES_PER_MINUTE", 30, 1, 240)
    server.max_active_adverts = env_int("TRU_MARKET_MAX_ACTIVE_ADVERTS", 1000, 1, 100000)

    print("=" * 66)
    print(f" TRU PUBLIC MARKET INTENT API — {API_VERSION}")
    print("=" * 66)
    print(f"LISTEN=http://{HOST}:{args.port}")
    print("BIND_SCOPE=LOOPBACK_ONLY")
    print(f"DB={db_path}")
    print("ACTIVE_PAIRS=" + ",".join(sorted(
        p["pairId"] for p in SCHEMA.PAIRS.values() if p["state"] == "active"
    )))
    print("PLANNED_PAIRS=" + ",".join(sorted(
        p["pairId"] for p in SCHEMA.PAIRS.values() if p["state"] == "planned"
    )))
    print("RESERVATION=" + ("ENABLED" if server.reservation_enabled else "DISABLED_FAIL_CLOSED"))
    print("SWAP_CREATION=" + ("ENABLED_LOCAL_AGENT_HANDSHAKE" if server.reservation_enabled else "DISABLED_FAIL_CLOSED"))
    print("HANDSHAKE_RELAY_V2=" + ("ENABLED" if server.reservation_enabled else "DISABLED_FAIL_CLOSED"))
    print("COIN_MOVEMENT=DISABLED")
    print("CANONICAL_QUOTE=ENABLED")
    print("PRICE_CONVENTION=QUOTE_PER_BASE")
    print("PRICING_STATUS=INDICATIVE_INTENT_BOOK")
    print("PUBLIC_WRITES=" + ("ENABLED" if server.public_writes else "DISABLED_FAIL_CLOSED"))
    print(f"POST_RATE_LIMIT={server.post_per_minute}/minute")
    print(f"WITHDRAW_RATE_LIMIT={server.withdraw_per_minute}/minute")
    print(f"TAKE_RATE_LIMIT={server.take_per_minute}/minute")
    print(f"MAX_ACTIVE_ADVERTS={server.max_active_adverts}")
    print("ALLOWED_ORIGINS=" + ",".join(sorted(origins)))
    print("=" * 66)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
