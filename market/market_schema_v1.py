#!/usr/bin/env python3
"""
TRU MARKET-01A.0 — multi-chain public intent schema foundation.

This module is deliberately market-data only:
- no wallet access
- no RPC access
- no swap creation
- no funding
- no private keys
- no preimages
- no HTLC role keys/destinations

Adding BTC, BSV, or another chain later should require registry entries and an
adapter implementation, not a new public advert shape.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from decimal import Decimal, getcontext
from typing import Any, Dict

SCHEMA_VERSION = "TRU-MARKET-INTENT-V1"
PAIR_SEPARATOR = "_"
MIN_TIMEOUT_GAP_SECONDS = 6 * 60 * 60
MIN_LIFE_SECONDS = 5 * 60
MAX_LIFE_SECONDS = 7 * 24 * 60 * 60
MAX_CONFIRMATIONS = 10_000

ATOM_RE = re.compile(r"^(0|[1-9][0-9]*)$")
ADVERT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Registry entries are metadata/capability declarations only. "planned" does
# NOT claim that a chain's swap adapter is implemented or production-ready.
ASSETS: Dict[str, Dict[str, Any]] = {
    "TRU": {
        "assetId": "TRU",
        "chainId": "tru-mainnet",
        "ticker": "TRU",
        "decimals": 8,
        "adapter": "tru-v1-bare-htlc",
        "state": "active",
    },
    "BSTY": {
        "assetId": "BSTY",
        "chainId": "globalboost-mainnet",
        "ticker": "BSTY",
        "decimals": 8,
        "adapter": "bsty-p2sh-htlc",
        "state": "active",
    },
    "BTC": {
        "assetId": "BTC",
        "chainId": "bitcoin-mainnet",
        "ticker": "BTC",
        "decimals": 8,
        "adapter": "bitcoin-htlc-pending",
        "state": "planned",
    },
    "BSV": {
        "assetId": "BSV",
        "chainId": "bsv-mainnet",
        "ticker": "BSV",
        "decimals": 8,
        "adapter": "bsv-htlc-pending",
        "state": "planned",
    },
}

PAIRS: Dict[str, Dict[str, Any]] = {
    "TRU_BSTY": {"pairId": "TRU_BSTY", "base": "TRU", "quote": "BSTY", "state": "active"},
    "TRU_BTC":  {"pairId": "TRU_BTC",  "base": "TRU", "quote": "BTC",  "state": "planned"},
    "TRU_BSV":  {"pairId": "TRU_BSV",  "base": "TRU", "quote": "BSV",  "state": "planned"},
}

SIDES = {"SELL_BASE", "BUY_BASE"}
FUNDING_ORDERS = {"MAKER_FIRST", "TAKER_FIRST"}
PUBLIC_STATUSES = {"ACTIVE", "WITHDRAWN", "EXPIRED"}

# Fields that must never appear in a public intent.
FORBIDDEN_PUBLIC_KEYS = {
    "preimage", "secret", "secretHex", "secretHash160",
    "privateKey", "privkey", "wif", "seed", "mnemonic",
    "claimPubKey", "refundPubKey", "claimDestination", "refundDestination",
    "pairingToken", "pairingSession", "truSwapRpcToken", "rpcPassword",
    "walletPassword", "swapId",
}

CLIENT_INTENT_KEYS = (
    "schemaVersion",
    "pairId",
    "side",
    "baseAtoms",
    "quoteAtoms",
    "baseMinConfirmations",
    "quoteMinConfirmations",
    "fundingOrder",
    "makerRefundSeconds",
    "takerRefundSeconds",
    "lifeSeconds",
)

PUBLIC_ADVERT_KEYS = CLIENT_INTENT_KEYS + (
    "advertId",
    "intentHash",
    "createdAt",
    "expiresAt",
    "status",
)


def fail(message: str) -> None:
    raise ValueError(message)


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _walk_keys(v)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def assert_no_forbidden_public_fields(value: Any) -> None:
    bad = sorted({k for k in _walk_keys(value) if k in FORBIDDEN_PUBLIC_KEYS})
    if bad:
        fail("forbidden public field(s): " + ", ".join(bad))


def parse_atoms(name: str, value: Any) -> int:
    if not isinstance(value, str) or not ATOM_RE.fullmatch(value):
        fail(f"{name} must be an unsigned base-10 integer string")
    n = int(value)
    if n <= 0:
        fail(f"{name} must be greater than zero")
    if n.bit_length() > 128:
        fail(f"{name} exceeds v1 128-bit quantity bound")
    return n


def parse_int(name: str, value: Any, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{name} must be an integer")
    if value < lo or value > hi:
        fail(f"{name} must be between {lo} and {hi}")
    return value


def pair_spec(pair_id: Any, require_active: bool = True) -> Dict[str, Any]:
    if not isinstance(pair_id, str) or pair_id not in PAIRS:
        fail("unknown pairId")
    p = PAIRS[pair_id]
    if require_active and p["state"] != "active":
        fail(f"pair {pair_id} is registered but not active")
    return p


def validate_client_intent(obj: Any, require_active_pair: bool = True) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        fail("intent must be an object")
    assert_no_forbidden_public_fields(obj)

    unknown = sorted(set(obj) - set(CLIENT_INTENT_KEYS))
    missing = [k for k in CLIENT_INTENT_KEYS if k not in obj]
    if unknown:
        fail("unknown intent field(s): " + ", ".join(unknown))
    if missing:
        fail("missing intent field(s): " + ", ".join(missing))

    if obj["schemaVersion"] != SCHEMA_VERSION:
        fail("unsupported schemaVersion")

    p = pair_spec(obj["pairId"], require_active=require_active_pair)

    if obj["side"] not in SIDES:
        fail("side must be SELL_BASE or BUY_BASE")

    base_atoms = parse_atoms("baseAtoms", obj["baseAtoms"])
    quote_atoms = parse_atoms("quoteAtoms", obj["quoteAtoms"])

    base_conf = parse_int("baseMinConfirmations", obj["baseMinConfirmations"], 1, MAX_CONFIRMATIONS)
    quote_conf = parse_int("quoteMinConfirmations", obj["quoteMinConfirmations"], 1, MAX_CONFIRMATIONS)

    if obj["fundingOrder"] not in FUNDING_ORDERS:
        fail("fundingOrder must be MAKER_FIRST or TAKER_FIRST")

    maker_refund = parse_int("makerRefundSeconds", obj["makerRefundSeconds"], 1, 30 * 24 * 60 * 60)
    taker_refund = parse_int("takerRefundSeconds", obj["takerRefundSeconds"], 1, 30 * 24 * 60 * 60)
    life = parse_int("lifeSeconds", obj["lifeSeconds"], MIN_LIFE_SECONDS, MAX_LIFE_SECONDS)

    if obj["fundingOrder"] == "MAKER_FIRST":
        gap = maker_refund - taker_refund
    else:
        gap = taker_refund - maker_refund
    if gap < MIN_TIMEOUT_GAP_SECONDS:
        fail(f"first-funded leg must have at least {MIN_TIMEOUT_GAP_SECONDS} seconds more refund time")

    # Return a canonical, type-stable object. Quantities remain strings.
    return {
        "schemaVersion": SCHEMA_VERSION,
        "pairId": p["pairId"],
        "side": obj["side"],
        "baseAtoms": str(base_atoms),
        "quoteAtoms": str(quote_atoms),
        "baseMinConfirmations": base_conf,
        "quoteMinConfirmations": quote_conf,
        "fundingOrder": obj["fundingOrder"],
        "makerRefundSeconds": maker_refund,
        "takerRefundSeconds": taker_refund,
        "lifeSeconds": life,
    }


def canonical_intent_bytes(obj: Any, require_active_pair: bool = True) -> bytes:
    clean = validate_client_intent(obj, require_active_pair=require_active_pair)
    # sort_keys + compact separators + UTF-8 is the V1 canonical representation.
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def intent_hash_hex(obj: Any, require_active_pair: bool = True) -> str:
    return hashlib.sha256(canonical_intent_bytes(obj, require_active_pair=require_active_pair)).hexdigest()


def validate_public_advert(obj: Any, require_active_pair: bool = True) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        fail("advert must be an object")
    assert_no_forbidden_public_fields(obj)

    unknown = sorted(set(obj) - set(PUBLIC_ADVERT_KEYS))
    missing = [k for k in PUBLIC_ADVERT_KEYS if k not in obj]
    if unknown:
        fail("unknown advert field(s): " + ", ".join(unknown))
    if missing:
        fail("missing advert field(s): " + ", ".join(missing))

    intent = {k: obj[k] for k in CLIENT_INTENT_KEYS}
    clean = validate_client_intent(intent, require_active_pair=require_active_pair)

    advert_id = obj["advertId"]
    if not isinstance(advert_id, str) or not ADVERT_ID_RE.fullmatch(advert_id):
        fail("advertId must be 16 random bytes encoded as 32 lowercase hex characters")

    expected_hash = intent_hash_hex(clean, require_active_pair=require_active_pair)
    if obj["intentHash"] != expected_hash or not HASH_RE.fullmatch(str(obj["intentHash"])):
        fail("intentHash mismatch")

    created = parse_int("createdAt", obj["createdAt"], 1, 0x7FFFFFFFFFFFFFFF)
    expires = parse_int("expiresAt", obj["expiresAt"], 1, 0x7FFFFFFFFFFFFFFF)
    if expires <= created:
        fail("expiresAt must be greater than createdAt")
    if expires - created != clean["lifeSeconds"]:
        fail("expiresAt-createdAt must equal lifeSeconds")

    if obj["status"] not in PUBLIC_STATUSES:
        fail("invalid public status")

    return {
        **clean,
        "advertId": advert_id,
        "intentHash": expected_hash,
        "createdAt": created,
        "expiresAt": expires,
        "status": obj["status"],
    }


def maker_gives_asset(intent: Dict[str, Any]) -> str:
    p = pair_spec(intent["pairId"], require_active=False)
    return p["base"] if intent["side"] == "SELL_BASE" else p["quote"]


def maker_gets_asset(intent: Dict[str, Any]) -> str:
    p = pair_spec(intent["pairId"], require_active=False)
    return p["quote"] if intent["side"] == "SELL_BASE" else p["base"]


def price_quote_per_base(intent: Dict[str, Any]) -> Decimal:
    clean = validate_client_intent(intent, require_active_pair=False)
    p = pair_spec(clean["pairId"], require_active=False)
    base = ASSETS[p["base"]]
    quote = ASSETS[p["quote"]]
    getcontext().prec = 50
    base_units = Decimal(clean["baseAtoms"]) / (Decimal(10) ** int(base["decimals"]))
    quote_units = Decimal(clean["quoteAtoms"]) / (Decimal(10) ** int(quote["decimals"]))
    return quote_units / base_units


def registry_document() -> Dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "quantityEncoding": "unsigned base-10 atom strings",
        "priceConvention": "quote asset units per 1 base asset; derived from baseAtoms/quoteAtoms",
        "authoritativeTradeRule": "posted intents are not trades; only confirmed atomic settlements may feed LAST/volume/OHLC/VWAP",
        "assets": ASSETS,
        "pairs": PAIRS,
    }


def selftest() -> None:
    sample = {
        "schemaVersion": SCHEMA_VERSION,
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
    clean = validate_client_intent(sample)
    h = intent_hash_hex(sample)
    assert len(h) == 64
    assert maker_gives_asset(clean) == "TRU"
    assert maker_gets_asset(clean) == "BSTY"
    assert price_quote_per_base(clean) == Decimal("100")

    public = {
        **clean,
        "advertId": "11" * 16,
        "intentHash": h,
        "createdAt": 2_000_000_000,
        "expiresAt": 2_000_021_600,
        "status": "ACTIVE",
    }
    assert validate_public_advert(public)["intentHash"] == h

    # Planned pairs are registered but cannot become live accidentally.
    planned = {**sample, "pairId": "TRU_BTC"}
    try:
        validate_client_intent(planned)
        raise AssertionError("planned pair accepted as active")
    except ValueError as exc:
        assert "not active" in str(exc)

    # No private/swap material in the public intent.
    try:
        validate_client_intent({**sample, "secretHash160": "00" * 20})
        raise AssertionError("forbidden secretHash160 accepted")
    except ValueError as exc:
        assert "forbidden public field" in str(exc)

    # Timelock gap is enforced according to funding order.
    try:
        validate_client_intent({**sample, "makerRefundSeconds": 50000, "takerRefundSeconds": 40000})
        raise AssertionError("unsafe timeout gap accepted")
    except ValueError as exc:
        assert "first-funded leg" in str(exc)

    # Atom strings reject floats, signs, leading-zero ambiguity, and zero.
    for bad in (0, 1.2, "-1", "+1", "01", "0", "1.0"):
        try:
            validate_client_intent({**sample, "baseAtoms": bad})
            raise AssertionError(f"bad atom quantity accepted: {bad!r}")
        except ValueError:
            pass

    print("MARKET_01A0_SCHEMA_SELFTEST=PASS")
    print("ACTIVE_PAIR=TRU_BSTY")
    print("PLANNED_PAIR=TRU_BTC")
    print("PLANNED_PAIR=TRU_BSV")
    print("PRICE_CONVENTION=QUOTE_PER_BASE")
    print("PUBLIC_INTENT_SECRETS=NONE")
    print("POSTED_INTENT_IS_TRADE=NO")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--print-registry", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return 0
    if args.print_registry:
        print(json.dumps(registry_document(), indent=2, sort_keys=True))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
