#!/usr/bin/env python3
"""TRU-SWAP-OFFER-V2 two-party public handshake foundation.

Pure schema/canonicalization layer. No RPC, wallet, network, secret-preimage,
funding, transaction, or coin movement logic lives here.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from typing import Any, Dict

OFFER_VERSION = "TRU-SWAP-OFFER-V2"
ACCEPT_VERSION = "TRU-SWAP-ACCEPT-V2"
FINAL_VERSION = "TRU-SWAP-HANDSHAKE-V2"
PROTOCOL = "TRU-SWAP-V1"
PAIR_ID = "TRU_BSTY"
TRU_CHAIN_ID = "tru-mainnet"
BSTY_CHAIN_ID = "globalboost-mainnet"
MIN_TIMEOUT_GAP_SECONDS = 6 * 60 * 60
MAX_REFUND_SECONDS = 30 * 24 * 60 * 60
MAX_CONFIRMATIONS = 10_000

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
PUBKEY_RE = re.compile(r"^(02|03)[0-9a-f]{64}$")
ATOM_RE = re.compile(r"^[1-9][0-9]*$")

FORBIDDEN_KEY_PARTS = (
    "preimage", "privatekey", "privkey", "wif", "seed", "mnemonic",
    "passphrase", "password", "authtoken", "rpcpassword", "pairingtoken",
    "pairingsession", "truswaprpctoken",
)


class HandshakeError(ValueError):
    pass


def fail(message: str) -> None:
    raise HandshakeError(message)


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _walk_keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_keys(v)


def assert_public_only(value: Any) -> None:
    for key in _walk_keys(value):
        kl = key.lower()
        if any(part in kl for part in FORBIDDEN_KEY_PARTS):
            fail(f"forbidden private/secret field: {key}")


def canonical_bytes(value: Any) -> bytes:
    assert_public_only(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def domain_hash(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\x00" + canonical_bytes(value)
    ).hexdigest()


def _hex64(name: str, value: Any, *, nonzero: bool = True) -> str:
    v = str(value)
    if not HEX64_RE.fullmatch(v):
        fail(f"{name} must be 64 lowercase hex characters")
    if nonzero and v == "0" * 64:
        fail(f"{name} must not be all-zero")
    return v


def _h160(name: str, value: Any) -> str:
    v = str(value)
    if not HEX40_RE.fullmatch(v):
        fail(f"{name} must be 40 lowercase hex characters")
    return v


def _pubkey(name: str, value: Any) -> str:
    v = str(value)
    if not PUBKEY_RE.fullmatch(v):
        fail(f"{name} must be a compressed lowercase secp256k1 pubkey")
    return v


def _atom(name: str, value: Any) -> str:
    v = str(value)
    if not ATOM_RE.fullmatch(v):
        fail(f"{name} must be a positive canonical atom string")
    return v


def _bounded_int(name: str, value: Any, lo: int, hi: int) -> int:
    if isinstance(value, bool):
        fail(f"{name} must be an integer")
    try:
        n = int(value)
    except Exception:
        fail(f"{name} must be an integer")
    if str(n) != str(value) and not isinstance(value, int):
        fail(f"{name} must use canonical integer form")
    if n < lo or n > hi:
        fail(f"{name} outside {lo}..{hi}")
    return n


def expected_roles(maker_give_chain: str, participant: str) -> Dict[str, str]:
    if maker_give_chain not in {"tru", "bsty"}:
        fail("makerGiveChain must be tru or bsty")
    if participant not in {"maker", "taker"}:
        fail("participant must be maker or taker")

    if maker_give_chain == "tru":
        maker = {"tru": "refund", "bsty": "claim"}
    else:
        maker = {"tru": "claim", "bsty": "refund"}
    if participant == "maker":
        return maker
    return {
        "tru": "claim" if maker["tru"] == "refund" else "refund",
        "bsty": "claim" if maker["bsty"] == "refund" else "refund",
    }


def normalize_terms(obj: Any) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        fail("terms must be an object")
    assert_public_only(obj)
    required = {
        "pairId", "makerGiveChain", "truAmountAtoms", "bstyAmountAtoms",
        "truMinConfirmations", "bstyMinConfirmations", "fundingOrder",
        "makerRefundSeconds", "takerRefundSeconds",
    }
    unknown = sorted(set(obj) - required)
    missing = sorted(required - set(obj))
    if unknown:
        fail("unknown term field(s): " + ", ".join(unknown))
    if missing:
        fail("missing term field(s): " + ", ".join(missing))
    if obj["pairId"] != PAIR_ID:
        fail("pairId must be TRU_BSTY")
    maker_give = str(obj["makerGiveChain"])
    if maker_give not in {"tru", "bsty"}:
        fail("makerGiveChain must be tru or bsty")
    funding_order = str(obj["fundingOrder"])
    if funding_order not in {"MAKER_FIRST", "TAKER_FIRST"}:
        fail("fundingOrder must be MAKER_FIRST or TAKER_FIRST")

    maker_refund = _bounded_int(
        "makerRefundSeconds", obj["makerRefundSeconds"], 1, MAX_REFUND_SECONDS
    )
    taker_refund = _bounded_int(
        "takerRefundSeconds", obj["takerRefundSeconds"], 1, MAX_REFUND_SECONDS
    )
    gap = (
        maker_refund - taker_refund
        if funding_order == "MAKER_FIRST"
        else taker_refund - maker_refund
    )
    if gap < MIN_TIMEOUT_GAP_SECONDS:
        fail(
            f"first-funded participant must have at least "
            f"{MIN_TIMEOUT_GAP_SECONDS} seconds more refund time"
        )

    return {
        "pairId": PAIR_ID,
        "makerGiveChain": maker_give,
        "truAmountAtoms": _atom("truAmountAtoms", obj["truAmountAtoms"]),
        "bstyAmountAtoms": _atom("bstyAmountAtoms", obj["bstyAmountAtoms"]),
        "truMinConfirmations": _bounded_int(
            "truMinConfirmations", obj["truMinConfirmations"], 1, MAX_CONFIRMATIONS
        ),
        "bstyMinConfirmations": _bounded_int(
            "bstyMinConfirmations", obj["bstyMinConfirmations"], 1, MAX_CONFIRMATIONS
        ),
        "fundingOrder": funding_order,
        "makerRefundSeconds": maker_refund,
        "takerRefundSeconds": taker_refund,
    }


def normalize_role_material(
    obj: Any, participant: str, maker_give_chain: str
) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        fail("role material must be an object")
    assert_public_only(obj)
    expected = expected_roles(maker_give_chain, participant)
    required = {"participant", "tru", "bsty"}
    if set(obj) != required:
        fail("role material must contain exactly participant, tru, bsty")
    if obj["participant"] != participant:
        fail(f"role material participant must be {participant}")

    tru = obj["tru"]
    bsty = obj["bsty"]
    if not isinstance(tru, dict) or not isinstance(bsty, dict):
        fail("tru/bsty role material must be objects")
    if set(tru) != {"role", "allocationId", "pubkey"}:
        fail("TRU role material must contain role, allocationId, pubkey")
    if set(bsty) != {"role", "pubkey"}:
        fail("BSTY role material must contain role, pubkey")
    if tru["role"] != expected["tru"]:
        fail(f"{participant} TRU role must be {expected['tru']}")
    if bsty["role"] != expected["bsty"]:
        fail(f"{participant} BSTY role must be {expected['bsty']}")

    return {
        "participant": participant,
        "tru": {
            "role": expected["tru"],
            "allocationId": _hex64("allocationId", tru["allocationId"]),
            "pubkey": _pubkey("TRU pubkey", tru["pubkey"]),
        },
        "bsty": {
            "role": expected["bsty"],
            "pubkey": _pubkey("BSTY pubkey", bsty["pubkey"]),
        },
    }


def secret_owner(terms: Dict[str, Any]) -> str:
    return "maker" if terms["fundingOrder"] == "MAKER_FIRST" else "taker"


def make_offer(
    terms: Any,
    maker_role_material: Any,
    *,
    offer_nonce: str,
    created_at: int,
    expires_at: int,
    secret_hash160: str | None = None,
) -> Dict[str, Any]:
    t = normalize_terms(terms)
    maker = normalize_role_material(
        maker_role_material, "maker", t["makerGiveChain"]
    )
    nonce = _hex64("offerNonce", offer_nonce)
    created = _bounded_int("createdAt", created_at, 1, 0x7FFFFFFF)
    expires = _bounded_int("expiresAt", expires_at, created + 1, 0x7FFFFFFF)
    owner = secret_owner(t)

    core: Dict[str, Any] = {
        "version": OFFER_VERSION,
        "protocol": PROTOCOL,
        "offerNonce": nonce,
        "createdAt": created,
        "expiresAt": expires,
        "terms": t,
        "makerRoleMaterial": maker,
        "secretOwner": owner,
    }
    if owner == "maker":
        if secret_hash160 is None:
            fail("MAKER_FIRST offer requires maker secretHash160 commitment")
        core["secretHash160"] = _h160("secretHash160", secret_hash160)
    elif secret_hash160 is not None:
        fail("TAKER_FIRST offer must not contain maker secretHash160")

    offer = dict(core)
    offer["offerId"] = domain_hash(OFFER_VERSION, core)
    return offer


def validate_offer(obj: Any, *, now: int | None = None) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        fail("offer must be an object")
    assert_public_only(obj)
    if obj.get("version") != OFFER_VERSION or obj.get("protocol") != PROTOCOL:
        fail("unsupported offer version/protocol")
    offer_id = _hex64("offerId", obj.get("offerId"))
    t = normalize_terms(obj.get("terms"))
    maker = normalize_role_material(
        obj.get("makerRoleMaterial"), "maker", t["makerGiveChain"]
    )
    owner = secret_owner(t)
    if obj.get("secretOwner") != owner:
        fail("secretOwner does not match fundingOrder")
    created = _bounded_int("createdAt", obj.get("createdAt"), 1, 0x7FFFFFFF)
    expires = _bounded_int("expiresAt", obj.get("expiresAt"), created + 1, 0x7FFFFFFF)
    nonce = _hex64("offerNonce", obj.get("offerNonce"))

    core: Dict[str, Any] = {
        "version": OFFER_VERSION,
        "protocol": PROTOCOL,
        "offerNonce": nonce,
        "createdAt": created,
        "expiresAt": expires,
        "terms": t,
        "makerRoleMaterial": maker,
        "secretOwner": owner,
    }
    if owner == "maker":
        core["secretHash160"] = _h160("secretHash160", obj.get("secretHash160"))
    elif "secretHash160" in obj:
        fail("TAKER_FIRST offer must not carry secretHash160")

    expected_id = domain_hash(OFFER_VERSION, core)
    if offer_id != expected_id:
        fail("offerId canonical hash mismatch")
    clean = dict(core)
    clean["offerId"] = offer_id
    if set(obj) != set(clean):
        fail("offer contains unknown/missing fields")
    if now is not None and int(now) >= expires:
        fail("offer expired")
    return clean


def make_acceptance(
    offer: Any,
    taker_role_material: Any,
    *,
    accept_nonce: str,
    accepted_at: int,
    secret_hash160: str | None = None,
) -> Dict[str, Any]:
    o = validate_offer(offer, now=accepted_at)
    t = o["terms"]
    taker = normalize_role_material(
        taker_role_material, "taker", t["makerGiveChain"]
    )
    nonce = _hex64("acceptNonce", accept_nonce)
    accepted = _bounded_int(
        "acceptedAt", accepted_at, o["createdAt"], o["expiresAt"] - 1
    )
    owner = o["secretOwner"]

    core: Dict[str, Any] = {
        "version": ACCEPT_VERSION,
        "protocol": PROTOCOL,
        "offerId": o["offerId"],
        "acceptNonce": nonce,
        "acceptedAt": accepted,
        "takerRoleMaterial": taker,
        "secretOwner": owner,
    }
    if owner == "taker":
        if secret_hash160 is None:
            fail("TAKER_FIRST acceptance requires taker secretHash160 commitment")
        core["secretHash160"] = _h160("secretHash160", secret_hash160)
    elif secret_hash160 is not None:
        fail("MAKER_FIRST acceptance must not replace maker secretHash160")

    acceptance = dict(core)
    acceptance["acceptId"] = domain_hash(ACCEPT_VERSION, core)
    return acceptance


def validate_acceptance(
    offer: Any, acceptance: Any, *, now: int | None = None
) -> Dict[str, Any]:
    o = validate_offer(offer)
    if not isinstance(acceptance, dict):
        fail("acceptance must be an object")
    assert_public_only(acceptance)
    if acceptance.get("version") != ACCEPT_VERSION or acceptance.get("protocol") != PROTOCOL:
        fail("unsupported acceptance version/protocol")
    if acceptance.get("offerId") != o["offerId"]:
        fail("acceptance references a different offer")
    accept_id = _hex64("acceptId", acceptance.get("acceptId"))
    accepted = _bounded_int(
        "acceptedAt", acceptance.get("acceptedAt"), o["createdAt"], o["expiresAt"] - 1
    )
    nonce = _hex64("acceptNonce", acceptance.get("acceptNonce"))
    taker = normalize_role_material(
        acceptance.get("takerRoleMaterial"), "taker", o["terms"]["makerGiveChain"]
    )
    owner = o["secretOwner"]
    if acceptance.get("secretOwner") != owner:
        fail("acceptance secretOwner mismatch")

    core: Dict[str, Any] = {
        "version": ACCEPT_VERSION,
        "protocol": PROTOCOL,
        "offerId": o["offerId"],
        "acceptNonce": nonce,
        "acceptedAt": accepted,
        "takerRoleMaterial": taker,
        "secretOwner": owner,
    }
    if owner == "taker":
        core["secretHash160"] = _h160(
            "secretHash160", acceptance.get("secretHash160")
        )
    elif "secretHash160" in acceptance:
        fail("MAKER_FIRST acceptance must not carry secretHash160")

    expected_id = domain_hash(ACCEPT_VERSION, core)
    if accept_id != expected_id:
        fail("acceptId canonical hash mismatch")
    clean = dict(core)
    clean["acceptId"] = accept_id
    if set(acceptance) != set(clean):
        fail("acceptance contains unknown/missing fields")
    if now is not None and int(now) >= o["expiresAt"]:
        fail("offer expired before finalization")
    return clean


def final_record_params(offer: Any, acceptance: Any, *, finalized_at: int) -> Dict[str, Any]:
    o = validate_offer(offer)
    a = validate_acceptance(o, acceptance, now=finalized_at)
    t = o["terms"]
    finalized = _bounded_int(
        "finalizedAt", finalized_at, a["acceptedAt"], o["expiresAt"] - 1
    )
    maker = o["makerRoleMaterial"]
    taker = a["takerRoleMaterial"]

    if maker["tru"]["allocationId"] == taker["tru"]["allocationId"]:
        fail("maker/taker TRU allocationId values must be distinct")
    if maker["tru"]["pubkey"] == taker["tru"]["pubkey"]:
        fail("maker/taker TRU pubkeys must be distinct")
    if maker["bsty"]["pubkey"] == taker["bsty"]["pubkey"]:
        fail("maker/taker BSTY pubkeys must be distinct")

    by_tru_role = {
        maker["tru"]["role"]: maker["tru"],
        taker["tru"]["role"]: taker["tru"],
    }
    by_bsty_role = {
        maker["bsty"]["role"]: maker["bsty"],
        taker["bsty"]["role"]: taker["bsty"],
    }
    if set(by_tru_role) != {"claim", "refund"} or set(by_bsty_role) != {"claim", "refund"}:
        fail("handshake does not contain exactly one owner for each chain role")

    secret_hash = (
        o["secretHash160"]
        if o["secretOwner"] == "maker"
        else a["secretHash160"]
    )

    maker_give = t["makerGiveChain"]
    taker_give = "bsty" if maker_give == "tru" else "tru"
    first_chain = maker_give if t["fundingOrder"] == "MAKER_FIRST" else taker_give
    chain_funding_order = "TRU_FIRST" if first_chain == "tru" else "BSTY_FIRST"

    maker_refund_time = finalized + t["makerRefundSeconds"]
    taker_refund_time = finalized + t["takerRefundSeconds"]
    if maker_give == "tru":
        tru_refund_time = maker_refund_time
        bsty_refund_time = taker_refund_time
    else:
        tru_refund_time = taker_refund_time
        bsty_refund_time = maker_refund_time

    first_time = tru_refund_time if first_chain == "tru" else bsty_refund_time
    second_time = bsty_refund_time if first_chain == "tru" else tru_refund_time
    if first_time - second_time < MIN_TIMEOUT_GAP_SECONDS:
        fail("finalized refund-time gap is unsafe")
    if max(tru_refund_time, bsty_refund_time) > 0x7FFFFFFF:
        fail("finalized refund time exceeds TRU-SWAP-V1 timestamp domain")

    return {
        "truChainId": TRU_CHAIN_ID,
        "bstyChainId": BSTY_CHAIN_ID,
        "fundingOrder": chain_funding_order,
        "secretHash160": secret_hash,
        "truClaimPubkey": by_tru_role["claim"]["pubkey"],
        "truRefundPubkey": by_tru_role["refund"]["pubkey"],
        "bstyClaimPubkey": by_bsty_role["claim"]["pubkey"],
        "bstyRefundPubkey": by_bsty_role["refund"]["pubkey"],
        "truClaimAllocationId": by_tru_role["claim"]["allocationId"],
        "truRefundAllocationId": by_tru_role["refund"]["allocationId"],
        "truAmountAtoms": int(t["truAmountAtoms"]),
        "bstyAmountAtoms": int(t["bstyAmountAtoms"]),
        "truRefundTime": tru_refund_time,
        "bstyRefundTime": bsty_refund_time,
    }


def final_bundle(offer: Any, acceptance: Any, *, finalized_at: int) -> Dict[str, Any]:
    o = validate_offer(offer)
    a = validate_acceptance(o, acceptance, now=finalized_at)
    params = final_record_params(o, a, finalized_at=finalized_at)
    core = {
        "version": FINAL_VERSION,
        "protocol": PROTOCOL,
        "offerId": o["offerId"],
        "acceptId": a["acceptId"],
        "secretOwner": o["secretOwner"],
        "recordParams": params,
    }
    out = dict(core)
    out["handshakeId"] = domain_hash(FINAL_VERSION, core)
    return out


def _role(participant: str, maker_give: str, n: int) -> Dict[str, Any]:
    roles = expected_roles(maker_give, participant)
    # Synthetic compressed keys are shape vectors for the pure handshake test.
    # Runtime wallet/node validity is separately proven in 01A/01B1/01B1A.
    tru_prefix = "02" if n % 2 == 0 else "03"
    bsty_prefix = "03" if n % 2 == 0 else "02"
    return {
        "participant": participant,
        "tru": {
            "role": roles["tru"],
            "allocationId": f"{n:064x}",
            "pubkey": tru_prefix + f"{n + 100:064x}",
        },
        "bsty": {
            "role": roles["bsty"],
            "pubkey": bsty_prefix + f"{n + 200:064x}",
        },
    }


def _terms(maker_give: str, funding_order: str) -> Dict[str, Any]:
    if funding_order == "MAKER_FIRST":
        maker_refund, taker_refund = 86400, 43200
    else:
        maker_refund, taker_refund = 43200, 86400
    return {
        "pairId": PAIR_ID,
        "makerGiveChain": maker_give,
        "truAmountAtoms": "100000000",
        "bstyAmountAtoms": "250000000",
        "truMinConfirmations": 6,
        "bstyMinConfirmations": 6,
        "fundingOrder": funding_order,
        "makerRefundSeconds": maker_refund,
        "takerRefundSeconds": taker_refund,
    }


def _expect_error(fn, label: str) -> None:
    try:
        fn()
    except HandshakeError:
        return
    raise AssertionError(label)


def selftest() -> None:
    now = 2_000_000_000
    case_no = 0
    for maker_give in ("tru", "bsty"):
        for funding_order in ("MAKER_FIRST", "TAKER_FIRST"):
            case_no += 1
            terms = _terms(maker_give, funding_order)
            maker = _role("maker", maker_give, case_no * 10 + 1)
            taker = _role("taker", maker_give, case_no * 10 + 2)
            maker_secret = "11" * 20 if funding_order == "MAKER_FIRST" else None
            taker_secret = "22" * 20 if funding_order == "TAKER_FIRST" else None
            offer = make_offer(
                terms,
                maker,
                offer_nonce=f"{case_no + 100:064x}",
                created_at=now,
                expires_at=now + 3600,
                secret_hash160=maker_secret,
            )
            accepted = make_acceptance(
                offer,
                taker,
                accept_nonce=f"{case_no + 200:064x}",
                accepted_at=now + 10,
                secret_hash160=taker_secret,
            )
            bundle = final_bundle(offer, accepted, finalized_at=now + 20)
            rp = bundle["recordParams"]

            expected_first = (
                maker_give
                if funding_order == "MAKER_FIRST"
                else ("bsty" if maker_give == "tru" else "tru")
            )
            assert rp["fundingOrder"] == (
                "TRU_FIRST" if expected_first == "tru" else "BSTY_FIRST"
            )
            if expected_first == "tru":
                assert rp["truRefundTime"] - rp["bstyRefundTime"] >= MIN_TIMEOUT_GAP_SECONDS
            else:
                assert rp["bstyRefundTime"] - rp["truRefundTime"] >= MIN_TIMEOUT_GAP_SECONDS

            maker_roles = expected_roles(maker_give, "maker")
            if maker_roles["tru"] == "claim":
                assert rp["truClaimPubkey"] == maker["tru"]["pubkey"]
                assert rp["truClaimAllocationId"] == maker["tru"]["allocationId"]
            else:
                assert rp["truRefundPubkey"] == maker["tru"]["pubkey"]
                assert rp["truRefundAllocationId"] == maker["tru"]["allocationId"]
            if maker_roles["bsty"] == "claim":
                assert rp["bstyClaimPubkey"] == maker["bsty"]["pubkey"]
            else:
                assert rp["bstyRefundPubkey"] == maker["bsty"]["pubkey"]

            assert bundle["secretOwner"] == (
                "maker" if funding_order == "MAKER_FIRST" else "taker"
            )
            assert "preimage" not in json.dumps(bundle).lower()
            assert "private" not in json.dumps(bundle).lower()

            # Canonical stability under key reordering.
            reordered = json.loads(json.dumps(offer, sort_keys=False))
            assert validate_offer(reordered)["offerId"] == offer["offerId"]

            # Offer tamper must invalidate its canonical id.
            tampered = copy.deepcopy(offer)
            tampered["terms"]["truAmountAtoms"] = "100000001"
            _expect_error(lambda: validate_offer(tampered), "tampered offer accepted")

            # Acceptance cannot be moved to another offer.
            bad_accept = copy.deepcopy(accepted)
            bad_accept["offerId"] = "ab" * 32
            _expect_error(
                lambda: validate_acceptance(offer, bad_accept),
                "cross-offer acceptance replay accepted",
            )

            # Participant role ownership cannot be swapped.
            bad_role = copy.deepcopy(taker)
            bad_role["tru"]["role"] = maker_roles["tru"]
            _expect_error(
                lambda: make_acceptance(
                    offer,
                    bad_role,
                    accept_nonce=f"{case_no + 300:064x}",
                    accepted_at=now + 11,
                    secret_hash160=taker_secret,
                ),
                "wrong taker TRU role accepted",
            )

    # Secret ownership follows first funder; wrong placement is rejected.
    maker_first_offer = make_offer(
        _terms("tru", "MAKER_FIRST"),
        _role("maker", "tru", 91),
        offer_nonce="91" * 32,
        created_at=now,
        expires_at=now + 3600,
        secret_hash160="33" * 20,
    )
    _expect_error(
        lambda: make_acceptance(
            maker_first_offer,
            _role("taker", "tru", 92),
            accept_nonce="92" * 32,
            accepted_at=now + 1,
            secret_hash160="44" * 20,
        ),
        "taker replaced maker-owned secret commitment",
    )

    taker_first_terms = _terms("tru", "TAKER_FIRST")
    _expect_error(
        lambda: make_offer(
            taker_first_terms,
            _role("maker", "tru", 93),
            offer_nonce="93" * 32,
            created_at=now,
            expires_at=now + 3600,
            secret_hash160="55" * 20,
        ),
        "maker secret accepted for TAKER_FIRST",
    )

    # Private/secret-preimage material is never part of handshake envelopes.
    bad_terms = dict(_terms("tru", "MAKER_FIRST"))
    bad_terms["preimage"] = "00" * 32
    _expect_error(lambda: normalize_terms(bad_terms), "preimage field accepted")

    # Expired offers fail closed.
    exp = make_offer(
        _terms("tru", "MAKER_FIRST"),
        _role("maker", "tru", 94),
        offer_nonce="94" * 32,
        created_at=now,
        expires_at=now + 10,
        secret_hash160="66" * 20,
    )
    _expect_error(lambda: validate_offer(exp, now=now + 10), "expired offer accepted")

    print("SWAP_FRESH_01B2_HANDSHAKE_SELFTEST=PASS")
    print("OFFER_VERSION=TRU-SWAP-OFFER-V2")
    print("ACCEPT_VERSION=TRU-SWAP-ACCEPT-V2")
    print("FINAL_VERSION=TRU-SWAP-HANDSHAKE-V2")
    print("ROLE_OWNERSHIP_BOTH_DIRECTIONS=PASS")
    print("FUNDING_ORDER_BOTH_DIRECTIONS=PASS")
    print("FIRST_FUNDER_SECRET_OWNER=PASS")
    print("CANONICAL_OFFER_ID=PASS")
    print("CANONICAL_ACCEPT_ID=PASS")
    print("CROSS_OFFER_REPLAY=REJECTED")
    print("TAMPERED_OFFER=REJECTED")
    print("PRIVATE_MATERIAL=NONE")
    print("PREIMAGE=NONE")
    print("SWAP_RECORD_CREATE=NO")
    print("FUNDING=NO")
    print("COIN_MOVEMENT=NO")


def main() -> int:
    ap = argparse.ArgumentParser(description="TRU two-party offer handshake V2 foundation")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
