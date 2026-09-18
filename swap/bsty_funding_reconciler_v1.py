#!/usr/bin/env python3
"""
TRU SWAP-FRESH-01B4C — BSTY funding reconciliation foundation.

Pure read-only reconciliation logic for an already-prepared BSTY funding
journal attempt. This module never broadcasts, never calls sendtoaddress,
never mutates SWAP-A state, and never writes journal state.

Candidate identity is the exact per-swap BSTY P2SH output:
  * frozen 103-byte TRU-SWAP-V1 redeem script,
  * HASH160(redeem) P2SH scriptPubKey,
  * exact uint64 BSTY amount,
  * transaction observed in mempool or a block at/after startingHeight.

Zero candidates are never treated as permission to retry.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any, Callable, Dict, Iterable, List, Mapping

VERSION = "BSTY-FUNDING-RECONCILER-V1"
JOURNAL_DOMAIN = "TRU-SWAP-FUNDING-V1"
COMMITMENT_DOMAIN = "TRU-SWAP-BSTY-CONTRACT-COMMITMENT-V1"
MAX_SCAN_BLOCKS_DEFAULT = 4096

REFUND_TIME_MIN = 500_000_000
REFUND_TIME_MAX = 0x7FFFFFFF

OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_CHECKLOCKTIMEVERIFY = 0xB1


class ReconcileError(RuntimeError):
    pass


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _require_hex(value: Any, nbytes: int, name: str) -> str:
    s = str(value or "")
    if not re.fullmatch(rf"[0-9a-f]{{{nbytes * 2}}}", s):
        raise ReconcileError(f"{name} must be lowercase {nbytes}-byte hex")
    return s


def _require_atoms(value: Any) -> int:
    if isinstance(value, bool):
        raise ReconcileError("amountAtoms")
    s = str(value)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", s):
        raise ReconcileError("amountAtoms")
    n = int(s)
    if n <= 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ReconcileError("amountAtoms")
    return n


def _push(data: bytes) -> bytes:
    n = len(data)
    if n > 75:
        raise ReconcileError("push too large for frozen V1 script")
    return bytes([n]) + data


def _scriptnum(n: int) -> bytes:
    if n < 0:
        raise ReconcileError("negative scriptnum")
    if n == 0:
        return b""
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def canonical_bsty_redeem_script(record: Mapping[str, Any]) -> bytes:
    secret = bytes.fromhex(_require_hex(record.get("secretHash160"), 20, "secretHash160"))
    claim = bytes.fromhex(_require_hex(record.get("bstyClaimPubkey"), 33, "bstyClaimPubkey"))
    refund = bytes.fromhex(_require_hex(record.get("bstyRefundPubkey"), 33, "bstyRefundPubkey"))

    if claim[0] not in (2, 3) or refund[0] not in (2, 3):
        raise ReconcileError("BSTY role pubkeys must be compressed SEC1")
    if claim == refund:
        raise ReconcileError("BSTY claim/refund role pubkeys must be distinct")

    refund_time = int(record.get("bstyRefundTime", 0))
    if not (REFUND_TIME_MIN <= refund_time <= REFUND_TIME_MAX):
        raise ReconcileError("bstyRefundTime outside frozen V1 timestamp domain")

    script = (
        bytes([OP_IF, OP_HASH160])
        + _push(secret)
        + bytes([OP_EQUALVERIFY])
        + _push(claim)
        + bytes([OP_CHECKSIG, OP_ELSE])
        + _push(_scriptnum(refund_time))
        + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
        + _push(refund)
        + bytes([OP_CHECKSIG, OP_ENDIF])
    )
    if len(script) != 103:
        raise ReconcileError(f"canonical BSTY HTLC length drift: {len(script)}")
    return script


def canonical_bsty_p2sh_scriptpubkey(record: Mapping[str, Any]) -> bytes:
    redeem = canonical_bsty_redeem_script(record)
    return bytes([OP_HASH160, 0x14]) + hash160(redeem) + bytes([OP_EQUAL])


def bsty_contract_commitment(record: Mapping[str, Any]) -> str:
    spk = canonical_bsty_p2sh_scriptpubkey(record)
    payload = COMMITMENT_DOMAIN.encode("ascii") + b"|" + spk
    return hashlib.sha256(payload).hexdigest()


def expected_bsty_funding(record: Mapping[str, Any]) -> Dict[str, Any]:
    redeem = canonical_bsty_redeem_script(record)
    spk = canonical_bsty_p2sh_scriptpubkey(record)
    return {
        "amountAtoms": _require_atoms(record.get("bstyAmountAtoms")),
        "redeemScriptHex": redeem.hex(),
        "p2shScriptPubKeyHex": spk.hex(),
        "commitment": bsty_contract_commitment(record),
    }


def validate_bsty_journal_attempt(
    record: Mapping[str, Any], attempt: Mapping[str, Any]
) -> Dict[str, Any]:
    swap_id = _require_hex(record.get("swapId"), 32, "swapId")
    if str(attempt.get("swapId", "")) != swap_id:
        raise ReconcileError("journal swapId mismatch")
    if attempt.get("chain") != "bsty":
        raise ReconcileError("journal chain must be bsty")

    expected = expected_bsty_funding(record)
    if _require_atoms(attempt.get("amountAtoms")) != expected["amountAtoms"]:
        raise ReconcileError("journal BSTY amount mismatch")
    if str(attempt.get("expectedContractCommitment", "")) != expected["commitment"]:
        raise ReconcileError("journal BSTY contract commitment mismatch")

    starting_height = int(attempt.get("startingHeight", -1))
    if starting_height < 0:
        raise ReconcileError("journal startingHeight")

    state = str(attempt.get("state", ""))
    if state not in {
        "PREPARED", "BROADCASTING", "TX_IDENTIFIED", "CONFIRMED",
        "RECORDED", "AMBIGUOUS", "ABORTED",
    }:
        raise ReconcileError("journal state")

    return expected


def _read_varint(raw: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(raw):
        raise ReconcileError("truncated varint")
    x = raw[pos]
    pos += 1
    if x < 0xFD:
        return x, pos
    if x == 0xFD:
        if pos + 2 > len(raw):
            raise ReconcileError("truncated varint16")
        return int.from_bytes(raw[pos:pos + 2], "little"), pos + 2
    if x == 0xFE:
        if pos + 4 > len(raw):
            raise ReconcileError("truncated varint32")
        return int.from_bytes(raw[pos:pos + 4], "little"), pos + 4
    if pos + 8 > len(raw):
        raise ReconcileError("truncated varint64")
    return int.from_bytes(raw[pos:pos + 8], "little"), pos + 8


def parse_bsty_tx_outputs(raw_hex: str) -> List[Dict[str, Any]]:
    """Parse Bitcoin-family raw transaction outputs with exact uint64 values."""
    if not isinstance(raw_hex, str) or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise ReconcileError("raw BSTY transaction must be hex")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReconcileError("raw BSTY transaction hex") from exc

    pos = 0
    if len(raw) < 4:
        raise ReconcileError("truncated version")
    pos += 4

    segwit = False
    if pos + 2 <= len(raw) and raw[pos] == 0 and raw[pos + 1] != 0:
        segwit = True
        pos += 2

    nvin, pos = _read_varint(raw, pos)
    if nvin > 100_000:
        raise ReconcileError("unreasonable vin count")
    for _ in range(nvin):
        if pos + 36 > len(raw):
            raise ReconcileError("truncated input")
        pos += 36
        script_len, pos = _read_varint(raw, pos)
        if script_len > len(raw) - pos:
            raise ReconcileError("truncated scriptSig")
        pos += script_len
        if pos + 4 > len(raw):
            raise ReconcileError("truncated sequence")
        pos += 4

    nvout, pos = _read_varint(raw, pos)
    if nvout > 100_000:
        raise ReconcileError("unreasonable vout count")

    outputs: List[Dict[str, Any]] = []
    for n in range(nvout):
        if pos + 8 > len(raw):
            raise ReconcileError("truncated output amount")
        amount = int.from_bytes(raw[pos:pos + 8], "little")
        pos += 8
        script_len, pos = _read_varint(raw, pos)
        if script_len > len(raw) - pos:
            raise ReconcileError("truncated scriptPubKey")
        script = raw[pos:pos + script_len]
        pos += script_len
        outputs.append({
            "n": n,
            "amountAtoms": amount,
            "scriptPubKeyHex": script.hex(),
        })

    if segwit:
        for _ in range(nvin):
            nstack, pos = _read_varint(raw, pos)
            for _ in range(nstack):
                item_len, pos = _read_varint(raw, pos)
                if item_len > len(raw) - pos:
                    raise ReconcileError("truncated witness item")
                pos += item_len

    if pos + 4 > len(raw):
        raise ReconcileError("truncated locktime")
    pos += 4
    if pos != len(raw):
        raise ReconcileError("unexpected trailing BSTY transaction bytes")

    return outputs


def _matching_vouts(
    outputs: Iterable[Mapping[str, Any]], expected: Mapping[str, Any]
) -> List[int]:
    hits: List[int] = []
    for row in outputs:
        try:
            n = int(row.get("n", -1))
            amount = int(row.get("amountAtoms", -1))
            script = str(row.get("scriptPubKeyHex", "")).lower()
        except Exception:
            continue
        if (
            n >= 0
            and amount == expected["amountAtoms"]
            and script == expected["p2shScriptPubKeyHex"]
        ):
            hits.append(n)
    return sorted(set(hits))


def _txid_list(mempool: Any) -> List[str]:
    if isinstance(mempool, Mapping):
        rows = list(mempool.keys())
    elif isinstance(mempool, list):
        rows = list(mempool)
    else:
        raise ReconcileError("BSTY getrawmempool response")
    out: List[str] = []
    for txid in rows:
        s = str(txid)
        if not re.fullmatch(r"[0-9a-f]{64}", s):
            raise ReconcileError("BSTY mempool malformed txid")
        out.append(s)
    return out


def scan_bsty_funding_candidates(
    record: Mapping[str, Any],
    attempt: Mapping[str, Any],
    rpc: Callable[[str, Mapping[str, Any]], Any],
    *,
    max_scan_blocks: int = MAX_SCAN_BLOCKS_DEFAULT,
) -> List[Dict[str, Any]]:
    expected = validate_bsty_journal_attempt(record, attempt)
    starting_height = int(attempt["startingHeight"])
    if max_scan_blocks < 1:
        raise ReconcileError("max_scan_blocks")

    found: Dict[tuple[str, int], Dict[str, Any]] = {}

    mempool = rpc("getrawmempool", {})
    for txid in _txid_list(mempool):
        raw_hex = rpc("getrawtransaction", {
            "txid": txid,
            "verbose": False,
            "blockhash": None,
        })
        if not isinstance(raw_hex, str):
            raise ReconcileError("BSTY mempool getrawtransaction response")
        for vout in _matching_vouts(parse_bsty_tx_outputs(raw_hex), expected):
            found[(txid, vout)] = {
                "txid": txid,
                "vout": vout,
                "confirmations": 0,
                "blockHeight": None,
                "location": "mempool",
            }

    tip_raw = rpc("getblockcount", {})
    try:
        tip = int(tip_raw)
    except Exception as exc:
        raise ReconcileError("BSTY getblockcount response") from exc
    if tip < -1:
        raise ReconcileError("BSTY negative tip")

    if starting_height <= tip:
        span = tip - starting_height + 1
        if span > max_scan_blocks:
            raise ReconcileError(
                f"BSTY reconciliation scan span {span} exceeds cap {max_scan_blocks}"
            )

        for height in range(starting_height, tip + 1):
            blockhash = rpc("getblockhash", {"height": height})
            if not isinstance(blockhash, str) or not re.fullmatch(r"[0-9a-f]{64}", blockhash):
                raise ReconcileError(f"BSTY getblockhash response at height {height}")

            block = rpc("getblock", {"blockhash": blockhash, "verbosity": 1})
            if not isinstance(block, Mapping):
                raise ReconcileError(f"BSTY getblock response at height {height}")
            txs = block.get("tx")
            if not isinstance(txs, list):
                raise ReconcileError(f"BSTY block tx list missing at height {height}")

            for item in txs:
                txid = str(item.get("txid")) if isinstance(item, Mapping) else str(item)
                if not re.fullmatch(r"[0-9a-f]{64}", txid):
                    raise ReconcileError("BSTY block contains malformed txid")

                raw_hex = None
                if isinstance(item, Mapping) and isinstance(item.get("hex"), str):
                    raw_hex = item["hex"]
                if raw_hex is None:
                    raw_hex = rpc("getrawtransaction", {
                        "txid": txid,
                        "verbose": False,
                        "blockhash": blockhash,
                    })
                if not isinstance(raw_hex, str):
                    raise ReconcileError("BSTY confirmed getrawtransaction response")

                for vout in _matching_vouts(parse_bsty_tx_outputs(raw_hex), expected):
                    found[(txid, vout)] = {
                        "txid": txid,
                        "vout": vout,
                        "confirmations": tip - height + 1,
                        "blockHeight": height,
                        "location": "block",
                    }

    return sorted(found.values(), key=lambda x: (x["txid"], x["vout"]))


def classify_bsty_candidates(candidates: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    rows = list(candidates)
    if not rows:
        return {
            "classification": "ZERO_CANDIDATES",
            "candidateCount": 0,
            "safeToRetry": False,
            "action": "HOLD_RECONCILE",
        }
    if len(rows) == 1:
        return {
            "classification": "ONE_CANDIDATE",
            "candidateCount": 1,
            "safeToRetry": False,
            "action": "ADOPT_TX_IDENTIFIED",
            "candidate": dict(rows[0]),
        }
    return {
        "classification": "MULTIPLE_CANDIDATES",
        "candidateCount": len(rows),
        "safeToRetry": False,
        "action": "AMBIGUOUS_FAIL_CLOSED",
    }


def reconcile_bsty_attempt(
    record: Mapping[str, Any],
    attempt: Mapping[str, Any],
    rpc: Callable[[str, Mapping[str, Any]], Any],
    *,
    max_scan_blocks: int = MAX_SCAN_BLOCKS_DEFAULT,
) -> Dict[str, Any]:
    candidates = scan_bsty_funding_candidates(
        record, attempt, rpc, max_scan_blocks=max_scan_blocks
    )
    out = classify_bsty_candidates(candidates)
    out["journalState"] = str(attempt.get("state", ""))
    out["journalMutation"] = False
    out["swapStateMutation"] = False
    out["broadcast"] = False
    return out


def _vi(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _fixture_tx(outputs: List[tuple[int, bytes]], *, segwit: bool = False) -> str:
    raw = bytearray()
    raw += struct.pack("<I", 2)
    if segwit:
        raw += b"\x00\x01"
    raw += _vi(1)
    raw += bytes.fromhex("11" * 32)
    raw += struct.pack("<I", 0)
    raw += _vi(0)
    raw += struct.pack("<I", 0xFFFFFFFE)
    raw += _vi(len(outputs))
    for amount, script in outputs:
        raw += struct.pack("<Q", amount)
        raw += _vi(len(script))
        raw += script
    if segwit:
        raw += _vi(1) + _vi(2) + b"\x01\x02"
    raw += struct.pack("<I", 0)
    return raw.hex()


def selftest() -> None:
    record = {
        "swapId": "12" * 32,
        "secretHash160": "34" * 20,
        "bstyClaimPubkey": "02" + "56" * 32,
        "bstyRefundPubkey": "03" + "78" * 32,
        "bstyRefundTime": 1_800_000_000,
        "bstyAmountAtoms": "9007199254740993",
    }
    expected = expected_bsty_funding(record)
    attempt = {
        "swapId": record["swapId"],
        "chain": "bsty",
        "amountAtoms": record["bstyAmountAtoms"],
        "expectedContractCommitment": expected["commitment"],
        "startingHeight": 100,
        "state": "BROADCASTING",
    }

    assert len(bytes.fromhex(expected["redeemScriptHex"])) == 103
    assert len(bytes.fromhex(expected["p2shScriptPubKeyHex"])) == 23
    assert expected["p2shScriptPubKeyHex"].startswith("a914")
    assert expected["p2shScriptPubKeyHex"].endswith("87")
    assert expected["amountAtoms"] == 9007199254740993

    raw = _fixture_tx([
        (7, b"\x51"),
        (expected["amountAtoms"], bytes.fromhex(expected["p2shScriptPubKeyHex"])),
    ])
    parsed = parse_bsty_tx_outputs(raw)
    assert parsed[1]["amountAtoms"] == 9007199254740993
    assert _matching_vouts(parsed, expected) == [1]

    raw_wit = _fixture_tx([
        (expected["amountAtoms"], bytes.fromhex(expected["p2shScriptPubKeyHex"])),
    ], segwit=True)
    assert _matching_vouts(parse_bsty_tx_outputs(raw_wit), expected) == [0]

    tx1 = "aa" * 32
    tx2 = "bb" * 32
    wrong = "cc" * 32
    bh100 = "dd" * 32
    bh101 = "ee" * 32

    wrong_raw = _fixture_tx([
        (expected["amountAtoms"] + 1, bytes.fromhex(expected["p2shScriptPubKeyHex"])),
    ])

    fixture = {
        ("getrawmempool", None): [tx1, wrong],
        ("getrawtransaction", tx1): raw,
        ("getrawtransaction", wrong): wrong_raw,
        ("getblockcount", None): 101,
        ("getblockhash", 100): bh100,
        ("getblockhash", 101): bh101,
        ("getblock", bh100): {"tx": []},
        ("getblock", bh101): {"tx": []},
    }

    def rpc(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return fixture[(method, None)]
        if method == "getrawtransaction":
            return fixture[(method, str(params["txid"]))]
        if method == "getblockcount":
            return fixture[(method, None)]
        if method == "getblockhash":
            return fixture[(method, int(params["height"]))]
        if method == "getblock":
            return fixture[(method, str(params["blockhash"]))]
        raise AssertionError(method)

    rows = scan_bsty_funding_candidates(record, attempt, rpc)
    assert len(rows) == 1 and rows[0]["txid"] == tx1 and rows[0]["vout"] == 1
    assert rows[0]["confirmations"] == 0

    zero = classify_bsty_candidates([])
    assert zero["classification"] == "ZERO_CANDIDATES"
    assert zero["safeToRetry"] is False
    assert zero["action"] == "HOLD_RECONCILE"

    one = classify_bsty_candidates(rows)
    assert one["classification"] == "ONE_CANDIDATE"
    assert one["action"] == "ADOPT_TX_IDENTIFIED"

    multi = classify_bsty_candidates([
        {"txid": tx1, "vout": 1}, {"txid": tx2, "vout": 0}
    ])
    assert multi["classification"] == "MULTIPLE_CANDIDATES"
    assert multi["action"] == "AMBIGUOUS_FAIL_CLOSED"

    confirmed = _fixture_tx([
        (expected["amountAtoms"], bytes.fromhex(expected["p2shScriptPubKeyHex"])),
    ])
    bh102 = "ff" * 32
    fixture2 = {
        ("getrawmempool", None): [],
        ("getblockcount", None): 102,
        ("getblockhash", 100): bh100,
        ("getblockhash", 101): bh101,
        ("getblockhash", 102): bh102,
        ("getblock", bh100): {"tx": []},
        ("getblock", bh101): {"tx": [tx2]},
        ("getblock", bh102): {"tx": []},
        ("getrawtransaction", tx2): confirmed,
    }

    def rpc2(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return fixture2[(method, None)]
        if method == "getblockcount":
            return fixture2[(method, None)]
        if method == "getblockhash":
            return fixture2[(method, int(params["height"]))]
        if method == "getblock":
            return fixture2[(method, str(params["blockhash"]))]
        if method == "getrawtransaction":
            return fixture2[(method, str(params["txid"]))]
        raise AssertionError(method)

    rows2 = scan_bsty_funding_candidates(record, attempt, rpc2)
    assert len(rows2) == 1
    assert rows2[0]["txid"] == tx2
    assert rows2[0]["vout"] == 0
    assert rows2[0]["confirmations"] == 2
    assert rows2[0]["blockHeight"] == 101

    bad = dict(attempt)
    bad["expectedContractCommitment"] = "00" * 32
    try:
        validate_bsty_journal_attempt(record, bad)
    except ReconcileError:
        pass
    else:
        raise AssertionError("commitment mismatch accepted")

    def rpc_large(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return []
        if method == "getblockcount":
            return 5000
        raise AssertionError(method)

    try:
        scan_bsty_funding_candidates(record, attempt, rpc_large, max_scan_blocks=5)
    except ReconcileError:
        pass
    else:
        raise AssertionError("scan cap not enforced")

    print("SWAP_FRESH_01B4C_BSTY_RECONCILER_SELFTEST=PASS")
    print("VERSION=BSTY-FUNDING-RECONCILER-V1")
    print("FROZEN_BSTY_REDEEMSCRIPT_BYTES=103")
    print("BSTY_P2SH_SCRIPTPUBKEY_BYTES=23")
    print("EXACT_UINT64_RAW_TX_PARSE=PASS")
    print("SEGWIT_RAW_TX_PARSE=PASS")
    print("MEMPOOL_EXACT_CANDIDATE_SCAN=PASS")
    print("BLOCK_EXACT_CANDIDATE_SCAN=PASS")
    print("BLOCK_CONFIRMATION_DERIVATION=PASS")
    print("WRONG_AMOUNT_OR_OUTPUT=IGNORED")
    print("ZERO_CANDIDATE_SAFE_TO_RETRY=NO")
    print("ONE_CANDIDATE_ACTION=ADOPT_TX_IDENTIFIED")
    print("MULTIPLE_CANDIDATES=AMBIGUOUS_FAIL_CLOSED")
    print("JOURNAL_COMMITMENT_BINDING=PASS")
    print("SCAN_RANGE_CAP=FAIL_CLOSED")
    print("JOURNAL_MUTATION=NO")
    print("SWAP_STATE_MUTATION=NO")
    print("SENDTOADDRESS=NO")
    print("FUNDING=NO")
    print("TX_BROADCAST=NO")
    print("COIN_MOVEMENT=NO")


if __name__ == "__main__":
    selftest()
