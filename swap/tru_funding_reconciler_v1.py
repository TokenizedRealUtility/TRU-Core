#!/usr/bin/env python3
"""
TRU SWAP-FRESH-01B4B — TRU funding reconciliation foundation.

Read-only reconciliation logic for an already-prepared durable funding journal
attempt. This module never broadcasts, never calls htlccreate, never mutates
SWAP-A state, and never writes journal state.

The job of this layer is intentionally narrow:

  * derive the exact frozen TRU-SWAP-V1 bare 103-byte HTLC output script;
  * derive the exact canonical TRU funding metadata output;
  * scan the TRU mempool and blocks from the journal's starting height;
  * identify exact funding candidates by metadata + vout=1 amount + script;
  * classify 0 / 1 / multiple exact candidates;
  * never declare a zero-candidate result safe to retry.

Agent/journal mutation is deliberately deferred to the next binding patch.

REORG-SWAP-01C: CONFIRMED/RECORDED rows use one exact-tx gettransaction
snapshot instead of scanning for replacement candidates. An explicitly supplied
sidecar store persists public observations. No live Agent binding is added here.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

VERSION = "TRU-FUNDING-RECONCILER-V1"
REORG_VERSION = "TRU-REORG-SWAP-01C"
JOURNAL_DOMAIN = "TRU-SWAP-FUNDING-V1"
COMMITMENT_DOMAIN = "TRU-SWAP-TRU-CONTRACT-COMMITMENT-V1"
MAX_SCAN_BLOCKS_DEFAULT = 4096

REFUND_TIME_MIN = 500_000_000
REFUND_TIME_MAX = 0x7FFFFFFF

OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_CHECKLOCKTIMEVERIFY = 0xB1

HTLC_META_TEXT = b"TRU_CONTRACT:HTLC_Atomic_Swap_V1"


class ReconcileError(RuntimeError):
    pass


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


def canonical_tru_htlc_script(record: Mapping[str, Any]) -> bytes:
    secret = bytes.fromhex(_require_hex(record.get("secretHash160"), 20, "secretHash160"))
    claim = bytes.fromhex(_require_hex(record.get("truClaimPubkey"), 33, "truClaimPubkey"))
    refund = bytes.fromhex(_require_hex(record.get("truRefundPubkey"), 33, "truRefundPubkey"))

    if claim[0] not in (2, 3) or refund[0] not in (2, 3):
        raise ReconcileError("TRU role pubkeys must be compressed SEC1")
    if claim == refund:
        raise ReconcileError("TRU claim/refund role pubkeys must be distinct")

    refund_time = int(record.get("truRefundTime", 0))
    if not (REFUND_TIME_MIN <= refund_time <= REFUND_TIME_MAX):
        raise ReconcileError("truRefundTime outside frozen V1 timestamp domain")

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
        raise ReconcileError(f"canonical TRU HTLC length drift: {len(script)}")
    return script


def canonical_tru_metadata_script() -> bytes:
    if not HTLC_META_TEXT or len(HTLC_META_TEXT) > 75:
        raise ReconcileError("HTLC metadata invariant")
    return b"\x6a" + bytes([len(HTLC_META_TEXT)]) + HTLC_META_TEXT


def tru_contract_commitment(record: Mapping[str, Any]) -> str:
    script = canonical_tru_htlc_script(record)
    payload = (
        COMMITMENT_DOMAIN.encode("ascii")
        + b"|"
        + script
    )
    return hashlib.sha256(payload).hexdigest()


def expected_tru_funding(record: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "amountAtoms": _require_atoms(record.get("truAmountAtoms")),
        "contractVout": 1,
        "contractScriptHex": canonical_tru_htlc_script(record).hex(),
        "metadataVout": 0,
        "metadataScriptHex": canonical_tru_metadata_script().hex(),
        "commitment": tru_contract_commitment(record),
    }


def validate_tru_journal_attempt(
    record: Mapping[str, Any], attempt: Mapping[str, Any]
) -> Dict[str, Any]:
    swap_id = _require_hex(record.get("swapId"), 32, "swapId")
    if str(attempt.get("swapId", "")) != swap_id:
        raise ReconcileError("journal swapId mismatch")
    if attempt.get("chain") != "tru":
        raise ReconcileError("journal chain must be tru")

    expected = expected_tru_funding(record)
    if _require_atoms(attempt.get("amountAtoms")) != expected["amountAtoms"]:
        raise ReconcileError("journal TRU amount mismatch")
    if str(attempt.get("expectedContractCommitment", "")) != expected["commitment"]:
        raise ReconcileError("journal TRU contract commitment mismatch")

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


def parse_tru_tx_outputs(raw_hex: str) -> List[Dict[str, Any]]:
    """
    Parse only the exact fields needed for reconciliation.

    TRU serialization:
      version:u32le
      vin_count:varint
      each vin: 32-byte txid, vout:u32le, scriptSig:varbytes, sequence:u32le
      vout_count:varint
      each vout: amount:u64le, scriptPubKey:varbytes
      lockTime:u32le
      tokenMetadataFlag:u8 + optional metadata

    Exact u64 amounts are retained; no JSON floating-point conversion is used.
    """
    if not isinstance(raw_hex, str) or not re.fullmatch(r"[0-9a-fA-F]*", raw_hex):
        raise ReconcileError("raw transaction must be hex")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReconcileError("raw transaction hex") from exc

    pos = 0
    if len(raw) < 4:
        raise ReconcileError("truncated version")
    pos += 4

    nvin, pos = _read_varint(raw, pos)
    if nvin > 100_000:
        raise ReconcileError("unreasonable vin count")
    for _ in range(nvin):
        if pos + 36 > len(raw):
            raise ReconcileError("truncated input")
        pos += 32 + 4
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

    if pos + 5 > len(raw):
        raise ReconcileError("truncated lockTime/metadata flag")
    # lockTime + token metadata flag. The reconciler does not need metadata body.
    pos += 4
    metadata_flag = raw[pos]
    if metadata_flag not in (0, 1):
        raise ReconcileError("invalid token metadata flag")

    return outputs


def _outputs_match(outputs: Iterable[Mapping[str, Any]], expected: Mapping[str, Any]) -> bool:
    by_n = {int(o["n"]): o for o in outputs}
    meta = by_n.get(0)
    contract = by_n.get(1)
    if meta is None or contract is None:
        return False
    return (
        int(meta.get("amountAtoms", -1)) == 0
        and str(meta.get("scriptPubKeyHex", "")).lower() == expected["metadataScriptHex"]
        and int(contract.get("amountAtoms", -1)) == expected["amountAtoms"]
        and str(contract.get("scriptPubKeyHex", "")).lower() == expected["contractScriptHex"]
    )


def _mempool_outputs(txinfo: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rows = txinfo.get("vout")
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        try:
            n = int(row.get("index"))
            amount = int(row.get("amount"))
            script = str(row.get("scriptPubKey", "")).lower()
        except Exception:
            continue
        out.append({"n": n, "amountAtoms": amount, "scriptPubKeyHex": script})
    return out


def scan_tru_funding_candidates(
    record: Mapping[str, Any],
    attempt: Mapping[str, Any],
    rpc: Callable[[str, Mapping[str, Any]], Any],
    *,
    max_scan_blocks: int = MAX_SCAN_BLOCKS_DEFAULT,
) -> List[Dict[str, Any]]:
    expected = validate_tru_journal_attempt(record, attempt)
    starting_height = int(attempt["startingHeight"])
    if max_scan_blocks < 1:
        raise ReconcileError("max_scan_blocks")

    found: Dict[str, Dict[str, Any]] = {}

    mempool = rpc("getrawmempool", {"verbose": True})
    if not isinstance(mempool, Mapping):
        raise ReconcileError("TRU getrawmempool verbose response")
    for txid, info in mempool.items():
        if not re.fullmatch(r"[0-9a-f]{64}", str(txid)):
            continue
        if not isinstance(info, Mapping) or info.get("error"):
            continue
        if _outputs_match(_mempool_outputs(info), expected):
            found[str(txid)] = {
                "txid": str(txid),
                "vout": 1,
                "confirmations": 0,
                "blockHeight": None,
                "location": "mempool",
            }

    tip_raw = rpc("getblockcount", {})
    try:
        tip = int(tip_raw)
    except Exception as exc:
        raise ReconcileError("TRU getblockcount response") from exc
    if tip < -1:
        raise ReconcileError("TRU negative tip")

    if starting_height <= tip:
        span = tip - starting_height + 1
        if span > max_scan_blocks:
            raise ReconcileError(
                f"TRU reconciliation scan span {span} exceeds cap {max_scan_blocks}"
            )

        for height in range(starting_height, tip + 1):
            block = rpc("getblockbyheight", {"height": height})
            if not isinstance(block, Mapping) or int(block.get("height", -1)) != height:
                raise ReconcileError(f"TRU block response mismatch at height {height}")
            txids = block.get("tx")
            if not isinstance(txids, list):
                raise ReconcileError(f"TRU block tx list missing at height {height}")

            for txid in txids:
                txid = str(txid)
                if not re.fullmatch(r"[0-9a-f]{64}", txid):
                    raise ReconcileError("TRU block contains malformed txid")

                raw_hex = rpc("getrawtransaction", {"txid": txid, "verbose": False})
                if not isinstance(raw_hex, str):
                    raise ReconcileError("TRU getrawtransaction response")
                outputs = parse_tru_tx_outputs(raw_hex)
                if _outputs_match(outputs, expected):
                    found[txid] = {
                        "txid": txid,
                        "vout": 1,
                        "confirmations": tip - height + 1,
                        "blockHeight": height,
                        "location": "block",
                    }

    return sorted(found.values(), key=lambda x: x["txid"])


def classify_tru_candidates(candidates: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    rows = list(candidates)
    if not rows:
        return {
            "classification": "ZERO_CANDIDATES",
            "candidateCount": 0,
            "safeToRetry": False,
            "action": "HOLD_RECONCILE",
        }
    if len(rows) == 1:
        c = dict(rows[0])
        return {
            "classification": "ONE_CANDIDATE",
            "candidateCount": 1,
            "safeToRetry": False,
            "action": "ADOPT_TX_IDENTIFIED",
            "candidate": c,
        }
    return {
        "classification": "MULTIPLE_CANDIDATES",
        "candidateCount": len(rows),
        "safeToRetry": False,
        "action": "AMBIGUOUS_FAIL_CLOSED",
    }


def _terminal_tru_identity(record, attempt):
    expected = validate_tru_journal_attempt(record, attempt)
    if attempt.get("state") not in {"CONFIRMED", "RECORDED"}:
        raise ReconcileError("terminal TRU journal state required")
    sid = _require_hex(record.get("swapId"), 32, "swapId")
    operation = hashlib.sha256(f"{JOURNAL_DOMAIN}|{sid}|tru".encode()).hexdigest()
    if attempt.get("operationId") != operation:
        raise ReconcileError("terminal journal operationId mismatch")
    txid = _require_hex(attempt.get("txid"), 32, "terminal journal txid")
    if type(attempt.get("vout")) is not int or attempt["vout"] != 1:
        raise ReconcileError("terminal journal vout must be 1")
    for key, value in (("preparedTxid", txid), ("preparedContractVout", 1)):
        if attempt.get(key) is not None:
            if type(attempt[key]) is not type(value) or attempt[key] != value:
                raise ReconcileError("terminal prepared identity mismatch")
    if attempt.get("preparedPayloadSha256") is not None:
        _require_hex(attempt["preparedPayloadSha256"], 32, "prepared payload hash")
    # Support the canonical flat record and its public evidence projection.
    evidence = record.get("evidence", {})
    if not isinstance(evidence, Mapping):
        raise ReconcileError("record evidence must be an object")
    for source in (record, evidence):
        if source.get("truFundingTxid") not in (None, "", txid):
            raise ReconcileError("record funding txid mismatch")
        if source.get("truFundingVout") is not None:
            if type(source["truFundingVout"]) is not int or source["truFundingVout"] != 1:
                raise ReconcileError("record funding vout mismatch")
    return expected, txid


def _terminal_tru_status(response, txid, expected, attempt):
    from reorg_funding_guard_v1 import normalize_tx_status

    if not isinstance(response, dict) or response.get("error") is not None:
        raise ReconcileError("TRU transaction status RPC failed")
    if response.get("txid") != txid:
        raise ReconcileError("TRU transaction status identity mismatch")
    try:
        normalized = normalize_tx_status(response)
    except (ValueError, TypeError):
        raise ReconcileError("invalid TRU transaction status") from None
    state = normalized["txState"]
    # Tighten optional policy fields to the actual REORG-TX-01 RPC contract.
    signal = state in {"SIDECHAIN", "CONFLICTED"}
    if response.get("reorgSignal") is not signal:
        raise ReconcileError("inconsistent TRU reorg signal")
    if signal:
        if response.get("conflicted") is not (state == "CONFLICTED"):
            raise ReconcileError("inconsistent TRU conflict flag")
    elif response.get("conflicted") not in (None, False):
        raise ReconcileError("unexpected TRU conflict flag")
    conflict = response.get("conflictingTxid")
    if state == "CONFLICTED":
        _require_hex(conflict, 32, "conflicting txid")
        if conflict == txid:
            raise ReconcileError("transaction cannot conflict with itself")
    elif conflict is not None:
        raise ReconcileError("unexpected conflicting transaction")

    out = {"txid": txid, **normalized}
    active_fields = ("blockheight", "blockhash")
    side_fields = ("sideBlockHeight", "sideBlockHash")
    fields = active_fields if state == "CONFIRMED" else side_fields if signal else ()
    if fields:
        height = response.get(fields[0])
        if type(height) is not int or height < 1:
            raise ReconcileError("invalid TRU transaction block height")
        out[fields[0]] = height
        out[fields[1]] = _require_hex(response.get(fields[1]), 32, "transaction block hash")
    for key in active_fields + side_fields:
        if key not in fields and response.get(key) is not None:
            raise ReconcileError("contradictory TRU transaction block metadata")

    if state != "NOT_FOUND":
        raw = response.get("hex")
        if not isinstance(raw, str) or len(raw) > 2 * 1024 * 1024:
            raise ReconcileError("TRU transaction bytes missing or too large")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", raw):
            raise ReconcileError("invalid TRU transaction bytes")
        if not _outputs_match(parse_tru_tx_outputs(raw), expected):
            raise ReconcileError("TRU transaction funding outputs mismatch")
        digest = attempt.get("preparedPayloadSha256")
        if digest is not None and hashlib.sha256(bytes.fromhex(raw)).hexdigest() != digest:
            raise ReconcileError("TRU transaction differs from persisted prepared payload")
    # Never return or persist RPC hex, secrets, free-text errors, or unknown keys.
    return out


def observe_terminal_tru_attempt(
    record: Mapping[str, Any],
    attempt: Mapping[str, Any],
    rpc: Callable[[str, Mapping[str, Any]], Any],
    *,
    overlay_store: Any = None,
    observed_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Observe exact durable funding identity; optionally persist to a sidecar.

    rpc must return the unwrapped gettransaction result, as public_raw does.
    RPC/validation/storage failures raise ReconcileError; they never become
    NOT_FOUND or retry permission. The caller owns the sidecar lifecycle.
    Public journal rows need not expose prepared raw bytes; policy stays held.
    """
    from reorg_funding_guard_v1 import plan_funding_reorg_recovery

    expected, txid = _terminal_tru_identity(record, attempt)
    if observed_ms is not None and (type(observed_ms) is not int or observed_ms < 0):
        raise ReconcileError("observed_ms must be a nonnegative integer")
    try:
        response = rpc("gettransaction", {"txid": txid})
    except Exception:
        raise ReconcileError("TRU transaction status unavailable; hold and reconcile") from None
    status = _terminal_tru_status(response, txid, expected, attempt)
    # Pass only public identity fields to the policy/store. 01C cannot supply
    # the independent proofs needed for same-transaction rebroadcast eligibility.
    durable = {key: attempt[key] for key in (
        "state", "txid", "preparedTxid", "preparedPayloadSha256"
    ) if key in attempt}
    plan = plan_funding_reorg_recovery(durable, status)
    out = {
        "version": REORG_VERSION,
        "classification": "TERMINAL_REORG_OBSERVATION",
        "txid": txid,
        "vout": 1,
        "journalState": attempt["state"],
        "currentTxState": status["txState"],
        "confirmations": status["confirmations"],
        "historicalState": plan["historicalState"],
        "action": plan["action"],
        "txStatus": status,
        "safeToRetry": False,
        "sameTxRebroadcastEligible": False,
        "freshFundingAllowed": False,
        "automaticBroadcast": False,
        "broadcast": False,
        "journalMutation": False,
        "swapStateMutation": False,
        "overlayRecorded": False,
        "overlayDeduped": False,
        "historyScope": "CURRENT_SNAPSHOT_AND_JOURNAL",
    }
    if overlay_store is not None:
        try:
            saved = overlay_store.record_observation(
                swap_id=record["swapId"], chain="tru", durable_row=durable,
                tx_status=status, observed_ms=observed_ms,
            )
        except Exception:
            raise ReconcileError("TRU reorg sidecar observation failed; hold and reconcile") from None
        out["historyScope"] = "DURABLE_SIDECAR"
        out["overlayRecorded"] = saved["recorded"]
        out["overlayDeduped"] = saved["deduped"]
        overlay = saved.get("overlay")
        if overlay is not None:
            out["historicalState"] = overlay["historical_state"]
            out["action"] = overlay["action"]
    return out


def reconcile_tru_attempt(
    record: Mapping[str, Any],
    attempt: Mapping[str, Any],
    rpc: Callable[[str, Mapping[str, Any]], Any],
    *,
    max_scan_blocks: int = MAX_SCAN_BLOCKS_DEFAULT,
    overlay_store: Any = None,
    observed_ms: Optional[int] = None,
) -> Dict[str, Any]:
    if attempt.get("state") in {"CONFIRMED", "RECORDED"}:
        return observe_terminal_tru_attempt(
            record, attempt, rpc, overlay_store=overlay_store,
            observed_ms=observed_ms,
        )
    candidates = scan_tru_funding_candidates(
        record, attempt, rpc, max_scan_blocks=max_scan_blocks
    )
    out = classify_tru_candidates(candidates)
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


def _fixture_tx(outputs: List[tuple[int, bytes]]) -> str:
    raw = bytearray()
    raw += struct.pack("<I", 1)
    raw += _vi(1)
    raw += bytes.fromhex("11" * 32)
    raw += struct.pack("<I", 0)
    raw += _vi(0)
    raw += struct.pack("<I", 0xFFFFFFFF)
    raw += _vi(len(outputs))
    for amount, script in outputs:
        raw += struct.pack("<Q", amount)
        raw += _vi(len(script))
        raw += script
    raw += struct.pack("<I", 0)
    raw += b"\x00"
    return raw.hex()


def selftest() -> None:
    record = {
        "swapId": "12" * 32,
        "secretHash160": "34" * 20,
        "truClaimPubkey": "02" + "56" * 32,
        "truRefundPubkey": "03" + "78" * 32,
        "truRefundTime": 1_800_000_000,
        "truAmountAtoms": "9007199254740993",
    }
    expected = expected_tru_funding(record)
    attempt = {
        "operationId": hashlib.sha256(
            f"{JOURNAL_DOMAIN}|{record['swapId']}|tru".encode()
        ).hexdigest(),
        "swapId": record["swapId"],
        "chain": "tru",
        "amountAtoms": record["truAmountAtoms"],
        "expectedContractCommitment": expected["commitment"],
        "startingHeight": 100,
        "state": "BROADCASTING",
    }

    assert len(bytes.fromhex(expected["contractScriptHex"])) == 103
    assert expected["metadataScriptHex"].startswith("6a")
    assert expected["amountAtoms"] == 9007199254740993

    raw = _fixture_tx([
        (0, bytes.fromhex(expected["metadataScriptHex"])),
        (expected["amountAtoms"], bytes.fromhex(expected["contractScriptHex"])),
        (7, b"\x51"),
    ])
    parsed = parse_tru_tx_outputs(raw)
    assert parsed[1]["amountAtoms"] == 9007199254740993
    assert _outputs_match(parsed, expected)

    tx1 = "aa" * 32
    tx2 = "bb" * 32
    wrong = "cc" * 32

    fixture = {
        ("getrawmempool", True): {
            tx1: {
                "vout": [
                    {"index": 0, "amount": 0, "scriptPubKey": expected["metadataScriptHex"]},
                    {"index": 1, "amount": expected["amountAtoms"], "scriptPubKey": expected["contractScriptHex"]},
                ]
            },
            wrong: {
                "vout": [
                    {"index": 0, "amount": 0, "scriptPubKey": "6a00"},
                    {"index": 1, "amount": expected["amountAtoms"], "scriptPubKey": expected["contractScriptHex"]},
                ]
            },
        },
        ("getblockcount", None): 101,
        ("getblockbyheight", 100): {"height": 100, "tx": [wrong]},
        ("getblockbyheight", 101): {"height": 101, "tx": []},
        ("getrawtransaction", wrong): _fixture_tx([
            (0, b"\x6a\x00"),
            (expected["amountAtoms"], bytes.fromhex(expected["contractScriptHex"])),
        ]),
    }

    def rpc(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return fixture[(method, bool(params.get("verbose")))]
        if method == "getblockcount":
            return fixture[(method, None)]
        if method == "getblockbyheight":
            return fixture[(method, int(params["height"]))]
        if method == "getrawtransaction":
            return fixture[(method, str(params["txid"]))]
        raise AssertionError(method)

    rows = scan_tru_funding_candidates(record, attempt, rpc)
    assert [x["txid"] for x in rows] == [tx1]
    one = classify_tru_candidates(rows)
    assert one["classification"] == "ONE_CANDIDATE"
    assert one["action"] == "ADOPT_TX_IDENTIFIED"
    assert one["safeToRetry"] is False

    zero = classify_tru_candidates([])
    assert zero["classification"] == "ZERO_CANDIDATES"
    assert zero["safeToRetry"] is False
    assert zero["action"] == "HOLD_RECONCILE"

    multi = classify_tru_candidates([
        {"txid": tx1}, {"txid": tx2}
    ])
    assert multi["classification"] == "MULTIPLE_CANDIDATES"
    assert multi["action"] == "AMBIGUOUS_FAIL_CLOSED"

    # Confirmed exact candidate uses exact raw u64 amount and block-derived confirmations.
    fixture2 = {
        ("getrawmempool", True): {},
        ("getblockcount", None): 102,
        ("getblockbyheight", 100): {"height": 100, "tx": []},
        ("getblockbyheight", 101): {"height": 101, "tx": [tx2]},
        ("getblockbyheight", 102): {"height": 102, "tx": []},
        ("getrawtransaction", tx2): raw,
    }
    def rpc2(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return fixture2[(method, bool(params.get("verbose")))]
        if method == "getblockcount":
            return fixture2[(method, None)]
        if method == "getblockbyheight":
            return fixture2[(method, int(params["height"]))]
        if method == "getrawtransaction":
            return fixture2[(method, str(params["txid"]))]
        raise AssertionError(method)

    rows2 = scan_tru_funding_candidates(record, attempt, rpc2)
    assert len(rows2) == 1
    assert rows2[0]["txid"] == tx2
    assert rows2[0]["vout"] == 1
    assert rows2[0]["confirmations"] == 2
    assert rows2[0]["blockHeight"] == 101

    # Journal commitment mismatch must fail before any scan.
    bad_attempt = dict(attempt)
    bad_attempt["expectedContractCommitment"] = "00" * 32
    try:
        validate_tru_journal_attempt(record, bad_attempt)
    except ReconcileError:
        pass
    else:
        raise AssertionError("commitment mismatch accepted")

    # Scan range cap is fail-closed.
    def rpc_large(method: str, params: Mapping[str, Any]) -> Any:
        if method == "getrawmempool":
            return {}
        if method == "getblockcount":
            return 5000
        raise AssertionError(method)
    try:
        scan_tru_funding_candidates(record, attempt, rpc_large, max_scan_blocks=5)
    except ReconcileError:
        pass
    else:
        raise AssertionError("scan cap not enforced")

    print("SWAP_FRESH_01B4B_TRU_RECONCILER_SELFTEST=PASS")
    print("VERSION=TRU-FUNDING-RECONCILER-V1")
    print("FROZEN_TRU_HTLC_BYTES=103")
    print("TRU_FUNDING_METADATA_MATCH=PASS")
    print("EXACT_UINT64_RAW_TX_PARSE=PASS")
    print("MEMPOOL_EXACT_CANDIDATE_SCAN=PASS")
    print("BLOCK_EXACT_CANDIDATE_SCAN=PASS")
    print("BLOCK_CONFIRMATION_DERIVATION=PASS")
    print("WRONG_METADATA_OR_OUTPUT=IGNORED")
    print("ZERO_CANDIDATE_SAFE_TO_RETRY=NO")
    print("ONE_CANDIDATE_ACTION=ADOPT_TX_IDENTIFIED")
    print("MULTIPLE_CANDIDATES=AMBIGUOUS_FAIL_CLOSED")
    print("JOURNAL_COMMITMENT_BINDING=PASS")
    print("SCAN_RANGE_CAP=FAIL_CLOSED")
    print("JOURNAL_MUTATION=NO")
    print("SWAP_STATE_MUTATION=NO")
    print("HTLC_CREATION=NO")
    print("FUNDING=NO")
    print("TX_BROADCAST=NO")
    print("COIN_MOVEMENT=NO")


if __name__ == "__main__":
    selftest()
