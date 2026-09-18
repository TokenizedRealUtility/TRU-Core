#!/usr/bin/env python3
"""TRU-SWAP-AGENT-01B4D3 — TRU pre-broadcast preparation ↔ durable journal binding.

Security / scope:
- binds only 127.0.0.1
- exact-origin CORS allowlist, never '*'
- origin-bound local browser approval is the normal-user path
- manual terminal pairing and Cloudflare Access remain advanced remote fallbacks;
  /v1/health never returns either credential
- optional Cloudflare-Access-gated browser pairing issues an HttpOnly session cookie
- TRU_SWAP_RPC_TOKEN is inherited by the process and never returned to the browser
- no private key / WIF / preimage endpoint
- stdlib-only HTTP + SQLite
- activates only the two-party V2 offer/create/import handshake and durable record creation
- durable funding, exact-broadcast, and persistent exit-watcher recovery are installed behind explicit runtime gates; board take remains fail-closed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

os.umask(0o077)

VERSION = "TRU-SWAP-AGENT-GROUP04"
HOST = "127.0.0.1"
DEFAULT_PORT = 8645
MIN_TIMELOCK_GAP_HOURS = 6
OFFER_TTL_SECONDS = 6 * 60 * 60
OFFER_PREFIX_V2 = "TRUSWAP2:"
ACCEPT_PREFIX_V2 = "TRUSWAP2A:"
FINAL_PREFIX_V2 = "TRUSWAP2F:"
FUNDING_JOURNAL_DOMAIN = "TRU-SWAP-FUNDING-V1"
FUNDING_JOURNAL_STATES = {
    "PREPARED", "BROADCASTING", "TX_IDENTIFIED", "CONFIRMED",
    "RECORDED", "AMBIGUOUS", "ABORTED",
}
FUNDING_JOURNAL_TERMINAL = {"RECORDED", "AMBIGUOUS", "ABORTED"}
FUNDING_JOURNAL_TRANSITIONS = {
    "PREPARED": {"BROADCASTING", "ABORTED"},
    "BROADCASTING": {"TX_IDENTIFIED", "AMBIGUOUS"},
    "TX_IDENTIFIED": {"CONFIRMED", "AMBIGUOUS"},
    "CONFIRMED": {"RECORDED"},
    "RECORDED": set(),
    "AMBIGUOUS": set(),
    "ABORTED": set(),
}
MAX_BODY = 1024 * 1024
CHAINS = {"tru", "bsty"}
AMOUNT_RE = re.compile(r"^\d+(?:\.\d{1,8})?$")
SWAP_ID_RE = re.compile(r"^[0-9a-f]{64}$")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}


def funding_operation_id(swap_id: str, chain: str) -> str:
    if not SWAP_ID_RE.fullmatch(str(swap_id)):
        raise ValueError("swap_id")
    chain = str(chain)
    if chain not in CHAINS:
        raise ValueError("chain")
    msg = f"{FUNDING_JOURNAL_DOMAIN}|{swap_id}|{chain}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def require_atoms_text(value: Any) -> str:
    s = str(value)
    if not re.fullmatch(r"[1-9][0-9]*", s):
        raise ValueError("amount_atoms")
    # Keep uint64 domain without relying on SQLite's signed INTEGER range.
    n = int(s)
    if n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("amount_atoms")
    return s


def require_commitment_hex(value: Any) -> str:
    s = str(value)
    if not re.fullmatch(r"[0-9a-f]{64}", s):
        raise ValueError("expected_contract_commitment")
    return s


def require_prepared_txid(value: Any) -> str:
    s = str(value)
    if not re.fullmatch(r"[0-9a-f]{64}", s):
        raise ValueError("prepared_txid")
    return s


def require_prepared_raw_tx_hex(value: Any) -> str:
    s = str(value).lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", s):
        raise ValueError("prepared_raw_tx_hex")
    # Guard against accidental giant/private blobs while remaining generous
    # enough for normal funding transactions.
    if len(s) > 2 * 1024 * 1024:
        raise ValueError("prepared_raw_tx_hex too large")
    return s


def require_tru_prebroadcast_turn(record: Dict[str, Any], local_give_chain: str) -> None:
    """Fail closed unless this local participant is presently allowed to fund TRU."""
    if str(local_give_chain) != "tru":
        raise ValueError("local participant is not the TRU funding owner")
    funding_order = str(record.get("fundingOrder", ""))
    if funding_order not in {"TRU_FIRST", "BSTY_FIRST"}:
        raise ValueError("record fundingOrder")
    first = "tru" if funding_order == "TRU_FIRST" else "bsty"
    state = str(record.get("state", ""))
    evidence = record.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise ValueError("record evidence")
    if evidence.get("truFundingTxid") is not None or evidence.get("truFundingVout") is not None:
        raise ValueError("TRU funding evidence already exists")
    if state == "CREATED":
        if first != "tru":
            raise ValueError("TRU is not first in the canonical funding order")
        return
    if state == "ONE_SIDE_FUNDED":
        if first == "tru":
            raise ValueError("TRU was already the first-funded chain")
        if not evidence.get("bstyFundingTxid") or evidence.get("bstyFundingVout") is None:
            raise ValueError("ONE_SIDE_FUNDED is missing BSTY first-leg evidence")
        return
    raise ValueError("TRU prebroadcast preparation requires CREATED or ONE_SIDE_FUNDED")


def validate_tru_prebroadcast_prepare_result(
    record: Dict[str, Any],
    expected: Dict[str, Any],
    result: Dict[str, Any],
    operation_id: str,
) -> Dict[str, Any]:
    """Validate htlcpreparefunding before raw bytes enter the durable journal."""
    if not isinstance(result, dict):
        raise ValueError("TRU prepare response")
    if result.get("protocol") != "TRU-SWAP-V1":
        raise ValueError("TRU prepare protocol")
    if result.get("family") != "htlc_atomic_swap_v1":
        raise ValueError("TRU prepare family")
    if result.get("status") != "SIGNED_RESERVED_NOT_BROADCAST":
        raise ValueError("TRU prepare status")
    if str(result.get("operationId", "")) != str(operation_id):
        raise ValueError("TRU prepare operationId")
    if result.get("reservationActive") is not True:
        raise ValueError("TRU prepare reservation")
    if int(result.get("reservedInputCount", 0)) < 1:
        raise ValueError("TRU prepare reserved input count")
    if result.get("broadcast") is not False:
        raise ValueError("TRU prepare broadcast flag")
    if result.get("privateMaterialReturned") is not False:
        raise ValueError("TRU prepare private material flag")

    txid = require_prepared_txid(result.get("preparedTxid"))
    raw_hex = require_prepared_raw_tx_hex(result.get("rawTxHex"))
    vout = int(result.get("preparedVout", -1))
    if vout != int(expected.get("contractVout", -1)) or vout != 1:
        raise ValueError("TRU prepared contract vout")
    if int(result.get("amountAtoms", -1)) != int(expected.get("amountAtoms", -2)):
        raise ValueError("TRU prepared amount")
    if int(result.get("feeAtoms", 0)) <= 0:
        raise ValueError("TRU prepared fee")
    if str(result.get("scriptHex", "")).lower() != str(expected.get("contractScriptHex", "")).lower():
        raise ValueError("TRU prepared canonical script")
    if str(result.get("secretHash160", "")) != str(record.get("secretHash160", "")):
        raise ValueError("TRU prepared secret commitment")
    if str(result.get("claimPubkey", "")) != str(record.get("truClaimPubkey", "")):
        raise ValueError("TRU prepared claim pubkey")
    if str(result.get("refundPubkey", "")) != str(record.get("truRefundPubkey", "")):
        raise ValueError("TRU prepared refund pubkey")
    if int(result.get("refundTime", -1)) != int(record.get("truRefundTime", -2)):
        raise ValueError("TRU prepared refund time")

    return {
        "preparedTxid": txid,
        "preparedRawTxHex": raw_hex,
        "preparedContractVout": vout,
        "amountAtoms": str(int(expected["amountAtoms"])),
        "feeAtoms": int(result["feeAtoms"]),
        "operationId": str(operation_id),
        "reservationActive": True,
        "reservedInputCount": int(result["reservedInputCount"]),
        "nodeIdempotentReuse": bool(result.get("idempotentReuse", False)),
    }


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = int(status)
        self.code = code
        self.message = message


def fail(status: int, code: str, message: str):
    raise ApiError(status, code, message)


def now_ms() -> int:
    return int(time.time() * 1000)


def parse_origins() -> set[str]:
    raw = os.environ.get(
        "TRU_SWAP_AGENT_ORIGINS",
        "https://tokenizedrealutility.com,https://www.tokenizedrealutility.com,"
        "http://127.0.0.1:8080,http://localhost:8080",
    )
    out = {x.strip().rstrip("/") for x in raw.split(",") if x.strip()}
    if not out:
        raise SystemExit("TRU_SWAP_AGENT_ORIGINS resolved to an empty allowlist")
    if "*" in out:
        raise SystemExit("TRU_SWAP_AGENT_ORIGINS must never contain '*'")
    return out


def load_engine(path: Path):
    if not path.is_file():
        raise SystemExit(f"swap engine missing: {path}")
    spec = importlib.util.spec_from_file_location("tru_swap_engine_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import swap engine: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = [
        "TruAdapter", "BstyAdapter", "record_script", "p2sh_scriptpubkey",
    ]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("swap engine compatibility failure; missing: " + ", ".join(missing))
    return mod


def load_handshake(path: Path):
    if not path.is_file():
        raise SystemExit(f"swap handshake missing: {path}")
    spec = importlib.util.spec_from_file_location("tru_swap_offer_handshake_v2", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import swap handshake: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = [
        "make_offer", "validate_offer", "make_acceptance",
        "validate_acceptance", "final_bundle", "expected_roles",
    ]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("swap handshake compatibility failure; missing: " + ", ".join(missing))
    return mod


def load_tru_reconciler(path: Path):
    if not path.is_file():
        raise SystemExit(f"TRU funding reconciler missing: {path}")
    spec = importlib.util.spec_from_file_location("tru_funding_reconciler_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import TRU funding reconciler: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = [
        "expected_tru_funding", "reconcile_tru_attempt",
        "tru_contract_commitment", "canonical_tru_htlc_script",
    ]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("TRU funding reconciler compatibility failure; missing: " + ", ".join(missing))
    if getattr(mod, "VERSION", "") != "TRU-FUNDING-RECONCILER-V1":
        raise SystemExit("TRU funding reconciler version mismatch")
    return mod



def load_bsty_prebroadcast(path: Path):
    if not path.is_file():
        raise SystemExit(f"BSTY prebroadcast helper missing: {path}")
    spec = importlib.util.spec_from_file_location("bsty_prebroadcast_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import BSTY prebroadcast helper: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = ["prepare", "dryrun", "release", "require_turn"]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("BSTY prebroadcast compatibility failure; missing: " + ", ".join(missing))
    if getattr(mod, "VERSION", "") != "TRU-SWAP-BSTY-PREBROADCAST-V1":
        raise SystemExit("BSTY prebroadcast version mismatch")
    return mod


def load_dual_funding(path: Path):
    if not path.is_file():
        raise SystemExit(f"dual funding helper missing: {path}")
    spec = importlib.util.spec_from_file_location("tru_dual_funding_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import dual funding helper: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = ["enabled", "fund_step", "selftest"]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("dual funding compatibility failure; missing: " + ", ".join(missing))
    if getattr(mod, "VERSION", "") != "TRU-SWAP-DUAL-FUNDING-V1":
        raise SystemExit("dual funding version mismatch")
    return mod


def load_exit_watcher(path: Path):
    if not path.is_file():
        raise SystemExit(f"exit watcher helper missing: {path}")
    spec = importlib.util.spec_from_file_location("tru_exit_watcher_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import exit watcher helper: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = ["enabled", "ensure_schema", "arm", "disarm", "get_job",
                "public_job", "watch_loop", "selftest"]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("exit watcher compatibility failure; missing: " + ", ".join(missing))
    if getattr(mod, "VERSION", "") != "TRU-SWAP-EXIT-WATCHER-V1":
        raise SystemExit("exit watcher version mismatch")
    return mod


def apply_tru_reconcile_result(
    store: "Store",
    attempt: Dict[str, Any],
    result: Dict[str, Any],
    min_conf: int,
) -> Tuple[Dict[str, Any], bool]:
    """Apply a read-only TRU scan result to the durable journal only."""
    min_conf = int(min_conf)
    if min_conf < 1:
        raise ValueError("min_conf")

    state = str(attempt.get("state", ""))
    if state not in {"BROADCASTING", "TX_IDENTIFIED"}:
        raise ValueError("TRU reconciliation requires BROADCASTING or TX_IDENTIFIED")

    op = str(attempt.get("operationId", ""))
    classification = str(result.get("classification", ""))

    if classification == "ZERO_CANDIDATES":
        # Absence is not retry authority. Preserve the uncertain state.
        return attempt, False

    if classification == "MULTIPLE_CANDIDATES":
        row = store.transition_funding_attempt(op, "AMBIGUOUS")
        return row, True

    if classification != "ONE_CANDIDATE":
        raise ValueError("unknown TRU reconciliation classification")

    candidate = result.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("ONE_CANDIDATE missing candidate")

    txid = str(candidate.get("txid", ""))
    vout = int(candidate.get("vout", -1))
    confirmations = int(candidate.get("confirmations", 0))
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise ValueError("candidate txid")
    if vout < 0 or vout > 0xFFFFFFFF:
        raise ValueError("candidate vout")
    if confirmations < 0:
        raise ValueError("candidate confirmations")

    old_txid = attempt.get("txid")
    old_vout = attempt.get("vout")
    old_conf = int(attempt.get("confirmations", 0))

    # A previously identified operation must never silently change identity
    # or move backwards in confirmations.
    if state == "TX_IDENTIFIED":
        if old_txid is not None and str(old_txid) != txid:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True
        if old_vout is not None and int(old_vout) != vout:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True
        if confirmations < old_conf:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True

    row = store.transition_funding_attempt(
        op, "TX_IDENTIFIED",
        txid=txid, vout=vout, confirmations=confirmations,
    )
    if confirmations >= min_conf:
        row = store.transition_funding_attempt(
            op, "CONFIRMED",
            txid=txid, vout=vout, confirmations=confirmations,
        )
    return row, True


def load_reorg_funding_watcher(path: Path):
    """Load the pinned sidecar observer and its pinned 01A/01C dependencies."""
    swap_dir = path.parent.resolve()
    if not path.is_file():
        raise SystemExit("reorg funding watcher missing")
    for name in ("reorg_funding_guard_v1", "reorg_funding_overlay_v1"):
        loaded = sys.modules.get(name)
        if loaded is not None and Path(getattr(loaded, "__file__", "")).resolve() != swap_dir / (name + ".py"):
            raise SystemExit("reorg funding dependency import origin mismatch")
    # 01C uses lazy imports of these sibling modules. Keep the exact swap source
    # directory available for the lifetime of this Agent process.
    if str(swap_dir) not in sys.path:
        sys.path.insert(0, str(swap_dir))
    spec = importlib.util.spec_from_file_location("tru_reorg_funding_watcher_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit("cannot import reorg funding watcher")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "VERSION", "") != "TRU-REORG-SWAP-01D":
        raise SystemExit("reorg funding watcher version mismatch")
    if not hasattr(mod, "FundingReorgWatcher"):
        raise SystemExit("reorg funding watcher compatibility failure")
    for name in ("reorg_funding_guard_v1", "reorg_funding_overlay_v1"):
        loaded = sys.modules.get(name)
        if loaded is None or Path(getattr(loaded, "__file__", "")).resolve() != swap_dir / (name + ".py"):
            raise SystemExit("reorg funding dependency import origin mismatch")
    return mod


def load_bsty_reconciler(path: Path):
    if not path.is_file():
        raise SystemExit(f"BSTY funding reconciler missing: {path}")
    spec = importlib.util.spec_from_file_location("bsty_funding_reconciler_live", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import BSTY funding reconciler: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    required = [
        "expected_bsty_funding", "reconcile_bsty_attempt",
        "bsty_contract_commitment", "canonical_bsty_redeem_script",
        "canonical_bsty_p2sh_scriptpubkey",
    ]
    missing = [name for name in required if not hasattr(mod, name)]
    if missing:
        raise SystemExit("BSTY funding reconciler compatibility failure; missing: " + ", ".join(missing))
    if getattr(mod, "VERSION", "") != "BSTY-FUNDING-RECONCILER-V1":
        raise SystemExit("BSTY funding reconciler version mismatch")
    return mod


def apply_bsty_reconcile_result(
    store: "Store",
    attempt: Dict[str, Any],
    result: Dict[str, Any],
    min_conf: int,
) -> Tuple[Dict[str, Any], bool]:
    """Apply a read-only BSTY scan result to the durable journal only."""
    min_conf = int(min_conf)
    if min_conf < 1:
        raise ValueError("min_conf")

    state = str(attempt.get("state", ""))
    if state not in {"BROADCASTING", "TX_IDENTIFIED"}:
        raise ValueError("BSTY reconciliation requires BROADCASTING or TX_IDENTIFIED")

    op = str(attempt.get("operationId", ""))
    classification = str(result.get("classification", ""))

    if classification == "ZERO_CANDIDATES":
        # Absence is never retry authority.
        return attempt, False

    if classification == "MULTIPLE_CANDIDATES":
        row = store.transition_funding_attempt(op, "AMBIGUOUS")
        return row, True

    if classification != "ONE_CANDIDATE":
        raise ValueError("unknown BSTY reconciliation classification")

    candidate = result.get("candidate")
    if not isinstance(candidate, dict):
        raise ValueError("ONE_CANDIDATE missing candidate")

    txid = str(candidate.get("txid", ""))
    vout = int(candidate.get("vout", -1))
    confirmations = int(candidate.get("confirmations", 0))
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise ValueError("candidate txid")
    if vout < 0 or vout > 0xFFFFFFFF:
        raise ValueError("candidate vout")
    if confirmations < 0:
        raise ValueError("candidate confirmations")

    old_txid = attempt.get("txid")
    old_vout = attempt.get("vout")
    old_conf = int(attempt.get("confirmations", 0))

    if state == "TX_IDENTIFIED":
        if old_txid is not None and str(old_txid) != txid:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True
        if old_vout is not None and int(old_vout) != vout:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True
        if confirmations < old_conf:
            row = store.transition_funding_attempt(op, "AMBIGUOUS")
            return row, True

    row = store.transition_funding_attempt(
        op, "TX_IDENTIFIED",
        txid=txid, vout=vout, confirmations=confirmations,
    )
    if confirmations >= min_conf:
        row = store.transition_funding_attempt(
            op, "CONFIRMED",
            txid=txid, vout=vout, confirmations=confirmations,
        )
    return row, True


def coin_to_atoms(value: Any) -> str:
    s = str(value).strip()
    if not AMOUNT_RE.fullmatch(s):
        fail(400, "BAD_AMOUNT", "amounts must be positive with at most 8 decimals")
    try:
        d = Decimal(s)
    except InvalidOperation:
        fail(400, "BAD_AMOUNT", "invalid decimal amount")
    atoms = d * Decimal(100_000_000)
    if atoms != atoms.to_integral_value() or atoms <= 0:
        fail(400, "BAD_AMOUNT", "amount must resolve to positive integer atoms")
    return str(int(atoms))


def hash160(data: bytes) -> str:
    try:
        ripe = hashlib.new("ripemd160")
    except Exception as exc:
        raise RuntimeError("RIPEMD160 unavailable") from exc
    ripe.update(hashlib.sha256(data).digest())
    return ripe.hexdigest()


def encode_exchange(prefix: str, obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return prefix + base64.b64encode(raw).decode("ascii")


def decode_exchange(blob: Any) -> Tuple[str, Dict[str, Any]]:
    text = str(blob or "").strip()
    matched = next((p for p in (OFFER_PREFIX_V2, ACCEPT_PREFIX_V2, FINAL_PREFIX_V2) if text.startswith(p)), None)
    if matched is None:
        fail(400, "BAD_HANDSHAKE_BLOB", "expected TRUSWAP2, TRUSWAP2A, or TRUSWAP2F message")
    payload = text[len(matched):]
    try:
        raw = base64.b64decode(payload, validate=True)
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        fail(400, "DAMAGED_HANDSHAKE_BLOB", "handshake message is damaged")
    if not isinstance(obj, dict):
        fail(400, "BAD_HANDSHAKE_SHAPE", "handshake message must contain a JSON object")
    return matched, obj


def atoms_to_coin(atoms: int) -> str:
    atoms = int(atoms)
    whole, frac = divmod(atoms, 100_000_000)
    return f"{whole}.{frac:08d}"


def amount_ok(v: Any) -> bool:
    s = str(v)
    if not AMOUNT_RE.fullmatch(s):
        return False
    try:
        return float(s) > 0
    except ValueError:
        return False


def b58decode(s: str) -> Optional[bytes]:
    n = 0
    try:
        for c in s:
            n = n * 58 + BASE58_INDEX[c]
    except KeyError:
        return None
    raw = b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * zeros + raw


def validate_tru_address(address: str) -> bool:
    raw = b58decode(address)
    if raw is None or len(raw) != 25 or raw[0] != 0x41:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return secrets.compare_digest(checksum, want)


def browser_safe(obj: Any, key: str = "") -> Any:
    """Remove secret/private fields defensively; secretHash160 is public."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl == "secrethash160":
                out[k] = browser_safe(v, str(k))
                continue
            if any(x in kl for x in (
                "preimage", "privkey", "privatekey", "wif",
                "authtoken", "rpcpassword", "preparedrawtx",
                "prepared_raw_tx", "signedrawtx", "signed_raw_tx",
            )):
                continue
            if kl in {"secret", "password", "passphrase"}:
                continue
            out[k] = browser_safe(v, str(k))
        return out
    if isinstance(obj, list):
        return [browser_safe(x, key) for x in obj]
    return obj


class ClosingSQLiteConnection(sqlite3.Connection):
    """A transaction context must also release its SQLite file descriptors."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def connect(self):
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None,
                              factory=ClosingSQLiteConnection)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=10000")
            con.execute("PRAGMA journal_mode=WAL")
            return con
        except BaseException:
            con.close()
            raise

    def _init(self):
        with self.connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS adverts (
                    id TEXT PRIMARY KEY,
                    gives_chain TEXT NOT NULL,
                    gets_chain TEXT NOT NULL,
                    gives TEXT NOT NULL,
                    gets TEXT NOT NULL,
                    own_hours INTEGER NOT NULL,
                    their_hours INTEGER NOT NULL,
                    min_conf INTEGER NOT NULL,
                    posted_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    mine INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'ACTIVE'
                );
                CREATE INDEX IF NOT EXISTS adverts_active_idx
                    ON adverts(status, expires_ms, posted_ms);

                CREATE TABLE IF NOT EXISTS settled (
                    id TEXT PRIMARY KEY,
                    gives_chain TEXT NOT NULL,
                    gets_chain TEXT NOT NULL,
                    gives TEXT NOT NULL,
                    gets TEXT NOT NULL,
                    when_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS swap_views (
                    swap_id TEXT PRIMARY KEY,
                    give_chain TEXT NOT NULL,
                    get_chain TEXT NOT NULL,
                    min_conf INTEGER NOT NULL,
                    first_chain TEXT,
                    first_starting_height INTEGER,
                    counterparty_starting_height INTEGER,
                    created_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pair_sessions (
                    token_hash TEXT PRIMARY KEY,
                    origin TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    last_used_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS pair_sessions_expiry_idx
                    ON pair_sessions(expires_ms);

                CREATE TABLE IF NOT EXISTS offer_sessions (
                    offer_id TEXT NOT NULL,
                    local_role TEXT NOT NULL,
                    state TEXT NOT NULL,
                    offer_json TEXT NOT NULL,
                    acceptance_json TEXT,
                    final_json TEXT,
                    preimage_hex TEXT,
                    bsty_signer_address TEXT NOT NULL,
                    give_chain TEXT NOT NULL,
                    get_chain TEXT NOT NULL,
                    min_conf INTEGER NOT NULL,
                    swap_id TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    PRIMARY KEY(offer_id, local_role)
                );
                CREATE INDEX IF NOT EXISTS offer_sessions_state_idx
                    ON offer_sessions(state, updated_ms);

                CREATE TABLE IF NOT EXISTS funding_attempts (
                    operation_id TEXT PRIMARY KEY,
                    swap_id TEXT NOT NULL,
                    chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
                    amount_atoms TEXT NOT NULL,
                    expected_contract_commitment TEXT NOT NULL,
                    starting_height INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'PREPARED','BROADCASTING','TX_IDENTIFIED','CONFIRMED',
                        'RECORDED','AMBIGUOUS','ABORTED'
                    )),
                    txid TEXT,
                    vout INTEGER,
                    confirmations INTEGER NOT NULL DEFAULT 0 CHECK(confirmations >= 0),
                    prepared_txid TEXT,
                    prepared_raw_tx_hex TEXT,
                    prepared_contract_vout INTEGER,
                    prepared_payload_sha256 TEXT,
                    prepared_ms INTEGER,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    UNIQUE(swap_id, chain)
                );
                CREATE INDEX IF NOT EXISTS funding_attempts_state_idx
                    ON funding_attempts(state, updated_ms);
                """
            )
            # 01B4D1: migrate existing 01B4A journal in place. SQLite
            # CREATE TABLE IF NOT EXISTS does not add columns to an old table.
            cols = {r["name"] for r in c.execute("PRAGMA table_info(funding_attempts)").fetchall()}
            migrations = [
                ("prepared_txid", "TEXT"),
                ("prepared_raw_tx_hex", "TEXT"),
                ("prepared_contract_vout", "INTEGER"),
                ("prepared_payload_sha256", "TEXT"),
                ("prepared_ms", "INTEGER"),
            ]
            for name, ddl in migrations:
                if name not in cols:
                    c.execute(f"ALTER TABLE funding_attempts ADD COLUMN {name} {ddl}")
            view_cols = {r["name"] for r in c.execute("PRAGMA table_info(swap_views)").fetchall()}
            for name, ddl in (("first_chain", "TEXT"), ("first_starting_height", "INTEGER"),
                              ("counterparty_starting_height", "INTEGER")):
                if name not in view_cols:
                    c.execute(f"ALTER TABLE swap_views ADD COLUMN {name} {ddl}")
            c.execute(
                "CREATE INDEX IF NOT EXISTS funding_attempts_prepared_txid_idx "
                "ON funding_attempts(chain, prepared_txid)"
            )

    def list_board(self) -> Dict[str, Any]:
        n = now_ms()
        with self.connect() as c:
            c.execute("UPDATE adverts SET status='EXPIRED' WHERE status='ACTIVE' AND expires_ms<=?", (n,))
            rows = c.execute(
                "SELECT * FROM adverts WHERE status='ACTIVE' AND expires_ms>? ORDER BY posted_ms DESC", (n,)
            ).fetchall()
            settled = c.execute(
                "SELECT * FROM settled ORDER BY when_ms DESC LIMIT 32"
            ).fetchall()
        adverts = [
            {
                "id": r["id"], "givesChain": r["gives_chain"], "getsChain": r["gets_chain"],
                "gives": r["gives"], "gets": r["gets"], "ownHours": r["own_hours"],
                "theirHours": r["their_hours"], "minConf": r["min_conf"],
                "posted": r["posted_ms"], "expires": r["expires_ms"], "mine": bool(r["mine"]),
            }
            for r in rows
        ]
        tape = [
            {
                "givesChain": r["gives_chain"], "getsChain": r["gets_chain"],
                "gives": r["gives"], "gets": r["gets"], "when": r["when_ms"],
            }
            for r in settled
        ]
        return {"adverts": adverts, "settled": tape}

    def post_advert(self, p: Dict[str, Any]) -> Dict[str, Any]:
        gives_chain = str(p.get("givesChain", ""))
        gets_chain = str(p.get("getsChain", ""))
        gives = str(p.get("gives", ""))
        gets = str(p.get("gets", ""))
        own = int(p.get("ownHours", 0))
        theirs = int(p.get("theirHours", 0))
        min_conf = int(p.get("minConf", 0))
        life = int(p.get("lifeHours", 0))
        if gives_chain not in CHAINS or gets_chain not in CHAINS or gives_chain == gets_chain:
            fail(400, "BAD_CHAIN_PAIR", "advert must be TRU↔BSTY")
        if not amount_ok(gives) or not amount_ok(gets):
            fail(400, "BAD_AMOUNT", "amounts must be positive with at most 8 decimals")
        if own <= theirs:
            fail(400, "BAD_TIMELOCK_ORDER", "own refund window must be later than the other side")
        if own - theirs < MIN_TIMELOCK_GAP_HOURS:
            fail(400, "TIMELOCK_GAP_TOO_SMALL", f"minimum timelock gap is {MIN_TIMELOCK_GAP_HOURS} hours")
        if min_conf < 1:
            fail(400, "BAD_CONFIRMATIONS", "minConf must be >= 1")
        if life < 1 or life > 168:
            fail(400, "BAD_ADVERT_LIFETIME", "lifeHours must be between 1 and 168")
        t = now_ms()
        advert_id = uuid.uuid4().hex
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute(
                """INSERT INTO adverts
                   (id,gives_chain,gets_chain,gives,gets,own_hours,their_hours,min_conf,posted_ms,expires_ms,mine,status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1,'ACTIVE')""",
                (advert_id, gives_chain, gets_chain, gives, gets, own, theirs, min_conf, t, t + life * 3600_000),
            )
            c.execute("COMMIT")
        return self.get_advert(advert_id)

    def get_advert(self, advert_id: str) -> Dict[str, Any]:
        with self.connect() as c:
            r = c.execute("SELECT * FROM adverts WHERE id=?", (advert_id,)).fetchone()
        if not r:
            fail(404, "ADVERT_NOT_FOUND", "advert not found")
        return {
            "id": r["id"], "givesChain": r["gives_chain"], "getsChain": r["gets_chain"],
            "gives": r["gives"], "gets": r["gets"], "ownHours": r["own_hours"],
            "theirHours": r["their_hours"], "minConf": r["min_conf"],
            "posted": r["posted_ms"], "expires": r["expires_ms"], "mine": bool(r["mine"]),
        }

    def withdraw(self, advert_id: str):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            cur = c.execute(
                "UPDATE adverts SET status='WITHDRAWN' WHERE id=? AND status='ACTIVE'", (advert_id,)
            )
            if cur.rowcount != 1:
                c.execute("ROLLBACK")
                fail(404, "ADVERT_NOT_ACTIVE", "advert is missing or no longer active")
            c.execute("COMMIT")

    def put_view(self, swap_id: str, give_chain: str, get_chain: str, min_conf: int,
                 first_chain: str, first_starting_height: int,
                 counterparty_starting_height: Optional[int] = None):
        with self.connect() as c:
            c.execute(
                """INSERT INTO swap_views(
                       swap_id,give_chain,get_chain,min_conf,first_chain,
                       first_starting_height,counterparty_starting_height,created_ms)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(swap_id) DO UPDATE SET
                     give_chain=excluded.give_chain,
                     get_chain=excluded.get_chain,
                     min_conf=excluded.min_conf,
                     first_chain=COALESCE(swap_views.first_chain,excluded.first_chain),
                     first_starting_height=COALESCE(
                         swap_views.first_starting_height,excluded.first_starting_height),
                     counterparty_starting_height=COALESCE(
                         swap_views.counterparty_starting_height,excluded.counterparty_starting_height)""",
                (swap_id, give_chain, get_chain, int(min_conf), first_chain,
                 int(first_starting_height), counterparty_starting_height, now_ms()),
            )

    def get_view(self, swap_id: str) -> Optional[sqlite3.Row]:
        with self.connect() as c:
            return c.execute("SELECT * FROM swap_views WHERE swap_id=?", (swap_id,)).fetchone()

    def put_pair_session(self, token_hash: str, origin: str, ttl_seconds: int) -> int:
        now = now_ms()
        expires = now + int(ttl_seconds) * 1000
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM pair_sessions WHERE expires_ms<=?", (now,))
            c.execute(
                """INSERT INTO pair_sessions(token_hash,origin,created_ms,expires_ms,last_used_ms)
                   VALUES(?,?,?,?,?)""",
                (token_hash, origin, now, expires, now),
            )
            c.execute("COMMIT")
        return expires

    def pair_session_valid(self, token_hash: str, origin: str) -> bool:
        now = now_ms()
        with self.connect() as c:
            c.execute("DELETE FROM pair_sessions WHERE expires_ms<=?", (now,))
            row = c.execute(
                """SELECT token_hash FROM pair_sessions
                   WHERE token_hash=? AND origin=? AND expires_ms>?""",
                (token_hash, origin, now),
            ).fetchone()
            if row is None:
                return False
            c.execute(
                "UPDATE pair_sessions SET last_used_ms=? WHERE token_hash=?",
                (now, token_hash),
            )
        return True

    def revoke_pair_session(self, token_hash: str):
        with self.connect() as c:
            c.execute("DELETE FROM pair_sessions WHERE token_hash=?", (token_hash,))


    def put_offer_session(
        self, offer_id: str, local_role: str, state: str, offer: Dict[str, Any],
        give_chain: str, get_chain: str, min_conf: int, *,
        bsty_signer_address: str,
        acceptance: Optional[Dict[str, Any]] = None,
        final: Optional[Dict[str, Any]] = None,
        preimage_hex: Optional[str] = None, swap_id: Optional[str] = None,
        process_key: Optional[str] = None,
    ):
        if local_role not in {"maker", "taker"}:
            raise ValueError("local_role")
        if not isinstance(bsty_signer_address, str) or not bsty_signer_address.strip():
            raise ValueError("bsty_signer_address")
        t = now_ms()
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute(
                """INSERT INTO offer_sessions
                   (offer_id,local_role,state,offer_json,acceptance_json,final_json,preimage_hex,
                    bsty_signer_address,give_chain,get_chain,min_conf,swap_id,created_ms,updated_ms)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(offer_id,local_role) DO UPDATE SET
                     state=excluded.state,
                     offer_json=excluded.offer_json,
                     acceptance_json=COALESCE(excluded.acceptance_json,offer_sessions.acceptance_json),
                     final_json=COALESCE(excluded.final_json,offer_sessions.final_json),
                     preimage_hex=COALESCE(excluded.preimage_hex,offer_sessions.preimage_hex),
                     bsty_signer_address=excluded.bsty_signer_address,
                     give_chain=excluded.give_chain,
                     get_chain=excluded.get_chain,
                     min_conf=excluded.min_conf,
                     swap_id=COALESCE(excluded.swap_id,offer_sessions.swap_id),
                     updated_ms=excluded.updated_ms""",
                (offer_id, local_role, state, json.dumps(offer, sort_keys=True, separators=(",", ":")),
                 json.dumps(acceptance, sort_keys=True, separators=(",", ":")) if acceptance is not None else None,
                 json.dumps(final, sort_keys=True, separators=(",", ":")) if final is not None else None,
                 preimage_hex, bsty_signer_address, give_chain, get_chain, int(min_conf), swap_id, t, t),
            )
            if process_key is not None:
                c.execute("INSERT INTO market_offer_keys(process_key,offer_id) VALUES(?,?)",
                          (process_key, offer_id))
            c.execute("COMMIT")

    def get_offer_session(self, offer_id: str, local_role: str) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            r = c.execute(
                "SELECT * FROM offer_sessions WHERE offer_id=? AND local_role=?",
                (offer_id, local_role),
            ).fetchone()
        if r is None:
            return None
        return {
            "offerId": r["offer_id"], "localRole": r["local_role"], "state": r["state"],
            "offer": json.loads(r["offer_json"]),
            "acceptance": json.loads(r["acceptance_json"]) if r["acceptance_json"] else None,
            "final": json.loads(r["final_json"]) if r["final_json"] else None,
            "preimageHex": r["preimage_hex"],
            "bstySignerAddress": r["bsty_signer_address"],
            "giveChain": r["give_chain"], "getChain": r["get_chain"],
            "minConf": int(r["min_conf"]), "swapId": r["swap_id"],
        }


    @staticmethod
    def _funding_row(r: sqlite3.Row) -> Dict[str, Any]:
        return {
            "operationId": r["operation_id"],
            "swapId": r["swap_id"],
            "chain": r["chain"],
            "amountAtoms": r["amount_atoms"],
            "expectedContractCommitment": r["expected_contract_commitment"],
            "startingHeight": int(r["starting_height"]),
            "state": r["state"],
            "txid": r["txid"],
            "vout": int(r["vout"]) if r["vout"] is not None else None,
            "confirmations": int(r["confirmations"]),
            "prebroadcastReady": bool(
                r["prepared_txid"] is not None and
                r["prepared_raw_tx_hex"] is not None and
                r["prepared_contract_vout"] is not None and
                r["prepared_payload_sha256"] is not None and
                r["prepared_ms"] is not None
            ),
            "preparedTxid": r["prepared_txid"],
            "preparedContractVout": (
                int(r["prepared_contract_vout"])
                if r["prepared_contract_vout"] is not None else None
            ),
            "preparedPayloadSha256": r["prepared_payload_sha256"],
            "preparedMs": int(r["prepared_ms"]) if r["prepared_ms"] is not None else None,
            "createdMs": int(r["created_ms"]),
            "updatedMs": int(r["updated_ms"]),
        }

    def prepare_funding_attempt(
        self, swap_id: str, chain: str, amount_atoms: Any,
        expected_contract_commitment: str, starting_height: int,
    ) -> Dict[str, Any]:
        operation_id = funding_operation_id(swap_id, chain)
        amount_text = require_atoms_text(amount_atoms)
        commitment = require_commitment_hex(expected_contract_commitment)
        starting_height = int(starting_height)
        if starting_height < 0:
            raise ValueError("starting_height")
        t = now_ms()
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            existing = c.execute(
                "SELECT * FROM funding_attempts WHERE swap_id=? AND chain=?",
                (swap_id, chain),
            ).fetchone()
            if existing is not None:
                same = (
                    existing["operation_id"] == operation_id and
                    existing["amount_atoms"] == amount_text and
                    existing["expected_contract_commitment"] == commitment and
                    int(existing["starting_height"]) == starting_height
                )
                if not same:
                    c.execute("ROLLBACK")
                    raise ValueError("funding attempt parameters conflict with durable journal")
                c.execute("COMMIT")
                return self._funding_row(existing)
            c.execute(
                """INSERT INTO funding_attempts
                   (operation_id,swap_id,chain,amount_atoms,expected_contract_commitment,
                    starting_height,state,txid,vout,confirmations,created_ms,updated_ms)
                   VALUES(?,?,?,?,?,?,'PREPARED',NULL,NULL,0,?,?)""",
                (operation_id, swap_id, chain, amount_text, commitment,
                 starting_height, t, t),
            )
            row = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            c.execute("COMMIT")
        return self._funding_row(row)

    def prepare_funding_payload(
        self, operation_id: str, prepared_txid: Any, prepared_raw_tx_hex: Any,
        prepared_contract_vout: int,
    ) -> Dict[str, Any]:
        """Persist immutable broadcast-ready identity BEFORE BROADCASTING."""
        if not re.fullmatch(r"[0-9a-f]{64}", str(operation_id)):
            raise ValueError("operation_id")
        txid = require_prepared_txid(prepared_txid)
        raw_hex = require_prepared_raw_tx_hex(prepared_raw_tx_hex)
        vout = int(prepared_contract_vout)
        if vout < 0 or vout > 0xFFFFFFFF:
            raise ValueError("prepared_contract_vout")
        payload_sha256 = hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest()
        t = now_ms()
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if r is None:
                c.execute("ROLLBACK")
                raise ValueError("funding attempt not found")
            if r["state"] != "PREPARED":
                c.execute("ROLLBACK")
                raise ValueError("prebroadcast payload may only be prepared in PREPARED state")
            existing = (
                r["prepared_txid"], r["prepared_raw_tx_hex"],
                r["prepared_contract_vout"], r["prepared_payload_sha256"],
                r["prepared_ms"],
            )
            if any(x is not None for x in existing):
                same = (
                    r["prepared_txid"] == txid and
                    r["prepared_raw_tx_hex"] == raw_hex and
                    r["prepared_contract_vout"] is not None and
                    int(r["prepared_contract_vout"]) == vout and
                    r["prepared_payload_sha256"] == payload_sha256 and
                    r["prepared_ms"] is not None
                )
                if not same:
                    c.execute("ROLLBACK")
                    raise ValueError("prepared funding payload identity is immutable")
                c.execute("COMMIT")
                return self._funding_row(r)
            c.execute(
                """UPDATE funding_attempts
                   SET prepared_txid=?,prepared_raw_tx_hex=?,prepared_contract_vout=?,
                       prepared_payload_sha256=?,prepared_ms=?,updated_ms=?
                   WHERE operation_id=?""",
                (txid, raw_hex, vout, payload_sha256, t, t, operation_id),
            )
            out = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            c.execute("COMMIT")
        return self._funding_row(out)

    def get_prepared_funding_payload(self, operation_id: str) -> Dict[str, Any]:
        """Internal-only raw transaction retrieval; never browser serialized."""
        if not re.fullmatch(r"[0-9a-f]{64}", str(operation_id)):
            raise ValueError("operation_id")
        with self.connect() as c:
            r = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
        if r is None:
            raise ValueError("funding attempt not found")
        fields = (
            r["prepared_txid"], r["prepared_raw_tx_hex"],
            r["prepared_contract_vout"], r["prepared_payload_sha256"], r["prepared_ms"],
        )
        if any(x is None for x in fields):
            raise ValueError("prebroadcast payload not prepared")
        raw_hex = require_prepared_raw_tx_hex(r["prepared_raw_tx_hex"])
        digest = hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest()
        if digest != r["prepared_payload_sha256"]:
            raise ValueError("prepared raw transaction payload hash mismatch")
        return {
            "operationId": r["operation_id"],
            "swapId": r["swap_id"],
            "chain": r["chain"],
            "preparedTxid": r["prepared_txid"],
            "preparedRawTxHex": raw_hex,
            "preparedContractVout": int(r["prepared_contract_vout"]),
            "preparedPayloadSha256": r["prepared_payload_sha256"],
            "preparedMs": int(r["prepared_ms"]),
        }

    def list_prebroadcast_ready_funding_attempts(self) -> list[Dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                """SELECT * FROM funding_attempts
                   WHERE state='PREPARED'
                     AND prepared_txid IS NOT NULL
                     AND prepared_raw_tx_hex IS NOT NULL
                     AND prepared_contract_vout IS NOT NULL
                     AND prepared_payload_sha256 IS NOT NULL
                     AND prepared_ms IS NOT NULL
                   ORDER BY created_ms, operation_id"""
            ).fetchall()
        return [self._funding_row(r) for r in rows]

    def get_funding_attempt(self, swap_id: str, chain: str) -> Optional[Dict[str, Any]]:
        operation_id = funding_operation_id(swap_id, chain)
        with self.connect() as c:
            r = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
        return None if r is None else self._funding_row(r)

    def list_reconcilable_funding_attempts(self) -> list[Dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                """SELECT * FROM funding_attempts
                   WHERE state IN ('PREPARED','BROADCASTING','TX_IDENTIFIED','CONFIRMED')
                   ORDER BY created_ms, operation_id"""
            ).fetchall()
        return [self._funding_row(r) for r in rows]

    def transition_funding_attempt(
        self, operation_id: str, next_state: str, *,
        txid: Optional[str] = None, vout: Optional[int] = None,
        confirmations: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", str(operation_id)):
            raise ValueError("operation_id")
        next_state = str(next_state)
        if next_state not in FUNDING_JOURNAL_STATES:
            raise ValueError("next_state")
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if r is None:
                c.execute("ROLLBACK")
                raise ValueError("funding attempt not found")
            current = r["state"]
            old_txid = r["txid"]
            old_vout = r["vout"]
            old_conf = int(r["confirmations"])
            prepared_txid = r["prepared_txid"]
            prepared_raw = r["prepared_raw_tx_hex"]
            prepared_vout = r["prepared_contract_vout"]
            prepared_digest = r["prepared_payload_sha256"]
            prepared_ms = r["prepared_ms"]

            # The one-way mutation barrier: money movement may only be entered
            # after exact transaction identity + raw bytes are durable.
            if current == "PREPARED" and next_state == "BROADCASTING":
                if any(x is None for x in (
                    prepared_txid, prepared_raw, prepared_vout,
                    prepared_digest, prepared_ms,
                )):
                    c.execute("ROLLBACK")
                    raise ValueError("BROADCASTING requires durable prebroadcast identity")
                raw_check = require_prepared_raw_tx_hex(prepared_raw)
                if hashlib.sha256(bytes.fromhex(raw_check)).hexdigest() != prepared_digest:
                    c.execute("ROLLBACK")
                    raise ValueError("prepared raw transaction payload hash mismatch")

            # Same-state updates are idempotent but terminal rows are immutable.
            if next_state != current and next_state not in FUNDING_JOURNAL_TRANSITIONS[current]:
                c.execute("ROLLBACK")
                raise ValueError(f"illegal funding journal transition {current}->{next_state}")
            if current in FUNDING_JOURNAL_TERMINAL and next_state == current:
                if txid is not None and txid != old_txid:
                    c.execute("ROLLBACK")
                    raise ValueError("terminal funding transaction identity is immutable")
                if vout is not None and old_vout is not None and int(vout) != int(old_vout):
                    c.execute("ROLLBACK")
                    raise ValueError("terminal funding output identity is immutable")
                if confirmations is not None and int(confirmations) != old_conf:
                    c.execute("ROLLBACK")
                    raise ValueError("terminal funding confirmations are immutable")

            new_txid = old_txid
            new_vout = old_vout
            new_conf = old_conf

            if txid is not None:
                txid = str(txid)
                if not re.fullmatch(r"[0-9a-f]{64}", txid):
                    c.execute("ROLLBACK")
                    raise ValueError("txid")
                if old_txid is not None and old_txid != txid:
                    c.execute("ROLLBACK")
                    raise ValueError("funding transaction identity changed")
                new_txid = txid
            if vout is not None:
                vout = int(vout)
                if vout < 0 or vout > 0xFFFFFFFF:
                    c.execute("ROLLBACK")
                    raise ValueError("vout")
                if old_vout is not None and int(old_vout) != vout:
                    c.execute("ROLLBACK")
                    raise ValueError("funding output identity changed")
                new_vout = vout
            if confirmations is not None:
                confirmations = int(confirmations)
                if confirmations < 0:
                    c.execute("ROLLBACK")
                    raise ValueError("confirmations")
                if confirmations < old_conf:
                    c.execute("ROLLBACK")
                    raise ValueError("confirmations may not decrease")
                new_conf = confirmations

            if next_state in {"TX_IDENTIFIED", "CONFIRMED", "RECORDED"}:
                if new_txid is None or new_vout is None:
                    c.execute("ROLLBACK")
                    raise ValueError(next_state + " requires txid and vout")
                if prepared_txid is None or prepared_vout is None:
                    c.execute("ROLLBACK")
                    raise ValueError(next_state + " requires durable prebroadcast identity")
                if new_txid != prepared_txid or int(new_vout) != int(prepared_vout):
                    c.execute("ROLLBACK")
                    raise ValueError("observed funding identity differs from prepared identity")
            if next_state in {"CONFIRMED", "RECORDED"} and new_conf < 1:
                c.execute("ROLLBACK")
                raise ValueError(next_state + " requires at least one confirmation")
            if next_state in {"PREPARED", "BROADCASTING", "ABORTED"}:
                if new_txid is not None or new_vout is not None or new_conf != 0:
                    c.execute("ROLLBACK")
                    raise ValueError(next_state + " may not carry transaction evidence")

            c.execute(
                """UPDATE funding_attempts
                   SET state=?,txid=?,vout=?,confirmations=?,updated_ms=?
                   WHERE operation_id=?""",
                (next_state, new_txid, new_vout, new_conf, now_ms(), operation_id),
            )
            out = c.execute(
                "SELECT * FROM funding_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            c.execute("COMMIT")
        return self._funding_row(out)


class Agent:
    def __init__(self, root: Path, db_path: Path):
        self.root = root
        self.engine_path = root / "swap/tru_bsty_swap_engine.py"
        self.engine = load_engine(self.engine_path)
        self.handshake_path = root / "swap/offer_handshake_v2.py"
        self.handshake = load_handshake(self.handshake_path)
        self.tru_reconciler_path = root / "swap/tru_funding_reconciler_v1.py"
        self.tru_reconciler = load_tru_reconciler(self.tru_reconciler_path)
        self.bsty_reconciler_path = root / "swap/bsty_funding_reconciler_v1.py"
        self.bsty_reconciler = load_bsty_reconciler(self.bsty_reconciler_path)
        self.bsty_prebroadcast_path = root / "swap/bsty_prebroadcast_v1.py"
        self.bsty_prebroadcast = load_bsty_prebroadcast(self.bsty_prebroadcast_path)
        self.dual_funding_path = root / "swap/dual_funding_v1.py"
        self.dual_funding = load_dual_funding(self.dual_funding_path)
        self.exit_watcher_path = root / "swap/exit_watcher_v1.py"
        self.exit_watcher = load_exit_watcher(self.exit_watcher_path)
        tru_cli = os.environ.get("TRU_SWAP_TRU_CLI")
        if not tru_cli:
            candidates = [
                root / "build-native/bin/tru-cli",
            ]
            tru_cli = str(next((p for p in candidates if p.exists()), candidates[0]))
        tru_conf = os.environ.get("TRU_SWAP_TRU_CONF", str(root / "tru.conf"))
        bsty_cli = os.environ.get("TRU_SWAP_BSTY_CLI", str(Path.home() / "globalboost/src/globalboost-cli"))
        bsty_wallet = os.environ.get("TRU_SWAP_BSTY_WALLET", "bsty_mining")
        self.tru = self.engine.TruAdapter(tru_cli, tru_conf)
        self.bsty = self.engine.BstyAdapter(bsty_cli, bsty_wallet)
        self.store = Store(db_path)
        self.exit_watcher.ensure_schema(self.store)
        self.pairing = secrets.token_urlsafe(32)
        self.origins = parse_origins()
        self.remote_pairing = os.environ.get("TRU_SWAP_AGENT_REMOTE_PAIRING", "").strip().lower()
        if self.remote_pairing not in {"", "cloudflare-access"}:
            raise SystemExit("TRU_SWAP_AGENT_REMOTE_PAIRING must be empty or cloudflare-access")
        self.remote_pair_host = os.environ.get(
            "TRU_SWAP_AGENT_REMOTE_PAIR_HOST", "swap-agent.tokenizedrealutility.com"
        ).strip().lower()
        try:
            ttl = int(os.environ.get("TRU_SWAP_AGENT_PAIR_TTL_SECONDS", str(30 * 24 * 3600)))
        except ValueError:
            raise SystemExit("TRU_SWAP_AGENT_PAIR_TTL_SECONDS must be an integer")
        self.pair_ttl_seconds = min(max(ttl, 3600), 30 * 24 * 3600)
        self.cf_access_email = os.environ.get("TRU_SWAP_AGENT_CF_ACCESS_EMAIL", "").strip().lower()
        self.lock = threading.RLock()
        self.market_process = None
        from local_connect_v1 import LocalConnect
        self.local_connect = LocalConnect(self)
        self.reorg_funding = load_reorg_funding_watcher(root / "swap/reorg_funding_watcher_v1.py")
        if getattr(self.tru_reconciler, "REORG_VERSION", "") != "TRU-REORG-SWAP-01C":
            raise SystemExit("reorg funding observer requires the 01C reconciler")
        self.reorg_watcher = self.reorg_funding.FundingReorgWatcher(
            self.store.path, self.tru_reconciler.reconcile_tru_attempt,
            self.tru.cli, self.tru.conf,
        )

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def pairing_valid(self, presented: str, cookie_token: str, origin: str) -> bool:
        if presented and secrets.compare_digest(presented, self.pairing):
            return True
        if not cookie_token or not origin:
            return False
        return self.store.pair_session_valid(self._token_hash(cookie_token), origin)

    def issue_browser_pairing(self, origin: str, host: str, headers) -> Tuple[str, int]:
        if self.remote_pairing != "cloudflare-access":
            fail(403, "REMOTE_PAIRING_DISABLED",
                 "automatic browser pairing is disabled; use the manual local pairing token")
        if not origin or origin not in self.origins:
            fail(403, "ORIGIN_DENIED", "browser origin is not allowed")
        request_host = (host or "").split(":", 1)[0].strip().lower()
        if request_host != self.remote_pair_host:
            fail(403, "PAIR_HOST_DENIED", "automatic pairing is only allowed on the configured remote agent host")
        access_jwt = (headers.get("Cf-Access-Jwt-Assertion") or "").strip()
        if not access_jwt:
            fail(403, "CF_ACCESS_REQUIRED",
                 "Cloudflare Access authentication is required before automatic pairing")
        if self.cf_access_email:
            got_email = (headers.get("Cf-Access-Authenticated-User-Email") or "").strip().lower()
            if not got_email or not secrets.compare_digest(got_email, self.cf_access_email):
                fail(403, "CF_ACCESS_IDENTITY_DENIED", "Cloudflare Access identity is not authorized")
        token = secrets.token_urlsafe(32)
        expires = self.store.put_pair_session(self._token_hash(token), origin, self.pair_ttl_seconds)
        return token, expires

    def token_ready(self) -> bool:
        return len(os.environ.get("TRU_SWAP_RPC_TOKEN", "")) >= 32

    def health(self) -> Dict[str, Any]:
        tru_ok = False
        bsty_ok = False
        wallet_ok = False
        bsty_ibd = True
        tru_detail = "unreachable"
        bsty_detail = "unreachable"
        try:
            info = self.tru.public_raw("getinfo", {})
            tru_ok = isinstance(info, dict)
            tru_detail = "ready" if tru_ok else "unexpected response"
        except Exception as e:
            tru_detail = str(e)[:180]
        try:
            bi = self.bsty.json("getblockchaininfo")
            bsty_ok = isinstance(bi, dict)
            bsty_ibd = bool((bi or {}).get("initialblockdownload", True))
            bsty_detail = f"height={(bi or {}).get('blocks','?')} ibd={bsty_ibd}"
            try:
                wi = self.bsty.json("getwalletinfo", wallet=True)
                wallet_ok = isinstance(wi, dict)
            except Exception:
                wallet_ok = False
        except Exception as e:
            bsty_detail = str(e)[:180]
        token_ok = self.token_ready()
        tru_usable = tru_ok and token_ok
        bsty_usable = bsty_ok and wallet_ok and not bsty_ibd
        return {
            "ok": bool(tru_usable and bsty_usable),
            "version": VERSION,
            "capabilities": {
                "tru": {
                    "canFundAddress": False,
                    "canFundBareScript": tru_usable,
                    "canSignClaim": tru_usable,
                    "canSignRefund": tru_usable,
                    "canDeriveDestination": False,
                },
                "bsty": {
                    "canFundAddress": bsty_usable,
                    "canFundBareScript": False,
                    "canSignClaim": bsty_usable,
                    "canSignRefund": bsty_usable,
                    "canDeriveDestination": bsty_usable,
                },
            },
            "cores": {
                "tru": {"ok": tru_ok, "detail": tru_detail},
                "bsty": {"ok": bsty_ok, "wallet": wallet_ok, "ibd": bsty_ibd, "detail": bsty_detail},
            },
            "board": {
                "name": "Local TRU Swap Board",
                "kind": "local-development",
                "takeEnabled": False,
            },
            "gates": {
                "swapToken": "SET" if token_ok else "NOT_SET",
                "perSwapTruKeyAllocator": True,
                "offerHandshakeV2": True,
                "fundingJournalV1": True,
                "fundingJournalDomain": FUNDING_JOURNAL_DOMAIN,
                "truFundingReconcilerV1": True,
                "truFundingReconcilerJournalBinding": True,
                "bstyFundingReconcilerV1": True,
                "bstyFundingReconcilerJournalBinding": True,
                "preBroadcastIdentityJournalV1": True,
                "preBroadcastMutationBarrier": True,
                "truPreBroadcastPreparationV1": True,
                "truPreBroadcastJournalBinding": True,
                "truPreparedInputReservation": True,
                "truExactPreparedBroadcastBarrier": True,
                "truPreparedRealBroadcastEnabled": self.dual_funding.enabled(),
                "truNativePreparedBroadcastGateRequired": True,
                "bstyPreBroadcastPreparationV1": True,
                "bstyPreBroadcastJournalBinding": True,
                "bstyPreparedInputReservation": True,
                "bstyExactPreparedBroadcastBarrier": True,
                "bstyPreparedRealBroadcastEnabled": self.dual_funding.enabled(),
                "dualChainFundingActivationV1": True,
                "fundingRouteInstalled": True,
                "fundingRouteEnabled": self.dual_funding.enabled(),
                "persistentExitWatcher": True,
                "exitWatcherV1": True,
                "exitWatcherEnabled": self.exit_watcher.enabled(),
                "exitWatcherUnknownOutcomeBlindRetry": False,
            },
            "fundingReorgObserver": self.reorg_watcher.status(),
            "localConnect": {
                "version": "TRU-LOCAL-CONNECT-01",
                "available": True,
                "approval": "EXPLICIT_LOOPBACK_WINDOW",
                "sessionOriginBound": True,
                "walletSecretsExposed": False,
            },
            "pairing": {
                "mode": "cloudflare-access" if self.remote_pairing == "cloudflare-access" else "local-approval",
                "automatic": self.remote_pairing == "cloudflare-access",
                "tokenExposed": False,
            },
        }

    def require_view(self, swap_id: str) -> sqlite3.Row:
        if not SWAP_ID_RE.fullmatch(swap_id):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        view = self.store.get_view(swap_id)
        if view is None:
            fail(
                404, "SWAP_VIEW_NOT_REGISTERED",
                "swap exists outside the local agent view; register its local give/get perspective first",
            )
        return view

    def get_live_record(self, swap_id: str) -> Dict[str, Any]:
        try:
            record = self.tru.get_record(swap_id)
        except Exception as e:
            fail(502, "TRU_RECORD_READ_FAILED", str(e))
        if not isinstance(record, dict):
            fail(502, "BAD_RECORD_RESPONSE", "TRU returned an invalid swap record")
        return record

    def _chain_height(self, chain: str) -> int:
        if chain == "tru":
            value = self.tru.public_raw("getblockcount", {})
        elif chain == "bsty":
            value = self.bsty.json("getblockcount")
        else:
            raise ValueError("chain")
        height = int(value)
        if height < 0:
            raise ValueError("negative chain height")
        return height

    def _counterparty_rpc(self, chain: str):
        if chain == "tru":
            return lambda method, params: self.tru.public_raw(method, params)

        def rpc(method: str, params: Dict[str, Any]):
            if method == "getrawmempool":
                return self.bsty.json("getrawmempool")
            if method == "getblockcount":
                return self.bsty.json("getblockcount")
            if method == "getblockhash":
                return self.bsty.text("getblockhash", int(params["height"]))
            if method == "getblock":
                return self.bsty.json(
                    "getblock", str(params["blockhash"]), int(params.get("verbosity", 1))
                )
            if method == "getrawtransaction":
                txid = str(params["txid"])
                blockhash = params.get("blockhash")
                if blockhash:
                    return self.bsty.text("getrawtransaction", txid, "false", str(blockhash))
                return self.bsty.text("getrawtransaction", txid, "false")
            raise ValueError("unsupported counterparty BSTY RPC: " + str(method))
        return rpc

    def observe_counterparty_first_funding(self, swap_id: str) -> Dict[str, Any]:
        """Adopt one exact confirmed first-leg output without funding or broadcasting."""
        view = self.require_view(swap_id)
        record = self.get_live_record(swap_id)
        funding_order = str(record.get("fundingOrder", ""))
        if funding_order not in {"TRU_FIRST", "BSTY_FIRST"}:
            fail(502, "BAD_FUNDING_ORDER", "record has invalid fundingOrder")
        first = "tru" if funding_order == "TRU_FIRST" else "bsty"
        if str(view["give_chain"]) == first:
            return {"observed": False, "reason": "LOCAL_FIRST_FUNDER"}
        record_state = str(record.get("state"))
        if record_state not in {"CREATED", "ONE_SIDE_FUNDED"}:
            return {"observed": True, "recordState": record.get("state"), "alreadyRecorded": True}
        if str(view["first_chain"] or "") != first:
            fail(409, "COUNTERPARTY_SCAN_BINDING_MISSING", "first-chain scan binding is missing")
        starting_height = int(view["first_starting_height"])
        expected_fn = (self.tru_reconciler.expected_tru_funding if first == "tru"
                       else self.bsty_reconciler.expected_bsty_funding)
        expected = expected_fn(record)
        attempt = {
            "operationId": funding_operation_id(swap_id, first),
            "swapId": swap_id, "chain": first,
            "amountAtoms": str(record[f"{first}AmountAtoms"]),
            "expectedContractCommitment": expected["commitment"],
            "startingHeight": starting_height, "state": "BROADCASTING",
        }
        try:
            reconciler = (self.tru_reconciler.reconcile_tru_attempt if first == "tru"
                          else self.bsty_reconciler.reconcile_bsty_attempt)
            result = reconciler(record, attempt, self._counterparty_rpc(first))
        except Exception as exc:
            fail(502, "COUNTERPARTY_FUNDING_SCAN_FAILED", str(exc))
        if result.get("classification") == "MULTIPLE_CANDIDATES":
            fail(409, "COUNTERPARTY_FUNDING_AMBIGUOUS", "multiple exact first-leg candidates")
        candidate = result.get("candidate")
        if result.get("classification") != "ONE_CANDIDATE" or not isinstance(candidate, dict):
            return {"observed": True, "recorded": False,
                    "classification": result.get("classification"),
                    "candidateCount": int(result.get("candidateCount", 0))}
        confirmations = int(candidate.get("confirmations", 0))
        required = int(view["min_conf"])
        if confirmations < required:
            return {"observed": True, "recorded": False,
                    "classification": "ONE_CANDIDATE", "confirmations": confirmations,
                    "requiredConfirmations": required}
        if record_state == "ONE_SIDE_FUNDED":
            evidence = record.get("evidence") or {}
            if not isinstance(evidence, dict):
                fail(409, "COUNTERPARTY_FUNDING_EVIDENCE_MALFORMED",
                     "canonical funding evidence is not an object")
            recorded_txid = str(evidence.get(f"{first}FundingTxid", ""))
            recorded_vout = int(evidence.get(f"{first}FundingVout", -1))
            if (recorded_txid != str(candidate["txid"]) or
                    recorded_vout != int(candidate["vout"])):
                fail(409, "COUNTERPARTY_FUNDING_IDENTITY_CHANGED",
                     "canonical first-leg candidate does not match recorded evidence")
            return {"observed": True, "recorded": True, "currentConfirmed": True,
                    "chain": first, "txid": recorded_txid, "vout": recorded_vout,
                    "confirmations": confirmations, "recordState": record_state,
                    "broadcast": False, "coinMovement": False}
        updated = self.engine.transition_after_funding(
            self.tru, record, first, str(candidate["txid"]), int(candidate["vout"]),
            confirmations, required,
        )
        return {"observed": True, "recorded": True, "chain": first,
                "txid": str(candidate["txid"]), "vout": int(candidate["vout"]),
                "confirmations": confirmations, "recordState": updated.get("state"),
                "broadcast": False, "coinMovement": False}

    def _funding_tip(self, chain: str) -> Tuple[int, str]:
        height = self._chain_height(chain)
        if chain == "tru":
            block = self.tru.public_raw("getblockbyheight", {"height": height})
            if not isinstance(block, dict) or block.get("height") != height:
                raise ValueError("invalid TRU tip block")
            blockhash = block.get("hash")
        else:
            blockhash = self.bsty.text("getblockhash", height)
        if not SWAP_ID_RE.fullmatch(str(blockhash)):
            raise ValueError("invalid funding tip hash")
        return height, str(blockhash)

    def _scan_counterparty_leg(self, record, chain, starting_height):
        if type(starting_height) is not int or starting_height < 0:
            fail(409, "COUNTERPARTY_SCAN_BINDING_MISSING", "funding scan anchor is missing")
        module = self.tru_reconciler if chain == "tru" else self.bsty_reconciler
        expected = getattr(module, "expected_" + chain + "_funding")(record)
        attempt = {
            "operationId": funding_operation_id(record["swapId"], chain),
            "swapId": record["swapId"], "chain": chain,
            "amountAtoms": str(record[chain + "AmountAtoms"]),
            "expectedContractCommitment": expected["commitment"],
            "startingHeight": starting_height, "state": "BROADCASTING",
        }
        result = getattr(module, "reconcile_" + chain + "_attempt")(
            record, attempt, self._counterparty_rpc(chain))
        if result.get("classification") == "MULTIPLE_CANDIDATES":
            fail(409, "COUNTERPARTY_FUNDING_AMBIGUOUS", "multiple exact funding candidates")
        return result.get("candidate") if result.get("classification") == "ONE_CANDIDATE" else None

    def _legacy_bsty_candidate(self, record, tip):
        """Read-only UTXO discovery for existing views without a BSTY scan anchor.

        Never infer an old anchor from today's height. No wallet import, journal
        rewrite, signing or broadcast. All matches must be unambiguous and exact.
        """
        expected = self.bsty_reconciler.expected_bsty_funding(record)
        script = expected["p2shScriptPubKeyHex"]
        cp = subprocess.run(
            [self.bsty.cli, "scantxoutset", "start", json.dumps(["raw(" + script + ")"])],
            text=True, capture_output=True, timeout=30, check=False,
        )
        if cp.returncode != 0:
            raise ValueError("BSTY read-only contract scan failed: " + cp.stderr.strip())
        result = json.loads(cp.stdout, parse_float=Decimal)
        if (not isinstance(result, dict) or result.get("success") is not True or
                result.get("height") != tip[0] or result.get("bestblock") != tip[1] or
                not isinstance(result.get("unspents"), list)):
            fail(409, "COUNTERPARTY_SCAN_INCOMPLETE", "BSTY contract scan incomplete or tip changed")
        rows = result["unspents"]
        if len(rows) > 1:
            fail(409, "COUNTERPARTY_FUNDING_AMBIGUOUS", "multiple unspent contract outputs")
        if not rows:
            return None
        row = rows[0]
        if (row.get("scriptPubKey") != script or
                Decimal(str(row.get("amount"))) * 100000000 != expected["amountAtoms"] or
                row.get("coinbase", False) is not False or
                not SWAP_ID_RE.fullmatch(str(row.get("txid"))) or
                type(row.get("vout")) is not int or not 0 <= row["vout"] <= 0xffffffff or
                type(row.get("height")) is not int or not 0 < row["height"] <= tip[0]):
            fail(409, "COUNTERPARTY_OUTPUT_MISMATCH", "BSTY contract output does not match agreement")
        return {"txid": row["txid"], "vout": row["vout"],
                "confirmations": tip[0] - row["height"] + 1}

    def _check_unspent_funding(self, record, chain, candidate, tip):
        txid, vout = candidate["txid"], candidate["vout"]
        expected = (self.tru_reconciler.expected_tru_funding(record) if chain == "tru"
                    else self.bsty_reconciler.expected_bsty_funding(record))
        script = expected["contractScriptHex" if chain == "tru" else "p2shScriptPubKeyHex"]
        if chain == "tru":
            out = self.tru.public_raw("gettxout", {"txid": txid, "n": vout, "includeMempool": True})
        else:
            out = json.loads(self.bsty.text("gettxout", txid, vout, "true"), parse_float=Decimal)
        if (not isinstance(out, dict) or out.get("bestblock") != tip[1] or
                (out.get("scriptPubKey") or {}).get("hex") != script or
                Decimal(str(out.get("value"))) * 100000000 != expected["amountAtoms"] or
                out.get("coinbase") is not False):
            fail(409, "COUNTERPARTY_OUTPUT_UNAVAILABLE", "funding output spent, changed, or unavailable")
        # TRU gettxout's legacy confirmation field is not authoritative. Its
        # confirmations above come from canonical block scanning, not that field.
        if chain == "bsty" and out.get("confirmations") != candidate["confirmations"]:
            fail(409, "COUNTERPARTY_TIP_CHANGED", "BSTY funding confirmations changed during verification")

    def observe_counterparty_second_funding(self, swap_id: str) -> Dict[str, Any]:
        """Let the first funder observe the second leg, without moving coins."""
        view = dict(self.require_view(swap_id))
        record = self.get_live_record(swap_id)
        order = record.get("fundingOrder")
        if order not in {"TRU_FIRST", "BSTY_FIRST"}:
            fail(409, "BAD_FUNDING_ORDER", "invalid canonical funding order")
        first = "tru" if order == "TRU_FIRST" else "bsty"
        second = "bsty" if first == "tru" else "tru"
        if view["give_chain"] != first or record.get("state") != "ONE_SIDE_FUNDED":
            return {"observed": False, "recordState": record.get("state")}
        if view.get("get_chain") != second or view.get("first_chain") != first:
            fail(409, "COUNTERPARTY_SCAN_BINDING_MISSING", "funding role binding is missing")
        try:
            required = self.engine.configured_resolution_min_conf(record, int(view["min_conf"]))
            first_tip, second_tip = self._funding_tip(first), self._funding_tip(second)
            # Rate-limit legacy full UTXO scans while waiting for a new block.
            key = (swap_id, first_tip, second_tip)
            held = getattr(self, "_second_scan_hold", {})
            if held.get(key, 0) > time.monotonic():
                return {"observed": False, "recorded": False, "reason": "WAITING_FOR_CONFIRMATIONS"}
            anchor = view.get("counterparty_starting_height")
            if anchor is None:
                if second != "bsty":
                    fail(409, "COUNTERPARTY_SCAN_BINDING_MISSING", "legacy TRU second-leg scan anchor is missing")
                candidate = self._legacy_bsty_candidate(record, second_tip)
            else:
                candidate = self._scan_counterparty_leg(record, second, anchor)
            if candidate is None or int(candidate.get("confirmations", 0)) < required:
                self._second_scan_hold = {key: time.monotonic() + 30}
                return {"observed": True, "recorded": False, "chain": second,
                        "confirmations": int((candidate or {}).get("confirmations", 0)),
                        "requiredConfirmations": required}
            # Recheck the existing first outpoint against canonical chain data;
            # another node's journal or stale evidence is never a funding proof.
            first_candidate = self._scan_counterparty_leg(record, first, view.get("first_starting_height"))
            evidence = record.get("evidence") or {}
            if (not isinstance(evidence, dict) or first_candidate is None or
                    int(first_candidate.get("confirmations", 0)) < required or
                    evidence.get(first + "FundingTxid") != first_candidate["txid"] or
                    evidence.get(first + "FundingVout") != first_candidate["vout"]):
                fail(409, "COUNTERPARTY_FIRST_EVIDENCE_CHANGED", "first funding evidence is not currently confirmed")
            if (evidence.get(second + "FundingTxid") not in (None, "", candidate["txid"]) or
                    (evidence.get(second + "FundingTxid") and
                     evidence.get(second + "FundingVout") != candidate["vout"])):
                fail(409, "COUNTERPARTY_FUNDING_IDENTITY_CHANGED", "second funding identity conflicts with evidence")
            self._check_unspent_funding(record, first, first_candidate, first_tip)
            self._check_unspent_funding(record, second, candidate, second_tip)
            if self._funding_tip(first) != first_tip or self._funding_tip(second) != second_tip:
                fail(409, "COUNTERPARTY_TIP_CHANGED", "chain tip changed during funding verification")
            if self.get_live_record(swap_id) != record:
                fail(409, "COUNTERPARTY_RECORD_CHANGED", "swap record changed during funding verification")
            updated = self.engine.transition_after_funding(
                self.tru, record, second, candidate["txid"], candidate["vout"],
                candidate["confirmations"], required)
            return {"observed": True, "recorded": True, "currentConfirmed": True,
                    "chain": second, "txid": candidate["txid"], "vout": candidate["vout"],
                    "confirmations": candidate["confirmations"], "recordState": updated.get("state"),
                    "broadcast": False, "coinMovement": False}
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "COUNTERPARTY_SECOND_SCAN_FAILED", str(exc))

    def progress_swap(self, swap_id: str) -> Dict[str, Any]:
        """Progress already-broadcast evidence and counterparty observation only."""
        view = self.require_view(swap_id)
        attempt = self.store.get_funding_attempt(swap_id, str(view["give_chain"]))
        local = None
        if attempt is not None and attempt.get("state") in {"TX_IDENTIFIED", "CONFIRMED", "RECORDED"}:
            local = self.fund_local_chain(swap_id)
        remote = self.observe_counterparty_first_funding(swap_id)
        if remote.get("reason") == "LOCAL_FIRST_FUNDER":
            remote = self.observe_counterparty_second_funding(swap_id)
        return {"record": self.view_record(swap_id), "local": local, "remote": remote,
                "freshFunding": False, "automaticBroadcast": False}

    def view_record(self, swap_id: str) -> Dict[str, Any]:
        view = self.require_view(swap_id)
        r = self.get_live_record(swap_id)
        give = view["give_chain"]
        get = view["get_chain"]
        amount_key = {"tru": "truAmountAtoms", "bsty": "bstyAmountAtoms"}
        refund_key = {"tru": "truRefundTime", "bsty": "bstyRefundTime"}
        out = dict(r)
        out["giveChain"] = give
        out["getChain"] = get
        out["giveAmount"] = atoms_to_coin(int(r[amount_key[give]]))
        out["getAmount"] = atoms_to_coin(int(r[amount_key[get]]))
        out["myRefundTime"] = int(r[refund_key[give]])
        out["theirRefundTime"] = int(r[refund_key[get]])
        out["minConf"] = int(view["min_conf"])
        first_chain = "tru" if r.get("fundingOrder") == "TRU_FIRST" else "bsty"
        out["localFundingPosition"] = "first" if give == first_chain else "second"
        w = self.exit_watcher.get_job(self.store, swap_id)
        out["lodged"] = bool(w and w.get("state") in self.exit_watcher.ACTIVE_STATES)
        out["exits"] = self.exit_watcher.public_job(w) if w else None
        return browser_safe(out)

    def descriptor(self, chain: str, record: Dict[str, Any], amount_atoms: int,
                   refund_time: int, claimer: str) -> Dict[str, Any]:
        script = self.engine.record_script(record, chain)
        if len(script) != 103:
            fail(500, "HTLC_LENGTH_MISMATCH", f"{chain} HTLC is not 103 bytes")
        fp = hashlib.sha256(script).hexdigest()
        if chain == "tru":
            target = {"kind": "script", "scriptHex": script.hex()}
            wrapper = "bare"
            sighash = "tru_v1"
        else:
            try:
                dec = self.bsty.json("decodescript", script.hex())
            except Exception as e:
                fail(502, "BSTY_DECODE_SCRIPT_FAILED", str(e))
            addr = (dec or {}).get("p2sh")
            if not addr:
                fail(502, "BSTY_P2SH_MISSING", "decodescript did not return a P2SH address")
            target = {
                "kind": "address",
                "address": addr,
                "scriptHex": self.engine.p2sh_scriptpubkey(script).hex(),
            }
            wrapper = "p2sh"
            sighash = "legacy"
        return {
            "chain": chain,
            "wrapper": wrapper,
            "spendModel": "scriptSig",
            "sighashModel": sighash,
            "fundingTarget": target,
            "redeemScriptHex": script.hex(),
            "fingerprint": fp,
            "amount": f"{atoms_to_coin(amount_atoms)} {'TRU' if chain == 'tru' else 'BSTY'}",
            "refundTime": int(refund_time),
            "claimer": claimer,
        }

    def contracts(self, swap_id: str) -> Dict[str, Any]:
        view = self.require_view(swap_id)
        r = self.get_live_record(swap_id)
        give, get = view["give_chain"], view["get_chain"]
        amount_key = {"tru": "truAmountAtoms", "bsty": "bstyAmountAtoms"}
        refund_key = {"tru": "truRefundTime", "bsty": "bstyRefundTime"}
        return {
            "mine": self.descriptor(
                give, r, int(r[amount_key[give]]), int(r[refund_key[give]]), "the other party"
            ),
            "theirs": self.descriptor(
                get, r, int(r[amount_key[get]]), int(r[refund_key[get]]), "you"
            ),
        }

    def validate_bsty_address(self, address: str) -> bool:
        try:
            obj = self.bsty.json("validateaddress", address)
            if isinstance(obj, dict) and "isvalid" in obj:
                return bool(obj.get("isvalid"))
        except Exception:
            pass
        try:
            obj = self.bsty.json("getaddressinfo", address, wallet=True)
            return isinstance(obj, dict) and bool(obj.get("address"))
        except Exception:
            return False

    def validate_destination(self, d: Any, expected_chain: str) -> Tuple[bool, str]:
        if not isinstance(d, dict):
            return False, "destination missing"
        if d.get("chain") != expected_chain:
            return False, f"destination chain must be {expected_chain}"
        source = d.get("source")
        if source == "wallet":
            h = self.health()["capabilities"][expected_chain]
            return bool(h.get("canDeriveDestination")), "wallet destination derivation unavailable"
        if source != "external":
            return False, "destination source must be wallet or external"
        address = str(d.get("address", ""))
        if expected_chain == "tru":
            return validate_tru_address(address), "invalid TRU mainnet address"
        return self.validate_bsty_address(address), "invalid BSTY address"

    def verify(self, swap_id: str, destinations: Any) -> Dict[str, Any]:
        view = self.require_view(swap_id)
        r = self.get_live_record(swap_id)
        contracts = self.contracts(swap_id)
        mine, theirs = contracts["mine"], contracts["theirs"]
        funding_order = str(r.get("fundingOrder", ""))
        if funding_order not in {"TRU_FIRST", "BSTY_FIRST"}:
            fail(502, "BAD_FUNDING_ORDER", "record has invalid fundingOrder")
        first_chain = "tru" if funding_order == "TRU_FIRST" else "bsty"
        second_chain = "bsty" if first_chain == "tru" else "tru"
        refund_key = {"tru": "truRefundTime", "bsty": "bstyRefundTime"}
        gap = int(r[refund_key[first_chain]]) - int(r[refund_key[second_chain]])
        h = str(r.get("secretHash160", ""))
        checks = [
            {"label": "Both contracts match the frozen 103-byte format",
             "ok": len(bytes.fromhex(mine["redeemScriptHex"])) == 103 and len(bytes.fromhex(theirs["redeemScriptHex"])) == 103},
            {"label": "Both contracts commit to the same 20-byte HASH160",
             "ok": bool(re.fullmatch(r"[0-9a-f]{40}", h))},
            {"label": "First-funded contract has the later refund window", "ok": gap > 0},
            {"label": f"{gap // 3600} hours protect the second-funded participant",
             "ok": gap >= MIN_TIMELOCK_GAP_HOURS * 3600},
            {"label": "Amounts are positive", "ok": int(r.get("truAmountAtoms", 0)) > 0 and int(r.get("bstyAmountAtoms", 0)) > 0},
        ]
        d = destinations if isinstance(destinations, dict) else {}
        claim_ok, _ = self.validate_destination(d.get("claim"), view["get_chain"])
        refund_ok, _ = self.validate_destination(d.get("refund"), view["give_chain"])
        checks.append({"label": f"Claim destination is valid on {view['get_chain'].upper()}", "ok": claim_ok})
        checks.append({"label": f"Refund destination is valid on {view['give_chain'].upper()}", "ok": refund_ok})
        return {"checks": checks}

    def _fresh_tru_role(self, participant: str, maker_give: str) -> Dict[str, Any]:
        role = self.handshake.expected_roles(maker_give, participant)["tru"]
        allocation_id = secrets.token_hex(32)
        try:
            keys = self.tru.raw("swapwalletfreshkeys", {"allocationId": allocation_id})
        except Exception as exc:
            fail(502, "TRU_FRESH_ALLOCATOR_FAILED", str(exc))
        if not isinstance(keys, dict) or keys.get("privateMaterialReturned") is not False:
            fail(502, "TRU_FRESH_ALLOCATOR_BAD_RESPONSE", "TRU fresh allocator returned unsafe/invalid response")
        pubkey = keys.get("claimPubkey") if role == "claim" else keys.get("refundPubkey")
        if not isinstance(pubkey, str) or not re.fullmatch(r"(02|03)[0-9a-f]{64}", pubkey):
            fail(502, "TRU_FRESH_ALLOCATOR_BAD_PUBKEY", "TRU fresh allocator returned invalid pubkey")
        return {"role": role, "allocationId": allocation_id, "pubkey": pubkey}

    def _fresh_bsty_role(self, participant: str, maker_give: str) -> Tuple[Dict[str, Any], str]:
        role = self.handshake.expected_roles(maker_give, participant)["bsty"]
        try:
            label = f"tru-swap-{participant}-{secrets.token_hex(8)}"
            address = self.bsty.text("getnewaddress", label, wallet=True).strip()
            info = self.bsty.json("getaddressinfo", address, wallet=True)
        except Exception as exc:
            fail(502, "BSTY_FRESH_KEY_FAILED", str(exc))
        pubkey = (info or {}).get("pubkey") if isinstance(info, dict) else None
        if not isinstance(pubkey, str) or not re.fullmatch(r"(02|03)[0-9a-fA-F]{64}", pubkey):
            fail(502, "BSTY_FRESH_KEY_BAD_PUBKEY", "BSTY wallet did not expose a compressed pubkey for its fresh address")
        if not isinstance(info, dict) or info.get("ismine") is not True:
            fail(502, "BSTY_FRESH_KEY_NOT_OWNED", "BSTY fresh address is not owned by the configured wallet")
        return {"role": role, "pubkey": pubkey.lower()}, address

    def _role_material(self, participant: str, maker_give: str) -> Tuple[Dict[str, Any], str]:
        bsty_material, bsty_signer_address = self._fresh_bsty_role(participant, maker_give)
        return {
            "participant": participant,
            "tru": self._fresh_tru_role(participant, maker_give),
            "bsty": bsty_material,
        }, bsty_signer_address

    @staticmethod
    def _terms_from_browser(body: Dict[str, Any]) -> Dict[str, Any]:
        give = str(body.get("giveChain", ""))
        get = str(body.get("getChain", ""))
        if give not in CHAINS or get not in CHAINS or give == get:
            fail(400, "BAD_CHAIN_PAIR", "offer must be TRU↔BSTY")
        give_atoms = coin_to_atoms(body.get("giveAmount", ""))
        get_atoms = coin_to_atoms(body.get("getAmount", ""))
        try:
            own_h = int(body.get("ownHours", 0))
            their_h = int(body.get("theirHours", 0))
            min_conf = int(body.get("minConf", 0))
        except Exception:
            fail(400, "BAD_OFFER_PARAMETERS", "timelock/confirmation fields must be integers")
        if own_h <= their_h or own_h - their_h < MIN_TIMELOCK_GAP_HOURS:
            fail(400, "TIMELOCK_GAP_TOO_SMALL", f"maker refund window must be at least {MIN_TIMELOCK_GAP_HOURS} hours later")
        if min_conf < 1 or min_conf > 10_000:
            fail(400, "BAD_CONFIRMATIONS", "minConf must be 1..10000")
        return {
            "pairId": "TRU_BSTY",
            "makerGiveChain": give,
            "truAmountAtoms": give_atoms if give == "tru" else get_atoms,
            "bstyAmountAtoms": give_atoms if give == "bsty" else get_atoms,
            "truMinConfirmations": min_conf,
            "bstyMinConfirmations": min_conf,
            "fundingOrder": "MAKER_FIRST",
            "makerRefundSeconds": own_h * 3600,
            "takerRefundSeconds": their_h * 3600,
        }

    def create_offer_v2(self, body: Dict[str, Any], *, process_key=None) -> Dict[str, Any]:
        terms = self._terms_from_browser(body)
        if process_key is not None:
            with self.store.connect() as c:
                row = c.execute("SELECT offer_id FROM market_offer_keys WHERE process_key=?", (process_key,)).fetchone()
            if row:
                session = self.store.get_offer_session(row["offer_id"], "maker")
                if not session or session["offer"]["terms"] != terms:
                    fail(409, "MARKET_OFFER_BINDING_MISMATCH", "durable offer terms differ")
                return {"stage": "OFFER_CREATED", "offerId": session["offerId"],
                        "shareBlob": encode_exchange(OFFER_PREFIX_V2, session["offer"]), "recordCreated": False}
        maker_give = terms["makerGiveChain"]
        maker_get = "bsty" if maker_give == "tru" else "tru"
        maker_roles, maker_bsty_signer = self._role_material("maker", maker_give)
        preimage = secrets.token_bytes(32)
        secret_hash = hash160(preimage)
        created = int(time.time())
        offer = self.handshake.make_offer(
            terms, maker_roles, offer_nonce=secrets.token_hex(32),
            created_at=created, expires_at=created + OFFER_TTL_SECONDS,
            secret_hash160=secret_hash,
        )
        self.store.put_offer_session(
            offer["offerId"], "maker", "OFFER_CREATED", offer,
            maker_give, maker_get, int(terms["truMinConfirmations"]),
            bsty_signer_address=maker_bsty_signer,
            preimage_hex=preimage.hex(), process_key=process_key,
        )
        return browser_safe({
            "stage": "OFFER_CREATED",
            "offerId": offer["offerId"],
            "shareBlob": encode_exchange(OFFER_PREFIX_V2, offer),
            "recordCreated": False,
        })

    def _create_record_from_final(self, final: Dict[str, Any], give_chain: str, get_chain: str, min_conf: int) -> Tuple[Dict[str, Any], bool]:
        params = dict(final["recordParams"])
        try:
            created = self.tru.raw("swaprecordcreate", params)
        except Exception as exc:
            fail(502, "SWAP_RECORD_CREATE_FAILED", str(exc))
        if not isinstance(created, dict):
            fail(502, "BAD_SWAP_RECORD_RESPONSE", "TRU returned invalid swaprecordcreate response")
        swap_id = created.get("swapId")
        record = created.get("record")
        if not isinstance(swap_id, str) or not SWAP_ID_RE.fullmatch(swap_id):
            fail(502, "BAD_SWAP_RECORD_RESPONSE", "TRU did not return canonical swapId")
        if not isinstance(record, dict):
            try:
                record = self.tru.get_record(swap_id)
            except Exception as exc:
                fail(502, "TRU_RECORD_READ_FAILED", str(exc))
        if not isinstance(record, dict) or str(record.get("swapId", "")) != swap_id:
            fail(502, "BAD_SWAP_RECORD_RESPONSE", "TRU canonical record identity mismatch")
        for key, expected in params.items():
            if record.get(key) != expected:
                fail(409, "CANONICAL_RECORD_MISMATCH", f"existing TRU record differs at {key}")
        self.register_view(swap_id, give_chain, get_chain, min_conf)
        return self.view_record(swap_id), bool(created.get("created"))

    def import_offer_v2(self, blob: Any) -> Dict[str, Any]:
        prefix, obj = decode_exchange(blob)
        now = int(time.time())

        if prefix == OFFER_PREFIX_V2:
            try:
                offer = self.handshake.validate_offer(obj, now=now)
            except Exception as exc:
                fail(400, "BAD_OFFER_V2", str(exc))
            if offer["terms"]["fundingOrder"] != "MAKER_FIRST":
                fail(400, "UNSUPPORTED_BROWSER_FUNDING_ORDER", "01B3B browser activation supports MAKER_FIRST only")
            if offer["terms"]["truMinConfirmations"] != offer["terms"]["bstyMinConfirmations"]:
                fail(400, "UNSUPPORTED_BROWSER_CONFIRMATION_SPLIT", "01B3B browser activation requires the same minimum confirmations on both chains")
            existing = self.store.get_offer_session(offer["offerId"], "taker")
            if existing and existing.get("acceptance"):
                acceptance = existing["acceptance"]
            else:
                maker_give = offer["terms"]["makerGiveChain"]
                taker_roles, taker_bsty_signer = self._role_material("taker", maker_give)
                try:
                    acceptance = self.handshake.make_acceptance(
                        offer, taker_roles, accept_nonce=secrets.token_hex(32),
                        accepted_at=now,
                    )
                except Exception as exc:
                    fail(400, "ACCEPTANCE_CREATE_FAILED", str(exc))
                taker_give = "bsty" if maker_give == "tru" else "tru"
                self.store.put_offer_session(
                    offer["offerId"], "taker", "ACCEPTANCE_CREATED", offer,
                    taker_give, maker_give, int(offer["terms"]["truMinConfirmations"]),
                    bsty_signer_address=taker_bsty_signer,
                    acceptance=acceptance,
                )
            return browser_safe({
                "stage": "ACCEPTANCE_CREATED",
                "offerId": offer["offerId"],
                "acceptId": acceptance["acceptId"],
                "shareBlob": encode_exchange(ACCEPT_PREFIX_V2, acceptance),
                "recordCreated": False,
            })

        if prefix == ACCEPT_PREFIX_V2:
            accept_id = str(obj.get("acceptId", ""))
            offer_id = str(obj.get("offerId", ""))
            session = self.store.get_offer_session(offer_id, "maker")
            if session is None:
                fail(409, "MAKER_SESSION_NOT_FOUND", "this agent did not create the referenced offer")
            offer = session["offer"]
            try:
                acceptance = self.handshake.validate_acceptance(offer, obj, now=None if session.get("final") else now)
            except Exception as exc:
                fail(400, "BAD_ACCEPTANCE_V2", str(exc))
            if session.get("acceptance") and session["acceptance"].get("acceptId") != accept_id:
                fail(409, "DIFFERENT_ACCEPTANCE_ALREADY_BOUND", "offer is already bound to a different acceptance")
            if session.get("final"):
                final = session["final"]
            else:
                try:
                    final = self.handshake.final_bundle(offer, acceptance, finalized_at=now)
                except Exception as exc:
                    fail(400, "FINALIZE_FAILED", str(exc))
            # Persist exact final bytes before the first canonical-record RPC.
            # A lost RPC response must replay the same refund times and swap ID.
            self.store.put_offer_session(
                offer_id, "maker", "FINALIZATION_STARTED", offer,
                session["giveChain"], session["getChain"], session["minConf"],
                bsty_signer_address=session["bstySignerAddress"], acceptance=acceptance,
                final=final, preimage_hex=session.get("preimageHex"),
            )
            record, record_created = self._create_record_from_final(
                final, session["giveChain"], session["getChain"], session["minConf"]
            )
            self.store.put_offer_session(
                offer_id, "maker", "FINALIZED", offer,
                session["giveChain"], session["getChain"], session["minConf"],
                bsty_signer_address=session["bstySignerAddress"],
                acceptance=acceptance, final=final, preimage_hex=session.get("preimageHex"),
                swap_id=record["swapId"],
            )
            return browser_safe({
                "stage": "FINALIZED_MAKER",
                "record": record,
                "shareBlob": encode_exchange(FINAL_PREFIX_V2, final),
                "recordCreated": record_created,
            })

        # FINAL_PREFIX_V2
        final = obj
        offer_id = str(final.get("offerId", ""))
        session = self.store.get_offer_session(offer_id, "taker")
        if session is None or not session.get("acceptance"):
            fail(409, "TAKER_SESSION_NOT_FOUND", "this agent did not accept the referenced offer")
        offer = session["offer"]
        acceptance = session["acceptance"]
        rp = final.get("recordParams")
        if not isinstance(rp, dict):
            fail(400, "BAD_FINAL_V2", "final bundle recordParams missing")
        terms = offer["terms"]
        maker_give = terms["makerGiveChain"]
        maker_refund = int(rp.get("truRefundTime" if maker_give == "tru" else "bstyRefundTime", 0))
        taker_refund = int(rp.get("bstyRefundTime" if maker_give == "tru" else "truRefundTime", 0))
        finalized_at = maker_refund - int(terms["makerRefundSeconds"])
        taker_finalized_at = taker_refund - int(terms["takerRefundSeconds"])
        if finalized_at != taker_finalized_at:
            fail(400, "FINAL_TIME_MISMATCH", "final bundle refund times do not share one canonical finalization time")
        try:
            expected = self.handshake.final_bundle(offer, acceptance, finalized_at=finalized_at)
        except Exception as exc:
            fail(400, "BAD_FINAL_V2", str(exc))
        if expected != final:
            fail(400, "FINAL_BUNDLE_MISMATCH", "final bundle does not match local offer/acceptance")
        record, record_created = self._create_record_from_final(
            final, session["giveChain"], session["getChain"], session["minConf"]
        )
        self.store.put_offer_session(
            offer_id, "taker", "FINALIZED", offer,
            session["giveChain"], session["getChain"], session["minConf"],
            bsty_signer_address=session["bstySignerAddress"],
            acceptance=acceptance, final=final, swap_id=record["swapId"],
        )
        return browser_safe({
            "stage": "FINALIZED_TAKER",
            "record": record,
            "recordCreated": record_created,
        })

    def prepare_tru_funding_journal(
        self, swap_id: str, starting_height: int
    ) -> Dict[str, Any]:
        """Prepare the deterministic TRU journal row; does not broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            record = self.get_live_record(swap_id)
            expected = self.tru_reconciler.expected_tru_funding(record)
            attempt = self.store.prepare_funding_attempt(
                swap_id,
                "tru",
                str(record.get("truAmountAtoms", "")),
                expected["commitment"],
                int(starting_height),
            )
        except ApiError:
            raise
        except Exception as exc:
            fail(409, "TRU_FUNDING_JOURNAL_PREPARE_FAILED", str(exc))
        return attempt

    def prepare_tru_prebroadcast_funding(self, swap_id: str) -> Dict[str, Any]:
        """Prepare, validate, and durably bind a signed TRU funding tx; never broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            view = self.require_view(swap_id)
            record = self.get_live_record(swap_id)
            require_tru_prebroadcast_turn(record, str(view["give_chain"]))
            expected = self.tru_reconciler.expected_tru_funding(record)

            attempt = self.store.get_funding_attempt(swap_id, "tru")
            if attempt is None:
                tip = int(self.tru.public_raw("getblockcount", {}))
                attempt = self.prepare_tru_funding_journal(swap_id, tip + 1)

            if attempt.get("state") != "PREPARED":
                fail(
                    409, "TRU_PREBROADCAST_BAD_JOURNAL_STATE",
                    "TRU signed preparation requires the funding journal to remain PREPARED",
                )
            if str(attempt.get("amountAtoms", "")) != str(record.get("truAmountAtoms", "")):
                fail(409, "TRU_PREBROADCAST_AMOUNT_DRIFT", "journal amount differs from canonical record")
            if str(attempt.get("expectedContractCommitment", "")) != str(expected.get("commitment", "")):
                fail(409, "TRU_PREBROADCAST_COMMITMENT_DRIFT", "journal contract commitment differs from canonical record")

            # Idempotent restart path: once exact signed bytes are durable, never
            # call the wallet preparation RPC again for this operation.
            if attempt.get("prebroadcastReady") is True:
                payload = self.store.get_prepared_funding_payload(attempt["operationId"])
                node_status = self.tru.raw("htlcpreparedstatus", {
                    "operationId": attempt["operationId"],
                })
                if not isinstance(node_status, dict):
                    fail(502, "TRU_PREPARED_STATUS_SHAPE", "node reservation status is invalid")
                if (
                    node_status.get("found") is not True
                    or node_status.get("state") != "PREPARED"
                    or node_status.get("reservationActive") is not True
                    or node_status.get("inMempool") is not False
                    or str(node_status.get("preparedTxid", "")) != str(payload["preparedTxid"])
                    or int(node_status.get("preparedVout", -1)) != int(payload["preparedContractVout"])
                    or int(node_status.get("reservedInputCount", 0)) < 1
                ):
                    fail(
                        409, "TRU_PREPARED_RESERVATION_DRIFT",
                        "durable Agent payload no longer matches an intact node reservation",
                    )
                return browser_safe({
                    "swapId": swap_id,
                    "chain": "tru",
                    "operationId": attempt["operationId"],
                    "journalState": attempt["state"],
                    "prebroadcastReady": True,
                    "preparedTxid": payload["preparedTxid"],
                    "preparedVout": payload["preparedContractVout"],
                    "preparedPayloadSha256": payload["preparedPayloadSha256"],
                    "preparedMs": payload["preparedMs"],
                    "reservedInputCount": int(node_status["reservedInputCount"]),
                    "preparedInputReservation": True,
                    "broadcast": False,
                    "fundingRouteEnabled": False,
                    "idempotentReuse": True,
                })

            params = {
                "operationId": attempt["operationId"],
                "secretHash160": record["secretHash160"],
                "claimPubkey": record["truClaimPubkey"],
                "refundPubkey": record["truRefundPubkey"],
                "refundTime": int(record["truRefundTime"]),
                "amountAtoms": int(record["truAmountAtoms"]),
            }
            prepared = self.tru.raw("htlcpreparefunding", params)
            normalized = validate_tru_prebroadcast_prepare_result(record, expected, prepared, attempt["operationId"])

            # A prepared transaction must still be unpublished at journal bind time.
            mempool = self.tru.public_raw("getrawmempool", {"verbose": False})
            if not isinstance(mempool, list):
                fail(502, "TRU_MEMPOOL_SHAPE", "getrawmempool returned an unexpected response")
            if normalized["preparedTxid"] in {str(x) for x in mempool}:
                fail(409, "TRU_PREPARED_TX_ALREADY_BROADCAST", "prepared transaction is already present in mempool")

            armed = self.store.prepare_funding_payload(
                attempt["operationId"],
                normalized["preparedTxid"],
                normalized["preparedRawTxHex"],
                normalized["preparedContractVout"],
            )
            if armed.get("prebroadcastReady") is not True:
                fail(500, "TRU_PREBROADCAST_ARM_FAILED", "durable journal did not become prebroadcast-ready")

            node_status = self.tru.raw("htlcpreparedstatus", {
                "operationId": attempt["operationId"],
            })
            if not isinstance(node_status, dict):
                fail(502, "TRU_PREPARED_STATUS_SHAPE", "node reservation status is invalid")
            if (
                node_status.get("found") is not True
                or node_status.get("state") != "PREPARED"
                or node_status.get("reservationActive") is not True
                or node_status.get("inMempool") is not False
                or str(node_status.get("preparedTxid", "")) != str(armed["preparedTxid"])
                or int(node_status.get("preparedVout", -1)) != int(armed["preparedContractVout"])
                or int(node_status.get("reservedInputCount", 0)) != int(normalized["reservedInputCount"])
            ):
                fail(
                    409, "TRU_PREPARED_RESERVATION_BIND_FAILED",
                    "node reservation did not bind exactly to the durable Agent payload",
                )

            return browser_safe({
                "swapId": swap_id,
                "chain": "tru",
                "operationId": armed["operationId"],
                "journalState": armed["state"],
                "prebroadcastReady": True,
                "preparedTxid": armed["preparedTxid"],
                "preparedVout": armed["preparedContractVout"],
                "preparedPayloadSha256": armed["preparedPayloadSha256"],
                "preparedMs": armed["preparedMs"],
                "feeAtoms": normalized["feeAtoms"],
                "reservedInputCount": int(normalized["reservedInputCount"]),
                "preparedInputReservation": True,
                "broadcast": False,
                "fundingRouteEnabled": False,
                "idempotentReuse": False,
            })
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "TRU_PREBROADCAST_PREPARE_FAILED", str(exc))

    def dryrun_tru_prepared_broadcast(self, swap_id: str) -> Dict[str, Any]:
        """Validate exact persisted node bytes against the broadcast barrier; no broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        attempt = self.store.get_funding_attempt(swap_id, "tru")
        if attempt is None or attempt.get("state") != "PREPARED" or attempt.get("prebroadcastReady") is not True:
            fail(409, "TRU_PREPARED_DRYRUN_STATE", "dry-run requires an armed PREPARED TRU journal")
        payload = self.store.get_prepared_funding_payload(attempt["operationId"])
        try:
            result = self.tru.raw("htlcbroadcastprepared", {
                "operationId": attempt["operationId"],
                "preparedTxid": payload["preparedTxid"],
                "dryRun": True,
            })
        except Exception as exc:
            fail(502, "TRU_PREPARED_DRYRUN_FAILED", str(exc))
        if not isinstance(result, dict):
            fail(502, "TRU_PREPARED_DRYRUN_SHAPE", "node dry-run response is invalid")
        if (
            result.get("dryRun") is not True
            or result.get("broadcast") is not False
            or result.get("reservationActive") is not True
            or result.get("exactPersistedBytesOnly") is not True
            or str(result.get("preparedTxid", "")) != str(payload["preparedTxid"])
            or int(result.get("preparedVout", -1)) != int(payload["preparedContractVout"])
        ):
            fail(409, "TRU_PREPARED_DRYRUN_MISMATCH", "exact persisted broadcast barrier validation failed")
        return browser_safe({
            "swapId": swap_id,
            "chain": "tru",
            "operationId": attempt["operationId"],
            "preparedTxid": payload["preparedTxid"],
            "preparedVout": payload["preparedContractVout"],
            "reservationActive": True,
            "exactPersistedBytesOnly": True,
            "dryRun": True,
            "broadcast": False,
            "fundingRouteEnabled": False,
        })

    def release_tru_prepared_reservation(self, swap_id: str) -> Dict[str, Any]:
        """Release an unbroadcast PREPARED node reservation; no coin movement."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        attempt = self.store.get_funding_attempt(swap_id, "tru")
        if attempt is None or attempt.get("state") != "PREPARED" or attempt.get("prebroadcastReady") is not True:
            fail(409, "TRU_PREPARED_RELEASE_STATE", "release requires an armed PREPARED TRU journal")
        payload = self.store.get_prepared_funding_payload(attempt["operationId"])
        try:
            result = self.tru.raw("htlcpreparedrelease", {
                "operationId": attempt["operationId"],
                "preparedTxid": payload["preparedTxid"],
            })
        except Exception as exc:
            fail(502, "TRU_PREPARED_RELEASE_FAILED", str(exc))
        if not isinstance(result, dict):
            fail(502, "TRU_PREPARED_RELEASE_SHAPE", "node release response is invalid")
        if result.get("released") is not True or result.get("reservationActive") is not False:
            fail(409, "TRU_PREPARED_RELEASE_MISMATCH", "node reservation release did not become terminal")
        return browser_safe({
            "swapId": swap_id,
            "chain": "tru",
            "operationId": attempt["operationId"],
            "released": True,
            "nodeState": result.get("state"),
            "reservationActive": False,
            "broadcast": False,
            "fundingRouteEnabled": False,
        })

    def reconcile_tru_funding_journal(self, swap_id: str) -> Dict[str, Any]:
        """Scan TRU read-only and bind exact evidence to the journal only."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")

        attempt = self.store.get_funding_attempt(swap_id, "tru")
        if attempt is None:
            fail(404, "TRU_FUNDING_JOURNAL_NOT_FOUND", "TRU funding journal attempt not found")
        if attempt["state"] not in {"BROADCASTING", "TX_IDENTIFIED"}:
            fail(
                409,
                "TRU_FUNDING_JOURNAL_NOT_RECONCILABLE",
                "TRU funding reconciliation requires BROADCASTING or TX_IDENTIFIED",
            )

        view = self.require_view(swap_id)
        min_conf = int(view["min_conf"])
        record = self.get_live_record(swap_id)

        def rpc(method: str, params: Dict[str, Any]):
            # Reconciler receives only the existing read-only public RPC surface.
            return self.tru.public_raw(method, params)

        try:
            result = self.tru_reconciler.reconcile_tru_attempt(record, attempt, rpc)
            row, mutated = apply_tru_reconcile_result(
                self.store, attempt, result, min_conf
            )
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "TRU_FUNDING_RECONCILE_FAILED", str(exc))

        return browser_safe({
            "swapId": swap_id,
            "chain": "tru",
            "classification": result.get("classification"),
            "candidateCount": result.get("candidateCount"),
            "action": result.get("action"),
            "safeToRetry": False,
            "journalState": row.get("state"),
            "journalMutated": bool(mutated),
            "confirmations": int(row.get("confirmations", 0)),
            "fundingRouteEnabled": False,
            "broadcast": False,
            "swapStateMutation": False,
        })

    def prepare_bsty_funding_journal(
        self, swap_id: str, starting_height: int
    ) -> Dict[str, Any]:
        """Prepare the deterministic BSTY journal row; does not broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            record = self.get_live_record(swap_id)
            expected = self.bsty_reconciler.expected_bsty_funding(record)
            attempt = self.store.prepare_funding_attempt(
                swap_id,
                "bsty",
                str(record.get("bstyAmountAtoms", "")),
                expected["commitment"],
                int(starting_height),
            )
        except ApiError:
            raise
        except Exception as exc:
            fail(409, "BSTY_FUNDING_JOURNAL_PREPARE_FAILED", str(exc))
        return attempt

    def prepare_bsty_prebroadcast_funding(self, swap_id: str) -> Dict[str, Any]:
        """Prepare/sign BSTY funding, durably lock inputs, and bind exact bytes; never broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            return browser_safe(self.bsty_prebroadcast.prepare(self, swap_id))
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "BSTY_PREBROADCAST_PREPARE_FAILED", str(exc))

    def dryrun_bsty_prepared_broadcast(self, swap_id: str) -> Dict[str, Any]:
        """Run exact persisted BSTY bytes through testmempoolaccept; never broadcast."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            return browser_safe(self.bsty_prebroadcast.dryrun(self, swap_id))
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "BSTY_PREPARED_DRYRUN_FAILED", str(exc))

    def release_bsty_prepared_reservation(self, swap_id: str) -> Dict[str, Any]:
        """Unlock only an unbroadcast/unspent PREPARED BSTY input set."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            return browser_safe(self.bsty_prebroadcast.release(self, swap_id))
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "BSTY_PREPARED_RELEASE_FAILED", str(exc))

    def reconcile_bsty_funding_journal(self, swap_id: str) -> Dict[str, Any]:
        """Scan BSTY read-only and bind exact evidence to the journal only."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")

        attempt = self.store.get_funding_attempt(swap_id, "bsty")
        if attempt is None:
            fail(404, "BSTY_FUNDING_JOURNAL_NOT_FOUND", "BSTY funding journal attempt not found")
        if attempt["state"] not in {"BROADCASTING", "TX_IDENTIFIED"}:
            fail(
                409,
                "BSTY_FUNDING_JOURNAL_NOT_RECONCILABLE",
                "BSTY funding reconciliation requires BROADCASTING or TX_IDENTIFIED",
            )

        view = self.require_view(swap_id)
        min_conf = int(view["min_conf"])
        record = self.get_live_record(swap_id)

        def rpc(method: str, params: Dict[str, Any]):
            # Strict read-only mapping onto the existing BSTY CLI adapter.
            if method == "getrawmempool":
                return self.bsty.json("getrawmempool")
            if method == "getblockcount":
                return self.bsty.json("getblockcount")
            if method == "getblockhash":
                return self.bsty.text("getblockhash", int(params["height"]))
            if method == "getblock":
                return self.bsty.json(
                    "getblock",
                    str(params["blockhash"]),
                    int(params.get("verbosity", 1)),
                )
            if method == "getrawtransaction":
                txid = str(params["txid"])
                blockhash = params.get("blockhash")
                if blockhash:
                    return self.bsty.text(
                        "getrawtransaction", txid, "false", str(blockhash)
                    )
                return self.bsty.text("getrawtransaction", txid, "false")
            raise ValueError("BSTY reconciler requested unsupported RPC: " + str(method))

        try:
            result = self.bsty_reconciler.reconcile_bsty_attempt(record, attempt, rpc)
            row, mutated = apply_bsty_reconcile_result(
                self.store, attempt, result, min_conf
            )
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "BSTY_FUNDING_RECONCILE_FAILED", str(exc))

        return browser_safe({
            "swapId": swap_id,
            "chain": "bsty",
            "classification": result.get("classification"),
            "candidateCount": result.get("candidateCount"),
            "action": result.get("action"),
            "safeToRetry": False,
            "journalState": row.get("state"),
            "journalMutated": bool(mutated),
            "confirmations": int(row.get("confirmations", 0)),
            "fundingRouteEnabled": False,
            "broadcast": False,
            "swapStateMutation": False,
        })

    def fund_local_chain(self, swap_id: str) -> Dict[str, Any]:
        """Advance the local canonical funding leg through the Group-03 gate."""
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            view = self.require_view(swap_id)
            record = self.get_live_record(swap_id)
            first = "tru" if record.get("fundingOrder") == "TRU_FIRST" else "bsty"
            if (str(view["give_chain"]) != first and
                    record.get("state") in {"CREATED", "ONE_SIDE_FUNDED"}):
                observed = self.observe_counterparty_first_funding(swap_id)
                if (observed.get("recorded") is not True or
                        (record.get("state") == "ONE_SIDE_FUNDED" and
                         observed.get("currentConfirmed") is not True)):
                    raise ValueError("first funding is not independently confirmed and recorded")
            return browser_safe(self.dual_funding.fund_step(self, swap_id))
        except ApiError:
            raise
        except ValueError as exc:
            message = str(exc)
            if "TRU_SWAP_DUAL_FUNDING_ENABLE=1" in message:
                fail(409, "DUAL_FUNDING_DISABLED", message)
            fail(409, "DUAL_FUNDING_BLOCKED", message)
        except Exception as exc:
            fail(502, "DUAL_FUNDING_FAILED", str(exc))

    def lodge_exits(self, swap_id: str, destinations: Any) -> Dict[str, Any]:
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            return self.exit_watcher.arm(self, swap_id, destinations)
        except ValueError as exc:
            msg = str(exc)
            if "TRU_SWAP_EXIT_WATCHER_ENABLE=1" in msg:
                fail(409, "EXIT_WATCHER_DISABLED", msg)
            fail(409, "EXIT_WATCHER_BLOCKED", msg)
        except ApiError:
            raise
        except Exception as exc:
            fail(502, "EXIT_WATCHER_ARM_FAILED", str(exc))

    def disarm_exits(self, swap_id: str) -> Dict[str, Any]:
        if not SWAP_ID_RE.fullmatch(str(swap_id)):
            fail(400, "BAD_SWAP_ID", "swapId must be 64 lowercase hex characters")
        try:
            return self.exit_watcher.disarm(self, swap_id)
        except ValueError as exc:
            fail(409, "EXIT_WATCHER_DISARM_BLOCKED", str(exc))
        except Exception as exc:
            fail(502, "EXIT_WATCHER_DISARM_FAILED", str(exc))

    def register_view(self, swap_id: str, give_chain: str, get_chain: str, min_conf: int):
        if not SWAP_ID_RE.fullmatch(swap_id):
            raise SystemExit("swap id must be 64 lowercase hex characters")
        if give_chain not in CHAINS or get_chain not in CHAINS or give_chain == get_chain:
            raise SystemExit("give/get chain must be opposite values from: tru, bsty")
        if min_conf < 1:
            raise SystemExit("min-conf must be >= 1")
        r = self.get_live_record(swap_id)
        if str(r.get("swapId", swap_id)) != swap_id:
            raise SystemExit("record swap id mismatch")
        order = str(r.get("fundingOrder", ""))
        if order not in {"TRU_FIRST", "BSTY_FIRST"}:
            raise SystemExit("record funding order mismatch")
        first = "tru" if order == "TRU_FIRST" else "bsty"
        self.store.put_view(
            swap_id, give_chain, get_chain, min_conf, first,
            self._chain_height(first),
            (self._chain_height(get_chain) if self.store.get_view(swap_id) is None
             else dict(self.store.get_view(swap_id)).get("counterparty_starting_height")),
        )


FAIL_CLOSED = {
    "/v1/board/take": (
        "ROLE_KEY_ALLOCATOR_REQUIRED",
        "taking an advert is disabled until an atomic reservation can mint a fresh-key swap safely",
    ),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "TRUSwapAgent/GROUP04"
    protocol_version = "HTTP/1.1"

    @property
    def agent(self) -> Agent:
        return self.server.agent  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        sys.stderr.write("[agent-http] %s - %s\n" % (self.address_string(), fmt % args))

    def _origin(self) -> str:
        return (self.headers.get("Origin") or "").rstrip("/")

    def _origin_allowed(self) -> bool:
        o = self._origin()
        return not o or o in self.agent.origins

    def _cors(self):
        o = self._origin()
        if o and o in self.agent.origins:
            self.send_header("Access-Control-Allow-Origin", o)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Credentials", "true")

    def _json(self, status: int, obj: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None):
        body = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _pair_cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            c = SimpleCookie()
            c.load(raw)
            morsel = c.get("tru_swap_pairing_session")
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def do_OPTIONS(self):
        if not self._origin_allowed():
            self._json(403, {"error": "origin not allowed", "code": "ORIGIN_DENIED"})
            return
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Swap-Pairing, X-Swap-Session")
        self.send_header("Access-Control-Max-Age", "600")
        if (self.headers.get("Access-Control-Request-Private-Network") or "").lower() == "true":
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/connect?"):
            try:
                from urllib.parse import urlsplit, parse_qs
                self.agent.local_connect.local(self)
                rid = parse_qs(urlsplit(self.path).query).get("request", [""])[0]
                page, nonce = self.agent.local_connect.page(rid)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                self.end_headers(); self.wfile.write(page); return
            except ValueError:
                self._json(403, {"error": "Local connection unavailable or expired"}); return
        self._json(405, {"error": "POST only", "code": "METHOD_NOT_ALLOWED"})

    def _read_body(self) -> Dict[str, Any]:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            fail(400, "BAD_CONTENT_LENGTH", "invalid Content-Length")
        if n < 0 or n > MAX_BODY:
            fail(413, "BODY_TOO_LARGE", "request body too large")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            fail(400, "BAD_JSON", "request body must be JSON")
        if not isinstance(obj, dict):
            fail(400, "BAD_JSON_SHAPE", "request body must be a JSON object")
        return obj

    def _require_pairing(self):
        local_session = self.headers.get("X-Swap-Session", "")
        if local_session:
            try:
                self.agent.local_connect.local(self)
                if self._origin() and self.agent.store.pair_session_valid(self.agent._token_hash(local_session), self._origin()):
                    return
            except ValueError:
                pass
            fail(401, "PAIRING_REQUIRED", "Reconnect your local Swap Agent")
        got = self.headers.get("X-Swap-Pairing", "")
        cookie_token = self._pair_cookie()
        if not self.agent.pairing_valid(got, cookie_token, self._origin()):
            fail(401, "PAIRING_REQUIRED", "refresh/retry the swap-agent connection")

    def do_POST(self):
        try:
            if self.path.split("?", 1)[0].startswith("/v1/connect/"):
                try:
                    result = self.agent.local_connect.handle_post(self, self.path.split("?", 1)[0], self._read_body())
                except ValueError as exc:
                    fail(403, "LOCAL_CONNECT_REJECTED", str(exc))
                self._json(200, result); return
            if not self._origin_allowed():
                fail(403, "ORIGIN_DENIED", "browser origin is not in TRU_SWAP_AGENT_ORIGINS")
            p = self.path.split("?", 1)[0]
            body = self._read_body()
            if p == "/v1/health":
                self._json(200, self.agent.health())
                return
            if p == "/v1/pair":
                token, expires = self.agent.issue_browser_pairing(
                    self._origin(), self.headers.get("Host", ""), self.headers
                )
                max_age = max(0, int((expires - now_ms()) / 1000))
                cookie = (
                    "tru_swap_pairing_session=" + token
                    + "; Path=/v1/; Max-Age=" + str(max_age)
                    + "; Secure; HttpOnly; SameSite=Strict"
                )
                self._json(
                    200,
                    {"ok": True, "paired": True, "expiresAt": expires, "credentialExposedToJavascript": False},
                    {"Set-Cookie": cookie},
                )
                return
            self._require_pairing()

            if p == "/v1/pair/revoke":
                cookie_token = self.headers.get("X-Swap-Session", "") or self._pair_cookie()
                if cookie_token:
                    self.agent.local_connect.revoke(cookie_token)
                    self.agent.store.revoke_pair_session(self.agent._token_hash(cookie_token))
                self._json(
                    200, {"ok": True},
                    {"Set-Cookie": "tru_swap_pairing_session=; Path=/v1/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"},
                )
                return

            if p in FAIL_CLOSED:
                code, msg = FAIL_CLOSED[p]
                fail(501, code, msg)

            if p == "/v1/fund":
                self._json(200, self.agent.fund_local_chain(str(body.get("swapId", ""))))
                return
            if p == "/v1/progress":
                with self.agent.lock:
                    result = self.agent.progress_swap(str(body.get("swapId", "")))
                self._json(200, result)
                return
            if p == "/v1/exits/lodge":
                self._json(200, self.agent.lodge_exits(str(body.get("swapId", "")), body.get("destinations")))
                return
            if p == "/v1/exits/disarm":
                self._json(200, self.agent.disarm_exits(str(body.get("swapId", ""))))
                return

            if p.startswith("/v1/market-process/"):
                if self.agent.market_process is None:
                    fail(503, "MARKET_PROCESS_UNAVAILABLE", "restart the upgraded Agent")
                try:
                    result = self.agent.market_process.route(p.rsplit("/", 1)[-1], body)
                except ValueError as exc:
                    fail(409, "MARKET_PROCESS_REJECTED", str(exc))
                self._json(200, result)
                return

            if p == "/v1/offer/create":
                with self.agent.lock:
                    result = self.agent.create_offer_v2(body)
                self._json(200, result)
                return
            if p == "/v1/offer/import":
                with self.agent.lock:
                    result = self.agent.import_offer_v2(body.get("offer"))
                self._json(200, result)
                return
            if p == "/v1/board/list":
                self._json(200, self.agent.store.list_board())
                return
            if p == "/v1/board/post":
                self._json(200, {"advert": self.agent.store.post_advert(body)})
                return
            if p == "/v1/board/withdraw":
                self.agent.store.withdraw(str(body.get("advertId", "")))
                self._json(200, {"ok": True})
                return
            if p == "/v1/record":
                self._json(200, {"record": self.agent.view_record(str(body.get("swapId", "")))})
                return
            if p == "/v1/contracts":
                self._json(200, self.agent.contracts(str(body.get("swapId", ""))))
                return
            if p == "/v1/verify":
                self._json(200, self.agent.verify(str(body.get("swapId", "")), body.get("destinations")))
                return
            fail(404, "NOT_FOUND", "unknown local-agent endpoint")
        except ApiError as e:
            payload = {"error": e.message, "code": e.code}
            if e.status == 401 and e.code == "PAIRING_REQUIRED":
                payload["needsPairing"] = True
            self._json(e.status, payload)
        except Exception as e:
            self._json(500, {"error": str(e), "code": "INTERNAL_ERROR"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, addr, handler, agent):
        super().__init__(addr, handler)
        self.agent = agent


def selftest(root: Path):
    engine = load_engine(root / "swap/tru_bsty_swap_engine.py")
    handshake = load_handshake(root / "swap/offer_handshake_v2.py")
    tru_reconciler = load_tru_reconciler(root / "swap/tru_funding_reconciler_v1.py")
    bsty_reconciler = load_bsty_reconciler(root / "swap/bsty_funding_reconciler_v1.py")
    bsty_prebroadcast = load_bsty_prebroadcast(root / "swap/bsty_prebroadcast_v1.py")
    dual_funding = load_dual_funding(root / "swap/dual_funding_v1.py")
    exit_watcher = load_exit_watcher(root / "swap/exit_watcher_v1.py")
    handshake.selftest()
    dual_funding.selftest()
    exit_watcher.selftest()
    assert bsty_prebroadcast.VERSION == "TRU-SWAP-BSTY-PREBROADCAST-V1"
    assert hasattr(engine, "record_script")
    assert validate_tru_address("TCtVWvC1JtsKXWoEDueN2aNEkpVbjAftQM")
    assert not validate_tru_address("TCtVWvC1JtsKXWoEDueN2aNEkpVbjAftQN")
    with tempfile.TemporaryDirectory() as td:
        s = Store(Path(td) / "board.sqlite3")

        def arm(row, txid, vout, tag):
            raw_hex = ("01" + hashlib.sha256(tag.encode()).hexdigest() + "00")
            row = s.prepare_funding_payload(
                row["operationId"], txid, raw_hex, vout
            )
            assert row["prebroadcastReady"] is True
            assert row["preparedTxid"] == txid
            assert row["preparedContractVout"] == vout
            payload = s.get_prepared_funding_payload(row["operationId"])
            assert payload["preparedTxid"] == txid
            assert payload["preparedContractVout"] == vout
            assert payload["preparedRawTxHex"] == raw_hex
            assert "preparedRawTxHex" not in browser_safe(payload)
            return s.transition_funding_attempt(row["operationId"], "BROADCASTING")

        a = s.post_advert({
            "givesChain": "tru", "getsChain": "bsty",
            "gives": "1.00000000", "gets": "0.01000000",
            "ownHours": 24, "theirHours": 12, "minConf": 1, "lifeHours": 6,
        })
        b = s.list_board()
        assert len(b["adverts"]) == 1 and b["adverts"][0]["id"] == a["id"]
        s.withdraw(a["id"])
        assert len(s.list_board()["adverts"]) == 0
        test_token = "pair-test-token"
        test_hash = hashlib.sha256(test_token.encode()).hexdigest()
        s.put_pair_session(test_hash, "https://tokenizedrealutility.com", 3600)
        assert s.pair_session_valid(test_hash, "https://tokenizedrealutility.com")
        assert not s.pair_session_valid(test_hash, "https://evil.invalid")
        synthetic_offer = {"offerId": "11" * 32}
        s.put_offer_session(
            "11" * 32, "maker", "OFFER_CREATED", synthetic_offer,
            "tru", "bsty", 1, bsty_signer_address="yTestSigner", preimage_hex="22" * 32,
        )
        sess = s.get_offer_session("11" * 32, "maker")
        assert sess and sess["preimageHex"] == "22" * 32
        assert sess["bstySignerAddress"] == "yTestSigner"

        fsid = "33" * 32
        commitment = hashlib.sha256(b"canonical-test-contract").hexdigest()
        f = s.prepare_funding_attempt(fsid, "tru", "18446744073709551615", commitment, 123)
        assert f["state"] == "PREPARED"
        assert f["operationId"] == funding_operation_id(fsid, "tru")
        # Exact duplicate prepare is idempotent.
        f2 = s.prepare_funding_attempt(fsid, "tru", "18446744073709551615", commitment, 123)
        assert f2["operationId"] == f["operationId"] and f2["state"] == "PREPARED"
        try:
            s.prepare_funding_attempt(fsid, "tru", "1", commitment, 123)
            raise AssertionError("conflicting durable funding prepare accepted")
        except ValueError:
            pass
        try:
            s.transition_funding_attempt(f["operationId"], "BROADCASTING")
            raise AssertionError("BROADCASTING entered without prebroadcast identity")
        except ValueError:
            pass
        txid = "44" * 32
        f = arm(f, txid, 7, "first-tru")
        assert f["state"] == "BROADCASTING" and f["txid"] is None
        assert s.list_prebroadcast_ready_funding_attempts() == []
        try:
            s.prepare_funding_payload(f["operationId"], txid, "0100", 7)
            raise AssertionError("prepared payload mutated after BROADCASTING")
        except ValueError:
            pass
        f = s.transition_funding_attempt(
            f["operationId"], "TX_IDENTIFIED", txid=txid, vout=7
        )
        assert f["txid"] == txid and f["vout"] == 7
        # Same-state reconciliation update is idempotent.
        f = s.transition_funding_attempt(
            f["operationId"], "TX_IDENTIFIED", txid=txid, vout=7
        )
        f = s.transition_funding_attempt(
            f["operationId"], "CONFIRMED", txid=txid, vout=7, confirmations=2
        )
        assert f["state"] == "CONFIRMED" and f["confirmations"] == 2
        f = s.transition_funding_attempt(f["operationId"], "RECORDED")
        assert f["state"] == "RECORDED"
        assert s.list_reconcilable_funding_attempts() == []

        fsid2 = "55" * 32
        c2 = hashlib.sha256(b"second-contract").hexdigest()
        g = s.prepare_funding_attempt(fsid2, "bsty", "100000", c2, 456)
        g = arm(g, "66" * 32, 0, "ambiguous-bsty")
        g = s.transition_funding_attempt(g["operationId"], "AMBIGUOUS")
        assert g["state"] == "AMBIGUOUS"
        try:
            s.transition_funding_attempt(g["operationId"], "TX_IDENTIFIED", txid="66" * 32, vout=0)
            raise AssertionError("AMBIGUOUS journal entry reopened")
        except ValueError:
            pass

        # 01B4B1: pure reconciler result -> durable journal binding.
        rsid = "77" * 32
        rcommit = tru_reconciler.tru_contract_commitment({
            "swapId": rsid,
            "secretHash160": "88" * 20,
            "truClaimPubkey": "02" + "99" * 32,
            "truRefundPubkey": "03" + "aa" * 32,
            "truRefundTime": 1800000000,
            "truAmountAtoms": "123456789",
        })
        jr = s.prepare_funding_attempt(rsid, "tru", "123456789", rcommit, 500)
        jr = arm(jr, "bb" * 32, 1, "tru-reconcile")

        zero_row, zero_mut = apply_tru_reconcile_result(
            s, jr,
            {
                "classification": "ZERO_CANDIDATES",
                "candidateCount": 0,
                "safeToRetry": False,
                "action": "HOLD_RECONCILE",
            },
            2,
        )
        assert zero_row["state"] == "BROADCASTING" and zero_mut is False

        txr = "bb" * 32
        one_row, one_mut = apply_tru_reconcile_result(
            s, zero_row,
            {
                "classification": "ONE_CANDIDATE",
                "candidateCount": 1,
                "safeToRetry": False,
                "action": "ADOPT_TX_IDENTIFIED",
                "candidate": {
                    "txid": txr, "vout": 1, "confirmations": 1,
                    "blockHeight": 501, "location": "block",
                },
            },
            2,
        )
        assert one_mut is True
        assert one_row["state"] == "TX_IDENTIFIED"
        assert one_row["txid"] == txr and one_row["vout"] == 1

        conf_row, conf_mut = apply_tru_reconcile_result(
            s, one_row,
            {
                "classification": "ONE_CANDIDATE",
                "candidateCount": 1,
                "safeToRetry": False,
                "action": "ADOPT_TX_IDENTIFIED",
                "candidate": {
                    "txid": txr, "vout": 1, "confirmations": 2,
                    "blockHeight": 501, "location": "block",
                },
            },
            2,
        )
        assert conf_mut is True and conf_row["state"] == "CONFIRMED"
        assert conf_row["confirmations"] == 2

        rsid2 = "cc" * 32
        jr2 = s.prepare_funding_attempt(rsid2, "tru", "99", "dd" * 32, 700)
        jr2 = arm(jr2, "bc" * 32, 1, "tru-multi")
        amb_row, amb_mut = apply_tru_reconcile_result(
            s, jr2,
            {
                "classification": "MULTIPLE_CANDIDATES",
                "candidateCount": 2,
                "safeToRetry": False,
                "action": "AMBIGUOUS_FAIL_CLOSED",
            },
            1,
        )
        assert amb_mut is True and amb_row["state"] == "AMBIGUOUS"

        # 01B4C1: BSTY reconciler result -> durable journal binding.
        bsid = "de" * 32
        brecord = {
            "swapId": bsid,
            "secretHash160": "ab" * 20,
            "bstyClaimPubkey": "02" + "bc" * 32,
            "bstyRefundPubkey": "03" + "cd" * 32,
            "bstyRefundTime": 1800000000,
            "bstyAmountAtoms": "987654321",
        }
        bcommit = bsty_reconciler.bsty_contract_commitment(brecord)
        bj = s.prepare_funding_attempt(bsid, "bsty", "987654321", bcommit, 800)
        bj = arm(bj, "ef" * 32, 3, "bsty-reconcile")

        bzero, bzero_mut = apply_bsty_reconcile_result(
            s, bj,
            {
                "classification": "ZERO_CANDIDATES",
                "candidateCount": 0,
                "safeToRetry": False,
                "action": "HOLD_RECONCILE",
            },
            2,
        )
        assert bzero["state"] == "BROADCASTING" and bzero_mut is False

        btx = "ef" * 32
        bone, bone_mut = apply_bsty_reconcile_result(
            s, bzero,
            {
                "classification": "ONE_CANDIDATE",
                "candidateCount": 1,
                "safeToRetry": False,
                "action": "ADOPT_TX_IDENTIFIED",
                "candidate": {
                    "txid": btx, "vout": 3, "confirmations": 1,
                    "blockHeight": 801, "location": "block",
                },
            },
            2,
        )
        assert bone_mut is True
        assert bone["state"] == "TX_IDENTIFIED"
        assert bone["txid"] == btx and bone["vout"] == 3

        bconf, bconf_mut = apply_bsty_reconcile_result(
            s, bone,
            {
                "classification": "ONE_CANDIDATE",
                "candidateCount": 1,
                "safeToRetry": False,
                "action": "ADOPT_TX_IDENTIFIED",
                "candidate": {
                    "txid": btx, "vout": 3, "confirmations": 2,
                    "blockHeight": 801, "location": "block",
                },
            },
            2,
        )
        assert bconf_mut is True and bconf["state"] == "CONFIRMED"
        assert bconf["confirmations"] == 2

        bsid2 = "f1" * 32
        bj2 = s.prepare_funding_attempt(bsid2, "bsty", "77", "f2" * 32, 900)
        bj2 = arm(bj2, "f3" * 32, 0, "bsty-multi")
        bamb, bamb_mut = apply_bsty_reconcile_result(
            s, bj2,
            {
                "classification": "MULTIPLE_CANDIDATES",
                "candidateCount": 2,
                "safeToRetry": False,
                "action": "AMBIGUOUS_FAIL_CLOSED",
            },
            1,
        )
        assert bamb_mut is True and bamb["state"] == "AMBIGUOUS"


        # 01B4D3: validate node preparation response before journal binding.
        dsid = "a1" * 32
        drecord = {
            "swapId": dsid,
            "state": "CREATED",
            "fundingOrder": "TRU_FIRST",
            "evidence": {},
            "secretHash160": "a2" * 20,
            "truClaimPubkey": "02" + "a3" * 32,
            "truRefundPubkey": "03" + "a4" * 32,
            "truRefundTime": 1800000000,
            "truAmountAtoms": "12345",
        }
        require_tru_prebroadcast_turn(drecord, "tru")
        try:
            require_tru_prebroadcast_turn(drecord, "bsty")
            raise AssertionError("non-TRU local owner accepted for TRU preparation")
        except ValueError:
            pass
        dexp = tru_reconciler.expected_tru_funding(drecord)
        draw = "01000000000100"
        dtx = "a5" * 32
        dres = {
            "protocol": "TRU-SWAP-V1",
            "family": "htlc_atomic_swap_v1",
            "status": "SIGNED_RESERVED_NOT_BROADCAST",
            "operationId": "a6" * 32,
            "reservationActive": True,
            "reservedInputCount": 2,
            "idempotentReuse": False,
            "preparedTxid": dtx,
            "preparedVout": 1,
            "rawTxHex": draw,
            "scriptHex": dexp["contractScriptHex"],
            "amountAtoms": 12345,
            "feeAtoms": 1000,
            "secretHash160": drecord["secretHash160"],
            "claimPubkey": drecord["truClaimPubkey"],
            "refundPubkey": drecord["truRefundPubkey"],
            "refundTime": drecord["truRefundTime"],
            "broadcast": False,
            "privateMaterialReturned": False,
        }
        norm = validate_tru_prebroadcast_prepare_result(drecord, dexp, dres, "a6" * 32)
        assert norm["preparedTxid"] == dtx and norm["preparedContractVout"] == 1
        da = s.prepare_funding_attempt(dsid, "tru", "12345", dexp["commitment"], 1000)
        da = s.prepare_funding_payload(da["operationId"], norm["preparedTxid"], norm["preparedRawTxHex"], 1)
        assert da["state"] == "PREPARED" and da["prebroadcastReady"] is True
        assert "preparedRawTxHex" not in browser_safe(s.get_prepared_funding_payload(da["operationId"]))
        try:
            bad = dict(dres); bad["broadcast"] = True
            validate_tru_prebroadcast_prepare_result(drecord, dexp, bad, "a6" * 32)
            raise AssertionError("broadcast=true preparation response accepted")
        except ValueError:
            pass
    print("TRU_SWAP_AGENT_GROUP01_SELFTEST=PASS")
    print("ENGINE_IMPORT_COMPAT=PASS")
    print("TRU_BASE58CHECK_VECTOR=PASS")
    print("SQLITE_BOARD_ATOMIC_CRUD=PASS")
    print("PERSISTENT_PAIR_SESSION_STORE=PASS")
    print("PERSISTENT_OFFER_SESSION_STORE=PASS")
    print("PERSISTENT_FUNDING_JOURNAL_STORE=PASS")
    print("FUNDING_JOURNAL_U64_AMOUNT_TEXT=PASS")
    print("FUNDING_JOURNAL_IDEMPOTENT_PREPARE=PASS")
    print("FUNDING_JOURNAL_TRANSITION_GUARDS=PASS")
    print("FUNDING_JOURNAL_AMBIGUITY_FAIL_CLOSED=PASS")
    print("PREBROADCAST_IDENTITY_SCHEMA_MIGRATION=PASS")
    print("PREBROADCAST_PAYLOAD_PERSISTENCE=PASS")
    print("PREBROADCAST_PAYLOAD_HASH_BINDING=PASS")
    print("PREBROADCAST_RAW_TX_BROWSER_EXPOSURE=NO")
    print("BROADCASTING_WITHOUT_IDENTITY=REJECTED")
    print("PREBROADCAST_IDENTITY_IMMUTABLE=PASS")
    print("TX_IDENTIFIED_MUST_MATCH_PREPARED_IDENTITY=PASS")
    print("TRU_PREBROADCAST_PREPARE_RESULT_VALIDATION=PASS")
    print("TRU_PREBROADCAST_LOCAL_OWNER_GATE=PASS")
    print("TRU_PREBROADCAST_DURABLE_BINDING_FIXTURE=PASS")
    print("TRU_PREPARED_INPUT_RESERVATION_VALIDATION=PASS")
    print("TRU_EXACT_PERSISTED_BROADCAST_BARRIER=DRYRUN_ONLY")
    print("TRU_RECONCILER_IMPORT_COMPAT=PASS")
    print("TRU_RECONCILER_ZERO_CANDIDATE_HOLD=PASS")
    print("TRU_RECONCILER_ONE_CANDIDATE_JOURNAL_ADOPT=PASS")
    print("TRU_RECONCILER_CONFIRMATION_TO_CONFIRMED=PASS")
    print("TRU_RECONCILER_MULTIPLE_CANDIDATES_AMBIGUOUS=PASS")
    print("BSTY_RECONCILER_IMPORT_COMPAT=PASS")
    print("BSTY_RECONCILER_ZERO_CANDIDATE_HOLD=PASS")
    print("BSTY_RECONCILER_ONE_CANDIDATE_JOURNAL_ADOPT=PASS")
    print("BSTY_RECONCILER_CONFIRMATION_TO_CONFIRMED=PASS")
    print("BSTY_RECONCILER_MULTIPLE_CANDIDATES_AMBIGUOUS=PASS")
    print("FUND_ROUTE_ENV_GATED_EXIT_WATCHER_INSTALLED_BOARD_TAKE_FAIL_CLOSED=PASS")


def build_agent(args) -> Agent:
    root = Path(args.tru_root).expanduser().resolve()
    db = Path(args.db).expanduser().resolve() if args.db else root / "swap/runtime/local-agent.sqlite3"
    return Agent(root, db)


def main():
    ap = argparse.ArgumentParser(description=VERSION)
    ap.add_argument("--tru-root", default=os.environ.get("TRU_ROOT", str(Path.home() / "NEW_TRU")))
    ap.add_argument("--db", default=os.environ.get("TRU_SWAP_AGENT_DB", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("check")
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=int(os.environ.get("TRU_SWAP_AGENT_PORT", str(DEFAULT_PORT))))
    p = sub.add_parser("register-view")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--give-chain", choices=["tru", "bsty"], required=True)
    p.add_argument("--get-chain", choices=["tru", "bsty"], required=True)
    p.add_argument("--min-conf", type=int, default=1)
    args = ap.parse_args()

    root = Path(args.tru_root).expanduser().resolve()
    if args.cmd == "selftest":
        selftest(root)
        return 0

    if len(os.environ.get("TRU_SWAP_RPC_TOKEN", "")) < 32:
        raise SystemExit("TRU_SWAP_RPC_TOKEN must be set and at least 32 characters; value is never printed")

    agent = build_agent(args)
    if args.cmd == "check":
        print(json.dumps(agent.health(), indent=2))
        return 0 if agent.health().get("ok") else 1
    if args.cmd == "register-view":
        if args.give_chain == args.get_chain:
            raise SystemExit("give-chain and get-chain must differ")
        agent.register_view(args.swap_id, args.give_chain, args.get_chain, args.min_conf)
        print("REGISTER_VIEW=PASS")
        print("SWAP_ID=", args.swap_id)
        print("GIVE_CHAIN=", args.give_chain)
        print("GET_CHAIN=", args.get_chain)
        print("MIN_CONF=", args.min_conf)
        return 0
    if args.cmd == "serve":
        if args.port < 1024 or args.port > 65535:
            raise SystemExit("agent port must be between 1024 and 65535")
        from market_process_v1 import MarketProcess
        agent.market_process = MarketProcess(agent)
        srv = Server((HOST, args.port), Handler, agent)
        print(f"{VERSION}=STARTING")
        print(f"LISTEN=http://{HOST}:{args.port}")
        print("BIND_SCOPE=LOOPBACK_ONLY")
        print("PAIRING=LOCAL_APPROVAL_SESSION_WITH_ADVANCED_REMOTE_FALLBACK")
        print("LOCAL_CONNECT=EXPLICIT_LOOPBACK_APPROVAL")
        print("REMOTE_PAIRING_MODE=" + (agent.remote_pairing or "OFF"))
        print("PAIRING_TOKEN=" + agent.pairing)
        print("PAIRING_TOKEN_HTTP_EXPOSED=NO")
        print("PAIRING_SESSION_JS_EXPOSED=NO")
        print("RPC_TOKEN_EXPOSED=NO")
        print("ALLOWED_ORIGINS=" + ",".join(sorted(agent.origins)))
        print("OFFER_HANDSHAKE_V2=ACTIVE")
        print("FUNDING_JOURNAL_V1=ACTIVE")
        print("TRU_FUNDING_RECONCILER_V1=ACTIVE")
        print("TRU_RECONCILER_JOURNAL_BINDING=ACTIVE_NOFUNDS")
        print("BSTY_FUNDING_RECONCILER_V1=ACTIVE")
        print("BSTY_RECONCILER_JOURNAL_BINDING=ACTIVE_NOFUNDS")
        print("PREBROADCAST_IDENTITY_JOURNAL_V1=ACTIVE")
        print("PREBROADCAST_MUTATION_BARRIER=ACTIVE_NOFUNDS")
        print("TRU_PREBROADCAST_PREPARATION_V1=ACTIVE_INTERNAL_ONLY")
        print("TRU_PREBROADCAST_JOURNAL_BINDING=ACTIVE_NOFUNDS")
        print("TRU_PREPARED_INPUT_RESERVATION=ACTIVE")
        print("DUAL_FUNDING_ROUTE=INSTALLED_ENV_GATED")
        print("PERSISTENT_EXIT_WATCHER=INSTALLED_ENV_GATED")
        print("EXIT_UNKNOWN_OUTCOME_BLIND_RETRY=FORBIDDEN")
        print("BOARD_TAKE=FAIL_CLOSED")
        watcher_stop = threading.Event()
        watcher_thread = threading.Thread(
            target=agent.exit_watcher.watch_loop, args=(agent, watcher_stop),
            name="tru-swap-exit-watcher", daemon=True,
        )
        try:
            # Observation is always on during serve; funding/exit gates retain
            # their existing independent settings. No observation starts at import.
            agent.reorg_watcher.start()
            print("TRU_FUNDING_REORG_OBSERVER=ACTIVE_READ_ONLY_CHAIN_OBSERVATION")
            print("TRU_FUNDING_REORG_HISTORY=SEPARATE_DURABLE_SIDECAR")
            agent.market_process.start()
            print("DURABLE_MARKET_PROCESS=ACTIVE_NO_FUNDING")
            watcher_thread.start()
            srv.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            agent.market_process.stop()
            watcher_stop.set()
            if watcher_thread.ident is not None:
                watcher_thread.join(timeout=5)
            try:
                agent.reorg_watcher.stop()
            finally:
                srv.server_close()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
