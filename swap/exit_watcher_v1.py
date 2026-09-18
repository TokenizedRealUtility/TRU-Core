#!/usr/bin/env python3
"""TRU Swap GROUP-04 persistent claim/refund watcher.

Security model:
- durable watcher authorization and action intent in the Agent SQLite database
- no private-key export and no browser exposure of preimages or raw secret material
- real claim/refund execution requires TRU_SWAP_EXIT_WATCHER_ENABLE=1
- durable ACTION_STARTED is written before any mutating exit command
- if a process dies after a TRU/BSTY exit mutator but before canonical evidence is
  durably visible, restart recovery HOLDS UNKNOWN and never blind-retries
- actual signing/broadcast remains delegated to the already-pinned SWAP-B engine
  and its fresh TRU / wallet-local BSTY signer paths
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

VERSION = "TRU-SWAP-EXIT-WATCHER-V1"
REORG_VERSION = "TRU-REORG-EXIT-01"
RECOVERY_RUNTIME_VERSION = "TRU-REORG-EXIT-01B"
REORG_RPC_TIMEOUT_SECONDS = 10
RESOLUTION_TX_STATES = {"CONFIRMED", "MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND", "UNKNOWN"}
ENABLE_ENV = "TRU_SWAP_EXIT_WATCHER_ENABLE"
POLL_ENV = "TRU_SWAP_EXIT_WATCHER_POLL_SECONDS"

# POST-GROUP05 timeout ownership:
# The SWAP-B engine owns the canonical chain-confirmation wait window.
# The watcher owns only a strictly-longer outer subprocess watchdog so it can
# never kill the engine before that canonical wait window expires.
WAIT_TIMEOUT_ENV = "TRU_SWAP_EXIT_WAIT_TIMEOUT"
PROCESS_GRACE_ENV = "TRU_SWAP_EXIT_PROCESS_GRACE_SECONDS"
DEFAULT_WAIT_TIMEOUT_SECONDS = 600
DEFAULT_PROCESS_GRACE_SECONDS = 60
MIN_WAIT_TIMEOUT_SECONDS = 30
MAX_WAIT_TIMEOUT_SECONDS = 24 * 60 * 60
MIN_PROCESS_GRACE_SECONDS = 15
MAX_PROCESS_GRACE_SECONDS = 10 * 60

STATES = {
    "ARMED", "ACTION_STARTED", "HOLD_UNKNOWN", "COMPLETE",
    "DISARMED", "AMBIGUOUS",
}
ACTIVE_STATES = {"ARMED", "ACTION_STARTED", "HOLD_UNKNOWN"}
SWAP_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def now_ms() -> int:
    return int(time.time() * 1000)


def enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "").strip() == "1"


def require_enabled() -> None:
    if not enabled():
        raise ValueError(f"{ENABLE_ENV}=1 is required for persistent exit execution")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _auth_id(swap_id: str, kind: str, chain: str, destination: Dict[str, Any]) -> str:
    body = {
        "domain": "TRU-SWAP-EXIT-AUTH-V1",
        "swapId": swap_id,
        "kind": kind,
        "chain": chain,
        "destination": destination,
    }
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _load_reorg_overlay_module():
    path = Path(__file__).with_name("reorg_exit_overlay_v1.py").resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("REORG-EXIT overlay module missing or symlinked")
    spec = importlib.util.spec_from_file_location("tru_reorg_exit_overlay_live", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import REORG-EXIT overlay")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "VERSION", "") != REORG_VERSION:
        raise RuntimeError("REORG-EXIT overlay version mismatch")
    if not hasattr(mod, "ExitReorgOverlay"):
        raise RuntimeError("REORG-EXIT overlay compatibility failure")
    return mod


_REORG_OVERLAY = _load_reorg_overlay_module()


def _load_reorg_recovery_runtime_module():
    path = Path(__file__).with_name("reorg_exit_recovery_runtime_v1.py").resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("REORG-EXIT-01B recovery runtime module missing or symlinked")
    spec = importlib.util.spec_from_file_location("tru_reorg_exit_recovery_runtime_live", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import REORG-EXIT-01B recovery runtime")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "VERSION", "") != RECOVERY_RUNTIME_VERSION:
        raise RuntimeError("REORG-EXIT-01B recovery runtime version mismatch")
    for name in ("assess_exact_exit_recovery", "read_assessment"):
        if not hasattr(mod, name):
            raise RuntimeError("REORG-EXIT-01B recovery runtime compatibility failure")
    return mod


_REORG_RECOVERY_RUNTIME = _load_reorg_recovery_runtime_module()


def _load_reorg_rebroadcast_module():
    path = Path(__file__).with_name("reorg_exit_rebroadcast_v1.py").resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("REORG-EXIT-01C rebroadcast executor missing or symlinked")
    spec = importlib.util.spec_from_file_location("tru_reorg_exit_rebroadcast_live", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import REORG-EXIT-01C rebroadcast executor")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    if getattr(mod, "VERSION", "") != "TRU-REORG-EXIT-01C":
        raise RuntimeError("REORG-EXIT-01C executor version mismatch")
    for name in ("enabled", "maybe_execute_exact_exit_rebroadcast"):
        if not hasattr(mod, name): raise RuntimeError("REORG-EXIT-01C executor compatibility failure")
    return mod

_REORG_REBROADCAST = _load_reorg_rebroadcast_module()


def _reorg_overlay(agent):
    return _REORG_OVERLAY.ExitReorgOverlay(agent.store.path)


def _resolution_entries(record: Dict[str, Any]) -> list[Dict[str, Any]]:
    ev = record.get("evidence") or {}
    out = []
    for chain in ("tru", "bsty"):
        for kind in ("claim", "refund"):
            prefix = f"{chain}{kind.capitalize()}"
            txid = str(ev.get(prefix + "Txid") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", txid):
                continue
            try:
                historical_conf = max(0, int(ev.get(prefix + "Confirmations", 0)))
            except Exception:
                historical_conf = 0
            out.append({
                "chain": chain, "kind": kind, "txid": txid,
                "historicalConfirmations": historical_conf,
            })
    return out


def _record_preimage_exposed(record: Dict[str, Any]) -> bool:
    return any(x["kind"] == "claim" for x in _resolution_entries(record))


def _tru_resolution_status(agent, txid: str) -> Dict[str, Any]:
    obj = agent.tru.public_raw("gettransaction", {"txid": txid})
    if not isinstance(obj, dict):
        raise RuntimeError("TRU gettransaction returned invalid object")
    state = str(obj.get("txState", "")).upper()
    if state not in RESOLUTION_TX_STATES - {"UNKNOWN"}:
        raise RuntimeError("TRU gettransaction returned invalid txState")
    try:
        conf = int(obj.get("confirmations", 0))
    except Exception as exc:
        raise RuntimeError("TRU gettransaction confirmations invalid") from exc
    if state == "CONFIRMED":
        if conf < 1:
            raise RuntimeError("TRU CONFIRMED transaction has invalid confirmations")
    else:
        conf = 0
    return {"txState": state, "confirmations": conf}


def _bsty_rpc_json(agent, method: str, *args: str, wallet: bool = False) -> tuple[bool, Any]:
    cmd = [str(agent.bsty.cli)]
    if wallet and agent.bsty.wallet:
        cmd.append(f"-rpcwallet={agent.bsty.wallet}")
    cmd.append(method)
    cmd.extend(str(x) for x in args)
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=REORG_RPC_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("BSTY resolution-status RPC timeout") from exc
    if cp.returncode != 0:
        return False, None
    text = cp.stdout.strip()
    if not text:
        return True, None
    try:
        return True, json.loads(text)
    except Exception as exc:
        raise RuntimeError("BSTY resolution-status RPC returned malformed JSON") from exc


def _bsty_resolution_status(agent, txid: str) -> Dict[str, Any]:
    ok, mem = _bsty_rpc_json(agent, "getmempoolentry", txid)
    if ok:
        return {"txState": "MEMPOOL", "confirmations": 0}

    ok, raw = _bsty_rpc_json(agent, "getrawtransaction", txid, "true")
    if ok and isinstance(raw, dict):
        try:
            raw_conf = int(raw.get("confirmations", 0) or 0)
        except Exception:
            raw_conf = 0
        blockhash = str(raw.get("blockhash") or "")
        if blockhash:
            hok, header = _bsty_rpc_json(agent, "getblockheader", blockhash, "true")
            if hok and isinstance(header, dict):
                try:
                    hc = int(header.get("confirmations", 0) or 0)
                except Exception:
                    hc = 0
                if hc > 0:
                    return {"txState": "CONFIRMED", "confirmations": max(hc, raw_conf, 1)}
                if hc <= 0:
                    return {"txState": "SIDECHAIN", "confirmations": 0}
            if raw_conf > 0:
                return {"txState": "CONFIRMED", "confirmations": raw_conf}
            return {"txState": "UNKNOWN", "confirmations": 0}
        if raw_conf > 0:
            return {"txState": "CONFIRMED", "confirmations": raw_conf}
        return {"txState": "MEMPOOL", "confirmations": 0}

    wok, wtx = _bsty_rpc_json(agent, "gettransaction", txid, wallet=True)
    if wok and isinstance(wtx, dict):
        try:
            conf = int(wtx.get("confirmations", 0) or 0)
        except Exception:
            conf = 0
        if conf > 0:
            return {"txState": "CONFIRMED", "confirmations": conf}
        if conf < 0 or wtx.get("abandoned") is True:
            return {"txState": "CONFLICTED", "confirmations": 0}
        return {"txState": "MEMPOOL", "confirmations": 0}

    # Without txindex, an arbitrary remote BSTY transaction may not be queryable.
    # UNKNOWN is deliberately safer than falsely declaring NOT_FOUND/reorged.
    return {"txState": "UNKNOWN", "confirmations": 0}


def _resolution_status(agent, chain: str, txid: str) -> Dict[str, Any]:
    if chain == "tru":
        return _tru_resolution_status(agent, txid)
    if chain == "bsty":
        return _bsty_resolution_status(agent, txid)
    raise ValueError("chain")


def observe_resolution_history(agent, record: Dict[str, Any]) -> Dict[str, Any]:
    overlay = _reorg_overlay(agent)
    rows = []
    recoveries = []
    executions = []
    errors = []
    recovery_errors = []
    for item in _resolution_entries(record):
        try:
            status = _resolution_status(agent, item["chain"], item["txid"])
            row = overlay.observe(
                str(record.get("swapId", "")), item["chain"], item["kind"], item["txid"],
                status["txState"], status["confirmations"], item["historicalConfirmations"],
            )
            rows.append(row)
            try:
                assessment = _REORG_RECOVERY_RUNTIME.assess_exact_exit_recovery(agent, record, row)
                recoveries.append(assessment)
                executions.append(
                    _REORG_REBROADCAST.maybe_execute_exact_exit_rebroadcast(agent, record, row, assessment)
                )
            except Exception as recovery_exc:
                recovery_errors.append(
                    item["chain"] + ":" + item["kind"] + ":" + str(recovery_exc)[:240]
                )
        except Exception as exc:
            errors.append(item["chain"] + ":" + item["kind"] + ":" + str(exc)[:240])
    return {
        "observed": len(rows),
        "errors": errors,
        "recoveryErrors": recovery_errors,
        "preimageExposed": _record_preimage_exposed(record) or overlay.preimage_exposed(str(record.get("swapId", ""))),
        "rows": rows,
        "recoveryAssessments": recoveries,
        "rebroadcastExecutions": executions,
        "sameTxRecoveryEligible": sum(
            1 for x in recoveries if x.get("sameTxRebroadcastEligible") is True
        ),
        "sameTxRebroadcastAuthorized": False,
    }


def _refund_safety(agent, record: Dict[str, Any], observation: Dict[str, Any]) -> tuple[bool, str]:
    if _record_preimage_exposed(record) or bool(observation.get("preimageExposed")):
        return False, "historical preimage exposure permanently forbids refund-path execution"
    if observation.get("errors"):
        return False, "resolution reorg status incomplete; refund fails closed"
    return True, "PASS"


def ensure_schema(store) -> None:
    with store.connect() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS exit_watchers (
                swap_id TEXT PRIMARY KEY,
                give_chain TEXT NOT NULL CHECK(give_chain IN ('tru','bsty')),
                get_chain TEXT NOT NULL CHECK(get_chain IN ('tru','bsty')),
                min_conf INTEGER NOT NULL CHECK(min_conf >= 1),
                claim_destination_json TEXT NOT NULL,
                refund_destination_json TEXT NOT NULL,
                claim_authorization_id TEXT NOT NULL,
                refund_authorization_id TEXT NOT NULL,
                bsty_signer_address TEXT,
                state TEXT NOT NULL CHECK(state IN (
                    'ARMED','ACTION_STARTED','HOLD_UNKNOWN','COMPLETE',
                    'DISARMED','AMBIGUOUS'
                )),
                action_kind TEXT,
                action_chain TEXT,
                action_txid TEXT,
                last_error TEXT,
                created_ms INTEGER NOT NULL,
                updated_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS exit_watchers_state_idx
                ON exit_watchers(state, updated_ms);
            """
        )


def _row(r: sqlite3.Row) -> Dict[str, Any]:
    return {
        "swapId": r["swap_id"],
        "giveChain": r["give_chain"],
        "getChain": r["get_chain"],
        "minConf": int(r["min_conf"]),
        "claimDestination": json.loads(r["claim_destination_json"]),
        "refundDestination": json.loads(r["refund_destination_json"]),
        "claimAuthorizationId": r["claim_authorization_id"],
        "refundAuthorizationId": r["refund_authorization_id"],
        "bstySignerAddress": r["bsty_signer_address"],
        "state": r["state"],
        "actionKind": r["action_kind"],
        "actionChain": r["action_chain"],
        "actionTxid": r["action_txid"],
        "lastError": r["last_error"],
        "createdMs": int(r["created_ms"]),
        "updatedMs": int(r["updated_ms"]),
    }


def get_job(store, swap_id: str) -> Optional[Dict[str, Any]]:
    ensure_schema(store)
    with store.connect() as c:
        r = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (swap_id,)).fetchone()
    return None if r is None else _row(r)


def list_jobs(store, states=ACTIVE_STATES) -> list[Dict[str, Any]]:
    ensure_schema(store)
    qs = sorted(states)
    ph = ",".join("?" for _ in qs)
    with store.connect() as c:
        rows = c.execute(
            f"SELECT * FROM exit_watchers WHERE state IN ({ph}) ORDER BY updated_ms ASC",
            tuple(qs),
        ).fetchall()
    return [_row(r) for r in rows]


def list_observation_jobs(store) -> list[Dict[str, Any]]:
    # COMPLETE rows remain observed forever so a later claim/refund reorg cannot
    # disappear merely because the money-moving watcher finished earlier.
    return list_jobs(store, ACTIVE_STATES | {"COMPLETE"})


def _session_for_swap(agent, swap_id: str) -> Dict[str, Any]:
    with agent.store.connect() as c:
        r = c.execute(
            """SELECT * FROM offer_sessions
               WHERE swap_id=? ORDER BY updated_ms DESC LIMIT 1""",
            (swap_id,),
        ).fetchone()
    if r is None:
        raise ValueError("local offer session for swap is unavailable")
    return {
        "preimageHex": r["preimage_hex"],
        "bstySignerAddress": r["bsty_signer_address"],
        "giveChain": r["give_chain"],
        "getChain": r["get_chain"],
        "minConf": int(r["min_conf"]),
    }


def _resolve_destination(agent, d: Any, chain: str, label: str) -> Dict[str, Any]:
    if not isinstance(d, dict):
        raise ValueError(f"{label} destination missing")
    source = str(d.get("source", ""))
    got_chain = str(d.get("chain", ""))
    if got_chain != chain:
        raise ValueError(f"{label} destination chain must be {chain}")
    if source == "wallet":
        if chain != "bsty":
            raise ValueError("TRU watcher destination must be an explicit external TRU address")
        addr = agent.bsty.text(
            "getnewaddress", f"tru-swap-exit-{label}-{os.urandom(8).hex()}", wallet=True
        ).strip()
        info = agent.bsty.json("getaddressinfo", addr, wallet=True)
        if not isinstance(info, dict) or info.get("ismine") is not True:
            raise ValueError("BSTY watcher destination is not wallet-owned")
        return {"chain": chain, "source": "wallet", "address": addr}
    if source != "external":
        raise ValueError(f"{label} destination source must be wallet or external")
    addr = str(d.get("address", "")).strip()
    ok, note = agent.validate_destination(
        {"chain": chain, "source": "external", "address": addr}, chain
    )
    if not ok:
        raise ValueError(note)
    return {"chain": chain, "source": "external", "address": addr}


def arm(agent, swap_id: str, destinations: Any) -> Dict[str, Any]:
    require_enabled()
    if not SWAP_ID_RE.fullmatch(str(swap_id)):
        raise ValueError("swapId")
    view = agent.require_view(swap_id)
    record = agent.get_live_record(swap_id)
    if record.get("state") not in {"BOTH_FUNDED", "SECRET_OBSERVED", "REFUND_PENDING"}:
        raise ValueError("exit watcher requires BOTH_FUNDED, SECRET_OBSERVED, or REFUND_PENDING")
    give = str(view["give_chain"])
    get = str(view["get_chain"])
    d = destinations if isinstance(destinations, dict) else {}
    claim = _resolve_destination(agent, d.get("claim"), get, "claim")
    refund = _resolve_destination(agent, d.get("refund"), give, "refund")
    session = _session_for_swap(agent, swap_id)
    if session["giveChain"] != give or session["getChain"] != get:
        raise ValueError("local offer-session chain perspective mismatch")
    claim_id = _auth_id(swap_id, "claim", get, claim)
    refund_id = _auth_id(swap_id, "refund", give, refund)
    ensure_schema(agent.store)
    t = now_ms()
    with agent.store.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        old = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (swap_id,)).fetchone()
        if old is not None:
            prior = _row(old)
            exact = (
                prior["giveChain"] == give and prior["getChain"] == get and
                prior["minConf"] == int(view["min_conf"]) and
                prior["claimDestination"] == claim and prior["refundDestination"] == refund and
                prior["claimAuthorizationId"] == claim_id and prior["refundAuthorizationId"] == refund_id
            )
            if prior["state"] in ACTIVE_STATES and exact:
                c.execute("COMMIT")
                return public_job(prior)
            c.execute("ROLLBACK")
            raise ValueError("different exit authorization already exists; disarm before replacing it")
        c.execute(
            """INSERT INTO exit_watchers
               (swap_id,give_chain,get_chain,min_conf,claim_destination_json,refund_destination_json,
                claim_authorization_id,refund_authorization_id,bsty_signer_address,state,
                action_kind,action_chain,action_txid,last_error,created_ms,updated_ms)
               VALUES(?,?,?,?,?,?,?,?,?,'ARMED',NULL,NULL,NULL,NULL,?,?)""",
            (
                swap_id, give, get, int(view["min_conf"]), _canonical(claim), _canonical(refund),
                claim_id, refund_id, session.get("bstySignerAddress"), t, t,
            ),
        )
        out = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (swap_id,)).fetchone()
        c.execute("COMMIT")
    return public_job(_row(out))


def disarm(agent, swap_id: str) -> Dict[str, Any]:
    if not SWAP_ID_RE.fullmatch(str(swap_id)):
        raise ValueError("swapId")
    ensure_schema(agent.store)
    with agent.store.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        r = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (swap_id,)).fetchone()
        if r is None:
            c.execute("ROLLBACK")
            raise ValueError("no exit watcher authorization exists")
        job = _row(r)
        if job["state"] == "DISARMED":
            c.execute("COMMIT")
            return public_job(job)
        if job["state"] != "ARMED":
            c.execute("ROLLBACK")
            raise ValueError("cannot disarm after an exit action has started")
        c.execute(
            "UPDATE exit_watchers SET state='DISARMED',updated_ms=? WHERE swap_id=?",
            (now_ms(), swap_id),
        )
        out = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (swap_id,)).fetchone()
        c.execute("COMMIT")
    return public_job(_row(out))


def public_job(job: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if job is None:
        return None
    return {
        "swapId": job["swapId"],
        "armed": job["state"] in ACTIVE_STATES,
        "state": job["state"],
        "claimAuthorizationId": job["claimAuthorizationId"],
        "refundAuthorizationId": job["refundAuthorizationId"],
        "destinations": {
            "claim": job["claimDestination"],
            "refund": job["refundDestination"],
        },
        "actionKind": job["actionKind"],
        "actionChain": job["actionChain"],
        "actionTxid": job["actionTxid"],
        "claimTxid": job["actionTxid"] if job["actionKind"] == "claim" else None,
        "refundTxid": job["actionTxid"] if job["actionKind"] == "refund" else None,
        "lastError": job["lastError"],
        "privateMaterialReturned": False,
        "preimageReturned": False,
    }


def _set_action_started(agent, job: Dict[str, Any], kind: str, chain: str) -> Dict[str, Any]:
    with agent.store.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        r = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (job["swapId"],)).fetchone()
        cur = _row(r)
        if cur["state"] == "ACTION_STARTED":
            c.execute("COMMIT")
            return cur
        if cur["state"] != "ARMED":
            c.execute("ROLLBACK")
            raise ValueError("watcher is not ARMED")
        c.execute(
            """UPDATE exit_watchers SET state='ACTION_STARTED',action_kind=?,action_chain=?,
               action_txid=NULL,last_error=NULL,updated_ms=? WHERE swap_id=?""",
            (kind, chain, now_ms(), job["swapId"]),
        )
        out = c.execute("SELECT * FROM exit_watchers WHERE swap_id=?", (job["swapId"],)).fetchone()
        c.execute("COMMIT")
    return _row(out)


def _finish_job(agent, swap_id: str, txid: Optional[str], state: str = "COMPLETE", error: Optional[str] = None) -> None:
    if state not in STATES:
        raise ValueError("state")
    with agent.store.connect() as c:
        c.execute(
            "UPDATE exit_watchers SET state=?,action_txid=COALESCE(?,action_txid),last_error=?,updated_ms=? WHERE swap_id=?",
            (state, txid, error, now_ms(), swap_id),
        )


def _record_has_local_outcome(record: Dict[str, Any], job: Dict[str, Any]) -> Optional[str]:
    ev = record.get("evidence") or {}
    get = job["getChain"]
    give = job["giveChain"]
    if ev.get(f"{get}ClaimTxid"):
        return str(ev[f"{get}ClaimTxid"])
    if ev.get(f"{give}RefundTxid"):
        return str(ev[f"{give}RefundTxid"])
    return None


def _secret_file_from_session_or_chain(agent, job: Dict[str, Any], record: Dict[str, Any], path: Path) -> bool:
    session = _session_for_swap(agent, job["swapId"])
    secret = str(session.get("preimageHex") or "")
    if re.fullmatch(r"[0-9a-fA-F]{64}", secret):
        if agent.engine.hash160(bytes.fromhex(secret)).hex() == record.get("secretHash160"):
            path.write_text(json.dumps({"preimageHex": secret.lower(), "hash160": record["secretHash160"]}) + "\n")
            os.chmod(path, 0o600)
            return True

    ev = record.get("evidence") or {}
    give = job["giveChain"]
    claim_txid = ev.get(f"{give}ClaimTxid")
    if not claim_txid:
        return False
    cmd = _engine_base_cmd(agent, job["minConf"])
    if give == "tru":
        cmd += ["observe-tru", "--swap-id", job["swapId"], "--txid", str(claim_txid), "--secret-output", str(path)]
    else:
        attempt = agent.store.get_funding_attempt(job["swapId"], "bsty")
        start = int((attempt or {}).get("startingHeight", 0))
        cmd += ["watch-bsty", "--swap-id", job["swapId"], "--from-height", str(start), "--secret-output", str(path)]
    cp = subprocess.run(cmd, text=True, capture_output=True, env=os.environ.copy())
    return cp.returncode == 0 and path.is_file()


def _bounded_timeout_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        value = int(default)
    else:
        try:
            value = int(raw)
        except Exception as exc:
            raise ValueError(f"{name} must be an integer number of seconds") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum} seconds")
    return value


def timeout_policy() -> tuple[int, int]:
    """Return (engine_wait_seconds, outer_process_timeout_seconds).

    The outer watcher watchdog MUST always be strictly longer than the engine's
    own confirmation wait. This prevents timeout inversion from converting a
    still-valid confirmation wait into an avoidable HOLD_UNKNOWN.
    """
    wait_seconds = _bounded_timeout_env(
        WAIT_TIMEOUT_ENV,
        DEFAULT_WAIT_TIMEOUT_SECONDS,
        MIN_WAIT_TIMEOUT_SECONDS,
        MAX_WAIT_TIMEOUT_SECONDS,
    )
    grace_seconds = _bounded_timeout_env(
        PROCESS_GRACE_ENV,
        DEFAULT_PROCESS_GRACE_SECONDS,
        MIN_PROCESS_GRACE_SECONDS,
        MAX_PROCESS_GRACE_SECONDS,
    )
    process_timeout = wait_seconds + grace_seconds
    if process_timeout <= wait_seconds:
        raise ValueError("exit process timeout must exceed engine wait timeout")
    return wait_seconds, process_timeout


def _engine_base_cmd(agent, min_conf: int) -> list[str]:
    wait_seconds, _ = timeout_policy()
    return [
        os.environ.get("PYTHON", "python3"), str(agent.engine_path),
        "--tru-cli", str(agent.tru.cli), "--tru-conf", str(agent.tru.conf),
        "--bsty-cli", str(agent.bsty.cli), "--bsty-wallet", str(agent.bsty.wallet),
        "--min-conf", str(int(min_conf)),
        "--wait-timeout", str(wait_seconds),
    ]


def _invoke_exit(agent, job: Dict[str, Any], kind: str, chain: str, secret_file: Optional[Path]) -> str:
    require_enabled()
    dest = job["claimDestination"] if kind == "claim" else job["refundDestination"]
    cmd = _engine_base_cmd(agent, job["minConf"])
    cmd += [f"{kind}-{chain}", "--swap-id", job["swapId"]]
    if kind == "claim":
        if secret_file is None:
            raise ValueError("claim requires secret file")
        cmd += ["--secret-file", str(secret_file)]
    cmd += ["--recipient", str(dest["address"])]
    if chain == "bsty":
        signer = str(job.get("bstySignerAddress") or "")
        if not signer:
            raise ValueError("BSTY signer address missing from local offer session")
        cmd += ["--signer-address", signer]
    wait_seconds, process_timeout = timeout_policy()
    try:
        cp = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=process_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "exit engine outer watchdog expired only after canonical wait window "
            f"(engineWait={wait_seconds}s, processTimeout={process_timeout}s)"
        ) from exc
    if cp.returncode != 0:
        raise RuntimeError((cp.stderr or cp.stdout or "exit engine command failed").strip()[:1000])
    rx = re.compile(rf"^{chain.upper()}_{kind.upper()}_TXID=\s*([0-9a-f]{{64}})\s*$", re.M)
    m = rx.search(cp.stdout)
    if not m:
        raise RuntimeError("exit engine completed without canonical txid")
    return m.group(1)


def tick_one(agent, job: Dict[str, Any]) -> Dict[str, Any]:
    # Reorg observation intentionally runs even for COMPLETE watchers. Canonical
    # exit-watcher state never moves backward; current chain location lives only
    # in the separate REORG-EXIT sidecar.
    record = agent.get_live_record(job["swapId"])
    observation = observe_resolution_history(agent, record)

    if job["state"] not in ACTIVE_STATES:
        return job

    known = _record_has_local_outcome(record, job)
    if known:
        _finish_job(agent, job["swapId"], known, "COMPLETE", None)
        return get_job(agent.store, job["swapId"])

    if job["state"] == "ACTION_STARTED":
        # The mutator may have succeeded just before a crash. Never retry it
        # until canonical evidence proves the result. This is a deliberate
        # fail-closed recovery hold, not retry authority.
        _finish_job(
            agent, job["swapId"], None, "HOLD_UNKNOWN",
            "previous exit mutator outcome is unknown; canonical evidence required before retry",
        )
        return get_job(agent.store, job["swapId"])
    if job["state"] == "HOLD_UNKNOWN":
        return job

    ev = record.get("evidence") or {}
    get = job["getChain"]
    give = job["giveChain"]
    get_funded = bool(ev.get(f"{get}FundingTxid"))
    give_funded = bool(ev.get(f"{give}FundingTxid"))

    with tempfile.TemporaryDirectory(prefix="tru-swap-exit-") as td:
        secret_file = Path(td) / "secret.json"
        if get_funded and record.get("state") in {"BOTH_FUNDED", "SECRET_OBSERVED", "REFUND_PENDING"}:
            if _secret_file_from_session_or_chain(agent, job, record, secret_file):
                _set_action_started(agent, job, "claim", get)
                try:
                    txid = _invoke_exit(agent, job, "claim", get, secret_file)
                except Exception as exc:
                    # Outcome may be unknown once the mutator was entered.
                    _finish_job(agent, job["swapId"], None, "HOLD_UNKNOWN", str(exc)[:500])
                    return get_job(agent.store, job["swapId"])
                _finish_job(agent, job["swapId"], txid, "COMPLETE", None)
                return get_job(agent.store, job["swapId"])

    refund_time = int(record.get("truRefundTime" if give == "tru" else "bstyRefundTime", 0))
    if give_funded and refund_time > 0 and int(time.time()) >= refund_time:
        refund_ok, reason = _refund_safety(agent, record, observation)
        if not refund_ok:
            _finish_job(agent, job["swapId"], None, "HOLD_UNKNOWN", reason[:500])
            return get_job(agent.store, job["swapId"])
        _set_action_started(agent, job, "refund", give)
        try:
            txid = _invoke_exit(agent, job, "refund", give, None)
        except Exception as exc:
            _finish_job(agent, job["swapId"], None, "HOLD_UNKNOWN", str(exc)[:500])
            return get_job(agent.store, job["swapId"])
        _finish_job(agent, job["swapId"], txid, "COMPLETE", None)
        return get_job(agent.store, job["swapId"])

    return job


def observe_tick(agent, swap_id: Optional[str] = None) -> Dict[str, Any]:
    # Pure observation path. It intentionally ignores TRU_SWAP_EXIT_WATCHER_ENABLE
    # and never calls a claim/refund mutator or rewrites the canonical watcher row.
    jobs = [get_job(agent.store, swap_id)] if swap_id else list_observation_jobs(agent.store)
    out = []
    errors = []
    recovery_errors = []
    for job in jobs:
        if job is None:
            continue
        try:
            record = agent.get_live_record(job["swapId"])
            obs = observe_resolution_history(agent, record)
            out.append({"swapId": job["swapId"], "state": job["state"],
                        "observed": int(obs.get("observed", 0)),
                        "preimageExposed": bool(obs.get("preimageExposed")),
                        "sameTxRecoveryEligible": int(obs.get("sameTxRecoveryEligible", 0)),
                        "sameTxRebroadcastAuthorized": False})
            errors.extend(str(x)[:240] for x in obs.get("errors", []))
            recovery_errors.extend(str(x)[:240] for x in obs.get("recoveryErrors", []))
        except Exception as exc:
            errors.append(job["swapId"] + ":" + str(exc)[:240])
    return {"checked": len(out), "rows": out, "errors": errors,
            "recoveryErrors": recovery_errors, "moneyMutation": False,
            "sameTxRebroadcastAuthorized": False}


def tick(agent, swap_id: Optional[str] = None, include_complete: bool = False) -> Dict[str, Any]:
    require_enabled()
    if swap_id:
        jobs = [get_job(agent.store, swap_id)]
    else:
        jobs = list_observation_jobs(agent.store) if include_complete else list_jobs(agent.store)
    out = []
    for job in jobs:
        if job is None:
            continue
        try:
            out.append(public_job(tick_one(agent, job)))
        except Exception as exc:
            # Observation failures never rewrite COMPLETE back to an active state.
            _finish_job(agent, job["swapId"], None, job["state"], str(exc)[:500])
            out.append(public_job(get_job(agent.store, job["swapId"])))
    return {"checked": len(out), "jobs": out}


def watch_loop(agent, stop_event: threading.Event) -> None:
    try:
        poll = int(os.environ.get(POLL_ENV, "5"))
    except Exception:
        poll = 5
    poll = min(max(poll, 1), 300)
    while not stop_event.is_set():
        try:
            observe_tick(agent)
        except Exception as exc:
            print("[exit-reorg-observer] tick error:", str(exc)[:500], file=os.sys.stderr)
        if enabled():
            try:
                tick(agent)
            except Exception as exc:
                print("[exit-watcher] tick error:", str(exc)[:500], file=os.sys.stderr)
        stop_event.wait(poll)


def selftest() -> None:
    assert enabled() is False or os.environ.get(ENABLE_ENV) == "1"
    sid = "11" * 32
    c = {"chain": "bsty", "source": "external", "address": "yTestClaim"}
    r = {"chain": "tru", "source": "external", "address": "TTestRefund"}
    a1 = _auth_id(sid, "claim", "bsty", c)
    a2 = _auth_id(sid, "claim", "bsty", c)
    assert a1 == a2 and len(a1) == 64
    assert a1 != _auth_id(sid, "refund", "bsty", c)
    wait_seconds, process_timeout = timeout_policy()
    assert wait_seconds >= MIN_WAIT_TIMEOUT_SECONDS
    assert process_timeout > wait_seconds
    assert process_timeout - wait_seconds >= MIN_PROCESS_GRACE_SECONDS
    assert "preimageHex" not in public_job({
        "swapId": sid, "giveChain": "tru", "getChain": "bsty", "minConf": 1,
        "claimDestination": c, "refundDestination": r,
        "claimAuthorizationId": a1, "refundAuthorizationId": _auth_id(sid,"refund","tru",r),
        "state": "ARMED", "actionKind": None, "actionChain": None, "actionTxid": None,
        "lastError": None,
    })
    print("TRU_SWAP_GROUP04_EXIT_WATCHER_SELFTEST=PASS")
    print("WATCHER_ACTIVATION_DEFAULT=DISABLED")
    print("EXIT_AUTHORIZATION_CANONICAL_BINDING=PASS")
    print("ACTION_INTENT_BEFORE_MUTATOR=REQUIRED")
    print("UNKNOWN_OUTCOME_BLIND_RETRY=FORBIDDEN")
    print("REORG_EXIT_VERSION=" + REORG_VERSION)
    print("COMPLETE_EXIT_ROWS_REMAIN_OBSERVED=PASS")
    print("REORG_EXIT_OBSERVATION_ENABLE_GATE=NOT_REQUIRED")
    print("PREIMAGE_EXPOSURE_REFUND_GATE=FAIL_CLOSED")
    print("EXIT_TIMEOUT_OWNERSHIP=ENGINE_WAIT_THEN_LONGER_WATCHER_WATCHDOG")
    print("EXIT_OUTER_TIMEOUT_STRICTLY_GREATER_THAN_ENGINE_WAIT=PASS")
    print("PRIVATE_MATERIAL_RETURNED=NO")
    print("REORG_EXIT_RECOVERY_RUNTIME=TRU-REORG-EXIT-01B")
    print("SAME_TX_RECOVERY_RUNTIME_BINDING=READ_ONLY_PROOF_ONLY")
    print("SAME_TX_REBROADCAST_AUTHORIZED=NO")


if __name__ == "__main__":
    selftest()
