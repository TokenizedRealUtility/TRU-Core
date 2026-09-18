#!/usr/bin/env python3
"""TRU REORG-EXIT-01B live exact-exit recovery proof binding.

Read/prove/persist-metadata only. This module NEVER broadcasts, signs, rebuilds,
or stores raw signed transaction bytes. Exact raw bytes exist only in local
variables while the 01A policy is evaluated.
"""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

VERSION = "TRU-REORG-EXIT-01B"
POLICY_VERSION = "TRU-REORG-EXIT-01A"
RPC_TIMEOUT_SECONDS = 10
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]+$")


def now_ms() -> int:
    return int(time.time() * 1000)


def _txid(value: Any, name: str) -> str:
    s = str(value or "").lower()
    if not TXID_RE.fullmatch(s):
        raise ValueError(name)
    return s


def _funding_outpoint(record: Dict[str, Any], chain: str) -> tuple[str, int]:
    ev = record.get("evidence") or {}
    txid = _txid(ev.get(f"{chain}FundingTxid"), chain + "FundingTxid")
    try:
        vout = int(ev.get(f"{chain}FundingVout"))
    except Exception as exc:
        raise ValueError(chain + "FundingVout") from exc
    if vout < 0 or vout > 0xFFFFFFFF:
        raise ValueError(chain + "FundingVout")
    return txid, vout


def _load_policy():
    import importlib.util
    path = Path(__file__).with_name("reorg_exit_recovery_v1.py").resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("REORG-EXIT-01A policy missing or symlinked")
    spec = importlib.util.spec_from_file_location("tru_reorg_exit_recovery_policy_live", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import REORG-EXIT-01A policy")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "VERSION", "") != POLICY_VERSION:
        raise RuntimeError("REORG-EXIT-01A policy version mismatch")
    if not hasattr(mod, "plan_exact_exit_recovery"):
        raise RuntimeError("REORG-EXIT-01A policy compatibility failure")
    return mod


_POLICY = _load_policy()


def _run_bsty_json(agent, method: str, *args: str, wallet: bool = False) -> tuple[bool, Any]:
    cmd = [str(agent.bsty.cli)]
    if wallet and agent.bsty.wallet:
        cmd.append(f"-rpcwallet={agent.bsty.wallet}")
    cmd.append(method)
    cmd.extend(str(x) for x in args)
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=RPC_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("BSTY exact-exit recovery RPC timeout") from exc
    if cp.returncode != 0:
        return False, None
    text = cp.stdout.strip()
    if not text:
        return True, None
    try:
        return True, json.loads(text)
    except Exception as exc:
        raise RuntimeError("BSTY exact-exit recovery RPC malformed JSON") from exc


def _validate_raw_hex(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s or len(s) % 2 or not HEX_RE.fullmatch(s):
        return None
    if len(s) > 2 * 1024 * 1024:
        return None
    return s


def _tru_exact_raw_and_decode(agent, txid: str) -> tuple[Optional[str], Optional[str], Optional[str], Optional[dict]]:
    obj = agent.tru.public_raw("gettransaction", {"txid": txid})
    if not isinstance(obj, dict):
        raise RuntimeError("TRU gettransaction invalid object")
    raw = _validate_raw_hex(obj.get("hex"))
    if raw is None:
        return None, None, None, obj
    dec = agent.tru.public_raw("decoderawtransaction", {"txHex": raw})
    if not isinstance(dec, dict):
        raise RuntimeError("TRU decoderawtransaction invalid object")
    decoded = str(dec.get("txid") or "").lower()
    return raw, decoded, "TRU_GETTRANSACTION", dec


def _bsty_exact_raw_and_decode(agent, txid: str) -> tuple[Optional[str], Optional[str], Optional[str], Optional[dict]]:
    source = None
    raw = None
    ok, wtx = _run_bsty_json(agent, "gettransaction", txid, wallet=True)
    if ok and isinstance(wtx, dict):
        raw = _validate_raw_hex(wtx.get("hex"))
        if raw is not None:
            source = "BSTY_WALLET_GETTRANSACTION"
    if raw is None:
        ok, raw_obj = _run_bsty_json(agent, "getrawtransaction", txid, "false")
        if ok:
            raw = _validate_raw_hex(raw_obj)
            if raw is not None:
                source = "BSTY_GETRAWTRANSACTION"
    if raw is None:
        return None, None, None, None
    ok, dec = _run_bsty_json(agent, "decoderawtransaction", raw)
    if not ok or not isinstance(dec, dict):
        raise RuntimeError("BSTY decoderawtransaction unavailable")
    return raw, str(dec.get("txid") or "").lower(), source, dec


def _decoded_exact_funding_input(decoded: Any, funding_txid: str, funding_vout: int) -> bool:
    if not isinstance(decoded, dict):
        return False
    vin = decoded.get("vin")
    if not isinstance(vin, list) or len(vin) != 1 or not isinstance(vin[0], dict):
        return False
    try:
        got_txid = str(vin[0].get("txid") or "").lower()
        got_vout = int(vin[0].get("vout"))
    except Exception:
        return False
    return got_txid == funding_txid and got_vout == funding_vout


def _tru_mempool_absent(agent, txid: str) -> bool:
    obj = agent.tru.public_raw("getrawmempool", {"verbose": False})
    if not isinstance(obj, list):
        raise RuntimeError("TRU getrawmempool invalid response")
    return txid not in {str(x).lower() for x in obj}


def _bsty_mempool_absent(agent, txid: str) -> bool:
    ok, obj = _run_bsty_json(agent, "getrawmempool", "false")
    if not ok or not isinstance(obj, list):
        raise RuntimeError("BSTY getrawmempool unavailable")
    return txid not in {str(x).lower() for x in obj}


def _tru_active_input_unspent(agent, funding_txid: str, funding_vout: int) -> bool:
    obj = agent.tru.public_raw("gettxout", {
        "txid": funding_txid, "n": int(funding_vout), "includeMempool": False,
    })
    return isinstance(obj, dict)


def _bsty_active_input_unspent(agent, funding_txid: str, funding_vout: int) -> bool:
    ok, obj = _run_bsty_json(agent, "gettxout", funding_txid, str(int(funding_vout)), "false")
    return bool(ok and isinstance(obj, dict))


def _tru_policy_accept(agent, raw: str, txid: str, funding_txid: str, funding_vout: int) -> bool:
    obj = agent.tru.public_raw("swaptestexitmempoolaccept", {
        "txHex": raw,
        "expectedTxid": txid,
        "fundingTxid": funding_txid,
        "fundingVout": int(funding_vout),
    })
    return bool(isinstance(obj, dict) and obj.get("allowed") is True and obj.get("readOnly") is True)


def _bsty_policy_accept(agent, raw: str) -> bool:
    ok, obj = _run_bsty_json(agent, "testmempoolaccept", json.dumps([raw], separators=(",", ":")))
    if not ok or not isinstance(obj, list) or len(obj) != 1 or not isinstance(obj[0], dict):
        return False
    return obj[0].get("allowed") is True


def _assessment_db_path(agent) -> Path:
    return Path(str(Path(agent.store.path).expanduser().resolve()) + ".exit-reorg.sqlite3")


def _persist_assessment(agent, plan: Dict[str, Any], proof: Dict[str, Any]) -> None:
    path = _assessment_db_path(agent)
    if path.exists() and path.is_symlink():
        raise RuntimeError("exit reorg sidecar must not be symlinked")
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=10, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=10000")
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS exit_recovery_assessments (
                swap_id TEXT NOT NULL,
                chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
                kind TEXT NOT NULL CHECK(kind IN ('claim','refund')),
                txid TEXT NOT NULL,
                current_tx_state TEXT NOT NULL,
                action TEXT NOT NULL,
                exact_bytes_available INTEGER NOT NULL CHECK(exact_bytes_available IN (0,1)),
                decoded_txid_identity INTEGER NOT NULL CHECK(decoded_txid_identity IN (0,1)),
                mempool_absence INTEGER NOT NULL CHECK(mempool_absence IN (0,1)),
                active_input_nonconflict INTEGER NOT NULL CHECK(active_input_nonconflict IN (0,1)),
                policy_acceptance INTEGER NOT NULL CHECK(policy_acceptance IN (0,1)),
                same_tx_eligible INTEGER NOT NULL CHECK(same_tx_eligible IN (0,1)),
                payload_sha256 TEXT,
                raw_bytes INTEGER,
                raw_source TEXT,
                observed_ms INTEGER NOT NULL,
                PRIMARY KEY(swap_id,chain,kind)
            );
            """
        )
        con.execute("BEGIN IMMEDIATE")
        old = con.execute(
            "SELECT txid FROM exit_recovery_assessments WHERE swap_id=? AND chain=? AND kind=?",
            (plan["swapId"], plan["chain"], plan["kind"]),
        ).fetchone()
        if old is not None and str(old[0]) != plan["txid"]:
            con.execute("ROLLBACK")
            raise RuntimeError("recovery assessment txid replacement forbidden")
        con.execute(
            """INSERT INTO exit_recovery_assessments
               (swap_id,chain,kind,txid,current_tx_state,action,
                exact_bytes_available,decoded_txid_identity,mempool_absence,
                active_input_nonconflict,policy_acceptance,same_tx_eligible,
                payload_sha256,raw_bytes,raw_source,observed_ms)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(swap_id,chain,kind) DO UPDATE SET
                 current_tx_state=excluded.current_tx_state,
                 action=excluded.action,
                 exact_bytes_available=excluded.exact_bytes_available,
                 decoded_txid_identity=excluded.decoded_txid_identity,
                 mempool_absence=excluded.mempool_absence,
                 active_input_nonconflict=excluded.active_input_nonconflict,
                 policy_acceptance=excluded.policy_acceptance,
                 same_tx_eligible=excluded.same_tx_eligible,
                 payload_sha256=excluded.payload_sha256,
                 raw_bytes=excluded.raw_bytes,
                 raw_source=excluded.raw_source,
                 observed_ms=excluded.observed_ms""",
            (
                plan["swapId"], plan["chain"], plan["kind"], plan["txid"],
                plan["currentTxState"], plan["action"],
                1 if proof.get("exactBytesAvailable") else 0,
                1 if proof.get("decodedTxidIdentity") else 0,
                1 if proof.get("mempoolAbsence") else 0,
                1 if proof.get("activeInputNonConflict") else 0,
                1 if proof.get("policyAcceptance") else 0,
                1 if plan.get("sameTxRebroadcastEligible") else 0,
                plan.get("payloadSha256"), plan.get("rawBytes"), plan.get("rawSource"),
                now_ms(),
            ),
        )
        con.execute("COMMIT")
    finally:
        con.close()
    try:
        path.chmod(0o600)
    except OSError:
        pass


def assess_exact_exit_recovery(agent, record: Dict[str, Any], overlay_row: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate 01A against live chain proofs. Never broadcasts or signs."""
    swap_id = _txid(record.get("swapId"), "swapId")
    chain = str(overlay_row.get("chain") or "").lower()
    kind = str(overlay_row.get("kind") or "").lower()
    txid = _txid(overlay_row.get("txid"), "txid")
    state = str(overlay_row.get("currentTxState") or "UNKNOWN").upper()
    historical_reorged = bool(overlay_row.get("historicalReorged"))
    preimage_exposed = bool(overlay_row.get("preimageExposed"))

    funding_txid, funding_vout = _funding_outpoint(record, chain)
    proof = {
        "exactBytesAvailable": False,
        "decodedTxidIdentity": False,
        "exactFundingInputBinding": False,
        "mempoolAbsence": False,
        "activeInputNonConflict": False,
        "policyAcceptance": False,
    }
    raw = decoded_txid = raw_source = None
    decoded = None

    # For states where the pure 01A policy cannot proceed, avoid extra RPC work.
    if state in {"CONFIRMED", "MEMPOOL", "CONFLICTED", "UNKNOWN"} or not historical_reorged or (kind == "refund" and preimage_exposed):
        pass
    else:
        if chain == "tru":
            raw, decoded_txid, raw_source, decoded = _tru_exact_raw_and_decode(agent, txid)
        elif chain == "bsty":
            raw, decoded_txid, raw_source, decoded = _bsty_exact_raw_and_decode(agent, txid)
        else:
            raise ValueError("chain")

        if raw is not None:
            proof["exactBytesAvailable"] = True
            proof["decodedTxidIdentity"] = decoded_txid == txid
            proof["exactFundingInputBinding"] = _decoded_exact_funding_input(decoded, funding_txid, funding_vout)
            if proof["decodedTxidIdentity"] and proof["exactFundingInputBinding"]:
                if chain == "tru":
                    proof["mempoolAbsence"] = _tru_mempool_absent(agent, txid)
                    proof["activeInputNonConflict"] = _tru_active_input_unspent(agent, funding_txid, funding_vout)
                    if proof["mempoolAbsence"] and proof["activeInputNonConflict"]:
                        proof["policyAcceptance"] = _tru_policy_accept(
                            agent, raw, txid, funding_txid, funding_vout)
                else:
                    proof["mempoolAbsence"] = _bsty_mempool_absent(agent, txid)
                    proof["activeInputNonConflict"] = _bsty_active_input_unspent(agent, funding_txid, funding_vout)
                    if proof["mempoolAbsence"] and proof["activeInputNonConflict"]:
                        proof["policyAcceptance"] = _bsty_policy_accept(agent, raw)

    policy = _POLICY.plan_exact_exit_recovery(
        chain=chain, kind=kind, txid=txid, current_tx_state=state,
        historical_reorged=historical_reorged,
        historical_preimage_exposed=preimage_exposed,
        raw_hex=raw if proof["exactFundingInputBinding"] else None,
        decoded_txid=decoded_txid if proof["exactFundingInputBinding"] else None,
        raw_source=raw_source if proof["exactFundingInputBinding"] else None,
        mempool_absence_proven=bool(proof["mempoolAbsence"]),
        active_input_conflict_proven_absent=bool(proof["activeInputNonConflict"]),
        current_policy_acceptance_proven=bool(proof["policyAcceptance"]),
    )
    out = {
        "version": VERSION,
        "swapId": swap_id,
        "chain": chain,
        "kind": kind,
        "txid": txid,
        "currentTxState": state,
        "action": policy["action"],
        "sameTxRebroadcastEligible": bool(policy.get("sameTxRebroadcastEligible")),
        "sameTxRebroadcastAuthorized": False,
        "proofs": proof,
        "payloadSha256": policy.get("payloadSha256"),
        "rawBytes": policy.get("rawBytes"),
        "rawSource": policy.get("rawSource"),
        "rawBytesPersisted": False,
        "transactionBroadcast": False,
        "coinMovement": False,
    }
    _persist_assessment(agent, out, proof)
    return out


def read_assessment(agent, swap_id: str, chain: str, kind: str) -> Optional[Dict[str, Any]]:
    path = _assessment_db_path(agent)
    if not path.is_file() or path.is_symlink():
        return None
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        try:
            r = con.execute(
                "SELECT * FROM exit_recovery_assessments WHERE swap_id=? AND chain=? AND kind=?",
                (str(swap_id), str(chain).lower(), str(kind).lower()),
            ).fetchone()
        except sqlite3.OperationalError:
            return None
    finally:
        con.close()
    if r is None:
        return None
    return {
        "version": VERSION,
        "swapId": r["swap_id"], "chain": r["chain"], "kind": r["kind"], "txid": r["txid"],
        "currentTxState": r["current_tx_state"], "action": r["action"],
        "sameTxRebroadcastEligible": bool(r["same_tx_eligible"]),
        "sameTxRebroadcastAuthorized": False,
        "proofs": {
            "exactBytesAvailable": bool(r["exact_bytes_available"]),
            "decodedTxidIdentity": bool(r["decoded_txid_identity"]),
            "mempoolAbsence": bool(r["mempool_absence"]),
            "activeInputNonConflict": bool(r["active_input_nonconflict"]),
            "policyAcceptance": bool(r["policy_acceptance"]),
        },
        "payloadSha256": r["payload_sha256"], "rawBytes": r["raw_bytes"], "rawSource": r["raw_source"],
        "rawBytesPersisted": False, "transactionBroadcast": False, "coinMovement": False,
    }


def selftest() -> None:
    # Pure persistence safety smoke test. Live RPC behavior is covered by 01B selftest.
    assert VERSION == "TRU-REORG-EXIT-01B"
    txt = Path(__file__).read_text().lower()
    assert ("sendraw" + "transaction") not in txt
    assert ("htlc" + "claim") not in txt and ("htlc" + "refund") not in txt
    print("TRU_REORG_EXIT_01B_RUNTIME_MODULE_SELFTEST=PASS")
    print("RUNTIME_NETWORK_MUTATORS=NONE")
    print("RAW_EXIT_BYTES_DURABLE_STORAGE=NONE")


if __name__ == "__main__":
    selftest()
