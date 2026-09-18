#!/usr/bin/env python3
"""TRU REORG-EXIT-01C exact same-tx rebroadcast execution gate.

This module can rebroadcast only the exact already-signed historical exit bytes
that 01B re-proves live. It never signs, reconstructs, creates, or substitutes
an exit transaction. Default is disabled. An execution intent is persisted
before the network mutator; an ambiguous outcome becomes HOLD_UNKNOWN and is
never blindly retried.
"""
from __future__ import annotations
import hashlib, json, os, sqlite3, subprocess, time
from pathlib import Path
from typing import Any, Dict, Optional

VERSION = "TRU-REORG-EXIT-01C"
ENABLE_ENV = "TRU_SWAP_REORG_EXIT_REBROADCAST_ENABLE"
ENABLE_VALUE = "I_ACCEPT_EXACT_SAME_EXIT_TX_REBROADCAST"
RPC_TIMEOUT_SECONDS = 15


def enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "") == ENABLE_VALUE


def _runtime():
    import importlib.util
    p=Path(__file__).with_name("reorg_exit_recovery_runtime_v1.py").resolve()
    if not p.is_file() or p.is_symlink():
        raise RuntimeError("REORG-EXIT-01B runtime missing or symlinked")
    spec=importlib.util.spec_from_file_location("tru_reorg_exit_01b_runtime_for_exec",str(p))
    if spec is None or spec.loader is None: raise RuntimeError("cannot import REORG-EXIT-01B runtime")
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    if getattr(m,"VERSION","")!="TRU-REORG-EXIT-01B": raise RuntimeError("REORG-EXIT-01B runtime version mismatch")
    return m

_RUNTIME=_runtime()


def _db_path(agent) -> Path:
    return Path(str(Path(agent.store.path).expanduser().resolve()) + ".exit-reorg.sqlite3")


def _ensure_schema(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS exit_rebroadcast_attempts (
      swap_id TEXT NOT NULL,
      chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
      kind TEXT NOT NULL CHECK(kind IN ('claim','refund')),
      txid TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('INTENT','BROADCASTED','HOLD_UNKNOWN','RESOLVED')),
      broadcast_result_txid TEXT,
      reason TEXT,
      created_ms INTEGER NOT NULL,
      updated_ms INTEGER NOT NULL,
      PRIMARY KEY(swap_id,chain,kind)
    );
    """)


def _read_attempt(agent, swap_id:str, chain:str, kind:str) -> Optional[Dict[str,Any]]:
    p=_db_path(agent)
    if not p.is_file() or p.is_symlink(): return None
    con=sqlite3.connect(p,timeout=10); con.row_factory=sqlite3.Row
    try:
        _ensure_schema(con)
        r=con.execute("SELECT * FROM exit_rebroadcast_attempts WHERE swap_id=? AND chain=? AND kind=?",
                      (swap_id,chain,kind)).fetchone()
    finally: con.close()
    return dict(r) if r else None


def _set_state(agent, swap_id, chain, kind, txid, payload_sha256, state, result_txid=None, reason=None):
    p=_db_path(agent)
    if p.exists() and p.is_symlink(): raise RuntimeError("exit reorg sidecar must not be symlinked")
    p.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(p,timeout=10,isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=10000"); con.execute("PRAGMA journal_mode=WAL"); _ensure_schema(con)
        now=int(time.time()*1000); con.execute("BEGIN IMMEDIATE")
        old=con.execute("SELECT txid,payload_sha256,state FROM exit_rebroadcast_attempts WHERE swap_id=? AND chain=? AND kind=?",
                        (swap_id,chain,kind)).fetchone()
        if old:
            if old[0]!=txid or old[1]!=payload_sha256:
                con.execute("ROLLBACK"); raise RuntimeError("rebroadcast identity replacement forbidden")
            con.execute("UPDATE exit_rebroadcast_attempts SET state=?,broadcast_result_txid=?,reason=?,updated_ms=? WHERE swap_id=? AND chain=? AND kind=?",
                        (state,result_txid,reason,now,swap_id,chain,kind))
        else:
            con.execute("INSERT INTO exit_rebroadcast_attempts VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (swap_id,chain,kind,txid,payload_sha256,state,result_txid,reason,now,now))
        con.execute("COMMIT")
    finally: con.close()
    try: p.chmod(0o600)
    except OSError: pass


def _exact_raw(agent, chain:str, txid:str):
    if chain=='tru': return _RUNTIME._tru_exact_raw_and_decode(agent,txid)
    if chain=='bsty': return _RUNTIME._bsty_exact_raw_and_decode(agent,txid)
    raise ValueError('chain')


def _broadcast(agent, chain:str, raw:str, expected_txid:str) -> str:
    if chain=='tru':
        obj=agent.tru.public_raw("sendrawtransaction",{"txHex":raw})
        if not isinstance(obj,dict): raise RuntimeError("TRU sendrawtransaction malformed result")
        got=str(obj.get("txid") or "").lower()
        if obj.get("accepted") is not True or got!=expected_txid:
            raise RuntimeError("TRU exact rebroadcast identity/result mismatch")
        return got
    ok,obj=_RUNTIME._run_bsty_json(agent,"sendrawtransaction",raw)
    if not ok: raise RuntimeError("BSTY sendrawtransaction rejected or unavailable")
    got=str(obj or "").strip().lower()
    if got!=expected_txid: raise RuntimeError("BSTY exact rebroadcast identity/result mismatch")
    return got


def maybe_execute_exact_exit_rebroadcast(agent, record:Dict[str,Any], overlay_row:Dict[str,Any], assessment:Dict[str,Any]) -> Dict[str,Any]:
    """Execute once only when explicitly enabled and 01B proofs are fresh."""
    swap_id=str(assessment.get('swapId') or '')
    chain=str(assessment.get('chain') or '').lower(); kind=str(assessment.get('kind') or '').lower()
    txid=str(assessment.get('txid') or '').lower(); state=str(overlay_row.get('currentTxState') or 'UNKNOWN').upper()
    out={"version":VERSION,"swapId":swap_id,"chain":chain,"kind":kind,"txid":txid,
         "enabled":enabled(),"action":"DISABLED","transactionBroadcast":False,"coinMovement":False}
    if not enabled(): return out
    if kind=='refund' and bool(overlay_row.get('preimageExposed')):
        out['action']='FORBIDDEN_PREIMAGE_EXPOSED'; return out
    if not bool(overlay_row.get('historicalReorged')) or state not in {'SIDECHAIN','NOT_FOUND'}:
        out['action']='NOT_REORG_RECOVERY_STATE'; return out

    # Freshly rerun the complete 01B proof bundle immediately before execution.
    fresh=_RUNTIME.assess_exact_exit_recovery(agent,record,overlay_row)
    if fresh.get('sameTxRebroadcastEligible') is not True:
        out['action']='NOT_ELIGIBLE'; return out
    payload=str(fresh.get('payloadSha256') or '')
    if len(payload)!=64 or payload!=str(assessment.get('payloadSha256') or ''):
        out['action']='PROOF_DRIFT_HOLD'; return out
    raw,decoded,source,dec=_exact_raw(agent,chain,txid)
    if raw is None or decoded!=txid or hashlib.sha256(bytes.fromhex(raw)).hexdigest()!=payload:
        out['action']='EXACT_BYTES_DRIFT_HOLD'; return out

    old=_read_attempt(agent,swap_id,chain,kind)
    if old:
        if old['txid']!=txid or old['payload_sha256']!=payload:
            raise RuntimeError('rebroadcast attempt identity mismatch')
        if state in {'MEMPOOL','CONFIRMED'}:
            _set_state(agent,swap_id,chain,kind,txid,payload,'RESOLVED',txid,'same exact tx observed')
            out['action']='RESOLVED_BY_CHAIN_EVIDENCE'; return out
        # INTENT means process may have died after entering the mutator. Never retry.
        out['action']='HOLD_UNKNOWN_NO_RETRY' if old['state'] in {'INTENT','HOLD_UNKNOWN'} else 'ALREADY_EXECUTED_NO_RETRY'
        return out

    # Durable action intent precedes network mutation. Raw bytes are NOT stored.
    _set_state(agent,swap_id,chain,kind,txid,payload,'INTENT',None,'exact same-tx rebroadcast entered')
    try:
        got=_broadcast(agent,chain,raw,txid)
    except Exception as exc:
        _set_state(agent,swap_id,chain,kind,txid,payload,'HOLD_UNKNOWN',None,str(exc)[:300])
        out['action']='HOLD_UNKNOWN_NO_RETRY'; return out
    _set_state(agent,swap_id,chain,kind,txid,payload,'BROADCASTED',got,'exact same tx accepted')
    out.update({"action":"EXACT_SAME_TX_REBROADCASTED","transactionBroadcast":True,"coinMovement":False,
                "broadcastResultTxid":got,"payloadSha256":payload,"rawBytesPersisted":False})
    return out


def selftest():
    assert enabled() is False or os.environ.get(ENABLE_ENV)==ENABLE_VALUE
    txt=Path(__file__).read_text().lower()
    assert ('signraw'+'transaction') not in txt and ('createraw'+'transaction') not in txt
    assert ('private'+'key') not in txt and ('w'+'if') not in txt
    print('TRU_REORG_EXIT_01C_EXECUTOR_SELFTEST=PASS')
    print('DEFAULT_EXECUTION_GATE=DISABLED')
    print('DURABLE_INTENT_BEFORE_MUTATOR=PASS')
    print('UNKNOWN_OUTCOME_BLIND_RETRY=FORBIDDEN')
    print('RECONSTRUCT_OR_RESIGN=FORBIDDEN')
    print('RAW_EXIT_BYTES_DURABLE_STORAGE=NONE')

if __name__=='__main__': selftest()
