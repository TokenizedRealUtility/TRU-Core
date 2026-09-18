#!/usr/bin/env python3
"""TRU REORG-SWAP-01B — durable funding reorg observation overlay.

This module deliberately does NOT mutate the canonical funding_attempts journal.
The original funding journal remains monotonic and terminal RECORDED stays
terminal. Reorg history is stored in a separate sidecar SQLite overlay.

No RPC client, wallet, transaction builder, or broadcast primitive exists here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from reorg_funding_guard_v1 import plan_funding_reorg_recovery

VERSION = "TRU-REORG-SWAP-01B"
INTEGRATION_HARDENING = "TRU-REORG-SWAP-01C"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CHAINS = {"tru", "bsty"}
TX_STATES = {"CONFIRMED", "MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND"}

DDL = """
CREATE TABLE IF NOT EXISTS funding_reorg_overlay (
    swap_id TEXT NOT NULL,
    chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
    txid TEXT NOT NULL,
    durable_journal_state TEXT NOT NULL,
    historical_state TEXT NOT NULL CHECK(historical_state='REORGED'),
    current_tx_state TEXT NOT NULL
        CHECK(current_tx_state IN ('CONFIRMED','MEMPOOL','SIDECHAIN','CONFLICTED','NOT_FOUND')),
    action TEXT NOT NULL,
    first_reorg_ms INTEGER NOT NULL,
    last_observed_ms INTEGER NOT NULL,
    observation_count INTEGER NOT NULL CHECK(observation_count >= 1),
    last_observation_sha256 TEXT NOT NULL,
    last_block_height INTEGER,
    last_block_hash TEXT,
    conflicting_txid TEXT,
    PRIMARY KEY (swap_id, chain)
);

CREATE TABLE IF NOT EXISTS funding_reorg_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    swap_id TEXT NOT NULL,
    chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
    txid TEXT NOT NULL,
    durable_journal_state TEXT NOT NULL,
    historical_state TEXT NOT NULL CHECK(historical_state='REORGED'),
    current_tx_state TEXT NOT NULL
        CHECK(current_tx_state IN ('CONFIRMED','MEMPOOL','SIDECHAIN','CONFLICTED','NOT_FOUND')),
    action TEXT NOT NULL,
    observed_ms INTEGER NOT NULL,
    confirmations INTEGER NOT NULL CHECK(confirmations >= 0),
    block_height INTEGER,
    block_hash TEXT,
    conflicting_txid TEXT,
    observation_sha256 TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS funding_reorg_events_swap_chain_idx
    ON funding_reorg_events(swap_id, chain, event_id);
"""


def _require_hex64(name: str, value: Any) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ValueError(f"{name} must be lowercase 64-hex")
    return value


def _normalize_chain(chain: Any) -> str:
    value = str(chain or "").lower()
    if value not in CHAINS:
        raise ValueError("chain must be tru or bsty")
    return value


def _selected_evidence(tx_status: Dict[str, Any]) -> Dict[str, Any]:
    state = tx_status.get("txState")
    if state not in TX_STATES:
        raise ValueError("unsupported txState")

    confirmations = tx_status.get("confirmations")
    if not isinstance(confirmations, int) or isinstance(confirmations, bool):
        raise ValueError("confirmations must be integer")
    if confirmations < 0:
        raise ValueError("negative confirmations forbidden")

    if state == "CONFIRMED":
        height = tx_status.get("blockheight")
        block_hash = tx_status.get("blockhash")
    else:
        height = tx_status.get("sideBlockHeight")
        block_hash = tx_status.get("sideBlockHash")

    if height is not None:
        height = int(height)
        if height < 0:
            raise ValueError("negative block height")
    if block_hash is not None:
        _require_hex64("block hash", block_hash)

    conflict = tx_status.get("conflictingTxid")
    if conflict is not None:
        _require_hex64("conflicting txid", conflict)

    return {
        "txState": state,
        "confirmations": confirmations,
        "blockHeight": height,
        "blockHash": block_hash,
        "conflictingTxid": conflict,
    }


def _digest_observation(
    *,
    swap_id: str,
    chain: str,
    txid: str,
    journal_state: str,
    historical_state: str,
    action: str,
    evidence: Dict[str, Any],
) -> str:
    obj = {
        "swapId": swap_id,
        "chain": chain,
        "txid": txid,
        "journalState": journal_state,
        "historicalState": historical_state,
        "action": action,
        "evidence": evidence,
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class ReorgFundingOverlayStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(DDL)
        self.conn.commit()
        try:
            os.chmod(self.db_path, 0o600)
        except (FileNotFoundError, PermissionError):
            pass

    def close(self) -> None:
        self.conn.close()

    def get_overlay(self, swap_id: str, chain: str) -> Optional[Dict[str, Any]]:
        swap_id = _require_hex64("swap_id", swap_id)
        chain = _normalize_chain(chain)
        row = self.conn.execute(
            "SELECT * FROM funding_reorg_overlay WHERE swap_id=? AND chain=?",
            (swap_id, chain),
        ).fetchone()
        return dict(row) if row is not None else None

    def list_events(self, swap_id: str, chain: str) -> list[Dict[str, Any]]:
        swap_id = _require_hex64("swap_id", swap_id)
        chain = _normalize_chain(chain)
        rows = self.conn.execute(
            "SELECT * FROM funding_reorg_events "
            "WHERE swap_id=? AND chain=? ORDER BY event_id",
            (swap_id, chain),
        ).fetchall()
        return [dict(r) for r in rows]

    def record_observation(
        self,
        *,
        swap_id: str,
        chain: str,
        durable_row: Dict[str, Any],
        tx_status: Dict[str, Any],
        observed_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Persist reorg evidence only; never mutate funding_attempts."""
        swap_id = _require_hex64("swap_id", swap_id)
        chain = _normalize_chain(chain)
        if not isinstance(durable_row, dict):
            raise ValueError("durable_row must be dict")

        txid = _require_hex64("txid", durable_row.get("txid"))
        journal_state = str(durable_row.get("state") or "")
        evidence = _selected_evidence(tx_status)
        now_ms = int(observed_ms if observed_ms is not None else time.time() * 1000)
        if now_ms < 0:
            raise ValueError("observed_ms must be nonnegative")

        plan = plan_funding_reorg_recovery(durable_row, tx_status)

        # REORG-SWAP-01C: serialize identity check, event deduplication, and
        # latest observation projection. Repeated evidence may recur after a
        # reconfirmation; deduplication must never leave stale current status.
        with self.conn:
            self.conn.execute("BEGIN IMMEDIATE")
            existing = self.get_overlay(swap_id, chain)

            if existing is not None and existing["txid"] != txid:
                raise ValueError("overlay durable funding identity mismatch")

            # No prior reorg and still active: do not create overlay noise.
            if existing is None and plan.get("historicalState") != "REORGED":
                return {
                    "recorded": False,
                    "deduped": False,
                    "historicalState": plan.get("historicalState"),
                    "action": plan.get("action"),
                }

            # Once a reorg exists, history is permanent even if the tx reconfirms.
            if existing is not None and evidence["txState"] == "CONFIRMED":
                historical_state = "REORGED"
                action = "RECOVERED_CONFIRMED"
            else:
                historical_state = "REORGED"
                action = str(plan.get("action") or "HOLD_UNKNOWN")

            digest = _digest_observation(
                swap_id=swap_id,
                chain=chain,
                txid=txid,
                journal_state=journal_state,
                historical_state=historical_state,
                action=action,
                evidence=evidence,
            )

            prior_event = self.conn.execute(
                "SELECT event_id FROM funding_reorg_events "
                "WHERE observation_sha256=?",
                (digest,),
            ).fetchone()

            if prior_event is None:
                self.conn.execute(
                    "INSERT INTO funding_reorg_events("
                    "swap_id,chain,txid,durable_journal_state,historical_state,"
                    "current_tx_state,action,observed_ms,confirmations,"
                    "block_height,block_hash,conflicting_txid,observation_sha256"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        swap_id,
                        chain,
                        txid,
                        journal_state,
                        historical_state,
                        evidence["txState"],
                        action,
                        now_ms,
                        evidence["confirmations"],
                        evidence["blockHeight"],
                        evidence["blockHash"],
                        evidence["conflictingTxid"],
                        digest,
                    ),
                )

            current = self.conn.execute(
                "SELECT * FROM funding_reorg_overlay WHERE swap_id=? AND chain=?",
                (swap_id, chain),
            ).fetchone()

            if current is None:
                first_reorg_ms = now_ms
                observation_count = 1
                self.conn.execute(
                    "INSERT INTO funding_reorg_overlay("
                    "swap_id,chain,txid,durable_journal_state,historical_state,"
                    "current_tx_state,action,first_reorg_ms,last_observed_ms,"
                    "observation_count,last_observation_sha256,last_block_height,"
                    "last_block_hash,conflicting_txid"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        swap_id,
                        chain,
                        txid,
                        journal_state,
                        historical_state,
                        evidence["txState"],
                        action,
                        first_reorg_ms,
                        now_ms,
                        observation_count,
                        digest,
                        evidence["blockHeight"],
                        evidence["blockHash"],
                        evidence["conflictingTxid"],
                    ),
                )
            else:
                self.conn.execute(
                    "UPDATE funding_reorg_overlay SET "
                    "txid=?,durable_journal_state=?,historical_state='REORGED',"
                    "current_tx_state=?,action=?,last_observed_ms=?,"
                    "observation_count=observation_count+?,"
                    "last_observation_sha256=?,last_block_height=?,"
                    "last_block_hash=?,conflicting_txid=? "
                    "WHERE swap_id=? AND chain=?",
                    (
                        txid,
                        journal_state,
                        evidence["txState"],
                        action,
                        now_ms,
                        1 if prior_event is None else 0,
                        digest,
                        evidence["blockHeight"],
                        evidence["blockHash"],
                        evidence["conflictingTxid"],
                        swap_id,
                        chain,
                    ),
                )

            row = self.get_overlay(swap_id, chain)
            return {
                "recorded": True,
                "deduped": prior_event is not None,
                "overlay": row,
                "observationSha256": digest,
            }


def selftest() -> None:
    sid = "aa" * 32
    txid = "bb" * 32
    raw = bytes.fromhex("01020304")
    durable = {
        "state": "RECORDED",
        "txid": txid,
        "preparedTxid": txid,
        "preparedRawTxHex": raw.hex(),
        "preparedPayloadSha256": hashlib.sha256(raw).hexdigest(),
    }

    confirmed = {
        "txState": "CONFIRMED",
        "known": True,
        "active": True,
        "confirmations": 5,
        "blockheight": 100,
        "blockhash": "11" * 32,
        "reorgSignal": False,
    }
    side = {
        "txState": "SIDECHAIN",
        "known": True,
        "active": False,
        "confirmations": 0,
        "sideBlockHeight": 100,
        "sideBlockHash": "22" * 32,
        "reorgSignal": True,
        "conflicted": False,
        "conflictingTxid": None,
    }
    conflict = dict(side)
    conflict.update({
        "txState": "CONFLICTED",
        "conflicted": True,
        "conflictingTxid": "33" * 32,
    })

    with tempfile.TemporaryDirectory(prefix="tru-reorg-overlay-") as td:
        db = Path(td) / "overlay.sqlite3"
        st = ReorgFundingOverlayStore(db)

        # Stable active confirmation creates no overlay.
        r = st.record_observation(
            swap_id=sid, chain="tru", durable_row=durable,
            tx_status=confirmed, observed_ms=1000,
        )
        assert r["recorded"] is False
        assert st.get_overlay(sid, "tru") is None
        assert st.list_events(sid, "tru") == []

        # First non-active observation makes REORGED durable.
        r = st.record_observation(
            swap_id=sid, chain="tru", durable_row=durable,
            tx_status=side, observed_ms=2000,
        )
        assert r["recorded"] is True and r["deduped"] is False
        ov = r["overlay"]
        assert ov["historical_state"] == "REORGED"
        assert ov["current_tx_state"] == "SIDECHAIN"
        assert ov["first_reorg_ms"] == 2000
        assert ov["observation_count"] == 1

        # Same exact evidence is idempotent.
        r = st.record_observation(
            swap_id=sid, chain="tru", durable_row=durable,
            tx_status=side, observed_ms=3000,
        )
        assert r["deduped"] is True
        assert r["overlay"]["observation_count"] == 1
        assert len(st.list_events(sid, "tru")) == 1

        # Conflict is new durable evidence, first reorg timestamp is preserved.
        r = st.record_observation(
            swap_id=sid, chain="tru", durable_row=durable,
            tx_status=conflict, observed_ms=4000,
        )
        ov = r["overlay"]
        assert ov["current_tx_state"] == "CONFLICTED"
        assert ov["action"] == "HOLD_REORG_CONFLICT"
        assert ov["conflicting_txid"] == "33" * 32
        assert ov["first_reorg_ms"] == 2000
        assert ov["observation_count"] == 2

        # Reconfirmation never erases historical reorg.
        r = st.record_observation(
            swap_id=sid, chain="tru", durable_row=durable,
            tx_status=confirmed, observed_ms=5000,
        )
        ov = r["overlay"]
        assert ov["historical_state"] == "REORGED"
        assert ov["current_tx_state"] == "CONFIRMED"
        assert ov["action"] == "RECOVERED_CONFIRMED"
        assert ov["observation_count"] == 3

        # Reopen proves durability.
        st.close()
        st = ReorgFundingOverlayStore(db)
        ov = st.get_overlay(sid, "tru")
        assert ov["historical_state"] == "REORGED"
        assert ov["observation_count"] == 3
        assert len(st.list_events(sid, "tru")) == 3

        # Overlay DB never owns or mutates canonical funding_attempts.
        tables = {
            r[0] for r in st.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "funding_attempts" not in tables

        cols = []
        for table in ("funding_reorg_overlay", "funding_reorg_events"):
            cols.extend(
                r[1].lower()
                for r in st.conn.execute(f"PRAGMA table_info({table})").fetchall()
            )
        for forbidden in (
            "preimage", "privkey", "private", "wif", "passphrase",
            "rpc_token", "raw_tx", "rawtx",
        ):
            assert all(forbidden not in c for c in cols)

        st.close()

    print("TRU_REORG_SWAP_01B_SELFTEST=PASS")
    print("CANONICAL_FUNDING_JOURNAL_MUTATION=NONE")
    print("RECORDED_TERMINAL_STATE=PRESERVED")
    print("REORG_HISTORY=SEPARATE_DURABLE_OVERLAY")
    print("REORG_EVENT_DEDUPLICATION=PASS")
    print("RECONFIRMATION_DOES_NOT_ERASE_REORG_HISTORY=PASS")
    print("PRIVATE_FIELDS_IN_OVERLAY=NONE")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not args.selftest:
        raise SystemExit("This module is a library; run with --selftest only.")
    selftest()


if __name__ == "__main__":
    main()

