#!/usr/bin/env python3
"""TRU REORG-EXIT-01 durable resolution-history sidecar.

This module stores only public resolution transaction identity/state metadata.
It never stores preimages, private keys, raw signed transactions, passwords,
or wallet/RPC credentials. Canonical TRU swap records and Agent exit watcher
rows remain authoritative and are never rewritten by this overlay.
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

VERSION = "TRU-REORG-EXIT-01"
TX_STATES = {"CONFIRMED", "MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND", "UNKNOWN"}
CHAINS = {"tru", "bsty"}
KINDS = {"claim", "refund"}
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
REORG_STATES = {"MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND"}


def now_ms() -> int:
    return int(time.time() * 1000)


def sidecar_path(agent_db_path: Path | str) -> Path:
    main = Path(agent_db_path).expanduser().resolve()
    p = Path(str(main) + ".exit-reorg.sqlite3")
    if p == main:
        raise ValueError("exit reorg sidecar aliases Agent database")
    funding = Path(str(main) + ".funding-reorg.sqlite3")
    if p == funding:
        raise ValueError("exit reorg sidecar aliases funding reorg sidecar")
    return p


class ExitReorgOverlay:
    def __init__(self, agent_db_path: Path | str):
        self.agent_db_path = Path(agent_db_path).expanduser().resolve()
        self.path = sidecar_path(self.agent_db_path)
        self._ensure_path_safe()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _ensure_path_safe(self) -> None:
        if self.path.exists() and self.path.is_symlink():
            raise ValueError("exit reorg sidecar must not be a symlink")
        if self.agent_db_path.exists():
            try:
                if self.path.exists() and os.path.samefile(self.agent_db_path, self.path):
                    raise ValueError("exit reorg sidecar aliases Agent database")
            except FileNotFoundError:
                pass
        funding = Path(str(self.agent_db_path) + ".funding-reorg.sqlite3")
        if funding.exists() and self.path.exists():
            try:
                if os.path.samefile(funding, self.path):
                    raise ValueError("exit reorg sidecar aliases funding reorg sidecar")
            except FileNotFoundError:
                pass

    def connect(self):
        self._ensure_path_safe()
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=10000")
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def _ensure_schema(self) -> None:
        with self.connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS exit_reorg_overlay (
                    swap_id TEXT NOT NULL,
                    chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
                    kind TEXT NOT NULL CHECK(kind IN ('claim','refund')),
                    txid TEXT NOT NULL,
                    historical_confirmations INTEGER NOT NULL CHECK(historical_confirmations >= 0),
                    current_tx_state TEXT NOT NULL CHECK(current_tx_state IN (
                        'CONFIRMED','MEMPOOL','SIDECHAIN','CONFLICTED','NOT_FOUND','UNKNOWN'
                    )),
                    current_confirmations INTEGER NOT NULL CHECK(current_confirmations >= 0),
                    historical_reorged INTEGER NOT NULL CHECK(historical_reorged IN (0,1)),
                    preimage_exposed INTEGER NOT NULL CHECK(preimage_exposed IN (0,1)),
                    first_observed_ms INTEGER NOT NULL,
                    last_observed_ms INTEGER NOT NULL,
                    PRIMARY KEY(swap_id,chain,kind)
                );
                CREATE TABLE IF NOT EXISTS exit_reorg_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    swap_id TEXT NOT NULL,
                    chain TEXT NOT NULL CHECK(chain IN ('tru','bsty')),
                    kind TEXT NOT NULL CHECK(kind IN ('claim','refund')),
                    txid TEXT NOT NULL,
                    from_tx_state TEXT,
                    to_tx_state TEXT NOT NULL,
                    confirmations INTEGER NOT NULL CHECK(confirmations >= 0),
                    observed_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS exit_reorg_events_swap_idx
                    ON exit_reorg_events(swap_id,seq);
                """
            )

    @staticmethod
    def _validate(swap_id: str, chain: str, kind: str, txid: str,
                  tx_state: str, current_confirmations: int,
                  historical_confirmations: int) -> tuple[str, str, str, str, str, int, int]:
        swap_id = str(swap_id)
        chain = str(chain).lower()
        kind = str(kind).lower()
        txid = str(txid).lower()
        tx_state = str(tx_state).upper()
        current_confirmations = int(current_confirmations)
        historical_confirmations = int(historical_confirmations)
        if not TXID_RE.fullmatch(swap_id):
            raise ValueError("swapId")
        if chain not in CHAINS:
            raise ValueError("chain")
        if kind not in KINDS:
            raise ValueError("kind")
        if not TXID_RE.fullmatch(txid):
            raise ValueError("txid")
        if tx_state not in TX_STATES:
            raise ValueError("txState")
        if current_confirmations < 0 or historical_confirmations < 0:
            raise ValueError("confirmations")
        if tx_state != "CONFIRMED" and current_confirmations != 0:
            raise ValueError("non-confirmed state must report zero confirmations")
        if tx_state == "CONFIRMED" and current_confirmations < 1:
            raise ValueError("confirmed state requires confirmations")
        return (swap_id, chain, kind, txid, tx_state,
                current_confirmations, historical_confirmations)

    def observe(self, swap_id: str, chain: str, kind: str, txid: str,
                tx_state: str, current_confirmations: int = 0,
                historical_confirmations: int = 0) -> Dict[str, Any]:
        (swap_id, chain, kind, txid, tx_state,
         current_confirmations, historical_confirmations) = self._validate(
            swap_id, chain, kind, txid, tx_state,
            current_confirmations, historical_confirmations,
        )
        t = now_ms()
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            old = c.execute(
                "SELECT * FROM exit_reorg_overlay WHERE swap_id=? AND chain=? AND kind=?",
                (swap_id, chain, kind),
            ).fetchone()
            if old is not None and str(old["txid"]) != txid:
                c.execute("ROLLBACK")
                raise ValueError("resolution transaction identity replacement forbidden")

            prior_state = None if old is None else str(old["current_tx_state"])
            prior_hist = 0 if old is None else int(old["historical_confirmations"])
            prior_reorg = 0 if old is None else int(old["historical_reorged"])
            prior_exposure = 0 if old is None else int(old["preimage_exposed"])
            hist_conf = max(prior_hist, historical_confirmations, current_confirmations)
            exposure = 1 if kind == "claim" or prior_exposure else 0
            historical_was_confirmed = hist_conf > 0
            reorged = 1 if prior_reorg or (historical_was_confirmed and tx_state in REORG_STATES) else 0

            if old is None:
                c.execute(
                    """INSERT INTO exit_reorg_overlay
                       (swap_id,chain,kind,txid,historical_confirmations,current_tx_state,
                        current_confirmations,historical_reorged,preimage_exposed,
                        first_observed_ms,last_observed_ms)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (swap_id, chain, kind, txid, hist_conf, tx_state,
                     current_confirmations, reorged, exposure, t, t),
                )
            else:
                c.execute(
                    """UPDATE exit_reorg_overlay SET
                       historical_confirmations=?,current_tx_state=?,current_confirmations=?,
                       historical_reorged=?,preimage_exposed=?,last_observed_ms=?
                       WHERE swap_id=? AND chain=? AND kind=?""",
                    (hist_conf, tx_state, current_confirmations, reorged, exposure, t,
                     swap_id, chain, kind),
                )

            if old is None or prior_state != tx_state:
                c.execute(
                    """INSERT INTO exit_reorg_events
                       (swap_id,chain,kind,txid,from_tx_state,to_tx_state,confirmations,observed_ms)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (swap_id, chain, kind, txid, prior_state, tx_state,
                     current_confirmations, t),
                )
            row = c.execute(
                "SELECT * FROM exit_reorg_overlay WHERE swap_id=? AND chain=? AND kind=?",
                (swap_id, chain, kind),
            ).fetchone()
            c.execute("COMMIT")
        return self._row(row)

    @staticmethod
    def _row(r: sqlite3.Row) -> Dict[str, Any]:
        return {
            "swapId": r["swap_id"],
            "chain": r["chain"],
            "kind": r["kind"],
            "txid": r["txid"],
            "historicalConfirmations": int(r["historical_confirmations"]),
            "currentTxState": r["current_tx_state"],
            "currentConfirmations": int(r["current_confirmations"]),
            "historicalReorged": bool(r["historical_reorged"]),
            "preimageExposed": bool(r["preimage_exposed"]),
            "firstObservedMs": int(r["first_observed_ms"]),
            "lastObservedMs": int(r["last_observed_ms"]),
        }

    def get(self, swap_id: str, chain: str, kind: str) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            r = c.execute(
                "SELECT * FROM exit_reorg_overlay WHERE swap_id=? AND chain=? AND kind=?",
                (str(swap_id), str(chain).lower(), str(kind).lower()),
            ).fetchone()
        return None if r is None else self._row(r)

    def list_swap(self, swap_id: str) -> list[Dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT * FROM exit_reorg_overlay WHERE swap_id=? ORDER BY chain,kind",
                (str(swap_id),),
            ).fetchall()
        return [self._row(r) for r in rows]

    def preimage_exposed(self, swap_id: str) -> bool:
        with self.connect() as c:
            r = c.execute(
                "SELECT 1 FROM exit_reorg_overlay WHERE swap_id=? AND preimage_exposed=1 LIMIT 1",
                (str(swap_id),),
            ).fetchone()
        return r is not None

    def event_count(self, swap_id: str) -> int:
        with self.connect() as c:
            r = c.execute(
                "SELECT COUNT(*) AS n FROM exit_reorg_events WHERE swap_id=?",
                (str(swap_id),),
            ).fetchone()
        return int(r["n"])

    def status(self) -> Dict[str, Any]:
        with self.connect() as c:
            r = c.execute(
                """SELECT COUNT(*) AS rows,
                          COALESCE(SUM(historical_reorged),0) AS reorged,
                          COALESCE(SUM(preimage_exposed),0) AS exposed
                   FROM exit_reorg_overlay"""
            ).fetchone()
        return {
            "version": VERSION,
            "sidecar": str(self.path),
            "rows": int(r["rows"]),
            "historicalReorgedRows": int(r["reorged"]),
            "preimageExposureRows": int(r["exposed"]),
            "privateMaterialStored": False,
        }


def selftest() -> None:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="tru-reorg-exit-overlay-") as td:
        main = Path(td) / "agent.sqlite3"
        main.write_bytes(b"")
        o = ExitReorgOverlay(main)
        sid = "11" * 32
        txid = "22" * 32
        a = o.observe(sid, "tru", "claim", txid, "CONFIRMED", 3, 3)
        assert a["preimageExposed"] is True and a["historicalReorged"] is False
        b = o.observe(sid, "tru", "claim", txid, "SIDECHAIN", 0, 3)
        assert b["preimageExposed"] is True and b["historicalReorged"] is True
        c = o.observe(sid, "tru", "claim", txid, "CONFIRMED", 1, 3)
        assert c["historicalReorged"] is True and o.event_count(sid) == 3
        o.observe(sid, "tru", "claim", txid, "CONFIRMED", 2, 3)
        assert o.event_count(sid) == 3
        try:
            o.observe(sid, "tru", "claim", "33" * 32, "CONFIRMED", 1, 1)
        except ValueError:
            pass
        else:
            raise AssertionError("identity replacement accepted")
        assert o.preimage_exposed(sid) is True
        assert not any("preimage" in k.lower() and k != "preimageExposed" for k in a)
    print("TRU_REORG_EXIT_01_OVERLAY_SELFTEST=PASS")
    print("PREIMAGE_EXPOSURE_PERMANENT_FLAG=PASS")
    print("RECONFIRMATION_DOES_NOT_ERASE_REORG_HISTORY=PASS")
    print("RESOLUTION_TX_IDENTITY_REPLACEMENT=FORBIDDEN")
    print("PRIVATE_SECRET_MATERIAL_STORED=NO")


if __name__ == "__main__":
    selftest()
