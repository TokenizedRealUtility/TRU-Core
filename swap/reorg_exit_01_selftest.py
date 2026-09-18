#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    p = HERE / filename
    spec = importlib.util.spec_from_file_location(name, str(p))
    if spec is None or spec.loader is None:
        raise RuntimeError("import failure: " + filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ov = load("reorg_exit_overlay_test", "reorg_exit_overlay_v1.py")
ew = load("exit_watcher_reorg_test", "exit_watcher_v1.py")


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self):
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        return con


class Agent:
    def __init__(self, store, record):
        self.store = store
        self.record = record

    def get_live_record(self, swap_id):
        assert swap_id == self.record["swapId"]
        return json.loads(json.dumps(self.record))


def insert_job(store, sid, state="COMPLETE", give="tru", get="bsty"):
    ew.ensure_schema(store)
    t = int(time.time() * 1000)
    claim = {"chain": get, "source": "external", "address": "claim-destination"}
    refund = {"chain": give, "source": "external", "address": "refund-destination"}
    with store.connect() as c:
        c.execute(
            """INSERT INTO exit_watchers
               (swap_id,give_chain,get_chain,min_conf,claim_destination_json,refund_destination_json,
                claim_authorization_id,refund_authorization_id,bsty_signer_address,state,
                action_kind,action_chain,action_txid,last_error,created_ms,updated_ms)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, give, get, 1, json.dumps(claim), json.dumps(refund),
             "aa" * 32, "bb" * 32, None, state,
             "claim" if state == "COMPLETE" else None,
             get if state == "COMPLETE" else None,
             "99" * 32 if state == "COMPLETE" else None,
             None, t, t),
        )


def main():
    assert ew.REORG_VERSION == "TRU-REORG-EXIT-01"
    assert ov.VERSION == "TRU-REORG-EXIT-01"
    sid = "11" * 32
    tru_claim = "21" * 32
    bsty_claim = "22" * 32
    tru_refund = "23" * 32
    bsty_refund = "24" * 32

    with tempfile.TemporaryDirectory(prefix="tru-reorg-exit-01-") as td:
        store = Store(Path(td) / "agent.sqlite3")
        insert_job(store, sid, "COMPLETE")
        record = {
            "swapId": sid,
            "state": "SETTLED",
            "secretHash160": "12" * 20,
            "truRefundTime": int(time.time()) + 3600,
            "bstyRefundTime": int(time.time()) + 3600,
            "evidence": {
                "truFundingTxid": "31" * 32,
                "bstyFundingTxid": "32" * 32,
                "truClaimTxid": tru_claim,
                "truClaimConfirmations": 4,
                "bstyClaimTxid": bsty_claim,
                "bstyClaimConfirmations": 3,
                "truRefundTxid": tru_refund,
                "truRefundConfirmations": 2,
                "bstyRefundTxid": bsty_refund,
                "bstyRefundConfirmations": 2,
            },
        }
        agent = Agent(store, record)
        states = {
            ("tru", tru_claim): {"txState": "CONFIRMED", "confirmations": 4},
            ("bsty", bsty_claim): {"txState": "CONFIRMED", "confirmations": 3},
            ("tru", tru_refund): {"txState": "CONFIRMED", "confirmations": 2},
            ("bsty", bsty_refund): {"txState": "CONFIRMED", "confirmations": 2},
        }
        old_status = ew._resolution_status
        ew._resolution_status = lambda agent_, chain, txid: dict(states[(chain, txid)])
        try:
            jobs = ew.list_observation_jobs(store)
            assert len(jobs) == 1 and jobs[0]["state"] == "COMPLETE"
            # Observation must run even while the money-mutator enable gate is OFF.
            prior_enable = os.environ.pop(ew.ENABLE_ENV, None)
            try:
                passive = ew.observe_tick(agent)
                assert passive["checked"] == 1 and passive["moneyMutation"] is False
            finally:
                if prior_enable is not None:
                    os.environ[ew.ENABLE_ENV] = prior_enable
            before = ew.get_job(store, sid)
            ew.tick_one(agent, before)
            after = ew.get_job(store, sid)
            assert after["state"] == "COMPLETE"
            overlay = ov.ExitReorgOverlay(store.path)
            rows = overlay.list_swap(sid)
            assert len(rows) == 4
            assert sum(1 for x in rows if x["kind"] == "claim" and x["preimageExposed"]) == 2

            # Reorg the TRU claim. History and exposure must remain monotonic.
            states[("tru", tru_claim)] = {"txState": "SIDECHAIN", "confirmations": 0}
            ew.tick_one(agent, ew.get_job(store, sid))
            r = overlay.get(sid, "tru", "claim")
            assert r["historicalReorged"] is True
            assert r["preimageExposed"] is True
            reorg_events = overlay.event_count(sid)

            # Reconfirm, then reorg the same exact claim again. Historical state stays true.
            states[("tru", tru_claim)] = {"txState": "CONFIRMED", "confirmations": 1}
            ew.tick_one(agent, ew.get_job(store, sid))
            states[("tru", tru_claim)] = {"txState": "SIDECHAIN", "confirmations": 0}
            ew.tick_one(agent, ew.get_job(store, sid))
            r2 = overlay.get(sid, "tru", "claim")
            assert r2["historicalReorged"] is True and r2["preimageExposed"] is True
            assert overlay.event_count(sid) >= reorg_events + 2

            # Canonical exit watcher completion is never moved backward by the sidecar.
            assert ew.get_job(store, sid)["state"] == "COMPLETE"
        finally:
            ew._resolution_status = old_status

    # Refund must fail closed from durable exposure even if a later record view
    # contains no claim field at all.
    with tempfile.TemporaryDirectory(prefix="tru-reorg-exit-refund-") as td:
        store = Store(Path(td) / "agent.sqlite3")
        insert_job(store, sid, "ARMED", give="tru", get="bsty")
        overlay = ov.ExitReorgOverlay(store.path)
        overlay.observe(sid, "tru", "claim", tru_claim, "SIDECHAIN", 0, 1)
        record = {
            "swapId": sid,
            "state": "REFUND_PENDING",
            "secretHash160": "12" * 20,
            "truRefundTime": int(time.time()) - 1,
            "bstyRefundTime": int(time.time()) + 3600,
            "evidence": {"truFundingTxid": "31" * 32},
        }
        agent = Agent(store, record)
        mutator_called = {"v": False}
        old_invoke = ew._invoke_exit
        old_status = ew._resolution_status
        ew._invoke_exit = lambda *a, **k: mutator_called.__setitem__("v", True) or ("88" * 32)
        ew._resolution_status = lambda *a, **k: {"txState": "UNKNOWN", "confirmations": 0}
        old_enable = os.environ.get(ew.ENABLE_ENV)
        os.environ[ew.ENABLE_ENV] = "1"
        try:
            out = ew.tick_one(agent, ew.get_job(store, sid))
            assert out["state"] == "HOLD_UNKNOWN"
            assert mutator_called["v"] is False
            assert "preimage exposure" in (out["lastError"] or "")
        finally:
            ew._invoke_exit = old_invoke
            ew._resolution_status = old_status
            if old_enable is None:
                os.environ.pop(ew.ENABLE_ENV, None)
            else:
                os.environ[ew.ENABLE_ENV] = old_enable

    # Sidecar module must contain no money-mutating RPC vocabulary and no secret storage fields.
    text = (HERE / "reorg_exit_overlay_v1.py").read_text().lower()
    for forbidden in ("sendrawtransaction", "htlcbroadcastprepared", "preimage_hex", "private_key", "wif"):
        assert forbidden not in text

    print("TRU_REORG_EXIT_01_SELFTEST=PASS")
    print("TRU_BSTY_CLAIM_REFUND_FOUR_WAY_OBSERVATION=PASS")
    print("COMPLETE_EXIT_WATCHERS_REMAIN_OBSERVED=PASS")
    print("PASSIVE_REORG_OBSERVER_INDEPENDENT_OF_MONEY_ENABLE_GATE=PASS")
    print("CANONICAL_EXIT_WATCHER_STATE_MUTATION_BY_REORG=NONE")
    print("PREIMAGE_EXPOSURE_PERMANENCE=PASS")
    print("CLAIM_REORG_RECONFIRM_REORG_HISTORY=PASS")
    print("HISTORICAL_EXPOSURE_REFUND_PATH=HOLD_UNKNOWN")
    print("OPPOSITE_PATH_MUTATOR_AFTER_EXPOSURE=FORBIDDEN")
    print("AUTOMATIC_REBROADCAST=NO")
    print("FRESH_EXIT_TRANSACTION_AFTER_REORG=NO")
    print("PRIVATE_SECRET_MATERIAL_IN_SIDECAR=NONE")
    print("SAME_TX_REBROADCAST=DEFERRED_NOT_AUTHORIZED")


if __name__ == "__main__":
    main()
