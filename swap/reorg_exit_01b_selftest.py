#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def load(name: str, filename: str):
    p = HERE / filename
    spec = importlib.util.spec_from_file_location(name, str(p))
    if spec is None or spec.loader is None:
        raise RuntimeError("import failure: " + filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Store:
    def __init__(self, path: Path):
        self.path = str(path)


class Tru:
    def __init__(self, *, txid: str, funding_txid: str, funding_vout: int, raw: str,
                 mode: str = "sidechain", forbid_calls: bool = False):
        self.txid = txid
        self.funding_txid = funding_txid
        self.funding_vout = funding_vout
        self.raw = raw
        self.mode = mode
        self.forbid_calls = forbid_calls
        self.calls = []

    def public_raw(self, method, params=None):
        if self.forbid_calls:
            raise AssertionError("live recovery RPC should not run for fail-closed path")
        self.calls.append((method, dict(params or {})))
        if method == "gettransaction":
            if self.mode == "not_found":
                return {"txState": "NOT_FOUND", "confirmations": 0}
            return {"txState": "SIDECHAIN", "confirmations": 0, "hex": self.raw}
        if method == "decoderawtransaction":
            return {"txid": self.txid, "vin": [{"txid": self.funding_txid, "vout": self.funding_vout}]}
        if method == "getrawmempool":
            return []
        if method == "gettxout":
            return {"txid": self.funding_txid, "n": self.funding_vout, "amount_atoms": 123}
        if method == "swaptestexitmempoolaccept":
            assert params["txHex"] == self.raw
            assert params["expectedTxid"] == self.txid
            assert params["fundingTxid"] == self.funding_txid
            assert int(params["fundingVout"]) == self.funding_vout
            return {"version": "TRU-REORG-EXIT-01B", "allowed": True, "readOnly": True,
                    "transactionBroadcast": False, "mempoolMutation": False}
        raise AssertionError("unexpected TRU RPC " + method)


class Bsty:
    def __init__(self):
        self.cli = "/synthetic/bsty-cli"
        self.wallet = "synthetic"


class Agent:
    def __init__(self, db: Path, tru: Tru):
        self.store = Store(db)
        self.tru = tru
        self.bsty = Bsty()


def row(chain: str, kind: str, txid: str, state: str, *, reorged=True, exposed=False):
    return {
        "chain": chain, "kind": kind, "txid": txid,
        "currentTxState": state,
        "historicalReorged": reorged,
        "preimageExposed": exposed,
    }


def main() -> None:
    rt = load("reorg_exit_01b_runtime_test", "reorg_exit_recovery_runtime_v1.py")
    policy = load("reorg_exit_01b_policy_test", "reorg_exit_recovery_v1.py")
    assert rt.VERSION == "TRU-REORG-EXIT-01B"
    assert policy.VERSION == "TRU-REORG-EXIT-01A"

    swap_id = "11" * 32
    tru_funding = "22" * 32
    bsty_funding = "33" * 32
    tru_exit = "44" * 32
    bsty_exit = "55" * 32
    # Large distinctive ephemeral byte sequence. It must not be persisted.
    tru_raw = "0200000001" + "a7" * 160
    bsty_raw = "0300000001" + "b8" * 160
    record = {
        "swapId": swap_id,
        "evidence": {
            "truFundingTxid": tru_funding, "truFundingVout": 7,
            "bstyFundingTxid": bsty_funding, "bstyFundingVout": 9,
        },
    }

    with tempfile.TemporaryDirectory(prefix="tru-reorg-exit-01b-") as td:
        db = Path(td) / "agent.sqlite3"
        agent = Agent(db, Tru(txid=tru_exit, funding_txid=tru_funding,
                              funding_vout=7, raw=tru_raw))

        # TRU sidechain exact bytes + exact input + all three live proofs => eligible.
        p = rt.assess_exact_exit_recovery(
            agent, record, row("tru", "claim", tru_exit, "SIDECHAIN", exposed=True))
        assert p["sameTxRebroadcastEligible"] is True
        assert p["sameTxRebroadcastAuthorized"] is False
        assert p["action"] == "SAME_TX_REBROADCAST_ELIGIBLE_POLICY_ONLY"
        for k in ("exactBytesAvailable", "decodedTxidIdentity", "exactFundingInputBinding",
                  "mempoolAbsence", "activeInputNonConflict", "policyAcceptance"):
            assert p["proofs"][k] is True, k
        methods = [x[0] for x in agent.tru.calls]
        assert methods == ["gettransaction", "decoderawtransaction", "getrawmempool",
                           "gettxout", "swaptestexitmempoolaccept"]

        stored = rt.read_assessment(agent, swap_id, "tru", "claim")
        assert stored and stored["sameTxRebroadcastEligible"] is True
        assert stored["sameTxRebroadcastAuthorized"] is False
        assert stored["rawBytesPersisted"] is False

        # NOT_FOUND without live exact raw bytes is a hard HOLD; no reconstruction.
        agent_nf = Agent(Path(td) / "nf.sqlite3",
                         Tru(txid=tru_exit, funding_txid=tru_funding,
                             funding_vout=7, raw=tru_raw, mode="not_found"))
        q = rt.assess_exact_exit_recovery(
            agent_nf, record, row("tru", "claim", tru_exit, "NOT_FOUND", exposed=True))
        assert q["sameTxRebroadcastEligible"] is False
        assert q["action"] == "HOLD_EXACT_BYTES_UNAVAILABLE_OR_MISMATCH"
        assert [x[0] for x in agent_nf.tru.calls] == ["gettransaction"]

        # CONFLICTED never invokes recovery probing.
        agent_conflict = Agent(Path(td) / "conflict.sqlite3",
                               Tru(txid=tru_exit, funding_txid=tru_funding,
                                   funding_vout=7, raw=tru_raw, forbid_calls=True))
        c = rt.assess_exact_exit_recovery(
            agent_conflict, record, row("tru", "claim", tru_exit, "CONFLICTED", exposed=True))
        assert c["action"] == "HOLD_ACTIVE_INPUT_CONFLICT"
        assert c["sameTxRebroadcastEligible"] is False

        # Permanent preimage exposure forbids refund recovery before any proof RPC.
        agent_refund = Agent(Path(td) / "refund.sqlite3",
                             Tru(txid=tru_exit, funding_txid=tru_funding,
                                 funding_vout=7, raw=tru_raw, forbid_calls=True))
        r = rt.assess_exact_exit_recovery(
            agent_refund, record, row("tru", "refund", tru_exit, "SIDECHAIN", exposed=True))
        assert r["action"] == "HOLD_REFUND_FORBIDDEN_AFTER_PREIMAGE_EXPOSURE"
        assert r["sameTxRebroadcastEligible"] is False

        # BSTY parity: exact wallet bytes + decode + mempool/input/policy proofs.
        calls = []
        old = rt._run_bsty_json
        def fake_bsty(_agent, method, *args, wallet=False):
            calls.append((method, args, wallet))
            if method == "gettransaction":
                return True, {"hex": bsty_raw}
            if method == "decoderawtransaction":
                return True, {"txid": bsty_exit,
                              "vin": [{"txid": bsty_funding, "vout": 9}]}
            if method == "getrawmempool":
                return True, []
            if method == "gettxout":
                return True, {"txid": bsty_funding, "n": 9, "value": 1.0}
            if method == "testmempoolaccept":
                return True, [{"txid": bsty_exit, "allowed": True}]
            raise AssertionError("unexpected BSTY RPC " + method)
        rt._run_bsty_json = fake_bsty
        try:
            agent_b = Agent(Path(td) / "bsty.sqlite3",
                            Tru(txid=tru_exit, funding_txid=tru_funding,
                                funding_vout=7, raw=tru_raw, forbid_calls=True))
            b = rt.assess_exact_exit_recovery(
                agent_b, record, row("bsty", "claim", bsty_exit, "SIDECHAIN", exposed=True))
            assert b["sameTxRebroadcastEligible"] is True
            assert b["sameTxRebroadcastAuthorized"] is False
            assert [x[0] for x in calls] == ["gettransaction", "decoderawtransaction",
                                             "getrawmempool", "gettxout", "testmempoolaccept"]
        finally:
            rt._run_bsty_json = old

        # Durable storage is metadata-only. Raw signed exit bytes never enter DB/WAL.
        for pth in Path(td).glob("*.exit-reorg.sqlite3*"):
            blob = pth.read_bytes()
            assert tru_raw.encode() not in blob
            assert bsty_raw.encode() not in blob
        con = sqlite3.connect(str(db) + ".exit-reorg.sqlite3")
        try:
            cols = {x[1] for x in con.execute("PRAGMA table_info(exit_recovery_assessments)")}
        finally:
            con.close()
        assert "raw_hex" not in cols and "preimage" not in cols and "private_key" not in cols

    # C++ RPC must remain an explicit read-only probe and must not invoke mutators.
    rpc = ROOT / "src" / "rpc_server.cpp"
    assert rpc.is_file()
    text = rpc.read_text()
    start = text.index("static json handleSwapTestExitMempoolAccept")
    end = text.index("//========================\n// List transactions", start)
    handler = text[start:end]
    assert '"readOnly", true' in handler
    assert '"transactionBroadcast", false' in handler
    assert "validateTransaction" in handler
    for forbidden in ("addTransaction(", "sendRawTransaction", "broadcastTransaction",
                      "handleHtlcClaim", "handleHtlcRefund"):
        assert forbidden not in handler, forbidden
    assert 'm=="swaptestexitmempoolaccept"' in text

    # Runtime and watcher must not contain any transaction broadcast/re-sign primitive.
    runtime_text = (HERE / "reorg_exit_recovery_runtime_v1.py").read_text().lower()
    watcher_text = (HERE / "exit_watcher_v1.py").read_text().lower()
    assert ("sendraw" + "transaction") not in runtime_text
    assert ("htlc" + "claim") not in runtime_text
    assert ("htlc" + "refund") not in runtime_text
    assert "sametxrebroadcastauthorized\": false" in watcher_text.replace(" ", "") or \
           '"sametxrebroadcastauthorized": false' in watcher_text

    print("TRU_REORG_EXIT_01B_SELFTEST=PASS")
    print("TRU_READ_ONLY_EXIT_POLICY_RPC=PASS")
    print("TRU_BSTY_RECOVERY_PROOF_PARITY=PASS")
    print("EXACT_LIVE_RAW_BYTES_EPHEMERAL_ONLY=PASS")
    print("NODE_DECODED_TXID_IDENTITY=PASS")
    print("EXACT_FUNDING_OUTPOINT_BINDING=PASS")
    print("MEMPOOL_ABSENCE_PROOF=PASS")
    print("ACTIVE_INPUT_NONCONFLICT_PROOF=PASS")
    print("CURRENT_POLICY_ACCEPTANCE_PROOF=PASS")
    print("NOT_FOUND_WITHOUT_EXACT_BYTES=HOLD")
    print("CONFLICTED_RECOVERY=FORBIDDEN")
    print("REFUND_AFTER_HISTORICAL_PREIMAGE_EXPOSURE=FORBIDDEN")
    print("RECOVERY_SIDECAR_RAW_BYTES=NONE")
    print("SAME_TX_REBROADCAST_ELIGIBILITY=LIVE_PROVEN_POLICY_ONLY")
    print("SAME_TX_REBROADCAST_AUTHORIZED=NO")
    print("AUTOMATIC_REBROADCAST=NO")
    print("COIN_MOVEMENT=NO")


if __name__ == "__main__":
    main()
