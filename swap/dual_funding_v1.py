#!/usr/bin/env python3
"""TRU SWAP GROUP-03 — dual-chain exact prepared funding activation.

This module is the ONLY Group-03 money-mutation layer.

Safety properties:
- disabled unless TRU_SWAP_DUAL_FUNDING_ENABLE=1
- never constructs a replacement funding transaction
- TRU broadcasts only the exact durable transaction already bound by GROUP-01
- BSTY broadcasts only the exact durable transaction already bound by GROUP-02
- journal enters BROADCASTING before the one broadcast primitive
- crash retry reuses the same durable txid/raw bytes
- canonical SWAP-A evidence is recorded only after confirmed exact funding
- no private key, WIF, passphrase, preimage, or raw transaction is returned
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict

VERSION = "TRU-SWAP-DUAL-FUNDING-V1"
ENABLE_ENV = "TRU_SWAP_DUAL_FUNDING_ENABLE"
TXID_RE = re.compile(r"^[0-9a-f]{64}$")


def enabled() -> bool:
    return os.environ.get(ENABLE_ENV, "") == "1"


def require_enabled() -> None:
    if not enabled():
        raise ValueError(
            "dual-chain funding activation is installed but disabled; "
            "TRU_SWAP_DUAL_FUNDING_ENABLE=1 is required"
        )


def _txid(value: Any) -> str:
    s = str(value or "").lower()
    if not TXID_RE.fullmatch(s):
        raise ValueError("invalid prepared funding txid")
    return s


def _payload(agent, attempt: Dict[str, Any]) -> Dict[str, Any]:
    if attempt.get("prebroadcastReady") is not True:
        raise ValueError("funding journal has no durable prebroadcast identity")
    p = agent.store.get_prepared_funding_payload(attempt["operationId"])
    txid = _txid(p.get("preparedTxid"))
    vout = int(p.get("preparedContractVout", -1))
    if vout < 0:
        raise ValueError("invalid prepared funding vout")
    raw = str(p.get("preparedRawTxHex", "")).lower()
    if not raw or len(raw) % 2 or not re.fullmatch(r"[0-9a-f]+", raw):
        raise ValueError("invalid durable prepared raw transaction")
    return {
        "operationId": str(attempt["operationId"]),
        "preparedTxid": txid,
        "preparedVout": vout,
        "preparedRawTxHex": raw,
    }


def _exact_attempt(agent, swap_id: str, chain: str) -> Dict[str, Any]:
    row = agent.store.get_funding_attempt(swap_id, chain)
    if row is None:
        raise ValueError(f"{chain.upper()} funding journal is missing")
    if str(row.get("swapId")) != str(swap_id) or str(row.get("chain")) != chain:
        raise ValueError("funding journal identity drift")
    return row


def _to_broadcasting(agent, attempt: Dict[str, Any]) -> Dict[str, Any]:
    if attempt.get("state") == "BROADCASTING":
        return attempt
    if attempt.get("state") != "PREPARED":
        raise ValueError("broadcast entry requires PREPARED or BROADCASTING journal")
    _payload(agent, attempt)
    return agent.store.transition_funding_attempt(
        attempt["operationId"], "BROADCASTING"
    )


def _to_tx_identified(
    agent, attempt: Dict[str, Any], txid: str, vout: int
) -> Dict[str, Any]:
    txid = _txid(txid)
    p = _payload(agent, attempt)
    if txid != p["preparedTxid"] or int(vout) != int(p["preparedVout"]):
        raise ValueError("broadcast identity differs from durable prepared identity")
    if attempt.get("state") == "TX_IDENTIFIED":
        if (
            str(attempt.get("txid", "")).lower() != txid
            or int(attempt.get("vout", -1)) != int(vout)
        ):
            raise ValueError("TX_IDENTIFIED journal identity drift")
        return attempt
    if attempt.get("state") != "BROADCASTING":
        raise ValueError("TX_IDENTIFIED requires BROADCASTING journal")
    return agent.store.transition_funding_attempt(
        attempt["operationId"], "TX_IDENTIFIED", txid=txid, vout=int(vout)
    )


def _broadcast_tru(agent, swap_id: str, attempt: Dict[str, Any]) -> Dict[str, Any]:
    require_enabled()
    if attempt.get("state") == "PREPARED":
        # GROUP-01 exact-byte dry-run and reservation proof occurs before the
        # journal crosses the mutation barrier.
        dry = agent.dryrun_tru_prepared_broadcast(swap_id)
        if (
            dry.get("dryRun") is not True
            or dry.get("broadcast") is not False
            or dry.get("exactPersistedBytesOnly") is not True
        ):
            raise ValueError("TRU GROUP-01 dry-run barrier failed")
    attempt = _to_broadcasting(agent, attempt)
    p = _payload(agent, attempt)

    # The native node independently requires
    # TRU_SWAP_PREPARED_BROADCAST_ENABLE=1.  This Agent cannot bypass it.
    r = agent.tru.raw(
        "htlcbroadcastprepared",
        {
            "operationId": p["operationId"],
            "preparedTxid": p["preparedTxid"],
            "dryRun": False,
        },
    )
    if not isinstance(r, dict):
        raise ValueError("TRU prepared broadcast response shape")
    if (
        _txid(r.get("preparedTxid")) != p["preparedTxid"]
        or int(r.get("preparedVout", -1)) != p["preparedVout"]
        or r.get("dryRun") is not False
        or r.get("broadcast") is not True
        or r.get("exactPersistedBytesOnly") is not True
        or r.get("rawTxReturned") is not False
    ):
        raise ValueError("TRU exact prepared broadcast barrier mismatch")

    row = _to_tx_identified(
        agent, attempt, p["preparedTxid"], p["preparedVout"]
    )
    return {
        "swapId": swap_id,
        "chain": "tru",
        "operationId": p["operationId"],
        "journalState": row["state"],
        "preparedTxid": p["preparedTxid"],
        "preparedVout": p["preparedVout"],
        "broadcast": True,
        "exactPersistedBytesOnly": True,
        "rawTxReturned": False,
    }


def _bsty_exact_seen(agent, txid: str, vout: int) -> bool:
    try:
        if txid in agent.bsty_prebroadcast._mempool(agent):
            return True
    except Exception:
        pass
    try:
        out = agent.bsty.json("gettxout", txid, int(vout), "true")
        if isinstance(out, dict) and out.get("value") is not None:
            return True
    except Exception:
        pass
    return False


def _broadcast_bsty(agent, swap_id: str, attempt: Dict[str, Any]) -> Dict[str, Any]:
    require_enabled()
    if attempt.get("state") == "PREPARED":
        # GROUP-02 exact persisted-byte testmempoolaccept gate occurs before
        # the journal crosses the mutation barrier.
        dry = agent.dryrun_bsty_prepared_broadcast(swap_id)
        if (
            dry.get("dryRun") is not True
            or dry.get("broadcast") is not False
            or dry.get("exactPersistedBytesOnly") is not True
            or dry.get("mempoolAllowed") is not True
        ):
            raise ValueError("BSTY GROUP-02 testmempoolaccept barrier failed")
    attempt = _to_broadcasting(agent, attempt)
    p = _payload(agent, attempt)

    record = agent.get_live_record(swap_id)
    validated = agent.bsty_prebroadcast._validate_signed(
        agent, record, p["preparedRawTxHex"], p["preparedTxid"]
    )
    if (
        _txid(validated.get("txid")) != p["preparedTxid"]
        or int(validated.get("vout", -1)) != p["preparedVout"]
    ):
        raise ValueError("BSTY exact durable signed transaction drift")

    already_seen = _bsty_exact_seen(
        agent, p["preparedTxid"], p["preparedVout"]
    )
    if not already_seen:
        try:
            sent = _txid(
                agent.bsty.text(
                    "sendrawtransaction", p["preparedRawTxHex"], wallet=False
                )
            )
        except Exception:
            # A transport/process failure may have occurred after acceptance.
            # Only exact txid observation authorizes forward progress.
            if not _bsty_exact_seen(
                agent, p["preparedTxid"], p["preparedVout"]
            ):
                raise
            sent = p["preparedTxid"]
        if sent != p["preparedTxid"]:
            raise ValueError("BSTY sendrawtransaction returned unexpected txid")

    row = _to_tx_identified(
        agent, attempt, p["preparedTxid"], p["preparedVout"]
    )
    return {
        "swapId": swap_id,
        "chain": "bsty",
        "operationId": p["operationId"],
        "journalState": row["state"],
        "preparedTxid": p["preparedTxid"],
        "preparedVout": p["preparedVout"],
        "broadcast": True,
        "exactPersistedBytesOnly": True,
        "rawTxReturned": False,
    }


def _record_confirmed(
    agent, swap_id: str, chain: str, attempt: Dict[str, Any]
) -> Dict[str, Any]:
    if attempt.get("state") == "RECORDED":
        return {
            "swapId": swap_id,
            "chain": chain,
            "journalState": "RECORDED",
            "recorded": True,
            "idempotentReuse": True,
        }
    if attempt.get("state") != "CONFIRMED":
        raise ValueError("canonical funding evidence requires CONFIRMED journal")

    txid = _txid(attempt.get("txid"))
    vout = int(attempt.get("vout", -1))
    conf = int(attempt.get("confirmations", 0))
    view = agent.require_view(swap_id)
    required = int(view["min_conf"])
    if conf < required:
        raise ValueError("confirmed journal is below canonical confirmation policy")

    record = agent.get_live_record(swap_id)
    ev = record.get("evidence") or {}
    key_txid = f"{chain}FundingTxid"
    key_vout = f"{chain}FundingVout"
    key_conf = f"{chain}FundingConfirmations"

    if ev.get(key_txid):
        if (
            str(ev.get(key_txid)).lower() != txid
            or int(ev.get(key_vout, -1)) != vout
        ):
            raise ValueError("canonical funding evidence conflicts with journal")
        # Crash-safe finish-forward: canonical evidence was committed before
        # the journal reached RECORDED.  Never transition the record twice.
    else:
        record = agent.engine.transition_after_funding(
            agent.tru, record, chain, txid, vout, conf, required
        )
        ev = record.get("evidence") or {}
        if (
            str(ev.get(key_txid, "")).lower() != txid
            or int(ev.get(key_vout, -1)) != vout
            or int(ev.get(key_conf, 0)) < required
        ):
            raise ValueError("canonical funding evidence persistence mismatch")

    row = agent.store.transition_funding_attempt(
        attempt["operationId"],
        "RECORDED",
        txid=txid,
        vout=vout,
        confirmations=conf,
    )
    return {
        "swapId": swap_id,
        "chain": chain,
        "journalState": row["state"],
        "recordState": record.get("state"),
        "recorded": True,
        "preparedTxid": txid,
        "preparedVout": vout,
        "confirmations": conf,
        "broadcast": True,
        "rawTxReturned": False,
    }


def fund_step(agent, swap_id: str) -> Dict[str, Any]:
    """Advance exactly one local funding leg idempotently.

    PREPARED -> BROADCASTING -> TX_IDENTIFIED -> CONFIRMED -> RECORDED.
    The function never creates a replacement transaction and never funds the
    non-local chain.
    """
    require_enabled()
    view = dict(agent.require_view(swap_id))
    chain = str(view.get("give_chain", ""))
    if chain not in {"tru", "bsty"}:
        raise ValueError("local funding chain")

    attempt = agent.store.get_funding_attempt(swap_id, chain)
    if attempt is None:
        if chain == "tru":
            agent.prepare_tru_prebroadcast_funding(swap_id)
        else:
            agent.prepare_bsty_prebroadcast_funding(swap_id)
        attempt = _exact_attempt(agent, swap_id, chain)

    state = str(attempt.get("state", ""))
    if state in {"AMBIGUOUS", "ABORTED"}:
        raise ValueError(f"{chain.upper()} funding journal is terminal: {state}")
    if state == "RECORDED":
        return _record_confirmed(agent, swap_id, chain, attempt)

    if state == "PREPARED":
        # Ensure restart-idempotent preparation/re-lock checks run before
        # allowing the mutation barrier to open.
        if chain == "tru":
            agent.prepare_tru_prebroadcast_funding(swap_id)
        else:
            agent.prepare_bsty_prebroadcast_funding(swap_id)
        attempt = _exact_attempt(agent, swap_id, chain)
        if chain == "tru":
            return _broadcast_tru(agent, swap_id, attempt)
        return _broadcast_bsty(agent, swap_id, attempt)

    if state == "BROADCASTING":
        # Crash recovery is an exact-byte replay only.
        if chain == "tru":
            return _broadcast_tru(agent, swap_id, attempt)
        return _broadcast_bsty(agent, swap_id, attempt)

    if state == "TX_IDENTIFIED":
        if chain == "tru":
            agent.reconcile_tru_funding_journal(swap_id)
        else:
            agent.reconcile_bsty_funding_journal(swap_id)
        attempt = _exact_attempt(agent, swap_id, chain)
        if attempt.get("state") == "CONFIRMED":
            return _record_confirmed(agent, swap_id, chain, attempt)
        return {
            "swapId": swap_id,
            "chain": chain,
            "journalState": attempt.get("state"),
            "confirmations": int(attempt.get("confirmations", 0)),
            "recorded": False,
            "broadcast": True,
            "waitingForConfirmations": True,
            "rawTxReturned": False,
        }

    if state == "CONFIRMED":
        return _record_confirmed(agent, swap_id, chain, attempt)

    raise ValueError("unsupported funding journal state: " + state)


# ---------------------------------------------------------------------------
# Offline deterministic selftest.  No live RPC, wallet, SQLite, or network.
# ---------------------------------------------------------------------------

class _FakeStore:
    def __init__(self, chain: str, txid: str):
        self.chain = chain
        self.row = {
            "operationId": "11" * 32,
            "swapId": "22" * 32,
            "chain": chain,
            "state": "PREPARED",
            "prebroadcastReady": True,
            "preparedTxid": txid,
            "preparedContractVout": 1 if chain == "tru" else 0,
            "txid": None,
            "vout": None,
            "confirmations": 0,
        }
        self.raw = "01020304"
    def get_funding_attempt(self, swap_id, chain):
        return dict(self.row) if chain == self.chain else None
    def get_prepared_funding_payload(self, operation_id):
        return {
            "preparedTxid": self.row["preparedTxid"],
            "preparedContractVout": self.row["preparedContractVout"],
            "preparedRawTxHex": self.raw,
        }
    def transition_funding_attempt(self, operation_id, next_state, **kw):
        allowed = {
            "PREPARED": {"BROADCASTING"},
            "BROADCASTING": {"TX_IDENTIFIED"},
            "TX_IDENTIFIED": {"CONFIRMED"},
            "CONFIRMED": {"RECORDED"},
        }
        if next_state not in allowed.get(self.row["state"], set()):
            raise ValueError("fake transition")
        self.row["state"] = next_state
        self.row.update(kw)
        return dict(self.row)


class _FakeTru:
    def __init__(self, store):
        self.store = store
        self.real_calls = 0
    def raw(self, method, params):
        if method != "htlcbroadcastprepared":
            raise ValueError("unexpected fake TRU method")
        self.real_calls += 1
        return {
            "preparedTxid": self.store.row["preparedTxid"],
            "preparedVout": self.store.row["preparedContractVout"],
            "dryRun": False,
            "broadcast": True,
            "exactPersistedBytesOnly": True,
            "rawTxReturned": False,
        }


class _FakeBstyPre:
    def _validate_signed(self, agent, record, raw, txid):
        return {"txid": txid, "vout": 0, "outpoints": [{"txid": "33"*32, "vout": 0}]}
    def _mempool(self, agent):
        return set()


class _FakeBsty:
    def __init__(self, store):
        self.store = store
        self.real_calls = 0
    def json(self, method, *args, **kwargs):
        if method == "gettxout":
            return None
        raise ValueError("unexpected fake BSTY json")
    def text(self, method, *args, **kwargs):
        if method != "sendrawtransaction":
            raise ValueError("unexpected fake BSTY method")
        self.real_calls += 1
        return self.store.row["preparedTxid"]


class _FakeAgent:
    def __init__(self, chain: str):
        txid = ("44" if chain == "tru" else "55") * 32
        self.store = _FakeStore(chain, txid)
        self.tru = _FakeTru(self.store)
        self.bsty = _FakeBsty(self.store)
        self.bsty_prebroadcast = _FakeBstyPre()
        self.dry_calls = 0
    def dryrun_tru_prepared_broadcast(self, swap_id):
        self.dry_calls += 1
        return {"dryRun": True, "broadcast": False, "exactPersistedBytesOnly": True}
    def dryrun_bsty_prepared_broadcast(self, swap_id):
        self.dry_calls += 1
        return {
            "dryRun": True, "broadcast": False,
            "exactPersistedBytesOnly": True, "mempoolAllowed": True
        }
    def get_live_record(self, swap_id):
        return {}


def selftest() -> None:
    old = os.environ.pop(ENABLE_ENV, None)
    try:
        a = _FakeAgent("tru")
        try:
            _broadcast_tru(a, a.store.row["swapId"], a.store.row)
            raise AssertionError("disabled TRU broadcast gate")
        except ValueError as exc:
            assert ENABLE_ENV in str(exc)
        assert a.tru.real_calls == 0 and a.store.row["state"] == "PREPARED"

        os.environ[ENABLE_ENV] = "1"
        a = _FakeAgent("tru")
        r = _broadcast_tru(a, a.store.row["swapId"], dict(a.store.row))
        assert r["journalState"] == "TX_IDENTIFIED"
        assert a.dry_calls == 1 and a.tru.real_calls == 1
        assert a.store.row["txid"] == ("44" * 32)

        b = _FakeAgent("bsty")
        r = _broadcast_bsty(b, b.store.row["swapId"], dict(b.store.row))
        assert r["journalState"] == "TX_IDENTIFIED"
        assert b.dry_calls == 1 and b.bsty.real_calls == 1
        assert b.store.row["txid"] == ("55" * 32)

        # Crash-retry starts from BROADCASTING and does not create/sign again.
        c = _FakeAgent("bsty")
        c.store.row["state"] = "BROADCASTING"
        r = _broadcast_bsty(c, c.store.row["swapId"], dict(c.store.row))
        assert r["journalState"] == "TX_IDENTIFIED"
        assert c.dry_calls == 0 and c.bsty.real_calls == 1
    finally:
        if old is None:
            os.environ.pop(ENABLE_ENV, None)
        else:
            os.environ[ENABLE_ENV] = old
    print("GROUP03_DUAL_FUNDING_SELFTEST=PASS")
    print("DEFAULT_ENABLE_GATE=PASS")
    print("TRU_EXACT_PREPARED_BROADCAST_SEQUENCE=PASS")
    print("BSTY_EXACT_PREPARED_BROADCAST_SEQUENCE=PASS")
    print("CRASH_REPLAY_EXACT_BYTES_ONLY=PASS")
    print("PRIVATE_MATERIAL=NONE")


if __name__ == "__main__":
    selftest()
