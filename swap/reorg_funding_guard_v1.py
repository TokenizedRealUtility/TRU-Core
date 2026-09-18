#!/usr/bin/env python3
"""TRU REORG-SWAP-01A — pure funding reorg recovery policy.

This module is intentionally:
  * read/policy only
  * independent of SQLite, subprocess, sockets, HTTP, RPC clients, or wallets
  * incapable of broadcasting or creating transactions

It converts CURRENT REORG-TX-01 observations plus durable journal history into a
deterministic recovery plan. Actual chain reads, policy validation, and any later
same-transaction rebroadcast remain owned by a separate executor.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict

VERSION = "TRU-REORG-SWAP-01A"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CURRENT_STATES = {"CONFIRMED", "MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND"}
PREVIOUSLY_CONFIRMED_JOURNAL_STATES = {"CONFIRMED", "RECORDED"}


def _bool_or_none(value: Any):
    return value if isinstance(value, bool) else None


def normalize_tx_status(obj: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("transaction status must be an object")
    state = obj.get("txState")
    if state not in CURRENT_STATES:
        raise ValueError("unsupported or missing txState")

    known = _bool_or_none(obj.get("known"))
    active = _bool_or_none(obj.get("active"))
    reorg_signal = _bool_or_none(obj.get("reorgSignal"))
    confirmations = obj.get("confirmations")

    if not isinstance(confirmations, int) or isinstance(confirmations, bool):
        raise ValueError("confirmations must be an integer")
    if confirmations < 0:
        raise ValueError("negative confirmations are forbidden")

    if state == "CONFIRMED":
        if known is not True or active is not True or confirmations < 1:
            raise ValueError("invalid CONFIRMED observation")
        if reorg_signal is not False:
            raise ValueError("active CONFIRMED cannot signal reorg")

    elif state == "MEMPOOL":
        if known is not True or active is not False or confirmations != 0:
            raise ValueError("invalid MEMPOOL observation")

    elif state in {"SIDECHAIN", "CONFLICTED"}:
        if known is not True or active is not False or confirmations != 0:
            raise ValueError("invalid non-active indexed observation")
        if reorg_signal is not True:
            raise ValueError("non-active indexed observation must signal reorg")

    elif state == "NOT_FOUND":
        if known is not False or active is not False or confirmations != 0:
            raise ValueError("invalid NOT_FOUND observation")
        if reorg_signal is not False:
            raise ValueError("current NOT_FOUND alone cannot claim history")

    return {
        "txState": state,
        "known": known,
        "active": active,
        "confirmations": confirmations,
        "reorgSignal": reorg_signal,
        "conflicted": bool(obj.get("conflicted")) if state in {"SIDECHAIN", "CONFLICTED"} else False,
        "conflictingTxid": obj.get("conflictingTxid"),
    }


def validate_prepared_identity(row: Dict[str, Any]) -> Dict[str, Any]:
    """Validate durable same-transaction identity without recomputing TRU txid.

    The earlier prepared-transaction barrier already bound prepared_txid to the
    node's exact raw-transaction round-trip. Here we require that durable txid
    identity remains unchanged and that the exact persisted raw bytes still match
    their durable payload SHA-256.
    """
    if not isinstance(row, dict):
        return {"ok": False, "reason": "journal row missing"}

    txid = row.get("txid")
    prepared_txid = row.get("preparedTxid", row.get("prepared_txid"))
    raw_hex = row.get("preparedRawTxHex", row.get("prepared_raw_tx_hex"))
    payload_sha = row.get("preparedPayloadSha256", row.get("prepared_payload_sha256"))

    if not isinstance(txid, str) or not HEX64.fullmatch(txid):
        return {"ok": False, "reason": "journal txid missing/invalid"}
    if prepared_txid != txid:
        return {"ok": False, "reason": "prepared txid no longer matches durable txid"}
    if not isinstance(raw_hex, str) or len(raw_hex) == 0 or len(raw_hex) % 2:
        return {"ok": False, "reason": "prepared raw transaction unavailable"}
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return {"ok": False, "reason": "prepared raw transaction is not hex"}
    if not isinstance(payload_sha, str) or not HEX64.fullmatch(payload_sha):
        return {"ok": False, "reason": "prepared payload hash missing/invalid"}

    actual = hashlib.sha256(raw).hexdigest()
    if actual != payload_sha:
        return {"ok": False, "reason": "prepared payload hash mismatch"}

    return {
        "ok": True,
        "txid": txid,
        "payloadSha256": payload_sha,
        "rawBytes": len(raw),
    }


def plan_funding_reorg_recovery(
    row: Dict[str, Any],
    tx_status: Dict[str, Any],
    *,
    mempool_absence_proven: bool = False,
    active_input_conflict_proven_absent: bool = False,
    current_policy_acceptance_proven: bool = False,
) -> Dict[str, Any]:
    """Return a pure recovery plan. Never executes a mutation."""
    obs = normalize_tx_status(tx_status)
    journal_state = row.get("state") if isinstance(row, dict) else None
    previously_confirmed = journal_state in PREVIOUSLY_CONFIRMED_JOURNAL_STATES

    base = {
        "version": VERSION,
        "journalState": journal_state,
        "currentTxState": obs["txState"],
        "historicalState": "NO_REORG_PROVEN",
        "action": "OBSERVE",
        "sameTxRebroadcastEligible": False,
        "freshFundingAllowed": False,
        "automaticBroadcast": False,
        "requiresExactPersistedIdentity": True,
    }

    # No historical confirmation means current absence is not enough to call a reorg.
    if not previously_confirmed:
        if obs["txState"] == "CONFIRMED":
            base["action"] = "ADOPT_CONFIRMATION_THROUGH_EXISTING_RECONCILER"
        elif obs["txState"] == "MEMPOOL":
            base["action"] = "WATCH_MEMPOOL"
        elif obs["txState"] in {"SIDECHAIN", "CONFLICTED"}:
            base["action"] = "HOLD_NONACTIVE_PRECONFIRMATION"
        else:
            base["action"] = "HOLD_UNKNOWN"
        return base

    if obs["txState"] == "CONFIRMED":
        base["historicalState"] = "STABLE_CONFIRMED"
        base["action"] = "NONE"
        return base

    # Once a durable CONFIRMED/RECORDED row is no longer active, history proves a reorg.
    base["historicalState"] = "REORGED"

    if obs["txState"] == "MEMPOOL":
        base["action"] = "WATCH_REORGED_TX_IN_MEMPOOL"
        return base

    if obs["txState"] == "CONFLICTED" or obs.get("conflicted"):
        base["action"] = "HOLD_REORG_CONFLICT"
        base["conflictingTxid"] = obs.get("conflictingTxid")
        return base

    ident = validate_prepared_identity(row)
    if not ident["ok"]:
        base["action"] = "HOLD_UNKNOWN"
        base["identityFailure"] = ident["reason"]
        return base

    # SIDECHAIN proves not active/not mempool in the REORG-TX-01 atomic snapshot,
    # but the later executor must still prove exact input non-conflict and current
    # policy acceptance immediately before any same-transaction rebroadcast.
    if obs["txState"] == "SIDECHAIN":
        mempool_absence_proven = True

    # NOT_FOUND can only become a same-tx candidate after independent proof that
    # the exact tx is absent from mempool and that its inputs are not consumed by
    # the current active chain.
    if not mempool_absence_proven:
        base["action"] = "HOLD_REORG_MEMPOOL_ABSENCE_UNPROVEN"
        return base
    if not active_input_conflict_proven_absent:
        base["action"] = "HOLD_REORG_INPUT_STATUS_UNPROVEN"
        return base
    if not current_policy_acceptance_proven:
        base["action"] = "HOLD_REORG_POLICY_REVALIDATION_REQUIRED"
        return base

    base["action"] = "SAME_TX_REBROADCAST_ELIGIBLE"
    base["sameTxRebroadcastEligible"] = True
    base["preparedTxid"] = ident["txid"]
    base["preparedPayloadSha256"] = ident["payloadSha256"]
    return base


def selftest() -> None:
    txid = "11" * 32
    raw = bytes.fromhex("01020304")
    row = {
        "state": "RECORDED",
        "txid": txid,
        "preparedTxid": txid,
        "preparedRawTxHex": raw.hex(),
        "preparedPayloadSha256": hashlib.sha256(raw).hexdigest(),
    }

    def status(state, *, conflicted=False, conflict=None):
        if state == "CONFIRMED":
            return {
                "txState": state, "known": True, "active": True,
                "confirmations": 3, "reorgSignal": False,
            }
        if state == "MEMPOOL":
            return {
                "txState": state, "known": True, "active": False,
                "confirmations": 0, "reorgSignal": False,
            }
        if state in {"SIDECHAIN", "CONFLICTED"}:
            return {
                "txState": state, "known": True, "active": False,
                "confirmations": 0, "reorgSignal": True,
                "conflicted": conflicted or state == "CONFLICTED",
                "conflictingTxid": conflict,
            }
        return {
            "txState": "NOT_FOUND", "known": False, "active": False,
            "confirmations": 0, "reorgSignal": False,
        }

    p = plan_funding_reorg_recovery(row, status("CONFIRMED"))
    assert p["historicalState"] == "STABLE_CONFIRMED"
    assert p["action"] == "NONE"

    p = plan_funding_reorg_recovery(row, status("MEMPOOL"))
    assert p["historicalState"] == "REORGED"
    assert p["action"] == "WATCH_REORGED_TX_IN_MEMPOOL"
    assert not p["sameTxRebroadcastEligible"]

    p = plan_funding_reorg_recovery(
        row, status("SIDECHAIN"),
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["historicalState"] == "REORGED"
    assert p["action"] == "SAME_TX_REBROADCAST_ELIGIBLE"
    assert p["sameTxRebroadcastEligible"]

    p = plan_funding_reorg_recovery(
        row, status("CONFLICTED", conflict="22" * 32),
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_REORG_CONFLICT"
    assert not p["sameTxRebroadcastEligible"]

    p = plan_funding_reorg_recovery(
        row, status("NOT_FOUND"),
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "SAME_TX_REBROADCAST_ELIGIBLE"
    assert p["sameTxRebroadcastEligible"]

    bad = dict(row)
    bad["preparedPayloadSha256"] = "00" * 32
    p = plan_funding_reorg_recovery(
        bad, status("NOT_FOUND"),
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_UNKNOWN"
    assert not p["sameTxRebroadcastEligible"]

    p = plan_funding_reorg_recovery(
        row, status("NOT_FOUND"),
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=False,
    )
    assert p["action"] == "HOLD_REORG_POLICY_REVALIDATION_REQUIRED"
    assert not p["sameTxRebroadcastEligible"]

    pre = dict(row)
    pre["state"] = "TX_IDENTIFIED"
    p = plan_funding_reorg_recovery(pre, status("NOT_FOUND"))
    assert p["historicalState"] == "NO_REORG_PROVEN"
    assert p["action"] == "HOLD_UNKNOWN"

    try:
        normalize_tx_status({
            "txState": "CONFIRMED", "known": True, "active": True,
            "confirmations": -1, "reorgSignal": False,
        })
    except ValueError:
        pass
    else:
        raise AssertionError("negative confirmation sentinel accepted")

    print("TRU_REORG_SWAP_01A_SELFTEST=PASS")
    print("FRESH_FUNDING_AFTER_REORG=FORBIDDEN")
    print("AUTOMATIC_BROADCAST=FORBIDDEN")
    print("SAME_TX_REBROADCAST_REQUIRES_EXACT_IDENTITY_AND_THREE_PROOFS=PASS")


if __name__ == "__main__":
    selftest()

