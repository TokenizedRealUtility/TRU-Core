#!/usr/bin/env python3
"""TRU REORG-EXIT-01A exact exit-transaction recovery policy.

Policy only. This module has no RPC client, subprocess, SQLite, wallet access,
transaction signer, or broadcast primitive.

The only recoverable exit is the exact already-observed claim/refund transaction.
Raw signed bytes must come from a live chain/wallet lookup, and the caller must
prove that decoding those exact bytes yields the durable exit txid. Rebuilding or
re-signing a replacement transaction is never recovery.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict

VERSION = "TRU-REORG-EXIT-01A"
CHAINS = {"tru", "bsty"}
KINDS = {"claim", "refund"}
TX_STATES = {"CONFIRMED", "MEMPOOL", "SIDECHAIN", "CONFLICTED", "NOT_FOUND", "UNKNOWN"}
RAW_SOURCES = {
    "TRU_GETTRANSACTION",
    "BSTY_GETRAWTRANSACTION",
    "BSTY_WALLET_GETTRANSACTION",
}
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]+$")


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(name + " must be boolean")
    return value


def _txid(value: Any, name: str = "txid") -> str:
    value = str(value or "").lower()
    if not TXID_RE.fullmatch(value):
        raise ValueError(name + " must be 64 lowercase hex characters")
    return value


def validate_exact_live_bytes(
    expected_txid: str,
    raw_hex: Any,
    decoded_txid: Any,
    raw_source: Any,
) -> Dict[str, Any]:
    """Validate an ephemeral exact-byte candidate without persisting it.

    TRU txids intentionally do not hash scriptSig bytes, so this policy does not
    guess a chain-specific txid algorithm. The runtime binding must ask the node
    to decode the exact returned raw bytes and pass that decoded txid here.
    """
    expected = _txid(expected_txid)
    source = str(raw_source or "")
    if source not in RAW_SOURCES:
        return {"ok": False, "reason": "raw transaction source is not an allowed live lookup"}
    if not isinstance(raw_hex, str):
        return {"ok": False, "reason": "exact raw transaction bytes unavailable"}
    raw_hex = raw_hex.strip().lower()
    if not raw_hex or len(raw_hex) % 2 or not HEX_RE.fullmatch(raw_hex):
        return {"ok": False, "reason": "exact raw transaction bytes are invalid hex"}
    decoded = str(decoded_txid or "").lower()
    if not TXID_RE.fullmatch(decoded):
        return {"ok": False, "reason": "node-decoded txid proof unavailable"}
    if decoded != expected:
        return {"ok": False, "reason": "exact raw transaction decodes to a different txid"}
    raw = bytes.fromhex(raw_hex)
    return {
        "ok": True,
        "txid": expected,
        "rawSource": source,
        "payloadSha256": hashlib.sha256(raw).hexdigest(),
        "rawBytes": len(raw),
        "rawPersisted": False,
    }


def plan_exact_exit_recovery(
    *,
    chain: str,
    kind: str,
    txid: str,
    current_tx_state: str,
    historical_reorged: bool,
    historical_preimage_exposed: bool,
    raw_hex: Any = None,
    decoded_txid: Any = None,
    raw_source: Any = None,
    mempool_absence_proven: bool = False,
    active_input_conflict_proven_absent: bool = False,
    current_policy_acceptance_proven: bool = False,
) -> Dict[str, Any]:
    """Return a deterministic plan. Never performs a chain mutation."""
    chain = str(chain).lower()
    kind = str(kind).lower()
    txid = _txid(txid)
    state = str(current_tx_state).upper()
    if chain not in CHAINS:
        raise ValueError("chain")
    if kind not in KINDS:
        raise ValueError("kind")
    if state not in TX_STATES:
        raise ValueError("current_tx_state")
    historical_reorged = _bool(historical_reorged, "historical_reorged")
    historical_preimage_exposed = _bool(
        historical_preimage_exposed, "historical_preimage_exposed")
    mempool_absence_proven = _bool(mempool_absence_proven, "mempool_absence_proven")
    active_input_conflict_proven_absent = _bool(
        active_input_conflict_proven_absent, "active_input_conflict_proven_absent")
    current_policy_acceptance_proven = _bool(
        current_policy_acceptance_proven, "current_policy_acceptance_proven")

    out: Dict[str, Any] = {
        "version": VERSION,
        "chain": chain,
        "kind": kind,
        "txid": txid,
        "currentTxState": state,
        "historicalReorged": historical_reorged,
        "preimageExposed": historical_preimage_exposed,
        "action": "OBSERVE",
        "sameTxRebroadcastEligible": False,
        "sameTxRebroadcastAuthorized": False,
        "freshExitTransactionAllowed": False,
        "reSignOrReconstructAllowed": False,
        "automaticBroadcast": False,
        "rawBytesPersisted": False,
        "requiresLiveExactBytes": True,
        "requiresNodeDecodedTxidIdentity": True,
        "requiresMempoolAbsenceProof": True,
        "requiresActiveInputNonConflictProof": True,
        "requiresCurrentPolicyAcceptanceProof": True,
    }

    if state == "CONFIRMED":
        out["action"] = "NONE_ALREADY_CONFIRMED"
        return out
    if state == "MEMPOOL":
        out["action"] = "WATCH_EXACT_TX_IN_MEMPOOL"
        return out
    if state == "UNKNOWN":
        out["action"] = "HOLD_UNKNOWN_CHAIN_STATUS"
        return out
    if state == "CONFLICTED":
        out["action"] = "HOLD_ACTIVE_INPUT_CONFLICT"
        return out
    if not historical_reorged:
        out["action"] = "HOLD_HISTORICAL_REORG_NOT_PROVEN"
        return out

    # Once any claim exposed the secret, no refund-path transaction may be
    # recovered/rebroadcast. Claim recovery may still be evaluated because it
    # cannot create the unsafe opposite-path transition.
    if kind == "refund" and historical_preimage_exposed:
        out["action"] = "HOLD_REFUND_FORBIDDEN_AFTER_PREIMAGE_EXPOSURE"
        return out

    identity = validate_exact_live_bytes(txid, raw_hex, decoded_txid, raw_source)
    if not identity["ok"]:
        out["action"] = "HOLD_EXACT_BYTES_UNAVAILABLE_OR_MISMATCH"
        out["identityFailure"] = identity["reason"]
        return out

    # NOT_FOUND is never recoverable by reconstruction. It can proceed only if
    # an allowed live wallet/chain lookup still supplied the exact bytes.
    if state == "NOT_FOUND" and not identity["ok"]:
        out["action"] = "HOLD_NOT_FOUND_EXACT_BYTES_UNAVAILABLE"
        return out

    if not mempool_absence_proven:
        out["action"] = "HOLD_MEMPOOL_ABSENCE_UNPROVEN"
        return out
    if not active_input_conflict_proven_absent:
        out["action"] = "HOLD_ACTIVE_INPUT_STATUS_UNPROVEN"
        return out
    if not current_policy_acceptance_proven:
        out["action"] = "HOLD_CURRENT_POLICY_REVALIDATION_REQUIRED"
        return out

    out.update({
        "action": "SAME_TX_REBROADCAST_ELIGIBLE_POLICY_ONLY",
        "sameTxRebroadcastEligible": True,
        "payloadSha256": identity["payloadSha256"],
        "rawBytes": identity["rawBytes"],
        "rawSource": identity["rawSource"],
    })
    return out


def selftest() -> None:
    txid = "11" * 32
    raw = "0100000001" + "22" * 40

    p = plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["sameTxRebroadcastEligible"] is True
    assert p["sameTxRebroadcastAuthorized"] is False
    assert p["reSignOrReconstructAllowed"] is False
    assert p["rawBytesPersisted"] is False

    p = plan_exact_exit_recovery(
        chain="bsty", kind="refund", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="BSTY_GETRAWTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_REFUND_FORBIDDEN_AFTER_PREIMAGE_EXPOSURE"
    assert not p["sameTxRebroadcastEligible"]

    p = plan_exact_exit_recovery(
        chain="bsty", kind="claim", txid=txid, current_tx_state="NOT_FOUND",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=None, decoded_txid=None, raw_source=None,
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_EXACT_BYTES_UNAVAILABLE_OR_MISMATCH"

    p = plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid="33" * 32, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_EXACT_BYTES_UNAVAILABLE_OR_MISMATCH"

    p = plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="CONFLICTED",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=False,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "HOLD_ACTIVE_INPUT_CONFLICT"

    p = plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=False,
    )
    assert p["action"] == "HOLD_CURRENT_POLICY_REVALIDATION_REQUIRED"

    p = plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="MEMPOOL",
        historical_reorged=True, historical_preimage_exposed=True,
    )
    assert p["action"] == "WATCH_EXACT_TX_IN_MEMPOOL"

    print("TRU_REORG_EXIT_01A_RECOVERY_POLICY_SELFTEST=PASS")
    print("EXACT_LIVE_RAW_BYTES_REQUIRED=PASS")
    print("NODE_DECODED_TXID_IDENTITY_REQUIRED=PASS")
    print("NOT_FOUND_WITHOUT_EXACT_BYTES=HOLD")
    print("REFUND_AFTER_PREIMAGE_EXPOSURE=FORBIDDEN")
    print("RECONSTRUCT_OR_RESIGN_AFTER_REORG=FORBIDDEN")
    print("SAME_TX_REBROADCAST_ELIGIBILITY_REQUIRES_THREE_LIVE_PROOFS=PASS")
    print("SAME_TX_REBROADCAST_EXECUTION=NOT_AUTHORIZED")
    print("AUTOMATIC_BROADCAST=NO")
    print("FRESH_EXIT_TRANSACTION_AFTER_REORG=NO")
    print("RAW_EXIT_BYTES_PERSISTED=NO")


if __name__ == "__main__":
    selftest()
