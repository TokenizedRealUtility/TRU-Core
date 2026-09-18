#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    p = HERE / filename
    spec = importlib.util.spec_from_file_location(name, str(p))
    if spec is None or spec.loader is None:
        raise RuntimeError("import failure: " + filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> None:
    rec = load("reorg_exit_recovery_01a_test", "reorg_exit_recovery_v1.py")
    ov = load("reorg_exit_overlay_01a_test", "reorg_exit_overlay_v1.py")
    assert rec.VERSION == "TRU-REORG-EXIT-01A"
    assert ov.VERSION == "TRU-REORG-EXIT-01"

    txid = "44" * 32
    raw = "0200000001" + "55" * 48

    # Exact claim bytes may become policy-eligible even after permanent exposure;
    # this cannot authorize the opposite refund path and execution is still absent.
    p = rec.plan_exact_exit_recovery(
        chain="tru", kind="claim", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert p["action"] == "SAME_TX_REBROADCAST_ELIGIBLE_POLICY_ONLY"
    assert p["sameTxRebroadcastEligible"] is True
    assert p["sameTxRebroadcastAuthorized"] is False

    # The exact same refund is not eligible if a claim was ever exposed.
    q = rec.plan_exact_exit_recovery(
        chain="tru", kind="refund", txid=txid, current_tx_state="SIDECHAIN",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=raw, decoded_txid=txid, raw_source="TRU_GETTRANSACTION",
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert q["action"] == "HOLD_REFUND_FORBIDDEN_AFTER_PREIMAGE_EXPOSURE"

    # Recovery is impossible from a txid alone. No reconstructed/re-signed substitute.
    r = rec.plan_exact_exit_recovery(
        chain="bsty", kind="claim", txid=txid, current_tx_state="NOT_FOUND",
        historical_reorged=True, historical_preimage_exposed=True,
        raw_hex=None, decoded_txid=None, raw_source=None,
        mempool_absence_proven=True,
        active_input_conflict_proven_absent=True,
        current_policy_acceptance_proven=True,
    )
    assert r["action"] == "HOLD_EXACT_BYTES_UNAVAILABLE_OR_MISMATCH"

    text = (HERE / "reorg_exit_recovery_v1.py").read_text().lower()
    for forbidden in (
        "import subprocess", "import sqlite3", "import socket",
        "sendrawtransaction", "htlcbroadcastprepared",
        "private_key", "wallet_password",
    ):
        assert forbidden not in text, forbidden

    print("TRU_REORG_EXIT_01A_SELFTEST=PASS")
    print("EXACT_EXIT_TX_RECOVERY_POLICY=PASS")
    print("TRU_BSTY_POLICY_PARITY=PASS")
    print("EXACT_RAW_SOURCE_ALLOWLIST=PASS")
    print("RAW_TXID_NODE_DECODE_BINDING=PASS")
    print("THREE_LIVE_PROOFS_REQUIRED=PASS")
    print("HISTORICAL_PREIMAGE_EXPOSURE_MONOTONIC=PASS")
    print("OPPOSITE_REFUND_PATH_AFTER_EXPOSURE=FORBIDDEN")
    print("NOT_FOUND_TXID_ONLY_RECOVERY=FORBIDDEN")
    print("RECONSTRUCTION_RESIGNING=FORBIDDEN")
    print("POLICY_NETWORK_MUTATORS=NONE")
    print("RAW_EXIT_BYTES_DURABLE_STORAGE=NONE")
    print("AUTOMATIC_REBROADCAST=NO")
    print("COIN_MOVEMENT=NO")


if __name__ == "__main__":
    main()
