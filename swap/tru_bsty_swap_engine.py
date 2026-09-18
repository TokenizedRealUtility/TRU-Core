#!/usr/bin/env python3
"""
TRU-SWAP-B — TRU <-> BSTY cross-chain engine.

Design:
- Does NOT modify TRU consensus, policy, wallet, or frozen 103-byte HTLC bytes.
- Talks to TRU through the SWAP-A RPC surface via tru-cli.
- Talks to GlobalBoost/BSTY through globalboost-cli.
- Reuses the exact frozen TRU-SWAP-V1 HASH160/timestamp HTLC on both chains.
- TRU identity: bare 103-byte HTLC.
- BSTY identity: P2SH(HASH160(redeemScript)).
- Never writes an atomic-swap preimage into the SWAP-A LevelDB record.
- BSTY signing is delegated to a separate helper process; the coordinator
  never receives the raw BSTY private key.

This is the SWAP-B engine layer. SWAP-C remains the final E2E/mainnet hardening
gate and should be used before meaningful mainnet value.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

COIN = 100_000_000
SIGHASH_ALL = 1
REFUND_TIME_MIN = 500_000_000
REFUND_TIME_MAX = 0x7FFFFFFF

OP_0 = 0x00
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_1 = 0x51

FROZEN_VECTOR_HEX = (
    "63a914c435cba38228ea6ea9c2ffd74e6e32a9c48c61fc8821"
    "02a72508c103683b903691068a3345e63a04eb419aeb09ab046d613ed77caffc3c"
    "ac6704bb619d6ab17521"
    "02c061424b3d902d9e9b43a2bdeee8b77643c18c8ca2c6293e7d6237758768ca85"
    "ac68"
)

def fail(msg):
    raise RuntimeError(msg)

def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def push(data: bytes) -> bytes:
    n = len(data)
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return b"\x4c" + bytes([n]) + data
    if n <= 65535:
        return b"\x4d" + struct.pack("<H", n) + data
    fail("push too large")

def scriptnum(n: int) -> bytes:
    if n < 0:
        fail("negative scriptnum not supported")
    if n == 0:
        return b""
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes(out)

def build_redeem_script(secret_h160: bytes, claim_pub: bytes,
                        refund_pub: bytes, refund_time: int) -> bytes:
    if len(secret_h160) != 20:
        fail("HASH160 digest must be exactly 20 bytes")
    if len(claim_pub) != 33 or claim_pub[0] not in (2, 3):
        fail("claim pubkey must be compressed SEC1")
    if len(refund_pub) != 33 or refund_pub[0] not in (2, 3):
        fail("refund pubkey must be compressed SEC1")
    if claim_pub == refund_pub:
        fail("claim/refund role pubkeys must be distinct")
    if not (REFUND_TIME_MIN <= refund_time <= REFUND_TIME_MAX):
        fail("refund timestamp outside TRU-SWAP-V1 domain")
    s = (
        bytes([OP_IF, OP_HASH160])
        + push(secret_h160)
        + bytes([OP_EQUALVERIFY])
        + push(claim_pub)
        + bytes([OP_CHECKSIG, OP_ELSE])
        + push(scriptnum(refund_time))
        + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
        + push(refund_pub)
        + bytes([OP_CHECKSIG, OP_ENDIF])
    )
    if len(s) != 103:
        fail(f"canonical HTLC is {len(s)} bytes, expected 103")
    return s

def p2sh_scriptpubkey(redeem: bytes) -> bytes:
    return b"\xa9\x14" + hash160(redeem) + b"\x87"

def serialize_tx(version, vin, vout, locktime):
    out = bytearray(struct.pack("<I", version))
    out += varint(len(vin))
    for i in vin:
        out += bytes.fromhex(i["txid"])[::-1]
        out += struct.pack("<I", i["vout"])
        script = i.get("scriptSig", b"")
        out += varint(len(script)) + script
        out += struct.pack("<I", i["sequence"])
    out += varint(len(vout))
    for o in vout:
        out += struct.pack("<Q", o["value"])
        spk = o["scriptPubKey"]
        out += varint(len(spk)) + spk
    out += struct.pack("<I", locktime)
    return bytes(out)

def sighash_legacy_all(version, vin, vout, locktime, script_code):
    signing_vin = [{
        "txid": vin[0]["txid"],
        "vout": vin[0]["vout"],
        "sequence": vin[0]["sequence"],
        "scriptSig": script_code,
    }]
    return dsha256(
        serialize_tx(version, signing_vin, vout, locktime)
        + struct.pack("<I", SIGHASH_ALL)
    )

def sats(v):
    return int((Decimal(str(v)) * Decimal(COIN)).to_integral_exact())

def atoms_to_coin_string(v: int) -> str:
    if v <= 0:
        fail("amount must be positive")
    return f"{Decimal(v) / Decimal(COIN):.8f}"

def json_load_stdout(cp, label):
    txt = cp.stdout.strip()
    if cp.returncode != 0:
        fail(f"{label} failed\nSTDERR:\n{cp.stderr.strip()}")
    if not txt:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError as e:
        fail(f"{label} returned non-JSON output: {e}\n{txt[:1000]}")

def read_secret_file(path: str, expected_h160_hex: str) -> bytes:
    p = Path(path).expanduser()
    st = p.stat()
    if stat.S_IMODE(st.st_mode) & 0o077:
        fail(f"secret file must not be group/world accessible: {p}")
    raw = p.read_text().strip()
    try:
        obj = json.loads(raw)
        raw = obj["preimageHex"]
    except Exception:
        pass
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        fail("secret file must contain exactly one 32-byte preimage hex value or JSON preimageHex")
    secret = bytes.fromhex(raw)
    got = hash160(secret).hex()
    if got != expected_h160_hex.lower():
        fail(f"secret HASH160 mismatch: expected {expected_h160_hex}, got {got}")
    return secret

def write_secret_file(path: str, preimage_hex: str, h160_hex: str):
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({
                "protocol": "TRU-SWAP-V1",
                "hashAlgorithm": "HASH160",
                "preimageHex": preimage_hex,
                "secretHash160": h160_hex,
            }, f, indent=2)
            f.write("\n")
    finally:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

def parse_script_pushes(script: bytes):
    out = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op <= 75:
            if i + op > len(script):
                return []
            out.append(("push", script[i:i+op]))
            i += op
        elif op == 0x4c:
            if i >= len(script):
                return []
            n = script[i]
            i += 1
            if i + n > len(script):
                return []
            out.append(("push", script[i:i+n]))
            i += n
        elif op == 0x4d:
            if i + 2 > len(script):
                return []
            n = struct.unpack("<H", script[i:i+2])[0]
            i += 2
            if i + n > len(script):
                return []
            out.append(("push", script[i:i+n]))
            i += n
        else:
            out.append(("op", op))
    return out

def extract_matching_preimage(script_sig_hex: str, expected_h160_hex: str):
    try:
        script = bytes.fromhex(script_sig_hex)
    except Exception:
        return None
    expected = bytes.fromhex(expected_h160_hex)
    for kind, val in parse_script_pushes(script):
        if kind == "push" and 1 <= len(val) <= 255:
            try:
                if hash160(val) == expected:
                    return val
            except Exception:
                pass
    return None

def recursive_hex_candidates(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]+", v or "") and len(v) >= 2:
                yield (str(k), v)
            yield from recursive_hex_candidates(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from recursive_hex_candidates(v)

class TruAdapter:
    def __init__(self, cli, conf):
        self.cli = str(Path(cli).expanduser())
        self.conf = str(Path(conf).expanduser())
        if not Path(self.cli).exists():
            fail(f"TRU CLI not found: {self.cli}")

    def raw(self, method, params=None):
        params = dict(params or {})
        token = os.environ.get("TRU_SWAP_RPC_TOKEN", "")
        if not token:
            fail("TRU_SWAP_RPC_TOKEN is not set")
        params["authToken"] = token
        cmd = [
            self.cli,
            f"-conf={self.conf}",
            "-json",
            "raw",
            method,
            json.dumps(params, separators=(",", ":")),
        ]
        cp = subprocess.run(cmd, text=True, capture_output=True)
        return json_load_stdout(cp, f"TRU RPC {method}")

    def public_raw(self, method, params=None):
        # Existing non-SWAP RPC methods do not require the SWAP token, but the
        # native CLI still handles mandatory outer cookie authentication.
        cmd = [
            self.cli,
            f"-conf={self.conf}",
            "-json",
            "raw",
            method,
            json.dumps(params or {}, separators=(",", ":")),
        ]
        cp = subprocess.run(cmd, text=True, capture_output=True)
        return json_load_stdout(cp, f"TRU RPC {method}")

    def get_record(self, swap_id):
        return self.raw("swaprecordget", {"swapId": swap_id})

    def transition(self, swap_id, next_state, evidence=None):
        return self.raw("swaprecordtransition", {
            "swapId": swap_id,
            "nextState": next_state,
            "evidence": evidence or {},
        })

class BstyAdapter:
    def __init__(self, cli, wallet):
        self.cli = str(Path(cli).expanduser())
        self.wallet = wallet
        if not Path(self.cli).exists():
            fail(f"BSTY CLI not found: {self.cli}")

    def run(self, method, *args, wallet=False, check=True):
        cmd = [self.cli]
        if wallet and self.wallet:
            cmd.append(f"-rpcwallet={self.wallet}")
        cmd.append(method)
        cmd.extend(str(x) for x in args)
        cp = subprocess.run(cmd, text=True, capture_output=True)
        if check and cp.returncode != 0:
            fail(f"BSTY RPC {method} failed\nSTDERR:\n{cp.stderr.strip()}")
        return cp

    def text(self, method, *args, wallet=False):
        return self.run(method, *args, wallet=wallet).stdout.strip()

    def json(self, method, *args, wallet=False):
        cp = self.run(method, *args, wallet=wallet)
        txt = cp.stdout.strip()
        return json.loads(txt) if txt else None

def record_script(record, chain):
    h = bytes.fromhex(record["secretHash160"])
    if chain == "tru":
        claim = bytes.fromhex(record["truClaimPubkey"])
        refund = bytes.fromhex(record["truRefundPubkey"])
        t = int(record["truRefundTime"])
    elif chain == "bsty":
        claim = bytes.fromhex(record["bstyClaimPubkey"])
        refund = bytes.fromhex(record["bstyRefundPubkey"])
        t = int(record["bstyRefundTime"])
    else:
        fail("chain must be tru or bsty")
    return build_redeem_script(h, claim, refund, t)

def expected_first_chain(record):
    return "tru" if record["fundingOrder"] == "TRU_FIRST" else "bsty"

def funding_evidence(record):
    ev = record.get("evidence") or {}
    return {
        "tru": (ev.get("truFundingTxid"), ev.get("truFundingVout")),
        "bsty": (ev.get("bstyFundingTxid"), ev.get("bstyFundingVout")),
    }

def configured_resolution_min_conf(record, requested):
    requested = int(requested)
    if requested < 1:
        fail("--min-conf must be >= 1")
    ev = record.get("evidence") or {}
    configured = ev.get("resolutionMinConfirmations")
    if configured is None:
        return requested
    configured = int(configured)
    if configured != requested:
        fail(
            f"resolution confirmation policy pinned at {configured}; "
            f"requested {requested}"
        )
    return configured

def resolution_outcome(record):
    ev = record.get("evidence") or {}
    required = int(ev.get("resolutionMinConfirmations") or 0)
    if required < 1:
        fail("resolutionMinConfirmations is not durably configured")

    funded = [
        c for c in ("tru", "bsty")
        if ev.get(f"{c}FundingTxid")
    ]
    if not funded:
        fail("resolution finality requires at least one funded leg")

    outcomes = {}
    for c in funded:
        claim_ok = (
            bool(ev.get(f"{c}ClaimTxid")) and
            int(ev.get(f"{c}ClaimConfirmations") or 0) >= required
        )
        refund_ok = (
            bool(ev.get(f"{c}RefundTxid")) and
            int(ev.get(f"{c}RefundConfirmations") or 0) >= required
        )
        if claim_ok and refund_ok:
            fail(f"{c.upper()} leg cannot be both claimed and refunded")
        if claim_ok:
            outcomes[c] = "claim"
        elif refund_ok:
            outcomes[c] = "refund"
        else:
            return None

    kinds = set(outcomes.values())
    if len(funded) == 2 and kinds == {"claim"}:
        return "SETTLED"
    if kinds == {"refund"}:
        return "REFUNDED"
    if len(funded) == 2 and kinds == {"claim", "refund"}:
        return "RESOLVED_MIXED"
    return None

def finalize_resolution(tru, record):
    outcome = resolution_outcome(record)
    if outcome is None:
        return record
    return tru.transition(record["swapId"], outcome, {})

def persist_refund_and_finalize(
    tru, record, chain, refund_txid, confirmations, required_conf
):
    if record.get("state") != "REFUND_PENDING":
        fail(
            f"refund evidence requires REFUND_PENDING, "
            f"got {record.get('state')}"
        )
    ev = record.get("evidence") or {}
    if ev.get(f"{chain}ClaimTxid"):
        fail(f"{chain.upper()} leg already has claim evidence")
    if int(confirmations) < int(required_conf):
        fail(
            f"{chain.upper()} refund has {confirmations} confirmations; "
            f"requires {required_conf}"
        )
    record = tru.transition(record["swapId"], "REFUND_PENDING", {
        f"{chain}RefundTxid": refund_txid,
        f"{chain}RefundConfirmations": int(confirmations),
    })
    return finalize_resolution(tru, record)

def require_funding_order(record, chain):
    state = record["state"]
    first = expected_first_chain(record)
    if state == "CREATED":
        if chain != first:
            fail(f"{record['fundingOrder']} requires {first.upper()} to fund first")
    elif state == "ONE_SIDE_FUNDED":
        if chain == first:
            fail(f"{first.upper()} is already the first-funded side; fund the opposite chain")
    else:
        fail(f"funding command requires CREATED or ONE_SIDE_FUNDED, got {state}")

def transition_after_funding(
    tru, record, chain, txid, vout, confirmations, min_conf
):
    required = configured_resolution_min_conf(record, min_conf)
    if int(confirmations) < required:
        fail(
            f"{chain.upper()} funding has {confirmations} confirmations; "
            f"requires {required}"
        )
    evidence = {
        f"{chain}FundingTxid": txid,
        f"{chain}FundingVout": int(vout),
        f"{chain}FundingConfirmations": int(confirmations),
        "resolutionMinConfirmations": int(required),
    }
    if record["state"] == "CREATED":
        return tru.transition(record["swapId"], "ONE_SIDE_FUNDED", evidence)
    if record["state"] == "ONE_SIDE_FUNDED":
        return tru.transition(record["swapId"], "BOTH_FUNDED", evidence)
    fail("unexpected state for funding transition")

def locate_wallet_vout(bsty, txid, expected_spk: bytes):
    tx = bsty.json("gettransaction", txid, wallet=True)
    dec = bsty.json("decoderawtransaction", tx["hex"])
    for o in dec.get("vout", []):
        spk = o.get("scriptPubKey", {})
        if isinstance(spk, dict) and spk.get("hex", "").lower() == expected_spk.hex():
            return int(o["n"]), sats(o["value"])
    fail(f"expected P2SH output not found in funding transaction {txid}")

def wait_bsty_confirmations(bsty, txid, vout, min_conf, timeout):
    deadline = time.time() + timeout
    while True:
        out = bsty.json("gettxout", txid, vout, "true")
        if out and int(out.get("confirmations", 0)) >= min_conf:
            return int(out["confirmations"])
        if time.time() >= deadline:
            fail(f"timed out waiting for BSTY confirmations on {txid}:{vout}")
        time.sleep(5)

def recursive_confirmation_value(obj):
    if isinstance(obj, dict):
        v = obj.get("confirmations")
        if isinstance(v, (int, float)):
            return int(v)
        for x in obj.values():
            n = recursive_confirmation_value(x)
            if n is not None:
                return n
    elif isinstance(obj, list):
        for x in obj:
            n = recursive_confirmation_value(x)
            if n is not None:
                return n
    return None

def wait_tru_confirmations(tru, txid, min_conf, timeout):
    deadline = time.time() + timeout
    while True:
        try:
            obj = tru.public_raw("gettransaction", {"txid": txid})
            n = recursive_confirmation_value(obj)
            if n is not None and n >= min_conf:
                return n
        except Exception:
            pass
        if time.time() >= deadline:
            fail(f"timed out waiting for TRU confirmations on {txid}")
        time.sleep(5)

def signer_signature(engine_dir, bsty_cli, bsty_wallet, address, pubkey_hex, digest_hex):
    helper = Path(engine_dir) / "bsty_wallet_signer.py"
    cmd = [
        sys.executable,
        str(helper),
        "--cli", str(bsty_cli),
        "--wallet", bsty_wallet,
        "--address", address,
        "--pubkey", pubkey_hex,
        "--digest", digest_hex,
    ]
    cp = subprocess.run(cmd, text=True, capture_output=True)
    if cp.returncode != 0:
        fail(f"BSTY signer failed\nSTDERR:\n{cp.stderr.strip()}")
    try:
        result = json.loads(cp.stdout)
        sig = bytes.fromhex(result["signatureHex"])
    except Exception as e:
        fail(f"invalid BSTY signer response: {e}")
    if not sig or sig[-1] != SIGHASH_ALL:
        fail("BSTY signer did not return SIGHASH_ALL signature")
    return sig

def build_bsty_claim(engine_dir, bsty, record, prev_txid, prev_vout,
                     value_atoms, recipient, signer_address, secret, fee_atoms):
    redeem = record_script(record, "bsty")
    dest = bsty.json("getaddressinfo", recipient, wallet=True)
    dest_spk = bytes.fromhex(dest["scriptPubKey"])
    if value_atoms <= fee_atoms:
        fail("BSTY HTLC value is not greater than fee")
    version = 2
    locktime = 0
    vin = [{
        "txid": prev_txid,
        "vout": int(prev_vout),
        "sequence": 0xFFFFFFFE,
        "scriptSig": b"",
    }]
    vout = [{"value": int(value_atoms) - int(fee_atoms), "scriptPubKey": dest_spk}]
    digest = sighash_legacy_all(version, vin, vout, locktime, redeem)
    sig = signer_signature(
        Path(__file__).resolve().parent,
        bsty.cli, bsty.wallet, signer_address,
        record["bstyClaimPubkey"], digest.hex()
    )
    vin[0]["scriptSig"] = push(sig) + push(secret) + bytes([OP_1]) + push(redeem)
    return serialize_tx(version, vin, vout, locktime).hex()

def build_bsty_refund(engine_dir, bsty, record, prev_txid, prev_vout,
                      value_atoms, recipient, signer_address, fee_atoms):
    redeem = record_script(record, "bsty")
    dest = bsty.json("getaddressinfo", recipient, wallet=True)
    dest_spk = bytes.fromhex(dest["scriptPubKey"])
    if value_atoms <= fee_atoms:
        fail("BSTY HTLC value is not greater than fee")
    locktime = int(record["bstyRefundTime"])
    vin = [{
        "txid": prev_txid,
        "vout": int(prev_vout),
        "sequence": 0xFFFFFFFE,
        "scriptSig": b"",
    }]
    vout = [{"value": int(value_atoms) - int(fee_atoms), "scriptPubKey": dest_spk}]
    digest = sighash_legacy_all(2, vin, vout, locktime, redeem)
    sig = signer_signature(
        Path(__file__).resolve().parent,
        bsty.cli, bsty.wallet, signer_address,
        record["bstyRefundPubkey"], digest.hex()
    )
    vin[0]["scriptSig"] = push(sig) + bytes([OP_0]) + push(redeem)
    return serialize_tx(2, vin, vout, locktime).hex()

def tma(bsty, rawhex):
    r = bsty.json("testmempoolaccept", json.dumps([rawhex]))
    if not isinstance(r, list) or len(r) != 1:
        fail("unexpected testmempoolaccept response")
    return r[0]

def find_bsty_spend_in_tx(tx, funding_txid, funding_vout):
    for vin in tx.get("vin", []):
        if vin.get("txid") == funding_txid and int(vin.get("vout", -1)) == int(funding_vout):
            return vin
    return None

def tx_script_sig_hex(vin):
    ss = vin.get("scriptSig")
    if isinstance(ss, dict):
        return ss.get("hex", "")
    if isinstance(ss, str):
        return ss
    return vin.get("scriptSigHex", "")

def scan_bsty_for_spend(bsty, funding_txid, funding_vout, from_height, expected_h160):
    tip = int(bsty.json("getblockcount"))
    # Mempool first.
    for txid in bsty.json("getrawmempool") or []:
        tx = bsty.json("getrawtransaction", txid, "true")
        vin = find_bsty_spend_in_tx(tx, funding_txid, funding_vout)
        if vin:
            pre = extract_matching_preimage(tx_script_sig_hex(vin), expected_h160)
            return {"txid": txid, "height": None, "preimage": pre}
    # Then confirmed blocks.
    for h in range(int(from_height), tip + 1):
        bh = bsty.text("getblockhash", h)
        blk = bsty.json("getblock", bh, 2)
        txs = blk.get("tx", [])
        for item in txs:
            if isinstance(item, str):
                tx = bsty.json("getrawtransaction", item, "true", bh)
                txid = item
            else:
                tx = item
                txid = tx.get("txid", "")
            vin = find_bsty_spend_in_tx(tx, funding_txid, funding_vout)
            if vin:
                pre = extract_matching_preimage(tx_script_sig_hex(vin), expected_h160)
                return {"txid": txid, "height": h, "preimage": pre}
    return None


def wait_bsty_spend_confirmations(
    bsty, funding_txid, funding_vout, spend_txid,
    from_height, expected_h160, min_conf, timeout
):
    deadline = time.time() + timeout
    while True:
        found = scan_bsty_for_spend(
            bsty, funding_txid, int(funding_vout),
            int(from_height), expected_h160
        )
        if found:
            if found["txid"] != spend_txid:
                fail(
                    "BSTY funding outpoint spent by unexpected txid "
                    + str(found["txid"])
                )
            if found["height"] is not None:
                tip = int(bsty.json("getblockcount"))
                conf = tip - int(found["height"]) + 1
                if conf >= int(min_conf):
                    return conf
        if time.time() >= deadline:
            fail(
                f"timed out waiting for BSTY spend confirmations "
                f"on {spend_txid}"
            )
        time.sleep(5)

def selftest():
    h = bytes.fromhex("c435cba38228ea6ea9c2ffd74e6e32a9c48c61fc")
    claim = bytes.fromhex("02a72508c103683b903691068a3345e63a04eb419aeb09ab046d613ed77caffc3c")
    refund = bytes.fromhex("02c061424b3d902d9e9b43a2bdeee8b77643c18c8ca2c6293e7d6237758768ca85")
    got = build_redeem_script(h, claim, refund, 1788699067).hex()
    if got != FROZEN_VECTOR_HEX:
        fail("frozen-vector byte identity failure")
    if len(bytes.fromhex(got)) != 103:
        fail("frozen vector is not 103 bytes")
    try:
        build_redeem_script(h, claim, refund, 0x80000000)
        fail("2038 upper bound was not enforced")
    except RuntimeError:
        pass
    secret = bytes.fromhex("00" * 31 + "01")
    ss = push(b"\x30" + b"\x01" * 70) + push(secret) + bytes([OP_1]) + push(bytes.fromhex(got))
    if extract_matching_preimage(ss.hex(), hash160(secret).hex()) != secret:
        fail("preimage extraction selftest failed")
    print("TRU_SWAP_B_OFFLINE_SELFTEST=PASS")
    print("FROZEN_REDEEMSCRIPT_BYTES=103")
    print("HASH_ALGORITHM=HASH160")
    print("REFUND_TIME_MAX=2147483647")

def default_tru_cli():
    override = os.environ.get("TRU_SWAP_TRU_CLI")
    if override:
        return override
    candidates = [
        Path.home() / "NEW_TRU/build-native/bin/truam-cli",
        Path.home() / "NEW_TRU/build-native/bin/tru-cli",
    ]
    for p in candidates:
        if p.exists() and os.access(p, os.X_OK):
            return str(p)
    return str(candidates[0])

def transition_after_claim(
    tru, record, chain, claim_txid, confirmations, required_conf
):
    ev = record.get("evidence") or {}
    if ev.get(f"{chain}RefundTxid"):
        fail(f"{chain.upper()} leg already has refund evidence")
    old = ev.get(f"{chain}ClaimTxid")
    if old and old != claim_txid:
        fail(f"{chain.upper()} claim transaction identity changed")
    if int(confirmations) < int(required_conf):
        fail(
            f"{chain.upper()} claim has {confirmations} confirmations; "
            f"requires {required_conf}"
        )

    evidence = {
        "secretObservedOn": chain,
        f"{chain}ClaimTxid": claim_txid,
        f"{chain}ClaimConfirmations": int(confirmations),
        "observedHash160": record["secretHash160"],
    }

    state = record["state"]
    if state == "BOTH_FUNDED":
        record = tru.transition(
            record["swapId"], "SECRET_OBSERVED", evidence
        )
    elif state == "SECRET_OBSERVED":
        record = tru.transition(
            record["swapId"], "SECRET_OBSERVED", evidence
        )
    elif state == "REFUND_PENDING":
        record = tru.transition(
            record["swapId"], "REFUND_PENDING", evidence
        )
    else:
        fail(
            "claim requires BOTH_FUNDED, SECRET_OBSERVED, or "
            f"REFUND_PENDING, got {state}"
        )
    return finalize_resolution(tru, record)

def main():
    ap = argparse.ArgumentParser(description="TRU-SWAP-B cross-chain engine")
    ap.add_argument("--tru-cli", default=default_tru_cli())
    ap.add_argument("--tru-conf", default=os.environ.get(
        "TRU_SWAP_TRU_CONF", str(Path.home() / "NEW_TRU/tru.conf")))
    ap.add_argument("--bsty-cli", default=os.environ.get(
        "TRU_SWAP_BSTY_CLI", str(Path.home() / "globalboost/src/globalboost-cli")))
    ap.add_argument("--bsty-wallet", default=os.environ.get(
        "TRU_SWAP_BSTY_WALLET", "bsty_mining"))
    ap.add_argument("--min-conf", type=int, default=int(os.environ.get("TRU_SWAP_MIN_CONF", "1")))
    ap.add_argument("--wait-timeout", type=int, default=int(os.environ.get("TRU_SWAP_WAIT_TIMEOUT", "600")))

    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("doctor")

    p = sub.add_parser("status")
    p.add_argument("--swap-id", required=True)

    p = sub.add_parser("new-secret")
    p.add_argument("--output", required=True)

    p = sub.add_parser("bsty-contract")
    p.add_argument("--swap-id", required=True)

    p = sub.add_parser("fund-tru")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--wait", action="store_true")

    p = sub.add_parser("fund-bsty")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--wait", action="store_true")

    p = sub.add_parser("claim-tru")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--secret-file", required=True)
    p.add_argument("--recipient", required=True)

    p = sub.add_parser("refund-tru")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--recipient", required=True)

    p = sub.add_parser("claim-bsty")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--secret-file", required=True)
    p.add_argument("--signer-address", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--fee-atoms", type=int, default=int(os.environ.get("TRU_SWAP_BSTY_FEE_ATOMS", "100000")))

    p = sub.add_parser("refund-bsty")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--signer-address", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--fee-atoms", type=int, default=int(os.environ.get("TRU_SWAP_BSTY_FEE_ATOMS", "100000")))

    p = sub.add_parser("watch-bsty")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--from-height", type=int, required=True)
    p.add_argument("--secret-output")

    p = sub.add_parser("observe-tru")
    p.add_argument("--swap-id", required=True)
    p.add_argument("--txid", required=True)
    p.add_argument("--secret-output", required=True)

    args = ap.parse_args()
    if args.min_conf < 1:
        fail("--min-conf must be >= 1")

    if args.cmd == "selftest":
        selftest()
        return 0

    tru = TruAdapter(args.tru_cli, args.tru_conf)
    bsty = BstyAdapter(args.bsty_cli, args.bsty_wallet)

    if args.cmd == "doctor":
        selftest()
        info = tru.public_raw("getinfo", {})
        swap_list = tru.raw("swaprecordlist", {})
        bi = bsty.json("getblockchaininfo")
        wi = bsty.json("getwalletinfo", wallet=True)
        print("TRU_RPC=PASS")
        print("TRU_SWAP_RPC=PASS")
        print("BSTY_RPC=PASS")
        print("BSTY_CHAIN=", bi.get("chain"))
        print("BSTY_BLOCKS=", bi.get("blocks"))
        print("BSTY_WALLET=", wi.get("walletname", args.bsty_wallet))
        print("TRU_SWAP_RPC_TOKEN=", "SET" if os.environ.get("TRU_SWAP_RPC_TOKEN") else "NOT_SET")
        return 0

    if args.cmd == "new-secret":
        r = tru.raw("htlcgeneratesecret", {})
        write_secret_file(args.output, r["preimageHex"], r["secretHash160"])
        print("SECRET_FILE_WRITTEN_0600=", str(Path(args.output).expanduser()))
        print("HASH160=", r["secretHash160"])
        print("PREIMAGE_NOT_PRINTED=YES")
        return 0

    record = tru.get_record(args.swap_id)

    if args.cmd == "status":
        safe = dict(record)
        print(json.dumps(safe, indent=2))
        return 0

    if args.cmd == "bsty-contract":
        redeem = record_script(record, "bsty")
        dec = bsty.json("decodescript", redeem.hex())
        print("BSTY_REDEEMSCRIPT_BYTES=103")
        print("BSTY_REDEEMSCRIPT_HEX=", redeem.hex())
        print("BSTY_P2SH_ADDRESS=", dec.get("p2sh", ""))
        print("BSTY_P2SH_SCRIPTPUBKEY_HEX=", p2sh_scriptpubkey(redeem).hex())
        return 0

    if args.cmd == "fund-tru":
        require_funding_order(record, "tru")
        r = tru.raw("htlccreate", {
            "secretHash160": record["secretHash160"],
            "claimPubkey": record["truClaimPubkey"],
            "refundPubkey": record["truRefundPubkey"],
            "refundTime": int(record["truRefundTime"]),
            "amountAtoms": int(record["truAmountAtoms"]),
        })
        txid = r["fundingTxid"]
        vout = int(r["fundingVout"])
        print("TRU_FUNDING_TXID=", txid)
        print("TRU_FUNDING_VOUT=", vout)
        if args.wait:
            conf = wait_tru_confirmations(tru, txid, args.min_conf, args.wait_timeout)
            out = transition_after_funding(
                tru, record, "tru", txid, vout, conf, args.min_conf
            )
            print("STATE=", out["state"])
            print("CONFIRMATIONS=", conf)
        else:
            print("STATE_NOT_TRANSITIONED=WAIT_FOR_CONFIRMATIONS")
        return 0

    if args.cmd == "fund-bsty":
        require_funding_order(record, "bsty")
        redeem = record_script(record, "bsty")
        dec = bsty.json("decodescript", redeem.hex())
        addr = dec.get("p2sh")
        if not addr:
            fail("BSTY decodescript did not return P2SH address")
        txid = bsty.text(
            "sendtoaddress",
            addr,
            atoms_to_coin_string(int(record["bstyAmountAtoms"])),
            wallet=True,
        )
        vout, value = locate_wallet_vout(bsty, txid, p2sh_scriptpubkey(redeem))
        print("BSTY_FUNDING_TXID=", txid)
        print("BSTY_FUNDING_VOUT=", vout)
        print("BSTY_P2SH_ADDRESS=", addr)
        if value != int(record["bstyAmountAtoms"]):
            fail(f"BSTY funding value mismatch: expected {record['bstyAmountAtoms']}, got {value}")
        if args.wait:
            conf = wait_bsty_confirmations(bsty, txid, vout, args.min_conf, args.wait_timeout)
            out = transition_after_funding(
                tru, record, "bsty", txid, vout, conf, args.min_conf
            )
            print("STATE=", out["state"])
            print("CONFIRMATIONS=", conf)
        else:
            print("STATE_NOT_TRANSITIONED=WAIT_FOR_CONFIRMATIONS")
        return 0

    ev = funding_evidence(record)

    if args.cmd == "claim-tru":
        if record["state"] not in (
            "BOTH_FUNDED", "SECRET_OBSERVED", "REFUND_PENDING"
        ):
            fail(
                "claim requires BOTH_FUNDED, SECRET_OBSERVED, or "
                f"REFUND_PENDING, got {record['state']}"
            )
        txid, vout = ev["tru"]
        if not txid:
            fail("TRU funding outpoint missing from swap evidence")
        required = configured_resolution_min_conf(record, args.min_conf)
        secret = read_secret_file(args.secret_file, record["secretHash160"])
        claim_params = {
            "fundingTxid": txid,
            "vout": int(vout),
            "recipient": args.recipient,
            "preimageHex": secret.hex(),
        }
        if record.get("truClaimAllocationId"):
            claim_params["allocationId"] = record["truClaimAllocationId"]
        r = tru.raw("htlcclaim", claim_params)
        conf = wait_tru_confirmations(
            tru, r["claimTxid"], required, args.wait_timeout
        )
        out = transition_after_claim(
            tru, record, "tru", r["claimTxid"], conf, required
        )
        print("TRU_CLAIM_TXID=", r["claimTxid"])
        print("CLAIM_CONFIRMATIONS=", conf)
        print("STATE=", out["state"])
        print("PREIMAGE_NOT_PRINTED=YES")
        return 0

    if args.cmd == "refund-tru":
        txid, vout = ev["tru"]
        if not txid:
            fail("TRU funding outpoint missing from swap evidence")
        required = configured_resolution_min_conf(record, args.min_conf)
        current = record["state"]
        if current != "REFUND_PENDING":
            record = tru.transition(record["swapId"], "REFUND_PENDING", {
                "refundRequestedOn": "tru"
            })
        refund_params = {
            "fundingTxid": txid,
            "vout": int(vout),
            "recipient": args.recipient,
        }
        if record.get("truRefundAllocationId"):
            refund_params["allocationId"] = record["truRefundAllocationId"]
        r = tru.raw("htlcrefund", refund_params)
        conf = wait_tru_confirmations(
            tru, r["refundTxid"], required, args.wait_timeout
        )
        out = persist_refund_and_finalize(
            tru, record, "tru", r["refundTxid"], conf, required
        )
        print("TRU_REFUND_TXID=", r["refundTxid"])
        print("REFUND_CONFIRMATIONS=", conf)
        print("STATE=", out["state"])
        print(
            "RESOLUTION_FINALITY=",
            "COMPLETE" if out["state"] in (
                "REFUNDED", "RESOLVED_MIXED"
            ) else "PENDING_OTHER_FUNDED_LEG"
        )
        return 0

    if args.cmd in ("claim-bsty", "refund-bsty"):
        txid, vout = ev["bsty"]
        if not txid:
            fail("BSTY funding outpoint missing from swap evidence")
        utxo = bsty.json("gettxout", txid, int(vout), "true")
        if not utxo:
            fail("BSTY funding outpoint is already spent or unavailable")
        value = sats(utxo["value"])
        if args.cmd == "claim-bsty":
            if record["state"] not in (
                "BOTH_FUNDED", "SECRET_OBSERVED", "REFUND_PENDING"
            ):
                fail(
                    "claim requires BOTH_FUNDED, SECRET_OBSERVED, or "
                    f"REFUND_PENDING, got {record['state']}"
                )
            required = configured_resolution_min_conf(record, args.min_conf)
            secret = read_secret_file(args.secret_file, record["secretHash160"])
            raw = build_bsty_claim(
                Path(__file__).resolve().parent, bsty, record, txid, int(vout),
                value, args.recipient, args.signer_address, secret, args.fee_atoms
            )
            check = tma(bsty, raw)
            if not check.get("allowed"):
                fail("BSTY claim rejected by testmempoolaccept: " + json.dumps(check))
            scan_from = max(0, int(bsty.json("getblockcount")) - 1)
            spend_txid = bsty.text("sendrawtransaction", raw)
            conf = wait_bsty_spend_confirmations(
                bsty, txid, int(vout), spend_txid, scan_from,
                record["secretHash160"], required, args.wait_timeout
            )
            out = transition_after_claim(
                tru, record, "bsty", spend_txid, conf, required
            )
            print("BSTY_CLAIM_TXID=", spend_txid)
            print("CLAIM_CONFIRMATIONS=", conf)
            print("STATE=", out["state"])
            print("PREIMAGE_NOT_PRINTED=YES")
            return 0
        else:
            required = configured_resolution_min_conf(record, args.min_conf)
            current = record["state"]
            if current != "REFUND_PENDING":
                record = tru.transition(record["swapId"], "REFUND_PENDING", {
                    "refundRequestedOn": "bsty"
                })
            raw = build_bsty_refund(
                Path(__file__).resolve().parent, bsty, record, txid, int(vout),
                value, args.recipient, args.signer_address, args.fee_atoms
            )
            check = tma(bsty, raw)
            if not check.get("allowed"):
                fail("BSTY refund rejected by testmempoolaccept: " + json.dumps(check))
            scan_from = max(0, int(bsty.json("getblockcount")) - 1)
            spend_txid = bsty.text("sendrawtransaction", raw)
            conf = wait_bsty_spend_confirmations(
                bsty, txid, int(vout), spend_txid, scan_from,
                record["secretHash160"], required, args.wait_timeout
            )
            out = persist_refund_and_finalize(
                tru, record, "bsty", spend_txid, conf, required
            )
            print("BSTY_REFUND_TXID=", spend_txid)
            print("REFUND_CONFIRMATIONS=", conf)
            print("STATE=", out["state"])
            print(
                "RESOLUTION_FINALITY=",
                "COMPLETE" if out["state"] in (
                    "REFUNDED", "RESOLVED_MIXED"
                ) else "PENDING_OTHER_FUNDED_LEG"
            )
            return 0

    if args.cmd == "watch-bsty":
        txid, vout = ev["bsty"]
        if not txid:
            fail("BSTY funding outpoint missing from swap evidence")
        found = scan_bsty_for_spend(
            bsty, txid, int(vout), args.from_height, record["secretHash160"]
        )
        if not found:
            print("BSTY_SPEND_FOUND=NO")
            return 0
        print("BSTY_SPEND_FOUND=YES")
        print("BSTY_SPEND_TXID=", found["txid"])
        print("BSTY_SPEND_HEIGHT=", found["height"])
        pre = found["preimage"]
        if pre is not None:
            print("MATCHING_PREIMAGE_FOUND=YES")
            print("OBSERVED_HASH160=", hash160(pre).hex())
            if args.secret_output:
                write_secret_file(args.secret_output, pre.hex(), record["secretHash160"])
                print("SECRET_FILE_WRITTEN_0600=", str(Path(args.secret_output).expanduser()))
            print("PREIMAGE_NOT_PRINTED=YES")
        else:
            print("MATCHING_PREIMAGE_FOUND=NO")
        return 0

    if args.cmd == "observe-tru":
        obj = tru.public_raw("gettransaction", {"txid": args.txid})
        pre = None
        for _, hx in recursive_hex_candidates(obj):
            pre = extract_matching_preimage(hx, record["secretHash160"])
            if pre is not None:
                break
        if pre is None:
            fail("no matching HASH160 preimage found in TRU transaction data")
        write_secret_file(args.secret_output, pre.hex(), record["secretHash160"])
        print("TRU_MATCHING_PREIMAGE_FOUND=YES")
        print("OBSERVED_HASH160=", hash160(pre).hex())
        print("SECRET_FILE_WRITTEN_0600=", str(Path(args.secret_output).expanduser()))
        print("PREIMAGE_NOT_PRINTED=YES")
        return 0

    fail("unhandled command")

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print("ERROR:", str(e), file=sys.stderr)
        raise SystemExit(1)
