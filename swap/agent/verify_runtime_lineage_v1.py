#!/usr/bin/env python3
"""Verify portable release pins plus the current machine's compiled-node receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

VERSION = "TRU-PORTABLE-LINEAGE-01"
LEDGER = "swap/POST_GROUP05_ACTIVE_LINEAGE.json"
SOURCE_MANIFEST = "swap/PORTABLE_BUILD_SOURCE_PINS.json"
RECEIPT = ".runtime_verify/TRU_PORTABLE_LINEAGE_01/ACTIVE.json"
BINARY = "build-native/bin/tru_advanced"


def fail(message: str) -> None:
    raise RuntimeError(message)


def strict_json(raw: bytes):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                fail("duplicate JSON key: " + key)
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_file(root: Path, relative: str) -> Path:
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        fail("unsafe runtime path: " + str(relative))
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            fail("symlinked runtime path: " + relative)
    if not path.is_file():
        fail("missing runtime file: " + relative)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("aliased/nonregular runtime file: " + relative)
    return path


def file_digest(root: Path, relative: str) -> str:
    h = hashlib.sha256()
    with safe_file(root, relative).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def valid_hash(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def release_identity(ledger) -> str:
    portable = ledger.get("portableRuntime")
    if not isinstance(portable, dict):
        fail("portable runtime declaration missing")
    body = {
        "buildSourceSetSha256": portable.get("buildSourceSetSha256"),
        "lineageVersion": ledger.get("version"),
        "pins": ledger.get("pins"),
        "portableVersion": VERSION,
    }
    return digest(canonical(body))


def verify(root: Path) -> dict:
    root = root.expanduser().resolve()
    ledger = strict_json(safe_file(root, LEDGER).read_bytes())
    pins = ledger.get("pins")
    if not isinstance(pins, dict) or not pins:
        fail("release pin set missing")
    if BINARY in pins:
        fail("machine-specific binary hash is still present in the Git release ledger")

    portable = ledger.get("portableRuntime")
    expected_declaration = {
        "binaryPath": BINARY,
        "buildSourceManifest": SOURCE_MANIFEST,
        "buildSourceSetSha256": digest(safe_file(root, SOURCE_MANIFEST).read_bytes()),
        "machineSpecificBinaryInGit": False,
        "receiptPath": RECEIPT,
        "version": VERSION,
    }
    if not isinstance(portable, dict):
        fail("portable runtime declaration missing")
    for key, value in expected_declaration.items():
        if portable.get(key) != value:
            fail("portable runtime declaration mismatch: " + key)
    if not valid_hash(portable.get("releaseId")):
        fail("invalid portable release identity")
    if portable["releaseId"] != release_identity(ledger):
        fail("portable release identity mismatch")

    for relative, expected in pins.items():
        if not valid_hash(expected):
            fail("invalid release pin: " + relative)
        actual = file_digest(root, relative)
        if actual != expected:
            fail("release pin mismatch: " + relative + "\nEXPECTED=" + expected + "\nACTUAL=" + actual)

    source_raw = safe_file(root, SOURCE_MANIFEST).read_bytes()
    source_pins = strict_json(source_raw)
    if not isinstance(source_pins, dict) or not source_pins:
        fail("build source manifest is empty")
    for relative, expected in source_pins.items():
        if not valid_hash(expected):
            fail("invalid build-source pin: " + relative)
        actual = file_digest(root, relative)
        if actual != expected:
            fail("build-source mismatch: " + relative + "\nEXPECTED=" + expected + "\nACTUAL=" + actual)

    receipt_path = safe_file(root, RECEIPT)
    if receipt_path.stat().st_uid != os.geteuid():
        fail("machine receipt is not owned by the current user")
    receipt = strict_json(receipt_path.read_bytes())
    required = {
        "binaryPath": BINARY,
        "build": "ISOLATED_FROM_EXACT_RELEASE_SOURCE",
        "buildSourceSetSha256": portable["buildSourceSetSha256"],
        "releaseId": portable["releaseId"],
        "version": VERSION,
    }
    for key, value in required.items():
        if receipt.get(key) != value:
            fail("machine receipt mismatch: " + key)
    binary_hash = receipt.get("binarySha256")
    if not valid_hash(binary_hash):
        fail("machine receipt binary hash is invalid")
    if file_digest(root, BINARY) != binary_hash:
        fail("local compiled binary differs from its machine receipt")
    binary = safe_file(root, BINARY)
    if binary.stat().st_uid != os.geteuid() or not os.access(binary, os.X_OK):
        fail("local compiled binary ownership/executable mode mismatch")
    with binary.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            fail("local compiled node is not an ELF executable")
    return {"releaseId": portable["releaseId"], "binarySha256": binary_hash}


def main() -> int:
    parser = argparse.ArgumentParser(description=VERSION)
    parser.add_argument("--tru-root", required=True)
    args = parser.parse_args()
    result = verify(Path(args.tru_root))
    print("TRU_PORTABLE_LINEAGE_01=PASS")
    print("RELEASE_ID=" + result["releaseId"])
    print("LOCAL_BINARY_SHA256=" + result["binarySha256"])
    print("MACHINE_SPECIFIC_BINARY_IN_GIT=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("FAIL: " + str(exc), file=os.sys.stderr)
        raise SystemExit(1)
