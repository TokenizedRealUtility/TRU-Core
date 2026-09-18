#!/usr/bin/env python3
"""
MARKET-01A.5.1 live public-write probe — curl transport repair.

Why:
Python urllib can be treated differently by an edge/CDN than the exact curl/browser
path already proven live. This probe deliberately uses curl for the same transport
shape as the successful manual verification.

Security:
- owner token is never printed
- owner token is sent to curl over stdin, not argv
- no swap is created
- no wallet/RPC access
- no coin movement
"""
from __future__ import annotations

import json
import secrets
import subprocess

ORIGIN = "https://tokenizedrealutility.com"
BASE = "https://market-api.tokenizedrealutility.com"


def call(path: str, method: str = "GET", body=None):
    cmd = [
        "curl",
        "-sS",
        "--fail-with-body",
        "--max-time", "12",
        "-H", f"Origin: {ORIGIN}",
        "-H", "Accept: application/json",
        "-w", "\n__HTTP_STATUS__:%{http_code}",
    ]

    payload = None
    if body is not None:
        cmd += [
            "-X", method,
            "-H", "Content-Type: application/json",
            "--data-binary", "@-",
        ]
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    elif method != "GET":
        cmd += ["-X", method]

    cmd.append(BASE + path)

    p = subprocess.run(
        cmd,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )

    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace").strip()

    marker = "\n__HTTP_STATUS__:"
    if marker not in out:
        raise RuntimeError(f"curl transport failed: {err or 'no HTTP status'}")

    raw, status_text = out.rsplit(marker, 1)
    try:
        status = int(status_text.strip())
    except ValueError:
        raise RuntimeError("invalid HTTP status from curl")

    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        data = {"error": raw[:300]}

    return status, data


def main() -> int:
    code, health = call("/v1/market/health")
    if code != 200 or not health.get("ok"):
        print(f"REMOTE_HEALTH=FAIL HTTP={code}")
        return 1

    if health.get("version") != "TRU-MARKET-API-01A5":
        print(f"REMOTE_VERSION=FAIL value={health.get('version')}")
        return 1

    if not health.get("publicWritesEnabled"):
        print("PUBLIC_WRITES=DISABLED")
        return 1

    if health.get("reservationEnabled") or health.get("swapCreationEnabled") or health.get("coinMovementEnabled"):
        print("FAIL_CLOSED_INVARIANT=FAIL")
        return 1

    print("REMOTE_HEALTH=PASS")
    print("REMOTE_VERSION=TRU-MARKET-API-01A5")
    print("PUBLIC_WRITES=ENABLED")
    print("TAKE_RESERVATION=ABSENT")
    print("SWAP_CREATION=NO")
    print("COIN_MOVEMENT=NO")

    salt = secrets.randbelow(900000) + 100000
    intent = {
        "schemaVersion": "TRU-MARKET-INTENT-V1",
        "pairId": "TRU_BSTY",
        "side": "SELL_BASE",
        "baseAtoms": str(100000000 + salt),
        "quoteAtoms": str(200000000 + salt),
        "baseMinConfirmations": 6,
        "quoteMinConfirmations": 6,
        "fundingOrder": "MAKER_FIRST",
        "makerRefundSeconds": 86400,
        "takerRefundSeconds": 43200,
        "lifeSeconds": 300,
    }

    advert_id = None
    owner_token = None
    withdrawn = False

    try:
        code, created = call("/v1/market/adverts", "POST", intent)
        if code != 201 or not created.get("ok"):
            print(f"REMOTE_PUBLIC_POST=FAIL HTTP={code} ERROR={created.get('error','')}")
            return 1

        advert = created.get("advert") or {}
        advert_id = advert.get("advertId")
        owner_token = created.get("ownerToken")

        if not advert_id or not owner_token:
            print("REMOTE_PUBLIC_POST=FAIL missing advertId/ownerToken")
            return 1

        print("REMOTE_PUBLIC_POST=PASS")
        print(f"ADVERT_ID={advert_id}")
        print("OWNER_TOKEN_RETURNED=YES")
        print("OWNER_TOKEN_PRINTED=NO")

        code, listing = call("/v1/market/adverts?pair=TRU_BSTY")
        if code != 200 or not listing.get("ok"):
            print(f"REMOTE_SHARED_LIST_VISIBILITY=FAIL HTTP={code}")
            return 1

        ids = {a.get("advertId") for a in listing.get("adverts", [])}
        if advert_id not in ids:
            print("REMOTE_SHARED_LIST_VISIBILITY=FAIL advert not found")
            return 1

        if owner_token in json.dumps(listing, sort_keys=True):
            print("OWNER_TOKEN_PUBLIC_LIST_LEAK=YES")
            return 1

        print("REMOTE_SHARED_LIST_VISIBILITY=PASS")
        print("OWNER_TOKEN_PUBLIC_LIST_LEAK=NO")

        # Prove wrong capability is rejected without exposing either token.
        wrong = secrets.token_urlsafe(32)
        code, _ = call(
            f"/v1/market/adverts/{advert_id}/withdraw",
            "POST",
            {"ownerToken": wrong},
        )
        if code != 403:
            print(f"WRONG_OWNER_WITHDRAW=FAIL HTTP={code}")
            return 1
        print("WRONG_OWNER_WITHDRAW=REJECTED")

        code, result = call(
            f"/v1/market/adverts/{advert_id}/withdraw",
            "POST",
            {"ownerToken": owner_token},
        )
        if code != 200 or not result.get("ok"):
            print(f"REMOTE_OWNER_WITHDRAW=FAIL HTTP={code} ERROR={result.get('error','')}")
            return 1

        withdrawn = True
        print("REMOTE_OWNER_WITHDRAW=PASS")

        code, listing2 = call("/v1/market/adverts?pair=TRU_BSTY")
        if code != 200:
            print(f"REMOTE_WITHDRAW_DISAPPEAR=FAIL HTTP={code}")
            return 1

        ids2 = {a.get("advertId") for a in listing2.get("adverts", [])}
        if advert_id in ids2:
            print("REMOTE_WITHDRAW_DISAPPEAR=FAIL still active")
            return 1

        print("REMOTE_WITHDRAW_DISAPPEAR=PASS")
        print("MARKET_01A5_LIVE_WRITE_PROBE=PASS")
        return 0

    finally:
        # Best-effort cleanup. Capability stays off argv and is never printed.
        if advert_id and owner_token and not withdrawn:
            try:
                call(
                    f"/v1/market/adverts/{advert_id}/withdraw",
                    "POST",
                    {"ownerToken": owner_token},
                )
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
