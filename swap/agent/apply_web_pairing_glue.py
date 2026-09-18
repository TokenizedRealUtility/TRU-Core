#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_web_pairing_glue.py <web-root>")

root = Path(sys.argv[1]).expanduser().resolve()
files = [root / "swap.js", root / "market.js"]

for p in files:
    if not p.is_file():
        raise SystemExit(f"missing {p}")
    s = p.read_text()
    required = [
        "tru_swap_pairing",
        "X-Swap-Pairing",
        "promptForPairing",
        "res.status === 401",
    ]
    missing = [x for x in required if x not in s]
    if missing:
        raise SystemExit(
            f"{p}: manual-pairing contract missing: " + ", ".join(missing)
        )
    if "res.headers.get('X-Swap-Pairing')" in s or 'res.headers.get("X-Swap-Pairing")' in s:
        raise SystemExit(
            f"{p}: automatic pairing-token capture is present; "
            "manual terminal pairing requires it to be removed"
        )
    print(f"MANUAL_PAIRING_WEB_CONTRACT=PASS {p}")

print("WEB_MUTATION=NO")
