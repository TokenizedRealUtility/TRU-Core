#!/usr/bin/env bash
set -Eeuo pipefail

CFG="${CLOUDFLARED_CONFIG:-/etc/cloudflared/config.yml}"
HOSTNAME="market-api.tokenizedrealutility.com"
SERVICE="http://127.0.0.1:8650"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ -f "$CFG" ]] || fail "cloudflared config not found: $CFG"

if grep -Fq "hostname: $HOSTNAME" "$CFG"; then
  echo "MARKET_API_INGRESS=ALREADY_PRESENT"
  sudo cloudflared --config "$CFG" tunnel ingress validate
  exit 0
fi

catch_count="$(grep -Ec '^[[:space:]]*-[[:space:]]+service:[[:space:]]+http_status:404[[:space:]]*$' "$CFG" || true)"
[[ "$catch_count" == "1" ]] || fail "expected exactly one final http_status:404 catch-all; found $catch_count"

ts="$(date +%Y%m%d-%H%M%S)"
backup="${CFG}.pre-market-01a3-${ts}.bak"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

cp "$CFG" "$tmp"

python3 - "$tmp" "$HOSTNAME" "$SERVICE" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
hostname = sys.argv[2]
service = sys.argv[3]
s = p.read_text()
lines = s.splitlines()

matches = [i for i, line in enumerate(lines)
           if line.strip() == "- service: http_status:404"]
if len(matches) != 1:
    raise SystemExit("expected exactly one final 404 ingress rule")

i = matches[0]
indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
block = [
    f"{indent}# PUBLIC MARKET API — MARKET-01A.3",
    f"{indent}- hostname: {hostname}",
    f"{indent}  service: {service}",
    "",
]
lines[i:i] = block
p.write_text("\n".join(lines) + "\n")
PY

echo "BACKUP=$backup"
sudo cp "$CFG" "$backup"
sudo cp "$tmp" "$CFG"

if ! sudo cloudflared --config "$CFG" tunnel ingress validate; then
  echo "VALIDATION_FAILED=YES"
  echo "ROLLBACK=$backup"
  sudo cp "$backup" "$CFG"
  sudo cloudflared --config "$CFG" tunnel ingress validate || true
  fail "new cloudflared config failed validation and was rolled back"
fi

sudo systemctl restart cloudflared
sudo systemctl is-active --quiet cloudflared || {
  echo "CLOUDFLARED_RESTART_FAILED=YES"
  echo "ROLLBACK=$backup"
  sudo cp "$backup" "$CFG"
  sudo systemctl restart cloudflared || true
  fail "cloudflared failed to restart; config rolled back"
}

echo "MARKET_API_INGRESS=APPLIED"
echo "HOSTNAME=$HOSTNAME"
echo "SERVICE=$SERVICE"
echo "CLOUDFLARED=ACTIVE"
echo
echo "DNS_NOTE:"
echo "  Ensure Cloudflare DNS has a proxied market-api hostname routed to the same Tunnel."
echo "  Do NOT place Cloudflare Access login in front of this public market-data hostname."
echo "  Public writes remain disabled by default until edge abuse/rate-limit controls are confirmed."
