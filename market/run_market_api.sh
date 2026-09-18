#!/usr/bin/env bash
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Public posting/withdrawal stays fail-closed until explicitly enabled after
# edge abuse/rate-limit controls are confirmed.
export TRU_MARKET_API_PUBLIC_WRITES="${TRU_MARKET_API_PUBLIC_WRITES:-0}"

exec python3 "$HERE/market_http_api_v1.py" "$@"
