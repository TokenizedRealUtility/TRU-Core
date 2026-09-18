#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${TRU_ROOT:-$HOME/NEW_TRU}"
NAME="market_api"

screen -S "$NAME" -X quit 2>/dev/null || true
sleep 0.3

screen -dmS "$NAME" bash -lc \
  "cd '$ROOT/market' && export TRU_MARKET_API_PUBLIC_WRITES='${TRU_MARKET_API_PUBLIC_WRITES:-0}' && exec ./run_market_api.sh"

sleep 0.5

if ! screen -list | grep -q "[.]${NAME}[[:space:]]"; then
  echo "ERROR: market_api screen did not remain running" >&2
  exit 1
fi

echo "MARKET_API_SCREEN=RUNNING"
echo "SCREEN_NAME=$NAME"
echo "LISTEN=http://127.0.0.1:8650"
echo "PUBLIC_WRITES=${TRU_MARKET_API_PUBLIC_WRITES:-0}"
