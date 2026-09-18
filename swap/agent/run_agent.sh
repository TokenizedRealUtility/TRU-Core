#!/usr/bin/env bash
set -euo pipefail
umask 077

TRU_ROOT="${TRU_ROOT:-$HOME/NEW_TRU}"
cd "$TRU_ROOT"

python3 "$TRU_ROOT/swap/agent/verify_runtime_lineage_v1.py" \
  --tru-root "$TRU_ROOT"

# Timeout policy is public configuration only; never contains secrets.
export TRU_SWAP_EXIT_WAIT_TIMEOUT="${TRU_SWAP_EXIT_WAIT_TIMEOUT:-600}"
export TRU_SWAP_EXIT_PROCESS_GRACE_SECONDS="${TRU_SWAP_EXIT_PROCESS_GRACE_SECONDS:-60}"

python3 - "$TRU_SWAP_EXIT_WAIT_TIMEOUT" "$TRU_SWAP_EXIT_PROCESS_GRACE_SECONDS" <<'PY'
import sys
wait=int(sys.argv[1]); grace=int(sys.argv[2])
if not 30 <= wait <= 24*60*60:
    raise SystemExit("FAIL: TRU_SWAP_EXIT_WAIT_TIMEOUT outside 30..86400 seconds")
if not 15 <= grace <= 10*60:
    raise SystemExit("FAIL: TRU_SWAP_EXIT_PROCESS_GRACE_SECONDS outside 15..600 seconds")
if wait + grace <= wait:
    raise SystemExit("FAIL: outer timeout must exceed engine wait")
print("EXIT_ENGINE_WAIT_SECONDS="+str(wait))
print("EXIT_WATCHER_PROCESS_TIMEOUT_SECONDS="+str(wait+grace))
print("EXIT_TIMEOUT_OWNERSHIP=PASS")
PY

NODE_PID="$(pgrep -n -x tru_advanced || true)"
[[ -n "$NODE_PID" ]] || {
  echo "FAIL: tru_advanced is not running; refusing to launch the Agent without a live inner-RPC token source" >&2
  exit 1
}

LIVE_TOKEN="$(
  tr '\0' '\n' < "/proc/$NODE_PID/environ" 2>/dev/null |
  sed -n 's/^TRU_SWAP_RPC_TOKEN=//p' |
  head -n1
)"

[[ -n "$LIVE_TOKEN" ]] || {
  echo "FAIL: live tru_advanced does not expose TRU_SWAP_RPC_TOKEN to this user" >&2
  exit 1
}
(( ${#LIVE_TOKEN} >= 32 )) || {
  echo "FAIL: live tru_advanced TRU_SWAP_RPC_TOKEN is too short" >&2
  exit 1
}

export TRU_SWAP_RPC_TOKEN="$LIVE_TOKEN"
unset LIVE_TOKEN

echo "TRU_SWAP_AGENT_INNER_TOKEN_SYNC=LIVE_NODE"
echo "TRU_SWAP_RPC_TOKEN_PRINTED=NO"

exec python3 -u "$TRU_ROOT/swap/agent/tru_swap_agent.py" \
  --tru-root "$TRU_ROOT" serve "$@"
