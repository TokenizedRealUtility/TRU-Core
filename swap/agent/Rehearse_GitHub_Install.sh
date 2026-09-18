#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  echo "Usage: $0 REPOSITORY_URL EXACT_COMMIT NEW_DESTINATION [--build]" >&2
  exit 64
}

[[ $# -eq 3 || $# -eq 4 ]] || usage
REPOSITORY_URL="$1"
EXACT_COMMIT="$2"
DESTINATION="$3"
MODE="${4:---preflight}"
[[ "$MODE" == "--preflight" || "$MODE" == "--build" ]] || usage
[[ "$EXACT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "FAIL: EXACT_COMMIT must be a full 40-character commit" >&2; exit 1; }
[[ ! -e "$DESTINATION" ]] || { echo "FAIL: destination already exists: $DESTINATION" >&2; exit 1; }

git clone --no-checkout -- "$REPOSITORY_URL" "$DESTINATION"
git -C "$DESTINATION" checkout --detach "$EXACT_COMMIT"
[[ "$(git -C "$DESTINATION" rev-parse HEAD)" == "$EXACT_COMMIT" ]] || { echo "FAIL: exact commit checkout mismatch" >&2; exit 1; }
[[ -z "$(git -C "$DESTINATION" status --porcelain)" ]] || { echo "FAIL: cloned checkout is not clean" >&2; exit 1; }
if git -C "$DESTINATION" ls-files --error-unmatch -- build-native/bin/tru_advanced >/dev/null 2>&1; then
  echo "FAIL: machine-specific Core binary is tracked in Git" >&2
  exit 1
fi

cd "$DESTINATION"
if [[ "$MODE" == "--build" ]]; then
  bash ./swap/agent/Install_TRU_Release.sh
  bash ./swap/agent/Install_TRU_Release.sh --verify
else
  bash ./swap/agent/Install_TRU_Release.sh --preflight
fi

echo "GITHUB_EXACT_COMMIT=$EXACT_COMMIT"
echo "GITHUB_CLEAN_INSTALL_REHEARSAL=PASS"
echo "NODE_STARTED=NO"
echo "WALLET_OR_CHAIN_DATABASE_CREATED=NO"
if [[ "$MODE" == "--preflight" ]]; then
  echo "FULL_BUILD_EXECUTED=NO (rerun with --build on the rehearsal machine)"
else
  echo "FULL_BUILD_EXECUTED=YES"
fi
