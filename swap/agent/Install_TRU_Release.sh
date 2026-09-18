#!/usr/bin/env bash
set -euo pipefail
umask 077
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TRU_ROOT="${TRU_ROOT:-$(cd -- "$HERE/../.." && pwd)}"
export TRU_ROOT
exec python3 "$HERE/install_release.py" "$@"
