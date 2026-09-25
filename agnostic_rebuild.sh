#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ============================================================================
# TRU portable build script (agnostic_rebuild.sh)
#
# Goals:
#   * no hard-coded username, HOME, repo path, x86_64 library path, or protoc path
#   * repo root is the directory containing this script
#   * normal rebuilds preserve runtime data
#   * SEC-14 encrypted wallet artifacts live outside the disposable build tree
#   * brand-new native nodes bootstrap their own encrypted wallet
#   * cross-builds build binaries only; they do not create/run a wallet
#
# Supported project architecture modes:
#   native | arm32 | arm64 | win64
#
# Examples:
#   ./agnostic_rebuild.sh
#   ./agnostic_rebuild.sh native
#   ./agnostic_rebuild.sh --arch native --run
#   ./agnostic_rebuild.sh --arch native --clean
#   ./agnostic_rebuild.sh --arch native --purge-build
#   ./agnostic_rebuild.sh --arch native --reset-utxo
#
# Environment overrides:
#   TRU_BUILD_JOBS=8
#   TRU_BUILD_DIR=/path/to/build-native
#   TRU_DATA_HOME=/persistent/location
#   TRU_WALLET_STORE=/persistent/location/wallet
#   TRU_RUNTIME_STORE=/persistent/location/runtime
#   TRU_BUILD_WITH_QT=OFF   # default is OFF; set ON for desktop Qt build
#   TRU_CMAKE_ARGS="-DFOO=ON -DBAR=/path"
# ============================================================================

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
    pwd -P
)"
REPO_ROOT="$SCRIPT_DIR"

ARCH="native"
RUN_AFTER_BUILD=0
CLEAN_FIRST=0
PURGE_BUILD=0
RESET_UTXO=0
JOBS="${TRU_BUILD_JOBS:-}"
TRU_BUILD_WITH_QT="${TRU_BUILD_WITH_QT:-OFF}"

usage() {
    cat <<'EOF'
Usage:
  ./agnostic_rebuild.sh [native|arm32|arm64|win64] [options]

Options:
  --arch MODE       native | arm32 | arm64 | win64
  --run             start tru_advanced after a successful native build
  --no-run          do not start the node (default)
  --clean           CMake clean-first build; preserves wallet/data
  --purge-build     delete the build directory before configuring
                    (wallet + runtime data are preserved first)
  --reset-utxo      explicitly remove bin/data/utxo after build
  --jobs N          parallel build jobs
  -h, --help        show this help

Normal rebuild:
  ./agnostic_rebuild.sh native

Build and launch:
  ./agnostic_rebuild.sh native --run

Fresh CMake/build tree while preserving wallet/runtime:
  ./agnostic_rebuild.sh native --purge-build

IMPORTANT:
  Normal rebuilds DO NOT erase chain/UTXO state.
  --reset-utxo is explicit because deleting node state should never be an
  accidental side effect of recompiling software.
EOF
}

fail() {
    printf '\033[31mERROR: %s\033[0m\n' "$*" >&2
    exit 1
}

info() {
    printf '\033[32m%s\033[0m\n' "$*"
}

warn() {
    printf '\033[33mWARNING: %s\033[0m\n' "$*" >&2
}

while (($#)); do
    case "$1" in
        native|arm32|arm64|win64)
            ARCH="$1"
            shift
            ;;
        --arch)
            (($# >= 2)) || fail "--arch requires a value"
            ARCH="$2"
            shift 2
            ;;
        --run)
            RUN_AFTER_BUILD=1
            shift
            ;;
        --no-run)
            RUN_AFTER_BUILD=0
            shift
            ;;
        --clean)
            CLEAN_FIRST=1
            shift
            ;;
        --purge-build)
            PURGE_BUILD=1
            shift
            ;;
        --reset-utxo)
            RESET_UTXO=1
            shift
            ;;
        --jobs)
            (($# >= 2)) || fail "--jobs requires a number"
            JOBS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1 (use --help)"
            ;;
    esac
done

case "$ARCH" in
    native|arm32|arm64|win64) ;;
    *) fail "unsupported architecture mode: $ARCH" ;;
esac

HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# Portable job-count discovery.
# ---------------------------------------------------------------------------
if [[ -z "$JOBS" ]]; then
    if command -v nproc >/dev/null 2>&1; then
        JOBS="$(nproc)"
    elif command -v getconf >/dev/null 2>&1; then
        JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
    elif command -v sysctl >/dev/null 2>&1; then
        JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 2)"
    else
        JOBS=2
    fi
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || fail "invalid build job count: $JOBS"

# ---------------------------------------------------------------------------
# Machine/user agnostic paths.
# ---------------------------------------------------------------------------
DEFAULT_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/tru"
TRU_DATA_HOME="${TRU_DATA_HOME:-$DEFAULT_DATA_HOME}"
WALLET_STORE="${TRU_WALLET_STORE:-$TRU_DATA_HOME/wallet}"
RUNTIME_STORE="${TRU_RUNTIME_STORE:-$TRU_DATA_HOME/runtime}"

if [[ -n "${TRU_BUILD_DIR:-}" ]]; then
    BUILD_DIR="$TRU_BUILD_DIR"
elif [[ "$ARCH" == "native" ]]; then
    BUILD_DIR="$REPO_ROOT/build-native"
else
    BUILD_DIR="$REPO_ROOT/build-$ARCH"
fi

BIN_DIR="$BUILD_DIR/bin"

WALLET_FILES=(
    "wallet_seed.dat.enc"
    "tru.dat.enc"
    "tru.dat.public"
)

RUNTIME_FILES=(
    "tru.conf"
    "allowed_scripts.json"
)

mkdir -p "$TRU_DATA_HOME" "$WALLET_STORE" "$RUNTIME_STORE"
chmod 700 "$TRU_DATA_HOME" "$WALLET_STORE" "$RUNTIME_STORE"

# ---------------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------------
# conda ships its own cmake, protobuf, leveldb and libstdc++. Activated, they
# shadow the system toolchain and yield link errors or a binary with a
# mismatched ABI that only runs on this machine.
#if [[ -n "${CONDA_PREFIX:-}" ]]; then
#    fail "conda environment '${CONDA_DEFAULT_ENV:-?}' is active.
#       It shadows the system toolchain. Run 'conda deactivate' and retry.
#       TRU's C++ build uses system packages only."
#fi

for cmd in cmake sha256sum install protoc git pkg-config; do
    command -v "$cmd" >/dev/null 2>&1 ||
        fail "required command is not installed: $cmd
       Run ./install-deps.sh first."
done

# Debian/Ubuntu installs JsonCpp headers under /usr/include/jsoncpp while some
# TRU source uses <json/...>. Derive the include root from pkg-config instead
# of hard-coding an architecture-specific path.
if pkg-config --exists jsoncpp 2>/dev/null; then
    JSONCPP_CFLAGS="$(pkg-config --cflags-only-I jsoncpp 2>/dev/null || true)"
    for flag in $JSONCPP_CFLAGS; do
        case "$flag" in
            -I*)
                jsoncpp_inc="${flag#-I}"
                case ":${CPATH:-}:" in
                    *":$jsoncpp_inc:"*) ;;
                    *) export CPATH="$jsoncpp_inc${CPATH:+:$CPATH}" ;;
                esac
                ;;
        esac
    done
fi

# Check the libraries too, not just the commands. Without this a missing
# -dev package surfaces as a wall of compiler/CMake errors instead of one
# actionable sentence.
if command -v c++ >/dev/null 2>&1; then
    REQUIRED_HEADERS=(
        openssl/evp.h
        leveldb/db.h
        cxxopts.hpp
        ethash/keccak.hpp
        nlohmann/json.hpp
        qrencode.h
        httplib.h
    )
    if [[ "$ARCH" == "native" ]]; then
        REQUIRED_HEADERS+=(CL/cl.h)
    fi

    for hdr in "${REQUIRED_HEADERS[@]}"; do
        echo "#include <$hdr>" | c++ -E -x c++ - >/dev/null 2>&1 ||
            fail "missing build dependency header: $hdr
       Run ./install-deps.sh first."
    done

    echo 'int main(){return 0;}' | c++ -x c++ - -lkeccak -o /dev/null >/dev/null 2>&1 ||
        fail "libkeccak not found (provided by ethash)
       Run ./install-deps.sh first."

    if [[ "$ARCH" == "native" ]]; then
        echo 'int main(){return 0;}' | c++ -x c++ - -lOpenCL -o /dev/null >/dev/null 2>&1 ||
            fail "OpenCL development library not found
       Run ./install-deps.sh first."
        echo 'int main(){return 0;}' | c++ -x c++ - -lqrencode -o /dev/null >/dev/null 2>&1 ||
            fail "libqrencode development library not found
       Run ./install-deps.sh first."
    fi
fi

[[ -f "$REPO_ROOT/CMakeLists.txt" ]] ||
    fail "CMakeLists.txt not found next to agnostic_rebuild.sh: $REPO_ROOT"

if [[ "$ARCH" == "native" ]]; then
    command -v c++ >/dev/null 2>&1 ||
    command -v g++ >/dev/null 2>&1 ||
    command -v clang++ >/dev/null 2>&1 ||
        fail "no native C++ compiler found"
fi

info "======================================================================"
info " TRU PORTABLE REBUILD"
info "======================================================================"
echo "REPO_ROOT=$REPO_ROOT"
echo "HOST_OS=$HOST_OS"
echo "HOST_ARCH=$HOST_ARCH"
echo "ARCH_MODE=$ARCH"
echo "BUILD_DIR=$BUILD_DIR"
echo "TRU_DATA_HOME=$TRU_DATA_HOME"
echo "WALLET_STORE=$WALLET_STORE"
echo "RUNTIME_STORE=$RUNTIME_STORE"
echo "BUILD_JOBS=$JOBS"
echo "RUN_AFTER_BUILD=$RUN_AFTER_BUILD"
echo "CLEAN_FIRST=$CLEAN_FIRST"
echo "PURGE_BUILD=$PURGE_BUILD"
echo "RESET_UTXO=$RESET_UTXO"
echo "BUILD_WITH_QT=$TRU_BUILD_WITH_QT"
echo

# ---------------------------------------------------------------------------
# SEC-14 encrypted-wallet handling.
# ---------------------------------------------------------------------------
wallet_count() {
    local dir="$1"
    local n=0
    local f
    [[ -d "$dir" ]] || {
        echo 0
        return
    }
    for f in "${WALLET_FILES[@]}"; do
        [[ -s "$dir/$f" ]] && n=$((n + 1))
    done
    echo "$n"
}

require_complete_or_empty_wallet_set() {
    local dir="$1"
    local n
    n="$(wallet_count "$dir")"
    if [[ "$n" -ne 0 && "$n" -ne "${#WALLET_FILES[@]}" ]]; then
        echo "Partial encrypted-wallet set detected in: $dir" >&2
        local f
        for f in "${WALLET_FILES[@]}"; do
            if [[ -s "$dir/$f" ]]; then
                echo "  PRESENT  $f" >&2
            else
                echo "  MISSING  $f" >&2
            fi
        done
        fail "SEC-14 requires the complete encrypted wallet artifact set or none"
    fi
}

wallet_sets_identical() {
    local a="$1"
    local b="$2"
    local f
    [[ "$(wallet_count "$a")" -eq 3 ]] || return 1
    [[ "$(wallet_count "$b")" -eq 3 ]] || return 1
    for f in "${WALLET_FILES[@]}"; do
        cmp -s "$a/$f" "$b/$f" || return 1
    done
    return 0
}

backup_wallet_store_if_needed() {
    local runtime_dir="$1"
    if [[ "$(wallet_count "$WALLET_STORE")" -eq 3 ]] &&
       ! wallet_sets_identical "$runtime_dir" "$WALLET_STORE"; then
        local stamp backup
        stamp="$(date +%Y%m%d-%H%M%S)"
        backup="${WALLET_STORE}.backup-${stamp}"
        cp -a "$WALLET_STORE" "$backup"
        chmod -R go-rwx "$backup"
        warn "persistent wallet differed from current runtime wallet"
        echo "WALLET_STORE_BACKUP=$backup"
    fi
}

sync_runtime_wallet_to_store() {
    local runtime_dir="$1"
    require_complete_or_empty_wallet_set "$runtime_dir"
    require_complete_or_empty_wallet_set "$WALLET_STORE"

    if [[ "$(wallet_count "$runtime_dir")" -eq 3 ]]; then
        backup_wallet_store_if_needed "$runtime_dir"
        local f
        for f in "${WALLET_FILES[@]}"; do
            install -m 600 "$runtime_dir/$f" "$WALLET_STORE/$f"
        done
        echo "WALLET_RUNTIME_TO_STORE_SYNC=PASS"
    fi
}

restore_wallet_from_store() {
    local runtime_dir="$1"
    require_complete_or_empty_wallet_set "$WALLET_STORE"
    require_complete_or_empty_wallet_set "$runtime_dir"

    if [[ "$(wallet_count "$runtime_dir")" -eq 0 &&
          "$(wallet_count "$WALLET_STORE")" -eq 3 ]]; then
        mkdir -p "$runtime_dir"
        local f
        for f in "${WALLET_FILES[@]}"; do
            install -m 600 "$WALLET_STORE/$f" "$runtime_dir/$f"
        done
        echo "WALLET_STORE_TO_RUNTIME_RESTORE=PASS"
    fi
}

# Capture the latest live wallet state before touching the build tree.
if [[ "$ARCH" == "native" ]]; then
    sync_runtime_wallet_to_store "$BIN_DIR"
fi

# ---------------------------------------------------------------------------
# Preserve non-build runtime files if --purge-build was explicitly requested.
# ---------------------------------------------------------------------------
PRESERVED_DATA=0
if [[ "$ARCH" == "native" && "$PURGE_BUILD" -eq 1 && -d "$BIN_DIR" ]]; then
    rm -rf "$RUNTIME_STORE/purge-preserve"
    mkdir -p "$RUNTIME_STORE/purge-preserve"
    chmod 700 "$RUNTIME_STORE/purge-preserve"

    if [[ -d "$BIN_DIR/data" ]]; then
        info "Preserving runtime data before build-tree purge..."
        cp -a "$BIN_DIR/data" "$RUNTIME_STORE/purge-preserve/data"
        PRESERVED_DATA=1
    fi

    for f in "${RUNTIME_FILES[@]}"; do
        if [[ -f "$BIN_DIR/$f" ]]; then
            cp -a "$BIN_DIR/$f" "$RUNTIME_STORE/purge-preserve/$f"
        fi
    done
fi

if [[ "$PURGE_BUILD" -eq 1 && -d "$BUILD_DIR" ]]; then
    info "Purging build directory: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Protobuf generated-source compatibility.
#
# message.proto is canonical. A checkout may contain message.pb.h/.cc generated
# by a newer protoc than the machine-local libprotobuf headers. Test the
# checked-in header against this machine; regenerate only when incompatible.
# ---------------------------------------------------------------------------
PROTO_SCHEMA="$REPO_ROOT/src/message.proto"
PROTO_HEADER="$REPO_ROOT/src/message.pb.h"
PROTO_SOURCE="$REPO_ROOT/src/message.pb.cc"

[[ -f "$PROTO_SCHEMA" ]] || fail "protobuf schema missing: $PROTO_SCHEMA"

protobuf_header_compatible() {
    [[ -f "$PROTO_HEADER" ]] || return 1
    local pb_cflags
    pb_cflags="$(pkg-config --cflags protobuf 2>/dev/null || true)"
    # shellcheck disable=SC2086
    printf '#include "message.pb.h"\nint main(){return 0;}\n' |
        c++ -std=c++17 -fsyntax-only -x c++ -I"$REPO_ROOT/src" $pb_cflags -         >/dev/null 2>&1
}

if protobuf_header_compatible; then
    echo "PROTOBUF_BINDINGS=COMPATIBLE"
else
    info "Regenerating protobuf bindings with machine-local $(protoc --version)..."
    (
        cd "$REPO_ROOT/src"
        protoc --cpp_out=. --proto_path=. message.proto
    )
    [[ -s "$PROTO_HEADER" && -s "$PROTO_SOURCE" ]] ||
        fail "protoc did not generate src/message.pb.h and src/message.pb.cc"
    protobuf_header_compatible ||
        fail "regenerated protobuf header is still incompatible with local headers"
    echo "PROTOBUF_REGEN=PASS"
fi

# ---------------------------------------------------------------------------
# Portable CMake configuration.
#
# Important: there are no hard-coded /usr/lib/x86_64-linux-gnu or /usr/bin
# dependency paths here. CMake gets first chance to discover dependencies.
# If protoc exists, its actual machine-local path is supplied as a hint.
# ---------------------------------------------------------------------------
CMAKE_ARGS=(
    -S "$REPO_ROOT"
    -B "$BUILD_DIR"
)

case "$ARCH" in
    native)
        ;;
    arm32)
        TOOLCHAIN="$REPO_ROOT/toolchain-arm32.cmake"
        [[ -f "$TOOLCHAIN" ]] || fail "missing toolchain: $TOOLCHAIN"
        CMAKE_ARGS+=(
            "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN"
            "-DBUILD_WITH_QT=OFF"
        )
        ;;
    arm64)
        TOOLCHAIN="$REPO_ROOT/toolchain-arm64.cmake"
        [[ -f "$TOOLCHAIN" ]] || fail "missing toolchain: $TOOLCHAIN"
        CMAKE_ARGS+=(
            "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN"
            "-DBUILD_WITH_QT=OFF"
        )
        ;;
    win64)
        TOOLCHAIN="$REPO_ROOT/toolchain-windows.cmake"
        [[ -f "$TOOLCHAIN" ]] || fail "missing toolchain: $TOOLCHAIN"
        CMAKE_ARGS+=(
            "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN"
            "-DBUILD_WITH_QT=OFF"
        )
        ;;
esac

CMAKE_ARGS+=("-DBUILD_WITH_QT=$TRU_BUILD_WITH_QT")

if command -v protoc >/dev/null 2>&1; then
    CMAKE_ARGS+=(
        "-DProtobuf_PROTOC_EXECUTABLE:FILEPATH=$(command -v protoc)"
    )
fi

# Optional project/site-specific CMake flags without editing this script.
if [[ -n "${TRU_CMAKE_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_CMAKE_ARGS=( ${TRU_CMAKE_ARGS} )
    CMAKE_ARGS+=("${EXTRA_CMAKE_ARGS[@]}")
fi

info "Configuring CMake..."
printf '  %q' cmake "${CMAKE_ARGS[@]}"
printf '\n'
cmake "${CMAKE_ARGS[@]}"

BUILD_ARGS=(
    --build "$BUILD_DIR"
    --parallel "$JOBS"
)
if [[ "$CLEAN_FIRST" -eq 1 ]]; then
    BUILD_ARGS+=(--clean-first)
fi

info "Building TRU..."
cmake "${BUILD_ARGS[@]}"

[[ -d "$BIN_DIR" ]] || fail "build completed but bin directory is missing: $BIN_DIR"

# ---------------------------------------------------------------------------
# Restore runtime state after an explicit build-tree purge.
# New build-generated files win; preserved files fill missing runtime state.
# ---------------------------------------------------------------------------
if [[ "$ARCH" == "native" && "$PURGE_BUILD" -eq 1 ]]; then
    mkdir -p "$BIN_DIR"

    if [[ "$PRESERVED_DATA" -eq 1 && ! -d "$BIN_DIR/data" ]]; then
        cp -a "$RUNTIME_STORE/purge-preserve/data" "$BIN_DIR/data"
        echo "RUNTIME_DATA_RESTORE=PASS"
    elif [[ "$PRESERVED_DATA" -eq 1 && -d "$BIN_DIR/data" ]]; then
        # CMake should not normally generate blockchain data. Refuse to merge
        # two trees silently.
        if [[ -n "$(find "$BIN_DIR/data" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
            fail "new build unexpectedly populated bin/data; refusing automatic merge"
        fi
        rm -rf "$BIN_DIR/data"
        cp -a "$RUNTIME_STORE/purge-preserve/data" "$BIN_DIR/data"
        echo "RUNTIME_DATA_RESTORE=PASS"
    fi

    for f in "${RUNTIME_FILES[@]}"; do
        if [[ ! -e "$BIN_DIR/$f" && -f "$RUNTIME_STORE/purge-preserve/$f" ]]; then
            cp -a "$RUNTIME_STORE/purge-preserve/$f" "$BIN_DIR/$f"
            echo "RUNTIME_FILE_RESTORED=$f"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Native encrypted-wallet restore/bootstrap.
# ---------------------------------------------------------------------------
if [[ "$ARCH" == "native" ]]; then
    ADVANCED="$BIN_DIR/tru_advanced"
    [[ -x "$ADVANCED" ]] ||
        fail "native build did not produce executable: $ADVANCED"

    require_complete_or_empty_wallet_set "$BIN_DIR"
    restore_wallet_from_store "$BIN_DIR"

    if [[ "$(wallet_count "$BIN_DIR")" -eq 0 ]]; then
        info "No encrypted wallet exists on this machine."
        info "Bootstrapping a NEW SEC-14 encrypted wallet for this node."
        info "The passphrase prompt remains local and is never printed."

        (
            cd "$BIN_DIR"
            ./tru_advanced --cli --bootstrap-encrypted-wallet
        )

        require_complete_or_empty_wallet_set "$BIN_DIR"
        [[ "$(wallet_count "$BIN_DIR")" -eq 3 ]] ||
            fail "wallet bootstrap did not create the complete encrypted artifact set"

        sync_runtime_wallet_to_store "$BIN_DIR"
        echo "NEW_MACHINE_WALLET_BOOTSTRAP=PASS"
    else
        # Refresh persistent copy after a successful build/restore.
        sync_runtime_wallet_to_store "$BIN_DIR"
        echo "ENCRYPTED_WALLET_READY=PASS"
    fi

    echo "ENCRYPTED_WALLET_ARTIFACTS:"
    for f in "${WALLET_FILES[@]}"; do
        stat -c '  mode=%a bytes=%s file=%n' "$BIN_DIR/$f" 2>/dev/null ||
        stat -f '  mode=%Lp bytes=%z file=%N' "$BIN_DIR/$f"
    done

    # Old rebuild.sh silently deleted this every time. It is now explicit.
    if [[ "$RESET_UTXO" -eq 1 ]]; then
        warn "Explicit --reset-utxo requested."
        rm -rf "$BIN_DIR/data/utxo"
        mkdir -p "$BIN_DIR/data/utxo"
        echo "UTXO_RESET=EXPLICIT_PASS"
    else
        echo "UTXO_RESET=NO"
    fi
fi

echo
info "======================================================================"
info " TRU BUILD COMPLETE"
info "======================================================================"
echo "ARCH_MODE=$ARCH"
echo "BUILD_DIR=$BUILD_DIR"
echo "BUILD=PASS"

if [[ "$ARCH" != "native" ]]; then
    echo "WALLET_BOOTSTRAP=NOT_APPLICABLE_CROSS_BUILD"
    echo "NODE_START=NO"
    exit 0
fi

if [[ "$RUN_AFTER_BUILD" -eq 1 ]]; then
    info "Starting TRU Advanced..."
    cd "$BIN_DIR"
    exec ./tru_advanced --cli
else
    echo "NODE_START=NO"
    echo
    echo "To run:"
    echo "  cd \"$BIN_DIR\""
    echo "  ./tru_advanced --cli "
fi
