#!/usr/bin/env bash
# ============================================================================
#  install-deps.sh — TRU build dependencies
#
#  Run ONCE per machine, then build with ./agnostic_rebuild.sh
#
#  Mirrors the Dockerfile deps+build stages exactly. If you change one,
#  change the other.
#
#  Usage:
#      ./install-deps.sh              install everything
#      ./install-deps.sh --check      report what is missing, change nothing
#      ./install-deps.sh --prefix DIR install git deps to DIR (default /usr/local)
# ============================================================================
set -euo pipefail

PREFIX="/usr/local"
CHECK_ONLY=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

while (($#)); do
    case "$1" in
        --check)  CHECK_ONLY=1; shift ;;
        --prefix) PREFIX="${2:?--prefix requires a path}"; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

info() { printf '\n== %s\n' "$*"; }
ok()   { printf '   OK      %s\n' "$*"; }
miss() { printf '   MISSING %s\n' "$*"; }
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

# ---------------------------------------------------------------------------
# conda shadows the system toolchain and produces binaries that link against
# the wrong libstdc++. Refuse rather than produce a subtly broken build.
# ---------------------------------------------------------------------------
if [[ -n "${CONDA_PREFIX:-}" ]]; then
    fail "conda environment '${CONDA_DEFAULT_ENV:-?}' is active.

It puts its own cmake, protobuf, leveldb and libstdc++ ahead of the system
ones, which produces link errors or a binary that only runs on this machine.

    conda deactivate

then run this script again. TRU's C++ build uses system packages only."
fi

# ---------------------------------------------------------------------------
have_cmd()    { command -v "$1" >/dev/null 2>&1; }
have_header() { echo "#include <$1>" | c++ -E -x c++ - >/dev/null 2>&1; }
have_lib()    { echo 'int main(){return 0;}' | c++ -x c++ - -l"$1" -o /dev/null >/dev/null 2>&1; }

report() {
    local missing=0
    info "Commands"
    for c in cc c++ cmake git make pkg-config protoc autoconf automake libtool libtoolize python3 clinfo; do
        if have_cmd "$c"; then ok "$c"; else miss "$c"; missing=1; fi
    done
    info "Headers"
    for h in openssl/evp.h leveldb/db.h google/protobuf/message.h boost/version.hpp \
             curl/curl.h fmt/core.h jsoncpp/json/json.h nlohmann/json.hpp sodium.h \
             CL/cl.h qrencode.h httplib.h; do
        if have_header "$h"; then ok "$h"; else miss "$h"; missing=1; fi
    done
    info "Libraries"
    for l in OpenCL qrencode crc32c keccak ethash wallycore; do
        if have_lib "$l"; then ok "lib$l"; else miss "lib$l"; missing=1; fi
    done
    if have_header cxxopts.hpp; then ok "cxxopts.hpp"; else miss "cxxopts.hpp"; missing=1; fi
    return $missing
}

if ((CHECK_ONLY)); then
    info "Checking TRU build dependencies (no changes will be made)"
    if report; then
        printf '\nAll dependencies present.\n'; exit 0
    else
        printf '\nSome dependencies are missing. Run without --check to install.\n'; exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Distribution packages
# ---------------------------------------------------------------------------
if ! have_cmd apt-get; then
    fail "this script only automates Debian/Ubuntu.

Install the equivalents of the Dockerfile package list for your distribution,
then run: ./install-deps.sh --check"
fi

info "Installing distribution packages"

# Ubuntu 24.04 names the versioned boost package; older releases do not.
BOOST_PKG="libboost-all-dev"
if apt-cache show libboost1.83-dev >/dev/null 2>&1; then
    BOOST_PKG="libboost1.83-dev"
fi

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates pkg-config \
    autoconf automake libtool libtool-bin python3 python3-dev libssl-dev \
    protobuf-compiler libprotobuf-dev "$BOOST_PKG" libleveldb-dev \
    libcurl4-openssl-dev libfmt-dev libjsoncpp-dev nlohmann-json3-dev libsodium-dev \
    ocl-icd-opencl-dev opencl-headers clinfo libqrencode-dev libcpp-httplib-dev

# The ICD loader/dev package is sufficient to build the GPU miner. Actual GPU
# discovery at runtime also requires a vendor OpenCL ICD (AMD/NVIDIA/Intel).
# We deliberately do not install a vendor-specific GPU stack here.
if [[ -d /etc/OpenCL/vendors ]]; then
    info "Installed OpenCL ICD descriptors"
    find /etc/OpenCL/vendors -maxdepth 1 -type f -name '*.icd' -print 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Dependencies not packaged by the distribution.
#
# NOTE: ethash installs libethash.a AND libkeccak.a plus ethash/keccak.hpp.
# TRU's CMakeLists does find_library(KECCAK_LIBRARY keccak) and src includes
# <ethash/keccak.hpp>, so ethash satisfies both. No vendored blob is needed.
# ---------------------------------------------------------------------------
cd "$WORK"

if have_lib crc32c; then
    info "crc32c already present, skipping"
else
    info "Building crc32c"
    git clone --depth 1 --recurse-submodules https://github.com/google/crc32c.git
    cmake -S crc32c -B crc32c/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DBUILD_SHARED_LIBS=ON -DCRC32C_BUILD_TESTS=OFF -DCRC32C_BUILD_BENCHMARKS=OFF
    cmake --build crc32c/build -j"$(nproc)"
    $SUDO cmake --install crc32c/build
fi

if have_lib keccak && have_lib ethash; then
    info "ethash/keccak already present, skipping"
else
    info "Building ethash (provides libethash.a, libkeccak.a, ethash/keccak.hpp)"
    git clone --depth 1 https://github.com/chfast/ethash.git
    cmake -S ethash -B ethash/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DETHASH_BUILD_TESTS=OFF
    cmake --build ethash/build -j"$(nproc)"
    $SUDO cmake --install ethash/build
fi

if have_lib wallycore; then
    info "libwally-core already present, skipping"
else
    info "Building libwally-core"
    git clone --depth 1 --recurse-submodules \
        https://github.com/ElementsProject/libwally-core.git
    cd libwally-core
    ./tools/autogen.sh
    ./configure --enable-shared --disable-static --prefix="$PREFIX"
    make -j"$(nproc)"
    $SUDO make install
    cd "$WORK"
fi

if have_header cxxopts.hpp; then
    info "cxxopts already present, skipping"
else
    info "Installing cxxopts (header only)"
    git clone --depth 1 --branch v3.2.1 https://github.com/jarro2783/cxxopts.git
    $SUDO install -m 644 cxxopts/include/cxxopts.hpp "$PREFIX/include/"
fi

$SUDO ldconfig

# ---------------------------------------------------------------------------
info "Verifying"
if report; then
    cat <<'DONE'

============================================================
 Dependencies installed.

 Next:
     cd /path/to/TRU
     ./agnostic_rebuild.sh

 Binaries land in build-native/bin/. Your encrypted wallet is kept
 outside the build tree in ~/.local/share/tru/wallet/ and restored
 after each build.
============================================================
DONE
else
    fail "some dependencies are still missing after installation (see above)"
fi
