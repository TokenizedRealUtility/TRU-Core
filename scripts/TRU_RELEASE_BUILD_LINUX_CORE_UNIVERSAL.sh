#!/usr/bin/env bash
# TRU Core: reusable Linux headless full-node release builder.
# Builds the current source tree on each run; creates an installable .deb and
# a tar.gz archive. No wallet, configuration secrets, or blockchain data shipped.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CORE="${TRU_REPO:-${TRU_CORE_ROOT:-}}"
if [[ -z "$CORE" ]]; then
    if [[ -f "$SCRIPT_DIR/CMakeLists.txt" && -d "$SCRIPT_DIR/src" ]]; then
        CORE="$SCRIPT_DIR"
    else
        CORE="$HOME/TRU-Core"
    fi
fi
OUTPUT="${TRU_RELEASE_ROOT:-}"
JOBS="${TRU_RELEASE_JOBS:-2}"
MODE="both"
ACTION="build"
REPLACE=0
KEEP_WORK=0

usage() {
    cat <<'HELP'
TRU_RELEASE_BUILD_LINUX_CORE_UNIVERSAL.sh [options]

Repeatable, headless TRU full-node Linux release builder. Always reads the
CURRENT source and VERSION; no hard-coded source SHA pins or release number.
Runs as an ordinary user. Requires a configured Linux C++ build environment.

  --core DIR          TRU-Core source checkout (default: script's repository,
                      or ~/TRU-Core; also TRU_REPO/TRU_CORE_ROOT)
  --output DIR        Release output (default: ~/TRU-RELEASES/vVERSION/linux-core;
                      also TRU_RELEASE_ROOT)
  --jobs N            Parallel compile jobs (default: 2; TRU_RELEASE_JOBS)
  --check             Verify environment and source, but do not build or write
  --tar-only          Produce .tar.gz only (dynamic OS libraries still needed)
  --deb-only          Produce .deb only (Debian / Ubuntu)
  --replace           Permit overwriting same-version packages after full build
  --keep-work         Keep isolated, public-source build directory for diagnosis
  -h, --help          Show this help

Default: build both .deb and .tar.gz, SHA256SUMS and BUILDINFO. Builds
tru_advanced and tru-cli, with Qt and OpenCL OFF. Neither miner nor desktop
wallet is included. Never uses sudo, installs anything, starts a node or
publishes a release. Never includes private tru.conf or wallet data.

If dependency analysis detects missing/privately installed shared libraries,
the public .deb fails rather than shipping a broken package. Build on the
oldest Debian/Ubuntu version you intend to support; this is NOT an AppImage.
HELP
}
fail() { printf '\n[TRU-CORE-RELEASE] ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[TRU-CORE-RELEASE] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"; }

while (($#)); do
    case "$1" in
        --core|--output|--jobs)
            (($# >= 2)) || fail "$1 needs a value"
            case "$1" in
                --core) CORE="$2";;
                --output) OUTPUT="$2";;
                --jobs) JOBS="$2";;
            esac
            shift 2;;
        --check) ACTION=check; shift;;
        --tar-only) MODE=tar; shift;;
        --deb-only) MODE=deb; shift;;
        --replace) REPLACE=1; shift;;
        --keep-work) KEEP_WORK=1; shift;;
        -h|--help) usage; exit 0;;
        *) fail "Unknown option: $1 (try --help)";;
    esac
done

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || fail "--jobs must be a positive integer"
[[ "$(uname -s)" == Linux ]] || fail "Linux host required"
[[ "${EUID:-$(id -u)}" -ne 0 ]] || fail "Run as your normal user, not sudo"
for cmd in cmake c++ tar gzip sha256sum find sort xargs file readelf ldd mktemp cp install timeout realpath cut awk du; do need "$cmd"; done
if [[ "$MODE" != tar ]]; then
    need dpkg
    need dpkg-deb
    need dpkg-shlibdeps
fi

CORE="$(realpath -e -- "$CORE")" || fail "Source checkout not found"
[[ -f "$CORE/CMakeLists.txt" && -f "$CORE/VERSION" ]] || fail "Not a TRU source checkout: $CORE"
[[ -f "$CORE/src/main.cpp" && -f "$CORE/src/tru-cli.cpp" ]] || fail "Missing TRU node or RPC client source"
[[ -f "$CORE/src/allowed_scripts.json" ]] || fail "src/allowed_scripts.json missing"
[[ -f "$CORE/tru.conf.example" ]] || fail "Public tru.conf.example missing (never use private tru.conf for a release)"
[[ -f "$CORE/cmake/TRUGuiDesktop.cmake" ]] || fail "cmake/TRUGuiDesktop.cmake missing"

VERSION="$(tr -d '\r\n' < "$CORE/VERSION")"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.+~]*$ ]] || fail "Unsafe/unsupported VERSION: $VERSION"
ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64) ARCH=amd64;;
        aarch64) ARCH=arm64;;
        *) fail "Unsupported architecture; use Debian/Ubuntu dpkg or extend ARCH mapping";;
    esac
fi
case "$ARCH" in amd64|arm64) : ;; *) fail "Supported package architectures: amd64, arm64 (got $ARCH)";; esac

if [[ -z "$OUTPUT" ]]; then
    OUTPUT="$HOME/TRU-RELEASES/v${VERSION}/linux-core"
fi
# --check must not create its output directory.
if [[ "$ACTION" == check ]]; then
    OUTPUT="$(realpath -m -- "$OUTPUT")"
else
    mkdir -p -- "$OUTPUT"
    OUTPUT="$(realpath -e -- "$OUTPUT")"
    [[ -w "$OUTPUT" ]] || fail "Not writable: $OUTPUT"
fi
# Do not let staging happen inside source files or in a published artifact.
[[ "$OUTPUT" != "$CORE" && "$OUTPUT" != "$CORE/"* ]] || fail "Choose a release output outside the source root"

PKG="TRU-Core-v${VERSION}-Linux-${ARCH}"
DEB="$OUTPUT/${PKG}.deb"
TAR="$OUTPUT/${PKG}.tar.gz"
SUMS="$OUTPUT/SHA256SUMS-Linux-Core-${ARCH}.txt"
INFO="$OUTPUT/BUILDINFO-Linux-Core-${ARCH}.txt"
LOG="$OUTPUT/BUILD-LOG-Linux-Core-${ARCH}.txt"

info "Repository: $CORE"
info "Source VERSION: $VERSION"
info "Architecture: $ARCH; mode: $MODE; jobs: $JOBS"
info "Release output: $OUTPUT"

if [[ -d "$CORE/.git" ]] && command -v git >/dev/null 2>&1; then
    GIT_COMMIT="$(git -C "$CORE" rev-parse HEAD 2>/dev/null || true)"
    GIT_DIRTY="$(git -C "$CORE" status --porcelain --untracked-files=no 2>/dev/null | head -1 || true)"
    [[ -z "$GIT_DIRTY" ]] || info "NOTICE: tracked source has uncommitted changes; output is built from the CURRENT files"
else
    GIT_COMMIT=none
fi

fingerprint() {
    # Hash only selected public build inputs. Private tru.conf is excluded.
    local entries=(CMakeLists.txt VERSION tru.conf.example src cmake)
    [[ ! -d "$CORE/desktop" ]] || entries+=(desktop)
    ( cd "$CORE" && find "${entries[@]}" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1 )
}

FINGERPRINT="$(fingerprint)"
info "Source fingerprint: $FINGERPRINT"
if [[ "$ACTION" == check ]]; then
    info "CHECK=PASS (source and required local tools present; build dependencies checked by CMake at build time)"
    exit 0
fi

if (( ! REPLACE )); then
    [[ "$MODE" == deb || ! -e "$TAR" ]] || fail "Existing archive: $TAR; use --replace after reviewing"
    [[ "$MODE" == tar || ! -e "$DEB" ]] || fail "Existing package: $DEB; use --replace after reviewing"
    [[ ! -e "$SUMS" && ! -e "$INFO" ]] || fail "Existing release manifest in $OUTPUT; use --replace after reviewing"
fi

# All build inputs are copied into an isolated temporary SOURCE SNAPSHOT. This
# intentionally excludes any private tru.conf and protects against accidental
# inclusion of a developer's existing blockchain database or wallet files.
WORK="$(mktemp -d "$OUTPUT/.tru-core-release-work.XXXXXXXX")"
SUCCESS=0
finish() {
    local result=$?
    if (( SUCCESS == 1 && KEEP_WORK == 0 )); then
        rm -rf -- "$WORK"
    else
        printf '[TRU-CORE-RELEASE] Work directory retained: %s\n' "$WORK" >&2
    fi
    if (( result != 0 )); then
        printf '[TRU-CORE-RELEASE] BUILD FAILED; no existing published packages were changed. Log: %s\n' "$LOG" >&2
    fi
}
trap finish EXIT
trap 'fail "Command failed at line $LINENO"' ERR
: > "$LOG"

SRC="$WORK/source"
BLD="$WORK/build"
mkdir -p "$SRC"
cp -a -- "$CORE/src" "$CORE/cmake" "$SRC/"
[[ ! -d "$CORE/desktop" ]] || cp -a -- "$CORE/desktop" "$SRC/"
for f in CMakeLists.txt VERSION tru.conf.example; do cp -- "$CORE/$f" "$SRC/$f"; done
# Build provenance is from exact, copied public input files; no secret config.
[[ "$(fingerprint)" == "$FINGERPRINT" ]] || fail "Source changed during snapshot: rerun"

run_logged() {
    printf '\n[TRU-CORE-RELEASE] CMD:' | tee -a "$LOG"
    printf ' %q' "$@" | tee -a "$LOG"
    printf '\n' | tee -a "$LOG"
    "$@" 2>&1 | tee -a "$LOG"
}

info "Configuring isolated public-source headless build"
run_logged cmake -S "$SRC" -B "$BLD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_WITH_QT=OFF \
    -DUSE_OPENCL=OFF \
    -DTRU_08B3T_TEST_HOOKS=OFF

info "Building the complete node and standalone RPC CLI"
run_logged cmake --build "$BLD" --target tru_advanced tru-cli --parallel "$JOBS"
NODE="$BLD/bin/tru_advanced"
CLI="$BLD/bin/tru-cli"
for executable in "$NODE" "$CLI"; do
    [[ -s "$executable" && -x "$executable" ]] || fail "Required binary missing/not executable: $executable"
    file "$executable" | grep -q 'ELF' || fail "Not a native Linux ELF executable: $executable"
    readelf -h "$executable" | grep -Eq 'Machine:.*(X86-64|AArch64)' || fail "Unexpected ELF architecture: $executable"
    if ldd "$executable" | grep -q 'not found'; then
        ldd "$executable" >&2
        fail "Missing linked shared libraries for $executable"
    fi
done

# Cheap smoke test, no blockchain state creation/network startup.
mkdir -p "$WORK/smoke-home"
info "Smoke testing tru_advanced --help (does not start Core)"
( cd "$WORK/smoke-home" && env -u TRU_CORE_VERSION HOME="$WORK/smoke-home" timeout 15 "$NODE" --help ) >> "$LOG" 2>&1 || fail "tru_advanced --help failed; inspect $LOG"
[[ "$(fingerprint)" == "$FINGERPRINT" ]] || fail "Source changed during build: discard and rerun"

STAGED_TAR="$WORK/$PKG"
STAGED_DEB="$WORK/deb"
mkdir -p "$STAGED_TAR/bin" "$STAGED_TAR/share/tru-core" "$STAGED_TAR/doc" "$STAGED_DEB/usr/bin" \
    "$STAGED_DEB/usr/share/tru-core" "$STAGED_DEB/usr/share/doc/tru-core" "$STAGED_DEB/DEBIAN"

install -m 0755 "$NODE" "$CLI" "$STAGED_TAR/bin/"
install -m 0755 "$NODE" "$CLI" "$STAGED_DEB/usr/bin/"
install -m 0644 "$SRC/src/allowed_scripts.json" "$STAGED_TAR/share/tru-core/"
install -m 0644 "$SRC/src/allowed_scripts.json" "$STAGED_DEB/usr/share/tru-core/"
install -m 0644 "$SRC/tru.conf.example" "$STAGED_TAR/share/tru-core/"
install -m 0644 "$SRC/tru.conf.example" "$STAGED_DEB/usr/share/tru-core/"
install -m 0644 "$SRC/VERSION" "$STAGED_TAR/VERSION"
install -m 0644 "$SRC/VERSION" "$STAGED_TAR/share/tru-core/VERSION"
install -m 0644 "$SRC/VERSION" "$STAGED_DEB/usr/share/tru-core/VERSION"

cat > "$WORK/tru-core" <<'LAUNCHER'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if (( EUID == 0 )); then
  echo 'Do not run TRU Core as root. Use a normal user account.' >&2
  exit 1
fi
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f /usr/share/tru-core/VERSION && "$HERE/tru_advanced" == /usr/bin/tru_advanced ]]; then
  BIN=/usr/bin/tru_advanced
  SHARE=/usr/share/tru-core
else
  BIN="$HERE/tru_advanced"
  SHARE="$HERE/../share/tru-core"
fi
NODE_HOME="${TRU_NODE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/tru-core}"
mkdir -p "$NODE_HOME/src" "$NODE_HOME/data"
NODE_HOME="$(cd -- "$NODE_HOME" && pwd -P)"
if [[ ! -f "$NODE_HOME/src/allowed_scripts.json" ]]; then
  cp -- "$SHARE/allowed_scripts.json" "$NODE_HOME/src/allowed_scripts.json"
fi
CONF="${TRU_NODE_CONF:-$NODE_HOME/tru.conf}"
if [[ ! -f "$CONF" ]]; then
  cp -n -- "$SHARE/tru.conf.example" "$CONF"
  chmod 0600 "$CONF"
  echo "Created $CONF from the PUBLIC template." >&2
  echo 'Review network, RPC and security settings before starting.' >&2
  echo 'Edit the config, then run tru-core again.' >&2
  exit 2
fi
cd -- "$NODE_HOME"  # Core's wallet file and some config paths are CWD-relative.
export TRU_CORE_VERSION="$(tr -d '\r\n' < "$SHARE/VERSION")"
exec "$BIN" --cli --rpcbind 127.0.0.1 --conf "$CONF" --datadir "$NODE_HOME/data/utxo" "$@"
LAUNCHER
chmod 0755 "$WORK/tru-core"
install -m 0755 "$WORK/tru-core" "$STAGED_TAR/bin/tru-core"
install -m 0755 "$WORK/tru-core" "$STAGED_DEB/usr/bin/tru-core"

cat > "$WORK/tru-core-cli" <<'CLIENT'
#!/usr/bin/env bash
set -Eeuo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ "$HERE" == /usr/bin ]]; then BIN=/usr/bin/tru-cli; else BIN="$HERE/tru-cli"; fi
NODE_HOME="${TRU_NODE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/tru-core}"
CONF="${TRU_NODE_CONF:-$NODE_HOME/tru.conf}"
[[ -f "$CONF" ]] || { echo "Missing local config: $CONF (run tru-core first)" >&2; exit 1; }
exec "$BIN" "-conf=$CONF" "$@"
CLIENT
chmod 0755 "$WORK/tru-core-cli"
install -m 0755 "$WORK/tru-core-cli" "$STAGED_TAR/bin/tru-core-cli"
install -m 0755 "$WORK/tru-core-cli" "$STAGED_DEB/usr/bin/tru-core-cli"

cat > "$WORK/README-CORE-LINUX.txt" <<README
TRU Core v${VERSION} — Linux ${ARCH}, native headless node
========================================================

Contents: tru_advanced (full validation and P2P node), tru-cli (RPC client),
          tru-core (convenience launcher), tru-core-cli (RPC convenience launcher).
No GPU/CPU miner or Qt desktop wallet in this full-node package.
No private keys, wallet files, blockchain data, or private tru.conf included.

Install:
  Debian/Ubuntu: sudo apt install ./$(basename "$DEB")
  Tarball: extract and run ./bin/tru-core

First run (as a NORMAL USER, never sudo):
  tru-core
  # Creates your private directory and a tru.conf template, then STOPS.
  # Review and edit ~/.local/share/tru-core/tru.conf before running again.
  tru-core

If extracting a tarball, run its bin/tru-core and bin/tru-core-cli directly.
The launcher's data home defaults to ~/.local/share/tru-core. Override with
TRU_NODE_HOME=/path/to/dedicated/folder. Override the config via TRU_NODE_CONF.
The launcher binds RPC to 127.0.0.1, not a public interface. Check P2P,
firewall, seeds and any other config settings yourself. Core may create a
wallet artifact relative to its working directory. Back it up securely.

Node CLI: tru-core-cli -help   (your installed tru-cli supports -conf=...)
Direct executable: tru_advanced --help
Stop the node gracefully; never terminate it by forcibly killing its process.

Deployment/runtime libraries: This binary uses the host's system libraries;
its tar.gz archive is NOT universal across all Linux distributions. Install
on an OS compatible with the recorded build machine/glibc in BUILDINFO.
A .deb is only published if Debian's dependency analysis succeeded.

No systemd service is installed/enabled automatically. This is intentional.
No installation or source patch is performed by the release build script.
README
install -m 0644 "$WORK/README-CORE-LINUX.txt" "$STAGED_TAR/README.txt"
install -m 0644 "$WORK/README-CORE-LINUX.txt" "$STAGED_DEB/usr/share/doc/tru-core/README.txt"

printf 'VERSION=%s\nARCH=%s\nGIT_COMMIT=%s\nSOURCE_FINGERPRINT_SHA256=%s\nBUILD_HOST=%s\nBUILD_OS=%s\nCOMPILER=%s\nUTC_BUILT=%s\n' \
    "$VERSION" "$ARCH" "$GIT_COMMIT" "$FINGERPRINT" "$(uname -m)" \
    "$( (grep '^PRETTY_NAME=' /etc/os-release || true) | cut -d= -f2- )" \
    "$(c++ --version | head -1)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$WORK/BUILDINFO.txt"
install -m 0644 "$WORK/BUILDINFO.txt" "$STAGED_TAR/BUILDINFO.txt"
install -m 0644 "$WORK/BUILDINFO.txt" "$STAGED_DEB/usr/share/doc/tru-core/BUILDINFO.txt"

# CMake has a branch that copies an existing private tru.conf into its own
# build/bin, but our isolated source snapshot includes ONLY tru.conf.example.
# Explicitly prevent this from ever entering a release artifact.
[[ ! -e "$STAGED_TAR/tru.conf" && ! -e "$STAGED_DEB/usr/share/tru-core/tru.conf" ]] || fail "Private config in staging"
# umask 077 protects temporary work, but directories INSIDE release archives
# and installed .debs need public traverse permissions.
find "$STAGED_TAR" "$STAGED_DEB" -type d -exec chmod 0755 {} +
# Release output under setgid shared folders can inherit g+s; dpkg-deb
# rejects that bit on DEBIAN/control directory even with mode 0755.
find "$STAGED_TAR" "$STAGED_DEB" -type d -exec chmod g-s {} +

PUBLISH=()
if [[ "$MODE" != deb ]]; then
    info "Creating versioned Linux tarball"
    tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
        -C "$WORK" -czf "$WORK/${PKG}.tar.gz" "$PKG"
    PUBLISH+=("$WORK/${PKG}.tar.gz:$TAR")
fi

if [[ "$MODE" != tar ]]; then
    info "Resolving real Debian runtime dependencies"
    # We require shlib metadata, not a guessed Depends list. The debian/control
    # scratch file is needed by dpkg-shlibdeps to locate build-package metadata.
    mkdir -p "$WORK/debian"
    printf 'Source: tru-core\nSection: net\nPriority: optional\nMaintainer: TRU Core Project <releases@tokenizedrealutility.com>\nStandards-Version: 4.6.0\n\nPackage: tru-core\nArchitecture: any\nDescription: TRU headless full node\n' > "$WORK/debian/control"
    depout="$(cd "$WORK" && dpkg-shlibdeps -O -e"$STAGED_DEB/usr/bin/tru_advanced" -e"$STAGED_DEB/usr/bin/tru-cli")" || fail "Dependency scan failed; libraries from /usr/local, Conda or other non-Debian sources may need a redistributable release build. No .deb created."
    depends="${depout#shlibs:Depends=}"
    [[ "$depends" != "$depout" && -n "$depends" ]] || fail "dpkg-shlibdeps returned no dependencies"
    size_kib="$(du -sk "$STAGED_DEB/usr" | awk '{print $1}')"
    cat > "$STAGED_DEB/DEBIAN/control" <<CONTROL
Package: tru-core
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: TRU Core Project <releases@tokenizedrealutility.com>
Depends: ${depends}
Installed-Size: ${size_kib}
Description: TRU Core headless full blockchain node and RPC client
 Independent TRU node, local RPC client, public configuration template and
 convenience launcher. Starts only when the user explicitly runs it.
CONTROL
    chmod 0644 "$STAGED_DEB/DEBIAN/control"
    dpkg-deb --build --root-owner-group "$STAGED_DEB" "$WORK/${PKG}.deb" | tee -a "$LOG"
    dpkg-deb --info "$WORK/${PKG}.deb" | tee -a "$LOG"
    dpkg-deb --contents "$WORK/${PKG}.deb" | tee -a "$LOG"
    PUBLISH+=("$WORK/${PKG}.deb:$DEB")
fi

[[ "$(fingerprint)" == "$FINGERPRINT" ]] || fail "Current source changed during packaging; discard and rerun"
for entry in "${PUBLISH[@]}"; do
    dest="${entry#*:}"
    if [[ -e "$dest" ]] && (( ! REPLACE )); then fail "Output changed during build: $dest"; fi
done

info "Publishing only verified finished artifacts"
for entry in "${PUBLISH[@]}"; do
    src="${entry%%:*}"
    dest="${entry#*:}"
    install -m 0644 "$src" "$dest.tmp.$$"
    mv -f -- "$dest.tmp.$$" "$dest"
done
install -m 0644 "$WORK/BUILDINFO.txt" "$INFO"
(
  cd "$OUTPUT"
  if [[ "$MODE" != deb ]]; then sha256sum "$(basename "$TAR")"; fi
  if [[ "$MODE" != tar ]]; then sha256sum "$(basename "$DEB")"; fi
) > "$SUMS"
chmod 0644 "$SUMS"
info "RELEASE_BUILD=PASS"
info "SHA256SUMS=$SUMS"
info "BUILDINFO=$INFO"
for entry in "${PUBLISH[@]}"; do info "ARTIFACT=${entry#*:}"; done
SUCCESS=1
