#!/usr/bin/env bash
# MAC-DESKTOP-01: run on macOS; builds/deploys only the Qt RPC client.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Run this build on a Mac with Xcode and Qt 6 installed.' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
qt_prefix=${TRU_QT_PREFIX:-}
if [[ -z "$qt_prefix" ]]; then
    command -v brew >/dev/null || { echo 'Set TRU_QT_PREFIX to your Qt 6 macOS kit.' >&2; exit 2; }
    qt_prefix=$(brew --prefix qt)
fi
[[ -f "$qt_prefix/lib/cmake/Qt6/Qt6Config.cmake" && -x "$qt_prefix/bin/macdeployqt" ]] || {
    echo "Not a complete Qt 6 macOS kit: $qt_prefix" >&2; exit 2;
}
for tool in cmake ctest xcrun hdiutil ditto lipo otool file codesign; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
xcrun --find clang++ >/dev/null
arch=${TRU_MAC_ARCH:-$(uname -m)}
case "$arch" in
    arm64|x86_64) label=$arch ;;
    'arm64;x86_64'|'x86_64;arm64') label=universal2 ;;
    *) echo 'TRU_MAC_ARCH must be arm64, x86_64, or arm64;x86_64.' >&2; exit 2 ;;
esac
build=${TRU_MAC_BUILD_DIR:-"$repo/build-macos-$label"}
mkdir -p "$build"
build=$(cd -- "$build" && pwd)
args=(-S "$repo/desktop" -B "$build" -G 'Unix Makefiles'
    -DCMAKE_BUILD_TYPE=Release -DTRU_DESKTOP_QT_MAJOR=6 -DTRU_DESKTOP_TESTS=ON
    "-DQt6_DIR=$qt_prefix/lib/cmake/Qt6" "-DCMAKE_PREFIX_PATH=$qt_prefix"
    "-DCMAKE_OSX_ARCHITECTURES=$arch")
if [[ -n "${TRU_MAC_DEPLOYMENT_TARGET:-}" ]]; then
    args+=("-DCMAKE_OSX_DEPLOYMENT_TARGET=$TRU_MAC_DEPLOYMENT_TARGET")
fi
cmake "${args[@]}"
cmake --build "$build" --parallel "${TRU_BUILD_JOBS:-2}"
(cd -- "$build" && ctest --output-on-failure)
app_name='TRU Core Desktop.app'
app="$build/bin/$app_name"
[[ -x "$app/Contents/MacOS/TRU Core Desktop" ]] || { echo "Missing bundle: $app" >&2; exit 1; }
# A fresh staging directory prevents mixing old deployed frameworks and new builds.
stage=$(mktemp -d "$build/package.XXXXXX")
ditto "$app" "$stage/$app_name"
(cd -- "$stage" && "$qt_prefix/bin/macdeployqt" "$app_name" -always-overwrite -codesign=-)
[[ -f "$stage/$app_name/Contents/PlugIns/platforms/libqcocoa.dylib" ]] || {
    echo 'Deployment is missing the Cocoa platform plugin.' >&2; exit 1;
}
IFS=';' read -r -a architectures <<< "$arch"
while IFS= read -r -d '' binary; do
    if file -b "$binary" | grep -q 'Mach-O'; then
        for slice in "${architectures[@]}"; do lipo "$binary" -verify_arch "$slice"; done
        # Reject development-machine dependencies missed by deployment.
        while IFS= read -r dependency; do
            case "$dependency" in
                /System/Library/*|/usr/lib/*) ;;
                /*) echo "Unbundled dependency in $binary: $dependency" >&2; exit 1 ;;
            esac
        done < <(otool -L "$binary" | tail -n +2 | sed -E 's/^[[:space:]]*//; s/ \(compatibility version.*$//')
    fi
done < <(find "$stage/$app_name" -type f -print0)
codesign --verify --deep --strict "$stage/$app_name"
ln -s /Applications "$stage/Applications"
dmg="$build/TRU-Core-Desktop-$label-development-$(date -u +%Y%m%dT%H%M%SZ).dmg"
hdiutil create -volname 'TRU Core Desktop' -srcfolder "$stage" -format UDZO "$dmg"
echo "App: $stage/$app_name"
echo "Development DMG: $dmg"
echo 'Ad-hoc signed, not notarized. See docs/MACOS_BUILD.md for public release signing.'
echo 'This package contains the RPC client; it requires a running TRU node through loopback RPC.'
