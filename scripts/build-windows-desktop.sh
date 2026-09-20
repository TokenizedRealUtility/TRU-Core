#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mxe_root=${TRU_MXE_ROOT:-/opt/mxe}
target=${TRU_MXE_TARGET:-x86_64-w64-mingw32.static}
build_dir=${TRU_WINDOWS_BUILD_DIR:-"$repo/build-win64-desktop"}
case "$target" in x86_64-w64-mingw32.static|x86_64-w64-mingw32.shared) ;; *) echo 'Use a 64-bit MXE target.' >&2; exit 2;; esac
wrapper="$mxe_root/usr/bin/$target-cmake"
[[ -x "$wrapper" ]] || { echo "Missing MXE CMake wrapper: $wrapper" >&2; exit 2; }
[[ -d "$mxe_root/usr/$target/qt5" ]] || { echo 'Build qtbase for the same MXE target first.' >&2; exit 2; }
"$wrapper" -S "$repo/desktop" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DTRU_DESKTOP_TESTS=OFF
"$wrapper" --build "$build_dir" --parallel "${TRU_BUILD_JOBS:-2}"
exe="$build_dir/bin/tru_desktop.exe"
[[ -s "$exe" ]] || { echo 'Build did not produce tru_desktop.exe.' >&2; exit 1; }
"$mxe_root/usr/bin/$target-objdump" -f "$exe"
"$mxe_root/usr/bin/$target-objdump" -p "$exe" | sed -n '/DLL Name:/p'
echo "Built: $exe"
echo 'This is the desktop RPC client, not tru_advanced.exe. Complete the Windows runtime checklist before publishing.'
