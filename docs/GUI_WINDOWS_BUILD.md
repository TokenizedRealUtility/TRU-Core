# TRU GUI-DESKTOP-01 + WINDOWS-DESKTOP-01

Prepared from the two attached source archives, September 20, 2026.

**This package updates the integrated Linux Qt GUI in NEW_TRU and TRU-Core. It also supplies a portable Qt RPC desktop client and a 64-bit Windows cross-build recipe. It does not complete the native Windows full-node port or provide a Windows executable.**

The integrated GUI is substantially updated, but is not full CLI feature parity. Canonical Voting V1 creation/calls, Token Issuer V1 minting, stateful K/V updates, bridge creation and the local evolution-provider pipeline remain CLI workflows. The new GUI can create canonical K/V anchors and inspect current contract records. No VAH activation flags are enabled.

## Apply to NEW_TRU

Use Python 3.9 or newer. Extract this package somewhere outside your repository. From the extracted package directory:

```bash
python3 apply_patch.py --tree new --root "$HOME/NEW_TRU" --check
python3 apply_patch.py --tree new --root "$HOME/NEW_TRU" --apply
```

The patch checks every replaced source file against the uploaded snapshot. It backs up changed files, checks the resulting hashes, and refuses conflicting/newer files. It does not stop the node, rebuild, touch chain data, replace wallets, change VERSION, or publish to GitHub.

If it reports a hash mismatch, preserve that newer file and rebase the patch. Do not overwrite it with this archive's older copy.

## Apply to the clean TRU-Core repository

Change the path below to your actual repository root (the directory containing `src/`):

```bash
python3 apply_patch.py --tree core --root "$HOME/TRU-Core" --check
python3 apply_patch.py --tree core --root "$HOME/TRU-Core" --apply
```

TRU-Core's attachment contains only the source directory. The installer preserves the real repository's existing root `CMakeLists.txt` and appends this integration line, backing up the original:

```cmake
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/TRUGuiDesktop.cmake")
```

That module adds the new GUI objects, Qt Network linkage and AUTOMOC to existing production targets. If testing the source-only archive, first place its files inside a `src/` folder; `desktop/` can build independently, but a full-node build also needs the real repository's root CMake/config/dependencies.

The same GUI and desktop files are installed in both trees. Each tree receives its own patched `main.cpp`; the clean source is not replaced with the development tree's main file. Other differing core files are preserved.

## Linux / Debian build

On the machine where TRU already builds, add the Qt dependencies:

```bash
sudo apt-get update
sudo apt-get install build-essential cmake qtbase5-dev libqt5network5 libqrencode-dev
cd "$HOME/NEW_TRU"
cmake -S . -B build-gui-desktop01 -DBUILD_WITH_QT=ON -DUSE_OPENCL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build-gui-desktop01 --target tru_advanced tru_miner_cpu tru-cli --parallel 2
```

This uses the existing TRU full-node dependencies: OpenSSL, curl, protobuf, Boost, fmt, LevelDB, jsoncpp, libsodium, qrencode, ethash/keccak and libwally-core. Qt alone is insufficient for a full node. If CMake reports one missing, use your existing TRU dependency setup. This patch does not replace the original dependency bootstrap.

To build the GPU miner too, install your existing OpenCL development/runtime stack, configure `USE_OPENCL=ON`, and build `tru_miner` as well. Keep the miner executable beside the newly built `tru_advanced` so the GUI finds it.

**Switch binaries only after stopping the existing node cleanly.** Run from the same working directory as your existing node, with your existing config, data and logging arguments. Do not launch a second node against the same data directory. For example, replacing the executable in your existing launch command:

```bash
/path/to/NEW_TRU/build-gui-desktop01/bin/tru_advanced --gui --conf /path/to/current/tru.conf --datadir /path/to/current/data/utxo
```

The source uses the working directory for `tru.dat` and the encrypted wallet artifact set; `--datadir` alone does not select a different wallet. Keep your established working directory. The new GUI asks for an existing encrypted wallet's passphrase in a local password dialog before RPC signing workers start. Encrypted wallet bootstrap remains the existing terminal `--bootstrap-encrypted-wallet` workflow.

Use the equivalent configure/build commands from the patched TRU-Core root before uploading its source. Review `git diff` and stage only intended source/build/docs files. Do not upload `.tru-patches`, configs, wallets, logs, build output or development backups.

## What changed

| Area | Implemented behavior |
|---|---|
| Encrypted wallets | Graphical startup unlock; authenticated address selection; canonical encrypted receive-address creation; unsafe legacy create/import/restore controls disabled for encrypted mode |
| Wallet handling | Address refresh no longer triggers mutations; backup/restore return values checked; encrypted backup describes the complete offline artifact set; settings close silently |
| TRU transfers | Exact atom parsing retained; recipient/amount review before sending; current encrypted address no longer passes through the legacy-only setter |
| Tokens | FT/NFT/SFT/NCFT additional string metadata; checked uint64 supply/transfer values; exact raw-unit balances filtered to selected owner; permanent retirement with explicit BURN confirmation |
| Contracts | Funded outputs, checked arithmetic, size-aware fees, correct little-endian time/threshold encoding, canonical metadata pushes and K/V TRUSTATE initialization; normal immutable RPC submission; final signed TXID shown |
| Contract vault | Uses the core's authoritative records directly, including stable roots/live anchors; stops reconstructing status from the old wallet helper; canonical time/hash redemption |
| Multisig | Create 2-of-3 escrow, generate a local signature package, verify/combine two signatures and release through existing wallet APIs |
| Mining | CPU/GPU external QProcess; configurable CPU threads; bounded visible output; owned-child shutdown before node close; no mining loop in the Qt thread |
| Core tools | Authenticated asynchronous RPC: chain, peers, mempool, balances, tokens, scripts, contracts, miners, provenance, AI interaction/response, and read-only swap records/status |
| UI | Scrollable forms, no animated background, noneditable data tables, stable transaction sorting, explicit submission errors, raw JSON receipts preserving uint64 values |

Legacy oracle execution and the made-up byte-scanning gas estimate are removed from the GUI path. Script validation reports VM preflight/byte size, not an invented gas price. Pending acceptance is not labeled block confirmation.

The old integrated wallet methods still perform some synchronous wallet/chain work; this is not a complete threading rewrite. The standalone client exposes the selected RPC operations only: it cannot unlock a wallet, send ordinary TRU, issue tokens, or replace the full integrated wallet. Some node RPCs still have legacy encrypted-wallet limitations; this package does not modify RPC or wallet internals to bypass them.

## Build the portable desktop client on Linux

This target needs only Qt5 Widgets/Network and a C++17 compiler:

```bash
cmake -S desktop -B build-desktop -DCMAKE_BUILD_TYPE=Release
cmake --build build-desktop --parallel 2
./build-desktop/bin/tru_desktop
```

Open Connection, verify the loopback RPC URL and cookie, then Connect. TRU's default RPC port comes from `src/tru_network_params.h`; the compiled client uses that value. The embedded GUI receives the actual configured RPC port/token directly from main.

The client uses the local cookie, `TRU_RPC_TOKEN`, or a session-only token. It disallows remote HTTP endpoints, credential-bearing URLs and redirects. For an existing remote node, use your established SSH connection to forward its RPC to localhost; the RPC credential still grants authority over that node's wallet. Wallet passphrases/private keys never belong in the desktop client.

## Windows cross-compilation: what works and what remains

Read [WINDOWS_FULL_NODE_STATUS.md](WINDOWS_FULL_NODE_STATUS.md) for the source-level blockers. Replacing `CMakeLists.txt` cannot make the current full node native-Windows compatible.

For the **desktop client**, use one consistent 64-bit MXE target. MXE supports both static and shared Windows targets and provides a CMake wrapper that selects the correct toolchain. See [MXE's official guide](https://mxe.cc/).

Install the host prerequisites listed by MXE for your Linux distribution. Then:

```bash
git clone https://github.com/mxe/mxe.git "$HOME/mxe"
cd "$HOME/mxe"
make MXE_TARGETS=x86_64-w64-mingw32.static JOBS=2 cc cmake qtbase
export TRU_MXE_ROOT="$HOME/mxe"
cd /path/to/patched/TRU-Core
bash scripts/build-windows-desktop.sh
```

Output: `build-win64-desktop/bin/tru_desktop.exe`. This recipe was not executed here because the MXE/Windows Qt toolchain is not installed. It is a build recipe, not a verified Windows release.

The wrapper is the preferred route. To use system CMake explicitly:

```bash
cmake -S desktop -B build-win64-desktop \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/desktop/toolchain-mxe64.cmake" \
  -DTRU_MXE_ROOT="$HOME/mxe" \
  -DTRU_MXE_TARGET=x86_64-w64-mingw32.static \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-win64-desktop --parallel 2
```

Do not copy `windows_CMakeLists.txt` over your native root build file. In NEW_TRU it is now a forwarding entry for the desktop target. Because the TRU-Core attachment contains no root build files, its existing Windows files are preserved; use the new desktop target and script instead. The obsolete 32-bit toolchain files are not used by this recipe.

For a shared target, deploy matching Qt DLLs, the Windows platform plugin and compiler runtime dependencies; use `windeployqt` from that same Windows Qt kit on Windows, then inspect the imports. See [Qt's Windows deployment guide](https://doc.qt.io/archives/qt-5.15/windows-deployment.html). Review the applicable dependency licenses for distribution, especially a static Qt build.

Before publishing any Windows binary, test on a clean Windows machine: launch without your developer PATH, connect through a local node/forward, authenticate, exercise read-only tools, verify missing-cookie errors, test DPI scaling, and close while a request is pending. The Windows client does not include a node, miner or swap Agent. Windows users needing a full node can use the Linux build under WSL2 while native portability work continues.

## Validation and rollback

Performed here:

- Portable Qt5 desktop configured, compiled and linked on Linux.
- Updated `walletgui.cpp` and `main.cpp` passed C++17/Qt syntax checks against both supplied source trees.
- Local HTTP transport tests passed: cookie authentication, exact uint64 request/receipt bytes, invalid amount rejection, little-endian encoding, application-level RPC errors, response IDs, disallowed remote endpoints, no redirect/no automatic retry, object-only parameters.
- Desktop rendered offscreen and visually checked; preview included.
- Installer tested for both tree modes, idempotence, hash-conflict refusal and rollback.

Not performed: full integrated node link, real-chain GUI transactions, miner process runtime, encrypted-wallet migration/recovery tests, Windows cross-build or Windows runtime. Treat this as a source patch candidate for your local acceptance run before public release. No network consensus, block/transaction validity, PoW, token encoding or chain storage code was changed.

Run the portable tests yourself:

```bash
cmake -S desktop -B build-desktop-test -DTRU_DESKTOP_TESTS=ON
cmake --build build-desktop-test --parallel 2
ctest --test-dir build-desktop-test --output-on-failure
```

Rollback with the exact backup path printed during apply:

```bash
python3 apply_patch.py --root /path/to/repo --rollback /path/to/repo/.tru-patches/GUI-DESKTOP-01/printed-timestamp
```

Rollback refuses to overwrite later edits. Rebuild after source rollback; the installer never changes an executable.
