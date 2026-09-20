# TRU MAC-DESKTOP-01

macOS desktop build and packaging add-on for GUI-DESKTOP-01.

This adds a native macOS **desktop RPC client** build. It creates a Finder `.app` and a development `.dmg` on your Mac. Apple Silicon (`arm64`), Intel (`x86_64`) and universal builds are selectable. It does not include a node, wallet-signing engine, or miner. Use a running TRU node through loopback RPC or an SSH forward. The integrated Linux GUI remains the fuller wallet application.

This is source and packaging automation, not a compiled or notarized Mac release. No Mac host was available here. Mac compilation, deployment, signing and runtime acceptance must be performed on macOS.

## 1. Apply after the previous GUI package

First apply `TRU_GUI_DESKTOP_01_PACKAGE.zip`. Then extract this add-on outside the repository and run with Python 3.9 or newer:

```bash
python3 apply_patch.py --tree new --root "$HOME/NEW_TRU" --check
python3 apply_patch.py --tree new --root "$HOME/NEW_TRU" --apply

python3 apply_patch.py --tree core --root "$HOME/TRU-Core" --check
python3 apply_patch.py --tree core --root "$HOME/TRU-Core" --apply
```

Use whichever paths exist on that machine. Both trees receive identical desktop changes. The installer pins the prerequisite desktop files, refuses conflicts, backs up replaced files, and supports rollback. It does not change `main.cpp`, `walletgui.cpp`, consensus, chain data, wallet files, or your existing root CMake files. Do not force a hash mismatch: it means the prerequisite is missing or the source has changed.

Changes: Qt 5/6 selection in the standalone desktop target; a Qt 6 high-DPI compatibility guard; a Mac bundle manifest; and a Mac build/deployment script. The Linux integrated node still uses Qt 5. Existing standalone Linux/Windows builds also default to Qt 5; the Mac script explicitly selects Qt 6.

## 2. Build on your Mac

Install Xcode and open it once to complete setup; select the matching developer tools. Install a dynamic Qt 6 macOS development kit and CMake 3.21.1 or newer. Qt's [Mac setup guide](https://doc.qt.io/qt-6/macos.html) explains compiler and architecture requirements.

On a Mac supported by the current Homebrew packages:

```bash
brew install cmake qt
cd /path/to/patched/TRU-Core
export TRU_QT_PREFIX="$(brew --prefix qt)"
bash scripts/build-macos-desktop.sh
```

Homebrew's [Qt formula](https://formulae.brew.sh/formula/qt) lists current OS/architecture availability. Do not assume its latest binary packages support an older Intel Mac. For Intel or a different supported macOS version, install a matching Qt kit using the Qt installer and set its actual path instead:

```bash
export TRU_QT_PREFIX="/actual/path/to/Qt/6.x.y/macos"
bash scripts/build-macos-desktop.sh
```

The script configures a separate build directory, compiles the client and offline transport tests, runs CTest, copies the app into a fresh staging directory, deploys Qt with the matching `macdeployqt`, checks the Cocoa plugin and binary architecture slices, rejects remaining absolute non-system library dependencies, and creates an ad-hoc-signed development disk image.

The final lines print the actual `.app` and `.dmg` paths. Typical output:

```text
build-macos-arm64/package.XXXXXX/TRU Core Desktop.app
build-macos-arm64/TRU-Core-Desktop-arm64-development-TIMESTAMP.dmg
```

Open the disk image and drag the app into Applications. A locally built ad-hoc-signed app is not a public signed/notarized release. Keep the staging directory until you finish testing or release packaging.

## 3. Apple Silicon, Intel and universal builds

The default is the current build process architecture. Build natively on each architecture for the simplest two-download release. If running Terminal under Rosetta, `uname -m` may select Intel; use native Terminal for Apple Silicon builds.

```bash
TRU_MAC_ARCH=arm64 bash scripts/build-macos-desktop.sh
TRU_MAC_ARCH=x86_64 bash scripts/build-macos-desktop.sh
TRU_MAC_ARCH='arm64;x86_64' bash scripts/build-macos-desktop.sh
```

These are alternatives, not commands that every Mac can run successfully. Your Qt kit and every linked dependency must contain the requested architecture(s). Universal output requires a universal Qt kit; selecting two architectures cannot convert single-architecture dependencies. The script verifies slices in deployed Mach-O files. The test executable must run on the build machine too; an Intel-only build on Apple Silicon requires a compatible execution environment.

Use a separate build directory when changing Qt kits or deployment targets:

```bash
TRU_MAC_BUILD_DIR="$PWD/build-macos-releasekit" bash scripts/build-macos-desktop.sh
```

The minimum supported macOS version comes from the selected compiler, Qt kit and dependencies. To set a compatible explicit deployment target, use `TRU_MAC_DEPLOYMENT_TARGET`; never lower it beneath your dependencies' supported minimum. Validate the result on the oldest macOS version you advertise. The package does not promise Catalina support or a specific minimum OS.

## 4. Connect to TRU

Launch the app, open Connection, set the loopback `/rpc` endpoint and the node's cookie, then Connect. On macOS the default cookie lookup is `~/.tru/rpc-cookie-PORT`; use the node's actual RPC port. The app can also use a session-only RPC token. A Finder launch may not inherit your terminal's environment variables.

For a TRU node running on your Linux machine, keep RPC bound to loopback and use an SSH forward. Substitute the actual node port in both positions:

```bash
ssh -N -L 127.0.0.1:LOCAL_PORT:127.0.0.1:NODE_RPC_PORT user@linux-host
```

Set the client endpoint to `http://127.0.0.1:LOCAL_PORT/rpc` and authenticate with that node's RPC credential. The Mac cannot automatically read a Linux host's cookie. Use the session-token field or a protected local credential file; do not put credentials into source, screenshots, or the app bundle. A node restart may require refreshing the credential.

The client has exactly the selected RPC features of GUI-DESKTOP-01. It does not add ordinary TRU sending, token issuance, wallet unlocking or mining. It never requests your wallet seed/private key. Full integrated wallet functionality on Mac requires the separate core port below.

## 5. Public Mac release

The build script does not contact Apple, sign with your developer identity, notarize, or publish anything. For a normal downloadable release, prepare a Developer ID Application identity and a Keychain-stored notarytool profile on your Mac. Use your own Apple developer account; no credentials belong in this patch.

Qt documents deployment/signing options in its [macOS deployment guide](https://doc.qt.io/qt-6/macos-deployment.html); Apple documents the [notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

After a successful build, use the printed staging app path below. Substitute the real identity and profile. Run these yourself only when ready to submit the artifact to Apple:

```bash
APP="/absolute/printed/staging/path/TRU Core Desktop.app"
IDENTITY="Developer ID Application: YOUR NAME (TEAMID)"
PROFILE="YOUR-KEYCHAIN-NOTARY-PROFILE"
RELEASE_DIR="$(mktemp -d "$PWD/tru-mac-release.XXXXXX")"

"$TRU_QT_PREFIX/bin/macdeployqt" "$APP" -always-overwrite \
  "-sign-for-notarization=$IDENTITY"
codesign --verify --deep --strict --verbose=2 "$APP"
ditto -c -k --keepParent "$APP" "$RELEASE_DIR/TRU-Core-Desktop.zip"
xcrun notarytool submit "$RELEASE_DIR/TRU-Core-Desktop.zip" \
  --keychain-profile "$PROFILE" --wait
```

Continue only if Apple's result is **Accepted**. If rejected, inspect the submission log and fix the cause before proceeding. Staple the accepted ticket, verify the app, then package the already-stapled app:

```bash
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
mkdir "$RELEASE_DIR/image"
ditto "$APP" "$RELEASE_DIR/image/TRU Core Desktop.app"
ln -s /Applications "$RELEASE_DIR/image/Applications"
hdiutil create -volname 'TRU Core Desktop' -srcfolder "$RELEASE_DIR/image" \
  -format UDZO "$RELEASE_DIR/TRU-Core-Desktop.dmg"
codesign --sign "$IDENTITY" --timestamp "$RELEASE_DIR/TRU-Core-Desktop.dmg"
xcrun notarytool submit "$RELEASE_DIR/TRU-Core-Desktop.dmg" \
  --keychain-profile "$PROFILE" --wait
```

Again require **Accepted**, then:

```bash
xcrun stapler staple "$RELEASE_DIR/TRU-Core-Desktop.dmg"
xcrun stapler validate "$RELEASE_DIR/TRU-Core-Desktop.dmg"
shasum -a 256 "$RELEASE_DIR/TRU-Core-Desktop.dmg"
```

Distribute the final DMG with its actual architecture, version, minimum OS, checksum and applicable dependency notices. Test the downloaded file on a clean Mac without Qt/Homebrew, including Gatekeeper, launch from Applications, authentication errors, node disconnection, reconnection, Retina scaling and closing during a request. Test both architectures if advertising both.

## 6. Full-node Mac work remains

The supplied core build is Linux-oriented. Specific follow-up work includes:

- `peer_connection.cpp`: replace the unguarded `MSG_NOSIGNAL` socket send path with a reviewed Darwin equivalent, preserving SIGPIPE/error handling.
- CMake and dependencies: supply matching Darwin/architecture builds for libwally, ethash/keccak, LevelDB, OpenSSL and other core dependencies; retain runtime library discovery when bundling.
- `tru_version.h` and `my_miner.cpp`: Linux executable/CPU discovery has `/proc` assumptions or Linux-only branches; provide Mac behavior before advertising those features.
- GPU paths: current OpenCL headers/runtime assumptions require separate review; this desktop patch provides no Mac GPU-mining claim.
- Node data and encrypted wallet lifecycle: make startup/data paths independent of Finder's working directory and validate durability, recovery, signal/shutdown and child-miner handling on Darwin.

This is a scoped list from source inspection, not an exhaustive port audit. Do not advertise a native Mac full node until it links and passes chain/wallet/P2P acceptance tests. A Linux node in a VM or on your existing Linux host can serve the desktop client in the meantime.

## Validation and rollback

See `VALIDATION.txt` for checks actually performed. No `.app`, `.dmg`, Developer ID signature or notarization result was produced on this Linux host.

Rollback this add-on using the exact backup path printed by its installer, before rolling back GUI-DESKTOP-01:

```bash
python3 apply_patch.py --root /path/to/repo \
  --rollback /path/to/repo/.tru-patches/MAC-DESKTOP-01/printed-timestamp
```

The installer refuses rollback over later edits. Rebuild separately after rollback.
