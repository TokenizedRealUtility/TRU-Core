#!/usr/bin/env python3
"""Build the pinned TRU Core from a clean Git checkout and issue a local receipt."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


VERSION = "TRU-GITHUB-INSTALL-01"
LEDGER = "swap/POST_GROUP05_ACTIVE_LINEAGE.json"
MANIFEST = "swap/PORTABLE_BUILD_SOURCE_PINS.json"
VERIFIER = "swap/agent/verify_runtime_lineage_v1.py"
CORE = "build-native/bin/tru_advanced"
CLI = "build-native/bin/tru-cli"
CONFIG = "build-native/bin/tru.conf"
POLICY = "build-native/bin/allowed_scripts.json"
RECEIPT = ".runtime_verify/TRU_PORTABLE_LINEAGE_01/ACTIVE.json"


def fail(message: str) -> None:
    raise RuntimeError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def safe_path(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
        fail("unsafe path: " + relative)
    target = root
    for part in relative.split("/"):
        target /= part
        if target.is_symlink():
            fail("symlinked path: " + relative)
    if target.exists():
        info = target.stat()
        if not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
            fail("aliased or nonregular path: " + relative)
    return target


def read_file(root: Path, relative: str) -> bytes:
    target = safe_path(root, relative)
    if not target.is_file():
        fail("missing file: " + relative)
    return target.read_bytes()


def file_hash(root: Path, relative: str) -> str:
    return digest(read_file(root, relative))


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=check, timeout=60)


def release_identity(ledger: dict) -> str:
    portable = ledger["portableRuntime"]
    body = {
        "buildSourceSetSha256": portable["buildSourceSetSha256"],
        "lineageVersion": ledger["version"],
        "pins": ledger["pins"],
        "portableVersion": "TRU-PORTABLE-LINEAGE-01",
    }
    return digest(canonical(body))


def verify_release(root: Path) -> tuple[dict, dict]:
    top = Path(git(root, "rev-parse", "--show-toplevel").stdout.decode().strip()).resolve()
    if top != root:
        fail("TRU_ROOT must be the Git checkout root")
    if git(root, "status", "--porcelain", "--untracked-files=no").stdout:
        fail("tracked checkout changes are present; install from a clean exact commit")
    tracked_binary = git(root, "ls-files", "--error-unmatch", "--", CORE, check=False)
    if tracked_binary.returncode == 0:
        fail("machine-specific TRU Core binary must not be stored in Git")
    ledger = strict_json(read_file(root, LEDGER))
    pins = ledger.get("pins")
    if not isinstance(pins, dict) or not pins:
        fail("release pin set is missing")
    if CORE in pins:
        fail("release ledger contains a machine-specific Core pin")
    for relative, expected in pins.items():
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            fail("invalid release pin: " + relative)
        if file_hash(root, relative) != expected:
            fail("release pin mismatch: " + relative)
    portable = ledger.get("portableRuntime", {})
    if portable.get("version") != "TRU-PORTABLE-LINEAGE-01":
        fail("portable release declaration is missing")
    if portable.get("buildSourceManifest") != MANIFEST or portable.get("binaryPath") != CORE:
        fail("portable release paths do not match this installer")
    if portable.get("buildSourceSetSha256") != file_hash(root, MANIFEST):
        fail("build source manifest identity mismatch")
    if portable.get("releaseId") != release_identity(ledger):
        fail("portable release identity mismatch")
    manifest = strict_json(read_file(root, MANIFEST))
    if not isinstance(manifest, dict) or not manifest:
        fail("build source manifest is empty")
    for relative, expected in manifest.items():
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            fail("invalid source pin: " + relative)
        if file_hash(root, relative) != expected:
            fail("build source mismatch: " + relative)
    return ledger, manifest


def process_gate() -> None:
    names = {"tru_advanced", "tru_miner", "tru_miner_cpu", "my_gpu_miner", "my_miner"}
    scripts = {"tru_swap_agent.py", "market_http_api_v1.py", "tru_market_api.py"}
    if not Path("/proc").is_dir():
        fail("Linux /proc is required")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            command = (proc / "comm").read_text().strip()
            arguments = [Path(item.decode(errors="replace")).name for item in (proc / "cmdline").read_bytes().split(b"\0") if item]
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            fail("cannot verify process state through /proc")
        if command in names or any(item in names | scripts for item in arguments):
            fail("node, miner, Agent, or Market is running (PID " + proc.name + ")")


def atomic_copy(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or destination.is_symlink():
        fail("unsafe activation path: " + str(destination))
    descriptor, temporary = tempfile.mkstemp(prefix=".github-install-", dir=destination.parent)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
            output_stream.flush()
            os.fchmod(output_stream.fileno(), mode)
            os.fsync(output_stream.fileno())
        os.replace(temporary, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def atomic_write(destination: Path, raw: bytes, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".github-install-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def run_logged(args: list[str], cwd: Path, log: Path, timeout: int) -> None:
    environment = dict(os.environ)
    for key in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CMAKE_TOOLCHAIN_FILE"):
        environment.pop(key, None)
    with log.open("ab") as stream:
        process = subprocess.Popen(args, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True, env=environment)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            raise
        if process.returncode:
            fail("build command failed; inspect " + str(log))


def build(root: Path, manifest: dict) -> tuple[Path, Path, Path, Path]:
    if not shutil.which("cmake") or not shutil.which("nm"):
        fail("cmake and nm are required")
    jobs = os.environ.get("TRU_BUILD_JOBS", "2")
    if re.fullmatch(r"[0-9]+", jobs) is None or not 1 <= int(jobs) <= 32:
        fail("TRU_BUILD_JOBS must be 1..32")
    parent = safe_path(root, ".patch_builds/TRU_GITHUB_INSTALL_01")
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=parent))
    work.chmod(0o700)
    source = work / "source"
    source.mkdir()
    for relative, expected in manifest.items():
        raw = read_file(root, relative)
        if digest(raw) != expected:
            fail("source changed during build: " + relative)
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    (source / "tru.conf").write_text(
        "[network]\nrpcbind=127.0.0.1\nrpcport=21832\np2pPort=21833\nlisten=1\nrpcMaxConnections=32\n",
        encoding="utf-8",
    )
    output = work / "build"
    log = work / "build.log"
    run_logged(
        ["cmake", "-S", str(source), "-B", str(output), "-DUSE_OPENCL=OFF", "-DBUILD_WITH_QT=OFF", "-DTRU_08B3T_TEST_HOOKS=OFF", "-DCMAKE_BUILD_TYPE=Release"],
        work,
        log,
        300,
    )
    run_logged(["cmake", "--build", str(output), "--target", "tru_advanced", "tru-cli", "--parallel", jobs], work, log, 3600)
    core, cli = output / "bin/tru_advanced", output / "bin/tru-cli"
    config, policy = output / "bin/tru.conf", output / "bin/allowed_scripts.json"
    for candidate in (core, cli):
        if not candidate.is_file() or candidate.is_symlink() or not os.access(candidate, os.X_OK):
            fail("isolated build did not produce " + candidate.name)
        if candidate.read_bytes()[:4] != b"\x7fELF":
            fail("isolated build output is not ELF: " + candidate.name)
    if not config.is_file() or not policy.is_file():
        fail("isolated build did not produce runtime configuration")
    symbols = subprocess.run(["nm", "-C", "--defined-only", str(core)], capture_output=True, check=True, timeout=120).stdout
    for name in (b"Blockchain::processAcceptedTransactionRelay(", b"P2PNode::isSelfEndpoint("):
        if name not in symbols:
            fail("required linked method missing: " + name.decode())
    print("FULL_ISOLATED_NODE_BUILD=PASS")
    return core, cli, config, policy


def receipt(ledger: dict, core: Path, cli: Path) -> bytes:
    portable = ledger["portableRuntime"]
    return canonical({
        "binaryPath": CORE,
        "binarySha256": digest(core.read_bytes()),
        "build": "ISOLATED_FROM_EXACT_RELEASE_SOURCE",
        "buildSourceSetSha256": portable["buildSourceSetSha256"],
        "releaseId": portable["releaseId"],
        "truCliSha256": digest(cli.read_bytes()),
        "version": "TRU-PORTABLE-LINEAGE-01",
    })


def invoke_verifier(root: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(safe_path(root, VERIFIER)), "--tru-root", str(root)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        fail((result.stderr or result.stdout).strip())
    print(result.stdout.strip())


def activate(root: Path, ledger: dict, outputs: tuple[Path, Path, Path, Path]) -> None:
    targets = [safe_path(root, item) for item in (CORE, CLI, CONFIG, POLICY, RECEIPT)]
    if any(target.exists() for target in targets):
        fail("runtime output already exists without a valid receipt; preserve it and investigate before installing")
    core, cli, config, policy = outputs
    created: list[Path] = []
    try:
        for source, relative, mode in ((core, CORE, 0o755), (cli, CLI, 0o755), (config, CONFIG, 0o600), (policy, POLICY, 0o644)):
            destination = safe_path(root, relative)
            atomic_copy(source, destination, mode)
            created.append(destination)
        receipt_path = safe_path(root, RECEIPT)
        atomic_write(receipt_path, receipt(ledger, core, cli), 0o600)
        created.append(receipt_path)
        invoke_verifier(root)
    except BaseException:
        for target in reversed(created):
            with contextlib.suppress(FileNotFoundError):
                target.unlink()
        print("ACTIVATION_ROLLBACK=CREATED_FILES_REMOVED", file=sys.stderr)
        raise


def main(argv: list[str] | None = None) -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Build a pinned TRU release from Git")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        fail("run as the checkout owner, without sudo")
    root = Path(os.environ.get("TRU_ROOT", os.getcwd())).expanduser().resolve()
    lock_path = safe_path(root, ".tru-github-install-01.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ledger, manifest = verify_release(root)
        receipt_path, core_path = safe_path(root, RECEIPT), safe_path(root, CORE)
        if receipt_path.exists() or core_path.exists():
            if not receipt_path.is_file() or not core_path.is_file():
                fail("partial local runtime detected; preserve it and investigate")
            invoke_verifier(root)
            print("TRU_GITHUB_INSTALL_01=INSTALLED_VERIFIED")
            return
        if args.verify:
            fail("local build receipt is missing; run without --verify")
        process_gate()
        print("EXACT_GIT_RELEASE_INPUTS=PASS")
        print("MACHINE_SPECIFIC_BINARY_IN_GIT=NO")
        if args.preflight:
            print("READ_ONLY_GITHUB_INSTALL_PREFLIGHT=PASS")
            return
        outputs = build(root, manifest)
        process_gate()
        activate(root, ledger, outputs)
        print("TRU_GITHUB_INSTALL_01=INSTALLED")
        print("NODE_STARTED=NO")
        print("WALLET_OR_CHAIN_DATABASE_CREATED=NO")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
