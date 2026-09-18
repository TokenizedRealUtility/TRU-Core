#!/usr/bin/env python3
"""Read-only readiness report for TRU Core, GlobalBoost, and the Swap Agent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
CONFIG = Path.home() / ".config/tru-swap/launcher.json"
CORE = ROOT / "build-native/bin/tru_advanced"
TRU_CLI = ROOT / "build-native/bin/tru-cli"
VERIFY = ROOT / "swap/agent/verify_runtime_lineage_v1.py"
HEALTH = "http://127.0.0.1:8645/v1/health"


def fail(message: str) -> None:
    raise RuntimeError(message)


def command(args: list[str], timeout: int = 20):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        fail(Path(args[0]).name + " " + args[-1] + " failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(Path(args[0]).name + " " + args[-1] + " returned invalid JSON")


def verify_runtime() -> str:
    result = subprocess.run(
        [sys.executable, str(VERIFY), "--tru-root", str(ROOT)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        fail((result.stderr or result.stdout or "runtime verification failed").strip())
    for line in result.stdout.splitlines():
        if line.startswith("RELEASE_ID="):
            return line.split("=", 1)[1]
    fail("runtime verifier did not return a release identity")


def core_process() -> Path:
    result = subprocess.run(["pgrep", "-x", "tru_advanced"], capture_output=True, text=True, timeout=10)
    ids = result.stdout.split()
    if len(ids) != 1:
        fail("exactly one TRU Core must be running for this checkout user")
    proc = Path("/proc") / ids[0]
    try:
        if proc.stat().st_uid != os.geteuid() or (proc / "exe").resolve() != CORE.resolve():
            fail("running TRU Core belongs to another checkout or user")
    except (FileNotFoundError, PermissionError):
        fail("running TRU Core could not be verified")
    return proc


def core_gates(proc: Path) -> dict[str, bool]:
    try:
        environment = dict(
            item.split(b"=", 1)
            for item in (proc / "environ").read_bytes().split(b"\0")
            if b"=" in item
        )
    except (FileNotFoundError, PermissionError):
        fail("TRU Core environment could not be verified")
    return {
        "privateAgentAuthentication": len(environment.get(b"TRU_SWAP_RPC_TOKEN", b"")) >= 32,
        "preparedBroadcast": environment.get(b"TRU_SWAP_PREPARED_BROADCAST_ENABLE") == b"1",
    }


def read_launcher_config() -> dict:
    if not CONFIG.exists():
        return {}
    if CONFIG.is_symlink() or CONFIG.stat().st_uid != os.geteuid():
        fail("unsafe launcher settings file")
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def detect_bsty(config: dict) -> tuple[str, str]:
    configured = os.environ.get("TRU_SWAP_BSTY_CLI") or config.get("bstyCli")
    candidates = [
        Path(configured).expanduser() if configured else None,
        ROOT.parent / "globalboost/src/globalboost-cli",
        Path.home() / "globalboost/src/globalboost-cli",
        Path.home() / "projects/globalboost/src/globalboost-cli",
    ]
    cli = next(
        (candidate for candidate in candidates if candidate and candidate.is_file() and os.access(candidate, os.X_OK)),
        None,
    )
    if cli is None:
        fail("globalboost-cli was not found")
    wallets = command([str(cli), "listwallets"])
    wallet = os.environ.get("TRU_SWAP_BSTY_WALLET") or config.get("bstyWallet")
    if wallet not in wallets:
        if isinstance(wallets, list) and len(wallets) == 1:
            wallet = wallets[0]
        else:
            fail("saved GlobalBoost wallet is not the single loaded wallet")
    return str(cli.resolve()), wallet


def agent_health() -> dict:
    request = urllib.request.Request(
        HEALTH,
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        fail("Swap Agent health check failed: " + str(exc))
    if payload.get("ok") is not True:
        fail("Swap Agent is not ready")
    return payload


def collect() -> dict:
    release_id = verify_runtime()
    proc = core_process()
    gates = core_gates(proc)
    if not all(gates.values()):
        fail("TRU Core swap startup gates are not both enabled")
    tru_height = command([str(TRU_CLI), "getblockcount"])
    tru_mempool = command([str(TRU_CLI), "getrawmempool"])
    cli, wallet = detect_bsty(read_launcher_config())
    bsty_chain = command([cli, "getblockchaininfo"])
    bsty_peers = command([cli, "getconnectioncount"])
    bsty_wallet = command([cli, "-rpcwallet=" + wallet, "getwalletinfo"])
    if bsty_chain.get("chain") != "main" or bsty_chain.get("initialblockdownload") is not False:
        fail("GlobalBoost is not synced on mainnet")
    if bsty_wallet.get("private_keys_enabled") is not True:
        fail("selected GlobalBoost wallet cannot sign")
    health = agent_health()
    required_agent_gates = {
        "fundingRouteEnabled": True,
        "exitWatcherEnabled": True,
        "truPreparedRealBroadcastEnabled": True,
        "bstyPreparedRealBroadcastEnabled": True,
    }
    reported = health.get("gates", {})
    if any(reported.get(name) is not value for name, value in required_agent_gates.items()):
        fail("Swap Agent action gates are not fully enabled")
    if health.get("cores", {}).get("tru", {}).get("ok") is not True:
        fail("Swap Agent cannot reach TRU Core")
    if health.get("cores", {}).get("bsty", {}).get("ok") is not True:
        fail("Swap Agent cannot reach GlobalBoost")
    return {
        "ok": True,
        "releaseId": release_id,
        "tru": {
            "height": tru_height,
            "mempoolTransactions": len(tru_mempool),
            "privateAgentAuthentication": gates["privateAgentAuthentication"],
            "preparedBroadcast": gates["preparedBroadcast"],
        },
        "bsty": {
            "height": bsty_chain.get("blocks"),
            "headers": bsty_chain.get("headers"),
            "peers": bsty_peers,
            "wallet": wallet or "(default wallet)",
            "privateKeysEnabled": True,
        },
        "agent": {
            "version": health.get("version"),
            "pairingMode": health.get("pairing", {}).get("mode"),
            "fundingEnabled": reported.get("fundingRouteEnabled") is True,
            "exitWatcherEnabled": reported.get("exitWatcherEnabled") is True,
        },
    }


def render(report: dict) -> None:
    print("TRU_RELEASE_PINS=PASS release=" + report["releaseId"][:12])
    print(
        "TRU_CORE=PASS height={height} mempool={mempoolTransactions} prepared-broadcast=ON private-agent-auth=ON".format(
            **report["tru"]
        )
    )
    print(
        "BSTY_CORE=PASS height={height}/{headers} peers={peers} wallet={wallet} signing=ON".format(
            **report["bsty"]
        )
    )
    print(
        "SWAP_AGENT=PASS version={version} pairing={pairingMode} funding=ON watcher=ON".format(
            **report["agent"]
        )
    )
    print("READ_ONLY_CHECK=PASS")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Read-only TRU swap readiness report")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        fail("run as the checkout user, without sudo")
    report = collect()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        render(report)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("CHECK: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
