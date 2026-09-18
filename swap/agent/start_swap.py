#!/usr/bin/env python3
"""Safe end-user launcher for the pinned TRU Core and Swap Agent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import webbrowser


ROOT = Path(__file__).resolve().parents[2]
CONFIG = Path.home() / ".config/tru-swap/launcher.json"
CORE = ROOT / "build-native/bin/tru_advanced"
VERIFY = ROOT / "swap/agent/verify_runtime_lineage_v1.py"
MARKET_URL = "https://tokenizedrealutility.com/market.html"


def fail(message: str) -> None:
    raise RuntimeError(message)


def run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def verify_runtime() -> None:
    result = run([sys.executable, str(VERIFY), "--tru-root", str(ROOT)], 180)
    if result.returncode:
        fail((result.stderr or result.stdout or "Runtime verification failed").strip())


def core_process() -> Path | None:
    result = run(["pgrep", "-x", "tru_advanced"])
    process_ids = result.stdout.split()
    if not process_ids:
        return None
    if len(process_ids) != 1:
        fail("Multiple TRU Cores are running. Use a separate OS user for each wallet node.")
    proc = Path("/proc") / process_ids[0]
    try:
        if proc.stat().st_uid != os.geteuid() or (proc / "exe").resolve() != CORE.resolve():
            fail("The running Core belongs to another checkout or user.")
    except (FileNotFoundError, PermissionError):
        fail("The running Core could not be verified. Start it again as this checkout user.")
    return proc


def core_environment(proc: Path) -> dict[bytes, bytes]:
    try:
        return dict(
            item.split(b"=", 1)
            for item in (proc / "environ").read_bytes().split(b"\0")
            if b"=" in item
        )
    except (FileNotFoundError, PermissionError):
        fail("The Core environment could not be verified. Start it as this checkout user.")


def read_config() -> dict:
    if not CONFIG.exists():
        return {}
    if CONFIG.is_symlink() or CONFIG.stat().st_uid != os.geteuid():
        fail("Unsafe launcher settings file")
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        fail("Invalid launcher settings")
    return data


def save_config(config: dict) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CONFIG.parent.is_symlink() or CONFIG.is_symlink():
        fail("Unsafe launcher settings path")
    if CONFIG.parent.stat().st_uid != os.geteuid():
        fail("Launcher settings directory is not owned by this user")
    descriptor, temporary = tempfile.mkstemp(dir=CONFIG.parent, prefix=".launcher-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(config, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, CONFIG)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rpc(cli: str, method: str, *options: str):
    result = run([cli, *options, method], 20)
    if result.returncode:
        fail("GlobalBoost " + method + " failed. Check the node and loaded wallet.")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("GlobalBoost " + method + " returned invalid JSON")


def detect_bsty_cli(environment: dict[str, str], config: dict) -> str:
    configured = environment.get("TRU_SWAP_BSTY_CLI") or config.get("bstyCli")
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
        fail("Install GlobalBoost and start its node. globalboost-cli must be executable.")
    return str(cli.resolve())


def wallet_settings(environment: dict[str, str], config: dict) -> tuple[str, str]:
    cli = detect_bsty_cli(environment, config)
    chain = rpc(cli, "getblockchaininfo")
    if chain.get("chain") != "main" or chain.get("initialblockdownload") is not False:
        fail("GlobalBoost must be synced on mainnet before using swaps.")
    wallets = rpc(cli, "listwallets")
    if not isinstance(wallets, list) or not wallets or any(not isinstance(item, str) for item in wallets):
        fail("Load your GlobalBoost wallet, then start TRU Swap again.")
    wallet = environment.get("TRU_SWAP_BSTY_WALLET", config.get("bstyWallet"))
    if wallet is not None and wallet not in wallets:
        fail("The selected GlobalBoost wallet is not loaded. Load it or use --choose-wallet.")
    if wallet is None:
        if len(wallets) == 1:
            wallet = wallets[0]
        else:
            if not sys.stdin.isatty():
                fail("Run Start_TRU_Swap.sh in a terminal to choose a wallet once.")
            print("Choose the GlobalBoost wallet for your swaps:")
            for index, item in enumerate(wallets, 1):
                print(f"{index}. {item or '(default wallet)'}")
            try:
                selection = int(input("Wallet number: "))
                if not 1 <= selection <= len(wallets):
                    raise ValueError
                wallet = wallets[selection - 1]
            except (ValueError, EOFError):
                fail("No wallet selected.")
    info = rpc(cli, "getwalletinfo", "-rpcwallet=" + wallet)
    if info.get("private_keys_enabled") is not True:
        fail("The selected GlobalBoost wallet cannot sign swaps.")
    return cli, wallet


def agent_environment(environment: dict[str, str], config: dict, watch_only: bool = False) -> dict[str, str]:
    result = dict(environment)
    result["TRU_ROOT"] = str(ROOT)
    for name in (
        "TRU_SWAP_GROUP05_CONFIRM",
        "TRU_SWAP_PREPARED_BROADCAST_ENABLE",
        "TRU_SWAP_MARKET_ORIGIN",
        "TRU_SWAP_AGENT_REMOTE_PAIRING",
        "TRU_SWAP_AGENT_REMOTE_PAIR_HOST",
    ):
        result.pop(name, None)
    result["TRU_SWAP_DUAL_FUNDING_ENABLE"] = "0" if watch_only else "1"
    result["TRU_SWAP_EXIT_WATCHER_ENABLE"] = "0" if watch_only else "1"
    if config.get("operatorMode") is True:
        result["TRU_SWAP_MARKET_ORIGIN"] = "http://127.0.0.1:8650"
        result["TRU_SWAP_AGENT_REMOTE_PAIRING"] = "cloudflare-access"
        result["TRU_SWAP_AGENT_REMOTE_PAIR_HOST"] = "swap-agent.tokenizedrealutility.com"
    return result


def start_core() -> None:
    if core_process() is not None:
        print("Your pinned TRU Core is already running.")
        return
    environment = dict(os.environ)
    for name in (
        "TRU_SWAP_GROUP05_CONFIRM",
        "TRU_SWAP_DUAL_FUNDING_ENABLE",
        "TRU_SWAP_EXIT_WATCHER_ENABLE",
    ):
        environment.pop(name, None)
    environment["TRU_SWAP_PREPARED_BROADCAST_ENABLE"] = "1"
    environment["TRU_SWAP_RPC_TOKEN"] = secrets.token_hex(32)
    os.chdir(CORE.parent)
    os.execve(str(CORE), ["tru_advanced", "--cli", "--enable-explorer"], environment)


def start_agent(args: argparse.Namespace) -> None:
    proc = core_process()
    if proc is None:
        fail("Start bash ./swap/agent/Start_TRU_Core.sh in another terminal first.")
    environment_bytes = core_environment(proc)
    if len(environment_bytes.get(b"TRU_SWAP_RPC_TOKEN", b"")) < 32:
        fail("Restart your Core with Start_TRU_Core.sh to create private Agent authentication.")
    if not args.watch_only and environment_bytes.get(b"TRU_SWAP_PREPARED_BROADCAST_ENABLE") != b"1":
        fail("Restart your Core with Start_TRU_Core.sh to enable swap-safe prepared broadcasts.")
    config = read_config()
    if args.operator:
        config["operatorMode"] = True
    if args.local_agent:
        config.pop("operatorMode", None)
    environment = dict(os.environ)
    if args.choose_wallet:
        config.pop("bstyWallet", None)
        environment.pop("TRU_SWAP_BSTY_WALLET", None)
    cli, wallet = wallet_settings(environment, config)
    config.update({"bstyCli": cli, "bstyWallet": wallet})
    save_config(config)
    environment = agent_environment(environment, config, args.watch_only)
    environment["TRU_SWAP_BSTY_CLI"] = cli
    environment["TRU_SWAP_BSTY_WALLET"] = wallet
    print("TRU Swap starting. GlobalBoost wallet: " + (wallet or "(default wallet)"), flush=True)
    if args.watch_only:
        print("Watch-only mode: funding and exit execution are disabled.", flush=True)
    else:
        print("Swap actions enabled. Funding still requires your approval on the swap page.", flush=True)
        print("Armed watchers may execute only the claim/refund destinations you approved.", flush=True)
    print("Open " + MARKET_URL + " and choose Connect TRU Swap.", flush=True)
    if not args.no_browser:
        try:
            webbrowser.open(MARKET_URL)
        except Exception:
            pass
    os.execve("/bin/bash", ["bash", str(ROOT / "swap/agent/run_agent.sh")], environment)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start the pinned TRU Core or Swap Agent")
    parser.add_argument("--core", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--watch-only", action="store_true", help="Disable funding and exit execution")
    parser.add_argument("--choose-wallet", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--operator", action="store_true", help="Remember the hosted gw878 Agent/Market settings")
    mode.add_argument("--local-agent", action="store_true", help="Forget hosted operator mode and use Local Connect")
    args = parser.parse_args(argv)
    if args.core and (args.watch_only or args.choose_wallet or args.no_browser or args.operator or args.local_agent):
        parser.error("Agent-only options cannot be combined with --core")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if os.geteuid() == 0:
        fail("Start as your normal checkout user, without sudo.")
    verify_runtime()
    if args.check:
        print("ACTIVE_RUNTIME_PINS=PASS")
        return
    if args.core:
        start_core()
    else:
        start_agent(args)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print("STARTUP: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
