# TRU Core 0.08.9 — `tru-cli` and UTXO Tools R2

`tru-cli` is TRU's standalone command-line client for node administration, scripting, diagnostics, wallet reads, mining information, and raw JSON-RPC access.

This guide covers authenticated CLI administration and the optional UTXO-TOOLS-01 R2 update. Commands depend on the features included in the installed Core and CLI build.

The current TRU source tree already includes:

- the `getbalance` RPC,
- the `getinfo` aggregate RPC,
- the `tru-cli` build target,
- Patch-05 authenticated RPC transport.

No separate Patch 31 installation or manual copy of `tru-cli.cpp` is required for the current release tree.

---

## Build

Use your existing project build configuration. Rebuild Core and CLI after applying a source patch. If this checkout provides the established rebuild script:

```bash
cd ~/NEW_TRU
./rebuild.sh
```

The CLI binary is produced at:

```text
build-native/bin/tru-cli
```

---

## Default connection

The native node defaults to:

```text
RPC host: 127.0.0.1
RPC port: 21832
```

Example:

```bash
cd ~/NEW_TRU/build-native/bin

./tru-cli getinfo
./tru-cli getbalance
./tru-cli getblockcount
./tru-cli getchaininfo
./tru-cli getconnectioncount
./tru-cli getpeerinfo
```

---

# RPC authentication

Privileged Core JSON-RPC is authenticated.

Every Core `/rpc` POST requires a Bearer credential. `tru-cli` handles this automatically and should normally be used without putting a token on the command line.

Authentication sources are checked using the configured RPC port:

1. `TRU_RPC_TOKEN` — explicit transport credential.
2. `TRU_RPC_COOKIE_FILE` — explicit private cookie path.
3. Default native cookie — `~/.tru/rpc-cookie-<port>`.

For the default port:

```text
~/.tru/rpc-cookie-21832
```

The cookie is private node/operator state and must not be committed to Git, printed in documentation, pasted into browser JavaScript, or exposed through a public web endpoint.

A normal local call is simply:

```bash
./tru-cli getblockcount
```

If the node and CLI use the same account and standard cookie location, no additional credential argument is required.

### Custom cookie path

For a private operator environment:

```bash
export TRU_RPC_COOKIE_FILE=/secure/private/path/rpc-cookie
./tru-cli getinfo
```

### Explicit transport credential

`TRU_RPC_TOKEN` may be used by private infrastructure when required:

```bash
export TRU_RPC_TOKEN='<PRIVATE_OPERATOR_SECRET>'
./tru-cli getinfo
```

Do not place an actual credential in documentation, shell history intended for sharing, source control, or browser-side code.

---

## Docker authentication

Raw Docker node images use the deterministic cookie location:

```text
/app/data/.rpc-cookie-21832
```

The Docker Compose layout uses the private shared RPC-auth path:

```text
/run/truam-rpc/token
```

When administering a containerized node, prefer running the CLI in the trusted container/private operator environment rather than extracting or printing the credential.

Example:

```bash
docker exec -it <TRU_NODE_CONTAINER> /app/truam-cli getinfo
```

Use the actual binary path/name present in the image if it differs.

---

# Common commands

```bash
./tru-cli getinfo
./tru-cli getbalance
./tru-cli getbalance <TRU_ADDRESS>
./tru-cli getblockcount
./tru-cli getchaininfo
./tru-cli getbestblockhash
./tru-cli getdifficulty
./tru-cli getconnectioncount
./tru-cli getpeerinfo
./tru-cli listaddresses
./tru-cli listunspent <TRU_ADDRESS>
./tru-cli listtransactions <TRU_ADDRESS>
./tru-cli getblock <BLOCK_HASH>
./tru-cli getblockbyheight <HEIGHT>
./tru-cli gettransaction <TXID>
./tru-cli getrawmempool
./tru-cli getmininginfo
./tru-cli gettokenmetadata <TOKEN_ID>
./tru-cli verifytokenbalance <TRU_ADDRESS> <TOKEN_ID>
```

`getbalance [address]` uses the existing Core balance semantics; do not assume a no-address call totals every wallet address. For eligible ordinary coins across wallet addresses, use the new `utxo list` command. Native token holdings are separate and should be queried with the token RPCs.

---

# Wallet UTXO tools — 0.08.9 / UTXO-TOOLS-01 R2

These commands require both Core and `tru-cli` to be rebuilt with UTXO-TOOLS-01 R2. The version label remains 0.08.9, so that label alone does not prove the tools are installed. Check `tru-cli --help`, the installer `verify` result, and the running executable.

The update adds wallet-wide ordinary-coin inventory, self-splitting, consolidation, manual input selection, and an optional bounded self-transfer runner. It does not change consensus, the subsidy, block validation, script execution, transaction serialization or existing getinfo/getbalance behavior.

## Command overview

| Command | Purpose | Signs/broadcasts? |
|---|---|---|
| `tru-cli -timeout=120 utxo list` | Inventory ordinary wallet coins across addresses | No |
| `tru-cli -timeout=120 utxo prepare JSON` | Build an unsigned split/consolidation plan | No |
| `tru-cli -timeout=120 utxo submit JSON` | Recheck, sign and submit the exact reviewed plan | Yes, with `confirm: "SUBMIT"` |
| `utxo_tool.py ... split` | Save a split preview | No |
| `utxo_tool.py ... consolidate` | Save a consolidation preview | No |
| `utxo_tool.py ... submit` | Display a saved plan; submit with `--execute` | Only with `--execute` |
| `utxo_tool.py ... run` | Preview or execute bounded self-transfer rounds | Only with `--execute` |

Native syntax is `utxo <list|prepare|submit> [JSON or @file]`. Do not put `action` in the native command's JSON; the subcommand supplies it. Request files are limited to 262,144 bytes. Native commands require a localhost endpoint and the server also enforces loopback access and existing RPC authentication.

## Timeout and operational limits

Use `-timeout=120` for UTXO commands. The ordinary CLI default is 30 seconds. A measured wallet inventory on NEW_TRU took about 49 seconds and succeeded with the longer timeout. The generic `could not reach node` message can also represent a timeout; it does not by itself prove Core stopped.

The helper already invokes the CLI with a 120-second read timeout and a 135-second subprocess timeout. These values are fixed in R2. More time is not a performance fix: if scans repeatedly exceed the limit, stop and investigate rather than starting overlapping scans. A cancelled client does not necessarily cancel server work. Submission reconstructs the plan more than once, so successful inventory timing does not guarantee submission will finish within its timeout.

Tool limits (not new consensus limits):

- At most 10,000 wallet addresses and 10,000 discovered UTXOs; excessive inventories fail rather than intentionally returning a partial total.
- At most 100 inputs and 100 outputs per prepared transaction.
- Split count: 2–99 equal outputs, plus optional change.
- Amounts: positive decimal TRU strings, at most eight decimal places; 100,000,000 atoms = 1 TRU.
- Existing output dust threshold: 546 atoms.
- Estimated fee: at least 10,000 atoms (0.0001 TRU), or the conservative signed-size relay fee if greater. Dust change can increase the fee only within `max_fee`.
- Input selection reserves the full `max_fee`, even if the expected fee is smaller.

## Prepare a local working directory

Linux examples below assume a configured build at `build-native`. Adjust ROOT for your installation; do not start two nodes against the same wallet or chain data.

```bash
ROOT="$HOME/NEW_TRU"  # use "$HOME/TRU-Core" for that installation
CLI="$ROOT/build-native/bin/tru-cli"
WORK="$HOME/tru-utxo-session-$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$WORK"
set -o pipefail
cd "$ROOT/build-native/bin"
```

Work files can expose address relationships and balances. Keep them outside the source repository. They contain no required private keys or passwords.

## 1. Read balances and eligible inputs

```bash
"$CLI" listaddresses
"$CLI" -timeout=120 utxo list > "$WORK/inventory.json"
# Continue only if the command succeeds:
python3 -m json.tool "$WORK/inventory.json"
```

The result includes `height`, `eligible_atoms`, `eligible_balance`, `eligible_utxos`, per-address totals under `addresses`, and individual `utxos` with `txid`, `vout`, `amount`, `amount_atoms`, `eligible` and `excluded_reason`.

This is an inventory of ordinary wallet-owned P2PKH coins, not a total of all wallet assets. Token-control, nonstandard/contract, reserved, immature coinbase, pending-spent, zero-value and future-height outputs are excluded where detected. WOTS/contract balances and unconfirmed incoming payments are not ordinary eligible funds. Existing `getinfo` and `getbalance` output is not redefined by this patch.

## 2. Native CLI: preview a split

Choose an existing ordinary address from your loaded wallet. All outputs, including change, go to that address. No new address is generated by this tool.

```bash
ADDRESS="REPLACE_WITH_YOUR_OWN_EXISTING_ADDRESS"

python3 - "$ADDRESS" "$WORK/split-request.json" <<'PY'
import json, sys
request = {"mode":"split", "address":sys.argv[1],
           "count":3, "amount":"0.01", "max_fee":"0.001"}
with open(sys.argv[2], "x") as f:
    json.dump(request, f, indent=2)
PY

"$CLI" -timeout=120 utxo prepare "@$WORK/split-request.json" \
  > "$WORK/split-plan.json"
# Continue only on success:
python3 -m json.tool "$WORK/split-plan.json"
```

Review every input, output, amount, fee, txid and `utxo_count_change`. `broadcast: false` means this is only a preview; neither signing nor broadcast has occurred. Inputs are not reserved.

Three equal outputs plus change normally means four outputs in ONE transaction. Net UTXO growth is output count minus input count. Automatic splitting selects large eligible inputs first across wallet addresses. A 0.03 TRU split can therefore consume a much larger input and return its remainder as change. To choose a smaller input, use manual input selection below. Combining addresses reveals their relationship publicly.

## 3. Manual input selection (coin control)

Save real eligible outpoints from the inventory; do not use placeholder transaction IDs in a live request:

```json
[
  {"txid":"REPLACE_WITH_REAL_64_HEX_TXID", "vout":0}
]
```

Save that array as `$WORK/selected-inputs.json`. Add it to a fresh split request:

```bash
python3 - "$WORK/split-request.json" "$WORK/selected-inputs.json" \
  "$WORK/selected-request.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f: request=json.load(f)
with open(sys.argv[2]) as f: request["inputs"]=json.load(f)
with open(sys.argv[3], "x") as f: json.dump(request, f, indent=2)
PY

"$CLI" -timeout=120 utxo prepare "@$WORK/selected-request.json" \
  > "$WORK/selected-plan.json"
```

Explicit inputs must be unique, eligible and sufficient for the outputs plus the full fee cap. The tool does not silently substitute other coins for unavailable explicit inputs. Use the resulting selected plan for submission, not the earlier automatic plan.

## 4. Enable signing and submit a reviewed plan

Submission requires an unlocked wallet and the existing wallet-send gate in the Core process. In Core's actual `tru.conf`, the supported setting is:

```ini
[network]
rpcWalletSend=1
```

Edit the existing section and setting rather than appending duplicates. `TRU_RPC_WALLET_SEND_ENABLE=1` is an alternative configuration key/environment setting; do not configure duplicate aliases. Restart Core normally if its configuration changed. Setting an environment variable only in the CLI terminal does not enable sends in an already-running Core process. This gate also affects existing wallet-send functionality.

Use the wallet's established unlock controls. Do not include passwords, seed phrases or private keys in these JSON files. The self-management tool uses its own explicit `max_fee`; the sendtoaddress per-payment amount cap does not govern these self-transfers.

Create a submit request containing the complete, unedited plan. Set PLAN to the exact preview you reviewed:

```bash
PLAN="$WORK/selected-plan.json"  # or "$WORK/split-plan.json"

python3 - "$PLAN" "$WORK/submit-request.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f: plan=json.load(f)
with open(sys.argv[2], "x") as f:
    json.dump({"plan":plan, "confirm":"SUBMIT"}, f, indent=2)
print("Reviewed transaction ID:", plan["txid"])
PY
```

The following command signs and submits a real transaction and spends its fee:

```bash
"$CLI" -timeout=120 utxo submit "@$WORK/submit-request.json" \
  > "$WORK/submit-result.json"
```

A successful acknowledgement includes `accepted: true`, `broadcast: true`, the expected `txid`, `fee_atoms` and `confirmed: false`. Core re-creates and compares the reviewed plan, checks wallet access and signing keys, rechecks inputs after signing, and uses its existing mempool admission path.

If the plan is stale or altered, prepare and review a fresh plan. A timeout or missing acknowledgement is an UNKNOWN outcome, not proof the transaction was rejected. Check the reviewed txid before attempting another submission. Keep request/result files; do not blindly repeat the command.

## 5. Verify confirmation and restart persistence

```bash
TXID="REPLACE_WITH_REVIEWED_TXID"
"$CLI" -json gettransaction "$TXID"
"$CLI" -json getrawmempool
"$CLI" -timeout=120 utxo list
```

Check actual confirmation and expected outputs, not just mempool disappearance. After confirmation, outputs should match the plan and consumed inputs should no longer be eligible. Confirm input total equals output total plus the approved fee. Wallet totals can also change because of other payments or newly matured rewards.

Restart through your normal shutdown/start workflow and check again. For release testing, confirm the transaction and containing block on an independent existing-version node too. A passed `auditchain` hash/PoW walk is not a transaction replay test.

## 6. Native CLI: consolidate selected coins

Consolidation spends several ordinary inputs into one output at your own chosen address. It costs a fee; a single-input consolidation does not reduce UTXO count. For initial testing, select only outputs created by the confirmed test split.

```bash
python3 - "$ADDRESS" "$WORK/selected-inputs.json" \
  "$WORK/consolidate-request.json" <<'PY'
import json, sys
with open(sys.argv[2]) as f: inputs=json.load(f)
request={"mode":"consolidate", "address":sys.argv[1],
         "max_fee":"0.001", "inputs":inputs}
with open(sys.argv[3], "x") as f: json.dump(request, f, indent=2)
PY

"$CLI" -timeout=120 utxo prepare "@$WORK/consolidate-request.json" \
  > "$WORK/consolidate-plan.json"
python3 -m json.tool "$WORK/consolidate-plan.json"
```

Use a fresh input file containing currently eligible coins; inputs spent by a prior test cannot be reused. Review, then follow the submission procedure with this plan and new request/result filenames. Omitting `inputs` automatically selects up to 100 small eligible coins across wallet addresses; review those selections carefully.

## 7. Optional Python helper

Native CLI commands above need no helper script. The optional `utxo_tool.py` ships in the R2 patch's `tools` folder; the installer does not copy it into the Core repository. If distributing it with source, place the unchanged reviewed script at `tools/utxo_tool.py` and include it explicitly in Git.

For a local patch-package installation:

```bash
PATCH="$HOME/TRU_089_UTXO_TOOLS_01_R2"
HELPER="$PATCH/tools/utxo_tool.py"
# If the community repository includes it instead:
# HELPER="$ROOT/tools/utxo_tool.py"

python3 "$HELPER" --help
python3 "$HELPER" --cli "$CLI" list
```

The helper takes a CLI executable path, not arbitrary CLI flags. R2 uses the CLI's default local endpoint; custom port/config workflows should use native CLI commands with the appropriate flags. Existing credential environment variables are inherited.

Preview a split (use fresh filenames):

```bash
python3 "$HELPER" --cli "$CLI" split \
  --address "$ADDRESS" --count 3 --amount 0.01 --max-fee 0.001 \
  --out "$WORK/helper-split-plan.json"
```

For explicit inputs, add `--inputs "$WORK/selected-inputs.json"` to that command.

Preview a consolidation:

```bash
python3 "$HELPER" --cli "$CLI" consolidate \
  --address "$ADDRESS" --inputs "$WORK/selected-inputs.json" \
  --max-fee 0.001 --out "$WORK/helper-consolidate-plan.json"
```

Display a saved plan without sending:

```bash
python3 "$HELPER" --cli "$CLI" submit \
  --plan "$WORK/helper-split-plan.json" \
  --journal "$WORK/helper-split-journal.json"
```

Only after review, add `--execute` to that submit command to sign and broadcast. The helper records durable submission intent before calling Core, then records the acknowledgement. Existing plan and journal filenames are refused. If interrupted or uncertain, inspect the saved transaction ID; do not delete the journal to bypass this protection. There is no automatic retry/resume.

## 8. Optional bounded self-transfer runner

Use only after individual split, consolidation and restart checks pass. These are test self-transfers, not independent user adoption. They consume fees and can increase the network's UTXO storage burden.

Preview only:

```bash
python3 "$HELPER" --cli "$CLI" run \
  --address "$ADDRESS" --count 2 --amount 0.01 \
  --rounds 2 --max-fee 0.001 --total-fee-budget 0.002 \
  --journal "$WORK/two-round-journal.json"
```

Append `--execute` to authorize actual rounds. The preview shows one candidate plan; it does not precompute or reserve every round. During execution, subsequent plans are prepared automatically under your supplied parameters and budget. Automatic selection can select other wallet coins; the runner does not guarantee reuse of the previous round's outputs.

The runner waits until inventory observes an eligible confirmed output from the submitted transaction before continuing. It checks again after each inventory call and a 10-second sleep; a slow inventory makes polling slower. It also waits after the final round. This observation is not irreversible finality.

Limits: 1–20 rounds; `rounds * max_fee` must not exceed the total budget; explicit `--inputs` is allowed for one round only. `--confirmation-timeout` defaults to 1,800 seconds (allowed 30–86,400); an in-progress RPC can extend wall-clock time beyond that deadline. Failures or uncertain acknowledgements stop execution without automatic resubmission. Keep the journal.

## Troubleshooting

| Result | Meaning / next step |
|---|---|
| `Unknown command` / missing `utxo` help | Check the CLI path and rebuild the patched CLI. |
| RPC method missing | Verify the running Core binary, not just the source VERSION. |
| `could not reach node` | Check listener/process and a lightweight RPC. A read timeout can produce this message; use 120 seconds for UTXO reads and inspect load if still slow. |
| Wallet sends disabled | Set the existing send gate in the Core configuration/process; restart if needed. |
| Wallet locked/private-access refusal | Unlock through existing wallet controls; never paste secrets into the helper. |
| Input missing/unavailable | It may be spent, pending, reserved, immature or excluded. Inspect inventory and prepare a fresh plan. |
| Preview changed/edited | Recreate and review a fresh plan; do not force submission. |
| Existing plan/journal file | Preserve it; investigate any pending transaction before using fresh filenames for a genuinely new operation. |
| Fee cap exceeded/insufficient funds | Review input values, dust, size and the full fee reserve; adjust deliberately. |
| Too many addresses/UTXOs | R2's bounded inventory refuses this wallet size; there is no pagination switch. |
| Timeout during submit | Outcome unknown. Look up the reviewed txid and journal before any further send. |

## Validation and rollback

The R2 focused suite covers reversible source installation, CLI transport, transaction construction/signature handling with simulated chain/wallet objects, and Python helper safeguards. Full Core build, actual wallet signing, confirmed split/consolidation, restart persistence, ordinary-payment regression checks and independent-node acceptance must be established on the release build. Inventory/preview success alone does not establish all these results.

The patch is reversible at the source level using its printed backup path:

```bash
python3 "$PATCH/install.py" revert --root "$ROOT" \
  --backup "REPLACE_WITH_PRINTED_SOURCE_BACKUP_PATH"
```

Stop the affected node before replacing binaries; rebuild the reverted source or restore retained prior binaries. Source reversal cannot undo accepted transactions or refund fees. Newly created outputs remain ordinary existing-format UTXOs.

---

# Read endpoint settings from configuration

```bash
./tru-cli -conf=/path/to/tru.conf getinfo
```

The configuration may provide node/RPC endpoint settings such as the RPC host and port.

Authentication is still supplied through the private Patch-05 credential mechanism.

---

# Raw JSON-RPC passthrough

Friendly wrappers cover common operations. `raw` can call any RPC method exposed by the node to the authenticated operator:

```bash
./tru-cli raw getblocktemplate
./tru-cli raw gettokenmetadata '{"tokenID":"example"}'
./tru-cli raw listunspent '{"address":"<TRU_ADDRESS>"}'
./tru-cli raw verifytokenbalance '{"address":"<TRU_ADDRESS>","tokenID":"example"}'
```

Raw access is privileged. Availability through `tru-cli raw` does not mean a method is safe for a public website.

---

# DID RPC note

TRU's signed DID registration flow includes:

```text
getDIDMapping
registerDIDSigned
```

The public web-wallet path uses signed registration while keeping the user's private key in the browser.

The legacy `createDID` RPC is not a public browser method and remains outside the public web-wallet gateway.

---

# Remote node administration

Core RPC defaults to loopback and should normally remain private.

A non-loopback RPC bind requires explicit operator opt-in:

```ini
[network]
rpcAllowRemote=1
```

Remote RPC also requires the Patch-05 transport credential and should be protected by host/network controls. Do not publish the privileged RPC listener to the open Internet merely because authentication exists.

Use placeholders in public documentation:

```bash
./tru-cli -rpcconnect=<PRIVATE_NODE_IP> -rpcport=21832 getinfo
```

Public websites should use the restricted server-side TRU web gateway rather than connecting browser JavaScript directly to Core `/rpc`.

---

# Options

| Option | Meaning | Default |
|---|---|---|
| `-rpcconnect=<ip>` | node RPC IP/host | `127.0.0.1` |
| `-rpcport=<port>` | node RPC port | `21832` |
| `-conf=<file>` | read endpoint settings from a TRU config file | — |
| `-json` | print raw JSON result instead of summary output | off |
| `-timeout=<sec>` | read timeout | `30` |
| `-h`, `--help` | show command help | — |

RPC authentication is not disabled by these options.

---

# Friendly commands → RPC methods

| `tru-cli` command | Node method |
|---|---|
| `getinfo` | `getinfo` |
| `getbalance [address]` | `getbalance` |
| `getblockcount` | `getblockcount` |
| `getchaininfo` | `getchaininfo` |
| `getbestblockhash` | `getchaininfo` → best hash |
| `getdifficulty` | `getchaininfo` → difficulty |
| `getpeerinfo` | `getpeerinfo` |
| `getconnectioncount` | `getpeerinfo` → count |
| `getnewaddress` | `getnewaddress` |
| `listaddresses` | `listaddresses` |
| `listunspent <addr>` | `listunspent` |
| `listtransactions <addr>` | `listtransactions` |
| `getblock <hash>` | `getblock` |
| `getblockbyheight <h>` | `getblockbyheight` |
| `gettransaction <txid>` | `gettransaction` |
| `getrawmempool` | `getrawmempool` |
| `getmininginfo` | `getminerstatus` |
| `gettokenmetadata <id>` | `gettokenmetadata` |
| `verifytokenbalance <addr> <id>` | `verifytokenbalance` |
| `utxo list` | `walletutxotools`, action `list` |
| `utxo prepare JSON` | `walletutxotools`, action `prepare` |
| `utxo submit JSON` | `walletutxotools`, action `submit` |
| `raw <method> [json]` | authenticated raw RPC passthrough |

---

# Exit codes

- `0` — success
- `1` — transport/authentication/response error
- `2` — RPC or argument error

Example:

```bash
./tru-cli getblockcount || echo "node unavailable or RPC call failed"
```

---

# Security notes

- Privileged Core `/rpc` requires Patch-05 Bearer/cookie authentication.
- Direct browser access to privileged Core RPC is intentionally forbidden.
- Core RPC defaults to `127.0.0.1:21832`.
- Non-loopback RPC requires explicit `rpcAllowRemote=1`.
- The RPC credential must never be exposed in browser JavaScript.
- Public websites should use TRU's restricted server-side gateway.
- Native miners and `tru-cli` automatically support the private RPC cookie.
- Do not commit `.rpc-cookie*`, environment secrets, WIFs, wallet seeds, or private configuration files to source control.
- `getbalance` is TRU coin balance; token balances are separate.
- `getinfo` currently reports the node's aggregate status and wallet-facing summary fields exposed by the implementation.

---

## Release status

This document retains the authenticated RPC and signed-DID guidance and adds UTXO-TOOLS-01 R2 usage for Core 0.08.9. The UTXO tools require patched Core and CLI binaries. This documentation is not a claim that every release integration test has passed.
