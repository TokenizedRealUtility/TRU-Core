# TRU-AGENT-03: bounded automatic checkpoints and provider adapters

Core stays **0.07.8**. Optional Python runtime becomes **0.3.0**.

This package follows TRU_AGENT_CHECKPOINT_02_PINNED and supports its exact NEW_TRU and cleaned TRU-Core profiles. It adds provider adapters and a Linux-only, private local checkpoint inbox. Nothing is enabled or submitted by installation. CMake and consensus rules are unchanged; existing V5 records and the existing anchor transaction format are reused.

Read `TEST_RESULTS.md` before deployment. This is an experimental patch with offline and focused C++ validation, not a claim of a completed full-node or live unattended-spending acceptance test.

## What changes

- `tru.conf` selects whether Core accepts automatic checkpoint requests and which private policy file to read.
- Each policy binds the mainnet genesis, actual NCFT token ID, original issuer, issuance TXID, approved manifest hash, and separate HMAC submission credential.
- Human-readable name and optional DID are labels. A supplied DID must match the issuance metadata's `meta_id`; this is not an independent DID-registry or DID-controller verification.
- Core reconstructs the exact V5 record, verifies prior history and confirmed anchor payloads, and uses the already unlocked encrypted issuer wallet. The runtime never receives a wallet key.
- Core atomically persists the evolution, queue entry, and reserved allowance. Replays cannot consume a second epoch; failed or ambiguous writes are retried as the same request.
- Runtime scheduling creates a checkpoint only after an explicit memory revision changes. It keeps one pending request and verifies confirmation before advancing to another.
- Chat supports Nemotron, OpenAI, Grok, Claude, Ollama native chat, and custom OpenAI-compatible chat-completions servers. Arbitrary API protocols or every provider-specific model feature are not supported.

This does not enable AI-authored memories or tool execution. Humans still save explicit memories. The scheduler automates anchoring those saved changes. Provider selection does not grant authority.

## 1. Install on both repositories

Exit agent chat and stop any existing agent watcher before upgrading. Keep your normal Core data/wallet backups. Extract the ZIP into a fresh package directory:

```bash
mkdir -p "$HOME/agent-tools"
unzip -n "$HOME/Downloads/TRU_AGENT_AUTO_03_PINNED.zip" -d "$HOME/agent-tools"
cd "$HOME/agent-tools/TRU_AGENT_AUTO_03_PINNED"

python3 install.py check --root "$HOME/NEW_TRU"
python3 install.py apply --root "$HOME/NEW_TRU"

python3 install.py check --root "$HOME/TRU-Core"
python3 install.py apply --root "$HOME/TRU-Core"
```

Run each `apply` only after that repository's `check` passes. A missing/drifted-file report names the paths; preserve it and rebase against the actual files. Do not force a match or fabricate test documents. Save the printed backup path.

```bash
cd "$HOME/NEW_TRU"
cmake --build build-native --target tru_advanced tru-cli -j4
python3 tools/agent-runtime/selftest.py
python3 tools/agent-runtime/selftest_anchor.py
python3 tools/agent-runtime/selftest_auto.py
```

Expected Python results: **12 + 5 + 12 tests pass**. They do not contact paid providers or mainnet. Use the actual build directory if yours differs. Build TRU-Core separately if you run its binaries; updating its source does not upgrade a running NEW_TRU process.

Restart the rebuilt Core through your normal clean shutdown/start procedure, preserving its working directory, data directory, and options. Start with automation disabled. Never run two nodes against the same data directory.

## 2. Select an existing agent runtime

Generic settings (edit for your agent):

```bash
export TRU_AGENT_CODE="$HOME/TRU-Core/tools/agent-runtime/tru_agent.py"
export TRU_AGENT_HOME="$HOME/tru-agents/my-agent/runtime"
export TRU_CORE_CLI="$HOME/NEW_TRU/build-native/bin/tru-cli"

tru_agent() {
  python3 "$TRU_AGENT_CODE" --home "$TRU_AGENT_HOME" "$@"
}
tru_agent status
```

For AXONA's already initialized runtime, use:

```bash
export TRU_AGENT_HOME="$HOME/axona/runtime-v01"
tru_agent status
```

Do **not** run `init` again. The existing database, manifest snapshot, memories, and checkpoints remain valid. New agents follow `AGENT_GUIDE.md` through a first confirmed manual memory checkpoint before using automation.

Functions and exports belong in the Linux shell, not at the chat `You:` prompt. Redefine them in a new terminal or put your chosen definitions in your own shell profile.

## 3. Keep Nemotron or configure another provider

Existing Nemotron configuration needs no change. To set it explicitly:

```bash
tru_agent provider-set --provider nemotron \
  --endpoint http://127.0.0.1:5051/v1/chat/completions --model nemotron
```

For other providers, use a model ID actually enabled for your service/account:

| Adapter | Endpoint | API-key environment variable |
|---|---|---|
| `openai` | `https://api.openai.com/v1/chat/completions` | `OPENAI_API_KEY` |
| `grok` | `https://api.x.ai/v1/chat/completions` | `XAI_API_KEY` |
| `claude` | `https://api.anthropic.com/v1/messages` | `ANTHROPIC_API_KEY` |
| `ollama` | `http://127.0.0.1:11434/api/chat` | None by default |
| `nemotron` | `http://127.0.0.1:5051/v1/chat/completions` | `NEMOTRON_API_KEY` if required |
| `custom` | Your full chat-completions URL | `TRU_AGENT_API_KEY` if required |

Example for OpenAI:

```bash
read -r -s -p 'OpenAI API key: ' OPENAI_API_KEY
printf '\n'
export OPENAI_API_KEY
read -r -p 'Your supported model ID: ' AGENT_MODEL
tru_agent provider-set --provider openai --model "$AGENT_MODEL" --allow-remote
tru_agent ask 'Introduce yourself briefly and explain your limitations.'
```

Grok and Claude use the same `provider-set` structure with `--provider grok` or `--provider claude`, their own supported model ID, and their corresponding environment key. API access/billing is separate from consumer chat subscriptions.

Ollama:

```bash
read -r -p 'Your installed Ollama model name: ' AGENT_MODEL
tru_agent provider-set --provider ollama --model "$AGENT_MODEL"
tru_agent ask 'What facts have I explicitly saved?'
```

A custom chat-completions endpoint:

```bash
read -r -p 'Full HTTPS chat-completions URL: ' AGENT_ENDPOINT
read -r -p 'Model ID: ' AGENT_MODEL
tru_agent provider-set --provider custom --endpoint "$AGENT_ENDPOINT" \
  --model "$AGENT_MODEL" --api-key-env TRU_AGENT_API_KEY --allow-remote
```

Remote inference sends the prompt, saved memories, and recent conversation to that provider. `--allow-remote` explicitly authorizes this configuration; omit it for loopback-only services. Remote HTTP is refused; use HTTPS. Redirects and inherited HTTP proxies are disabled. Keys stay in environment variables and are not written into configuration. Protect that process environment and avoid logging secrets.

Switching provider leaves memory, historical checkpoints, and the identity snapshot intact. It does not rewrite on-chain `ai_engine` metadata. This text-only prototype does not pass tool calls through to execution. Model-specific unsupported parameters/context limits still require choosing a compatible model. Failed/empty responses do not become completed chat turns.

Provider API references reviewed for the adapters:

- https://developers.openai.com/api/reference/resources/chat
- https://docs.x.ai/developers/rest-api-reference/inference/chat-completions
- https://platform.claude.com/docs/en/api/messages/create
- https://docs.ollama.com/api/chat

## 4. Prepare a disabled finite policy

Prerequisite: your exact latest memory checkpoint already passes `anchor-verify`. Its epoch must be the latest evolution. Use its actual local file:

```bash
read -r -p 'Full path of latest confirmed checkpoint: ' CHECKPOINT_FILE
tru_agent anchor-verify "$CHECKPOINT_FILE" --core-cli "$TRU_CORE_CLI"

tru_agent auto-prepare --checkpoint "$CHECKPOINT_FILE" \
  --core-cli "$TRU_CORE_CLI" \
  --policy-dir "$HOME/tru-agent-policies/my-agent" \
  --min-interval 3600 --max-per-day 4 \
  --budget-atoms 10000 --expires-days 7
```

For AXONA, use your existing checkpoint and its own directory:

```bash
export CHECKPOINT_FILE="$HOME/axona/runtime-v01/checkpoints/c6fff5ff65cd4333f1936e07ec8aa74343918af3f32cf71aae7477071cdc5be5.json"

tru_agent auto-prepare --checkpoint "$CHECKPOINT_FILE" \
  --core-cli "$TRU_CORE_CLI" \
  --policy-dir "$HOME/tru-agent-policies/axona" \
  --did did:on_tru:82e9bc6aa3b2eab3 \
  --min-interval 3600 --max-per-day 4 \
  --budget-atoms 10000 --expires-days 7
```

Run one applicable preparation command, not both. The command refuses to overwrite an existing setup. If the original checkpoint is no longer the latest epoch, use the latest confirmed checkpoint instead.

It writes a private credential, inbox, disabled `policy.json`, and local recovery state. It prints `POLICY_FILE`. No secret is printed. The policy contains your token and issuer pins, label/DID, baseline epoch, expiry, interval, per-day limit, fixed 1000-atom fee cap, and total allowance.

These example limits authorize at most ten 1000-atom checkpoint fees over the life of the allowance, at most four approvals per UTC calendar day, and at least an hour between approvals. They are approval/fee reservations, not a refunding balance: a queued or stalled anchor retains its reserved allowance. The first new approval need not wait an hour after the older manual baseline.

The budget ledger is per token in Core data and survives configuration reload and process restart. Renaming the label/DID or rotating the submission credential does not reset usage. Raising the total budget sets a new lifetime ceiling, not a fresh allowance. Restoring old Core data can restore an older ledger; disable automation and reconcile usage before enabling a restored node.

## 5. Point Core at the policy in tru.conf

Edit the **actual `tru.conf` selected by your running node**, which may be relative to its working directory or selected with `--conf`. Use a full absolute path; this parser does not expand `$HOME` or `~`.

For AXONA on the shown host:

```ini
[agent_checkpoint]
enabled=1
policy_file=/home/gw878/tru-agent-policies/axona/policy.json
```

For another agent, substitute the `POLICY_FILE` printed by preparation. Do not duplicate the section or keys. The only supported section keys are `enabled` and `policy_file`; all per-agent limits live in the referenced JSON file.

Alternatively, export these in the environment of the process that starts Core:

```bash
export TRU_AGENT_CHECKPOINT_ENABLE=1
export TRU_AGENT_CHECKPOINT_POLICY_FILE="$HOME/tru-agent-policies/axona/policy.json"
```

Explicit config values take precedence over environment values. Exporting in another terminal does not change an already running process. Restart Core after changing this startup configuration. The JSON policy itself is re-read at most once per 30-second worker poll and can be paused without restarting.

At this point the generated JSON still has both enable flags false, so no request is approved. Keep it that way until the build/restart and policy review succeed.

## 6. Review and explicitly enable the bounded policy

Use your actual printed path:

```bash
export AGENT_POLICY_FILE="$HOME/tru-agent-policies/axona/policy.json"
python3 -m json.tool "$AGENT_POLICY_FILE"
```

Review the token, issuance, original issuer, approved manifest, interval, daily cap, expiry, and total budget. This is the authorization for future unattended checkpoint fees. Only after that review, enable the policy using the following command. It enables the single generated agent; multi-agent operators must select their intended entries individually.

```bash
python3 - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(os.environ['TRU_AGENT_CODE']).parent))
import tru_agent as rt
from tru_agent_auto import replace_private
p = Path(os.environ['AGENT_POLICY_FILE'])
rt.safe_file(p)
v = json.loads(p.read_text())
if len(v['agents']) != 1:
    raise SystemExit('This helper is for one reviewed agent only.')
v['enabled'] = True
v['agents'][0]['enabled'] = True
replace_private(rt, p, rt.canonical(v))
print('BOUNDED_POLICY_ENABLED')
PY
```

Keep the encrypted Core wallet unlocked through your existing authenticated workflow. This patch does not store a passphrase or unlock the wallet. The original issuer must be available in that wallet, and the existing oracle funding path must have funds. Locked/unavailable wallets defer approval.

## 7. Supervised first automatic checkpoint

Save a meaningful new memory and exit chat, or use the shell command:

```bash
tru_agent remember 'Automatic checkpoint testing is enabled under a finite issuer-approved policy.'
tru_agent auto-step --core-cli "$TRU_CORE_CLI"
```

Expected initial output includes `AUTO_REQUEST_EXPORTED`. This is a request, not a confirmed anchor. Within the worker polling interval, inspect the node log for:

```text
[TRU-AGENT-03] approved token=... checkpoint=... reserved_atoms=1000
```

Or it will log `deferred` with a reason (locked wallet, interval, budget, missing confirmation, identity mismatch, etc.). The existing anchor worker handles preparation/broadcast/recovery after approval.

After mining, repeat:

```bash
tru_agent auto-step --core-cli "$TRU_CORE_CLI"
```

Expected completion includes `CHECKPOINT_ANCHOR_CONFIRMED=YES`, `ISSUER_AUTHORIZATION=VERIFIED`, a receipt path, and `AUTO_CHECKPOINT_COMPLETE`. A pending or invalid result does not advance the completed revision. Inspect persistent errors rather than manually creating a replacement request.

`auto-state.json` retains the exact pending checkpoint path. `auto-pending-request.json` retains its authenticated public envelope. Crash recovery republishes the same envelope, so a restart after persistence but before the acknowledgement cannot authorize another copy.

If manual evolution advances the token while a different checkpoint is pending, preserve outputs and investigate. Do not edit revisions, delete history, or repeatedly COMMIT to clear a conflict.

## 8. Start the repeating watcher

After the supervised test succeeds:

```bash
tru_agent auto-watch --core-cli "$TRU_CORE_CLI" --interval 60
```

Run this in a separate screen/session. It invokes a fresh `auto-step` process each minute. While an interactive agent chat holds the runtime lock, the watcher defers; it does not bypass locking. Exit chat to let it snapshot memory. Unchanged memory causes no new checkpoint and no fee.

Ctrl+C stops the watcher. It does not revoke the Core policy or retract a request already exported. For a persistent user service, use the supplied `tru-agent-auto@.service` and follow `SERVICE.md` after the supervised test.

The watcher needs the Core CLI for read-only confirmation and a local submission credential for the private inbox. It does not need the provider's API key and never calls a model while anchoring. The configured CLI still operates under your normal trusted local Core credentials; this prototype is not OS sandbox isolation from your own user account.

## Pause, revoke, and recovery

To stop **new automatic approvals**, set the policy document's root `enabled` to `false` using an atomic replacement, or set the individual agent's flag false. The worker notices at its next poll and rechecks the policy before committing. Stop the watcher as well if you want no new requests prepared.

```bash
python3 - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(os.environ['TRU_AGENT_CODE']).parent))
import tru_agent as rt
from tru_agent_auto import replace_private
p = Path(os.environ['AGENT_POLICY_FILE']); rt.safe_file(p)
v = json.loads(p.read_text()); v['enabled'] = False
replace_private(rt, p, rt.canonical(v))
print('NEW_AUTO_APPROVALS_DISABLED')
PY
```

**Already committed/queued/signed anchors continue through the existing queue.** Revocation cannot retract a transaction already broadcast. Budget is reserved at approval and never automatically refunded. Expiry also blocks new approvals, not completion of previously approved work.

Deleting or editing the ledger is not a reset mechanism. Missing ledger with an advanced epoch fails closed against the pinned baseline. A stale baseline after manual evolution requires deliberate operator review before changing that baseline; an existing ledger is always retained.

Keep the full runtime, policy/credential files, and Core off-chain evolution database in private consistent backups. Receipt verification is point-in-time; re-run `anchor-verify` if chain state changes. Core rechecks every prior anchor before approving another checkpoint. It cannot restore lost private memories from a digest.

## Multiple agents and security boundary

The policy document accepts up to 32 entries in `agents`, one per token. Combine separately generated entries into the one configured policy document, retaining each agent's own inbox, credential, baseline, and limits. Point each runtime's `auto-config.json` `policy_file` at that aggregate file before enabling it. Duplicate token policies are rejected; every policy must validate before processing begins. Never share one inbox or credential between agents.

Only one Core data instance should execute a given policy. Two independent node databases do not share an allowance ledger. Core trusts the operating-system account that controls its private policy files. This same-account prototype prevents accidental/general wallet calls and authenticates request bytes; it is not protection against malicious code already running as that OS user or root. Untrusted agents require separate accounts and a separately designed privileged broker.

Name and DID are labels, not bearer permissions. A DID that matches issuance metadata still does not prove control of a DID document. Authorization derives from the token/issuance pins, private request credential, configured limits, and the verified original issuer signature. Current ownership alone does not replace the existing original-issuer policy.

## Rollback

Disable policies and stop watchers first; stop Core before changing source. Use the printed source backup:

```bash
python3 install.py rollback --root "$HOME/NEW_TRU" \
  --backup /absolute/path/to/printed/backup
```

Rebuild and restart. This restores code, not private runtime files, checkpoint history, or Core budget state. Agent02 understands the V5 records created by this patch. If you configured a remote provider, switch back to a supported local Nemotron endpoint before reverting to runtime 0.2.0. Keep the automation state/ledger for future reconciliation.

Publish only code, documentation, and tests. Never commit policy credentials, private runtime directories, receipts, wallet files, or patch backups.
