# TRU Agent Runtime — experimental v0.3.0

Reusable local chat, explicit persistent memory, and private checkpoint preparation for TRU NCFT agent identities. Each agent gets its name and token identity from its own manifest and its own private runtime directory. Do not copy or rename the Python program for each agent.

This optional standalone tool uses Python 3.10+ on Linux and the standard library. It does not require CMake integration, rebuild Core, or change consensus. It requires a configured inference service. Existing loopback Nemotron configurations remain supported; remote providers require explicit opt-in. The shipped model default `nemotron` matches the reviewed Core provider integration; supply the alias your service actually accepts.

## What is included

- `tru_agent.py`: generic CLI; `--home` is mandatory.
- `selftest.py`: 12 offline tests using temporary storage and a fake loopback provider.
- `.gitignore`: ignores common private runtime files and Python bytecode in this directory.
- This README and `TEST_RESULTS.md`.

Store private data outside your source repository. The program refuses homes inside a Git checkout or a Core source tree. The ignore rules are an extra precaution, not a substitute for keeping private data outside Git.

## 1. Verify the installation

From your Core source root:

```bash
python3 tools/agent-runtime/tru_agent.py --help
python3 tools/agent-runtime/selftest.py
```

Expected: 12 tests pass. Tests do not use Core RPC, a real model, a wallet, or mainnet.

If you cloned a repository that already includes this directory, the scripts are already installed. No installer, pip dependencies, or build is needed.

## 2. Prepare the agent identity

Create and confirm the NCFT using your existing Core token creation workflow (reviewed menu: **13 → 4 — NCFT**). Record the actual short token ID, issuance TXID and issuing address. This tool does not create tokens or verify current blockchain ownership.

Prepare a private `TRU_AGENT_MANIFEST_V1` JSON manifest using your agent creation workflow. The required identity fields are:

| Field | Value |
|---|---|
| `schema` | `TRU_AGENT_MANIFEST_V1` |
| `name` | Your agent's display name |
| `token_id` | Actual 16-character lowercase hexadecimal token ID |
| `issuance_txid` | Actual 64-character lowercase hexadecimal issuance TXID |
| `issuing_address` | Original issuing address |
| `network_genesis` | Reviewed TRU mainnet identifier below |
| `avatar_url` | Real plain HTTPS image URL, without Markdown |

Mainnet identifier:

```text
b62fba2600030d97a06916b17694bec8d97ca14c1db682b2e57b424bd6000000
```

Other fields in an existing manifest are preserved in the snapshot. Keep the manifest file private (mode 600) and its directory mode 700. Existing manifests from the NCFT creation guide work, including later content revisions with the same schema name. Use real identifiers; passing these format checks is not blockchain verification.

## 3. Select locations for this agent

Edit the examples for your machine and your new agent. Use absolute paths:

```bash
export TRU_AGENT_CODE="$HOME/TRU-Core/tools/agent-runtime/tru_agent.py"
export TRU_AGENT_HOME="$HOME/tru-agents/my-agent/runtime"
export TRU_AGENT_MANIFEST="$HOME/tru-agents/my-agent/manifest-v1.json"
```

The code can instead live in NEW_TRU. Private storage must remain outside both repositories. Do not place it under `tools/agent-runtime`.

For every additional agent, select a different home and that agent's own manifest. Each directory has independent memories, chat context, identity snapshot, configuration, and checkpoints.

## 4. Initialize once

```bash
umask 077
python3 "$TRU_AGENT_CODE" --home "$TRU_AGENT_HOME" init \
  --manifest "$TRU_AGENT_MANIFEST" \
  --endpoint http://127.0.0.1:5051/v1/chat/completions \
  --model nemotron
```

Initialization snapshots the manifest and creates `config.json` and `state.sqlite3`. It refuses to replace an initialized runtime. It does not modify the source manifest, import an older `memory/current.json`, or update NCFT metadata.

The original Nemotron endpoint uses loopback HTTP with an explicit port and `/v1/chat/completions`. Version 0.3.0 additionally provides OpenAI, Grok, Claude, Ollama, and custom chat-completions adapters through `provider-set`; see AUTO_PROVIDERS.md. Remote endpoints require HTTPS and explicit `--allow-remote`. Redirects and environment HTTP proxies are disabled. There is no server component or public listening port in this runtime.

If the provider needs authentication:

```bash
read -r -s -p 'Provider API key: ' NEMOTRON_API_KEY
printf '\n'
export NEMOTRON_API_KEY
```

Skip this if your existing trusted loopback service requires no key. The API key is not stored in runtime files. The model alias and endpoint are explicit initialization settings; exporting Core's endpoint variable does not override this runtime's saved config.

## 5. Start chat and save a memory

Define a convenience command in your current shell:

```bash
tru_agent() {
  python3 "$TRU_AGENT_CODE" --home "$TRU_AGENT_HOME" "$@"
}
tru_agent status
tru_agent chat
```

At `You:`, try:

```text
Hello. Explain what this local prototype can do.
/remember My runtime restart test phrase is copper moon 37.
/memories
What is my runtime restart test phrase?
/exit
```

Only `/remember TEXT` or `remember TEXT` saves explicit memory. Ordinary chat alone does not. The assistant cannot execute commands or promote its replies to saved facts. Prompts, all explicit memories, and recent chat history go to the configured local provider. The provider's own deployment determines whether it forwards data elsewhere or logs it.

## 6. Verify restart persistence and recall

From the Linux shell:

```bash
tru_agent memories
tru_agent clear-chat
tru_agent chat
```

Ask without supplying the answer:

```text
What is my runtime restart test phrase?
```

The expected phrase is `copper moon 37`. Separate these two checks:

1. `memories` in a new process shows the saved fact: durable storage passed.
2. The model answers correctly after clearing chat: model recall from supplied memory passed.

If only the first passes, report a model recall failure rather than a storage failure. No training or model weight update occurs; saved memory is included in subsequent requests.

Exit with `/exit`. Each chat invocation is a new process; there is no daemon to restart. Keep only one process per agent home active. Different agents can run concurrently, subject to provider capacity.

## 7. Prepare and inspect a checkpoint

```bash
tru_agent checkpoint
read -r -p 'Paste CHECKPOINT_FILE path: ' CHECKPOINT_FILE
python3 -m json.tool "$CHECKPOINT_FILE"
tru_agent verify-checkpoint "$CHECKPOINT_FILE"
```

A checkpoint contains explicit memories, token identity, manifest digest, memory revision, creation time, and a random nonce. It excludes chat transcripts and API keys. Its filename is the SHA-256 of the exact file bytes. Keep it immutable and private.

Expected verification:

```text
LOCAL_CHECKPOINT_INTEGRITY=PASS; ONCHAIN_VERIFICATION=NOT_PERFORMED
```

This is local integrity verification, not proof of authority, truth, or on-chain provenance. With Core 0.07.8 checkpoint integration installed, use the manual handoff below to approve and verify this exact digest. Do not paste private memory JSON into AI evolution prompts or treat an AI-written checkpoint claim as an exact commitment.

## Commands

```bash
tru_agent status
tru_agent memories
tru_agent remember 'A fact I explicitly want retained.'
tru_agent ask 'What facts have I saved?'
tru_agent forget 1
tru_agent clear-chat
tru_agent checkpoint
```

Inside chat: `/remember TEXT`, `/memories`, `/forget ID`, `/checkpoint`, `/exit`.

`forget` removes an explicit fact from future memory lists. Old conversations, checkpoints, provider logs, and backups may still contain it. Clear chat context separately if needed. Neither command guarantees forensic erasure.

Limits: 50 explicit facts, 500 characters per fact, 4,000 characters per prompt, 512 requested output tokens. The database retains 200 chat messages; the last 12 are included with all explicit memories. A smaller model context may need shorter or fewer memories.

## Storage, backups and authorization

Runtime directories are private mode 700 and files mode 600. Storage is **plaintext, not encrypted**. Access is controlled by the Linux account, not by a wallet signature or a web login. Do not enter wallet secrets into chat or memory. Do not publish runtime directories.

Exit chat and all commands before backing up the entire runtime directory with your usual private, preferably encrypted backup process. Do not copy only a live SQLite database while another process is writing. Restore into a separate private directory and point `--home` there; preserve the complete set of files.

The runtime does not independently confirm issuance, current ownership, issuer authority, transfers, or evolution status. Its manifest snapshot records the identity you configured. The runtime itself has no wallet keys, signing, spending or autonomous tools. Core can perform the separately approved checkpoint evolution through the handoff below; unattended anchoring is disabled until the operator explicitly enables a finite Core policy and runs the separate scheduler.

## Existing experimental runtimes

The earlier AXONA runtime database/config format is compatible with this generic runner. After exiting the old process, point this script's `--home` at the existing private runtime directory and run `status`. Do not reinitialize or copy just the database. No agent-specific script rename or code fork is needed.

## Troubleshooting

- `--home` missing: pass the full private runtime path before the subcommand.
- Repository refusal: move the intended new runtime location outside source trees; preserve existing data before any deliberate migration.
- Already initialized: use `status` or `chat`, not another `init`.
- HTTP 401/403: check your provider's authentication and environment key.
- HTTP 400/404: check the model alias and chat-completions endpoint against the service configuration.
- Connection refused: start/configure your local inference service separately.
- Timeout/provider error: no partial chat turn is saved; previously committed memories remain. No automatic retry occurs.
- Busy runtime: exit the other process. Do not delete its lock file to bypass locking.
- Permission refusal: inspect the named path. Use mode 700 for private directories and 600 for owned files, without changing unrelated trees.
- Identity mismatch: do not silently edit the identity snapshot or its digest. Preserve it for review.

## Publishing with TRU-Core

Commit only this directory's software, tests, documentation, and `.gitignore`. The installer does not edit root ignore rules, modify CMake, stage Git files, or push commits. Existing root ignore rules may require review before adding the intended software files.

This is an experimental optional tool. Real-provider recall and any future chain adapter require separate validation. The package does not grant a new license for unrelated TRU-Core code; retain the repository's licensing policy when publishing.

## Core 0.07.8 checkpoint integration

The optional Core checkpoint patch adds two commands. Exit chat first:

```bash
python3 "$TRU_AGENT_CODE" --home "$TRU_AGENT_HOME" anchor-request /absolute/path/to/checkpoint.json
python3 "$TRU_AGENT_CODE" --home "$TRU_AGENT_HOME" anchor-verify /absolute/path/to/checkpoint.json \
  --core-cli "$HOME/NEW_TRU/build-native/bin/tru-cli"
```

The first command validates the immutable local checkpoint and exports seven public commitment fields, with no memory contents. In patched Core use **17 → 2 → 7** to import the printed request file. Review the token, hash, revision, and 1000-atom anchor fee; choose **2**, confirm the exact checkpoint hash, then type **COMMIT**. A prior confirmed ordinary evolution is required. Each later checkpoint must advance the memory revision.

Core signs the exact record under its existing issuer policy and automatically queues/submits/recovers the anchor using its existing oracle funding wallet. The runtime receives no private keys and makes no signing or submission RPC. Local status does not infer whether Core currently permits automatic approval; inspect the Core policy and watcher. Version 0.3.0 adds optional `auto-prepare`, `auto-step`, and `auto-watch` with Core-enforced policy budgets. Manual handoff remains available. See AUTO_PROVIDERS.md.

The second command calls the configured Core's read-only `verifytokenevolution`, checks the exact V5 descriptor, issuer proof, issuance identity, and confirmed payload, then writes a local receipt. It does not independently verify headers or attest the remote node. An error or pending response never produces a confirmed receipt. Repeating request export is idempotent; repeating verification checks current chain state and saves a fresh receipt. Never repeat a Core COMMIT merely because a command timed out.

Private runtime data stays outside Git. Preserve checkpoint bytes, identity snapshot, off-chain evolution records, chain data, and wallet backups. An on-chain digest alone does not preserve the private file or off-chain record.

Run `python3 tools/agent-runtime/selftest_anchor.py` for five additional offline checks.


## Version 0.3.0

Read [AUTO_PROVIDERS.md](AUTO_PROVIDERS.md) for provider configuration, the exact-source Core patch, and opt-in automatic checkpoint setup. The automation scheduler never calls a model or stores wallet keys. Existing memories and identity snapshots remain unchanged.
