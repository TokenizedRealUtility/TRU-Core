# TRU DataFeed — 0.08.1 release candidate

Publish small observations or commitments to batches of observations, then retrieve and verify them through your own TRU node. Examples use HAM radio/AIS reception and weather sensors. DataFeed is a Python companion to `tru-cli`, not a new `tru-cli datafeed` subcommand.

This candidate replaces the **unapplied TRU_DATAFEED_RPC_PERF_04** patch. Do not apply 04 before or after this package. It does not implement agent ownership handover.

## What is implemented

| Operation | Result |
|---|---|
| `queue` | Import JSON, JSONL, CSV or standard input into a local SQLite journal. No transaction. |
| `publish` | Preview a batch; with explicit `--broadcast`, ask Core to sign and submit one fee-bounded transaction. |
| `get` | Retrieve a unique DataFeed payload from known transaction outputs, including older TRUScript-wrapped records. |
| `verify` | Check active-chain confirmation and the batch hash; exits nonzero when incomplete or invalid. |
| `scan` | Discover feeds in an explicitly bounded block range. Reads actual transaction outputs. |
| `search` | Search/export the local discovery index. `--live` rechecks returned rows against Core. |
| `export-batch` | Save the exact ordered batch array needed to verify a hash commitment later. |
| `reconcile` | Inspect an uncertain publication; optionally associate a matching confirmed transaction with a new-format journal batch. Never rebroadcasts. |
| `watch` | Repeatedly preview queued data. **Does not automatically spend or publish.** |

The commitment is SHA-256 of the tool's canonical UTF-8 JSON **array**, including record order. It is not a Merkle tree. CSV imports preserve cell values as strings. A confirming block proves inclusion of the commitment, not whether the reported location, signal strength, temperature, or timestamp is true. Feed names are public labels; they do not establish an exclusive publisher identity.

## 1. Install the source patch

Requires Python 3.9+, an existing Core source/build setup, and the supplied exact source baseline. The installer does not change CMake, your chain database, wallet files, or publication journal.

```bash
unzip TRU_DATAFEED_05_DUAL_CORE_PINNED.zip
cd TRU_DATAFEED_05_DUAL_CORE_PINNED

python3 install.py check --tree NEW_TRU --root "$HOME/NEW_TRU"
python3 install.py check --tree TRU-Core --root "$HOME/TRU-Core"

python3 install.py apply --tree NEW_TRU --root "$HOME/NEW_TRU"
python3 install.py apply --tree TRU-Core --root "$HOME/TRU-Core"
```

Stop if a check reports drift. Do not bypass checks or copy older source over newer work. Both `--root` and `--core` are accepted.

Build using your existing configured build directory:

```bash
cd "$HOME/NEW_TRU"
cmake --build build-native --target tru_advanced tru-cli -j4
```

This package includes offline tests, but a full linked build and live two-node test were not performed in the patch workspace. Perform those release checks before publishing 0.08.1. Rebuild alone does not upgrade the running process; shut Core down normally and restart using your usual data directory and launch options. Do not delete or reinitialize chain data.

## 2. Enable explicit local wallet publication

In the `tru.conf` actually used by your running node, add to its **existing** `[network]` section:

```ini
[network]
TRU_RPC_WALLET_SEND_ENABLE=1
```

Do not create a duplicate section or replace the rest of your configuration. Core also accepts this existing setting through its process environment. Restart Core after changing it. This enables the existing local wallet-send opt-in; DataFeed still requires `--broadcast`, an owned address, and a per-transaction fee cap. Keep privileged wallet RPC private and authenticated. The public explorer proxy is not given a new spending method.

The loaded Core wallet must be unlocked when you choose to publish. Python never receives wallet private keys.

## 3. Set your local paths

Run these commands in a normal shell, not inside an AI chat prompt:

```bash
export DF="$HOME/NEW_TRU/tools/datafeed/tru_datafeed.py"
export TRUCLI="$HOME/NEW_TRU/build-native/bin/tru-cli"
export DF_DB="$HOME/.local/share/tru/datafeed-v1.sqlite3"
export DF_INDEX="$HOME/.local/share/tru/datafeed-v2-index.sqlite3"

df() {
  python3 "$DF" --cli "$TRUCLI" --db "$DF_DB" --index-db "$DF_INDEX" "$@"
}

"$TRUCLI" raw getdatafeedinfo '{}'
```

Expected capabilities include `format: TRU_DATAFEED_RPC_V1`, `max_payload_bytes: 254`, `fee_cap_enforced: true`, and `wallet_publish_enabled: true`. If publication is disabled, fix the node configuration before proceeding. Do not fall back to the old inscription RPC.

The `df` shell function lasts for that shell session; define it again in a new terminal, or save it in your shell configuration with your chosen paths.

## 4. Queue one HAM radio/AIS observation

Use a new test feed first, particularly if your old feed has unresolved `SUBMITTING` rows:

```bash
df queue --feed ham-demo-081 \
  --record '{"mmsi":366979030,"signalpower":-46.7371,"ppm":2.89352,"timestamp":"20261006072951"}'

df list --feed ham-demo-081
```

This only writes your local journal. No funds are spent.

Preview one inline observation:

```bash
df publish --feed ham-demo-081 --mode inline --batch-size 1
```

The **complete DataFeed payload must be at most 254 UTF-8 bytes**, so its OP_RETURN script fits the existing 257-byte relay limit. The old TRUScript wrapper could exceed this limit; the new compact path avoids that wrapper. An oversized inline batch is refused without truncation. Use hash mode or a smaller record when needed.

## 5. Publish deliberately

Choose a funded address belonging to the wallet loaded in Core. The address needs a mature, spendable ordinary coin UTXO; a token-control output cannot be used as the fee input. A balance at another address is not funding at the selected address.

```bash
"$TRUCLI" raw listaddresses '[]'
read -r -p 'Paste your funded Core-wallet address, then press Enter: ' DF_OWNER

df publish --feed ham-demo-081 --mode inline --batch-size 1 \
  --owner "$DF_OWNER" --max-fee-atoms 100000 --broadcast
```

`100000` atoms is a **maximum of 0.001 TRU**, not a requested fee. The existing wallet fee calculation is used and the actual fee is checked before signing. The supplied source has a 10000-atom base wallet fee. Insufficient funding, a low cap, or mempool policy can still refuse publication.

Save the printed `BATCH_ID` and `TXID`. `OBSERVED` means accepted by the local submission path, not mined. No mining or external message is triggered by this tool.

## 6. Retrieve and verify

Paste the printed transaction ID when prompted:

```bash
read -r -p 'Paste the publication TXID: ' DF_TXID

df get "$DF_TXID"
df verify "$DF_TXID"
df get "$DF_TXID" --output recovered-feed-record.json
```

After mining, expect `chain_confirmed: true`, `inline_hash_valid: true`, and `verified: true`. Before confirmation, `verify` exits nonzero. Wait and rerun the read-only command; do not publish again. `get` returns a report with the original inline observations in `records`.

The readback uses the transaction output bytes and Core's current chain classification, not a publisher-only metadata cache. This is verification through your trusted node, not an independent SPV proof. Reorgs can change confirmation status; recheck when it matters.

## 7. Batch files or continuous input

CSV example:

```bash
cat > observations.csv <<'CSV'
mmsi,signalpower,ppm,timestamp
366979030,-46.7371,2.89352,20261006072951
366979031,-43.1,1.7,20261006073012
CSV

df queue --feed ais-batches --file observations.csv
```

JSON array example:

```bash
cat > weather.json <<'JSON'
[
  {"station":"HAM-01","temperature_c":21.4,"humidity_percent":55},
  {"station":"HAM-01","temperature_c":21.6,"humidity_percent":54}
]
JSON

df queue --feed weather-demo --file weather.json
```

JSONL/stdin example:

```bash
printf '%s\n' '{"station":"HAM-01","temperature_c":22.1}' \
  '{"station":"HAM-01","temperature_c":22.2}' |
  df queue --feed weather-demo --stdin
```

You may pipe a receiver that emits one valid JSON object per line into `queue --stdin`. That queues observations only. For an endless stream, use finite input chunks: a queue invocation commits its import when input finishes. Timed automatic publishing and a continuously committing ingestion daemon are not implemented.

## 8. Hash mode and later verification

Hash mode keeps the source records off-chain and publishes a compact commitment:

```bash
df publish --feed ais-batches --mode hash --batch-size 100

df publish --feed ais-batches --mode hash --batch-size 100 \
  --owner "$DF_OWNER" --max-fee-atoms 100000 --broadcast

df batches --feed ais-batches
```

Use the actual printed batch ID, for example batch `2`:

```bash
df export-batch 2 --output ais-batch-2.json
```

Keep that file and your journal backed up. To verify it later:

```bash
df verify "$DF_TXID" --file ais-batch-2.json
```

Set `DF_TXID` to **that batch's** transaction first. The exported file must be the exact ordered JSON array, not the wrapper produced by `get`. Hash mode cannot recover missing original observations from the blockchain.

`--batch-size 1` selects one record per publication. `--batch-size 100` selects up to 100 queued records for one transaction. Each invocation publishes at most one batch; it does not drain the entire queue automatically.

## 9. Discover a feed on another synced node

A second node can scan the range containing the publication without the publisher's local cache. Substitute the real block range; TRU's genesis height is **1**:

```bash
df scan --from-height 36400 --to-height 36499 --max-blocks 100

df search --feed ham-demo-081 --live

df search --feed ham-demo-081 --format jsonl --output ham-records.jsonl

df search --feed ham-demo-081 --format csv --output ham-records.csv
```

These are bounded, requested scans; there is no hidden full-chain search by feed name. Each scan indexes all feeds in its block range. Use `search --feed` to filter. The retained `scan --feed` compatibility option does not restrict the shared index.

Search without `--live` explicitly labels results `CACHED_NOT_RECHECKED`. It is not a claim of current confirmation. The scanner prunes detected stale indexed branches. A reorg after a scan still requires another scan or live verification.

The first opening of a legacy discovery database resets its rebuildable v2/v3 discovery cache, because that cache depended on local metadata and feed-filtered scan coverage. Rescan the ranges you need. **The publication queue and batches are not reset.**

## 10. Uncertain submissions and the existing AIS attempt

A timeout or lost response can occur after submission. The journal stores the exact batch **before** sending RPC, leaves it `SUBMITTING` on uncertainty, and blocks another publication for that feed. It never automatically resets those rows to `QUEUED`.

For your original v1/v3 uncertain publication, do not publish it again simply because no TXID was printed. Scan the narrow range around the attempt, inspect mempool/transaction status, and compare the feed, count and commitment against your retained rows. A local `NOT_FOUND` result alone is not permission to pay again.

For a known candidate TXID:

```bash
df reconcile --feed spacedao-ais --txid YOUR_CANDIDATE_TXID
```

Without `--batch-id`, reconciliation is read-only. Legacy journals did not retain exact batch boundaries, so this package does not guess which old rows belonged together.

For **new-format batches**, after reviewing a matching confirmed transaction:

```bash
df reconcile --feed ham-demo-081 --batch-id 1 --txid YOUR_CONFIRMED_TXID
```

This requires the exact stored payload and batch hash. It associates your selected confirmed commitment with the local batch; it does not prove which timed-out RPC created it. It never submits a transaction. Stored `CONFIRMED` journal status is historical; use `verify` for current chain status.

## 11. Preview watching

```bash
df watch --feed weather-demo --interval 300 --batch-size 100
```

This previews pending batches every five minutes. `--once` performs one pass. Ctrl+C stops it. **AUTO_BROADCAST remains disabled.** Agent checkpoint `auto-watch` is a different tool and does not authorize datafeed spending.

## 12. Address-history fix

`getaddresstransactions` retains its existing JSON-array response and full-history default. It builds a temporary transaction-reference map under one chain read lock, replacing repeated full-chain searches for each input. It returns up to `count` matching rows, newest first.

```bash
"$TRUCLI" raw getaddresstransactions \
  '{"address":"REPLACE_WITH_YOUR_ADDRESS","count":10}'
```

An explicitly requested `maxBlocks: 64` limits that query's history window. `maxBlocks: 0` means full history. This is a linear read-side improvement, not a persistent address index; very large chains can still make cold queries expensive. Address history is no longer needed to retrieve a known DataFeed record.

## 13. Backup and rollback

Back up your publication SQLite file when no DataFeed process is writing it. Keep hash-mode batch exports separately. Private/off-chain data stays in those files unless you explicitly publish inline.

Source rollback:

```bash
cd /path/to/TRU_DATAFEED_05_DUAL_CORE_PINNED
python3 install.py rollback --tree NEW_TRU --root "$HOME/NEW_TRU"
python3 install.py rollback --tree TRU-Core --root "$HOME/TRU-Core"
```

Then rebuild and restart the desired binary normally. Rollback refuses drift, preserves backups, and does not undo on-chain transactions or change the SQLite journal. The upgraded journal's original `records` table remains compatible with earlier tools, but do not use earlier tools to bypass unresolved submissions.
