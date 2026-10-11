# TRU Core v0.08.1 — JSON-RPC method reference

> **Source-audited reference** for the uploaded `NEW_TRU/src/rpc_server.cpp` and `TRI-Core/rpc_server.cpp` (October 11, 2026). This is a **method inventory**, not a live-node integration test or exhaustive validation schema. Both files register the same method set; the public tree primarily removes development comments.

**Registered methods: 111.** Only methods in the live `startRPCServer()` dispatcher are counted; old backup files and unimplemented method names are excluded.

## How to call RPC

Core RPC is **authenticated** and deliberately not a public browser API. Local default: `127.0.0.1:21832`, `POST /rpc`, `Content-Type: application/json`. `tru-cli` automatically uses the configured Core authentication token/cookie. Never publish Core RPC credentials, seed phrases, WIF private keys or unrestricted Core RPC ports.

```bash
cd ~/NEW_TRU
./build/bin/tru-cli getinfo
./build/bin/tru-cli raw getblockcount '{}'
./build/bin/tru-cli raw getblockbyheight '{"height":123}'
./build/bin/tru-cli raw gettokenmetadata '{"txid":"PUT_REAL_TXID_HERE"}'
./build/bin/tru-cli raw getdatafeedrecord '{"txid":"PUT_REAL_TXID_HERE"}'
```

The equivalent JSON-RPC request body is:

```json
{"jsonrpc":"2.0","method":"getblockcount","params":{},"id":1}
```

**CLI distinction:** `tru-cli` offers friendly aliases plus `raw <method> <JSON-object>`. The official `gettokenmetadata` RPC requires `txid`; the friendly CLI command currently builds a `tokenID` field, so use `raw gettokenmetadata` with `{"txid":...}` instead. Do not assume Bitcoin Core RPC methods are implemented; e.g. `getmempoolinfo` is **not registered**.

## Complete method inventory

**Gateway key:** `Wallet` = publicly allowlisted via the explorer `POST /api/wallet/rpc`; `Mining` = allowlisted via `POST /api/mining/rpc`; `Core` = only registered on authenticated Core RPC (not through either public allowlist). Some wallet-gateway methods are signed submission or unsigned builders, not custodial sends. Being allowlisted does not guarantee success under runtime policy, node status or rate limits.

### Node, chain, network and diagnostics

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `getinfo` | Combined node, wallet and chain status (privileged; may expose Core wallet details) | none | Core |
| `getdesktopinfo` | Chain/node overview designed not to disclose the Core wallet balance/address | none | Wallet |
| `getchaininfo` | Chain tip, difficulty and status | none | Wallet, Mining |
| `getblockcount` | Current chain height | none | Wallet, Mining |
| `getblock` | Fetch block by hash | `hash` | Core |
| `getblockbyheight` | Fetch block at height | `height` | Core |
| `getpeerinfo` | Connected peer details | none | Wallet |
| `getchainhealth` | Data-provider chain health payload | none | Core |
| `getchainmetadata` | Data-provider chain information payload | none | Core |
| `getchainsupply` | Data-provider chain supply payload | none | Core |
| `auditchain` | Trigger chain audit/status operation | none | Core |
| `gettransaction` | Find a transaction and its active/mempool state | `txid` | Wallet |
| `getrawtransaction` | Return serialized or decoded transaction | `txid`, optional `verbose` | Core |
| `decoderawtransaction` | Decode raw transaction without broadcasting | `txHex` | Wallet, Mining |
| `gettxout` | Inspect unspent outpoint | `txid`, `n`, optional `includeMempool` | Wallet |
| `getaddresstransactions` | Address transaction history | `address`, optional `count`, `maxBlocks` | Wallet |
| `listtransactions` | Address-related transaction history | optional `address`, `count` | Wallet |
| `listunspent` | Enumerate UTXOs for an address | `address` | Core |
| `listunspentWeb` | Web-safe address UTXO list | `address` | Wallet |
| `getrawmempool` | Mempool transaction IDs, optionally verbose | optional `verbose` | Wallet, Mining |
| `getmempooltransactions` | Detailed mempool transactions | none | Wallet, Mining |
| `listmempooltransactions` | List mempool transactions | none | Wallet |

### Wallet, raw transactions and transfers

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `getbalance` | Balance for a supplied address or local current wallet | optional `address` | Core |
| `getnewaddress` | Generate a Core-wallet address | none | Core |
| `listaddresses` | List Core-wallet addresses | none | Core |
| `sendtoaddress` | Send native TRU from Core wallet, operator enabled/local only | `address` (string), `amount` (decimal string), optional `dry_run` (bool) | Core |
| `createrawtransaction` | Construct unsigned raw TRU transaction | `inputs`, `outputs` | Wallet |
| `signrawtransactionwithkey` | Sign a raw transaction using supplied private keys (sensitive) | `txHex`, `privKeys` | Core |
| `signrawtransactionwithkeyWeb` | Web-compatible raw transaction signing (sensitive; not exposed by public explorer gateway) | `txHex`, `privKeys` | Core |
| `sendrawtransaction` | Broadcast serialized signed transaction | `txHex` | Wallet |
| `sendrawtransactionWeb` | Browser-compatible transaction submission | `txHex` | Wallet |

### Tokens: FT, NFT, SFT and NCFT

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `issuetoken` | Issue a token with Core wallet | `type`, `tokenID`, `address`, `supply`, token-type metadata | Core |
| `issuetokensigned` | Submit an externally signed issuance | `signedTxHex`, `metadata`, optional `attachMetadata` | Wallet |
| `createtokentransaction` | Build an unsigned token-issuance transaction | `type`, `tokenID`, `name`, `senderAddress`, `utxo`, `fee`, type-specific fields | Core |
| `gettokenutxo` | Inspect token content by outpoint or token ID/address | `txid` + `vout`, or `tokenID` + `address` | Wallet |
| `gettokenmetadata` | Resolve transaction-level token metadata, including continuation fallback | `txid` (NOT `tokenID`) | Wallet |
| `tokenmetadisplay` | Display token metadata for address array | `addresses` array | Wallet |
| `verifytokenmetadata` | Verify token metadata tied to transaction | `txid` | Wallet |
| `verifytokenbalance` | Confirm address holdings for a token | `address`, `tokenID` | Core |
| `sendtoken` | Core-wallet token transfer | `tokenID`, `amount`, `recipient`, `senderAddress` | Core |
| `sendtokenweb` | Web token send implementation (not public-gateway allowlisted) | `tokenID`, `amount`, `recipient`, `senderAddress` | Core |
| `createsendtokentransaction` | Build unsigned token transfer | `tokenID`, `amount`, `recipient`, `senderAddress`, `feeUtxo`, `fee` | Wallet |
| `burntoken` | Burn/retire token from owner wallet | `tokenID`, `senderAddress`, `confirm` | Core |
| `createburntokentransaction` | Build unsigned burn transaction | `tokenID`, `senderAddress`, `feeUtxo`, `fee` | Wallet |
| `gettokenburninfo` | Retrieve burn/retirement configuration | none | Core |
| `debugtokentx` | Inspect token transaction diagnostics | `txid` | Core |

### TRUScripts, social identity and DIDs

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `inscribeTRUScript` | Core-wallet inscription creation | `data`, `owner` | Core |
| `inscribeTRUScriptSigned` | Submit signed inscription | `signedTxHex`, `inscriptionData`, `owner`, optional `requireBoundOpReturn` | Wallet |
| `getTRUScripts` | Inscriptions owned by address | `ownerAddress` | Wallet |
| `getTRUScriptDetails` | One inscription's details | `txid` | Wallet |
| `createTransferTRUScriptTransaction` | Build an unsigned inscription transfer | `inscriptionTxid`, `recipient`, `senderAddress`, `feeUtxo`, `fee` | Wallet |
| `transferTRUScript` | Core-wallet inscription transfer | `inscriptionTxid`, `recipient` | Core |
| `createDID` | Create/register DID through local chain logic | `did`, `address` | Core |
| `registerDIDSigned` | Register DID with identity signature | `did`, `address`, `publicKey`, `signature` | Wallet |
| `getDIDMapping` | Resolve DID-to-address mapping | `did` | Wallet |
| `createsocialpost` | Create DID-linked social message | `fromDID`, `message`, optional `tags`, `privateKey` | Core |

### DataFeed v1

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `getdatafeedinfo` | Show DataFeed format, payload limit and wallet-publish capability | none | Core |
| `publishdatafeed` | Publish one DataFeed envelope as TRU transaction | `data`, `owner`, `max_fee_atoms` (positive integer) | Core |
| `getdatafeedrecord` | Read DataFeed record directly from transaction bytes and confirmation state | `txid` | Core |
| `getdatafeedblock` | Extract DataFeed records from an indexed block | `height` | Core |

### Smart contracts, voting and locks

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `createcontracttransaction` | Build script-backed contract transaction subject to VM preflight | `type`, `name`, `scriptHex`, `senderAddress`, `utxo`, `amount`, optional `metadata`, `fee` | Wallet |
| `getcontracts` | List/index contracts | none | Wallet |
| `getcontractoutpoint07b` | Resolve a contract by canonical outpoint | `txid`, `vout` | Core |
| `redeemhashlock` | Redeem wallet-owned hashlock contract | `contractAddress`, `address`, `preimage` | Core |
| `redeemtimelock` | Redeem wallet-owned timelock contract | `contractAddress`, `address` | Core |
| `getvotingv1snapshot07b` | Confirmed on-chain Voting V1 state and counts | `root`, optional `voterAddress` | Core |
| `preparevotingv1create07b` | Create unsigned Voting V1 proposal transaction | `proposal`, `name`, `options`, `endTime`, `amount_atoms`, `senderAddress`, `utxo` | Core |
| `preparevotingv1ballot07b` | Create unsigned Voting V1 ballot transaction | `root`, `choice`, `senderAddress`, `utxo` | Core |
| `createmagiclock` | Construct legacy-style Magic Lock with current restrictions | `amount`, `targetPrefix`, optional `address`, `dataType` | Core |
| `unlockmagiclock` | Spend/claim a Magic Lock | `txid`, `vout`, `recipient` | Core |
| `listmagiclocks` | List locks, optionally by address | optional `address` | Wallet |
| `preparemagicsecret` | Make unsigned MagicLock V2 publish transaction | `address`, `scriptHex`, optional `txid`, `vout` | Wallet |
| `getmagicsecret` | Read public MagicLock V2 script/proof metadata | `txid` | Wallet |
| `publishmagicsecret` | Local-wallet MagicLock V2 publish (operator enabled) | `scriptHex` | Core |

### Mining and telemetry

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `getblocktemplate` | Construct mining template, including browser variant | optional `browserMinerAddress`, `browserExtraNonce` | Wallet, Mining |
| `submitblock` | Validate and submit block or browser candidate | `blockHex` or `browserCandidate` (shape dependent) | Wallet, Mining |
| `startmining` | Request mining operation | handler-specific parameters | Core |
| `reportmineractivity` | Report miner observed hashes/time | `minerAddress`, `hashesTried`, `timeTaken` | Wallet, Mining |
| `registerminer` | Register local miner address | `minerAddress` | Core |
| `unregisterminer` | Unregister miner address | `minerAddress` | Core |
| `getminerstatus` | Query miner address state | `minerAddress` | Core |
| `getallminers` | List registered/observed miners | none | Wallet |

### AI providers, AI tokens and evolution

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `configureAIProvider` | Set AI provider configuration (keep credentials private) | `address`, `provider`, provider-specific `api_key`, `model`, `endpoint`, `config` | Core |
| `getAIProviders` | Enumerate configured AI providers | none | Wallet |
| `testAIProvider` | Test a provider | `provider` | Wallet |
| `createAIToken` | Create NCFT/SFT AI token via wallet | `type`, `tokenID`, `name`, `address`, AI and issuance fields | Core |
| `interactWithAIToken` | Send interaction request to token's AI engine | `tokenID`, `address`, `message` | Core |
| `getAIResponse` | Retrieve an AI interaction response | `requestID` | Core |
| `getAITokenState` | Read persistent AI token state | `tokenID` | Wallet |
| `trainAIToken` | Submit training data to an AI token | `tokenID`, `training_data`, optional `address` | Core |
| `verifytokenevolution` | Verify recorded token evolution lineage | `tokenID`, optional `require_confirmed` | Wallet |
| `previewtokenevolution` | Preview proposed owner-mediated AI evolution | `tokenID`, `owner`, `provider`, optional `trigger`, `media_inputs` | Wallet |
| `committokenevolutionsigned` | Verify and submit owner-signed evolution anchor | `confirmation`, `tokenID`, `owner`, `record_json`, `publicKey`, `signature` | Wallet |
| `axonwalletinspect` | Inspect NEROMESH AXON payment handoff, loopback only | `uri` | Core |
| `axonwalletfund` | Explicitly fund inspected AXON intent, loopback only | `uri`, `expected_job_id`, `expected_intent_sha256`, `confirm:true` | Core |

### HTLC and swap-coordination operations

| Method | What it does | Primary JSON `params` keys | Access |
|---|---|---|---|
| `htlcgeneratesecret` | Generate HTLC secret material | none | Core |
| `htlcpreparefunding` | Prepare/reserve HTLC funding without broadcasting | `operationId`, `secretHash160`, `claimPubkey`, `refundPubkey`, `refundTime`, `amountAtoms` | Core |
| `htlcpreparedstatus` | Inspect prepared HTLC funding record | `operationId` | Core |
| `htlcpreparedrelease` | Release reservation for prepared HTLC | `operationId`, `preparedTxid` | Core |
| `htlcbroadcastprepared` | Broadcast previously prepared HTLC funding | `operationId`, `preparedTxid`, optional `dryRun` | Core |
| `htlccreate` | Create and fund HTLC (wallet operation) | `secretHash160`, `claimPubkey`, `refundPubkey`, `refundTime`, `amountAtoms` | Core |
| `htlcclaim` | Redeem an HTLC with its preimage | `fundingTxid`, `recipient`, `preimageHex`, optional `vout`, `allocationId` | Core |
| `htlcrefund` | Refund timelocked HTLC | `fundingTxid`, `recipient`, optional `vout`, `allocationId` | Core |
| `swaptestexitmempoolaccept` | Check prepared swap exit transaction for admission and expected identity | `txHex`, `expectedTxid`, `fundingTxid`, `fundingVout` | Core |
| `swaprecordcreate` | Create swap state journal record | swap-record object (refer to handler) | Core |
| `swaprecordget` | Fetch swap journal entry | `swapId` | Core |
| `swaprecordlist` | List swap journal entries | none | Core |
| `swaprecordtransition` | Advance journal entry with evidence | `swapId`, `nextState`, `evidence` | Core |
| `swapwalletfreshkeys` | Create/lookup isolated swap allocation key material | `allocationId` | Core |
| `swapwalletfreshselfproof` | Produce fresh-key ownership proof | `allocationId`, `role` | Core |
| `swapwalletrolekeys` | Retrieve swap wallet role key information | handler-specific parameters | Core |

## Important operational boundaries

- **No public unrestricted RPC:** `POST /rpc` requires authenticated local/approved transport; the explorer exposes only method allowlists. `GET /rpc` is intentionally rejected (405).
- **Public gateway drift:** `getminingleaderboard` appears in the wallet-gateway allowlist but is **not in the 111-method Core dispatcher**, so requests will return JSON-RPC “Method not found”. Do not advertise it as working.
- **Core wallet sending:** `sendtoaddress` and `publishmagicsecret` require local loopback and `TRU_RPC_WALLET_SEND_ENABLE=1`; `sendtoaddress` also enforces a configured send limit. A dry run checks syntax/limits/unlock status but **does not simulate UTXO selection or fees**.
- **Sensitive operations:** treat `configureAIProvider`, key signing, `htlc*`, `swapwallet*`, `axonwalletfund`, `issuetoken`, `burntoken`, and all broadcaster/wallet methods as privileged; application-level approval, wallet unlock controls and secure credential handling still matter.
- **Wallet ownership:** `listunspent`/`getbalance` for a supplied public address do not imply that a node holds its private key or may sign for it.
- **Smart-contract activation:** `createcontracttransaction` checks script resource limits and current family/policy restrictions; the code explicitly rejects *some* state-domain scripts at this builder preflight. Treat the supported contract families and activation state as version-specific, not arbitrary execution of every bytecode.
- **DataFeed:** `getdatafeedrecord` parses transaction output bytes and reports confirmations; `publishdatafeed` is operator-enabled and returns an unconfirmed tx ID, not a promise of inclusion. `TRUDF1` payload framing has a **254-byte cap** for the on-chain application envelope. DataFeed is an application feature, not a consensus proof that external data is true.
- **AI and agent flows:** preview, signed evolution commitment, provider calls and AXON wallet handoff depend on external services, an unlocked/authorized wallet or valid owner signatures. They are not proof that arbitrary agents may spend without limits.
- **HTLC funding:** `htlcpreparefunding`, broadcasting, claims and refunds have stateful, irreversible financial implications. Prefer the journaled Swap Agent workflow over manual calls from the CLI.
- **Signing caution:** RPC methods accepting `privKeys`, `privateKey`, `api_key` or similar fields should never be sent through a proxy you do not operate, copied to support chats, or placed in GitHub issues.
- **No native ZK privacy:** `verifyZeroKnowledgeProof` in `block.cpp` currently returns `true` (including with `HAS_ZKPROOF`), so this code does **not** provide verified zero-knowledge transactions or shielded transfers.

