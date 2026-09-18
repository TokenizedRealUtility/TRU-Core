# TRU `tru-cli` — authenticated JSON-RPC command-line client

`tru-cli` is TRU's standalone command-line client for node administration, scripting, diagnostics, wallet reads, mining information, and raw JSON-RPC access.

The current TRU source tree already includes:

- the `getbalance` RPC,
- the `getinfo` aggregate RPC,
- the `tru-cli` build target,
- Patch-05 authenticated RPC transport.

No separate Patch 31 installation or manual copy of `tru-cli.cpp` is required for the current release tree.

---

## Build

Build from the TRU source tree:

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

`getbalance` returns spendable TRU coin balance. Native token holdings are separate and should be queried with the token RPCs.

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

This document describes the current authenticated `tru-cli` model after the TRU RPC/Web Patch-05 security boundary and the signed DID registration update.
