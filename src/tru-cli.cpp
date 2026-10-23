// ============================================================================
//  tru-cli  --  Bitcoin-cli-style command-line client for the TRU node
// ----------------------------------------------------------------------------
//  Talks JSON-RPC to a running tru_advanced node over HTTP POST /rpc, exactly
//  like the standalone miners do (httplib + nlohmann::json, endpoint "/rpc",
//  body {jsonrpc, method, params, id}).
//
// Build target: tru-cli (configured in CMakeLists.txt).
//
//
//
//  USAGE:
//      tru-cli [options] <command> [args...]
//      tru-cli [options] raw <method> ['{"json":"params"}']
//
//  OPTIONS:
//      -rpcconnect=<ip>     node IP     (default 127.0.0.1)
//      -rpcport=<port>      node port   (default 21832)
//      -conf=<file>         read rpcconnect/rpcport from a tru.conf-style file
//      -json                print the raw JSON result (no pretty summary)
//      -timeout=<sec>       read timeout seconds (default 30)
//      -h / --help          this help
//
//  FRIENDLY COMMANDS (mapped to RPC methods, bitcoin-cli-like):
//      getinfo                          -> getinfo
//      getbalance [address]             -> getbalance {address?}
//      getblockcount                    -> getblockcount
//      getchaininfo                     -> getchaininfo
//      getbestblockhash                 -> getchaininfo (prints bestHash)
//      getdifficulty                    -> getchaininfo (prints difficulty)
//      getpeerinfo                      -> getpeerinfo
//      getconnectioncount               -> getpeerinfo (prints count)
//      getnewaddress                    -> getnewaddress
//      listaddresses                    -> listaddresses
//      listunspent <address>            -> listunspent {address}
//      listtransactions <address>       -> listtransactions {address}
//      getblock <hash>                  -> getblock {hash}
//      getblockbyheight <height>        -> getblockbyheight {height}
//      gettransaction <txid>            -> gettransaction {txid}
//      getrawmempool                    -> getrawmempool
//      getmininginfo                    -> getminerstatus (best-effort)
//      gettokenmetadata <tokenID>       -> gettokenmetadata {tokenID}
//      verifytokenbalance <addr> <tid>  -> verifytokenbalance {address,tokenID}
//      raw <method> [jsonparams]        -> passthrough to ANY node method
//
//  Exit code 0 on success, 1 on transport error, 2 on RPC error.
// ============================================================================

#include "tru_network_params.h"
#include "rpc_utils.h"  // Bearer/cookie RPC authentication
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <functional>

#include <httplib.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ------------------------------- config -------------------------------------
struct Config {
    std::string ip   = "127.0.0.1";
    int         port = tru_network::MAINNET_RPC_PORT;
    int         timeout = 30;
    bool        rawJson = false;
};

static void printUsage() {
    std::cout << R"TRUHELP088(tru-cli -- command-line RPC client for TRU Core (0.08.8 help)

Usage:
  tru-cli [options] <command> [args...]
  tru-cli [options] raw <method> ['{"json":"params"}']

Options:
  -rpcconnect=<ip>  node IP (default 127.0.0.1)
  -rpcport=<port>   RPC port (default 21832; P2P uses 21833)
  -conf=<file>      read connection settings from a tru.conf-style file
  -json             print raw JSON result instead of a friendly summary
  -timeout=<sec>    RPC read timeout (default 30 seconds)
  -h, --help        show this help locally; no RPC connection needed
  Place options before the command; later connection options override earlier ones.
  Use single quotes around JSON in a POSIX shell. Method names are case-sensitive.

Friendly commands -- these are all implemented direct command wrappers:
  getinfo                          aggregate node + wallet snapshot
  getbalance [address]             ordinary spendable TRU balance
  sendtoaddress <addr> <amount> [--dry-run]
                                   ordinary TRU send; local wallet opt-in required
  getblockcount                    current tip height
  getchaininfo                     tip summary; use -json for fork_recovery details
  getbestblockhash                 current best block hash (via getchaininfo)
  getdifficulty                    compact difficulty bits in hex (via getchaininfo)
  getpeerinfo                      connected peer information
  getconnectioncount               number of returned peer entries
  getnewaddress                    derive ordinary wallet address
  listaddresses                    ordinary wallet addresses
  listunspent <address>            spendable UTXOs for an address
  listtransactions <address>       transaction history for an address
  getblock <hash>                  block by hash
  getblockbyheight <height>        block at active-chain height
  gettransaction <txid>            transaction state and confirmation details
  getrawmempool                    mempool transaction IDs
  gettxout <txid> <n>              UTXO by outpoint; n is a non-negative integer
  getrawtransaction <txid> [-v]     raw bytes; -v, verbose or 1 selects decoded output
  decoderawtransaction <hex>       decode saved bytes without broadcasting
  getaddresstransactions <addr> [n] richer address history, optional count
  getmempooltransactions           full mempool entries
  getallminers                     miners known to this node
  getminerstatus <addr>            miner status (minerAddress parameter)
  getmininginfo                    legacy best-effort getminerstatus alias;
                                   no address supplied, so Core may reject it
  getcontracts                     contract inspection
  gettokenutxo <txid> <vout>        token UTXO by outpoint
  gettokenmetadata <tokenID>        token metadata
  verifytokenmetadata <txid>        metadata committed by a transaction
  verifytokenbalance <addr> <tid>   token balance for an address
  verifytokenevolution <tokenID>    evolution proof/history inspection
  getTRUScripts <ownerAddress>      inscriptions owned by an address
  getTRUScriptDetails <txid>        one inscription
  listmagiclocks [address]          MagicLocks, optionally filtered
  quantum <action> [JSON]           dedicated PQ01 plain-TRU wallet path (below)
  raw <method> [JSON]               authenticated passthrough to Core (below)

Quantum actions -- quantum <action> [JSON]:
  receive    create a fresh one-payment PQ01 descriptor
  list       list local descriptors and signing state
  status     inspect sidecar format and recovery information (0.08.8)
  backup     {"backup_file":"/absolute/private/NEW.pqbackup"}
             export encrypted state; refuses an existing destination (0.08.8)
  restore    {"backup_file":"/absolute/private/current.pqbackup",
              "confirm_recovery_only":true}
             recovery-only import: ALL imported keys quarantined from new signing
  input      {"txid":"TXID","vout":0}
             inspect a confirmed unspent input; maps to getquantuminput
  fund       {"txid":"ORDINARY_TXID","vout":0,"fee_atoms":10000,
              "destination":"FRESH_TRUQ1_DESCRIPTOR"}
             sign ordinary ECDSA funding into a PQ01 output; does NOT broadcast
  send       {"txid":"PQ01_TXID","vout":0,"fee_atoms":10000,
              "source":"SOURCE_DESCRIPTOR","destination":"FRESH_DESCRIPTOR"}
             sign a WOTS+ spend to a fresh PQ01 output; does NOT broadcast
  exit       {"txid":"PQ01_TXID","vout":0,"fee_atoms":10000,
              "source":"SOURCE_DESCRIPTOR","destination":"ORDINARY_ADDRESS",
              "confirm_exit":true}
             sign a WOTS+ spend to an ordinary ECDSA output; does NOT broadcast
  retry      {"source":"SOURCE_DESCRIPTOR"}
             retrieve saved signed bytes; never creates a replacement signature
  submit     {"txHex":"SAVED_RAW_HEX"}
             explicitly broadcast saved bytes; maps to sendquantumtransaction

  receive/list/status/backup/restore/fund/send/exit/retry map to quantumwallet
  with the corresponding action. Wallet actions require authenticated loopback
  RPC, an unlocked wallet and the operator's existing wallet-send opt-in.
  In tru.conf use the supported rpcWalletSend setting; do not expose signing RPC.
  Confirm active:true with raw getconsensus09info before funding or spending.
  fund/send/exit spend the WHOLE input minus the fee: one input, one output,
  no amount field, no change and no token metadata. 1 TRU = 100000000 atoms.
  Fee must be >=10000 atoms AND satisfy wallet policy and operator input cap.
  Decode and check rawHex before submit. A txid/accepted response is not confirmation.
  Check gettransaction and quantum input after mining; pending inputs are refused.

Quantum safety and migration:
  ONE payment per descriptor; ONE signing intent per key. Never reuse keys or
  send change back. Local "unused" does not prove an address never received funds.
  Back up the ordinary wallet AND current .pq01 / .pq01.recovery state together.
  Seed-only recovery is NOT supported. The local recovery copy is not off-machine
  backup or rollback-proof protection. Never clone signers or roll back both copies.
  State format 2 is unreadable by older binaries. Do not downgrade with stale files.
  Restore imports quarantine keys, including matched local keys; saved completed
  bytes can be retrieved, but imported keys cannot create new signatures.
  An imported funded output without saved spending bytes may remain unspendable.
  Use restore only for actual recovery after testing on a disposable wallet.
  Local destination reservations cannot prevent payments from other wallets/raw tools.
  Native desktop/Core hardening does not automatically update independent web/SDK code.

Activation / recovery / market inspection (RAW calls, not direct wrappers):
  tru-cli raw getconsensus09info '{}'
  tru-cli -json getchaininfo
  tru-cli raw getblocktemplate '{}'
  tru-cli raw getmarketportfolio '{"address":"YOUR_TRU_ADDRESS"}'
  getchaininfo.fork_recovery reports effective recovery state, reason and limits.
  chainValid is the last hash/PoW audit at the same tip, not transaction/UTXO replay.
  Compare hashes at a common height; equal heights alone do not prove one branch.
  buildmarkettransaction09 builds market transactions: use its documented request
  schema; it is not a new positional tru-cli command or proof of settlement.
  Pool builders must retain coinbase_required_outputs (including TR09) and
  required_token_metadata from the exact getblocktemplate payload they submit.

Other RPC methods:
  The catalog below lists method names from the reviewed 0.08.8 Core dispatcher.
  Invoke with: tru-cli raw METHOD '{"parameter":"value"}'
  It is a source snapshot, NOT live method discovery or complete parameter help.
  Some methods require parameters, wallet access, explicit approval or feature gates.
  No new friendly aliases or permissions are created by this help update.
  Internal/Web-suffixed methods remain subject to their own access constraints.
  HTLC funding/claim/refund/prepared-broadcast and swap state operations belong
  to the Swap Agent's durable journal; do not bypass it with ad-hoc raw calls.

Reviewed Core RPC method catalog (117 method names):
  auditchain
  axonwalletfund
  axonwalletinspect
  buildmarkettransaction09
  burntoken
  committokenevolutionsigned
  configureAIProvider
  createAIToken
  createburntokentransaction
  createcontracttransaction
  createDID
  createmagiclock
  createrawtransaction
  createsendtokentransaction
  createsocialpost
  createtokentransaction
  createTransferTRUScriptTransaction
  debugtokentx
  decoderawtransaction
  getaddresstransactions
  getAIProviders
  getAIResponse
  getAITokenState
  getallminers
  getbalance
  getblock
  getblockbyheight
  getblockcount
  getblocktemplate
  getchainhealth
  getchaininfo
  getchainmetadata
  getchainsupply
  getconsensus09info
  getcontractoutpoint07b
  getcontracts
  getdatafeedblock
  getdatafeedinfo
  getdatafeedrecord
  getdesktopinfo
  getDIDMapping
  getinfo
  getmagicsecret
  getmarketportfolio
  getmempooltransactions
  getminerstatus
  getnewaddress
  getpeerinfo
  getquantuminput
  getrawmempool
  getrawtransaction
  gettokenburninfo
  gettokenmetadata
  gettokenutxo
  gettransaction
  getTRUScriptDetails
  getTRUScripts
  gettxout
  getvotingv1snapshot07b
  htlcbroadcastprepared
  htlcclaim
  htlccreate
  htlcgeneratesecret
  htlcpreparedrelease
  htlcpreparedstatus
  htlcpreparefunding
  htlcrefund
  inscribeTRUScript
  inscribeTRUScriptSigned
  interactWithAIToken
  issuetoken
  issuetokensigned
  listaddresses
  listmagiclocks
  listmempooltransactions
  listtransactions
  listunspent
  listunspentWeb
  preparemagicsecret
  preparevotingv1ballot07b
  preparevotingv1create07b
  previewtokenevolution
  publishdatafeed
  publishmagicsecret
  quantumwallet
  redeemhashlock
  redeemtimelock
  registerDIDSigned
  registerminer
  reportmineractivity
  sendquantumtransaction
  sendrawtransaction
  sendrawtransactionWeb
  sendtoaddress
  sendtoken
  sendtokenweb
  signrawtransactionwithkey
  signrawtransactionwithkeyWeb
  startmining
  submitblock
  swaprecordcreate
  swaprecordget
  swaprecordlist
  swaprecordtransition
  swaptestexitmempoolaccept
  swapwalletfreshkeys
  swapwalletfreshselfproof
  swapwalletrolekeys
  testAIProvider
  tokenmetadisplay
  trainAIToken
  transferTRUScript
  unlockmagiclock
  unregisterminer
  verifytokenbalance
  verifytokenevolution
  verifytokenmetadata

Examples (replace TXIDs, descriptors, addresses and paths):
  tru-cli getinfo
  tru-cli sendtoaddress YOUR_ADDRESS 0.001 --dry-run
  tru-cli gettxout FUND_TXID 0
  tru-cli quantum receive
  tru-cli quantum status
  tru-cli quantum input '{"txid":"FUND_TXID","vout":0}'
  tru-cli quantum backup '{"backup_file":"/absolute/private/NEW.pqbackup"}'
  tru-cli quantum retry '{"source":"SOURCE_DESCRIPTOR"}'
  tru-cli decoderawtransaction SAVED_RAW_HEX
  tru-cli quantum submit '{"txHex":"SAVED_RAW_HEX"}'
  tru-cli gettransaction SUBMITTED_TXID
  tru-cli raw quantumwallet '{"action":"list"}'

This executable is the RPC client. The node's interactive Quantum Transactions
menu uses qr in tru_advanced --cli; it is not a tru-cli qr command.
)TRUHELP088";
}

// std::stoul("-3") does NOT throw: it wraps to a huge unsigned value, so a
// negative outpoint index would sail through and be sent to the node as
// 4294967293. Reject the sign explicitly.
static bool parseVout(const std::string& in, uint32_t& out) {
    if (in.empty()) return false;
    for (char c : in) if (c < '0' || c > '9') return false;
    try {
        unsigned long v = std::stoul(in);
        if (v > 0xFFFFFFFFUL) return false;
        out = static_cast<uint32_t>(v);
        return true;
    } catch (...) { return false; }
}

// Parse a tru.conf-style file for node.ip / node.port / rpcport / rpcconnect.
static void loadConf(const std::string& path, Config& cfg) {
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        // strip comments and whitespace
        auto hash = line.find_first_of("#;");
        if (hash != std::string::npos) line = line.substr(0, hash);
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto trim = [](std::string s){
            size_t a = s.find_first_not_of(" \t\r\n");
            size_t b = s.find_last_not_of(" \t\r\n");
            return (a==std::string::npos) ? std::string() : s.substr(a, b-a+1);
        };
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq+1));
        if (key.empty() || val.empty()) continue;
        if (key == "rpcconnect" || key == "node.ip")   cfg.ip = val;
        else if (key == "rpcport" || key == "node.port") { try { cfg.port = std::stoi(val); } catch (...) {} }
    }
}

// One JSON-RPC round trip. Returns the full response JSON (may contain "error").
static json rpcCall(const Config& cfg, const std::string& method, const json& params) {
    httplib::Client cli(cfg.ip, cfg.port);
    cli.set_default_headers(tru_rpc::clientAuthorizationHeaders(cfg.port));
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(cfg.timeout, 0);

    json req = {
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", method},
        {"params", params}
    };

    auto res = cli.Post("/rpc", req.dump(), "application/json");
    if (!res) {
        throw std::runtime_error("could not reach node at " + cfg.ip + ":" +
                                 std::to_string(cfg.port) + " (is tru_advanced running with RPC enabled?)");
    }
    if (res->status < 200 || res->status >= 300) {
        throw std::runtime_error("HTTP " + std::to_string(res->status) + " from node: " + res->body);
    }
    try {
        return json::parse(res->body);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("bad JSON from node: ") + e.what());
    }
}

// Pretty helpers ------------------------------------------------------------
static void printResultRaw(const json& resp) {
    if (resp.contains("result")) std::cout << resp["result"].dump(2) << "\n";
    else std::cout << resp.dump(2) << "\n";
}

static const json& mustResult(const json& resp) {
    if (resp.contains("error") && !resp["error"].is_null()) {
        std::string msg = resp["error"].is_object() && resp["error"].contains("message")
                          ? resp["error"]["message"].get<std::string>()
                          : resp["error"].dump();
        throw std::runtime_error("RPC error: " + msg);
    }
    static json empty;
    if (!resp.contains("result")) return empty;
    return resp["result"];
}

// ------------------------------- main ---------------------------------------
int main(int argc, char** argv) {
    Config cfg;
    std::vector<std::string> pos;   // positional args (command + params)

    // First pass: options (anything starting with '-'), rest are positional.
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto starts = [&](const char* p){ return a.rfind(p, 0) == 0; };
        if (a == "-h" || a == "--help") { printUsage(); return 0; }
        else if (starts("-rpcconnect=")) cfg.ip = a.substr(std::string("-rpcconnect=").size());
        else if (starts("-rpcport="))    { try { cfg.port = std::stoi(a.substr(std::string("-rpcport=").size())); } catch (...) {} }
        else if (starts("-timeout="))    { try { cfg.timeout = std::stoi(a.substr(std::string("-timeout=").size())); } catch (...) {} }
        else if (starts("-conf="))       loadConf(a.substr(std::string("-conf=").size()), cfg);
        else if (a == "-json")           cfg.rawJson = true;
        else                             pos.push_back(a);
    }

    if (pos.empty()) { printUsage(); return 0; }

    const std::string cmd = pos[0];

    try {
        // ---- raw passthrough: raw <method> [jsonparams] --------------------
        if (cmd == "raw") {
            if (pos.size() < 2) { std::cerr << "raw: need a method name\n"; return 2; }
            std::string method = pos[1];
            json params = json::object();
            if (pos.size() >= 3) {
                try { params = json::parse(pos[2]); }
                catch (const std::exception& e) { std::cerr << "raw: params is not valid JSON: " << e.what() << "\n"; return 2; }
            }
            json resp = rpcCall(cfg, method, params);
            printResultRaw(resp);
            return (resp.contains("error") && !resp["error"].is_null()) ? 2 : 0;
        }

        // Dedicated quantum namespace; JSON contains public data only.
        if (cmd == "quantum") {
            if(pos.size()<2 || pos.size()>3){std::cerr << "quantum <receive|list|status|backup|restore|fund|send|exit|retry|input|submit> [JSON]\n";return 2;}
            json p=pos.size()==3?json::parse(pos[2]):json::object();
            const auto action=pos[1];
            std::string m=action=="input"?"getquantuminput":action=="submit"?"sendquantumtransaction":"quantumwallet";
            if(m=="quantumwallet")p["action"]=action;
            auto r=rpcCall(cfg,m,p);printResultRaw(r);return r.contains("error")&&!r["error"].is_null()?2:0;
        }

        // ---- friendly commands --------------------------------------------
        json params = json::object();
        std::string method;
        // "summary" closures print a human line; default falls back to raw.
        std::function<void(const json&)> summary;

        if (cmd == "getinfo") {
            method = "getinfo";
            summary = [](const json& r){
                std::cout
                  << "version       " << r.value("version","")        << "\n"
                  << "blocks        " << r.value("blocks", 0)          << "\n"
                  << "bestblockhash " << r.value("bestblockhash","")   << "\n"
                  << "difficulty    " << r.value("difficultyhex","")   << " (" << r.value("difficulty",0) << ")\n"
                  << "connections   " << r.value("connections", 0)     << "\n"
                  << "chainvalid    " << (r.contains("chainvalid") && r["chainvalid"].is_boolean() ? (r["chainvalid"].get<bool>() ? "audit passed" : "audit failed") : "not audited at this tip") << "\n"
                  << "chainsize     " << r.value("chainsize", 0)       << "\n"
                  << "address       " << r.value("address","")         << "\n"
                  << "balance       " << r.value("balance","0.00000000") << " TRU\n";
            };
        }
        else if (cmd == "getbalance") {
            method = "getbalance";
            if (pos.size() >= 2) params["address"] = pos[1];
            summary = [](const json& r){
                std::cout << r.value("confirmed","0.00000000") << " TRU"
                          << "   (" << r.value("address","") << ")\n";
            };
        }
        else if (cmd == "sendtoaddress") {
            if (pos.size() < 3 || pos.size() > 4 ||
                (pos.size() == 4 && pos[3] != "--dry-run")) {
                std::cerr << "sendtoaddress: need <address> <decimal-TRU-amount> [--dry-run]\n";
                return 2;
            }
            // Locality is enforced again inside Core even if this client is bypassed.
            if (cfg.ip != "127.0.0.1" && cfg.ip != "localhost" && cfg.ip != "::1") {
                std::cerr << "sendtoaddress: use a local Core RPC connection\n";
                return 2;
            }
            method = "sendtoaddress";
            params["address"] = pos[1];
            params["amount"] = pos[2]; // Exact decimal string: never floating point.
            params["dry_run"] = pos.size() == 4;
            summary = [](const json& r) {
                if (r.value("dry_run", false)) {
                    std::cout << "VALIDATED (not signed or broadcast): "
                              << r.value("amount", "") << " TRU to "
                              << r.value("address", "") << "\n"
                              << r.value("note", "") << "\n";
                } else {
                    std::cout << "TXID " << r.value("txid", "") << "\n";
                }
            };
        }
        else if (cmd == "getblockcount") {
            method = "getblockcount";
            summary = [](const json& r){ std::cout << r.dump() << "\n"; };
        }
        else if (cmd == "getchaininfo") {
            method = "getchaininfo";
            summary = [](const json& r){
                std::cout
                  << "height     " << r.value("bestHeight", 0)  << "\n"
                  << "bestHash   " << r.value("bestHash","")    << "\n"
                  << "difficulty 0x" << std::hex << r.value("difficulty", 0u) << std::dec << "\n"
                  << "chainSize  " << r.value("chainSize", 0)   << "\n"
                  << "chainValid " << (r.contains("chainValid") && r["chainValid"].is_boolean() ? (r["chainValid"].get<bool>() ? "audit passed" : "audit failed") : "not audited at this tip") << "\n";
            };
        }
        else if (cmd == "getbestblockhash") {
            method = "getchaininfo";
            summary = [](const json& r){ std::cout << r.value("bestHash","") << "\n"; };
        }
        else if (cmd == "getdifficulty") {
            method = "getchaininfo";
            summary = [](const json& r){ std::cout << "0x" << std::hex << r.value("difficulty", 0u) << std::dec << "\n"; };
        }
        else if (cmd == "getpeerinfo") {
            method = "getpeerinfo";
            summary = nullptr; // array; just print JSON
        }
        else if (cmd == "getconnectioncount") {
            method = "getpeerinfo";
            summary = [](const json& r){ std::cout << (r.is_array() ? r.size() : 0) << "\n"; };
        }
        else if (cmd == "getnewaddress")   { method = "getnewaddress"; }
        else if (cmd == "listaddresses")   { method = "listaddresses"; }
        else if (cmd == "getrawmempool")   { method = "getrawmempool"; }
        else if (cmd == "getmininginfo")   { method = "getminerstatus"; }
        else if (cmd == "listunspent") {
            if (pos.size() < 2) { std::cerr << "listunspent: need <address>\n"; return 2; }
            method = "listunspent"; params["address"] = pos[1];
        }
        else if (cmd == "listtransactions") {
            if (pos.size() < 2) { std::cerr << "listtransactions: need <address>\n"; return 2; }
            method = "listtransactions"; params["address"] = pos[1];
        }
        else if (cmd == "getblock") {
            if (pos.size() < 2) { std::cerr << "getblock: need <hash>\n"; return 2; }
            method = "getblock"; params["hash"] = pos[1];
        }
        else if (cmd == "getblockbyheight") {
            if (pos.size() < 2) { std::cerr << "getblockbyheight: need <height>\n"; return 2; }
            method = "getblockbyheight";
            try { params["height"] = std::stoi(pos[1]); }
            catch (...) { std::cerr << "getblockbyheight: height must be an integer\n"; return 2; }
        }
        else if (cmd == "gettransaction") {
            if (pos.size() < 2) { std::cerr << "gettransaction: need <txid>\n"; return 2; }
            method = "gettransaction"; params["txid"] = pos[1];
        }
        else if (cmd == "gettokenmetadata") {
            if (pos.size() < 2) { std::cerr << "gettokenmetadata: need <tokenID>\n"; return 2; }
            method = "gettokenmetadata"; params["tokenID"] = pos[1];
        }
        else if (cmd == "verifytokenbalance") {
            if (pos.size() < 3) { std::cerr << "verifytokenbalance: need <address> <tokenID>\n"; return 2; }
            method = "verifytokenbalance"; params["address"] = pos[1]; params["tokenID"] = pos[2];
        }

        // ---- read-only wrappers (TRU_CLI_READONLY_01) ----------------------
        // Parameter names and types below are taken from the node's handlers,
        // not guessed: gettxout uses "n" (uint32), gettokenutxo uses "vout".
        else if (cmd == "gettxout") {
            if (pos.size() < 3) { std::cerr << "gettxout: need <txid> <n>\n"; return 2; }
            method = "gettxout"; params["txid"] = pos[1];
            uint32_t n = 0;
            if (!parseVout(pos[2], n)) { std::cerr << "gettxout: n must be a non-negative integer\n"; return 2; }
            params["n"] = n;
        }
        else if (cmd == "getrawtransaction") {
            if (pos.size() < 2) { std::cerr << "getrawtransaction: need <txid> [-v]\n"; return 2; }
            method = "getrawtransaction"; params["txid"] = pos[1];
            if (pos.size() > 2 && (pos[2] == "-v" || pos[2] == "verbose" || pos[2] == "1"))
                params["verbose"] = true;
        }
        else if (cmd == "decoderawtransaction") {
            if (pos.size() < 2) { std::cerr << "decoderawtransaction: need <hex>\n"; return 2; }
            method = "decoderawtransaction"; params["txHex"] = pos[1];
        }
        else if (cmd == "getaddresstransactions") {
            if (pos.size() < 2) { std::cerr << "getaddresstransactions: need <address> [count]\n"; return 2; }
            method = "getaddresstransactions"; params["address"] = pos[1];
            if (pos.size() > 2) {
                try { params["count"] = std::stoi(pos[2]); }
                catch (...) { std::cerr << "getaddresstransactions: count must be an integer\n"; return 2; }
            }
        }
        else if (cmd == "getmempooltransactions") { method = "getmempooltransactions"; summary = nullptr; }
        else if (cmd == "getcontracts")           { method = "getcontracts";           summary = nullptr; }
        else if (cmd == "getallminers")           { method = "getallminers";           summary = nullptr; }
        else if (cmd == "getminerstatus") {
            if (pos.size() < 2) { std::cerr << "getminerstatus: need <minerAddress>\n"; return 2; }
            method = "getminerstatus"; params["minerAddress"] = pos[1];
        }
        else if (cmd == "gettokenutxo") {
            if (pos.size() < 3) { std::cerr << "gettokenutxo: need <txid> <vout>\n"; return 2; }
            method = "gettokenutxo"; params["txid"] = pos[1];
            uint32_t vout = 0;
            if (!parseVout(pos[2], vout)) { std::cerr << "gettokenutxo: vout must be a non-negative integer\n"; return 2; }
            params["vout"] = vout;
        }
        else if (cmd == "verifytokenmetadata") {
            if (pos.size() < 2) { std::cerr << "verifytokenmetadata: need <txid>\n"; return 2; }
            method = "verifytokenmetadata"; params["txid"] = pos[1];
        }
        else if (cmd == "verifytokenevolution") {
            if (pos.size() < 2) { std::cerr << "verifytokenevolution: need <tokenID>\n"; return 2; }
            method = "verifytokenevolution"; params["tokenID"] = pos[1];
        }
        else if (cmd == "getTRUScripts") {
            if (pos.size() < 2) { std::cerr << "getTRUScripts: need <ownerAddress>\n"; return 2; }
            method = "getTRUScripts"; params["ownerAddress"] = pos[1];
        }
        else if (cmd == "getTRUScriptDetails") {
            if (pos.size() < 2) { std::cerr << "getTRUScriptDetails: need <txid>\n"; return 2; }
            method = "getTRUScriptDetails"; params["txid"] = pos[1];
        }
        else if (cmd == "listmagiclocks") {
            method = "listmagiclocks";
            if (pos.size() > 1) params["address"] = pos[1];
            summary = nullptr;
        }
        else {
            std::cerr << "Unknown command: " << cmd << "\n"
                      << "Try 'tru-cli --help', or use: tru-cli raw <method> [jsonparams]\n";
            return 2;
        }

        json resp = rpcCall(cfg, method, params);

        // Surface RPC errors clearly.
        if (resp.contains("error") && !resp["error"].is_null()) {
            std::string msg = resp["error"].is_object() && resp["error"].contains("message")
                              ? resp["error"]["message"].get<std::string>()
                              : resp["error"].dump();
            std::cerr << "RPC error: " << msg << "\n";
            return 2;
        }

        if (cfg.rawJson || !summary) {
            printResultRaw(resp);
        } else {
            const json& r = mustResult(resp);
            summary(r);
        }
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
