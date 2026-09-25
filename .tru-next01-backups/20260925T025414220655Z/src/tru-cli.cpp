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
    std::cout <<
"tru-cli -- command-line RPC client for the TRU node\n\n"
"Usage:\n"
"  tru-cli [options] <command> [args...]\n"
"  tru-cli [options] raw <method> ['{\"json\":\"params\"}']\n\n"
"Options:\n"
"  -rpcconnect=<ip>   node IP     (default 127.0.0.1)\n"
"  -rpcport=<port>    node port   (default 21832)\n"
"  -conf=<file>       read rpcconnect/rpcport from a tru.conf-style file\n"
"  -json              print raw JSON result instead of a summary\n"
"  -timeout=<sec>     read timeout (default 30)\n"
"  -h, --help         show this help\n\n"
"Common commands:\n"
"  getinfo                          aggregate node + wallet snapshot\n"
"  getbalance [address]             spendable TRU (defaults to wallet addr)\n"
"  getblockcount                    current height\n"
"  getchaininfo                     tip height/hash/difficulty/valid\n"
"  getbestblockhash                 best block hash\n"
"  getdifficulty                    current difficulty (hex)\n"
"  getpeerinfo                      connected peers\n"
"  getconnectioncount               number of peers\n"
"  getnewaddress                    derive a new address\n"
"  listaddresses                    wallet addresses\n"
"  listunspent <address>            spendable UTXOs for an address\n"
"  listtransactions <address>       tx history for an address\n"
"  getblock <hash>                  block by hash\n"
"  getblockbyheight <height>        block by height\n"
"  gettransaction <txid>            transaction detail\n"
"  getrawmempool                    mempool txids\n"
"  gettokenmetadata <tokenID>       token metadata\n"
"  verifytokenbalance <addr> <tid>  token balance for address\n\n"
"Chain / transaction inspection:\n"
"  gettxout <txid> <n>              one UTXO by outpoint\n"
"  getrawtransaction <txid> [-v]    raw tx hex, -v for decoded\n"
"  decoderawtransaction <hex>       decode a raw tx without broadcasting\n"
"  getaddresstransactions <addr> [n]  richer history than listtransactions\n"
"  getmempooltransactions           full mempool entries, not just txids\n\n"
"Mining:\n"
"  getallminers                     every miner this node knows\n"
"  getminerstatus <addr>            one miner's status\n\n"
"Contracts / tokens / scripts:\n"
"  getcontracts                     contracts without the explorer\n"
"  gettokenutxo <txid> <vout>       token UTXO by outpoint\n"
"  verifytokenmetadata <txid>       metadata as committed on chain\n"
"  verifytokenevolution <tokenID>   evolution chain for a token\n"
"  getTRUScripts <ownerAddress>     TRUscriptions owned by an address\n"
"  getTRUScriptDetails <txid>       one TRUscription\n"
"  listmagiclocks [address]         magic locks, optionally filtered\n\n"
"  raw <method> [jsonparams]        call ANY node method directly\n\n"
"Money-moving and HTLC methods are reachable through 'raw' only, on purpose.\n"
"Funding, claim, refund and prepared-broadcast belong to the Swap Agent, which\n"
"keeps the durable journal these commands would bypass.\n\n"
"Examples:\n"
"  tru-cli getinfo\n"
"  tru-cli getbalance 1Fyuq4Nzy65isRXwcbpaHaZJbcGPkS57hb\n"
"  tru-cli -rpcconnect=137.184.68.43 getblockcount\n"
"  tru-cli raw gettokenmetadata '{\"tokenID\":\"cottage\"}'\n"
"  tru-cli gettxout f5306c5d2ff3...0e9a 1\n"
"  tru-cli getaddresstransactions TQAwikxL4W5KcRSLP6KDPJpx86gkdFYxnZ 25\n";
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
                  << "chainvalid    " << (r.value("chainvalid", false) ? "yes" : "no") << "\n"
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
                  << "chainValid " << (r.value("chainValid", false) ? "yes" : "no") << "\n";
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
