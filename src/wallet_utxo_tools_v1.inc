// UTXO-TOOLS-01: privileged, local wallet self-management. No consensus changes.
// Included inside rpc_server.cpp's existing local-wallet RPC namespace.
namespace tru_utxo_tools_v1 {
constexpr size_t MAX_INPUTS = 100, MAX_OUTPUTS = 100, MAX_SCAN = 10000;
static void need(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
static void keys(const json& p, std::initializer_list<const char*> allowed) {
    need(p.is_object(), "Expected JSON object");
    for (auto it=p.begin(); it!=p.end(); ++it) {
        bool found=false; for (const char* k:allowed) if(it.key()==k) found=true;
        need(found,"Unexpected parameter");
    }
}
static uint64_t amount(const json& p, const char* key) {
    need(p.contains(key) && p.at(key).is_string(), "Amounts must be decimal TRU strings");
    uint64_t n=0; std::string error;
    need(parseJsonTRUAmount(p.at(key),n,error) && n>0 && n<=tru_limits::MAX_MONEY,"Invalid positive amount");
    return n;
}
static uint64_t add(uint64_t a,uint64_t b) {
    need(a<=tru_limits::MAX_MONEY && b<=tru_limits::MAX_MONEY-a,"Amount overflow"); return a+b;
}
static std::string outpoint(const UTXO& u) { return u.txid+":"+std::to_string(u.vout); }
struct Coin { UTXO u; std::string address; std::string excluded; };
static Coin classify(Blockchain& chain,const UTXO& u,const std::string& address,
                     const std::string& script,int tip) {
            Coin c{u,address,""}; std::string reserved;
            if(u.scriptPubKey!=script) c.excluded="nonstandard_or_contract";
            else if(chain.getStorage()->exists("tokenUTXO:"+outpoint(u))) c.excluded="token_control";
            else if(chain.getStorage()->getWithDataChecksum(tru_swap_prepared_funding::inputKey(u.txid,u.vout),reserved)) c.excluded="reserved";
            else if(u.createdAtHeight>static_cast<uint32_t>(tip)) c.excluded="unconfirmed";
            else if(u.isCoinbase && static_cast<uint64_t>(tip)+1 < static_cast<uint64_t>(u.createdAtHeight)+COINBASE_MATURITY) c.excluded="immature_coinbase";
            else if(chain.mempool->isUTXOSpentInMempool(u.txid,u.vout)) c.excluded="pending_spend";
            else if(u.amount==0) c.excluded="zero_value";
    return c;
}
// PERF01: address-scoped enumeration only for the enrolled Arcade wallet.
// Keep the same per-coin classification as inventory(); no cache or policy relaxation.
// prepare()/submit() still revalidate each explicit outpoint through selected().
static std::vector<Coin> scanEnrolledAddress(Blockchain& chain,Wallet& wallet,const std::string& address) {
    need(wallet.isLocalChainAvailable() && chain.getStorage() && chain.mempool,
         "Local chain/storage/mempool required");
    const int tip=chain.getBestTipHeight(); need(tip>=0 && tip<INT_MAX,"Invalid tip");
    const auto addresses=wallet.getAddresses();
    need(addresses.size()<=MAX_SCAN,"Too many addresses for this bounded tool");
    need(std::find(addresses.begin(),addresses.end(),address)!=addresses.end(),
         "Enrolled address is not owned by this Core wallet");
    const auto script=createP2PKHScriptHexFromAddress(address);
    std::vector<Coin> result;
    std::set<std::string> seen;
    for(const auto& u:chain.utxoSet.getUTXOsForAddress(address)) {
        if(!seen.insert(outpoint(u)).second)continue;
        need(result.size()<MAX_SCAN,"Too many address UTXOs for this bounded tool");
        result.push_back(classify(chain,u,address,script,tip));
    }
    return result;
}

static std::vector<Coin> scan(Blockchain& chain, Wallet& wallet) {
    need(wallet.isLocalChainAvailable() && chain.getStorage() && chain.mempool,"Local chain/storage/mempool required");
    const int tip=chain.getBestTipHeight(); need(tip>=0 && tip<INT_MAX,"Invalid tip");
    const auto addresses=wallet.getAddresses(); need(addresses.size()<=MAX_SCAN,"Too many addresses for this bounded tool");
    std::vector<Coin> result; std::set<std::string> seen;
    for(const auto& address:addresses) {
        const auto script=createP2PKHScriptHexFromAddress(address);
        for(const auto& u:chain.utxoSet.getUTXOsForAddress(address)) {
            if(!seen.insert(outpoint(u)).second) continue;
            need(result.size()<MAX_SCAN,"Too many UTXOs for this bounded tool");
            Coin c=classify(chain,u,address,script,tip);
            result.push_back(c);
        }
    }
    return result;
}
static json inventory(Blockchain& chain,Wallet& wallet) {
    json coins=json::array(), addresses=json::object(); uint64_t total=0; size_t eligible=0;
    for(const auto& a:wallet.getAddresses()) addresses[a]={{"eligible_atoms",0},{"eligible_utxos",0}};
    for(const auto& c:scan(chain,wallet)) {
        const bool ok=c.excluded.empty();
        if(ok) { total=add(total,c.u.amount); ++eligible;
            auto& a=addresses[c.address]; a["eligible_atoms"]=add(a["eligible_atoms"].get<uint64_t>(),c.u.amount);
            a["eligible_utxos"]=a["eligible_utxos"].get<size_t>()+1;
        }
        coins.push_back({{"txid",c.u.txid},{"vout",c.u.vout},{"address",c.address},
            {"amount_atoms",c.u.amount},{"amount",tru_amount::formatNumeric(c.u.amount)},
            {"eligible",ok},{"excluded_reason",c.excluded}});
    }
    return {{"tool_version",1},{"scope","confirmed ordinary P2PKH self-management funds; excludes pending, reserved, token and contract outputs"},
        {"eligible_atoms",total},{"eligible_balance",tru_amount::formatNumeric(total)},
        {"eligible_utxos",eligible},{"addresses",addresses},{"utxos",coins},{"height",chain.getBestTipHeight()}};
}
static json coinRefs(const std::vector<Coin>& coins) {
    json refs=json::array(); for(const auto& c:coins) refs.push_back({{"txid",c.u.txid},{"vout",c.u.vout}}); return refs;
}
static std::vector<Coin> choose(const json& p, const std::vector<Coin>& all, uint64_t target, bool consolidate) {
    std::vector<Coin> result;
    if(p.contains("inputs")) {
        need(p.at("inputs").is_array() && !p.at("inputs").empty() && p.at("inputs").size()<=MAX_INPUTS,"Expected 1..100 inputs");
        std::set<std::string> seen;
        for(const auto& r:p.at("inputs")) {
            keys(r,{"txid","vout"});
            need(r.contains("txid") && r.at("txid").is_string() && r.contains("vout") && r.at("vout").is_number_integer(),"Invalid input reference");
            const auto v=r.at("vout").get<int64_t>(); need(v>=0 && v<=INT_MAX,"Invalid output index");
            const auto txid=r.at("txid").get<std::string>(); need(txid.size()==64 && isHex(txid),"Invalid txid");
            const auto name=txid+":"+std::to_string(v); need(seen.insert(name).second,"Duplicate input");
            auto it=std::find_if(all.begin(),all.end(),[&](const Coin& c){return outpoint(c.u)==name;});
            need(it!=all.end() && it->excluded.empty(),"Input missing, unavailable, or not an ordinary wallet coin");
            result.push_back(*it);
        }
    } else {
        std::vector<Coin> candidates;
        for(const auto& c:all) if(c.excluded.empty()) candidates.push_back(c);
        // Prefer large inputs for a split; consolidation takes bounded small coins.
        std::sort(candidates.begin(),candidates.end(),[&](const Coin& a,const Coin& b){
            if(a.u.amount!=b.u.amount) return consolidate ? a.u.amount<b.u.amount : a.u.amount>b.u.amount;
            return outpoint(a.u)<outpoint(b.u);
        });
        uint64_t sum=0;
        for(const auto& c:candidates) { if(result.size()==MAX_INPUTS) break; result.push_back(c); sum=add(sum,c.u.amount); if(!consolidate && sum>=target) break; }
    }
    need(!result.empty(),"No eligible coins"); return result;
}
// Explicit inputs use canonical outpoint reads, never address-index membership.
// Both pre-sign and post-sign prepare calls perform these checks afresh.
static std::vector<Coin> selected(Blockchain& chain,Wallet& wallet,const json& p) {
    need(wallet.isLocalChainAvailable() && chain.getStorage() && chain.mempool,"Local chain/storage/mempool required");
    const int tip=chain.getBestTipHeight(); need(tip>=0 && tip<INT_MAX,"Invalid tip");
    const auto addresses=wallet.getAddresses(); need(addresses.size()<=MAX_SCAN,"Too many addresses for this bounded tool");
    std::map<std::string,std::string> owners;
    for(const auto& address:addresses) owners.emplace(createP2PKHScriptHexFromAddress(address),address);
    const auto& refs=p.at("inputs");
    need(refs.is_array() && !refs.empty() && refs.size()<=MAX_INPUTS,"Expected 1..100 inputs");
    std::set<std::string> seen; std::vector<Coin> result;
    for(const auto& r:refs) {
        keys(r,{"txid","vout"});
        need(r.contains("txid") && r.at("txid").is_string() && r.contains("vout") && r.at("vout").is_number_integer(),"Invalid input reference");
        const auto v=r.at("vout").get<int64_t>(); need(v>=0 && v<=INT_MAX,"Invalid output index");
        const auto txid=r.at("txid").get<std::string>(); need(txid.size()==64 && isHex(txid),"Invalid txid");
        need(seen.insert(txid+":"+std::to_string(v)).second,"Duplicate input");
        UTXO u;
        need(chain.utxoSet.getUTXO(txid,static_cast<uint32_t>(v),u),"Input missing or spent");
        need(u.txid==txid && u.vout==static_cast<uint32_t>(v),"Outpoint lookup mismatch");
        const auto owner=owners.find(u.scriptPubKey);
        need(owner!=owners.end(),"Input is not an ordinary wallet coin");
        auto c=classify(chain,u,owner->second,owner->first,tip);
        need(c.excluded.empty(),"Input unavailable or excluded");
        result.push_back(c);
    }
    return result;
}
struct Prepared { Transaction tx; std::vector<Coin> coins; json plan; uint64_t fee; };
static Prepared prepare(Blockchain& chain,Wallet& wallet,const json& p) {
    keys(p,{"action","mode","address","count","amount","max_fee","inputs","op_return_script_hex"});
    need(p.contains("address") && p.at("address").is_string(),"Destination required");
    const auto address=p.at("address").get<std::string>();
    const auto owned=wallet.getAddresses();
    need(chain.isValidAddress(address) && std::find(owned.begin(),owned.end(),address)!=owned.end(),"Destination must belong to this wallet");
    const auto mode=p.value("mode",std::string("split")); need(mode=="split" || mode=="consolidate" || mode=="pay" || mode=="anchor","Invalid mode");
    const bool consolidate=mode=="consolidate";
    const bool anchor=(mode=="anchor"); std::string anchorScript;
    if(anchor) {
        need(!p.contains("count") && !p.contains("amount"),"Anchor carries no payments");
        need(p.contains("op_return_script_hex") && p.at("op_return_script_hex").is_string(),"Missing anchor script");
        anchorScript=p.at("op_return_script_hex").get<std::string>();
        need(anchorScript.size()>=82 && anchorScript.size()<=154 && isHex(anchorScript),"Invalid anchor script");
        const auto b=hexDecode(anchorScript);
        need(b.size()>=41 && b.size()<=77 && b[0]==0x6a && b[1]==b.size()-2,"Noncanonical OP_RETURN");
        need(b[2]=='T' && b[3]=='R' && b[4]=='U' && b[5]=='A' && b[6]=='1',"Not TRUA1");
        size_t pos=39; need(pos<b.size(),"No name length");
        const size_t nl=b[pos++];need(nl<=24 && pos+nl<b.size(),"Bad name length");pos+=nl;
        const size_t sl=b[pos++];need(sl<=36 && nl+sl<=36 && pos+sl==b.size(),"Bad statement length");
    } else need(!p.contains("op_return_script_hex"),"Unexpected anchor data");
    uint64_t each=0, outputTotal=0; size_t count=anchor?0:1;
    if(anchor) { /* OP_RETURN + self-change only. */ }
    else if(mode=="pay") {
        need(!p.contains("count"),"Pay does not take count");
        each=amount(p,"amount"); need(each>=tru_limits::MIN_OUTPUT_DUST_ATOMS,"Output below dust threshold");
        outputTotal=each;
    } else if(!consolidate) {
        need(p.contains("count") && p.at("count").is_number_integer(),"Integer count required");
        const auto n=p.at("count").get<int64_t>(); need(n>=2 && n<=99,"Split count must be 2..99; one slot reserved for change"); count=static_cast<size_t>(n);
        each=amount(p,"amount"); need(each>=tru_limits::MIN_OUTPUT_DUST_ATOMS,"Output below dust threshold");
        need(each<=tru_limits::MAX_MONEY/count,"Output total overflow"); outputTotal=each*count;
    } else need(!p.contains("amount") && !p.contains("count"),"Consolidation does not take count/amount");
    const auto cap=amount(p,"max_fee");
    auto coins=choose(p,p.contains("inputs") ? selected(chain,wallet,p) : scan(chain,wallet),add(outputTotal,cap),consolidate);
    uint64_t total=0; Transaction tx(false);
    for(const auto& c:coins) { total=add(total,c.u.amount); tx.vin.emplace_back(c.u.txid,c.u.vout); }
    need(total>=add(outputTotal,cap),"Insufficient selected funds including maximum-fee reserve");
    const auto script=createP2PKHScriptHexFromAddress(address);
    for(size_t i=0;i<count;++i) tx.vout.emplace_back(consolidate?total:each,script);
    if(anchor) tx.vout.emplace_back(0,anchorScript);
    // Size an upper-bound signed transaction, including a possible change output.
    if(!consolidate) tx.vout.emplace_back(total-outputTotal,script);
    Transaction sized=tx;
    for(auto& input:sized.vin) input.scriptSig.assign(110,0);
    const uint64_t fee=std::max<uint64_t>(10000,sized.serializeBinary().size()*tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE);
    need(fee<=cap,"Estimated fee exceeds max_fee");
    uint64_t actualFee=fee;
    if(consolidate) { need(total-fee>=tru_limits::MIN_OUTPUT_DUST_ATOMS,"Consolidated output below dust"); tx.vout[0].amount=total-fee; }
    else {
        const auto change=total-outputTotal-fee;
        if(change>=tru_limits::MIN_OUTPUT_DUST_ATOMS) tx.vout.back().amount=change;
        else { tx.vout.pop_back(); actualFee=add(fee,change); need(actualFee<=cap,"Dust change would exceed max_fee"); }
    }
    need(tx.vout.size()<=MAX_OUTPUTS,"Too many outputs"); tx.computeTxId();
    json request={{"mode",mode},{"address",address},{"max_fee",tru_amount::formatNumeric(cap)},{"inputs",coinRefs(coins)}};
    if(anchor) request["op_return_script_hex"]=anchorScript;
    if(!consolidate && !anchor) {if(mode=="split") request["count"]=count;request["amount"]=tru_amount::formatNumeric(each);}
    json outputs=json::array(); for(size_t i=0;i<tx.vout.size();++i) {
        json output={{"vout",i},{"amount_atoms",tx.vout[i].amount},{"amount",tru_amount::formatNumeric(tx.vout[i].amount)}};
        if(anchor && i==0) {output["type"]="arcade_op_return";output["script_hex"]=anchorScript;}
        else output["address"]=address;
        outputs.push_back(output);
    }
    json plan={{"tool_version",1},{"request",request},{"txid",tx.txid},{"unsigned_hex",bytesToHex(tx.serializeBinary())},
        {"input_atoms",total},{"fee_atoms",actualFee},{"fee",tru_amount::formatNumeric(actualFee)},
        {"inputs_count",coins.size()},{"outputs_count",tx.vout.size()},{"outputs",outputs},
        {"utxo_count_change",static_cast<int>(tx.vout.size())-static_cast<int>(coins.size())},
        {"broadcast",false},{"note","Preview only. Inputs are not reserved; submission rechecks availability. Combining addresses links them publicly."}};
    return {tx,coins,plan,actualFee};
}
static json run(Blockchain& chain,Wallet& wallet,const json& p,int id,const std::string& peer,bool arcadeAuthorized=false) {
    try {
        need(rpcLocalPeer(peer),"UTXO tools require local authenticated RPC");
        need(p.is_object(),"Expected parameters object"); const auto action=p.value("action",std::string("list"));
        std::lock_guard<std::mutex> guard(g_cliSendMutex);
        if(action=="list") {keys(p,{"action"}); return makeResult(id,inventory(chain,wallet));}
        need(action=="prepare" || action=="submit","Unknown UTXO action");
        need(!chain.getForkRecoveryInfo().value("execution_halted",true),"Fork recovery halted");
        if(action=="prepare") return makeResult(id,prepare(chain,wallet,p).plan);
        keys(p,{"action","plan","confirm"});
        need(arcadeAuthorized || rpcEnvEnabled("TRU_RPC_WALLET_SEND_ENABLE"),"Wallet sends disabled");
        need(p.contains("plan") && p.at("plan").is_object() && p.value("confirm",std::string())=="SUBMIT","Explicit confirm=SUBMIT required");
        const auto& reviewed=p.at("plan");
        need(reviewed.contains("request"),"Missing reviewed request");
        if(arcadeAuthorized) {
            const auto& r=reviewed.at("request");
            need(r.value("mode",std::string())=="anchor","Arcade only permits OP_RETURN anchor mode");
            need(r.contains("op_return_script_hex") && r.at("op_return_script_hex").is_string(),"Missing arcade script");
            need(reviewed.at("fee_atoms").get<uint64_t>()<=1000000ULL,"Absolute 06B fee ceiling exceeded");
        }
        auto built=prepare(chain,wallet,reviewed.at("request"));
        need(reviewed==built.plan,"Preview changed or was edited; prepare and review again");
        wallet.requirePrivateAccess("UTXO self-management submission");
        // Sign only the exact re-created, reviewed ordinary transaction; keys stay in Core.
        for(size_t i=0;i<built.coins.size();++i) {
            const auto& c=built.coins[i];
            auto key=ECDSAKey::fromPrivateKey(wallet.getPrivateKeyForAddress(c.address));
            const auto pub=key.getCompressedSec1(); need(pubkeyToAddress(pub)==c.address,"Wallet signing key mismatch");
            auto hash=built.tx.getSigHash(i,hexDecode(c.u.scriptPubKey));
            auto sig=key.sign(std::string(hash.begin(),hash.end())); sig.push_back(1);
            need(sig.size()<76 && pub.size()==33,"Unexpected signature/public key size");
            auto& ss=built.tx.vin[i].scriptSig; ss.push_back(static_cast<unsigned char>(sig.size()));
            ss.insert(ss.end(),sig.begin(),sig.end()); ss.push_back(static_cast<unsigned char>(pub.size())); ss.insert(ss.end(),pub.begin(),pub.end());
        }
        built.tx.computeTxId(); need(built.tx.txid==reviewed.at("txid").get<std::string>(),"Signed transaction ID changed unexpectedly");
        const auto bytes=built.tx.serializeBinary().size();
        need(bytes<=tru_limits::MAX_CONSENSUS_TX_BYTES && built.fee>=bytes*tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE,"Signed transaction exceeds fee/size budget");
        need(!chain.getForkRecoveryInfo().value("execution_halted",true),"Fork recovery halted before broadcast");
        need(prepare(chain,wallet,reviewed.at("request")).plan==reviewed,"Inputs changed while signing; prepare again");
        need(chain.broadcastTransaction(built.tx),"Mempool rejected submission; check transaction ID before retrying");
        return makeResult(id,json{{"txid",built.tx.txid},{"accepted",true},{"broadcast",true},{"fee_atoms",built.fee},{"confirmed",false}});
    } catch(const std::exception& e) { return makeError(-32120,e.what()); }
}
} // namespace tru_utxo_tools_v1
