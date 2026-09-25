#pragma once
// TRU-DESKTOP-07B: unsigned Voting V1 transaction builders and read-only
// confirmed-state snapshots for local self-custody desktop signing.
// Included only after RPC helpers in rpc_server.cpp; never reads wallet keys.
#include "contract_state_lineage.h"
#include "contract_state_runtime.h"
#include "contract_call_policy.h"
#include "contract_call_envelope.h"
#include <ctime>
#include <cmath>

namespace tru_desktop_voting_rpc_07b {
static bool atomText(const json& value, uint64_t& out) {
    if(!value.is_string())return false;
    const auto text=value.get<std::string>();
    if(text.empty() || text.size()>20 || text.find_first_not_of("0123456789")!=std::string::npos)return false;
    try {out=std::stoull(text);return out<=tru_limits::MAX_MONEY;}catch(...){return false;}
}
static bool bounded(const json& v,size_t max){return v.is_string() && !v.get<std::string>().empty() &&
    v.get<std::string>().size()<=max;}
static std::vector<unsigned char> bytes(const std::string& s){return {s.begin(),s.end()};}
static std::vector<unsigned char> le64(uint64_t n){
    std::vector<unsigned char> out(8,0);
    for(unsigned i=0;i<8;++i)out[i]=static_cast<unsigned char>((n>>(8*i))&255U);
    return out;
}
static json load(Blockchain& chain,const std::string& root,
                 tru_contract_state_runtime::ConfirmedStateDomainSnapshot& snapshot,
                 std::string& live,std::size_t& num,uint64_t& end,
                 uint64_t& votes,std::string& reason){
    if(!tru_contract_state::IsCanonicalContractOutpoint(root))return makeError(-32602,"invalid voting root");
    auto* db=chain.getStorage();if(!db)return makeError(-32091,"chain storage unavailable");
    bool found=false;
    if(!db->getRaw(tru_contract_state::BuildContractLiveKey(root),live,found) || !found ||
       !tru_contract_state::IsCanonicalContractOutpoint(live))
        return makeError(-32092,"voting root has no confirmed live anchor");
    if(!tru_contract_state_runtime::LoadConfirmedStateDomain(*db,live,snapshot,reason) ||
       snapshot.root!=root || snapshot.family!="voting_v1" ||
       !tru_contract_state_runtime::ValidateVotingV1State(snapshot.state,num,end,reason) ||
       !tru_contract_state_runtime::ReadVotingU64(snapshot.state,"totalvotes",votes))
        return makeError(-32093,"confirmed Voting V1 state is invalid: "+reason);
    return nullptr;
}
static bool funding(Blockchain& chain,const json& p,
                    const std::string& addr, uint64_t minimum,
                    std::string& txid,uint32_t& n,uint64_t& amount,std::string& script){
    if(!p.contains("utxo") || !p["utxo"].is_object())return false;
    const json& u=p["utxo"];
    if(!u.contains("txid") || !u["txid"].is_string() ||
       !u.contains("vout") || !u["vout"].is_number_integer() ||
       !u.contains("amount_atoms") || !atomText(u["amount_atoms"],amount))return false;
    txid=u["txid"].get<std::string>();
    if(txid.size()!=64 || txid.find_first_not_of("0123456789abcdef")!=std::string::npos ||
       u["vout"].get<int64_t>()<0 || u["vout"].get<int64_t>()>UINT32_MAX)return false;
    n=u["vout"].get<uint32_t>();
    UTXO confirmed;
    if(!chain.utxoSet.getUTXO(txid,n,confirmed))return false;
    script=createP2PKHScriptHexFromAddress(addr);
    return confirmed.scriptPubKey==script && confirmed.amount==amount && amount>=minimum;
}
static json snapshot(Blockchain& chain,const json& p,int id){
    try {
        if(!p.is_object() || !p.contains("root") || !p["root"].is_string())
            return makeError(-32602,"root required");
        const auto root=p["root"].get<std::string>();
        tru_contract_state_runtime::ConfirmedStateDomainSnapshot s;
        std::string live,reason;size_t num=0;uint64_t end=0,votes=0;
        auto err=load(chain,root,s,live,num,end,votes,reason);
        if(!err.is_null())return err;
        json options=json::array(),counts=json::array();
        for(size_t i=0;i<num;++i){
            auto it=s.state.find("option"+std::to_string(i));
            uint64_t count=0;
            if(it==s.state.end() || !tru_contract_state_runtime::ReadVotingU64(s.state,
                "count"+std::to_string(i),count))return makeError(-32093,"invalid confirmed option");
            options.push_back(std::string(it->second.begin(),it->second.end()));
            counts.push_back(std::to_string(count));
        }
        auto it=s.state.find("proposal");
        if(it==s.state.end())return makeError(-32093,"missing proposal");
        std::string liveTx;uint32_t liveN=0;UTXO liveUtxo;
        if(!tru_contract_state::ParseCanonicalContractOutpoint(live,liveTx,liveN) ||
           !chain.utxoSet.getUTXO(liveTx,liveN,liveUtxo) || liveUtxo.scriptPubKey!="f751")
            return makeError(-32093,"confirmed voting anchor unavailable");
        json result{{"root",root},{"live",live},
          {"anchor_atoms",std::to_string(liveUtxo.amount)},
          {"anchor_script",liveUtxo.scriptPubKey},
          {"proposal",std::string(it->second.begin(),it->second.end())},
          {"options",options},{"counts",counts},{"totalVotes",std::to_string(votes)},
          {"endTime",std::to_string(end)}};
        if(p.contains("voterAddress") && p["voterAddress"].is_string()){
            const std::string addr=p["voterAddress"].get<std::string>();
            if(addr.empty() || !chain.isValidAddress(addr))return makeError(-32602,"invalid voterAddress");
            std::string hash;
            if(!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
               createP2PKHScriptHexFromAddress(addr),hash))return makeError(-32602,"non-P2PKH voter");
            result["alreadyVoted"]=s.state.find("voted:"+hash)!=s.state.end();
        }
        return makeResult(id,result);
    }catch(const std::exception&){return makeError(-32094,"voting snapshot unavailable");}
}
static json create(Blockchain& chain,const json& p,int id){
    try {
        if(!p.is_object() || !p.contains("proposal") || !bounded(p["proposal"],200) ||
            !p.contains("name") || !bounded(p["name"],35) ||
            !p.contains("options") || !p["options"].is_array() ||
            p["options"].size()<2 || p["options"].size()>10 ||
            !p.contains("endTime") || !p["endTime"].is_number() ||
            !p.contains("amount_atoms") || !p.contains("senderAddress") ||
            !p["senderAddress"].is_string())
            return makeError(-32602,"invalid Voting V1 proposal/name/options/endTime/amount/sender");
        // Qt JSON stores numbers as doubles. Accept only mathematically exact
        // seconds within uint32; reject fractional/NaN/overflow before casting.
        const double endDouble=p["endTime"].get<double>();
        if(!std::isfinite(endDouble) || std::floor(endDouble)!=endDouble ||
           endDouble<=static_cast<double>(std::time(nullptr)) || endDouble>UINT32_MAX)
            return makeError(-32602,"invalid future endTime seconds");
        const auto endSeconds=static_cast<std::uint64_t>(endDouble);
        const auto addr=p["senderAddress"].get<std::string>();
        if(!chain.isValidAddress(addr))return makeError(-32602,"invalid creator address");
        uint64_t amount=0;constexpr uint64_t fee=10000;
        if(!atomText(p["amount_atoms"],amount) || amount<546 || amount>tru_limits::MAX_MONEY-fee)
            return makeError(-32602,"invalid anchor amount atoms");
        tru_contract_state_init::StateInitEnvelope init;init.targetVout=1;
        const auto proposal=p["proposal"].get<std::string>();
        init.entries.emplace_back("proposal",bytes(proposal));
        init.entries.emplace_back("numoptions",std::vector<unsigned char>{static_cast<unsigned char>(p["options"].size())});
        init.entries.emplace_back("endtime",le64(endSeconds));
        const auto zero=le64(0);
        for(size_t i=0;i<p["options"].size();++i){
            if(!bounded(p["options"][i],50))return makeError(-32602,"option must be 1..50 bytes");
            init.entries.emplace_back("option"+std::to_string(i),bytes(p["options"][i].get<std::string>()));
            init.entries.emplace_back("count"+std::to_string(i),zero);
        }
        init.entries.emplace_back("totalvotes",zero);
        std::sort(init.entries.begin(),init.entries.end(),
            [](const auto& a,const auto& b){return a.first<b.first;});
        std::string reason;
        if(!tru_contract_call::IsCanonicalVotingV1InitEnvelope(init,reason))
            return makeError(-32602,"invalid Voting V1 initialization: "+reason);
        std::vector<unsigned char> initScript;
        if(!tru_contract_state_init::BuildOpReturnScript(init,initScript))
            return makeError(-32095,"could not build canonical TRUSTATE");
        std::string tid;uint32_t vout=0;uint64_t in=0;std::string ownerScript;
        if(!funding(chain,p,addr,amount+fee,tid,vout,in,ownerScript))
            return makeError(-32602,"creator input not an exact confirmed owned P2PKH UTXO");
        Transaction tx;tx.version=1;tx.lockTime=0;tx.vin.emplace_back(tid,vout);
        std::string marker="TRU_CONTRACT:"+p["name"].get<std::string>();
        if(marker.size()>80)return makeError(-32602,"name too large for marker");
        tx.vout.emplace_back(0,"6a"+fmt::format("{:02x}",marker.size())+bytesToHex(bytes(marker)));
        tx.vout.emplace_back(amount,"f751");
        tx.vout.emplace_back(0,bytesToHex(initScript));
        const uint64_t change=in-amount-fee;
        if(change>546)tx.vout.emplace_back(change,ownerScript);
        tx.computeTxId();
        return makeResult(id,json{{"unsignedTxHex",hexEncode(tx.serializeBinary())},
            {"root",tx.txid+":1"},{"initScriptHex",bytesToHex(initScript)},
            {"anchor_atoms",std::to_string(amount)},
            {"change_atoms",std::to_string(change>546?change:0)}});
    }catch(const std::exception&){return makeError(-32096,"Voting V1 unsigned creation failed");}
}
static json ballot(Blockchain& chain,const json& p,int id){
    try {
        if(!p.is_object() || !p.contains("root") || !p["root"].is_string() ||
           !p.contains("choice") || !p["choice"].is_number_integer() ||
           !p.contains("senderAddress") || !p["senderAddress"].is_string())
            return makeError(-32602,"invalid vote root/choice/address");
        const auto root=p["root"].get<std::string>();
        const auto addr=p["senderAddress"].get<std::string>();
        if(!chain.isValidAddress(addr))return makeError(-32602,"invalid voter address");
        tru_contract_state_runtime::ConfirmedStateDomainSnapshot s;
        std::string live,reason;size_t num=0;uint64_t end=0,votes=0;
        const auto err=load(chain,root,s,live,num,end,votes,reason);
        if(!err.is_null())return err;
        const int64_t choice=p["choice"].get<int64_t>();
        if(choice<0 || static_cast<uint64_t>(choice)>=num)return makeError(-32602,"choice out of range");
        if(static_cast<uint64_t>(std::time(nullptr))>end)return makeError(-32097,"vote expired");
        const auto senderScript=createP2PKHScriptHexFromAddress(addr);
        std::string senderHash;
        if(!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(senderScript,senderHash))
            return makeError(-32602,"non-canonical voter");
        if(s.state.count("voted:"+senderHash))return makeError(-32097,"address already voted");
        const std::string countKey="count"+std::to_string(choice);
        uint64_t current=0;
        if(!tru_contract_state_runtime::ReadVotingU64(s.state,countKey,current) || current==UINT64_MAX)
            return makeError(-32097,"vote counter overflow/missing");
        std::vector<unsigned char> unlock;
        if(!tru_contract_call::BuildStatefulKvV1UnlockScript(countKey,le64(current+1),unlock))
            return makeError(-32097,"bad canonical vote script");
        std::string liveTx;uint32_t liveN=0;
        if(!tru_contract_state::ParseCanonicalContractOutpoint(live,liveTx,liveN))
            return makeError(-32097,"malformed live anchor");
        UTXO anchor;
        if(!chain.utxoSet.getUTXO(liveTx,liveN,anchor) || anchor.scriptPubKey!="f751")
            return makeError(-32097,"confirmed live anchor no longer available");
        std::string tid;uint32_t n=0;uint64_t in=0;std::string voterScript;
        constexpr uint64_t fee=10000;
        if(!funding(chain,p,addr,fee+546,tid,n,in,voterScript) || (tid==liveTx && n==liveN))
            return makeError(-32602,"fee input must be a separate confirmed owned P2PKH UTXO");
        Transaction tx;tx.version=1;tx.lockTime=0;
        tx.vin.emplace_back(liveTx,liveN);tx.vin[0].scriptSig=unlock;
        tx.vin.emplace_back(tid,n);
        tx.vout.emplace_back(anchor.amount,anchor.scriptPubKey);
        tru_contract_call_envelope::StateCallEnvelope envelope;
        envelope.targetInput=0;envelope.continuationVout=0;
        if(!tru_contract_call::ComputeUnlockScriptSha256(unlock,envelope.unlockScriptSha256))
            return makeError(-32097,"could not hash vote calldata");
        std::vector<unsigned char> callScript;
        if(!tru_contract_call_envelope::BuildOpReturnScript(envelope,callScript))
            return makeError(-32097,"could not build TRUCALL");
        tx.vout.emplace_back(0,bytesToHex(callScript));
        const uint64_t change=in-fee;
        if(change)tx.vout.emplace_back(change,voterScript);
        tx.computeTxId();
        return makeResult(id,json{{"unsignedTxHex",hexEncode(tx.serializeBinary())},
          {"root",root},{"live",live},{"choice",choice},
          {"previous_count",std::to_string(current)},
          {"unlockScriptHex",bytesToHex(unlock)},
          {"callScriptHex",bytesToHex(callScript)},
          {"anchorScriptHex",anchor.scriptPubKey},
          {"anchor_atoms",std::to_string(anchor.amount)}});
    }catch(const std::exception&){return makeError(-32098,"Voting V1 unsigned ballot failed");}
}
} // namespace tru_desktop_voting_rpc_07b
