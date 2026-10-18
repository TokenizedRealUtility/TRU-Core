#pragma once
#include "consensus09_activation.h"
#include "market_lock09.h"
#include <openssl/sha.h>
#include <map>
#include <type_traits>
#include <stdexcept>
#include <string>
namespace tru_commit09 {
using Bytes=std::vector<unsigned char>;
inline void field(Bytes& b,const std::string& s){tru_market09::put(b,s.size(),8);b.insert(b.end(),s.begin(),s.end());}
inline std::string hash256(const Bytes& b){unsigned char a[32],z[32];SHA256(b.data(),b.size(),a);SHA256(a,32,z);return tru_market09::hex(Bytes(z,z+32));}
// Keep non-coinbase txids and their UTXO names stable. Commit the full wire
// payload separately through a unique zero-value coinbase output. No circular
// commitment: coinbase is excluded and its metadata is prohibited.
template<class Block> std::string digest(const Block& b){
    const char tag[]="TRU-BLOCK-PAYLOAD-V1|21e8|";Bytes data(tag,tag+sizeof(tag)-1);
    tru_market09::put(data,b.height,4);tru_market09::put(data,b.transactions.size()-1,8);
    for(size_t i=1;i<b.transactions.size();++i){
        const auto& tx=b.transactions[i];const auto raw=tx.serializeBinary();
        field(data,std::string(raw.begin(),raw.end()));
        // Extra object fields absent from binary encoding may affect legacy
        // execution/indexing. Bind them too; no implicit normalization.
        data.push_back(tx.isCoinbase?1:0);field(data,tx.txid);field(data,tx.sender);
        for(const auto& in:tx.vin){field(data,std::string(in.pubKey.begin(),in.pubKey.end()));field(data,std::string(in.scriptPubKey.begin(),in.scriptPubKey.end()));}
    }
    // JSON objects use sorted string keys. Block metadata is a redundant copy
    // only; check() forbids arbitrary miner-supplied/old-transaction records.
    std::map<std::string,std::string> sorted;
    for(const auto& kv:b.tokenMetadata)sorted.emplace(kv.first,kv.second.dump());
    tru_market09::put(data,sorted.size(),8);for(const auto& kv:sorted){field(data,kv.first);field(data,kv.second);}
    return hash256(data);
}
inline std::string prefix(){return "6a24" "54523039";} // push36 "TR09"+digest
// Mining helper runs after transaction selection and BEFORE Merkle/hash/PoW.
template<class Block> void prepare(Block& b){
    if(!tru09::active(static_cast<uint32_t>(b.height),tru09::COMMITMENT_HEIGHT))return;
    if(b.transactions.empty()||!b.transactions[0].isCoinbase)throw std::runtime_error("09 commitment needs coinbase");
    // These are non-wire caches/convenience fields. They cannot survive a
    // block round trip and must never choose a different state transition.
    for(size_t i=1;i<b.transactions.size();++i){
        b.transactions[i].sender.clear();
        for(auto& in:b.transactions[i].vin)in.scriptPubKey.clear();
    }
    b.tokenMetadata.clear();
    for(size_t i=1;i<b.transactions.size();++i)for(const auto& kv:b.transactions[i].tokenMetadata){
        if(kv.first!=b.transactions[i].txid)throw std::runtime_error("09 metadata must be bound to own txid");
        b.tokenMetadata[kv.first]=kv.second;
    }
    auto& cb=b.transactions[0];cb.tokenMetadata.clear();
    auto& out=cb.vout;
    out.erase(std::remove_if(out.begin(),out.end(),[](const auto& x){return x.scriptPubKey.rfind(prefix(),0)==0;}),out.end());
    typename std::decay_t<decltype(out)>::value_type c;
    c.amount=0;c.scriptPubKey=prefix()+digest(b);out.push_back(c);cb.computeTxId();
}
template<class Block> bool check(const Block& b){
    if(!tru09::active(static_cast<uint32_t>(b.height),tru09::COMMITMENT_HEIGHT))return true;
    if(b.transactions.empty()||!b.transactions[0].isCoinbase||!b.transactions[0].tokenMetadata.empty())return false;
    for(size_t i=1;i<b.transactions.size();++i){
        if(!b.transactions[i].sender.empty())return false;
        for(const auto& in:b.transactions[i].vin)if(!in.scriptPubKey.empty())return false;
    }
    std::map<std::string,std::string> expected,actual;
    for(size_t i=1;i<b.transactions.size();++i)for(const auto& kv:b.transactions[i].tokenMetadata){
        if(kv.first!=b.transactions[i].txid||!kv.second.is_object())return false;expected[kv.first]=kv.second.dump();
    }
    for(const auto& kv:b.tokenMetadata)actual[kv.first]=kv.second.dump();if(actual!=expected)return false;
    unsigned found=0;const auto wanted=prefix()+digest(b);
    for(const auto& o:b.transactions[0].vout){
        // Coinbase token issuance would bypass ordinary token authorization.
        tru_market09::Token t;tru_market09::Terms terms;
        if(tru_market09::tokenShape(o.scriptPubKey)||tru_market09::parseLock(o.scriptPubKey,terms))return false;
        if(o.scriptPubKey.rfind(prefix(),0)==0){if(o.amount||o.scriptPubKey!=wanted)return false;++found;}
    }return found==1;
}
}
