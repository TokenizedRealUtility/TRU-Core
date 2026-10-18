#pragma once
#include "market_lock09.h"
#include <string>
namespace tru_meta09 {
// Attached JSON may describe a token; it cannot invent a control or choose
// issuance index owner/quantity independently of its signed binary outputs.
template<class Tx,class Exists,class MetaHash,class Address> bool validate(
        const Tx& tx,Exists exists,MetaHash hash,Address address) {
    try {
        for(const auto& kv:tx.tokenMetadata){
            const auto& m=kv.second;
            if(kv.first!=tx.txid||!m.is_object())return false;
            if(!m.contains("tokenID"))continue;
            if(!m.at("tokenID").is_string()||!m.contains("type")||!m.at("type").is_string()||
               !m.contains("meta")||!m.at("meta").is_object())return false;
            const std::string id=m.at("tokenID").template get<std::string>();
            bool found=false;
            for(size_t n=1;n<tx.vout.size();++n){
                tru_market09::Token tok;if(!tru_market09::branch(tx,n,tok)||tok.asset.id!=id)continue;
                const char* names[]={"","FT","NFT","SFT","NCFT"};
                if(m.at("type").template get<std::string>()!=names[tok.asset.type]||hash(m.at("meta"))!=tok.asset.meta)return false;
                if(!exists(id)){
                    if(!m.contains("owner")||!m.at("owner").is_string()||m.at("owner").template get<std::string>()!=address(tok.owner))return false;
                    if(!m.contains("amount"))return false;
                    const auto& amount=m.at("amount");
                    if(amount.is_string()){if(amount.template get<std::string>()!=std::to_string(tok.amount))return false;}
                    else if(!(amount.is_number_unsigned()||(amount.is_number_integer()&&amount.template get<int64_t>()>=0))||amount.template get<uint64_t>()!=tok.amount)return false;
                    if(m.contains("controllingVout")){
                        const auto& control=m.at("controllingVout");
                        if(!(control.is_number_unsigned()||(control.is_number_integer()&&control.template get<int64_t>()>=0))||control.template get<uint64_t>()!=n)return false;
                    }else if(n!=1)return false;
                }
                found=true;break;
            }
            if(!found)return false;
        }
        return true;
    }catch(...){return false;}
}
}
