#pragma once
// TOKEN-EDITOR-01. Application authorization; never a consensus rule.
#include <nlohmann/json.hpp>
#include "crypto_ecdsa.h"
#include "address_helpers.h"
#include <openssl/sha.h>
#include <algorithm>
#include <vector>
#include <string>
#include <stdexcept>
namespace tru_editor {
using json=nlohmann::json;
inline void require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
inline bool hex(const std::string& s,size_t n){return s.size()==n && std::all_of(s.begin(),s.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});}
inline std::vector<unsigned char> unhex(const std::string& s){
    require(s.size()%2==0 && hex(s,s.size()),"Invalid authorization hex");
    std::vector<unsigned char> out;out.reserve(s.size()/2);
    const auto value=[](char c){return c<='9'?c-'0':c-'a'+10;};
    for(size_t i=0;i<s.size();i+=2)out.push_back(static_cast<unsigned char>((value(s[i])<<4)|value(s[i+1])));
    return out;
}
inline std::string toHex(const std::vector<unsigned char>& bytes){
    const char* h="0123456789abcdef";std::string s;
    for(auto c:bytes){s+=h[c>>4];s+=h[c&15];}return s;
}
inline std::string hashBytes(const std::string& text){
    unsigned char h[32];SHA256(reinterpret_cast<const unsigned char*>(text.data()),text.size(),h);
    return std::string(reinterpret_cast<const char*>(h),32);
}
inline std::string hashHex(const std::string& text){auto h=hashBytes(text);return toHex(std::vector<unsigned char>(h.begin(),h.end()));}
// read must read the Core's confirmed checksum-protected indexes, not caller metadata.
template<class Read> json context(Read read,const std::string& tokenID){
    require(hex(tokenID,8)||hex(tokenID,16),"Invalid token ID for issuer authority");
    std::string issuance,raw;
    require(read("tokenIssuance:"+tokenID,issuance)&&hex(issuance,64),"Confirmed issuance mapping unavailable");
    require(read("tokenMetadata:"+issuance,raw),"Confirmed issuance metadata unavailable");
    auto stored=json::parse(raw);
    require(stored.is_object()&&stored.value("tokenID","")==tokenID,"Issuance identity mismatch");
    const auto type=stored.value("type","");
    require(type=="SFT"||type=="NCFT","Only SFT/NCFT have this editor policy");
    const auto owner=stored.at("owner").get<std::string>();
    const auto decoded=decodeBase58Check(owner);
    require(decoded.size()==25 && decoded[0]==tru_network::MAINNET_P2PKH_VERSION,"Invalid original issuance owner");
    return json{{"policy","TRU_ORIGINAL_ISSUANCE_OWNER_V1"},{"network","TRUMain"},
                {"tokenID",tokenID},{"issuance_txid",issuance},{"owner",owner},{"type",type}};
}
inline std::string message(const json& unsignedRecord){
    require(!unsignedRecord.contains("editor_proof"),"Cannot sign an already sealed record");
    const auto& c=unsignedRecord.at("issuer_context");
    return "TRU-TOKEN-EVOLUTION-COMMIT-V1\nnetwork=TRUMain\ntokenID="+
        unsignedRecord.at("tokenID").get<std::string>()+"\nowner="+c.at("owner").get<std::string>()+
        "\nrecord_sha256="+hashHex(unsignedRecord.dump())+"\n";
}
inline bool verify(const json& record,const json& trusted){
    try{
        if(record.dump().size()>4U*1024U*1024U)return false;
        if(!record.is_object() || record.at("issuer_context")!=trusted ||
           record.at("tokenID")!=trusted.at("tokenID") || record.at("type")!=trusted.at("type"))return false;
        const auto& proof=record.at("editor_proof");
        if(!proof.is_object()||proof.size()!=3||proof.at("scheme")!="TRU_ISSUER_EXACT_PREVIEW_V1")return false;
        const auto pub=proof.at("public_key").get<std::string>();
        const auto sig=proof.at("signature").get<std::string>();
        if(!hex(pub,66)||(pub.substr(0,2)!="02"&&pub.substr(0,2)!="03")||sig.size()<16||sig.size()>144)return false;
        const auto key=unhex(pub);const auto signature=unhex(sig);
        if(!doesPubKeyMatchAddress(key,trusted.at("owner").get<std::string>()))return false;
        auto plain=record;plain.erase("editor_proof");
        return ECDSAKey::verifyCanonicalTransactionSignature(key,hashBytes(message(plain)),signature);
    }catch(...){return false;}
}
inline json proof(const std::vector<unsigned char>& pub,const std::vector<unsigned char>& sig){
    return json{{"scheme","TRU_ISSUER_EXACT_PREVIEW_V1"},{"public_key",toHex(pub)},{"signature",toHex(sig)}};
}
} // namespace tru_editor
