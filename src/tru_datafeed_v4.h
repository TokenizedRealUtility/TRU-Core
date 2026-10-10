#pragma once
// DataFeed application framing only. Never called by consensus or mempool.
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
namespace tru_datafeed_v4 {
using json = nlohmann::json;
inline bool hex64(const std::string& s) {
    if(s.size()!=64) return false;
    for(char c:s) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false;
    return true;
}
inline unsigned nibble(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    throw std::runtime_error("Invalid script hex");
}
inline std::string singlePush(const std::string& script) {
    if(script.size()<4 || script.size()>20000 || script.size()%2) return "";
    std::vector<unsigned char> b;
    try {for(size_t i=0;i<script.size();i+=2) b.push_back((nibble(script[i])<<4)|nibble(script[i+1]));}
    catch(...) {return "";}
    if(b[0]!=0x6a) return "";
    size_t pos=2, length=b[1];
    if(length==0x4c) {if(b.size()<3)return "";length=b[pos++];}
    else if(length==0x4d) {if(b.size()<4)return "";length=b[pos]|(size_t(b[pos+1])<<8);pos+=2;}
    else if(length>75) return "";
    if(!length || length!=b.size()-pos) return "";
    return std::string(b.begin()+pos,b.end());
}
inline json envelope(const std::string& data) {
    if(data.rfind("TRUDF1:",0)!=0) throw std::runtime_error("Not a TRUDF1 record");
    auto e=json::parse(data.substr(7));
    if(!e.is_object() || e.value("v",0)!=1 || !e.contains("n") ||
       !e["n"].is_number_unsigned() || e["n"].get<uint64_t>()<1 || e["n"].get<uint64_t>()>10000 ||
       !e.contains("f") || !e["f"].is_string() || e["f"].get<std::string>().empty() ||
       e["f"].get<std::string>().size()>128 || !hex64(e.value("h","")))
        throw std::runtime_error("Invalid DataFeed envelope");
    const auto mode=e.value("m","");
    if(mode!="hash" && mode!="inline") throw std::runtime_error("Invalid DataFeed mode");
    if(mode=="inline" && (!e.contains("r") || !e["r"].is_array() || e["r"].size()!=e["n"].get<size_t>()))
        throw std::runtime_error("Invalid inline record count");
    return e;
}
inline std::string script(const std::string& data) {
    envelope(data);
    // Existing generic relay limit: total script <=257 bytes. PUSHDATA1
    // costs two bytes in addition to OP_RETURN, leaving 254 payload bytes.
    if(data.size()>254) throw std::runtime_error("DataFeed payload exceeds 254 bytes; use hash mode or smaller batch");
    std::vector<unsigned char> b{0x6a};
    if(data.size()<=75) b.push_back(static_cast<unsigned char>(data.size()));
    else {b.push_back(0x4c);b.push_back(static_cast<unsigned char>(data.size()));}
    b.insert(b.end(),data.begin(),data.end());
    const char* h="0123456789abcdef";std::string out;
    for(auto c:b){out+=h[c>>4];out+=h[c&15];}return out;
}
template<class Tx> json records(const Tx& tx) {
    json out=json::array();
    for(size_t v=0;v<tx.vout.size();++v) {
        if(tx.vout[v].amount!=0) continue;
        auto data=singlePush(tx.vout[v].scriptPubKey);
        if(data.empty())continue;
        std::string encoding="compact_op_return";
        if(data.front()=='{') {
            try {auto wrapper=json::parse(data);
                if(wrapper.value("type","")!="TRUSCRIPT")continue;
                data=wrapper.value("data","");encoding="legacy_truscript";
            }catch(...){continue;}
        }
        if(data.rfind("TRUDF1:",0)!=0)continue;
        // Invalid feed payloads are not interpreted; they remain ordinary txs.
        try {envelope(data);}catch(...){continue;}
        out.push_back(json{{"vout",v},{"data",data},{"encoding",encoding}});
    }
    return out;
}
}
