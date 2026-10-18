#pragma once
// MARKET-03B: outbound-only native Core login. No listener and no signing RPC.
#include "tru_market_login_v1.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

namespace tru_market_headless_v1 {
using Json=nlohmann::json;
using Transport=std::function<Json(const std::string&,const Json&)>;
using Read=std::function<bool(std::string&)>;
using Write=std::function<void(const std::string&)>;
using Sign=std::function<Json(const tru_market_login_v1::Challenge&)>;
inline size_t receive(char* data,size_t size,size_t count,void* target) noexcept {
    if(size && count>std::numeric_limits<size_t>::max()/size)return 0;
    const size_t bytes=size*count;
    auto& body=*static_cast<std::string*>(target);
    if(bytes>65536 || body.size()>65536-bytes)return 0;
    try{body.append(data,bytes);return bytes;}catch(...){return 0;}
}
inline Json post(const std::string& route,const Json& payload){
    if(route!="redeem" && route!="claim" && route!="proof")throw std::runtime_error("Invalid connection operation");
    std::unique_ptr<CURL,decltype(&curl_easy_cleanup)> curl(curl_easy_init(),curl_easy_cleanup);
    if(!curl)throw std::runtime_error("Could not initialize HTTPS");
    std::unique_ptr<curl_slist,decltype(&curl_slist_free_all)> headers(
        curl_slist_append(nullptr,"Content-Type: application/json"),curl_slist_free_all);
    if(!headers)throw std::runtime_error("Could not initialize HTTPS headers");
    const std::string url="https://market.tokenizedrealutility.com/api/connect/"+route;
    const std::string body=payload.dump();std::string response;
    CURL* c=curl.get();
    curl_easy_setopt(c,CURLOPT_URL,url.c_str());
    curl_easy_setopt(c,CURLOPT_HTTPHEADER,headers.get());
    curl_easy_setopt(c,CURLOPT_POST,1L);
    curl_easy_setopt(c,CURLOPT_POSTFIELDS,body.c_str());
    curl_easy_setopt(c,CURLOPT_POSTFIELDSIZE,static_cast<long>(body.size()));
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,receive);
    curl_easy_setopt(c,CURLOPT_WRITEDATA,&response);
    curl_easy_setopt(c,CURLOPT_USERAGENT,"TRU-Core/MarketConnect-03B");
    curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(c,CURLOPT_PROXY,"");
    curl_easy_setopt(c,CURLOPT_CONNECTTIMEOUT,10L);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,20L);
    curl_easy_setopt(c,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(c,CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_setopt(c,CURLOPT_SSL_VERIFYHOST,2L);
    const auto result=curl_easy_perform(c);long status=0;
    curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&status);
    if(result!=CURLE_OK)throw std::runtime_error("Marketplace HTTPS request failed: "+std::string(curl_easy_strerror(result)));
    if(status==403)throw std::runtime_error("Marketplace HTTP 403. Check the Cloudflare exception for POST /api/connect/; do not disable TLS verification.");
    if(status==401 || status==409)throw std::runtime_error("Connection expired, cancelled or already used. Generate a fresh Headless Core code.");
    if(status!=200)throw std::runtime_error("Marketplace HTTP "+std::to_string(status)+". Start a fresh connection and retry.");
    const auto json=Json::parse(response);
    if(!json.is_object())throw std::runtime_error("Invalid marketplace response");
    return json;
}
inline bool run(const std::vector<std::string>& addresses,const Read& read,const Write& write,
                const Sign& sign,const Transport& transport=post){
    if(addresses.empty())throw std::runtime_error("Load a wallet with an address first");
    write("HEADLESS MARKET CONNECT\nIn the marketplace choose Headless Core.\nPairing code (0 cancels): ");
    std::string pair;if(!read(pair) || pair=="0")return false;
    pair.erase(std::remove_if(pair.begin(),pair.end(),[](unsigned char c){return c=='-' || std::isspace(c);}),pair.end());
    std::transform(pair.begin(),pair.end(),pair.begin(),[](unsigned char c){return static_cast<char>(std::toupper(c));});
    if(!std::regex_match(pair,std::regex("[0-9A-F]{16}")))throw std::runtime_error("Expected four groups of four pairing-code characters");
    const auto ticket=transport("redeem",{{"wallet","headless"},{"pairing_code",pair}});
    const auto id=ticket.at("id").get<std::string>(), secret=ticket.at("secret").get<std::string>();
    if(!std::regex_match(id,std::regex("[0-9a-f]{32}")) || !std::regex_match(secret,std::regex("[0-9a-f]{64}")))throw std::runtime_error("Invalid connection ticket");
    std::string code=id.substr(0,8);std::transform(code.begin(),code.end(),code.begin(),[](unsigned char c){return static_cast<char>(std::toupper(c));});
    const auto expiry=ticket.at("expires").get<std::int64_t>();
    if(ticket.at("code")!=code || expiry<=std::time(nullptr) || expiry>std::time(nullptr)+310)throw std::runtime_error("Invalid or expired connection ticket");
    size_t selected=0;
    if(addresses.size()>1){
        for(size_t i=0;i<addresses.size();++i)write(std::to_string(i+1)+". "+addresses[i]+"\n");
        write("Address number (0 cancels): ");std::string number;
        if(!read(number) || number=="0")return false;
        if(number.size()>10 || !std::regex_match(number,std::regex("[1-9][0-9]*")))throw std::runtime_error("Invalid address selection");
        const auto n=std::stoull(number);
        if(n>addresses.size())throw std::runtime_error("Invalid address selection");
        selected=static_cast<size_t>(n-1);
    }
    const std::string& address=addresses[selected];
    Json access={{"id",id},{"secret",secret}}, claim=access;claim["address"]=address;
    const auto c=transport("claim",claim);
    tru_market_login_v1::Challenge challenge;std::string reason;
    const auto exact=c.at("message").get<std::string>();
    if(!tru_market_login_v1::parse(exact,challenge,reason) || challenge.address!=address ||
       c.at("address")!=address || c.at("nonce")!=challenge.nonce || c.at("expires")!=challenge.expires ||
       challenge.expires!=expiry || c.at("code")!=code || c.at("network")!="tru-mainnet")
        throw std::runtime_error("Marketplace challenge identity mismatch");
    write("\nSIGN LOGIN ONLY\nSite: https://market.tokenizedrealutility.com\nNetwork: tru-mainnet\nAddress: "+address+
          "\nMatch browser verification code: "+code+"\nNo transfer or payment permission.\nType YES to approve: ");
    std::string approval;if(!read(approval) || approval!="YES")return false;
    if(!tru_market_login_v1::parse(exact,challenge,reason))throw std::runtime_error(reason);
    const auto signedProof=sign(challenge);
    if(signedProof.at("address")!=address || signedProof.at("nonce")!=challenge.nonce)throw std::runtime_error("Wallet proof mismatch");
    auto proof=access;
    for(const char* key:{"address","nonce","pubkey_hex","signature_hex"})proof[key]=signedProof.at(key);
    const auto result=transport("proof",proof);
    if(!result.value("ok",false))throw std::runtime_error("Marketplace did not accept the login proof");
    write("\nApproval delivered. Return to your browser; it will finish connecting and load your collection.\n");
    return true;
}
} // namespace
