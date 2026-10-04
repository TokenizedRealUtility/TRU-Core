#pragma once
// Observational helpers only. Never used in validation or reward calculation.
#include <nlohmann/json.hpp>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <cstdlib>
#include <mutex>
#include <chrono>

namespace tru_data_provider_v1 {
using json = nlohmann::json;
inline uint64_t integer(const std::string& s) {
    if(s.empty() || (s.size()>1 && s[0]=='0')) throw std::runtime_error("noncanonical supply integer");
    uint64_t n=0;
    for(char c:s) { if(c<'0'||c>'9'||n>(UINT64_MAX-static_cast<unsigned>(c-'0'))/10) throw std::runtime_error("invalid supply integer"); n=n*10+static_cast<unsigned>(c-'0'); }
    return n;
}
inline void add(uint64_t& n,uint64_t v) { if(v>UINT64_MAX-n)throw std::runtime_error("supply overflow");n+=v; }
inline std::string coins(uint64_t n) { const auto fraction=std::to_string(n%100000000ULL);return std::to_string(n/100000000ULL)+"."+std::string(8-fraction.size(),'0')+fraction; }
inline uint64_t scheduled(uint64_t height) {uint64_t total=0,reward=5000000000ULL;while(height&&reward){const auto count=std::min<uint64_t>(height,210000);add(total,count*reward);height-=count;reward>>=1;}return total;}
inline bool isHex(const std::string& s) {return s.size()%2==0&&s.find_first_not_of("0123456789abcdefABCDEF")==std::string::npos;}
inline json metadata() {
    // Only named public fields are ever returned. Never serialize node config.
    static const json value=[](){json out={{"mainnet_launch_date",nullptr},{"circulating_policy_reviewed",false},{"reserve_scripts",json::array()},
      {"website","https://tokenizedrealutility.com"},{"source","https://github.com/TokenizedRealUtility/TRU-Core"},
      {"wallet_downloads","https://github.com/TokenizedRealUtility/TRU-Core/releases"},{"logo_png","https://tokenizedrealutility.com/images/tru_logo.png"}};
      const char* p=std::getenv("TRU_DATA_PROVIDER_METADATA");if(!p||!*p)return out;
      std::ifstream f(p);if(!f)throw std::runtime_error("data-provider metadata file unavailable");json supplied;f>>supplied;
      for(const auto& key:{"mainnet_launch_date","circulating_policy_reviewed","reserve_scripts","website","source","wallet_downloads","logo_png"})if(supplied.contains(key))out[key]=supplied[key];
      if(!out["reserve_scripts"].is_array()||out["reserve_scripts"].size()>1000||!out["circulating_policy_reviewed"].is_boolean())throw std::runtime_error("invalid supply policy");
      std::set<std::string> unique;for(const auto& v:out["reserve_scripts"]){if(!v.is_string())throw std::runtime_error("invalid reserve script");auto s=v.get<std::string>();if(s.size()!=50||s.substr(0,6)!="76a914"||s.substr(46)!="88ac"||!isHex(s)||!unique.insert(s).second)throw std::runtime_error("reserve scripts must be unique P2PKH hex");}
      for(const auto& key:{"website","source","wallet_downloads","logo_png"})if(!out[key].is_string()||out[key].get<std::string>().rfind("https://",0)!=0)throw std::runtime_error("public metadata links must use HTTPS");
      return out;}();return value;
}
struct Supply {
    uint64_t unspent=0,burnedOutputs=0,immature=0,reserves=0,count=0;
    void consume(const std::string& key,const std::string& raw,uint64_t height,uint64_t maturity,const std::set<std::string>& excluded) {
        if(++count>5000000)throw std::runtime_error("supply scan limit exceeded");
        const auto colon=key.find(':');if(colon!=64||!isHex(key.substr(0,64)))throw std::runtime_error("malformed UTXO key");integer(key.substr(65));
        std::vector<std::string> parts;size_t start=0,pos;while((pos=raw.find('|',start))!=std::string::npos){parts.push_back(raw.substr(start,pos-start));start=pos+1;}parts.push_back(raw.substr(start));
        if(parts.size()<3||parts.size()>4||parts[0].rfind("height=",0)!=0)throw std::runtime_error("malformed UTXO record");
        const auto created=integer(parts[0].substr(7)),amount=integer(parts[1]);auto script=parts[2];
        if(created>height||!isHex(script)||(parts.size()==4&&parts[3]!="cb=1"&&parts[3]!="cb=0"))throw std::runtime_error("invalid UTXO fields");
        for(auto& c:script)if(c>='A'&&c<='F')c=static_cast<char>(c-'A'+'a');
        if(script.rfind("6a",0)==0||script.rfind("006a",0)==0){add(burnedOutputs,amount);return;}
        add(unspent,amount);
        const bool locked=parts.size()==4&&parts[3]=="cb=1"&&height+1-created<maturity;
        if(locked)add(immature,amount);else if(excluded.count(script))add(reserves,amount);
    }
    json result(uint64_t height,const json& meta) const {
        const auto cap=scheduled(UINT64_MAX),upper=scheduled(height);if(unspent>upper||immature>unspent||reserves>unspent-immature)throw std::runtime_error("supply totals exceed schedule");
        const uint64_t candidate=unspent-immature-reserves;
        json j={{"schema","TRU-SUPPLY-V1"},{"ticker","TRU"},{"decimals",8},{"height",height},
          {"total_supply",coins(unspent)},{"total_supply_atoms",std::to_string(unspent)},
          {"scheduled_issuance",coins(upper)},{"scheduled_issuance_atoms",std::to_string(upper)},
          {"max_supply",coins(cap)},{"max_supply_atoms",std::to_string(cap)},
          {"provably_unspendable_utxo_atoms",std::to_string(burnedOutputs)},
          {"immature_coinbase_atoms",std::to_string(immature)},{"listed_reserve_atoms",std::to_string(reserves)},
          {"circulating_supply",nullptr},{"circulating_supply_atoms",nullptr},{"circulating_supply_status","policy_review_required"},
          {"circulating_candidate",coins(candidate)},{"utxo_count",count},
          {"method","confirmed native-coin UTXO value, excluding OP_RETURN and OP_FALSE OP_RETURN outputs; token quantities are not counted"},
          {"circulation_policy","total supply minus immature coinbase outputs and explicitly listed P2PKH reserves; other contract encumbrances and unknown-key burns are not inferred"},
          {"reserve_scripts",meta["reserve_scripts"]}};
        if(meta.value("circulating_policy_reviewed",false)){j["circulating_supply"]=coins(candidate);j["circulating_supply_atoms"]=std::to_string(candidate);j["circulating_supply_status"]="project_reported_policy";}return j;
    }
};
} // namespace tru_data_provider_v1
