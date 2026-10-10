#pragma once
// Local application policy only. No transaction/consensus rules changed.
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <string>
#include <stdexcept>
#include <limits>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#endif
namespace tru_agent_auto {
using json=nlohmann::json;
inline std::string policyFile;
inline constexpr uint64_t feeAtoms=1000;
inline constexpr const char* genesis="b62fba2600030d97a06916b17694bec8d97ca14c1db682b2e57b424bd6000000";
inline void require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
inline bool hex(const std::string&s,size_t n){return s.size()==n&&s.find_first_not_of("0123456789abcdef")==std::string::npos;}
inline uint64_t number(const json&j,const char*k,uint64_t max=1000000000000ULL){
 const auto&v=j.at(k);require(v.is_number_unsigned(),"Expected unsigned policy/usage integer");auto n=v.get<uint64_t>();require(n<=max,"Policy/usage integer out of range");return n;
}
inline void privatePath(const std::filesystem::path&p,bool dir=false){
#ifndef _WIN32
 require(p.is_absolute(),"Absolute policy/inbox path required");
 for(auto q=p;!q.empty();q=q.parent_path()) {require(!std::filesystem::is_symlink(q),"Symlink policy path refused");if(q==q.root_path())break;}
 struct stat s{};require(lstat(p.c_str(),&s)==0&&s.st_uid==geteuid()&&!(s.st_mode&0077)&&(dir?S_ISDIR(s.st_mode):S_ISREG(s.st_mode)),"Private owned policy/inbox required (700 directory,600 file)");
#else
 throw std::runtime_error("Agent automation currently supports Linux only");
#endif
}
inline std::string readPrivate(const std::filesystem::path&p,size_t max){
 privatePath(p);std::string out;
#ifndef _WIN32
 int fd=open(p.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK);require(fd>=0,"Cannot open private file");
 struct stat s{};if(fstat(fd,&s)!=0||!S_ISREG(s.st_mode)||s.st_uid!=geteuid()||(s.st_mode&0077)||s.st_size<0||uint64_t(s.st_size)>max){close(fd);throw std::runtime_error("Unsafe/oversized private file");}
 char b[4096];ssize_t n;while((n=read(fd,b,sizeof b))>0){out.append(b,size_t(n));if(out.size()>max){close(fd);throw std::runtime_error("File too large");}}
 close(fd);require(n==0,"Private file read failed");
#endif
 return out;
}
inline std::string hmac(const std::string&key,const json&d){
 require(hex(key,64),"Credential must contain exactly 64 lowercase hex characters");
 // ASCII hex credential is the HMAC key, deliberately identical in Python/C++.
 auto msg=std::string("TRU-AGENT-CHECKPOINT-AUTO-V1\n")+genesis+"\n"+d.dump();
 unsigned char bytes[32];unsigned int n=0;
 require(HMAC(EVP_sha256(),key.data(),int(key.size()),reinterpret_cast<const unsigned char*>(msg.data()),msg.size(),bytes,&n)&&n==32,"HMAC failed");
 std::string result;const char* digits="0123456789abcdef";for(auto c:bytes){result+=digits[c>>4];result+=digits[c&15];}return result;
}
inline bool authenticated(const std::string&key,const json&d,const std::string&mac){auto expected=hmac(key,d);return hex(mac,64)&&CRYPTO_memcmp(mac.data(),expected.data(),64)==0;}
inline void validate(const json&p){
 require(p.is_object()&&p.size()==16,"Policy needs exactly the documented 16 fields");
 require(p.at("enabled").is_boolean(),"enabled must be boolean");
 require(p.at("network_genesis")==genesis,"Wrong policy network");
 require(hex(p.at("token_id").get<std::string>(),16)&&hex(p.at("issuance_txid").get<std::string>(),64)&&hex(p.at("manifest_sha256").get<std::string>(),64),"Invalid identity pins");
 for(const char*k:{"label","did","issuer","credential_file","inbox"})require(p.at(k).is_string()&&p.at(k).get<std::string>().size()<=512,"Invalid policy string");
 require(!p.at("issuer").get<std::string>().empty(),"Issuer required");
 require(number(p,"baseline_epoch")>0&&number(p,"expires_at_unix")>0,"Baseline/expiry required");
 require(number(p,"min_interval_seconds",31536000)>=60,"Minimum interval is 60 seconds");
 require(number(p,"max_per_day",1000)>0,"Daily cap required");
 require(number(p,"max_fee_atoms")==feeAtoms,"This builder uses exactly 1000 atoms per anchor");
 require(number(p,"total_budget_atoms")>=feeAtoms,"Finite total budget required");
}
inline json reserve(const json&p,const json&old,uint64_t now){
 validate(p);require(p.at("enabled")==true,"Agent policy disabled");
 require(now<number(p,"expires_at_unix"),"Agent policy expired");
 json u=old;
 if(u.is_null())u=json{{"spent_atoms",uint64_t(0)},{"last_at",uint64_t(0)},{"day",now/86400},{"day_count",uint64_t(0)}};
 require(u.is_object()&&u.size()==4,"Corrupt automatic usage ledger");
 auto spent=number(u,"spent_atoms"),last=number(u,"last_at"),day=number(u,"day"),count=number(u,"day_count");
 require(now>=last&&now/86400>=day,"Clock moved backwards; automatic approval paused");
 require(!last||now-last>=number(p,"min_interval_seconds"),"Checkpoint interval not reached");
 if(now/86400!=day)count=0;
 require(count<number(p,"max_per_day"),"Daily checkpoint allowance exhausted");
 auto budget=number(p,"total_budget_atoms");require(spent<=budget&&feeAtoms<=budget-spent,"Total checkpoint allowance exhausted");
 return json{{"spent_atoms",spent+feeAtoms},{"last_at",now},{"day",now/86400},{"day_count",count+1}};
}
// Startup configuration is immutable after worker start. Policy JSON is re-read each pass.
template<class Config> void configure(const Config&cfg){
 auto it=cfg.find("agent_checkpoint");
 std::string enabled,path;
 if(it!=cfg.end()){
  for(const auto&kv:it->second)require(kv.first=="enabled"||kv.first=="policy_file","Unknown [agent_checkpoint] setting");
  auto e=it->second.find("enabled");if(e!=it->second.end())enabled=e->second;
  auto f=it->second.find("policy_file");if(f!=it->second.end())path=f->second;
 }
 if(enabled.empty()){const char*e=std::getenv("TRU_AGENT_CHECKPOINT_ENABLE");enabled=e?e:"0";}
 if(path.empty()){const char*f=std::getenv("TRU_AGENT_CHECKPOINT_POLICY_FILE");if(f)path=f;}
 require(enabled=="0"||enabled=="1","Agent checkpoint enable must be 0 or 1");
 if(enabled=="0"){policyFile.clear();return;}
 require(!path.empty(),"Enabled automation requires policy_file");privatePath(path);policyFile=path;
}
} // namespace
