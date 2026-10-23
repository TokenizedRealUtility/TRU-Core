#pragma once
// Wallet-only PQ01 support. This file does not define consensus rules.
#include "wots_script09.h"
#include <sodium.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <set>
#include <algorithm>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace tru_quantum {
using Bytes=tru_pq01::Bytes;
using Json=nlohmann::json;
inline std::string hex(const Bytes& v) { static const char h[]="0123456789abcdef"; std::string s; for(auto b:v){s+=h[b>>4];s+=h[b&15];} return s; }
inline Bytes unhex(const std::string& s) {
 if(s.size()%2)throw std::runtime_error("Invalid quantum hex"); Bytes b;
 auto digit=[](char c)->unsigned{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("Quantum hex must be lowercase");};
 for(size_t i=0;i<s.size();i+=2)b.push_back((digit(s[i])<<4)|digit(s[i+1]));return b;
}
inline Bytes random(size_t n){Bytes b(n);randombytes_buf(b.data(),b.size());return b;}
inline std::string descriptor(const Bytes& script){const auto h=tru_pq01::hash(script);return "truq1:"+hex(script)+":"+hex(Bytes(h.begin(),h.begin()+8));}
inline Bytes script(const std::string& address){
 if(address.size()!=161 || address.substr(0,6)!="truq1:" || address[144]!=':')throw std::runtime_error("Expected a fresh truq1: receive descriptor");
 auto s=unhex(address.substr(6,138));if(s.size()!=69||!tru_pq01::canonicalScript(s)||descriptor(s)!=address)throw std::runtime_error("Invalid PQ01 descriptor/checksum");return s;
}
struct Secret { Bytes bytes; explicit Secret(Bytes b):bytes(std::move(b)){} ~Secret(){sodium_memzero(bytes.data(),bytes.size());} Secret(const Secret&)=delete; };
class FileLock {
#ifdef _WIN32
 HANDLE h=INVALID_HANDLE_VALUE;
#else
 int fd=-1;
#endif
public:
 explicit FileLock(const std::string& path){
#ifdef _WIN32
 h=CreateFileW(std::filesystem::path(path).wstring().c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("Quantum wallet busy or lock unavailable");
#else
 fd=::open(path.c_str(),O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
 if(fd<0)throw std::runtime_error("Cannot open quantum wallet lock");
 if(flock(fd,LOCK_EX|LOCK_NB)!=0){close(fd);fd=-1;throw std::runtime_error("Quantum wallet busy");}
#endif
 }
 ~FileLock(){
#ifdef _WIN32
 if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
#else
 if(fd>=0){flock(fd,LOCK_UN);close(fd);}
#endif
 }
 FileLock(const FileLock&)=delete;
};
inline void durableWrite(const std::string& path,const Bytes& b,bool replace=true){
 const auto temp=path+".tmp-"+hex(random(12));
#ifdef _WIN32
 auto t=std::filesystem::path(temp).wstring(),p=std::filesystem::path(path).wstring();
 HANDLE h=CreateFileW(t.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("Quantum save open failed");
 DWORD written=0;bool ok=WriteFile(h,b.data(),static_cast<DWORD>(b.size()),&written,nullptr)&&written==b.size()&&FlushFileBuffers(h);CloseHandle(h);
 if(!ok || !MoveFileExW(t.c_str(),p.c_str(),(replace?MOVEFILE_REPLACE_EXISTING:0)|MOVEFILE_WRITE_THROUGH)){DeleteFileW(t.c_str());throw std::runtime_error("Quantum save failed");}
#else
 int fd=open(temp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)throw std::runtime_error("Quantum save open failed");
 size_t pos=0;while(pos<b.size()){auto n=write(fd,b.data()+pos,b.size()-pos);if(n<=0){close(fd);unlink(temp.c_str());throw std::runtime_error("Quantum save write failed");}pos+=n;}
 if(fsync(fd)!=0){close(fd);unlink(temp.c_str());throw std::runtime_error("Quantum save fsync failed");}close(fd);
 if(replace){if(rename(temp.c_str(),path.c_str())!=0){unlink(temp.c_str());throw std::runtime_error("Quantum save rename failed");}}
 else {if(link(temp.c_str(),path.c_str())!=0){unlink(temp.c_str());throw std::runtime_error("Quantum backup destination exists or cannot be created");}unlink(temp.c_str());}
 auto dir=std::filesystem::path(path).parent_path();if(dir.empty())dir=".";
 fd=open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)throw std::runtime_error("Quantum directory open failed");int rc=fsync(fd);close(fd);if(rc!=0)throw std::runtime_error("Quantum directory fsync failed");
#endif
}
// QUANTUM-RECOVERY-02: wallet state only. No transaction/consensus rule changes.
// The recovery copy is a second local replica, NOT rollback-proof hardware.
// Never restore/clone both replicas to an earlier signing state.
class Store {
 std::string path_; FileLock lock_; Secret key_; Json state_;
 static Bytes key(const Bytes& master){if(sodium_init()<0||master.size()<32)throw std::runtime_error("Quantum wallet requires unlocked master seed");Bytes k(32);const std::string d="TRU-PQ01-WALLET-STORE-V1";crypto_generichash(k.data(),32,reinterpret_cast<const unsigned char*>(d.data()),d.size(),master.data(),master.size());return k;}
 Bytes derive(const std::string& id,unsigned index){auto b=unhex(id);b.push_back(index);Bytes r(32);crypto_auth_hmacsha256(r.data(),b.data(),b.size(),key_.bytes.data());return r;}
 static Json empty(){return {{"format",2},{"keys",Json::array()},{"destinations",Json::object()}};}
 static void validate(Json& s){
  if(!s.is_object()||(!s.contains("format"))||(s.at("format")!=1&&s.at("format")!=2)||!s.at("keys").is_array()||s.at("keys").size()>10000)throw std::runtime_error("Invalid quantum state format");
  std::set<std::string> addresses,ids;
  for(auto& r:s["keys"]){
   const auto id=r.at("id").get<std::string>(),a=r.at("address").get<std::string>();script(a);
   if(unhex(id).size()!=32||!addresses.insert(a).second||!ids.insert(id).second)throw std::runtime_error("Duplicate or invalid quantum key identity");
   const auto intent=r.at("intent").get<std::string>(),raw=r.at("rawHex").get<std::string>();
   if(!intent.empty()&&(intent.size()<67||intent[64]!=':'||unhex(intent.substr(0,64)).size()!=32||unhex(intent.substr(65)).empty()))throw std::runtime_error("Invalid quantum signing intent");
   if(!raw.empty()&&(intent.empty()||unhex(raw).empty()))throw std::runtime_error("Saved transaction without valid signing intent");
   if(r.contains("recovery_only")&&!r["recovery_only"].is_boolean())throw std::runtime_error("Invalid recovery-only flag");
  }
  if(!s.contains("destinations"))s["destinations"]=Json::object();
  if(!s["destinations"].is_object()||s["destinations"].size()>20000)throw std::runtime_error("Invalid quantum destination journal");
  for(auto it=s["destinations"].begin();it!=s["destinations"].end();++it){script(it.key());if(unhex(it.value().get<std::string>()).empty())throw std::runtime_error("Invalid destination reservation");}
  s["format"]=2;
 }
 Bytes encode(){
  validate(state_);const std::string magic="TRUPQW01";auto nonce=random(24);auto plain=state_.dump();
  if(plain.size()>16*1024*1024-48)throw std::runtime_error("Quantum state size limit reached");
  Bytes out(magic.begin(),magic.end());out.insert(out.end(),nonce.begin(),nonce.end());const auto start=out.size();out.resize(start+plain.size()+16);unsigned long long n=0;
  const int rc=crypto_aead_xchacha20poly1305_ietf_encrypt(out.data()+start,&n,reinterpret_cast<const unsigned char*>(plain.data()),plain.size(),reinterpret_cast<const unsigned char*>(magic.data()),8,nullptr,nonce.data(),key_.bytes.data());
  sodium_memzero(plain.data(),plain.size());if(rc!=0)throw std::runtime_error("Quantum state encryption failed");return out;
 }
 Json read(const std::string& path){
  if(std::filesystem::is_symlink(path)||!std::filesystem::is_regular_file(path)||std::filesystem::file_size(path)>16*1024*1024)throw std::runtime_error("Invalid quantum state file");
  std::ifstream f(path,std::ios::binary);Bytes in((std::istreambuf_iterator<char>(f)),{});const std::string magic="TRUPQW01";
  if(in.size()<48||std::string(in.begin(),in.begin()+8)!=magic)throw std::runtime_error("Invalid quantum state envelope");
  Secret plain{Bytes(in.size()-48)};unsigned long long n=0;
  if(crypto_aead_xchacha20poly1305_ietf_decrypt(plain.bytes.data(),&n,nullptr,in.data()+32,in.size()-32,reinterpret_cast<const unsigned char*>(magic.data()),8,in.data()+8,key_.bytes.data())!=0)throw std::runtime_error("Quantum state authentication failed; preserve both copies");
  auto result=Json::parse(plain.bytes.begin(),plain.bytes.begin()+n);validate(result);return result;
 }
 void merge(const Json& other,bool imported){
  for(const auto& incoming:other.at("keys")){
   Json* found=nullptr;
   for(auto& existing:state_["keys"]){
    if(existing.at("id")==incoming.at("id")||existing.at("address")==incoming.at("address")){
     if(existing.at("id")!=incoming.at("id")||existing.at("address")!=incoming.at("address"))throw std::runtime_error("Conflicting quantum key identity");
     found=&existing;break;
    }
   }
   if(!found){auto copy=incoming;if(imported)copy["recovery_only"]=true;state_["keys"].push_back(copy);continue;}
   auto& e=*found;
   if(e.at("intent")!=""&&incoming.at("intent")!=""&&e.at("intent")!=incoming.at("intent"))throw std::runtime_error("Conflicting one-time signing histories; signing blocked");
   if(e.at("intent")=="")e["intent"]=incoming.at("intent");
   if(e.at("rawHex")!=""&&incoming.at("rawHex")!=""&&e.at("rawHex")!=incoming.at("rawHex"))throw std::runtime_error("Conflicting saved quantum transactions");
   if(e.at("rawHex")=="")e["rawHex"]=incoming.at("rawHex");
   // External imports never authorize signing of a key whose full history is
   // unknown. A previously unused local key is quarantined on import as well.
   if(imported||e.value("recovery_only",false)||incoming.value("recovery_only",false))e["recovery_only"]=true;
  }
  for(auto it=other.at("destinations").begin();it!=other.at("destinations").end();++it){
   if(state_["destinations"].contains(it.key())&&state_["destinations"][it.key()]!=it.value())throw std::runtime_error("Conflicting destination-use histories");
   state_["destinations"][it.key()]=it.value();
  }
  validate(state_);
 }
 void save(){auto out=encode();durableWrite(path_+".recovery",out);durableWrite(path_,out);}
 Json& record(const std::string& address){script(address);for(auto& r:state_["keys"])if(r["address"]==address)return r;throw std::runtime_error("This wallet does not own that quantum descriptor");}
public:
 Store(const std::string& path,const Bytes& master,bool create=false):path_(path),lock_(path+".lock"),key_(key(master)){
  if(std::filesystem::is_symlink(path)||std::filesystem::is_symlink(path+".recovery"))throw std::runtime_error("Quantum state symlinks forbidden");
  const bool primary=std::filesystem::exists(path),recovery=std::filesystem::exists(path+".recovery");
  if(!primary&&!recovery){if(!create)throw std::runtime_error("Quantum state missing; restore a current backup in recovery-only mode");state_=empty();return;}
  state_=primary?read(path):read(path+".recovery");const auto prior=state_;
  bool replicasDiffer=false;
  if(primary&&recovery){auto other=read(path+".recovery");merge(other,false);replicasDiffer=(state_!=other);}
  // Upgrade v1/read-one-replica cases. Always establish both durable replicas
  // before a successful operation can expose a descriptor/signature.
  if(!primary||!recovery||state_!=prior||replicasDiffer){save();return;}
  // Even identical v1 files must upgrade on disk. All mutating operations save
  // format 2; list/status do not need an extra rewrite of identical replicas.
 }
 Json receive(){if(state_["keys"].size()>=10000)throw std::runtime_error("Quantum key limit reached");auto id=hex(random(32));auto seed=random(32);tru_pq01::Node s{};std::copy(seed.begin(),seed.end(),s.begin());std::array<tru_pq01::Node,67> p{};
 for(unsigned i=0;i<67;++i){Secret k{derive(id,i)};tru_pq01::Node x{};std::copy(k.bytes.begin(),k.bytes.end(),x.begin());p[i]=tru_pq01::chain(x,0,15,s,i);sodium_memzero(x.data(),x.size());}
 auto root=tru_pq01::root(p,s);Bytes spk{0x51,32};spk.insert(spk.end(),seed.begin(),seed.end());spk.push_back(32);spk.insert(spk.end(),root.begin(),root.end());spk.insert(spk.end(),{0xbb,0x51});
 Json r={{"id",id},{"address",descriptor(spk)},{"intent",""},{"rawHex",""}};state_["keys"].push_back(r);save();return {{"address",r["address"]},{"scriptPubKey",hex(spk)},{"sidecar",path_},{"warning","ONE payment per descriptor. Back up encrypted quantum state and ordinary wallet together. Seed alone is insufficient. Never roll back or clone signing state."}};}
 void reserveDestination(const std::string& destination,const std::string& unsignedHex){
  script(destination);if(unhex(unsignedHex).empty())throw std::runtime_error("Missing destination transaction intent");
  for(const auto& r:state_["keys"])if(r.at("address")==destination&&(r.at("intent")!=""||r.value("recovery_only",false)))throw std::runtime_error("Destination is a used/reserved or recovery-only local key");
  auto& uses=state_["destinations"];
  if(uses.contains(destination)&&uses[destination]!=unsignedHex)throw std::runtime_error("Destination already reserved for a different payment; obtain a fresh descriptor");
  uses[destination]=unsignedHex;save();
 }
 void backupTo(const std::string& destination){
  if(std::filesystem::exists(destination)||std::filesystem::is_symlink(destination))throw std::runtime_error("Choose a new backup filename; never overwrite backups");
  auto out=encode();durableWrite(destination,out,false);
 }
 Json restoreFrom(const std::string& backup){auto incoming=read(backup);merge(incoming,true);save();return {{"restored",true},{"mode","recovery_only"},{"warning","Imported keys cannot create signatures. Saved bytes can be retried. Unknown off-chain signing history cannot be reconstructed from the chain."}};}
 Json status()const{return {{"format",2},{"keys",state_.at("keys").size()},{"destination_reservations",state_.at("destinations").size()},{"recovery_copy",path_+".recovery"},{"seed_only_recovery",false},{"rollback_proof",false}};}
 Json list()const{Json a=Json::array();for(const auto& r:state_.at("keys"))a.push_back({{"address",r.at("address")},{"state",r.value("recovery_only",false)?"recovery_only":r.at("intent")==""?"unused":"reserved_or_signed"},{"has_saved_transaction",r.at("rawHex")!=""},{"recovery_only",r.value("recovery_only",false)}});return a;}
 std::string saved(const std::string& address){auto& r=record(address);if(r.at("rawHex")=="")throw std::runtime_error("No completed transaction saved; do not generate another signature from uncertain recovery state");return r.at("rawHex");}
 std::string sign(const std::string& address,const Bytes& digest,const std::string& unsignedHex,const std::function<std::string(const Bytes&)>& finish){
  if(digest.size()!=32||unhex(unsignedHex).empty())throw std::runtime_error("Invalid quantum signing intent");auto& r=record(address);auto spk=script(address);auto intent=hex(digest)+":"+unsignedHex;
  if(r["intent"]!=""&&r["intent"]!=intent)throw std::runtime_error("ONE-TIME KEY ALREADY RESERVED: only identical saved transaction bytes may be retried");
  if(r["rawHex"]!="")return r["rawHex"];
  if(r.value("recovery_only",false))throw std::runtime_error("RECOVERY-ONLY KEY: unknown signing history; no new signature permitted");
  r["intent"]=intent;save(); // Both replicas durable BEFORE signature creation.
  auto d=tru_pq01::digits(digest);tru_pq01::Node seed{};std::copy_n(spk.begin()+2,32,seed.begin());Bytes sig;sig.reserve(2144);
  for(unsigned i=0;i<67;++i){Secret k{derive(r.at("id"),i)};tru_pq01::Node x{};std::copy(k.bytes.begin(),k.bytes.end(),x.begin());auto y=tru_pq01::chain(x,0,d[i],seed,i);sig.insert(sig.end(),y.begin(),y.end());sodium_memzero(x.data(),32);}
  if(!tru_pq01::verify(sig,{1},Bytes(spk.begin()+2,spk.begin()+34),Bytes(spk.begin()+35,spk.begin()+67),digest))throw std::runtime_error("Quantum signature self-verification failed; key stays reserved");
  auto raw=finish(sig);if(unhex(raw).empty())throw std::runtime_error("Empty signed transaction; key stays reserved");r["rawHex"]=raw;save();return raw;
 }
};
} // namespace tru_quantum
