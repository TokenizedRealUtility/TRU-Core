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
inline void durableWrite(const std::string& path,const Bytes& b){
 const auto temp=path+".tmp-"+hex(random(12));
#ifdef _WIN32
 auto t=std::filesystem::path(temp).wstring(),p=std::filesystem::path(path).wstring();
 HANDLE h=CreateFileW(t.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("Quantum save open failed");
 DWORD written=0;bool ok=WriteFile(h,b.data(),static_cast<DWORD>(b.size()),&written,nullptr)&&written==b.size()&&FlushFileBuffers(h);CloseHandle(h);
 if(!ok || !MoveFileExW(t.c_str(),p.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){DeleteFileW(t.c_str());throw std::runtime_error("Quantum save failed");}
#else
 int fd=open(temp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)throw std::runtime_error("Quantum save open failed");
 size_t pos=0;while(pos<b.size()){auto n=write(fd,b.data()+pos,b.size()-pos);if(n<=0){close(fd);unlink(temp.c_str());throw std::runtime_error("Quantum save write failed");}pos+=n;}
 if(fsync(fd)!=0){close(fd);unlink(temp.c_str());throw std::runtime_error("Quantum save fsync failed");}close(fd);
 if(rename(temp.c_str(),path.c_str())!=0){unlink(temp.c_str());throw std::runtime_error("Quantum save rename failed");}
 auto dir=std::filesystem::path(path).parent_path();if(dir.empty())dir=".";
 fd=open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)throw std::runtime_error("Quantum directory open failed");int rc=fsync(fd);close(fd);if(rc!=0)throw std::runtime_error("Quantum directory fsync failed");
#endif
}
// One writer per sidecar. Signing intent is committed BEFORE signature creation.
// A retry can only reproduce the SAME digest and unsigned transaction. Reorgs
// and mempool failures never reset this state. Do not clone/roll back this file.
class Store {
 std::string path_; FileLock lock_; Secret key_; Json state_;
 static Bytes key(const Bytes& master){if(sodium_init()<0||master.size()<32)throw std::runtime_error("Quantum wallet requires unlocked master seed");Bytes k(32);const std::string d="TRU-PQ01-WALLET-STORE-V1";crypto_generichash(k.data(),32,reinterpret_cast<const unsigned char*>(d.data()),d.size(),master.data(),master.size());return k;}
 Bytes derive(const std::string& id,unsigned index){auto b=unhex(id);b.push_back(index);Bytes r(32);crypto_auth_hmacsha256(r.data(),b.data(),b.size(),key_.bytes.data());return r;}
 void save(){const std::string magic="TRUPQW01";auto nonce=random(24);auto plain=state_.dump();Bytes out(magic.begin(),magic.end());out.insert(out.end(),nonce.begin(),nonce.end());size_t start=out.size();out.resize(start+plain.size()+16);unsigned long long n=0;
 crypto_aead_xchacha20poly1305_ietf_encrypt(out.data()+start,&n,reinterpret_cast<const unsigned char*>(plain.data()),plain.size(),reinterpret_cast<const unsigned char*>(magic.data()),magic.size(),nullptr,nonce.data(),key_.bytes.data());sodium_memzero(plain.data(),plain.size());durableWrite(path_,out);}
 Json& record(const std::string& address){script(address);for(auto& r:state_["keys"])if(r["address"]==address)return r;throw std::runtime_error("This wallet does not own that quantum descriptor");}
public:
 Store(const std::string& path,const Bytes& master,bool create=false):path_(path),lock_(path+".lock"),key_(key(master)){
  if(!std::filesystem::exists(path)){if(!create)throw std::runtime_error("Quantum sidecar missing; restore the current sidecar before spending");state_={{"format",1},{"keys",Json::array()}};return;}
  if(std::filesystem::is_symlink(path)||!std::filesystem::is_regular_file(path)||std::filesystem::file_size(path)>16*1024*1024)throw std::runtime_error("Invalid quantum sidecar file");
  std::ifstream f(path,std::ios::binary);Bytes in((std::istreambuf_iterator<char>(f)),{});const std::string magic="TRUPQW01";
  if(in.size()<48||std::string(in.begin(),in.begin()+8)!=magic)throw std::runtime_error("Invalid quantum sidecar envelope");
  Secret plain{Bytes(in.size()-48)};unsigned long long n=0;
  if(crypto_aead_xchacha20poly1305_ietf_decrypt(plain.bytes.data(),&n,nullptr,in.data()+32,in.size()-32,reinterpret_cast<const unsigned char*>(magic.data()),8,in.data()+8,key_.bytes.data())!=0)throw std::runtime_error("Quantum sidecar authentication failed");
  state_=Json::parse(plain.bytes.begin(),plain.bytes.end());if(state_.at("format")!=1||!state_.at("keys").is_array())throw std::runtime_error("Invalid quantum sidecar format");
 }
 Json receive(){if(state_["keys"].size()>=10000)throw std::runtime_error("Quantum key limit reached");auto id=hex(random(32));auto seed=random(32);tru_pq01::Node s{};std::copy(seed.begin(),seed.end(),s.begin());std::array<tru_pq01::Node,67> p{};
 for(unsigned i=0;i<67;++i){Secret k{derive(id,i)};tru_pq01::Node x{};std::copy(k.bytes.begin(),k.bytes.end(),x.begin());p[i]=tru_pq01::chain(x,0,15,s,i);sodium_memzero(x.data(),x.size());}
 auto root=tru_pq01::root(p,s);Bytes spk{0x51,32};spk.insert(spk.end(),seed.begin(),seed.end());spk.push_back(32);spk.insert(spk.end(),root.begin(),root.end());spk.insert(spk.end(),{0xbb,0x51});
 Json r={{"id",id},{"address",descriptor(spk)},{"intent",""},{"rawHex",""}};state_["keys"].push_back(r);save();return {{"address",r["address"]},{"scriptPubKey",hex(spk)},{"sidecar",path_},{"warning","ONE payment per descriptor. Back up this encrypted sidecar together with the wallet. Ordinary seed recovery alone is insufficient. Never restore stale state or use cloned wallets."}};}
 void backupTo(const std::string& destination){
  if(std::filesystem::exists(destination)||std::filesystem::is_symlink(destination))throw std::runtime_error("Choose a new backup filename; existing backups are never overwritten");
  std::ifstream f(path_,std::ios::binary);Bytes b((std::istreambuf_iterator<char>(f)),{});if(b.empty())throw std::runtime_error("Cannot read quantum sidecar");durableWrite(destination,b);
 }
 Json list()const{Json a=Json::array();for(const auto& r:state_.at("keys"))a.push_back({{"address",r.at("address")},{"state",r.at("intent")==""?"unused":"reserved_or_signed"},{"has_saved_transaction",r.at("rawHex")!=""}});return a;}
 std::string saved(const std::string& address){auto r=record(address);if(r.at("rawHex")=="")throw std::runtime_error("No completed transaction saved for this descriptor");return r.at("rawHex");}
 std::string sign(const std::string& address,const Bytes& digest,const std::string& unsignedHex,const std::function<std::string(const Bytes&)>& finish){
  if(digest.size()!=32)throw std::runtime_error("Invalid quantum digest");auto& r=record(address);auto spk=script(address);auto intent=hex(digest)+":"+unsignedHex;
  if(r["intent"]!=""&&r["intent"]!=intent)throw std::runtime_error("ONE-TIME KEY ALREADY RESERVED: only the identical transaction can be retried");
  if(r["rawHex"]!="")return r["rawHex"];
  r["intent"]=intent;save(); // durable before exposing/creating any signature
  auto d=tru_pq01::digits(digest);tru_pq01::Node seed{};std::copy_n(spk.begin()+2,32,seed.begin());Bytes sig;sig.reserve(2144);
  for(unsigned i=0;i<67;++i){Secret k{derive(r.at("id"),i)};tru_pq01::Node x{};std::copy(k.bytes.begin(),k.bytes.end(),x.begin());auto y=tru_pq01::chain(x,0,d[i],seed,i);sig.insert(sig.end(),y.begin(),y.end());sodium_memzero(x.data(),32);}
  if(!tru_pq01::verify(sig,{1},Bytes(spk.begin()+2,spk.begin()+34),Bytes(spk.begin()+35,spk.begin()+67),digest))throw std::runtime_error("Quantum signature self-verification failed; key stays reserved");
  auto raw=finish(sig);r["rawHex"]=raw;save();return raw;
 }
};
} // namespace tru_quantum
