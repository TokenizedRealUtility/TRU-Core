#pragma once
// MAGIC-SECRET-02: application envelope only. No consensus rules or VM changes.
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <array>
#include <vector>
#include <string>
#include <stdexcept>
#include <functional>
#include <chrono>
#include <cstdint>
#include <algorithm>

namespace tru_magic_v2 {
using Bytes = std::vector<unsigned char>;
constexpr unsigned MIN_BITS=12, MAX_BITS=20, DEFAULT_BITS=18;
constexpr uint64_t MAX_ATTEMPTS=1ULL<<26;
constexpr size_t MAX_TEXT_BYTES=200;
inline const Bytes& magic() { static const Bytes m={'T','R','U','M','A','G','2',0}; return m; }
inline void require(bool ok,const char* msg){if(!ok)throw std::runtime_error(msg);}
inline std::string hex(const Bytes& v){static const char* h="0123456789abcdef";std::string s; for(auto c:v){s+=h[c>>4];s+=h[c&15];}return s;}
inline Bytes unhex(const std::string& s){require(s.size()%2==0,"Invalid hex");Bytes b;auto n=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;throw std::runtime_error("Invalid hex");};for(size_t i=0;i<s.size();i+=2)b.push_back((n(s[i])<<4)|n(s[i+1]));return b;}
inline Bytes random(size_t n){Bytes b(n);require(RAND_bytes(b.data(),int(n))==1,"Random generator failed");return b;}
inline Bytes hash(const Bytes& b){Bytes h(32);SHA256(b.data(),b.size(),h.data());return h;}
inline std::string newCode(){return "TRUM2-"+hex(random(32));}
inline Bytes codeBytes(const std::string& c){require(c.size()==70&&c.substr(0,6)=="TRUM2-","Use the complete creator-issued TRUM2 unlock code");return unhex(c.substr(6));}
inline bool validUtf8(const std::string& s){
 size_t i=0;while(i<s.size()){uint32_t c=static_cast<unsigned char>(s[i++]);if(c<128)continue;unsigned extra=0;uint32_t minimum=0;if(c>=0xc2&&c<=0xdf){c&=31;extra=1;minimum=128;}else if(c>=0xe0&&c<=0xef){c&=15;extra=2;minimum=2048;}else if(c>=0xf0&&c<=0xf4){c&=7;extra=3;minimum=65536;}else return false;if(i+extra>s.size())return false;while(extra--){unsigned b=static_cast<unsigned char>(s[i++]);if((b&0xc0)!=0x80)return false;c=(c<<6)|(b&63);}if(c<minimum||c>0x10ffff||(c>=0xd800&&c<=0xdfff))return false;}return true;
}
struct Envelope{unsigned bits; Bytes salt,iv,cipher;};
inline Envelope parse(const Bytes& p){require(p.size()>=55&&p.size()<=254,"Invalid MagicLock V2 envelope size");require(std::equal(magic().begin(),magic().end(),p.begin()),"Not a MagicLock V2 envelope");require(p[8]>=MIN_BITS&&p[8]<=MAX_BITS,"Unsupported work difficulty");return {p[8],Bytes(p.begin()+9,p.begin()+25),Bytes(p.begin()+25,p.begin()+37),Bytes(p.begin()+37,p.end())};}
inline Bytes header(unsigned bits,const Bytes& salt,const Bytes& iv){require(bits>=MIN_BITS&&bits<=MAX_BITS&&salt.size()==16&&iv.size()==12,"Invalid envelope parameters");Bytes h=magic();h.push_back(bits);h.insert(h.end(),salt.begin(),salt.end());h.insert(h.end(),iv.begin(),iv.end());return h;}
inline std::string script(const Bytes& p){parse(p);Bytes s={0x6a};if(p.size()<=75)s.push_back(p.size());else{s.push_back(0x4c);s.push_back(p.size());}s.insert(s.end(),p.begin(),p.end());require(s.size()<=257,"Envelope exceeds existing relay policy");return hex(s);}
inline Bytes fromScript(const std::string& sh){require(sh.size()<=514,"MagicLock script too large");Bytes s=unhex(sh);require(s.size()>=2&&s[0]==0x6a,"Expected OP_RETURN");size_t off=2,n=s[1];if(n==0x4c){require(s.size()>=3,"Truncated push");n=s[2];off=3;require(n>75,"Noncanonical push");}else require(n<=75,"Unsupported push");require(n==s.size()-off,"Trailing or truncated envelope");Bytes p(s.begin()+off,s.end());parse(p);return p;}
struct Progress{uint64_t attempts;double seconds;std::string digest;bool found;};
using Report=std::function<bool(const Progress&)>; // false cancels; no fake counters.
struct Work{Bytes key;uint64_t nonce,attempts;};
inline Work grind(const std::string& code,unsigned bits,const Bytes& salt,Report report={}){
 require(bits>=MIN_BITS&&bits<=MAX_BITS&&salt.size()==16,"Invalid work parameters");
 Bytes secret=codeBytes(code);const std::string domain="TRU-MAGIC-V2-WORK";Bytes pre(domain.begin(),domain.end());pre.push_back(bits);pre.insert(pre.end(),secret.begin(),secret.end());pre.insert(pre.end(),salt.begin(),salt.end());size_t offset=pre.size();pre.resize(offset+8);
 const auto start=std::chrono::steady_clock::now();auto last=start;
 for(uint64_t nonce=0;nonce<MAX_ATTEMPTS;++nonce){for(int j=0;j<8;++j)pre[offset+j]=static_cast<unsigned char>(nonce>>(8*j));auto d=hash(pre);bool found=true;for(unsigned i=0;i<bits;++i)if(d[i/8]&(0x80>>(i%8))){found=false;break;}
  if(found||(nonce&2047)==0){auto now=std::chrono::steady_clock::now();if(found||nonce==0||now-last>=std::chrono::milliseconds(80)){last=now;Progress p{nonce+1,std::chrono::duration<double>(now-start).count(),hex(d),found};if(report&&!report(p)){OPENSSL_cleanse(secret.data(),secret.size());OPENSSL_cleanse(pre.data(),pre.size());throw std::runtime_error("Grinding cancelled");}}}
  if(found){const std::string kd="TRU-MAGIC-V2-KEY";Bytes kp(kd.begin(),kd.end());kp.push_back(bits);kp.insert(kp.end(),secret.begin(),secret.end());kp.insert(kp.end(),salt.begin(),salt.end());kp.insert(kp.end(),pre.end()-8,pre.end());auto key=hash(kp);OPENSSL_cleanse(kp.data(),kp.size());OPENSSL_cleanse(secret.data(),secret.size());OPENSSL_cleanse(pre.data(),pre.size());return {key,nonce,nonce+1};}
 }
 OPENSSL_cleanse(secret.data(),secret.size());OPENSSL_cleanse(pre.data(),pre.size());throw std::runtime_error("Work limit reached; verify the code or create a fresh envelope");
}
struct CipherContext {EVP_CIPHER_CTX* p=EVP_CIPHER_CTX_new();~CipherContext(){EVP_CIPHER_CTX_free(p);}};
inline Bytes seal(const std::string& text,const std::string& code,unsigned bits,Report report={},Bytes salt={},Bytes iv={}){
 require(!text.empty()&&text.size()<=MAX_TEXT_BYTES&&validUtf8(text),"Secret must contain 1..200 UTF-8 bytes");if(salt.empty())salt=random(16);if(iv.empty())iv=random(12);Bytes aad=header(bits,salt,iv);auto work=grind(code,bits,salt,report);Bytes plain={0};plain.insert(plain.end(),text.begin(),text.end());Bytes out(plain.size()+16);CipherContext ctx;int n=0,len=0;bool ok=ctx.p&&EVP_EncryptInit_ex(ctx.p,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1&&EVP_CIPHER_CTX_ctrl(ctx.p,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1&&EVP_EncryptInit_ex(ctx.p,nullptr,nullptr,work.key.data(),iv.data())==1&&EVP_EncryptUpdate(ctx.p,nullptr,&n,aad.data(),int(aad.size()))==1&&EVP_EncryptUpdate(ctx.p,out.data(),&n,plain.data(),int(plain.size()))==1;len=n;ok=ok&&EVP_EncryptFinal_ex(ctx.p,out.data()+len,&n)==1;len+=n;out.resize(len+16);ok=ok&&EVP_CIPHER_CTX_ctrl(ctx.p,EVP_CTRL_GCM_GET_TAG,16,out.data()+len)==1;OPENSSL_cleanse(work.key.data(),work.key.size());OPENSSL_cleanse(plain.data(),plain.size());require(ok,"Encryption failed");aad.insert(aad.end(),out.begin(),out.end());parse(aad);return aad;
}
inline std::string open(const Bytes& p,const std::string& code,Report report={}){
 auto e=parse(p);auto work=grind(code,e.bits,e.salt,report);Bytes aad(p.begin(),p.begin()+37),plain(e.cipher.size());CipherContext ctx;int n=0,len=0;const int size=int(e.cipher.size()-16);bool ok=ctx.p&&EVP_DecryptInit_ex(ctx.p,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1&&EVP_CIPHER_CTX_ctrl(ctx.p,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1&&EVP_DecryptInit_ex(ctx.p,nullptr,nullptr,work.key.data(),e.iv.data())==1&&EVP_DecryptUpdate(ctx.p,nullptr,&n,aad.data(),int(aad.size()))==1&&EVP_DecryptUpdate(ctx.p,plain.data(),&n,e.cipher.data(),size)==1;len=n;ok=ok&&EVP_CIPHER_CTX_ctrl(ctx.p,EVP_CTRL_GCM_SET_TAG,16,e.cipher.data()+size)==1&&EVP_DecryptFinal_ex(ctx.p,plain.data()+len,&n)==1;len+=n;OPENSSL_cleanse(work.key.data(),work.key.size());if(!ok){OPENSSL_cleanse(plain.data(),plain.size());throw std::runtime_error("Wrong unlock code or altered ciphertext");}if(len<2||plain[0]!=0){OPENSSL_cleanse(plain.data(),plain.size());throw std::runtime_error("Unsupported secret content");}std::string text(plain.begin()+1,plain.begin()+len);OPENSSL_cleanse(plain.data(),plain.size());require(validUtf8(text),"Invalid UTF-8 secret");return text;
}
} // namespace tru_magic_v2
