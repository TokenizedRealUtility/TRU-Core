#ifndef TRU_MINER_TELEMETRY_V1_H
#define TRU_MINER_TELEMETRY_V1_H
// Optional application telemetry. No wallet key, transaction or consensus access.
// A signature identifies a reporting node session; it does NOT prove hash work
// or ownership of a reported reward address. Observations are deliberately bounded.
#include <arpa/inet.h>
#include <array>
#include <utility>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace tru_miner_telemetry {
constexpr std::uint64_t SERVICE = 1ULL << 48;
constexpr std::uint64_t SERVICE_IP = 1ULL << 49;
constexpr std::uint64_t MAX_RATE = 10000000000000ULL;
constexpr std::size_t CAPACITY = 256;
constexpr std::size_t LOCAL_ADDRESS_CAPACITY = 64;
constexpr std::size_t PER_SOURCE_ADDRESS_CAPACITY = 64;
constexpr unsigned VERIFY_BUDGET_PER_SECOND = 128;
constexpr std::int64_t LOCAL_SLOT_IDLE = 120;
constexpr std::int64_t TTL = 45;
constexpr const char* PREFIX = "TRU-MINER-REPORT-V1:";
constexpr const char* PREFIX_IP = "TRU-MINER-REPORT-V2:";
inline bool ipWire(const std::string& s) {return s.compare(0,std::string(PREFIX_IP).size(),PREFIX_IP)==0;}
inline bool reportWire(const std::string& s) {return ipWire(s)||s.compare(0,std::string(PREFIX).size(),PREFIX)==0;}
inline bool ipEnabled() {const char* p=std::getenv("TRU_MINER_REPORT_IP");return !p||std::string(p)!="0";}
// Only literal unicast addresses; no DNS, HTTP lookups, ports, zones, or peer-IP inference.
// RFC1918 and IPv6 ULA are allowed for operator-configured private networks.
inline std::string ipBytes(const std::string& ip) {
    if(ip.empty()||ip.size()>45||ip.find('\0')!=std::string::npos)return {};
    std::array<unsigned char,16> b{};
    if(inet_pton(AF_INET,ip.c_str(),b.data())==1) {
        if(b[0]==0||b[0]==127||b[0]>=224||(b[0]==169&&b[1]==254))return {};
        return std::string(1,char(4))+std::string(reinterpret_cast<const char*>(b.data()),4);
    }
    if(inet_pton(AF_INET6,ip.c_str(),b.data())!=1)return {};
    if(b[0]==255||(b[0]==254&&(b[1]&0xc0)==0x80))return {};
    // Reject unspecified, loopback, IPv4-compatible and IPv4-mapped forms.
    bool firstTenZero=true;for(int i=0;i<10;++i)if(b[i])firstTenZero=false;
    if(firstTenZero&&((b[10]==0&&b[11]==0)||(b[10]==255&&b[11]==255)))return {};
    return std::string(1,char(6))+std::string(reinterpret_cast<const char*>(b.data()),16);
}
inline std::string ipText(const std::string& b) {
    if(b.size()!=5&&b.size()!=17)return {};
    const int family=b[0]==4&&b.size()==5?AF_INET:b[0]==6&&b.size()==17?AF_INET6:0;
    char out[INET6_ADDRSTRLEN]{};
    if(!family||!inet_ntop(family,b.data()+1,out,sizeof(out)))return {};
    const std::string text=out;return ipBytes(text)==b?text:std::string{};
}
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
inline bool enabled() {const char* p=std::getenv("TRU_MINER_TELEMETRY");return !p||std::string(p)!="0";}
inline std::int64_t wallNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
inline std::int64_t monoNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline std::string hex(const std::string& in) {
    const char* alphabet="0123456789abcdef"; std::string out;out.reserve(in.size()*2);
    for (unsigned char c:in) {out+=alphabet[c>>4];out+=alphabet[c&15];}return out;
}
inline bool unhex(const std::string& in,std::string& out) {
    if (in.size()%2 || in.size()>512) return false;
    out.clear();
    auto nib=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};
    for(std::size_t i=0;i<in.size();i+=2) {int a=nib(in[i]),b=nib(in[i+1]);if(a<0||b<0)return false;out+=char((a<<4)|b);}return true;
}
inline bool addressOK(const std::string& a) {
    const std::string alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return a.size()>=26&&a.size()<=35&&std::all_of(a.begin(),a.end(),[&](char c){return alphabet.find(c)!=std::string::npos;});
}
inline void put64(std::string& s,std::uint64_t n) {for(int i=0;i<8;++i)s+=char((n>>(8*i))&255);}
inline std::uint64_t get64(const std::string& s,std::size_t p) {std::uint64_t n=0;for(int i=0;i<8;++i)n|=std::uint64_t(static_cast<unsigned char>(s[p+i]))<<(8*i);return n;}
struct Report {
    std::string source,address,wire,ipWire,advertisedIP;
    std::uint64_t sequence=0,rate=0;
    std::int64_t timestamp=0,received=0;
    bool local=false;
};
class Registry {
    Key key_{nullptr,EVP_PKEY_free};
    std::string public_,advertisedIP_;
    std::uint64_t sequence_=0;
    std::map<std::string,Report> reports_;
    std::map<std::string,std::int64_t> localLast_;
    mutable std::mutex mutex_;
    std::int64_t budgetSecond_=-1;
    unsigned budgetUsed_=0;
    void prune(std::int64_t wall,std::int64_t mono) {
        for(auto it=reports_.begin();it!=reports_.end();) {
            if(mono-it->second.received>120 && wall-it->second.timestamp>TTL)it=reports_.erase(it);else ++it;
        }
        // EXPLORER-MINERS-03: local publication slots are advisory telemetry,
        // not permanent session ownership. Expire idle slots so a restarted or
        // changing miner fleet cannot be locked out by the first four addresses.
        for(auto it=localLast_.begin();it!=localLast_.end();) {
            if(mono>=it->second && mono-it->second>LOCAL_SLOT_IDLE)it=localLast_.erase(it);else ++it;
        }
    }
public:
    Registry() {
        unsigned char seed[32];
        if(RAND_bytes(seed,sizeof(seed))!=1)return;
        key_.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed,sizeof(seed)));
        OPENSSL_cleanse(seed,sizeof(seed));
        if(!key_)return;
        public_.resize(32);std::size_t n=32;
        if(EVP_PKEY_get_raw_public_key(key_.get(),reinterpret_cast<unsigned char*>(&public_[0]),&n)!=1||n!=32) {
            key_.reset();public_.clear();
        }
    }
    std::string source() const {return hex(public_);}
    void setAdvertisedIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);advertisedIP_=ipText(ipBytes(ip));
    }
    // V1 and V2 share one observation/sequence. V1 remains independently relayable.
    std::string publish(const std::string& addr,double rate,std::int64_t wall=wallNow(),std::int64_t mono=monoNow()) {
        return publishReports(addr,rate,wall,mono).first;
    }
    // Bounded advisory telemetry: up to 64 recently active local reward addresses, once per 10 seconds.
    std::pair<std::string,std::string> publishReports(const std::string& addr,double rate,std::int64_t wall=wallNow(),std::int64_t mono=monoNow()) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!enabled()||!key_||!addressOK(addr)||!std::isfinite(rate)||rate<0||rate>MAX_RATE||wall<=0)return {};
        prune(wall,mono);
        auto last=localLast_.find(addr);
        if(last!=localLast_.end()&&mono-last->second<10)return {};
        if(last==localLast_.end()&&localLast_.size()>=LOCAL_ADDRESS_CAPACITY)return {};
        if(sequence_==UINT64_MAX)return {};
        std::string body="TRUMR001";body+=public_;put64(body,static_cast<std::uint64_t>(wall));put64(body,++sequence_);
        put64(body,static_cast<std::uint64_t>(rate));body+=char(addr.size());body+=addr;
        auto sign=[&](const std::string& data,const char* prefix)->std::string {
            Ctx ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);std::string signature(64,'\0');std::size_t n=64;
            if(!ctx||EVP_DigestSignInit(ctx.get(),nullptr,nullptr,nullptr,key_.get())!=1||
               EVP_DigestSign(ctx.get(),reinterpret_cast<unsigned char*>(&signature[0]),&n,
                 reinterpret_cast<const unsigned char*>(data.data()),data.size())!=1||n!=64)return {};
            return std::string(prefix)+hex(data+signature);
        };
        const std::string advertised=ipEnabled()?advertisedIP_:std::string{};
        std::string extended=body;extended.replace(0,8,"TRUMR002");
        extended+=advertised.empty()?std::string(1,'\0'):ipBytes(advertised);
        const std::string wire=sign(body,PREFIX),wireIP=sign(extended,PREFIX_IP);
        if(wire.empty()||wireIP.empty())return {};
        localLast_[addr]=mono;
        Report r; r.source=hex(public_);r.address=addr;r.sequence=sequence_;r.rate=static_cast<std::uint64_t>(rate);
        r.timestamp=wall;r.received=mono;r.local=true;r.wire=wire;r.ipWire=wireIP;r.advertisedIP=advertised;
        prune(wall,mono);reports_[r.source+":"+addr]=r;
        return {wire,wireIP};
    }
    bool accept(const std::string& wire,std::int64_t wall=wallNow(),std::int64_t mono=monoNow()) {
        // Global signature-verification budget supplements framing limits. Cheap
        // duplicate/replay rejection happens before consuming this budget so
        // relayed duplicates cannot starve fresh telemetry.
        std::lock_guard<std::mutex> lock(mutex_);
        const bool extended=ipWire(wire);
        const std::string prefix=extended?PREFIX_IP:PREFIX;
        if(wire.compare(0,prefix.size(),prefix)!=0||wire.size()>512)return false;
        std::string bytes;if(!unhex(wire.substr(prefix.size()),bytes)||bytes.size()<155)return false;
        if(bytes.compare(0,8,extended?"TRUMR002":"TRUMR001")!=0)return false;
        const std::size_t len=static_cast<unsigned char>(bytes[64]);
        if(len<26||len>35||bytes.size()<65+len+64)return false;
        std::string advertised;
        if(extended) {
            const auto ip=bytes.substr(65+len,bytes.size()-(65+len+64));
            if(ip!=std::string(1,'\0')) {advertised=ipText(ip);if(advertised.empty())return false;}
        } else if(bytes.size()!=65+len+64)return false;
        const auto timestamp=get64(bytes,40),sequence=get64(bytes,48),rate=get64(bytes,56);
        if(wall<=0||timestamp>static_cast<std::uint64_t>(wall+5)||
           timestamp+TTL<static_cast<std::uint64_t>(wall)||sequence==0||rate>MAX_RATE)return false;
        const std::string pub=bytes.substr(8,32),addr=bytes.substr(65,len);
        if(pub==public_||!addressOK(addr))return false;
        std::string id=hex(pub)+":"+addr;prune(wall,mono);
        auto old=reports_.find(id);
        if(old!=reports_.end()) {
            const auto& r=old->second;
            if(sequence<r.sequence)return false;
            if(sequence==r.sequence) {
                if(timestamp!=static_cast<std::uint64_t>(r.timestamp)||rate!=r.rate)return false;
                if(extended?!r.ipWire.empty():!r.wire.empty())return false;
            }
        }
        if(old==reports_.end()&&reports_.size()>=CAPACITY-4)return false;
        unsigned perSource=0;
        for(const auto& item:reports_)if(item.second.source==hex(pub))++perSource;
        if(old==reports_.end()&&perSource>=PER_SOURCE_ADDRESS_CAPACITY)return false;
        if(mono!=budgetSecond_) {budgetSecond_=mono;budgetUsed_=0;}
        if(++budgetUsed_>VERIFY_BUDGET_PER_SECOND)return false;
        Key key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,
                reinterpret_cast<const unsigned char*>(pub.data()),pub.size()),EVP_PKEY_free);
        Ctx ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        const std::size_t bodySize=bytes.size()-64;
        if(!key||!ctx||EVP_DigestVerifyInit(ctx.get(),nullptr,nullptr,nullptr,key.get())!=1||
           EVP_DigestVerify(ctx.get(),reinterpret_cast<const unsigned char*>(bytes.data()+bodySize),64,
                            reinterpret_cast<const unsigned char*>(bytes.data()),bodySize)!=1)return false;
        Report r;r.source=hex(pub);r.address=addr;r.sequence=sequence;r.rate=rate;
        r.timestamp=static_cast<std::int64_t>(timestamp);r.received=mono;
        // A second encoding never refreshes age, counts twice or downgrades V2 metadata.
        if(old!=reports_.end()&&sequence==old->second.sequence)r=old->second;
        if(extended) {r.ipWire=wire;r.advertisedIP=advertised;} else r.wire=wire;
        reports_[id]=r;return true;
    }
    std::vector<Report> snapshot(std::int64_t wall=wallNow(),std::int64_t mono=monoNow()) const {
        std::lock_guard<std::mutex> lock(mutex_);std::vector<Report> out;
        for(const auto& item:reports_) {
            const auto& r=item.second;
            if(wall>=r.timestamp-5&&wall-r.timestamp<=TTL&&mono>=r.received&&mono-r.received<=TTL)out.push_back(r);
        }return out;
    }
};
} // namespace
#endif
