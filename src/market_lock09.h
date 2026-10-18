#pragma once
// Consensus-only binary parsing. No DB, addresses, JSON, floating point or wall
// clock. ReadInput must return the *confirmed parent transaction* of a live UTXO.
#include "consensus09_activation.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>
namespace tru_market09 {
using Bytes=std::vector<unsigned char>;
inline bool unhex(const std::string& s,Bytes& b) {
    b.clear(); if(s.size()%2) return false;
    for(size_t i=0;i<s.size();i+=2) {
        auto d=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
        int a=d(s[i]),z=d(s[i+1]);if(a<0||z<0)return false;b.push_back(static_cast<unsigned char>(a*16+z));
    } return true;
}
inline std::string hex(const Bytes& b) {
    const char* t="0123456789abcdef";std::string s;for(auto c:b){s+=t[c>>4];s+=t[c&15];}return s;
}
inline uint64_t le(const Bytes& b,size_t p,unsigned n) {uint64_t r=0;for(unsigned j=0;j<n;++j)r|=uint64_t(b[p+j])<<(8*j);return r;}
inline void put(Bytes& b,uint64_t v,unsigned n) {for(unsigned j=0;j<n;++j)b.push_back(static_cast<unsigned char>(v>>(8*j)));}
inline bool add(uint64_t& sum,uint64_t n){if(n>UINT64_MAX-sum)return false;sum+=n;return true;}
inline std::string pay(const std::string& owner){return "76a914"+owner+"88ac";}
struct Asset {unsigned type=0;std::string id,meta;bool operator==(const Asset& a) const{return type==a.type&&id==a.id&&meta==a.meta;}};
struct Token {Asset asset;std::string owner;uint64_t amount=0;};
struct Terms {Asset offered,wanted;std::string seller;uint64_t quantity=0,price=0,lot=0;uint32_t expiry=0;};
inline bool tokenShape(const std::string& s) {
    Bytes b;return unhex(s,b)&&(b.size()==70||b.size()==66)&&b[0]==0x6a&&b[1]>=1&&b[1]<=4;
}
inline bool token(const std::string& s,Token& t) {
    Bytes b;if(!unhex(s,b)||(b.size()!=70&&b.size()!=66)||b[0]!=0x6a||b[1]<1||b[1]>4)return false;
    const size_t n=b.size()==70?8:4;Token r;r.asset.type=b[1];
    r.asset.id=hex(Bytes(b.begin()+2,b.begin()+2+n));
    r.amount=0;for(unsigned i=0;i<8;++i)r.amount=(r.amount<<8)|b[2+n+i];
    r.owner=hex(Bytes(b.begin()+10+n,b.begin()+30+n));r.asset.meta=hex(Bytes(b.begin()+30+n,b.end()));
    if(!r.amount||((r.asset.type==2||r.asset.type==4)&&r.amount!=1))return false;t=r;return true;
}
inline std::string data(const Token& t) {
    Bytes b{0x6a,static_cast<unsigned char>(t.asset.type)},x;
    if(!unhex(t.asset.id,x)||(x.size()!=4&&x.size()!=8))return "";b.insert(b.end(),x.begin(),x.end());
    for(int i=7;i>=0;--i)b.push_back(static_cast<unsigned char>(t.amount>>(8*i)));
    if(!unhex(t.owner,x)||x.size()!=20)return "";b.insert(b.end(),x.begin(),x.end());
    if(!unhex(t.asset.meta,x)||x.size()!=32)return "";b.insert(b.end(),x.begin(),x.end());return hex(b);
}
inline bool valid(const Terms& t) {
    Bytes b;
    if(t.offered.type<1||t.offered.type>4||t.offered.id.size()!=16||!unhex(t.offered.id,b)||
       t.offered.meta.size()!=64||!unhex(t.offered.meta,b)||t.seller.size()!=40||!unhex(t.seller,b)||
       !t.quantity||!t.price||!t.lot||t.quantity%t.lot||!t.expiry)return false;
    if((t.offered.type==2||t.offered.type==4)&&(t.quantity!=1||t.lot!=1))return false;
    if(t.wanted.type==0) {
        if(t.wanted.id!=std::string(16,'0')||t.wanted.meta!=std::string(64,'0'))return false;
    } else if(t.wanted.type>4||t.wanted.id==t.offered.id||t.wanted.id.size()!=16||!unhex(t.wanted.id,b)||
              t.wanted.meta.size()!=64||!unhex(t.wanted.meta,b))return false;
    if(t.quantity/t.lot>UINT64_MAX/t.price)return false;
    if(t.wanted.type==0&&t.quantity/t.lot*t.price>21000000ULL*100000000ULL)return false;
    if((t.wanted.type==2||t.wanted.type==4)&&t.quantity/t.lot*t.price!=1)return false;
    return true;
}
inline Bytes encode(const Terms& t) {
    Bytes b{'T','R','U','M','K','T','1',0,1,static_cast<unsigned char>(t.offered.type)},x;
    auto bytes=[&](const std::string& s){unhex(s,x);b.insert(b.end(),x.begin(),x.end());};
    bytes(t.offered.id);bytes(t.offered.meta);bytes(t.seller);put(b,t.quantity,8);
    b.push_back(static_cast<unsigned char>(t.wanted.type));bytes(t.wanted.id);bytes(t.wanted.meta);
    put(b,t.price,8);put(b,t.lot,8);put(b,t.expiry,4);return b;
}
inline bool decode(const Bytes& b,Terms& t) {
    const Bytes tag{'T','R','U','M','K','T','1',0,1};
    if(b.size()!=139||!std::equal(tag.begin(),tag.end(),b.begin()))return false;
    Terms r;r.offered.type=b[9];r.offered.id=hex(Bytes(b.begin()+10,b.begin()+18));
    r.offered.meta=hex(Bytes(b.begin()+18,b.begin()+50));r.seller=hex(Bytes(b.begin()+50,b.begin()+70));
    r.quantity=le(b,70,8);r.wanted.type=b[78];r.wanted.id=hex(Bytes(b.begin()+79,b.begin()+87));
    r.wanted.meta=hex(Bytes(b.begin()+87,b.begin()+119));r.price=le(b,119,8);r.lot=le(b,127,8);
    // Fixed size is 139: 8 tag+1 version+1 type+8 id+32 meta+20 owner+
    // 8 qty+1 wanted type+8 id+32 meta+8 price+8 lot+4 expiry.
    r.expiry=static_cast<uint32_t>(le(b,135,4));if(!valid(r))return false;t=r;return true;
}
inline std::string script(const Terms& t) {if(!valid(t))return "";auto b=encode(t);Bytes s{0x4c,static_cast<unsigned char>(b.size())};s.insert(s.end(),b.begin(),b.end());s.push_back(0xbc);s.push_back(0x51);return hex(s);}
inline bool parseLock(const std::string& s,Terms& t) {Bytes b;if(!unhex(s,b)||b.size()!=143||b[0]!=0x4c||b[1]!=139||b[141]!=0xbc||b[142]!=0x51)return false;return decode(Bytes(b.begin()+2,b.end()-2),t);}
// Canonical unlock: three direct pushes. Fill {01,quantityLE8,buyerHash16020};
// refund {02,strictDER+SIGHASH_ALL,compressedSecpPubKey33}.
inline bool pushes(const Bytes& s,std::vector<Bytes>& p) {p.clear();size_t i=0;while(i<s.size()){unsigned n=s[i++];if(n<1||n>75||n>s.size()-i)return false;p.emplace_back(s.begin()+i,s.begin()+i+n);i+=n;}return p.size()==3;}
struct Spend {unsigned mode=0;uint64_t quantity=0;std::string buyer;Bytes signature,pubkey;};
inline bool spend(const Bytes& b,Spend& s) {std::vector<Bytes> p;if(!pushes(b,p)||p[0].size()!=1)return false;Spend r;r.mode=p[0][0];if(r.mode==1){if(p[1].size()!=8||p[2].size()!=20)return false;r.quantity=le(p[1],0,8);r.buyer=hex(p[2]);}else if(r.mode==2){if(p[1].size()<9||p[1].size()>73||p[2].size()!=33||(p[2][0]!=2&&p[2][0]!=3))return false;r.signature=p[1];r.pubkey=p[2];}else return false;s=r;return true;}
template<class Tx> bool branch(const Tx& tx,size_t n,Token& t,Terms* out=nullptr) {
    if(!n||n>=tx.vout.size()||tx.vout[n-1].amount!=0||!token(tx.vout[n-1].scriptPubKey,t))return false;
    Terms terms;
    if(tx.vout[n].scriptPubKey==pay(t.owner)&&tx.vout[n].amount>0)return true;
    if(!parseLock(tx.vout[n].scriptPubKey,terms)||tx.vout[n].amount!=1||!(t.asset==terms.offered)||t.owner!=terms.seller||t.amount!=terms.quantity)return false;
    if(out)*out=terms;return true;
}
template<class Tx> bool pair(const Tx& tx,size_t n,const Token& expected,const std::string& control="") {
    Token t;if(n+1>=tx.vout.size()||!branch(tx,n+1,t)||!(t.asset==expected.asset)||t.amount!=expected.amount||t.owner!=expected.owner)return false;
    return tx.vout[n+1].amount==1&&tx.vout[n+1].scriptPubKey==(control.empty()?pay(expected.owner):control);
}
// Exact settlement layout; all outputs after the reserved prefix belong to the
// buyer (fill) or seller (refund). No hidden fee collector or platform key.
template<class Tx> bool outputs(const Tx& tx,const Terms& t,const Spend& s,uint32_t h,size_t& end) {
    end=0;if(s.mode==2){if(h<t.expiry||!pair(tx,0,Token{t.offered,t.seller,t.quantity}))return false;end=2;}
    else {
        if(h>=t.expiry||!s.quantity||s.quantity>t.quantity||s.quantity%t.lot)return false;
        if(!pair(tx,0,Token{t.offered,s.buyer,s.quantity}))return false;
        const uint64_t due=s.quantity/t.lot*t.price;
        if(!t.wanted.type){if(tx.vout.size()<3||tx.vout[2].amount!=due||tx.vout[2].scriptPubKey!=pay(t.seller))return false;end=3;}
        else{if(!pair(tx,2,Token{t.wanted,t.seller,due}))return false;end=4;}
        if(s.quantity<t.quantity){Terms rest=t;rest.quantity-=s.quantity;if(!pair(tx,end,Token{t.offered,t.seller,rest.quantity},script(rest)))return false;end+=2;}
    }
    const auto& owner=s.mode==1?s.buyer:t.seller;
    for(size_t n=end;n<tx.vout.size();++n){
        if(tx.vout[n].scriptPubKey==pay(owner))continue;
        Token c;
        if(s.mode!=1||!t.wanted.type||n+1>=tx.vout.size()||
           !branch(tx,n+1,c)||!(c.asset==t.wanted)||c.owner!=owner||
           tx.vout[n+1].scriptPubKey!=pay(owner))return false;
        ++n;
    }return true;
}
struct Result {bool ok=true,hasMarket=false;std::string reason;};
// Input callback receives input index and returns confirmed parent's full Tx.
// ExistingId is chain-derived issuance knowledge, never caller metadata.
template<class Tx,class ReadInput,class ExistingId> Result validate(const Tx& tx,uint32_t h,ReadInput read,ExistingId exists) {
    Result r;auto fail=[&](const char* why){r.ok=false;r.reason=why;return r;};
    if(!tru09::active(h,tru09::MARKET_HEIGHT))return r;
    // Block text transport retains script hex strings while TXIDs hash bytes.
    // Require a unique post-H output spelling, preventing case variants from
    // escaping token classification or sharing a payload commitment.
    for(const auto& o:tx.vout){Bytes bytes;if(!unhex(o.scriptPubKey,bytes)||hex(bytes)!=o.scriptPubKey)return fail("noncanonical output script hex");}
    std::map<std::string,uint64_t> ins,outs;std::map<std::string,unsigned> types;
    std::vector<Token> inputTokens(tx.vin.size());std::vector<bool> isToken(tx.vin.size(),false);
    std::vector<std::string> inputScripts;Terms spentTerms;Spend action;size_t locksIn=0,locksOut=0;
    for(size_t i=0;i<tx.vin.size();++i){
        Tx p;if(!read(i,p)||tx.vin[i].vout<0||size_t(tx.vin[i].vout)>=p.vout.size())return fail("missing confirmed parent");
        const auto n=size_t(tx.vin[i].vout);
        // Historical parent hex case is not an authority distinction.
        for(size_t k=(n?n-1:n);k<=n;++k){Bytes bytes;if(!unhex(p.vout[k].scriptPubKey,bytes))return fail("malformed parent script");p.vout[k].scriptPubKey=hex(bytes);}
        inputScripts.push_back(p.vout[n].scriptPubKey);
        Token t;isToken[i]=branch(p,n,t);inputTokens[i]=t;
        if(isToken[i]){if(!add(ins[t.asset.id],t.amount))return fail("token input overflow");if(types.count(t.asset.id)&&types[t.asset.id]!=t.asset.type)return fail("mixed input types");types[t.asset.id]=t.asset.type;}
        Terms terms;if(parseLock(p.vout[n].scriptPubKey,terms)){if(i!=0||!isToken[i]||++locksIn!=1)return fail("market input must be unique input zero");spentTerms=terms;if(!spend(tx.vin[i].scriptSig,action))return fail("noncanonical market unlock");r.hasMarket=true;}
    }
    for(size_t n=0;n<tx.vout.size();++n){
        Terms t;if(parseLock(tx.vout[n].scriptPubKey,t)){Token b;if(!n||!branch(tx,n,b)||++locksOut!=1)return fail("unpaired or duplicate market output");if(!locksIn&&t.expiry<=h)return fail("expired new lock");r.hasMarket=true;}
        Token b;if(!token(tx.vout[n].scriptPubKey,b)){
            if(tokenShape(tx.vout[n].scriptPubKey))return fail("invalid token quantity/type rules");
            continue;
        }
        Token checked;if(tx.vout[n].amount!=0||n+1>=tx.vout.size()||!branch(tx,n+1,checked))return fail("token/control mismatch");
        if(!add(outs[b.asset.id],b.amount))return fail("token output overflow");if(types.count(b.asset.id)&&types[b.asset.id]!=b.asset.type)return fail("token type changed");types[b.asset.id]=b.asset.type;
    }
    for(const auto& kv:ins)if(outs[kv.first]!=kv.second)return fail("token conservation");
    for(const auto& kv:outs)if(!ins.count(kv.first)&&exists(kv.first))return fail("unauthorized duplicate issuance");
    if(locksIn){
        size_t end;if(!outputs(tx,spentTerms,action,h,end))return fail("settlement outputs mismatch");
        const std::string owner=action.mode==1?action.buyer:spentTerms.seller;
        if(action.mode==1&&tx.vin.size()<2)return fail("buyer authorization missing");
        uint64_t paymentTokens=0;
        for(size_t i=1;i<inputScripts.size();++i){
            if(inputScripts[i]!=pay(owner))return fail("funding must belong to authorized party");
            if(isToken[i]){if(action.mode!=1||!(inputTokens[i].asset==spentTerms.wanted)||!add(paymentTokens,inputTokens[i].amount))return fail("unexpected funding token");}
        }
        if(action.mode==1&&spentTerms.wanted.type&&paymentTokens<action.quantity/spentTerms.lot*spentTerms.price)return fail("payment tokens not funded");
    }else if(locksOut){
        // A listing cannot be fabricated from an ordinary TRU input.
        for(size_t n=0;n<tx.vout.size();++n){Terms t;if(!parseLock(tx.vout[n].scriptPubKey,t))continue;
            if(inputScripts.empty()||inputScripts[0]!=pay(t.seller)||!isToken[0]||!(inputTokens[0].asset==t.offered)||inputTokens[0].amount<t.quantity)return fail("seller does not fund offered asset");
        }
    }
    return r;
}
}
