#pragma once
// WOTS+ SHA2, n=32,w=16,len=67. RFC 8391 algorithms 2,5,6,7,8;
// single OTS address 0 with a unique public seed per key. TRU message wrapper
// and 32-byte L-tree root are protocol-specific. Not an XMSS signature format.
#include <array>
#include <algorithm>
#include <cstdint>
#include <vector>
#include <openssl/sha.h>
#include <openssl/crypto.h>
namespace tru_pq01 {
using Bytes = std::vector<unsigned char>;
using Node = std::array<unsigned char,32>;
inline constexpr size_t CHAINS = 67, SIGNATURE_BYTES = 2144;
inline Node hash(const Bytes& b) { Node r{}; SHA256(b.data(),b.size(),r.data()); return r; }
inline void word(Node& a, unsigned i, uint32_t v) {
    for (unsigned j=0;j<4;++j) a[4*i+j]=static_cast<unsigned char>(v>>(24-8*j));
}
inline Node keyed(unsigned tag, const Node& key, const unsigned char* p, size_t n) {
    Bytes b(32,0); b[31]=static_cast<unsigned char>(tag);
    b.insert(b.end(),key.begin(),key.end()); b.insert(b.end(),p,p+n); return hash(b);
}
inline Node prf(const Node& seed, const Node& address) { return keyed(3,seed,address.data(),32); }
inline Node chain(Node x,unsigned start,unsigned steps,const Node& seed,unsigned index) {
    Node a{}; word(a,5,index);
    for (unsigned j=start;j<start+steps;++j) {
        word(a,6,j); word(a,7,0); const auto k=prf(seed,a);
        word(a,7,1); const auto mask=prf(seed,a);
        for (unsigned z=0;z<32;++z) x[z]^=mask[z];
        x=keyed(0,k,x.data(),32);
    }
    return x;
}
inline Node treeHash(const Node& l,const Node& r,const Node& seed,unsigned height,unsigned index) {
    Node a{}; word(a,3,1); word(a,5,height); word(a,6,index);
    word(a,7,0); const auto k=prf(seed,a);
    word(a,7,1); const auto m0=prf(seed,a);
    word(a,7,2); const auto m1=prf(seed,a);
    std::array<unsigned char,64> b{};
    for(unsigned j=0;j<32;++j) {b[j]=l[j]^m0[j];b[j+32]=r[j]^m1[j];}
    return keyed(1,k,b.data(),64);
}
inline Node root(std::array<Node,CHAINS> p,const Node& seed) {
    size_t len=CHAINS; unsigned h=0;
    while(len>1) {
        for(size_t i=0;i<len/2;++i) p[i]=treeHash(p[2*i],p[2*i+1],seed,h,static_cast<unsigned>(i));
        if(len&1) p[len/2]=p[len-1];
        len=(len+1)/2; ++h;
    }
    return p[0];
}
inline std::array<unsigned,CHAINS> digits(const Bytes& sighash) {
    const char domain[]="TRU-WOTS-V1|21e8|";
    Bytes b(domain,domain+sizeof(domain)-1); b.insert(b.end(),sighash.begin(),sighash.end());
    const auto h1=hash(b); b.assign(h1.begin(),h1.end()); const auto msg=hash(b);
    std::array<unsigned,CHAINS> d{}; unsigned sum=0;
    for(size_t i=0;i<32;++i) {d[2*i]=msg[i]>>4;d[2*i+1]=msg[i]&15;}
    for(size_t i=0;i<64;++i) sum+=15-d[i];
    // Three big-endian base-16 checksum digits (RFC left-shift/base_w).
    d[64]=(sum>>8)&15; d[65]=(sum>>4)&15; d[66]=sum&15; return d;
}
inline bool verify(const Bytes& sig,const Bytes& version,const Bytes& seedBytes,
                   const Bytes& rootBytes,const Bytes& sighash) {
    if(version!=Bytes{1} || sig.size()!=SIGNATURE_BYTES || seedBytes.size()!=32 ||
       rootBytes.size()!=32 || sighash.size()!=32) return false;
    Node seed{}; std::copy(seedBytes.begin(),seedBytes.end(),seed.begin());
    const auto d=digits(sighash); std::array<Node,CHAINS> pk{};
    for(size_t i=0;i<CHAINS;++i) {
        Node x{}; std::copy_n(sig.begin()+i*32,32,x.begin());
        pk[i]=chain(x,d[i],15-d[i],seed,static_cast<unsigned>(i));
    }
    const auto r=root(pk,seed); return CRYPTO_memcmp(r.data(),rootBytes.data(),32)==0;
}
}
