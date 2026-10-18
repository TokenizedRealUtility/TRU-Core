#pragma once
#include "wots_pq01.h"
namespace tru_pq01 {
// <01> <seed32> <root32> CHECKWOTSVERIFY [<compressedECDSA33>
// CHECKSIGVERIFY] OP_1. scriptSig order: [ECDSA signature] WOTS signature.
inline bool canonicalScript(const Bytes& s) {
    if(s.size()!=69 && s.size()!=104)return false;
    if(s[0]!=0x51||s[1]!=32||s[34]!=32||s[67]!=0xbb||s.back()!=0x51)return false;
    if(s.size()==104&&(s[68]!=33||(s[69]!=2&&s[69]!=3)||s[102]!=0xad))return false;
    return true;
}
}
