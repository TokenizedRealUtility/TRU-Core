#pragma once
// Presentation-only decoder. Never use this helper as a consensus ownership key.
#include "wots_script09.h"
#include <string>
namespace tru_pq01_display {
inline std::string hex(const tru_pq01::Bytes& bytes) {
    const char* digits="0123456789abcdef";std::string result;
    for(auto c:bytes){result+=digits[c>>4];result+=digits[c&15];}return result;
}
inline bool decode(const std::string& text, tru_pq01::Bytes& bytes) {
    bytes.clear();if(text.size()!=138 && text.size()!=208)return false;
    auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    for(size_t i=0;i<text.size();i+=2){int a=digit(text[i]),b=digit(text[i+1]);if(a<0||b<0){bytes.clear();return false;}bytes.push_back(static_cast<unsigned char>((a<<4)|b));}
    return tru_pq01::canonicalScript(bytes);
}
inline std::string address(const std::string& text) {
    tru_pq01::Bytes script;
    // The existing truq1 wallet parser supports 69-byte pure-PQ01 only.
    // Do not advertise an unsupported 104-byte hybrid as a receiving descriptor.
    if(!decode(text,script)||script.size()!=69)return {};
    const auto digest=tru_pq01::hash(script);
    return "truq1:"+hex(script)+":"+hex(tru_pq01::Bytes(digest.begin(),digest.begin()+8));
}
} // namespace tru_pq01_display
