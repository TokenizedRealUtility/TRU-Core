#pragma once
// MARKET-03: private, same-user IPC. No HTTP listener and no signing RPC.
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>
#include <regex>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tru_market_connect_v1 {
using Json = nlohmann::json;
inline int directory(const std::string& wallet) {
    if (wallet != "core" && wallet != "desktop") return -1;
    const char* home = std::getenv("HOME");
    if (!home || home[0]!='/') return -1;
    const std::string base=std::string(home)+"/.local/share/tru-market-connect";
    struct stat s{};
    if (::lstat(base.c_str(), &s)!=0 || !S_ISDIR(s.st_mode) || s.st_uid!=::getuid() || (s.st_mode&0077)) return -1;
    int parent=::open(base.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(parent<0)return -1;
    int fd=::openat(parent,wallet.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    ::close(parent);
    if(fd<0)return -1;
    if(::fstat(fd,&s)!=0 || s.st_uid!=::getuid() || (s.st_mode&0077)){::close(fd);return -1;}
    return fd;
}
inline bool take(const std::string& wallet,Json& out) {
    int d=directory(wallet);if(d<0)return false;
    const std::string claimed="claimed-"+std::to_string(::getpid())+".json";
    if(::renameat(d,"request.json",d,claimed.c_str())!=0){::close(d);return false;}
    int f=::openat(d,claimed.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(f<0){::unlinkat(d,claimed.c_str(),0);::close(d);return false;}
    struct stat s{};
    bool valid=::fstat(f,&s)==0 && S_ISREG(s.st_mode) && s.st_uid==::getuid() && !(s.st_mode&0077) && s.st_size>0 && s.st_size<=4096;
    std::string raw(valid?static_cast<size_t>(s.st_size):0,'\0');
    size_t at=0;
    while(valid && at<raw.size()){ssize_t n=::read(f,&raw[at],raw.size()-at);if(n<=0){valid=false;break;}at+=static_cast<size_t>(n);}
    ::close(f);::unlinkat(d,claimed.c_str(),0);::close(d);
    if(!valid)return false;
    try{
        out=Json::parse(raw);
        const auto id=out.at("id").get<std::string>();
        const auto op=out.at("op").get<std::string>();
        const auto exp=out.at("expires").get<long long>();
        const auto now=static_cast<long long>(std::time(nullptr));
        return std::regex_match(id,std::regex("[0-9a-f]{32}")) && (op=="accounts" || op=="sign") && exp>now && exp<=now+310;
    }catch(...){return false;}
}
inline void reply(const std::string& wallet,const Json& request,const Json& result) {
    const std::string id=request.value("id","");
    if(!std::regex_match(id,std::regex("[0-9a-f]{32}")))return;
    int d=directory(wallet);if(d<0)return;
    const std::string name="response-"+id+".json", tmp=name+".tmp";
    int f=::openat(d,tmp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(f<0){::close(d);return;}
    std::string raw=result.dump();size_t at=0;bool ok=raw.size()<=65536;
    while(ok && at<raw.size()){ssize_t n=::write(f,raw.data()+at,raw.size()-at);if(n<=0){ok=false;break;}at+=static_cast<size_t>(n);}
    if(::close(f)!=0)ok=false;
    if(ok)::renameat(d,tmp.c_str(),d,name.c_str());else ::unlinkat(d,tmp.c_str(),0);
    ::close(d);
}
}
