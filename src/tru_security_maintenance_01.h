#pragma once
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
namespace tru_maintenance01 {
inline constexpr const char* AUTO_ENV = "TRU_ENABLE_08B4D9_AUTOMATIC_REORG";
inline constexpr const char* AUTO_MAGIC = "I_ACCEPT_PRODUCTION_CHAINWORK_REORGANIZATION";
inline bool automaticReorg(const std::string* configured, const char* environment) {
    if (configured) {
        std::string v = *configured;
        std::transform(v.begin(),v.end(),v.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
        if(v=="1"||v=="true"||v=="yes"||v=="on") return true;
        if(v=="0"||v=="false"||v=="no"||v=="off") return false;
        throw std::runtime_error("Invalid [network] automaticReorg value; expected 0/1/true/false");
    }
    // Explicit environment presence overrides the default, including an empty
    // or malformed value (disabled). Explicit config always wins over it.
    return environment ? std::string(environment)==AUTO_MAGIC : true;
}
class TxIngressBudget {
    struct Bucket { double tokens; double time; };
    std::mutex mutex_;
    Bucket total_{1600.0,0.0};
    std::unordered_map<std::string,Bucket> peers_;
    bool initialized_{false};
public:
    // Policy units, not consensus gas. Legacy small-script transactions cost 1;
    // a canonical 2147-byte PQ unlocking script adds 9 units. A single existing
    // large valid transaction is not excluded merely for having many inputs.
    bool admit(const std::string& peer, double units, double now) {
        if(peer.empty() || peer.size()>128 || !std::isfinite(units) ||
           !std::isfinite(now) || units<1.0 || now<0.0) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if(!initialized_){total_.time=now;initialized_=true;}
        if(now<total_.time) return false;
        if(peers_.find(peer)==peers_.end() && peers_.size()>=4096){
            for(auto it=peers_.begin();it!=peers_.end();)
                if(now-it->second.time>=120.0)it=peers_.erase(it);else ++it;
            if(peers_.size()>=4096)return false;
        }
        auto result=peers_.emplace(peer,Bucket{160.0,now});
        auto& p=result.first->second;
        if(now<p.time)return false;
        p.tokens=std::min(160.0,p.tokens+(now-p.time)*40.0);p.time=now;
        total_.tokens=std::min(1600.0,total_.tokens+(now-total_.time)*400.0);total_.time=now;
        const double cost=std::min(160.0,units);
        if(p.tokens<cost||total_.tokens<cost)return false;
        p.tokens-=cost;total_.tokens-=cost;return true;
    }
};
inline TxIngressBudget& txIngressBudget(){static TxIngressBudget budget;return budget;}
inline double monotonicSeconds(){return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();}
} // namespace tru_maintenance01
