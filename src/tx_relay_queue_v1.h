#ifndef TRU_TX_RELAY_QUEUE_V1_H
#define TRU_TX_RELAY_QUEUE_V1_H
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_set>
// TX-RELAY-01: bounded identifiers only. No wallet access, transaction creation,
// persistence, mempool scanning, retransmission timer, or reorg resurrection.
namespace tru_tx_relay {
class Queue {
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<std::string> pending_;
    std::unordered_set<std::string> ids_;
    bool closed_=false;
public:
    static constexpr std::size_t CAPACITY=2048;
    bool enqueue(const std::string& id) noexcept {
        try {
            if(id.size()!=64||!std::all_of(id.begin(),id.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))return false;
            std::lock_guard<std::mutex> lock(mutex_);
            if(closed_)return false;
            if(ids_.count(id))return true;
            if(pending_.size()>=CAPACITY)return false;
            ids_.insert(id);
            try {pending_.push_back(id);}catch(...){ids_.erase(id);throw;}
            ready_.notify_one();return true;
        } catch(...) {return false;}
    }
    bool take(std::string& id) {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock,[&]{return closed_||!pending_.empty();});
        if(closed_)return false;
        id=std::move(pending_.front());pending_.pop_front();ids_.erase(id);return true;
    }
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);closed_=true;pending_.clear();ids_.clear();ready_.notify_all();
    }
};
}
#endif
