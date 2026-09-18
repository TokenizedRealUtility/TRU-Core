#ifndef MAIN_H
#define MAIN_H

#include <thread>

// -------------------------------------------------------------------
// ThreadJoiner: RAII class to ensure a thread is joined on destruction
// -------------------------------------------------------------------
class ThreadJoiner {
public:
    explicit ThreadJoiner(std::thread& t) : t_(t) {}
    ~ThreadJoiner() {
        if (t_.joinable()) {
            t_.join();
        }
    }
    // Prevent copying or assignment to avoid double-joining
    ThreadJoiner(const ThreadJoiner&) = delete;
    ThreadJoiner& operator=(const ThreadJoiner&) = delete;
private:
    std::thread& t_;
};

#endif // MAIN_H
