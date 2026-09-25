#pragma once
#include <atomic>
namespace tru_hardening {
// Local admission only. Shared between direct explorer and gateway submissions.
class SubmissionSlot {
    std::atomic<unsigned>* counter_{nullptr};
    bool admitted_{true};
public:
    explicit SubmissionSlot(std::atomic<unsigned>& count, bool needed = true) {
        if (!needed) return;
        unsigned current = count.load(std::memory_order_relaxed);
        while (current < 2) {
            if (count.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel)) {
                counter_ = &count; return;
            }
        }
        admitted_ = false;
    }
    ~SubmissionSlot() { if (counter_) counter_->fetch_sub(1, std::memory_order_release); }
    explicit operator bool() const { return admitted_; }
    SubmissionSlot(const SubmissionSlot&) = delete;
    SubmissionSlot& operator=(const SubmissionSlot&) = delete;
};
}
