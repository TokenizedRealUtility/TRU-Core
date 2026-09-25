#pragma once
// UI-only transaction intent validator. No keys and no consensus APIs.
// This header is also covered by tests/test_intent.cpp independent of Qt.
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
namespace tru_desktop_07 {
struct Output {std::uint64_t amount=0; std::string scriptHex;};
inline void verifyIntent(const std::vector<Output>& actual,
                         const std::vector<Output>& expected,
                         std::uint64_t inputs,
                         std::uint64_t maximumFee) {
    if (actual.size()!=expected.size() || actual.empty())
        throw std::runtime_error("unexpected output count");
    std::uint64_t sum=0;
    for(std::size_t i=0;i<actual.size();++i) {
        if(actual[i].amount!=expected[i].amount || actual[i].scriptHex!=expected[i].scriptHex)
            throw std::runtime_error("prepared output differs from locally approved intent");
        if(actual[i].amount>UINT64_MAX-sum)
            throw std::runtime_error("prepared output amount overflow");
        sum+=actual[i].amount;
    }
    if(inputs<sum || inputs-sum>maximumFee)
        throw std::runtime_error("prepared transaction fee exceeds approved limit");
}
}
