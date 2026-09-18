#pragma once

#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

namespace tru_amount {

inline constexpr std::uint64_t ATOMS_PER_TRU = 100000000ULL;

inline bool parse(const std::string& raw,
                  std::uint64_t& atomsOut,
                  std::string& reason)
{
    atomsOut = 0;
    reason.clear();

    std::size_t begin = 0;
    std::size_t end = raw.size();
    while (begin < end &&
           (raw[begin] == ' ' || raw[begin] == '\t' ||
            raw[begin] == '\r' || raw[begin] == '\n')) {
        ++begin;
    }
    while (end > begin &&
           (raw[end - 1] == ' ' || raw[end - 1] == '\t' ||
            raw[end - 1] == '\r' || raw[end - 1] == '\n')) {
        --end;
    }

    if (begin == end) {
        reason = "amount is empty";
        return false;
    }

    const std::string s = raw.substr(begin, end - begin);
    if (s.front() == '+' || s.front() == '-') {
        reason = "signs are not allowed";
        return false;
    }

    const std::size_t dot = s.find('.');
    if (dot != std::string::npos && s.find('.', dot + 1) != std::string::npos) {
        reason = "amount contains more than one decimal point";
        return false;
    }

    const std::string wholePart =
        dot == std::string::npos ? s : s.substr(0, dot);
    const std::string fracPart =
        dot == std::string::npos ? std::string() : s.substr(dot + 1);

    if (wholePart.empty() && fracPart.empty()) {
        reason = "amount has no digits";
        return false;
    }
    if (fracPart.size() > 8) {
        reason = "TRU supports at most 8 decimal places";
        return false;
    }

    auto digitsOnly = [](const std::string& part) {
        for (unsigned char c : part) {
            if (c < '0' || c > '9') return false;
        }
        return true;
    };

    if ((!wholePart.empty() && !digitsOnly(wholePart)) ||
        (!fracPart.empty() && !digitsOnly(fracPart))) {
        reason = "amount must contain decimal digits only";
        return false;
    }

    std::uint64_t whole = 0;
    for (char c : wholePart) {
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (whole >
            (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
            reason = "whole-TRU amount overflows uint64";
            return false;
        }
        whole = whole * 10ULL + digit;
    }

    std::uint64_t fraction = 0;
    for (char c : fracPart) {
        fraction = fraction * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    for (std::size_t i = fracPart.size(); i < 8; ++i) {
        fraction *= 10ULL;
    }

    const auto max = std::numeric_limits<std::uint64_t>::max();
    if (whole > (max - fraction) / ATOMS_PER_TRU) {
        reason = "TRU amount overflows uint64 atomic range";
        return false;
    }

    atomsOut = whole * ATOMS_PER_TRU + fraction;
    return true;
}

inline std::string formatNumeric(std::uint64_t atoms)
{
    const std::uint64_t whole = atoms / ATOMS_PER_TRU;
    const std::uint64_t fraction = atoms % ATOMS_PER_TRU;
    std::ostringstream out;
    out << whole << '.' << std::setw(8) << std::setfill('0') << fraction;
    return out.str();
}

inline std::string format(std::uint64_t atoms)
{
    return formatNumeric(atoms) + " TRU";
}

inline std::string formatAtoms(std::uint64_t atoms)
{
    return std::to_string(atoms) +
           (atoms == 1 ? " TRU atom" : " TRU atoms");
}

} // namespace tru_amount
