#pragma once
// TRU-AI-EVOLVE-07D: read-only, terminal-width-aware preview pagination.
// No wallet, RPC, issuer proof, evolution schema, or chain behavior here.
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace tru_evolve_preview07d {
struct Section {
    std::string title;
    std::vector<std::string> lines;
};
struct Page {
    std::string title;
    std::vector<std::string> lines;
};

inline std::string printable(const std::string& text) {
    // A provider/user trigger is untrusted terminal content. Prevent control
    // sequences and embedded newlines from stealing the terminal cursor.
    std::string out;
    out.reserve(text.size());
    bool whitespace = false;
    for (unsigned char c : text) {
        if (c <= 0x20U || c == 0x7fU ) {
            if (!out.empty()) whitespace = true;
            continue;
        }
        if (whitespace && !out.empty()) out.push_back(' ');
        whitespace = false;
        out.push_back(static_cast<char>(c));
    }
    if (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

// Width is in output bytes rather than terminal cells. This is conservative
// for ASCII values (IDs/hashes/JSON), while preserving every UTF-8 byte.
inline std::vector<std::string> wrapText(const std::string& raw, std::size_t width) {
    width = std::max<std::size_t>(12, width);
    const std::string text = printable(raw);
    if (text.empty()) return {"(empty)"};
    std::vector<std::string> lines;
    std::string line;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && text[pos] == ' ') ++pos;
        if (pos == text.size()) break;
        std::size_t end = text.find(' ', pos);
        if (end == std::string::npos) end = text.size();
        std::string word = text.substr(pos, end - pos);
        pos = end;
        if (!line.empty() && line.size() + 1 + word.size() > width) {
            lines.push_back(std::move(line));
            line.clear();
        }
        while (word.size() > width) {
            // Never split a UTF-8 continuation byte across rendered lines.
            std::size_t split = width;
            while (split > 0 && split < word.size() &&
                   (static_cast<unsigned char>(word[split]) & 0xc0U) == 0x80U)
                --split;
            if (split == 0) split = width;
            lines.push_back(word.substr(0, split));
            word.erase(0, split);
        }
        if (word.empty()) continue;
        if (line.empty()) line = std::move(word);
        else line += " " + word;
    }
    if (!line.empty()) lines.push_back(std::move(line));
    if (lines.empty()) lines.push_back("(empty)");
    return lines;
}

inline void field(std::vector<std::string>& dest,
                  const std::string& label,
                  const std::string& value,
                  std::size_t width) {
    dest.push_back(printable(label) + ":");
    const std::size_t available = std::max<std::size_t>(12, width > 2 ? width - 2 : 12);
    for (const auto& line : wrapText(value, available)) dest.push_back("  " + line);
}

// Never exceed the result zone. Header takes one line when capacity >= 2;
// capacity==1 is supported for short terminals without dropping content.
inline std::vector<Page> paginate(const std::vector<Section>& sections,
                                  std::size_t capacity,
                                  std::size_t terminalWidth = 80) {
    capacity = std::max<std::size_t>(1, capacity);
    const std::size_t chunkSize = capacity > 1 ? capacity - 1 : 1;
    std::vector<Page> result;
    for (const auto& section : sections) {
        const std::vector<std::string> fallback{ "(no fields)" };
        const auto& source = section.lines.empty() ? fallback : section.lines;
        for (std::size_t begin = 0; begin < source.size(); begin += chunkSize) {
            Page page{section.title, {}};
            if (capacity > 1) {
                const std::size_t maxTitle = terminalWidth > 10 ? terminalWidth - 8 : 12;
                page.lines.push_back("=== " + printable(section.title).substr(0, maxTitle) + " ===");
            }
            const std::size_t end = std::min(source.size(), begin + chunkSize);
            page.lines.insert(page.lines.end(), source.begin() + begin, source.begin() + end);
            result.push_back(std::move(page));
        }
    }
    if (result.empty()) result.push_back({"Preview", {"(no preview fields)"}});
    return result;
}
} // namespace tru_evolve_preview07d
