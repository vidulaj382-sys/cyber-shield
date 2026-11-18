#pragma once
// Small helpers shared by the whole core.
// Unit III: function templates and a nested namespace (cyber::util).
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace cyber {
namespace util {

// Function template: keep a value between a lower and an upper limit.
template <typename T>
const T& clampValue(const T& value, const T& low, const T& high) {
    if (value < low)
        return low;
    if (value > high)
        return high;
    return value;
}

// Function template: count the items of any container that satisfy a test.
template <typename Container, typename Test>
int countIf(const Container& items, Test test) {
    int count = 0;
    for (const auto& item : items)
        if (test(item))
            ++count;
    return count;
}

inline std::string toLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

inline std::string trim(const std::string& text) {
    const char* spaces = " \t\r\n";
    std::size_t first = text.find_first_not_of(spaces);
    if (first == std::string::npos)
        return "";
    return text.substr(first, text.find_last_not_of(spaces) - first + 1);
}

// Hides most letters of a name: "employee" becomes "e******e".
inline std::string maskName(const std::string& name) {
    if (name.size() <= 2)
        return std::string(name.size(), '*');
    return name.substr(0, 1) + std::string(name.size() - 2, '*') + name.substr(name.size() - 1);
}

// Replaces a name only where it stands alone as a whole word.
inline std::string replaceWord(const std::string& text, const std::string& word,
                               const std::string& replacement) {
    auto isLetter = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
    std::string result;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t hit = word.empty() ? std::string::npos : text.find(word, pos);
        if (hit == std::string::npos) {
            result += text.substr(pos);
            break;
        }
        bool alone = (hit == 0 || !isLetter(text[hit - 1])) &&
                     (hit + word.size() >= text.size() || !isLetter(text[hit + word.size()]));
        result += text.substr(pos, hit - pos);
        result += alone ? replacement : word;
        pos = hit + word.size();
    }
    return result;
}

inline bool startsWith(const std::string& text, const std::string& prefix) {
    return text.compare(0, prefix.size(), prefix) == 0;
}

// A deliberately simple password hash (djb2 with a salt), printed as hex.
// NOTE: fine for a course project, NOT secure enough for real systems.
inline std::string hashPassword(const std::string& password) {
    std::uint32_t hash = 5381;
    const std::string salted = "CyberShield$" + password;
    for (unsigned char c : salted)
        hash = hash * 33 + c; // hash * 33 + c
    const char* digits = "0123456789abcdef";
    std::string hex;
    for (int shift = 28; shift >= 0; shift -= 4)
        hex += digits[(hash >> shift) & 0xF];
    return hex;
}

// Function template: add one to the counter of a key (used to count things in a std::map).
template <typename Key>
void countUp(std::map<Key, int>& counts, const Key& key) {
    ++counts[key];
}

// Function template: the 'limit' biggest counters, biggest first.
template <typename Key>
std::vector<std::pair<Key, int>> topCounts(const std::map<Key, int>& counts, std::size_t limit) {
    std::vector<std::pair<Key, int>> list(counts.begin(), counts.end());
    std::sort(list.begin(), list.end(), [](const std::pair<Key, int>& a, const std::pair<Key, int>& b) {
        return a.second > b.second || (a.second == b.second && a.first < b.first);
    });
    if (list.size() > limit)
        list.resize(limit);
    return list;
}

// Binary text as readable hex ("Hi" -> "4869") and back.
inline std::string toHex(const std::string& data) {
    const char* digits = "0123456789abcdef";
    std::string hex;
    for (unsigned char c : data) {
        hex += digits[c >> 4];
        hex += digits[c & 0xF];
    }
    return hex;
}

// Returns an empty string and sets ok = false when the text is not valid hex.
inline std::string fromHex(const std::string& hex, bool& ok) {
    auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    ok = hex.size() % 2 == 0;
    std::string data;
    for (std::size_t i = 0; ok && i + 1 < hex.size(); i += 2) {
        int high = value(hex[i]), low = value(hex[i + 1]);
        if (high < 0 || low < 0)
            ok = false;
        else
            data += static_cast<char>(high * 16 + low);
    }
    return ok ? data : std::string();
}

} // namespace util
} // namespace cyber
