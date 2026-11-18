#include "XorCipher.h"

#include <cstdint>

namespace cyber {

std::string XorCipher::mix(const std::string& data) const {
    // Turn the key into a starting number.
    std::uint32_t state = 2166136261u;
    for (unsigned char c : key)
        state = (state ^ c) * 16777619u;

    // Every byte gets its own secret byte from a number generator.
    std::string result = data;
    for (char& c : result) {
        state = state * 1664525u + 1013904223u;
        c = static_cast<char>(static_cast<unsigned char>(c) ^ (state >> 24));
    }
    return result;
}

} // namespace cyber
