#pragma once
// Scrambles text with a secret key, so the Safe Box file cannot be read.
// Mixes every byte of the text with a secret stream made from the key. Doing it twice
// with the same key gives the original text back, so encrypt() and decrypt() are the
// same operation.
// NOTE: a teaching cipher. Real programs use AES or similar.
#include <string>

namespace cyber {

class XorCipher {
public:
    explicit XorCipher(const std::string& key) : key(key) {}

    std::string encrypt(const std::string& text) const { return mix(text); }
    std::string decrypt(const std::string& text) const { return mix(text); }

private:
    std::string mix(const std::string& data) const;
    std::string key;
};

} // namespace cyber
