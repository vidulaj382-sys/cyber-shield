#include "VaultItem.h"
#include "Exceptions.h"

namespace cyber {
namespace bytes {

void putNumber(std::string& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8)
        out += static_cast<char>((value >> shift) & 0xFF);
}

void putText(std::string& out, const std::string& text) {
    putNumber(out, static_cast<std::uint32_t>(text.size())); // length first, then the letters
    out += text;
}

std::uint32_t getNumber(const std::string& in, std::size_t& pos) {
    if (pos + 4 > in.size())
        throw FileException("safe box", "the file is damaged (it ends too early)");
    std::uint32_t value = 0;
    for (int shift = 0; shift < 32; shift += 8)
        value |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[pos++])) << shift;
    return value;
}

std::string getText(const std::string& in, std::size_t& pos) {
    std::uint32_t length = getNumber(in, pos);
    if (length > in.size() - pos)
        throw FileException("safe box", "the file is damaged (a text is too long)");
    std::string text = in.substr(pos, length);
    pos += length;
    return text;
}

} // namespace bytes
} // namespace cyber
