#include "Password.h"
#include "Utils.h"

#include <algorithm>
#include <cctype>

namespace cyber {

namespace {
// Very common passwords get a very low score whatever their length.
bool isCommon(const std::string& password) {
    const char* common[] = {"password", "123456", "qwerty", "admin", "letmein", "welcome", "iloveyou"};
    std::string lower = util::toLower(password);
    for (const char* word : common)
        if (lower.find(word) != std::string::npos)
            return true;
    return false;
}

struct Kinds {
    bool lower = false, upper = false, digit = false, symbol = false;
};

Kinds kindsIn(const std::string& text) {
    Kinds kinds;
    for (unsigned char c : text) {
        if (std::islower(c)) kinds.lower = true;
        else if (std::isupper(c)) kinds.upper = true;
        else if (std::isdigit(c)) kinds.digit = true;
        else kinds.symbol = true;
    }
    return kinds;
}
} // namespace

int Password::score() const {
    Kinds kinds = kindsIn(value);
    int points = std::min<int>(static_cast<int>(value.size()), 16) * 3; // length: up to 48
    if (kinds.lower) points += 8;
    if (kinds.upper) points += 12;
    if (kinds.digit) points += 12;
    if (kinds.symbol) points += 20;

    if (isCommon(value))
        points = std::min(points, 15);
    if (!value.empty() && value.find_first_not_of(value[0]) == std::string::npos)
        points = std::min(points, 10); // "aaaaaaaa"
    return util::clampValue(points, 0, 100);
}

std::string Password::rating() const {
    int s = score();
    if (s < 40) return "Weak";
    if (s < 70) return "OK";
    return "Strong";
}

std::string Password::tip() const {
    if (value.empty())
        return "Type a password to see how strong it is.";
    Kinds kinds = kindsIn(value);
    if (isCommon(value))
        return "This is a very common password. Pick something nobody could guess.";
    if (value.size() < 8)
        return "Make it at least 8 characters long.";
    if (!kinds.upper)
        return "Add a CAPITAL letter.";
    if (!kinds.digit)
        return "Add a number.";
    if (!kinds.symbol)
        return "Add a symbol like ! or #.";
    if (value.size() < 12)
        return "Almost perfect: a few more characters make it even stronger.";
    return "Great password!";
}

std::ostream& operator<<(std::ostream& out, const Password& p) {
    return out << std::string(p.value.size(), '*') << " (" << p.rating() << ", " << p.score() << "/100)";
}

} // namespace cyber
