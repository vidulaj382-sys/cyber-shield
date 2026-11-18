#pragma once
// A password with a strength score and a tip.
// Unit III: operator overloading (<, ==, +, <<) and string handling.
#include <ostream>
#include <string>

namespace cyber {

class Password {
public:
    explicit Password(const std::string& text) : value(text) {}

    const std::string& text() const { return value; }

    int score() const;           // 0 (terrible) .. 100 (excellent)
    std::string rating() const;  // "Weak", "OK" or "Strong"
    std::string tip() const;     // one sentence telling how to make it stronger

    // Operators
    bool operator<(const Password& other) const { return score() < other.score(); } // weaker than
    bool operator==(const Password& other) const { return value == other.value; }   // same text
    Password operator+(const std::string& extra) const { return Password(value + extra); } // add characters

    // Prints stars and the rating, never the real password.
    friend std::ostream& operator<<(std::ostream& out, const Password& p);

private:
    std::string value;
};

} // namespace cyber
