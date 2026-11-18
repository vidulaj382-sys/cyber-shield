#pragma once
// A 0..100 risk number for ONE device, built from several parts:
//   how important the device is + alerts + open problems + missing security checks.
// Unit III: operator+ (add the parts), operator< (to sort devices) and operator<<.
#include <ostream>
#include <string>
#include "Types.h"

namespace cyber {

class AssetRisk {
public:
    AssetRisk() : points(0) {}
    explicit AssetRisk(int points) : points(points) {}

    AssetRisk operator+(const AssetRisk& other) const { return AssetRisk(points + other.points); }
    bool operator<(const AssetRisk& other) const { return percent() < other.percent(); }

    int percent() const;          // 0..100, never more
    std::string level() const;    // Low / Medium / High / Critical
    Severity severity() const;    // the same level as a Severity (used for colours)

    friend std::ostream& operator<<(std::ostream& out, const AssetRisk& r);

private:
    int points;
};

} // namespace cyber
