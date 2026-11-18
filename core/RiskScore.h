#pragma once
// Unit III: operator overloading (+, +=, >, <<) on a small value class.
// The overall risk of the system is the sum of the risk points of every
// open incident, added together with operator+.
#include <ostream>
#include <string>
#include "Types.h"

namespace cyber {

class RiskScore {
public:
    RiskScore() : points(0) {}
    explicit RiskScore(int points) : points(points) {}

    // Risk points of ONE incident of this severity (Low=1 ... Critical=10).
    static RiskScore forSeverity(Severity severity);

    RiskScore operator+(const RiskScore& other) const { return RiskScore(points + other.points); }
    RiskScore& operator+=(const RiskScore& other);
    bool operator>(const RiskScore& other) const { return points > other.points; }

    int getPoints() const { return points; }
    int percent() const;          // 0..100
    std::string level() const;    // Low / Medium / High / Critical

    friend std::ostream& operator<<(std::ostream& out, const RiskScore& r);

private:
    int points;
};

} // namespace cyber
