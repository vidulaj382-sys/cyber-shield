#include "RiskScore.h"
#include "Utils.h"

namespace cyber {

RiskScore RiskScore::forSeverity(Severity severity) {
    switch (severity) {
    case Severity::Low:      return RiskScore(1);
    case Severity::Medium:   return RiskScore(3);
    case Severity::High:     return RiskScore(6);
    case Severity::Critical: return RiskScore(10);
    }
    return RiskScore(0);
}

RiskScore& RiskScore::operator+=(const RiskScore& other) {
    points += other.points;
    return *this; // returning *this allows chaining: a += b += c
}

int RiskScore::percent() const {
    return util::clampValue(points * 4, 0, 100); // 25 points = 100 %
}

std::string RiskScore::level() const {
    int p = percent();
    if (p < 25) return "Low";
    if (p < 50) return "Medium";
    if (p < 75) return "High";
    return "Critical";
}

std::ostream& operator<<(std::ostream& out, const RiskScore& r) {
    return out << r.percent() << "% (" << r.level() << ", " << r.points << " points)";
}

} // namespace cyber
