#include "AssetRisk.h"
#include "Utils.h"

namespace cyber {

int AssetRisk::percent() const {
    return util::clampValue(points, 0, 100);
}

Severity AssetRisk::severity() const {
    int p = percent();
    if (p < 25) return Severity::Low;
    if (p < 50) return Severity::Medium;
    if (p < 75) return Severity::High;
    return Severity::Critical;
}

std::string AssetRisk::level() const {
    return severityName(severity());
}

std::ostream& operator<<(std::ostream& out, const AssetRisk& r) {
    return out << r.percent() << "% (" << r.level() << ")";
}

} // namespace cyber
