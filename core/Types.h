#pragma once
#include <string>
#include "Exceptions.h"

namespace cyber {

enum class Severity { Low = 1, Medium = 2, High = 3, Critical = 4 };

inline std::string severityName(Severity s) {
    switch (s) {
    case Severity::Low:      return "Low";
    case Severity::Medium:   return "Medium";
    case Severity::High:     return "High";
    case Severity::Critical: return "Critical";
    }
    return "Unknown";
}

inline Severity toSeverity(int value) {
    if (value < 1 || value > 4)
        throw ValidationException("severity must be between 1 and 4");
    return static_cast<Severity>(value);
}

} // namespace cyber
