#include "SeverityCounts.h"

namespace cyber {

SeverityCounts::SeverityCounts() : counts(new int[kSize]) {
    for (int i = 0; i < kSize; ++i)
        counts[i] = 0;
}

// Deep copy: allocate a NEW array and copy the numbers into it.
SeverityCounts::SeverityCounts(const SeverityCounts& other) : counts(new int[kSize]) {
    for (int i = 0; i < kSize; ++i)
        counts[i] = other.counts[i];
}

SeverityCounts& SeverityCounts::operator=(const SeverityCounts& other) {
    if (this != &other) { // protect against self-assignment (uses the 'this' pointer)
        for (int i = 0; i < kSize; ++i)
            counts[i] = other.counts[i];
    }
    return *this;
}

SeverityCounts::~SeverityCounts() { delete[] counts; }

void SeverityCounts::add(Severity severity) {
    ++counts[static_cast<int>(severity) - 1];
}

int SeverityCounts::count(Severity severity) const {
    return counts[static_cast<int>(severity) - 1];
}

int SeverityCounts::largest() const {
    int best = 0;
    for (int i = 0; i < kSize; ++i)
        if (counts[i] > best)
            best = counts[i];
    return best;
}

} // namespace cyber
