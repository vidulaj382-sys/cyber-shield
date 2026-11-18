#pragma once
// Unit I: dynamic memory (new[] / delete[]) and the "rule of three":
// destructor + COPY CONSTRUCTOR + copy assignment, so copies never share
// (and never double-delete) the same array. Feeds the dashboard bar chart.
#include "Types.h"

namespace cyber {

class SeverityCounts {
public:
    static const int kSize = 4; // Low, Medium, High, Critical

    SeverityCounts();
    SeverityCounts(const SeverityCounts& other);            // copy constructor
    SeverityCounts& operator=(const SeverityCounts& other); // copy assignment
    ~SeverityCounts();                                      // destructor

    void add(Severity severity);
    int count(Severity severity) const;
    int largest() const;

private:
    int* counts; // heap array of kSize ints
};

} // namespace cyber
