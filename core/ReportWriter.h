#pragma once
// Unit I: friend class. ReportWriter is declared a friend inside
// SecurityManager, so it can read the manager's private containers
// without needing a getter for every one of them.
#include <string>

namespace cyber {

class SecurityManager;

class ReportWriter {
public:
    static std::string build(const SecurityManager& manager);
};

} // namespace cyber
