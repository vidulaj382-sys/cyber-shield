#pragma once
// NOT a login role any more - kept to demonstrate the DIAMOND of Unit II.
// It is both an Employee and an Admin (multiple inheritance), but Person
// exists only ONCE inside it thanks to the virtual base class. It overrides
// what both parents define, so there is no ambiguity.
#include "Admin.h"
#include "Employee.h"

namespace cyber {

class SecurityOfficer : public Employee, public Admin {
public:
    // The most derived class constructs the virtual base Person.
    SecurityOfficer(const std::string& u, const std::string& p)
        : Person(u, p), Employee(u, p), Admin(u, p) {}

    std::string roleName() const override { return "Security Officer"; }
    bool canManageAssets() const override { return false; } // Admins only
    bool canManageUsers() const override { return false; }  // Admins only
    std::string nameForOthers() const override { return Employee::nameForOthers(); }
    bool canScan() const override { return true; }
    bool canResolve() const override { return true; }
};

} // namespace cyber
