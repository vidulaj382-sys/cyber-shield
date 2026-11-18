#pragma once
// An ordinary staff member: can log in and report incidents, nothing more.
#include "Person.h"
#include "Utils.h"

namespace cyber {

class Employee : public virtual Person { // virtual base: shared in the diamond
public:
    Employee(const std::string& u, const std::string& p) : Person(u, p) {}
    std::string roleName() const override { return "Employee"; }

    // Privacy: other people (even the Admin) see only e******e, never the real name.
    std::string nameForOthers() const override { return util::maskName(name); }
};

} // namespace cyber
