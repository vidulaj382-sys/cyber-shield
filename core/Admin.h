#pragma once
// Administrator: full control over assets, users and data files.
#include "Person.h"

namespace cyber {

class Admin : public virtual Person { // virtual base: shared in the diamond
public:
    Admin(const std::string& u, const std::string& p) : Person(u, p) {}
    std::string roleName() const override { return "Admin"; }
    bool canManageAssets() const override { return true; }
    bool canManageUsers() const override { return true; }
    bool canScan() const override { return true; }
    bool canResolve() const override { return true; }
};

} // namespace cyber
