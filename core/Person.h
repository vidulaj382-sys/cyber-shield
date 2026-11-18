#pragma once
// Unit II: Person is the VIRTUAL BASE CLASS of the diamond
//
//              Person            (abstract: roleName() is pure virtual)
//             /      \           (virtual inheritance)
//        Employee    Admin
//             \      /
//          SecurityOfficer       (multiple inheritance)
//
// Multilevel inheritance: Entity -> Person -> Employee -> SecurityOfficer.
// (SecurityOfficer is kept to demonstrate the diamond; it is not a login role.)
#include <string>
#include "Entity.h"

namespace cyber {

class Person : public Entity {
public:
    Person(const std::string& username, const std::string& password);
    ~Person() override = default;

    virtual std::string roleName() const = 0; // pure virtual -> Person is abstract

    // What the role may do. Derived roles override the ones they allow.
    virtual bool canManageAssets() const { return false; }
    virtual bool canManageUsers() const { return false; }
    virtual bool canScan() const { return false; }
    virtual bool canResolve() const { return false; }

    // How OTHER people see this person's name. Normally the real name;
    // Employee overrides it so employee names stay private.
    virtual std::string nameForOthers() const { return name; }

    bool checkPassword(const std::string& attempt) const;
    std::string describe() const override;

private:
    std::string passwordHash; // only the hash is stored, never the password
};

} // namespace cyber
