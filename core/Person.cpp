#include "Person.h"
#include "Utils.h"

namespace cyber {

Person::Person(const std::string& username, const std::string& password)
    : Entity(username), passwordHash(util::hashPassword(password)) {}

bool Person::checkPassword(const std::string& attempt) const {
    return this->passwordHash == util::hashPassword(attempt);
}

std::string Person::describe() const {
    return name + " (" + roleName() + ")";
}

} // namespace cyber
