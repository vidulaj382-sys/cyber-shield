#include "Entity.h"

namespace cyber {

int Entity::nextId = 1;
int Entity::alive = 0;

Entity::Entity() : Entity("Unnamed") {}

Entity::Entity(const std::string& name) : id(nextId++), name(name) { ++alive; }

Entity::~Entity() { --alive; }

Entity& Entity::setName(const std::string& name) {
    this->name = name; // 'this' disambiguates the member from the parameter
    return *this;
}

std::string Entity::describe() const {
    return "#" + std::to_string(id) + " " + name;
}

} // namespace cyber
