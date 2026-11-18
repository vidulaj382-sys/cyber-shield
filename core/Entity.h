#pragma once
// Unit I: classes, constructors/destructors, static members, this pointer.
// Used as a *virtual base class* by Asset, Monitored and User (Unit II).
#include <string>

namespace cyber {

class Entity {
public:
    Entity();                                // default constructor
    explicit Entity(const std::string& name); // parameterised constructor
    virtual ~Entity();

    int getId() const { return id; }
    const std::string& getName() const { return name; }

    // Returns *this so calls can be chained: e.setName("x").setName("y")
    Entity& setName(const std::string& name);

    virtual std::string describe() const;

    // Gives a rebuilt object its old id back (used when an undo recreates a device).
    void restoreId(int oldId) { id = oldId; }

    static int liveCount() { return alive; }
    static int createdCount() { return nextId - 1; }

protected:
    int id;
    std::string name;

private:
    static int nextId;
    static int alive;
};

} // namespace cyber
