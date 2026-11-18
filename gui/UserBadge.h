#pragma once
// Sidebar user card: coloured circle with the initial, name and role.
#include <string>
#include <FL/Fl_Widget.H>

class UserBadge : public Fl_Widget {
public:
    UserBadge(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

    void set(const std::string& newName, const std::string& newRole);

protected:
    void draw() override;

private:
    std::string name;
    std::string role;
};
