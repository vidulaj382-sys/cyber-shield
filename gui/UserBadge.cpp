#include "UserBadge.h"
#include "Theme.h"

#include <cctype>

#include <FL/fl_draw.H>

void UserBadge::set(const std::string& newName, const std::string& newRole) {
    name = newName;
    role = newRole;
    redraw();
}

void UserBadge::draw() {
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::card);

    // Avatar circle with the first letter of the user name.
    const int d = 36;
    int ax = x() + 10, ay = y() + (h() - d) / 2;
    fl_color(theme::blue);
    fl_pie(ax, ay, d, d, 0, 360);
    std::string initial(1, name.empty() ? '?' : static_cast<char>(std::toupper(static_cast<unsigned char>(name[0]))));
    fl_color(FL_WHITE);
    fl_font(FL_HELVETICA_BOLD, 16);
    fl_draw(initial.c_str(), ax, ay, d, d, FL_ALIGN_CENTER);

    fl_color(theme::text);
    fl_font(FL_HELVETICA_BOLD, 13);
    fl_draw(name.c_str(), x() + 54, y() + 8, w() - 60, 20, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    fl_color(theme::accent);
    fl_font(FL_HELVETICA, 12);
    fl_draw(role.c_str(), x() + 54, y() + 28, w() - 60, 20, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
}
