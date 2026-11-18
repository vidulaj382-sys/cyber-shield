#include "StatusBanner.h"
#include "Theme.h"

#include <FL/fl_draw.H>

void StatusBanner::set(const std::string& newTitle, const std::string& newSubtitle,
                       Fl_Color newColor) {
    title = newTitle;
    subtitle = newSubtitle;
    accent = newColor;
    redraw();
}

void StatusBanner::draw() {
    // Background = the card colour with a little of the accent colour mixed in.
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), fl_color_average(accent, theme::card, 0.18f));

    fl_color(accent);
    fl_rectf(x(), y() + 10, 5, h() - 20); // stripe on the left

    fl_font(FL_HELVETICA_BOLD, 22);
    fl_draw(title.c_str(), x() + 22, y() + 8, w() - 40, 32, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    fl_color(theme::text);
    fl_font(FL_HELVETICA, 14);
    fl_draw(subtitle.c_str(), x() + 22, y() + 40, w() - 40, h() - 46,
            FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
}
