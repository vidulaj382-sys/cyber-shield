#include "RiskGauge.h"
#include "Theme.h"

#include <FL/fl_draw.H>

void RiskGauge::set(int newPercent, const std::string& newLevel, Fl_Color newColor) {
    percent = newPercent;
    level = newLevel;
    arcColor = newColor;
    redraw();
}

void RiskGauge::draw() {
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::card);

    fl_color(theme::accent);
    fl_font(FL_HELVETICA_BOLD, 14);
    fl_draw("Danger level", x() + 16, y() + 8, w() - 32, 24, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    // The gauge is the TOP half of a circle: angles 0 (right) .. 180 (left).
    // Everything is clipped to the card, because the "carve out" circle is a full circle.
    fl_push_clip(x(), y(), w(), h());
    int diameter = (h() - 76) * 2; // radius = space between the title and the centre line
    if (diameter > w() - 40)
        diameter = w() - 40;
    const int cx = x() + w() / 2;
    const int cy = y() + h() - 38; // centre of the circle = bottom of the half circle
    const int left = cx - diameter / 2, top = cy - diameter / 2;
    const int thickness = diameter / 7;

    fl_color(theme::grid);                                  // empty track
    fl_pie(left, top, diameter, diameter, 0, 180);
    fl_color(arcColor);                                      // filled part (clockwise from the left)
    fl_pie(left, top, diameter, diameter, 180 - 180.0 * percent / 100.0, 180);
    fl_color(theme::card);                                   // carve out the middle
    fl_pie(left + thickness, top + thickness, diameter - 2 * thickness,
           diameter - 2 * thickness, 0, 360);

    fl_color(theme::text);
    fl_font(FL_HELVETICA_BOLD, 28);
    fl_draw((std::to_string(percent) + "%").c_str(), cx - 60, cy - 40, 120, 40, FL_ALIGN_CENTER);
    fl_color(arcColor);
    fl_font(FL_HELVETICA_BOLD, 13);
    fl_draw((level + " risk").c_str(), cx - 60, cy + 2, 120, 22, FL_ALIGN_CENTER);
    fl_pop_clip();
}
