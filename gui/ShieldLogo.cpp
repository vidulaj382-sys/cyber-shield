#include "ShieldLogo.h"
#include "Theme.h"

#include <FL/fl_draw.H>

namespace {
// A shield outline as points in a 0..1 square.
const double kShield[][2] = {{0.50, 0.03}, {0.88, 0.18}, {0.88, 0.52}, {0.78, 0.76},
                             {0.50, 0.97}, {0.22, 0.76}, {0.12, 0.52}, {0.12, 0.18}};
const int kPoints = 8;

// Draws the shield filled with the current colour, shrunk by 'inset' (0..0.5).
void fillShield(int x, int y, int w, int h, double inset) {
    fl_begin_polygon();
    for (int i = 0; i < kPoints; ++i) {
        double px = 0.5 + (kShield[i][0] - 0.5) * (1.0 - inset);
        double py = 0.5 + (kShield[i][1] - 0.5) * (1.0 - inset);
        fl_vertex(x + px * w, y + py * h);
    }
    fl_end_polygon();
}
} // namespace

void ShieldLogo::draw() {
    fl_color(theme::accent);
    fillShield(x(), y(), w(), h(), 0.0);

    fl_color(theme::blue); // darker inner shield gives a bevelled look
    fillShield(x(), y(), w(), h(), 0.22);

    // White check mark.
    fl_color(FL_WHITE);
    fl_line_style(FL_SOLID, 3);
    fl_line(x() + w() * 0.34, y() + h() * 0.50, x() + w() * 0.46, y() + h() * 0.62);
    fl_line(x() + w() * 0.46, y() + h() * 0.62, x() + w() * 0.68, y() + h() * 0.36);
    fl_line_style(FL_SOLID, 1);
}
