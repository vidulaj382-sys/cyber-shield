#include "LockIcon.h"
#include "Theme.h"

#include <FL/fl_draw.H>

void LockIcon::draw() {
    Fl_Color color = locked ? theme::slotColor(theme::SlotHigh) : theme::slotColor(theme::SlotLow);

    // The curved bar on top (the "shackle"). When open, it is lifted and shifted.
    int bodyTop = y() + h() * 45 / 100;
    int shackleW = w() * 52 / 100;
    int shackleX = x() + (w() - shackleW) / 2 + (locked ? 0 : w() / 6);
    int shackleTop = y() + (locked ? 4 : 0);
    fl_color(color);
    fl_line_style(FL_SOLID, 9);
    fl_arc(shackleX, shackleTop, shackleW, shackleW, 0, 180);
    fl_line(shackleX, shackleTop + shackleW / 2, shackleX, bodyTop - (locked ? 0 : 10));
    fl_line(shackleX + shackleW, shackleTop + shackleW / 2, shackleX + shackleW,
            locked ? bodyTop : bodyTop - 10);
    fl_line_style(FL_SOLID, 1);

    // The body of the padlock with a keyhole.
    fl_draw_box(FL_RFLAT_BOX, x() + 4, bodyTop, w() - 8, h() - (bodyTop - y()), color);
    fl_color(theme::bg);
    int cx = x() + w() / 2, cy = bodyTop + (h() - (bodyTop - y())) / 2 - 4;
    fl_pie(cx - 7, cy - 7, 14, 14, 0, 360);
    fl_rectf(cx - 3, cy, 6, 16);
}
