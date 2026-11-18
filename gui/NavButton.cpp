#include "NavButton.h"
#include "Theme.h"

#include <FL/fl_draw.H>

void NavButton::draw() {
    if (selected)
        fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::navOn);
    else if (hover)
        fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::navHover);
    else
        fl_draw_box(FL_FLAT_BOX, x(), y(), w(), h(), theme::header);

    if (selected) { // accent bar on the left edge
        fl_color(theme::accent);
        fl_rectf(x(), y() + 8, 3, h() - 16);
    }

    // Small round marker in front of the label.
    fl_color(selected ? theme::accent : theme::grid);
    fl_pie(x() + 18, y() + h() / 2 - 4, 8, 8, 0, 360);

    fl_color(selected ? theme::text : theme::muted);
    fl_font(selected ? FL_HELVETICA_BOLD : FL_HELVETICA, 14);
    fl_draw(label(), x() + 38, y(), w() - 40, h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
}

int NavButton::handle(int event) {
    switch (event) {
    case FL_ENTER:
        hover = true;
        redraw();
        return 1;
    case FL_LEAVE:
        hover = false;
        redraw();
        return 1;
    }
    return Fl_Button::handle(event);
}
