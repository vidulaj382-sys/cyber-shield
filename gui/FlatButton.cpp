#include "FlatButton.h"
#include "Theme.h"

#include <FL/fl_draw.H>

void FlatButton::draw() {
    Fl_Color fill = color();
    if (!active())
        fill = fl_color_average(theme::muted, theme::bg, 0.25f); // disabled: a quiet grey in both themes
    else if (value() || (Fl::pushed() == this))
        fill = fl_darker(fill);             // pressed
    else if (hover)
        fill = fl_lighter(fill);            // mouse over

    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), fill);

    fl_color(active() ? labelcolor() : theme::muted);
    fl_font(labelfont(), labelsize());
    fl_draw(label(), x(), y(), w(), h(), FL_ALIGN_CENTER);
}

int FlatButton::handle(int event) {
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
