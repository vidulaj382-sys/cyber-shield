#include "AlertBar.h"
#include "Theme.h"

#include <FL/Fl.H>
#include <FL/fl_draw.H>

AlertBar::AlertBar(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {
    hide(); // invisible until an alert happens
}

AlertBar::~AlertBar() { Fl::remove_timeout(tick, this); }

void AlertBar::trigger(const std::string& newMessage) {
    message = newMessage;
    blinksLeft = 14; // about 5 seconds
    bright = true;
    show();
    redraw();
    Fl::remove_timeout(tick, this);
    Fl::add_timeout(0.4, tick, this);
}

void AlertBar::tick(void* self) {
    auto* bar = static_cast<AlertBar*>(self);
    bar->bright = !bar->bright;
    if (--bar->blinksLeft <= 0) {
        bar->hide(); // done blinking
        if (bar->parent())
            bar->parent()->redraw();
        return;
    }
    bar->redraw();
    Fl::repeat_timeout(0.4, tick, self);
}

void AlertBar::draw() {
    fl_draw_box(FL_FLAT_BOX, x(), y(), w(), h(),
                bright ? fl_rgb_color(220, 38, 38) : fl_rgb_color(127, 29, 29));
    fl_color(FL_WHITE);
    fl_font(FL_HELVETICA_BOLD, 13);
    fl_draw(("!  " + message).c_str(), x() + 14, y(), w() - 28, h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
}
