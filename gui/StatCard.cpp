#include "StatCard.h"
#include "Theme.h"

#include <FL/fl_draw.H>

StatCard::StatCard(int x, int y, int w, int h, const char* caption)
    : Fl_Widget(x, y, w, h), caption(caption), accent(theme::accent) {}

void StatCard::set(const std::string& newValue, const std::string& newNote, Fl_Color newAccent) {
    value = newValue;
    note = newNote;
    accent = newAccent;
    redraw();
}

void StatCard::draw() {
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::card);

    fl_color(accent); // coloured stripe on the left edge
    fl_rectf(x(), y() + 12, 4, h() - 24);

    fl_color(theme::muted);
    fl_font(FL_HELVETICA_BOLD, 11);
    fl_draw(caption.c_str(), x() + 16, y() + 8, w() - 24, 18, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    fl_color(accent);
    fl_font(FL_HELVETICA_BOLD, 34);
    fl_draw(value.c_str(), x() + 16, y() + 26, w() - 24, 42, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    fl_color(theme::muted);
    fl_font(FL_HELVETICA, 11);
    fl_draw(note.c_str(), x() + 16, y() + h() - 24, w() - 24, 18, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
}
