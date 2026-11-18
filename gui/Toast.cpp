#include "Toast.h"
#include "Theme.h"

#include <FL/Fl.H>
#include <FL/fl_draw.H>

namespace {
const int kWidth = 340;
const int kHeight = 96;
} // namespace

Toast::Toast(int x, int y, const std::string& title, const std::string& message)
    : Fl_Window(x, y, kWidth, kHeight), title(title), message(message) {
    clear_border();  // no title bar
    set_non_modal(); // never blocks the main window
    end();
}

void Toast::show(const Fl_Window* anchor, const std::string& title, const std::string& message) {
    int x = anchor->x() + anchor->w() - kWidth - 24;
    int y = anchor->y() + anchor->h() - kHeight - 24;
    Toast* toast = new Toast(x, y, title, message);
    toast->Fl_Window::show();
    Fl::add_timeout(6.0, close, toast); // disappears by itself
}

void Toast::close(void* self) {
    auto* toast = static_cast<Toast*>(self);
    Fl::remove_timeout(close, toast);
    toast->hide();
    Fl::delete_widget(toast); // FLTK deletes it safely, after the current event
}

int Toast::handle(int event) {
    if (event == FL_PUSH) { // a click closes it
        close(this);
        return 1;
    }
    return Fl_Window::handle(event);
}

void Toast::draw() {
    fl_draw_box(FL_FLAT_BOX, 0, 0, w(), h(), fl_rgb_color(185, 28, 28));
    fl_color(FL_WHITE);
    fl_rectf(0, 0, 6, h());
    fl_font(FL_HELVETICA_BOLD, 15);
    fl_draw(title.c_str(), 20, 8, w() - 32, 26, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    fl_font(FL_HELVETICA, 13);
    fl_draw(message.c_str(), 20, 36, w() - 36, h() - 44, FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
}
