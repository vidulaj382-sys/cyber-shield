#include "SplashWindow.h"
#include "ShieldLogo.h"
#include "Theme.h"

#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/fl_draw.H>

namespace {
const int kWidth = 520;
const int kHeight = 320;
} // namespace

SplashWindow::SplashWindow(std::function<void()> onDone)
    : Fl_Window(kWidth, kHeight), onDone(onDone) {
    clear_border(); // no title bar: it looks like a real splash screen
    color(theme::bg);

    new ShieldLogo(kWidth / 2 - 50, 36, 100, 112);

    auto* name = new Fl_Box(0, 162, kWidth, 40, "CYBER SHIELD");
    name->labelfont(FL_HELVETICA_BOLD);
    name->labelsize(30);
    name->labelcolor(theme::text);
    auto* tagline = new Fl_Box(0, 204, kWidth, 24, "Cybersecurity and Management System");
    theme::hint(tagline);
    tagline->labelsize(14);

    auto* loading = new Fl_Box(0, 262, kWidth, 20, "Starting up...");
    theme::hint(loading);
    end();

    // Centre the window on the screen.
    int sx, sy, sw, sh;
    Fl::screen_xywh(sx, sy, sw, sh);
    position(sx + (sw - kWidth) / 2, sy + (sh - kHeight) / 2);
}

SplashWindow::~SplashWindow() { Fl::remove_timeout(tick, this); }

void SplashWindow::start() {
    progress = 0.0;
    show();
    Fl::add_timeout(0.03, tick, this);
}

void SplashWindow::tick(void* self) {
    auto* splash = static_cast<SplashWindow*>(self);
    splash->progress += 0.02;
    if (splash->progress >= 1.0) {
        splash->hide();
        if (splash->onDone)
            splash->onDone(); // open the login window
        return;
    }
    splash->redraw();
    Fl::repeat_timeout(0.03, tick, self);
}

void SplashWindow::draw() {
    Fl_Window::draw(); // the logo and the texts

    const int barX = 110, barW = kWidth - 220, barY = 288, barH = 6;
    fl_color(theme::grid);
    fl_rectf(barX, barY, barW, barH);
    fl_color(theme::accent);
    fl_rectf(barX, barY, static_cast<int>(barW * progress), barH);
}
