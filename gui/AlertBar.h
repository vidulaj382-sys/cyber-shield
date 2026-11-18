#pragma once
// A red banner that BLINKS for a few seconds when a critical threat is found.
// It uses an FLTK timer (Fl::add_timeout) to switch between bright and dark red.
#include <string>
#include <FL/Fl_Widget.H>

class AlertBar : public Fl_Widget {
public:
    AlertBar(int x, int y, int w, int h);
    ~AlertBar() override;

    void trigger(const std::string& message); // show the banner and start blinking

protected:
    void draw() override;

private:
    static void tick(void* self); // called by the timer every 0.4 seconds

    std::string message;
    int blinksLeft = 0;
    bool bright = false;
};
