#pragma once
// A padlock drawn with FLTK: closed (locked) or open (unlocked).
#include <FL/Fl_Widget.H>

class LockIcon : public Fl_Widget {
public:
    LockIcon(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

    void setLocked(bool isLocked) {
        locked = isLocked;
        redraw();
    }

protected:
    void draw() override;

private:
    bool locked = true;
};
