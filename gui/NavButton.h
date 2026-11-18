#pragma once
// One entry of the sidebar: a dot, a label, and an accent bar when selected.
#include <FL/Fl_Button.H>

class NavButton : public Fl_Button {
public:
    NavButton(int x, int y, int w, int h, const char* label) : Fl_Button(x, y, w, h, label) {}

    void setSelected(bool on) {
        selected = on;
        redraw();
    }

protected:
    void draw() override;
    int handle(int event) override;

private:
    bool selected = false;
    bool hover = false;
};
