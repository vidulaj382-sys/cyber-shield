#pragma once
// The Cyber Shield logo: a shield with a check mark, drawn with polygons.
#include <FL/Fl_Widget.H>

class ShieldLogo : public Fl_Widget {
public:
    ShieldLogo(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

protected:
    void draw() override;
};
