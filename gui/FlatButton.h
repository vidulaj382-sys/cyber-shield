#pragma once
// A modern flat button: rounded corners, lighter on hover, darker when pressed.
// It is a normal Fl_Button, so callbacks work exactly as before.
#include <FL/Fl_Button.H>

class FlatButton : public Fl_Button {
public:
    FlatButton(int x, int y, int w, int h, const char* label = nullptr)
        : Fl_Button(x, y, w, h, label) {}

protected:
    void draw() override;
    int handle(int event) override;

private:
    bool hover = false;
};
