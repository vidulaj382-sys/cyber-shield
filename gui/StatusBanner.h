#pragma once
// A wide coloured message box: big title, small sentence below.
// Used on the Home page ("All clear!") and for link results ("Dangerous!").
#include <string>
#include <FL/Fl_Widget.H>

class StatusBanner : public Fl_Widget {
public:
    StatusBanner(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

    void set(const std::string& newTitle, const std::string& newSubtitle, Fl_Color newColor);

protected:
    void draw() override;

private:
    std::string title;
    std::string subtitle;
    Fl_Color accent = FL_GREEN;
};
