#pragma once
// A dashboard card: small caption, one big number and a short note.
// Custom widget = subclass of Fl_Widget that overrides draw().
#include <string>
#include <FL/Fl_Widget.H>

class StatCard : public Fl_Widget {
public:
    StatCard(int x, int y, int w, int h, const char* caption);

    void set(const std::string& value, const std::string& note, Fl_Color accent);

protected:
    void draw() override;

private:
    std::string caption;
    std::string value;
    std::string note;
    Fl_Color accent;
};
