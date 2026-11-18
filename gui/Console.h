#pragma once
// Console-style output box (monospace text on a dark background).
// Lines are coloured by their content: [DETECTED] red, [WARN] amber,
// [CLEAN] green, [QUEUED] cyan, everything else in the normal colour.
#include <string>

#include <FL/Fl_Group.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Text_Display.H>

class Console : public Fl_Group {
public:
    Console(int x, int y, int w, int h, const char* label, Fl_Color normalColor);
    ~Console() override;

    void println(const std::string& line); // add one line at the bottom
    void setText(const std::string& text); // replace everything
    void clear();

private:
    char styleFor(const std::string& line) const;

    Fl_Text_Display* display;
    Fl_Text_Buffer* textBuffer;
    Fl_Text_Buffer* styleBuffer; // one style letter per character of text
    Fl_Text_Display::Style_Table_Entry styles[5];
};
