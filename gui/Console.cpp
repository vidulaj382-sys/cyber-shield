#include "Console.h"
#include "Theme.h"

#include <sstream>

Console::Console(int x, int y, int w, int h, const char* label, Fl_Color normalColor)
    : Fl_Group(x, y, w, h, label) {
    align(FL_ALIGN_TOP_LEFT);
    theme::hint(this);

    textBuffer = new Fl_Text_Buffer();
    styleBuffer = new Fl_Text_Buffer();

    // Style letters: 'A' normal, 'B' red, 'C' amber, 'D' green, 'E' cyan.
    const Fl_Color colors[5] = {normalColor, theme::dangerText, theme::warnText,
                                theme::matrix, theme::accent};
    for (int i = 0; i < 5; ++i)
        styles[i] = {colors[i], FL_COURIER, 13, 0, 0}; // color, font, size, attributes, background

    display = new Fl_Text_Display(x, y, w, h);
    display->buffer(textBuffer);
    display->highlight_data(styleBuffer, styles, 5, 'A', nullptr, nullptr);
    theme::terminal(display, normalColor);
    display->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
    end();
}

Console::~Console() {
    // The display must go first: it still points at both buffers.
    remove(display);
    delete display;
    delete textBuffer;
    delete styleBuffer;
}

char Console::styleFor(const std::string& line) const {
    if (line.find("[DETECTED]") != std::string::npos || line.find("[ERROR") != std::string::npos)
        return 'B';
    if (line.find("[WARN") != std::string::npos)
        return 'C';
    if (line.find("[CLEAN]") != std::string::npos)
        return 'D';
    if (line.find("[QUEUED]") != std::string::npos)
        return 'E';
    return 'A';
}

void Console::println(const std::string& line) {
    // A "line" may contain several lines (separated by \n): handle each one.
    std::istringstream parts(line);
    std::string part;
    bool any = false;
    while (std::getline(parts, part)) {
        std::string text = part + "\n";
        textBuffer->append(text.c_str());
        styleBuffer->append(std::string(text.size(), styleFor(part)).c_str());
        any = true;
    }
    if (!any) { // an empty line
        textBuffer->append("\n");
        styleBuffer->append("A");
    }
    display->insert_position(textBuffer->length()); // scroll to the newest line
    display->show_insert_position();
}

void Console::setText(const std::string& text) {
    clear();
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line))
        println(line);
    display->insert_position(0); // show the top of a report
    display->show_insert_position();
}

void Console::clear() {
    textBuffer->text("");
    styleBuffer->text("");
}
