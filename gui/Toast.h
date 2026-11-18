#pragma once
// A small notification that pops up in the corner of the main window for a few
// seconds ("toast"). Click it to close it. It removes itself, nobody has to delete it.
#include <string>
#include <FL/Fl_Window.H>

class Toast : public Fl_Window {
public:
    // Shows a toast in the bottom-right corner of 'anchor'.
    static void show(const Fl_Window* anchor, const std::string& title, const std::string& message);

protected:
    void draw() override;
    int handle(int event) override;

private:
    Toast(int x, int y, const std::string& title, const std::string& message);
    static void close(void* self);

    std::string title;
    std::string message;
};
