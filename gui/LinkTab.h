#pragma once
// Link Checker: paste a web link and find out if it is safe BEFORE clicking it.
#include <FL/Fl_Box.H>
#include <FL/Fl_Input.H>

#include "Console.h"
#include "StatusBanner.h"
#include "TabPage.h"

class LinkTab : public TabPage {
public:
    LinkTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override {}

private:
    void onCheck();
    void fillExample(int index);

    Fl_Input* linkInput;
    StatusBanner* banner;
    Console* reasons;
    Fl_Box* advice;
    Fl_Widget* exampleButtons[3];
};
