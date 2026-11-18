#pragma once
// The "Concepts on this page" column. It slides over the right side of the
// page when the (i) button is clicked.
#include <string>

#include <FL/Fl_Box.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Help_View.H>

class ConceptPanel : public Fl_Group {
public:
    ConceptPanel(int x, int y, int w, int h);

    void showFor(const std::string& pageTitle); // fill the panel with that page's notes

private:
    Fl_Box* heading;
    Fl_Help_View* view;
};
