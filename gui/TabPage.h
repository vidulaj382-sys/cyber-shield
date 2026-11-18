#pragma once
// Base class of every page of the main window. Each page knows how to
// redraw itself from the core (refresh) - MainWindow only calls refresh()
// on a list of TabPage pointers (polymorphism in the GUI).
#include <FL/Fl_Group.H>

#include "../core/SecurityManager.h"
#include "FlatButton.h"
#include "Theme.h"

class TabPage : public Fl_Group {
public:
    TabPage(int x, int y, int w, int h, const char* title, const char* subtitle,
            cyber::SecurityManager& manager)
        : Fl_Group(x, y, w, h), manager(manager), pageTitle(title), pageSubtitle(subtitle) {
        theme::tab(this);
    }

    virtual void refresh() = 0; // pure virtual: reload the data shown on this page

    const char* title() const { return pageTitle; }
    const char* subtitle() const { return pageSubtitle; }

protected:
    cyber::SecurityManager& manager;

private:
    const char* pageTitle;
    const char* pageSubtitle;
};
