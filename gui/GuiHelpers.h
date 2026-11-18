#pragma once
// Small helpers shared by all tabs. The GUI never contains program logic:
// it only calls the core and shows the result (or the error message).
#include <exception>
#include <string>
#include <vector>

#include <FL/Fl_Browser.H>
#include <FL/Fl_Widget.H>
#include <FL/fl_ask.H>

#include "../core/Exceptions.h"
#include "FlatButton.h"
#include "Theme.h"

// Runs a GUI action. Any core exception becomes a message box (Unit IV).
template <typename Action>
void guarded(Action action) {
    try {
        action();
    } catch (const cyber::CyberException& e) {
        fl_alert("%s", e.what());
    } catch (const std::exception& e) {
        fl_alert("Unexpected error: %s", e.what());
    }
}

// Connects a button click to a member function of the tab that owns it.
#define ON_CLICK(owner, button, method) \
    (button)->callback([](Fl_Widget*, void* d) { static_cast<owner*>(d)->method(); }, this)

inline void setEnabled(Fl_Widget* w, bool enabled) {
    if (enabled)
        w->activate();
    else
        w->deactivate();
}

// Text starting with '@' is a format code in an FLTK browser; "@@" is a plain '@'.
inline std::string safeText(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (c == '@')
            out += '@';
        out += c;
    }
    return out;
}

// Empties a browser and writes its bold header row. Row ids are kept in a
// parallel vector; the header row gets id 0 (meaning "not a real row").
inline void startRows(Fl_Browser* list, std::vector<int>& ids, const std::string& header) {
    list->clear();
    ids.clear();
    list->add(("@b" + theme::rowColor(theme::SlotHeader) + header).c_str());
    ids.push_back(0);
}

// Id of the selected row, or an exception when nothing real is selected.
inline int selectedId(const Fl_Browser* list, const std::vector<int>& ids) {
    int line = list->value(); // 1-based, 0 = nothing selected
    if (line < 1 || line > static_cast<int>(ids.size()) || ids[line - 1] == 0)
        throw cyber::ValidationException("select a row in the list first");
    return ids[line - 1];
}
