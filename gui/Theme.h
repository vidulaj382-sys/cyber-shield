#pragma once
// Look and feel for Cyber Shield: one theme shared by every window.
// There are two palettes, dark and light. setLight(true/false) switches the
// palette; the windows are then built again so every widget picks up the new colours.
#include <FL/Enumerations.H>
#include <FL/Fl.H>
#include <FL/Fl_Browser_.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Input_.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Widget.H>

#include <string>

#include "../core/Types.h"

namespace theme {

// ---- the palette (plain variables, so setLight() can change them) -----------
inline bool isLight = false;

inline Fl_Color bg       = fl_rgb_color(15, 20, 32);    // window background
inline Fl_Color header   = fl_rgb_color(10, 14, 24);    // sidebar
inline Fl_Color panel    = fl_rgb_color(24, 32, 50);
inline Fl_Color field    = fl_rgb_color(11, 16, 28);    // lists and consoles
inline Fl_Color text     = fl_rgb_color(226, 232, 245);
inline Fl_Color muted    = fl_rgb_color(130, 145, 170);
inline Fl_Color accent   = fl_rgb_color(56, 189, 248);  // cyan
inline Fl_Color blue     = fl_rgb_color(37, 99, 235);
inline Fl_Color green    = fl_rgb_color(22, 163, 106);
inline Fl_Color red      = fl_rgb_color(220, 53, 69);
inline Fl_Color amber    = fl_rgb_color(217, 119, 6);
inline Fl_Color slate    = fl_rgb_color(51, 65, 92);    // quiet buttons
inline Fl_Color matrix   = fl_rgb_color(110, 240, 160); // terminal green
inline Fl_Color card     = fl_rgb_color(18, 25, 40);    // dashboard cards / chart
inline Fl_Color inputBg  = fl_rgb_color(28, 38, 62);
inline Fl_Color navHover = fl_rgb_color(20, 28, 46);
inline Fl_Color navOn    = fl_rgb_color(26, 38, 64);
inline Fl_Color grid     = fl_rgb_color(51, 65, 92);    // chart lines, gauge track
inline Fl_Color dangerText = fl_rgb_color(248, 113, 113); // red text in consoles
inline Fl_Color warnText   = fl_rgb_color(251, 191, 36);  // amber text in consoles

// Colours that text inside browsers can refer to ("@C<index>" codes).
// They live in FLTK's free colour slots, one slot per name.
enum Slot { SlotLow = 0, SlotMedium, SlotHigh, SlotCritical, SlotResolved, SlotHeader };

inline Fl_Color slotColor(Slot s) { return FL_FREE_COLOR + static_cast<int>(s); }

// Severity colour used by the chart and the incident list.
inline Fl_Color severityColor(cyber::Severity s) {
    return slotColor(static_cast<Slot>(static_cast<int>(s) - 1));
}

// The "@C<n>" prefix that colours one row of a browser.
inline std::string rowColor(Slot s) { return "@C" + std::to_string(slotColor(s)); }
inline std::string rowColor(cyber::Severity s) {
    return rowColor(static_cast<Slot>(static_cast<int>(s) - 1));
}

// Fills the palette variables and the FLTK default colours for one of the two themes.
inline void setPalette(bool light) {
    isLight = light;
    if (light) {
        bg = fl_rgb_color(241, 245, 249);   header = fl_rgb_color(255, 255, 255);
        panel = fl_rgb_color(255, 255, 255); field = fl_rgb_color(255, 255, 255);
        text = fl_rgb_color(15, 23, 42);     muted = fl_rgb_color(100, 116, 139);
        accent = fl_rgb_color(2, 132, 199);  slate = fl_rgb_color(100, 116, 139);
        matrix = fl_rgb_color(21, 128, 61);  card = fl_rgb_color(255, 255, 255);
        inputBg = fl_rgb_color(226, 232, 240); navHover = fl_rgb_color(241, 245, 249);
        navOn = fl_rgb_color(219, 234, 254); grid = fl_rgb_color(226, 232, 240);
        dangerText = fl_rgb_color(185, 28, 28); warnText = fl_rgb_color(180, 83, 9);

        Fl::background(241, 245, 249);
        Fl::background2(255, 255, 255);
        Fl::foreground(15, 23, 42);
        Fl::set_color(slotColor(SlotLow), 22, 163, 74);
        Fl::set_color(slotColor(SlotMedium), 202, 138, 4);
        Fl::set_color(slotColor(SlotHigh), 234, 88, 12);
        Fl::set_color(slotColor(SlotCritical), 220, 38, 38);
        Fl::set_color(slotColor(SlotResolved), 100, 116, 139);
        Fl::set_color(slotColor(SlotHeader), 2, 132, 199);
    } else {
        bg = fl_rgb_color(15, 20, 32);      header = fl_rgb_color(10, 14, 24);
        panel = fl_rgb_color(24, 32, 50);   field = fl_rgb_color(11, 16, 28);
        text = fl_rgb_color(226, 232, 245); muted = fl_rgb_color(130, 145, 170);
        accent = fl_rgb_color(56, 189, 248); slate = fl_rgb_color(51, 65, 92);
        matrix = fl_rgb_color(110, 240, 160); card = fl_rgb_color(18, 25, 40);
        inputBg = fl_rgb_color(28, 38, 62); navHover = fl_rgb_color(20, 28, 46);
        navOn = fl_rgb_color(26, 38, 64);   grid = fl_rgb_color(51, 65, 92);
        dangerText = fl_rgb_color(248, 113, 113); warnText = fl_rgb_color(251, 191, 36);

        Fl::background(15, 20, 32);
        Fl::background2(11, 16, 28);
        Fl::foreground(226, 232, 245);
        Fl::set_color(slotColor(SlotLow), 34, 197, 94);
        Fl::set_color(slotColor(SlotMedium), 250, 204, 21);
        Fl::set_color(slotColor(SlotHigh), 249, 115, 22);
        Fl::set_color(slotColor(SlotCritical), 239, 68, 68);
        Fl::set_color(slotColor(SlotResolved), 120, 135, 160);
        Fl::set_color(slotColor(SlotHeader), 56, 189, 248);
    }
}

// Call once at the start (and again whenever the theme changes), before windows are created.
inline void apply() {
    setPalette(isLight);
    Fl::set_color(FL_SELECTION_COLOR, 37, 99, 235);
    Fl::scheme("gtk+");

    // Modern Windows fonts (first letter of the name = style: ' ' normal, 'B' bold).
    Fl::set_font(FL_HELVETICA, " Segoe UI");
    Fl::set_font(FL_HELVETICA_BOLD, "BSegoe UI");
    Fl::set_font(FL_COURIER, " Consolas");
    Fl::set_font(FL_COURIER_BOLD, "BConsolas");
    Fl::scrollbar_size(12);
}

inline void setLight(bool light) {
    isLight = light;
    apply();
}

// Coloured button: the real drawing is done by FlatButton (flat, rounded, hover).
inline void button(Fl_Button* b, Fl_Color c) {
    b->color(c);
    b->labelcolor(FL_WHITE);
    b->labelfont(FL_HELVETICA_BOLD);
    b->labelsize(13);
}

// A page of the main window: flat, same colour as the window background.
inline void tab(Fl_Group* g) {
    g->box(FL_FLAT_BOX);
    g->color(bg);
}

// Text input / drop-down: flat field with a coloured cursor.
inline void input(Fl_Input_* in) {
    in->box(FL_FLAT_BOX);
    in->color(inputBg);
    in->textcolor(text);
    in->textsize(14);
    in->cursor_color(accent);
    in->selection_color(blue);
    in->labelcolor(muted);
    in->labelsize(13);
}

inline void choice(Fl_Choice* c) {
    c->box(FL_FLAT_BOX);
    c->color(inputBg);
    c->textcolor(text);
    c->textsize(14);
    c->labelcolor(muted);
    c->labelsize(13);
}

// Applies the input / choice style to every such widget inside a group
// (so each tab does not have to style its fields one by one).
inline void styleTree(Fl_Group* group) {
    for (int i = 0; i < group->children(); ++i) {
        Fl_Widget* child = group->child(i);
        if (auto* in = dynamic_cast<Fl_Input_*>(child))
            input(in);
        else if (auto* ch = dynamic_cast<Fl_Choice*>(child))
            choice(ch);
        else if (auto* sub = child->as_group())
            styleTree(sub);
    }
}

// Section heading inside a tab.
inline void heading(Fl_Widget* w) {
    w->labelcolor(accent);
    w->labelfont(FL_HELVETICA_BOLD);
    w->labelsize(15);
}

// Small grey helper text.
inline void hint(Fl_Widget* w) {
    w->labelcolor(muted);
    w->labelsize(12);
}

// Table-like list (Fl_Hold_Browser).
inline void list(Fl_Browser_* b) {
    b->color(field);
    b->textsize(13);
    b->textcolor(text);
    b->selection_color(blue);
    b->labelcolor(muted);
    b->labelsize(12);
}

// Console-style output area.
inline void terminal(Fl_Text_Display* d, Fl_Color ink) {
    d->color(field);
    d->textcolor(ink);
    d->textfont(FL_COURIER);
    d->textsize(13);
    d->selection_color(blue);
    d->cursor_color(ink);
    d->labelcolor(muted);
    d->labelsize(12);
}

} // namespace theme
