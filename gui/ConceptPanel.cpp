#include "ConceptPanel.h"
#include "ConceptGuide.h"
#include "FlatButton.h"
#include "Theme.h"

ConceptPanel::ConceptPanel(int x, int y, int w, int h) : Fl_Group(x, y, w, h) {
    auto* background = new Fl_Box(x, y, w, h);
    background->box(FL_RFLAT_BOX);
    background->color(theme::card);

    heading = new Fl_Box(x + 16, y + 10, w - 80, 28, "Concepts on this page");
    heading->labelfont(FL_HELVETICA_BOLD);
    heading->labelsize(16);
    heading->labelcolor(theme::accent);
    heading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    auto* closeBtn = new FlatButton(x + w - 52, y + 8, 38, 30, "X");
    theme::button(closeBtn, theme::slate);
    closeBtn->callback([](Fl_Widget*, void* d) { static_cast<ConceptPanel*>(d)->hide(); }, this);

    view = new Fl_Help_View(x + 10, y + 48, w - 20, h - 58);
    view->box(FL_FLAT_BOX);
    view->color(theme::card);
    view->textcolor(theme::text);
    view->textfont(FL_HELVETICA);
    view->textsize(13);

    end();
    hide();
}

void ConceptPanel::showFor(const std::string& pageTitle) {
    heading->copy_label(("Concepts: " + pageTitle).c_str());
    view->value(conceptguide::htmlFor(pageTitle).c_str());
    view->topline(0);
}
