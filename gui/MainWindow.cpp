#include "MainWindow.h"
#include "AssetsTab.h"
#include "DashboardTab.h"
#include "IncidentsTab.h"
#include "LinkTab.h"
#include "LogAnalyzerTab.h"
#include "LogTab.h"
#include "NetworkTab.h"
#include "ReportTab.h"
#include "ShieldLogo.h"
#include "ThreatsTab.h"
#include "Theme.h"
#include "Toast.h"
#include "UsersTab.h"
#include "VaultTab.h"

#ifdef _WIN32
#include <windows.h> // MessageBeep
#endif

namespace {
const int kWidth = 1100;
const int kHeight = 660;
const int kSidebar = 220;
const int kHeaderHeight = 96; // alert bar + page title area above the pages
const int kPanelWidth = 380;  // width of the "Concepts on this page" column
} // namespace

MainWindow::MainWindow(cyber::SecurityManager& manager, std::function<void()> onLogout,
                       std::function<void()> onToggleTheme)
    : Fl_Double_Window(kWidth, kHeight, "Cyber Shield: Cybersecurity and Management System"),
      manager(manager), onLogout(onLogout), onToggleTheme(onToggleTheme) {
    color(theme::bg);

    // ---- sidebar ----
    auto* sidebar = new Fl_Box(0, 0, kSidebar, kHeight);
    sidebar->box(FL_FLAT_BOX);
    sidebar->color(theme::header);

    new ShieldLogo(20, 18, 38, 42);
    auto* brand = new Fl_Box(66, 16, 150, 26, "CYBER SHIELD");
    brand->labelfont(FL_HELVETICA_BOLD);
    brand->labelsize(16);
    brand->labelcolor(theme::text);
    brand->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    auto* tagline = new Fl_Box(66, 40, 150, 20, "Keeping you safe");
    theme::hint(tagline);
    tagline->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    // ---- pages ----
    const int px = kSidebar + 22, py = kHeaderHeight;
    const int pw = kWidth - px - 22, ph = kHeight - py - 16;
    Fl_Group* area = new Fl_Group(kSidebar, 0, kWidth - kSidebar, kHeight);
    pageTitle = new Fl_Box(px, 28, 380, 36);
    pageTitle->labelfont(FL_HELVETICA_BOLD);
    pageTitle->labelsize(26);
    pageTitle->labelcolor(theme::text);
    pageTitle->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    pageSubtitle = new Fl_Box(px, 62, 520, 22);
    theme::hint(pageSubtitle);
    pageSubtitle->labelsize(13);
    pageSubtitle->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    // Theme button and the (i) button, top right.
    auto* themeBtn = new FlatButton(kWidth - 22 - 200 - 10 - 120, 30, 120, 36,
                                    theme::isLight ? "Dark mode" : "Light mode");
    theme::button(themeBtn, theme::slate);
    themeBtn->tooltip("Switch between the dark and the light look");
    themeBtn->callback([](Fl_Widget*, void* d) { static_cast<MainWindow*>(d)->onToggleTheme(); }, this);

    auto* infoBtn = new FlatButton(kWidth - 22 - 200, 30, 200, 36, "(i)  Concepts on this page");
    theme::button(infoBtn, theme::blue);
    infoBtn->tooltip("Shows which programming concepts this page uses, where they are, and why");
    infoBtn->callback([](Fl_Widget*, void* d) { static_cast<MainWindow*>(d)->toggleConcepts(); }, this);

    pages.push_back(new DashboardTab(px, py, pw, ph, manager));
    pages.push_back(new AssetsTab(px, py, pw, ph, manager));
    pages.push_back(new NetworkTab(px, py, pw, ph, manager));
    pages.push_back(new ThreatsTab(px, py, pw, ph, manager));
    pages.push_back(new LinkTab(px, py, pw, ph, manager));
    pages.push_back(new LogAnalyzerTab(px, py, pw, ph, manager));
    pages.push_back(new VaultTab(px, py, pw, ph, manager));
    pages.push_back(new IncidentsTab(px, py, pw, ph, manager));
    pages.push_back(new ReportTab(px, py, pw, ph, manager));
    pages.push_back(new LogTab(px, py, pw, ph, manager));
    pages.push_back(new UsersTab(px, py, pw, ph, manager));

    // Added AFTER the pages, so they are drawn on top of them.
    conceptPanel = new ConceptPanel(kWidth - 22 - kPanelWidth, py, kPanelWidth, ph);
    alertBar = new AlertBar(kSidebar, 0, kWidth - kSidebar, 24);
    area->end();

    // ---- navigation buttons (one per page) ----
    for (size_t i = 0; i < pages.size(); ++i) {
        auto* button = new NavButton(10, 74 + static_cast<int>(i) * 38, kSidebar - 20, 34,
                                     pages[i]->title());
        button->callback([](Fl_Widget* w, void* d) {
            auto* self = static_cast<MainWindow*>(d);
            for (size_t k = 0; k < self->navButtons.size(); ++k) // which button was clicked?
                if (self->navButtons[k] == w)
                    self->showPage(static_cast<int>(k));
        }, this);
        navButtons.push_back(button);
    }

    // ---- user card and logout at the bottom of the sidebar ----
    userBadge = new UserBadge(10, kHeight - 118, kSidebar - 20, 52);
    auto* logoutBtn = new FlatButton(10, kHeight - 54, kSidebar - 20, 36, "Logout");
    theme::button(logoutBtn, fl_rgb_color(150, 40, 55));
    logoutBtn->callback([](Fl_Widget*, void* d) { static_cast<MainWindow*>(d)->onLogout(); }, this);

    end();
    theme::styleTree(this);

    // The core calls this when it finds a CRITICAL threat (callback with std::function).
    manager.setAlertHandler([this](const std::string& message) { raiseAlert(message); });
}

MainWindow::~MainWindow() {
    manager.setAlertHandler(nullptr); // this window is going away: stop calling it
}

void MainWindow::raiseAlert(const std::string& message) {
    alertBar->trigger(message);                   // blinking red banner at the top
    Toast::show(this, "Critical threat!", message); // pop-up in the corner
#ifdef _WIN32
    MessageBeep(MB_ICONHAND);                     // warning sound
#endif
}

void MainWindow::showPage(int index) {
    currentPage = index;
    for (size_t i = 0; i < pages.size(); ++i) {
        bool selected = static_cast<int>(i) == index;
        if (selected)
            pages[i]->show();
        else
            pages[i]->hide();
        navButtons[i]->setSelected(selected);
    }
    pageTitle->label(pages[index]->title());
    pageSubtitle->label(pages[index]->subtitle());
    pages[index]->refresh(); // always show fresh data when a page is opened

    if (conceptPanel->visible()) // keep an open panel in step with the page
        conceptPanel->showFor(pages[index]->title());
    redraw();
}

void MainWindow::toggleConcepts() {
    if (conceptPanel->visible()) {
        conceptPanel->hide();
    } else {
        conceptPanel->showFor(pages[currentPage]->title());
        conceptPanel->show();
    }
    redraw();
}

void MainWindow::onLogin() {
    conceptPanel->hide();
    refreshAll();
    showPage(0);
}

void MainWindow::refreshAll() {
    if (const cyber::Person* user = manager.currentUser())
        userBadge->set(user->getName(), user->roleName());
    for (TabPage* page : pages)
        page->refresh(); // polymorphic call: each page reloads itself
    redraw();
}
