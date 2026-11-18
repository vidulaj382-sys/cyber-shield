#pragma once
// The main window: a sidebar for navigation, one page per feature, a "Concepts on this page"
// panel (the (i) button), a dark/light theme button, and a blinking alert bar + toast
// that appear when a CRITICAL threat is found.
#include <functional>
#include <string>
#include <vector>

#include <FL/Fl_Box.H>
#include <FL/Fl_Double_Window.H>

#include "../core/SecurityManager.h"
#include "AlertBar.h"
#include "ConceptPanel.h"
#include "FlatButton.h"
#include "NavButton.h"
#include "TabPage.h"
#include "UserBadge.h"

class MainWindow : public Fl_Double_Window {
public:
    MainWindow(cyber::SecurityManager& manager, std::function<void()> onLogout,
               std::function<void()> onToggleTheme);
    ~MainWindow() override;

    void onLogin();    // called after a successful login: refresh everything, show Home
    void refreshAll(); // update the sidebar and every page
    void showPage(int index);
    int currentPageIndex() const { return currentPage; }

private:
    void toggleConcepts();
    void raiseAlert(const std::string& message); // blinking bar + toast + beep

    cyber::SecurityManager& manager;
    std::function<void()> onLogout;
    std::function<void()> onToggleTheme;
    Fl_Box* pageTitle;
    Fl_Box* pageSubtitle;
    UserBadge* userBadge;
    ConceptPanel* conceptPanel;
    AlertBar* alertBar;
    int currentPage = 0;
    std::vector<NavButton*> navButtons;
    std::vector<TabPage*> pages; // owned by the window (they are its children)
};
