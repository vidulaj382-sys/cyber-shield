#pragma once
#include <functional>

#include <FL/Fl_Box.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Window.H>

#include "../core/SecurityManager.h"

class LoginWindow : public Fl_Window {
public:
    LoginWindow(cyber::SecurityManager& manager, std::function<void()> onSuccess);
    void reset();

private:
    void attemptLogin();
    void fillDemo(int index); // fills the fields with one of the demo accounts

    cyber::SecurityManager& manager;
    std::function<void()> onSuccess;
    Fl_Input* userInput;
    Fl_Secret_Input* passInput;
    Fl_Box* status;
    Fl_Widget* chips[2]; // the three demo-account buttons
};
