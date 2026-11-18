#include "LoginWindow.h"
#include "FlatButton.h"
#include "ShieldLogo.h"
#include "Theme.h"


namespace {
const int kWidth = 780;
const int kHeight = 470;
const int kLeft = 310; // width of the brand panel

const char* kDemoUser[] = {"admin", "employee"};
const char* kDemoPassword[] = {"admin123", "emp123"};
} // namespace

LoginWindow::LoginWindow(cyber::SecurityManager& manager, std::function<void()> onSuccess)
    : Fl_Window(kWidth, kHeight, "Cyber Shield - Login"), manager(manager), onSuccess(onSuccess) {
    color(theme::bg);

    // ---- brand panel (left) ----
    auto* brandPanel = new Fl_Box(0, 0, kLeft, kHeight);
    brandPanel->box(FL_FLAT_BOX);
    brandPanel->color(theme::header);

    new ShieldLogo(kLeft / 2 - 50, 70, 100, 112);

    auto* name = new Fl_Box(0, 200, kLeft, 36, "CYBER SHIELD");
    name->labelfont(FL_HELVETICA_BOLD);
    name->labelsize(26);
    name->labelcolor(theme::text);
    auto* tagline = new Fl_Box(0, 238, kLeft, 22, "Cybersecurity and Management System");
    theme::hint(tagline);
    tagline->labelsize(13);

    const char* features[] = {"Role based access control", "Live threat detection",
                              "Incident tracking and reports"};
    for (int i = 0; i < 3; ++i) {
        auto* dot = new Fl_Box(44, 304 + i * 30 + 8, 8, 8);
        dot->box(FL_OVAL_BOX);
        dot->color(theme::accent);
        auto* line = new Fl_Box(62, 304 + i * 30, kLeft - 80, 24, features[i]);
        line->labelcolor(theme::muted);
        line->labelsize(14);
        line->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    }

    // ---- sign-in form (right) ----
    const int fx = kLeft + 60, fw = kWidth - kLeft - 120;

    auto* welcome = new Fl_Box(fx, 52, fw, 40, "Welcome back");
    welcome->labelfont(FL_HELVETICA_BOLD);
    welcome->labelsize(28);
    welcome->labelcolor(theme::text);
    welcome->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    auto* sub = new Fl_Box(fx, 94, fw, 22, "Sign in to continue to your dashboard");
    theme::hint(sub);
    sub->labelsize(13);
    sub->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    userInput = new Fl_Input(fx, 152, fw, 38, "Username");
    userInput->align(FL_ALIGN_TOP_LEFT);
    passInput = new Fl_Secret_Input(fx, 220, fw, 38, "Password");
    passInput->align(FL_ALIGN_TOP_LEFT);

    auto* loginBtn = new FlatButton(fx, 282, fw, 42, "Sign In");
    theme::button(loginBtn, theme::blue);
    loginBtn->labelsize(15);
    loginBtn->shortcut(FL_Enter); // pressing Enter signs in
    loginBtn->callback([](Fl_Widget*, void* d) { static_cast<LoginWindow*>(d)->attemptLogin(); }, this);

    status = new Fl_Box(fx, 332, fw, 24);
    status->labelcolor(theme::dangerText);
    status->labelfont(FL_HELVETICA_BOLD);
    status->labelsize(12);
    status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    auto* demoLabel = new Fl_Box(fx, 370, fw, 20, "Demo accounts (click to fill in)");
    theme::hint(demoLabel);
    demoLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    const char* chipNames[] = {"Admin", "Employee"};
    const int chipWidth = (fw - 10) / 2;
    for (int i = 0; i < 2; ++i) {
        auto* chip = new FlatButton(fx + i * (chipWidth + 10), 396, chipWidth, 32, chipNames[i]);
        theme::button(chip, theme::slate);
        chips[i] = chip;
        chip->callback([](Fl_Widget* w, void* d) {
            auto* self = static_cast<LoginWindow*>(d);
            for (int k = 0; k < 2; ++k) // which chip was clicked?
                if (self->chips[k] == w)
                    self->fillDemo(k);
        }, this);
    }

    end();
    theme::styleTree(this);
    userInput->textsize(15);
    passInput->textsize(15);
}

void LoginWindow::fillDemo(int index) {
    userInput->value(kDemoUser[index]);
    passInput->value(kDemoPassword[index]);
    status->copy_label("");
}

void LoginWindow::reset() {
    passInput->value("");
    status->copy_label("");
    passInput->take_focus();
}

void LoginWindow::attemptLogin() {
    try {
        manager.login(userInput->value(), passInput->value());
        reset();
        onSuccess();
    } catch (const cyber::CyberException& e) {
        status->copy_label(e.what());
        passInput->value("");
    }
}
