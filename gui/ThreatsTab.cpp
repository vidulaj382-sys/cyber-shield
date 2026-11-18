#include "ThreatsTab.h"
#include "GuiHelpers.h"

#include <cstdlib>

#include <FL/Fl_Box.H>

using namespace cyber;

ThreatsTab::ThreatsTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Attack Detector", "Paste something suspicious and we will tell you if it is an attack.", manager) {
    source = new Fl_Input(x + 150, y + 12, 300, 28, "Where from?");
    source->value("web-01");
    source->labelcolor(theme::text);

    sample = new Fl_Multiline_Input(x + 150, y + 48, w - 170, 90, "Paste it here:");
    sample->value("URGENT: verify your account now, click here http://bank-login.example");
    sample->labelcolor(theme::text);
    sample->wrap(1);

    scanBtn = new FlatButton(x + 150, y + 148, 150, 30, "Check it now");
    theme::button(scanBtn, theme::blue);
    ON_CLICK(ThreatsTab, scanBtn, onScanText);
    auto* queueBtn = new FlatButton(x + 310, y + 148, 150, 30, "Check it later");
    theme::button(queueBtn, theme::slate);
    ON_CLICK(ThreatsTab, queueBtn, onQueue);
    runQueueBtn = new FlatButton(x + 470, y + 148, 190, 30);
    theme::button(runQueueBtn, theme::green);
    ON_CLICK(ThreatsTab, runQueueBtn, onRunQueue);

    failedLogins = new Fl_Int_Input(x + 150, y + 192, 90, 28, "Wrong tries:");
    failedLogins->value("7");
    failedLogins->labelcolor(theme::text);
    requests = new Fl_Int_Input(x + 400, y + 192, 90, 28, "Visitors/sec:");
    requests->value("2500");
    requests->labelcolor(theme::text);
    numbersBtn = new FlatButton(x + 510, y + 192, 190, 28, "Check the numbers");
    theme::button(numbersBtn, theme::amber);
    ON_CLICK(ThreatsTab, numbersBtn, onScanNumbers);

    auto* clearBtn = new FlatButton(x + w - 110, y + 192, 100, 28, "Clear");
    theme::button(clearBtn, theme::slate);
    clearBtn->callback([](Fl_Widget*, void* d) { static_cast<ThreatsTab*>(d)->console->clear(); }, this);

    console = new Console(x + 10, y + 248, w - 20, h - 258, "What we found", theme::matrix);
    console->println("Ready! Paste something suspicious (a message, a file name, an IP number) and press Check it now.");
    console->println("Try these: trojan.exe.zip  |  185.220.101.1  |  SYN flood  |  verify your account, click here");

    end();
}

void ThreatsTab::refresh() {
    const Person* user = manager.currentUser();
    bool canScan = user && user->canScan();
    setEnabled(scanBtn, canScan);
    setEnabled(runQueueBtn, canScan);
    setEnabled(numbersBtn, canScan);

    queueLabel = "Check all waiting (" + std::to_string(manager.pendingScans()) + " waiting)";
    runQueueBtn->label(queueLabel.c_str());
    runQueueBtn->redraw();
}

void ThreatsTab::show(const std::vector<std::string>& lines) {
    for (const std::string& line : lines)
        console->println(line);
    refresh();
}

void ThreatsTab::onScanText() {
    guarded([this] { show(manager.scan(source->value(), sample->value())); });
}

void ThreatsTab::onQueue() {
    guarded([this] {
        manager.queueSample(source->value(), sample->value());
        console->println("[QUEUED] sample from " + std::string(source->value()));
        refresh();
    });
}

void ThreatsTab::onRunQueue() {
    guarded([this] { show(manager.runQueue()); });
}

void ThreatsTab::onScanNumbers() {
    guarded([this] {
        show(manager.scan(source->value(), std::atoi(failedLogins->value()),
                          std::atoi(requests->value())));
    });
}
