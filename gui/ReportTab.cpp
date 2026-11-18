#include "ReportTab.h"
#include "GuiHelpers.h"

#include <FL/Fl_Button.H>

namespace {
const char* kReportFile = "security_report.txt";
}

ReportTab::ReportTab(int x, int y, int w, int h, cyber::SecurityManager& manager)
    : TabPage(x, y, w, h, "My Report", "A summary of everything, ready to save as a file.", manager) {
    auto* refreshBtn = new FlatButton(x + 10, y + 10, 140, 28, "Refresh");
    theme::button(refreshBtn, theme::blue);
    refreshBtn->callback([](Fl_Widget*, void* d) { static_cast<ReportTab*>(d)->refresh(); }, this);

    auto* saveBtn = new FlatButton(x + 160, y + 10, 200, 28, "Save report as a file");
    theme::button(saveBtn, theme::green);
    ON_CLICK(ReportTab, saveBtn, onSave);

    console = new Console(x + 10, y + 48, w - 20, h - 58, nullptr, theme::text);
    end();
}

void ReportTab::refresh() {
    guarded([this] { console->setText(manager.buildReport()); });
}

void ReportTab::onSave() {
    guarded([this] {
        manager.saveReport(kReportFile);
        fl_message("Report saved to %s", kReportFile);
    });
}
