#include "LogTab.h"
#include "GuiHelpers.h"

using namespace cyber;

LogTab::LogTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "History", "A diary of who did what and when. Filter it by level or by person.", manager) {
    level = new Fl_Choice(x + 60, y + 4, 100, 30, "Level:");
    for (const char* name : {"All", "INFO", "WARN", "ERROR"})
        level->add(name);
    level->value(0);
    level->callback([](Fl_Widget*, void* d) { static_cast<LogTab*>(d)->refresh(); }, this);

    user = new Fl_Input(x + 220, y + 4, 170, 30, "User:");
    user->tooltip("Type a user name (or any word) to see only the lines that mention it");
    user->when(FL_WHEN_CHANGED);
    user->callback([](Fl_Widget*, void* d) { static_cast<LogTab*>(d)->refresh(); }, this);

    auto* refreshBtn = new FlatButton(x + 404, y + 4, 100, 30, "Refresh");
    theme::button(refreshBtn, theme::blue);
    refreshBtn->callback([](Fl_Widget*, void* d) { static_cast<LogTab*>(d)->refresh(); }, this);

    summary = new Fl_Box(x + 516, y + 4, w - 516, 30);
    theme::hint(summary);
    summary->align(FL_ALIGN_RIGHT | FL_ALIGN_INSIDE);

    table = new DataTable(x, y + 44, w, h - 44);
    table->setColumns({"When", "Level", "What happened"}, {150, 70});

    end();
}

void LogTab::refresh() {
    guarded([this] {
        AuditView view = manager.auditView(level->text(), user->value());

        table->clearRows();
        int rowNumber = 0; // every line gets its own id, so selection works
        for (const AuditEntry& entry : view.entries) {
            std::string color; // INFO lines keep the normal colour
            if (entry.level == "WARN")
                color = theme::rowColor(Severity::Medium);
            else if (entry.level == "ERROR")
                color = theme::rowColor(Severity::Critical);
            table->addRow(++rowNumber, {entry.time, entry.level, entry.message}, color);
        }
        table->rebuild();

        // The counters come from a std::map<std::string, int>.
        std::string counts;
        for (const auto& pair : view.levelCounts)
            counts += "   " + pair.first + " " + std::to_string(pair.second);
        summary->copy_label(("Showing " + std::to_string(view.entries.size()) + " of " +
                             std::to_string(view.total) + " lines   |" + counts).c_str());
    });
}
