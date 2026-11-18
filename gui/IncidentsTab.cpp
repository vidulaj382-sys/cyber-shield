#include "IncidentsTab.h"
#include "GuiHelpers.h"

using namespace cyber;

namespace {
const char* kBinaryFile = "incidents.dat"; // binary save / load
const char* kTextFile = "incidents.txt";   // text export / import
} // namespace

IncidentsTab::IncidentsTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Problems", "Write down security problems and mark them as fixed.", manager) {
    const int bottom = 168;                  // height of the form area at the bottom
    const int tableW = w - 296;
    const int tableH = h - 44 - bottom;

    search = new Fl_Input(x + 70, y + 4, 260, 30, "Search:");
    search->when(FL_WHEN_CHANGED);
    search->callback([](Fl_Widget*, void* d) {
        auto* self = static_cast<IncidentsTab*>(d);
        self->table->setFilter(self->search->value());
    }, this);

    table = new DataTable(x, y + 44, tableW, tableH);
    table->setColumns({"Id", "How serious", "Status", "What happened", "Device", "Reported by"},
                      {58, 94, 58, 176, 74});
    table->callback([](Fl_Widget*, void* d) { static_cast<IncidentsTab*>(d)->onSelect(); }, this);

    // The timeline of the selected problem: who did what, and when.
    timeline = new Console(x + tableW + 12, y + 44, w - tableW - 12, tableH,
                           "Timeline of the selected problem", theme::text);
    timeline->println("Click a problem to see its timeline.");

    // ---- the form at the bottom ----
    const int fy = y + h - bottom + 12;
    title = new Fl_Input(x + 120, fy, 290, 28, "What happened?");
    asset = new Fl_Input(x + 120, fy + 36, 290, 28, "Which device?");
    severity = new Fl_Choice(x + 120, fy + 72, 120, 28, "How serious?");
    for (const char* name : {"Low", "Medium", "High", "Critical"})
        severity->add(name);
    severity->value(1);
    auto* reportBtn = new FlatButton(x + 250, fy + 72, 160, 28, "Report problem");
    theme::button(reportBtn, theme::blue);
    ON_CLICK(IncidentsTab, reportBtn, onReport);

    const int bx = x + 440, bw = 190;
    resolveBtn = new FlatButton(bx, fy - 4, bw, 30, "Mark as fixed");
    theme::button(resolveBtn, theme::green);
    ON_CLICK(IncidentsTab, resolveBtn, onResolve);
    undoBtn = new FlatButton(bx + bw + 10, fy - 4, bw, 30, "Undo last fix");
    theme::button(undoBtn, theme::amber);
    ON_CLICK(IncidentsTab, undoBtn, onUndo);

    auto* saveBtn = new FlatButton(bx, fy + 32, bw, 30, "Save my work");
    theme::button(saveBtn, theme::slate);
    ON_CLICK(IncidentsTab, saveBtn, onSave);
    loadBtn = new FlatButton(bx + bw + 10, fy + 32, bw, 30, "Open saved work");
    theme::button(loadBtn, theme::slate);
    ON_CLICK(IncidentsTab, loadBtn, onLoad);

    auto* exportBtn = new FlatButton(bx, fy + 68, bw, 30, "Export to text file");
    theme::button(exportBtn, theme::slate);
    ON_CLICK(IncidentsTab, exportBtn, onExport);
    importBtn = new FlatButton(bx + bw + 10, fy + 68, bw, 30, "Import from text file");
    theme::button(importBtn, theme::slate);
    ON_CLICK(IncidentsTab, importBtn, onImport);

    assignee = new Fl_Choice(bx, fy + 104, bw, 28);
    assignBtn = new FlatButton(bx + bw + 10, fy + 104, bw, 30, "Assign to selected");
    theme::button(assignBtn, theme::blue);
    assignBtn->tooltip("Choose a person on the left, click a problem, then press this");
    ON_CLICK(IncidentsTab, assignBtn, onAssign);

    end();
}

void IncidentsTab::fillAssignees() {
    const Person* user = manager.currentUser();
    if (!user || !user->canManageUsers()) { // only an Admin may list the people
        assignee->clear();
        assigneeNames.clear();
        return;
    }
    std::vector<const Person*> people = manager.listUsers();
    if (people.size() == assigneeNames.size())
        return; // nothing changed
    assignee->clear();
    assigneeNames.clear();
    for (const Person* p : people) {
        assignee->add(p->nameForOthers().c_str()); // employees appear in their hidden form
        assigneeNames.push_back(p->getName());
    }
    assignee->value(0);
}

void IncidentsTab::refresh() {
    table->clearRows();
    for (const Incident& inc : manager.getIncidents()) {
        // Open problems use their severity colour, fixed ones are grey.
        std::string color = inc.isOpen() ? theme::rowColor(inc.getSeverity())
                                         : theme::rowColor(theme::SlotResolved);
        table->addRow(inc.getId(),
                      {"INC-" + std::to_string(inc.getId()), severityName(inc.getSeverity()),
                       inc.isOpen() ? "OPEN" : "Fixed", inc.getTitle(), inc.getAsset(),
                       manager.displayName(inc.getReporter())},
                      color);
    }
    table->setFilter(search->value());
    onSelect();
    fillAssignees();

    const Person* user = manager.currentUser();
    bool canResolve = user && user->canResolve();
    setEnabled(resolveBtn, canResolve);
    setEnabled(undoBtn, canResolve && manager.canUndo());
    setEnabled(assignBtn, canResolve && !assigneeNames.empty());
    setEnabled(assignee, canResolve && !assigneeNames.empty());
    bool isAdmin = user && user->canManageUsers();
    setEnabled(loadBtn, isAdmin);
    setEnabled(importBtn, isAdmin);
}

void IncidentsTab::onSelect() {
    timeline->clear();
    int id = table->selectedIdOrZero();
    if (id == 0) {
        timeline->println("Click a problem to see its timeline.");
        return;
    }
    guarded([&] {
        std::vector<std::string> lines = manager.timelineLines(id);
        if (lines.empty())
            timeline->println("No history was saved for this problem.");
        for (const std::string& line : lines)
            timeline->println(line);
    });
}

void IncidentsTab::onReport() {
    guarded([this] {
        Severity level = toSeverity(severity->value() + 1);
        manager.reportIncident(title->value(), asset->value(), level);
        title->value("");
        refresh();
    });
}

void IncidentsTab::onResolve() {
    guarded([this] {
        manager.resolveIncident(table->selectedId());
        refresh();
    });
}

void IncidentsTab::onUndo() {
    guarded([this] {
        manager.undoResolve();
        refresh();
    });
}

void IncidentsTab::onAssign() {
    guarded([this] {
        int index = assignee->value();
        if (index < 0 || index >= static_cast<int>(assigneeNames.size()))
            throw ValidationException("choose a person first");
        manager.assignIncident(table->selectedId(), assigneeNames[index]);
        refresh();
    });
}

void IncidentsTab::onSave() {
    guarded([this] {
        manager.saveIncidents(kBinaryFile);
        fl_message("Saved to %s", kBinaryFile);
    });
}

void IncidentsTab::onLoad() {
    guarded([this] {
        manager.loadIncidents(kBinaryFile);
        refresh();
        fl_message("Loaded %s", kBinaryFile);
    });
}

void IncidentsTab::onExport() {
    guarded([this] {
        manager.exportIncidents(kTextFile);
        fl_message("Exported to %s\n(The text file keeps the problems but not their timelines.)", kTextFile);
    });
}

void IncidentsTab::onImport() {
    guarded([this] {
        manager.importIncidents(kTextFile);
        refresh();
        fl_message("Imported %s", kTextFile);
    });
}
