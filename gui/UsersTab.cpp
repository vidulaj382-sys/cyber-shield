#include "UsersTab.h"
#include "GuiHelpers.h"

#include "../core/Password.h"

using namespace cyber;

UsersTab::UsersTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "People", "Who is allowed to use this app (only an Admin can change this).", manager) {
    const int tableW = w - 350;

    search = new Fl_Input(x + 70, y + 4, 260, 30, "Search:");
    search->when(FL_WHEN_CHANGED);
    search->callback([](Fl_Widget*, void* d) {
        auto* self = static_cast<UsersTab*>(d);
        self->table->setFilter(self->search->value());
    }, this);

    table = new DataTable(x, y + 44, tableW, h - 44);
    table->setColumns({"Id", "Name", "Role", "Activity"}, {50, 130, 90});

    const int fx = x + tableW + 18, rw = w - tableW - 18;
    auto* heading = new Fl_Box(fx, y + 4, rw, 26, "Add or remove people (Admin only)");
    theme::heading(heading);
    heading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    form = new Fl_Group(fx, y + 36, rw, 270);
    username = new Fl_Input(fx + 90, y + 40, rw - 90, 28, "Name:");
    password = new Fl_Secret_Input(fx + 90, y + 76, rw - 90, 28, "Password:");
    password->when(FL_WHEN_CHANGED);
    password->callback([](Fl_Widget*, void* d) { static_cast<UsersTab*>(d)->onPasswordTyped(); }, this);
    strengthLabel = new Fl_Box(fx, y + 108, rw, 44, "");
    strengthLabel->labelsize(12);
    strengthLabel->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    role = new Fl_Choice(fx + 90, y + 158, rw - 90, 28, "Role:");
    for (const char* name : {"Employee", "Admin"})
        role->add(name);
    role->value(0);

    auto* addBtn = new FlatButton(fx, y + 202, rw, 32, "Add person");
    theme::button(addBtn, theme::blue);
    ON_CLICK(UsersTab, addBtn, onAdd);
    auto* removeBtn = new FlatButton(fx, y + 242, rw, 32, "Remove selected");
    theme::button(removeBtn, theme::red);
    ON_CLICK(UsersTab, removeBtn, onRemove);
    form->end();

    note = new Fl_Box(fx, y + 290, rw, 100);
    theme::hint(note);
    note->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    end();
    onPasswordTyped(); // show the first hint
}

void UsersTab::refresh() {
    const Person* user = manager.currentUser();
    bool isAdmin = user && user->canManageUsers();
    setEnabled(form, isAdmin);

    table->clearRows();
    realNames.clear();
    if (!isAdmin) {
        table->rebuild();
        note->copy_label("Only an Admin can see the user accounts.");
        return;
    }
    for (const Person* p : manager.listUsers()) {
        // nameForOthers() is a virtual function: an Employee hides its real name (e******e),
        // so the Admin never sees employee details directly - only this summary.
        std::string activity = p->canManageUsers()
                                   ? std::string("-")
                                   : std::to_string(manager.problemsReportedBy(p->getName())) +
                                         " problem(s) reported";
        table->addRow(p->getId(),
                      {"#" + std::to_string(p->getId()), p->nameForOthers(), p->roleName(), activity});
        realNames[p->getId()] = p->getName(); // the real name is kept only inside the program
    }
    table->setFilter(search->value());
    note->copy_label("Privacy: employee names are hidden from the Admin (shown like e******e). "
                     "An employee's Safe Box and passwords can never be seen by anyone else.");
}

// Shows how strong the new password is, with a tip, while it is being typed.
void UsersTab::onPasswordTyped() {
    Password typed(password->value());
    if (typed.text().empty()) {
        strengthLabel->copy_label("Pick a strong password. Weak ones are refused.");
        strengthLabel->labelcolor(theme::muted);
    } else {
        strengthLabel->copy_label(("Strength: " + typed.rating() + " (" + std::to_string(typed.score()) +
                                   "/100). " + typed.tip()).c_str());
        strengthLabel->labelcolor(typed.rating() == "Weak"   ? theme::slotColor(theme::SlotCritical)
                                  : typed.rating() == "OK"   ? theme::slotColor(theme::SlotMedium)
                                                             : theme::slotColor(theme::SlotLow));
    }
    strengthLabel->redraw();
}

void UsersTab::onAdd() {
    guarded([this] {
        manager.addUser(username->value(), password->value(), role->text());
        username->value("");
        password->value("");
        onPasswordTyped();
        refresh();
    });
}

void UsersTab::onRemove() {
    guarded([this] {
        int id = table->selectedId();
        std::string who = realNames[id];
        std::string shown = manager.displayName(who); // hidden form for an employee
        if (fl_choice("Remove user '%s'?", "Cancel", "Remove", nullptr, shown.c_str()) == 1) {
            manager.removeUser(who);
            refresh();
        }
    });
}
