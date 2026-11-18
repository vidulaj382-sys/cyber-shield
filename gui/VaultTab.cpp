#include "VaultTab.h"
#include "GuiHelpers.h"

#include "../core/PasswordEntry.h"

using namespace cyber;

VaultTab::VaultTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Safe Box", "A locked box for your secret notes and passwords.", manager) {
    buildLockedView(x, y, w, h);
    buildOpenView(x, y, w, h);
    end();
}

// ---- the locked view ---------------------------------------------------------

void VaultTab::buildLockedView(int x, int y, int w, int h) {
    lockedView = new Fl_Group(x, y, w, h);
    const int cx = x + w / 2;

    lockIcon = new LockIcon(cx - 40, y + 20, 80, 96);
    lockedTitle = new Fl_Box(x, y + 126, w, 36);
    lockedTitle->labelfont(FL_HELVETICA_BOLD);
    lockedTitle->labelsize(24);
    lockedTitle->labelcolor(theme::text);

    lockedText = new Fl_Box(cx - 260, y + 166, 520, 56);
    lockedText->labelsize(14);
    lockedText->labelcolor(theme::muted);
    lockedText->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    secretInput = new Fl_Secret_Input(cx - 170, y + 252, 340, 40, "Secret password");
    secretInput->align(FL_ALIGN_TOP_LEFT);
    confirmInput = new Fl_Secret_Input(cx - 170, y + 328, 340, 40, "Type it again");
    confirmInput->align(FL_ALIGN_TOP_LEFT);

    openButton = new FlatButton(cx - 170, y + 392, 340, 46);
    theme::button(openButton, theme::blue);
    openButton->labelsize(15);
    openButton->shortcut(FL_Enter);
    ON_CLICK(VaultTab, openButton, onOpenOrCreate);

    auto* warning = new Fl_Box(cx - 260, y + 452, 520, 40,
                               "Remember your secret password! If you forget it, nobody can open the box - not even us.");
    theme::hint(warning);
    warning->labelsize(12);
    warning->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    lockedView->end();
}

// ---- the open view -------------------------------------------------------------

void VaultTab::buildOpenView(int x, int y, int w, int h) {
    openView = new Fl_Group(x, y, w, h);

    auto* state = new Fl_Box(x, y, 400, 36, "The Safe Box is OPEN");
    state->labelfont(FL_HELVETICA_BOLD);
    state->labelsize(18);
    state->labelcolor(theme::slotColor(theme::SlotLow));
    state->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    auto* lockBtn = new FlatButton(x + w - 190, y, 190, 36, "Lock the box");
    theme::button(lockBtn, theme::slotColor(theme::SlotHigh));
    ON_CLICK(VaultTab, lockBtn, onLock);

    // left column: what is inside
    const int leftW = 410;
    search = new Fl_Input(x + 70, y + 44, leftW - 70, 28, "Search:");
    search->when(FL_WHEN_CHANGED);
    search->callback([](Fl_Widget*, void* d) {
        auto* self = static_cast<VaultTab*>(d);
        self->table->setFilter(self->search->value());
    }, this);

    table = new DataTable(x, y + 80, leftW, 200);
    table->setColumns({"Kind", "Name"}, {90});
    table->callback([](Fl_Widget*, void* d) { static_cast<VaultTab*>(d)->onSelect(); }, this);

    auto* deleteBtn = new FlatButton(x, y + 288, 200, 32, "Delete selected");
    theme::button(deleteBtn, theme::red);
    ON_CLICK(VaultTab, deleteBtn, onDelete);
    showButton = new FlatButton(x + 210, y + 288, 200, 32, "Show password");
    theme::button(showButton, theme::slate);
    ON_CLICK(VaultTab, showButton, onToggleSecret);

    details = new Console(x, y + 348, leftW, h - 348, "What is inside the selected item", theme::text);

    // right column: put something new inside
    const int rx = x + leftW + 24;
    const int rw = w - leftW - 24;
    const int fieldX = rx + 100, fieldW = rw - 100;

    auto* noteHeading = new Fl_Box(rx, y + 50, rw, 24, "Save a secret note (a document)");
    theme::heading(noteHeading);
    noteHeading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    noteTitle = new Fl_Input(fieldX, y + 84, fieldW, 32, "Title:");
    noteText = new Fl_Multiline_Input(fieldX, y + 124, fieldW, 84, "Your text:");
    noteText->wrap(1);
    auto* saveNote = new FlatButton(fieldX, y + 216, fieldW, 34, "Lock this note away");
    theme::button(saveNote, theme::blue);
    ON_CLICK(VaultTab, saveNote, onSaveNote);

    auto* passHeading = new Fl_Box(rx, y + 282, rw, 24, "Save a password");
    theme::heading(passHeading);
    passHeading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    site = new Fl_Input(fieldX, y + 316, fieldW, 32, "Website:");
    userName = new Fl_Input(fieldX, y + 356, fieldW, 32, "User name:");
    passwordInput = new Fl_Input(fieldX, y + 396, fieldW - 120, 32, "Password:");
    passwordInput->when(FL_WHEN_CHANGED);
    passwordInput->callback([](Fl_Widget*, void* d) { static_cast<VaultTab*>(d)->onPasswordTyped(); }, this);
    auto* generateBtn = new FlatButton(fieldX + fieldW - 112, y + 396, 112, 32, "Make one");
    theme::button(generateBtn, theme::slate);
    ON_CLICK(VaultTab, generateBtn, onGeneratePassword);
    strengthLabel = new Fl_Box(fieldX, y + 432, fieldW, 22, "");
    strengthLabel->labelsize(12);
    strengthLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    auto* savePass = new FlatButton(fieldX, y + 458, fieldW, 34, "Lock this password away");
    theme::button(savePass, theme::blue);
    ON_CLICK(VaultTab, savePass, onSavePassword);

    openView->end();
}

// ---- showing the right view ----------------------------------------------------

void VaultTab::refresh() {
    Vault& vault = manager.getVault();

    if (!vault.isUnlocked()) {
        openView->hide();
        lockedView->show();
        lockIcon->setLocked(true);
        secretInput->value("");
        confirmInput->value("");
        showSecret = false;

        if (vault.exists()) {
            lockedTitle->copy_label("Your Safe Box is locked");
            lockedText->copy_label("Type your secret password to open it.");
            confirmInput->hide();
            openButton->copy_label("Unlock");
        } else {
            lockedTitle->copy_label("Make your Safe Box");
            lockedText->copy_label("Choose ONE secret password. It protects all your notes and passwords.");
            confirmInput->show();
            openButton->copy_label("Create my Safe Box");
        }
        redraw();
        return;
    }

    lockedView->hide();
    openView->show();

    table->clearRows();
    for (const VaultItem* item : vault.items())
        table->addRow(item->getId(), {item->kind(), item->summary()});
    table->setFilter(search->value());
    showButton->copy_label(showSecret ? "Hide password" : "Show password");
    showDetails();
    redraw();
}

void VaultTab::showDetails() {
    details->clear();
    int id = table->selectedIdOrZero();
    if (id == 0) {
        details->println("Pick something in the list to see what is inside.");
        return;
    }
    for (const VaultItem* item : manager.getVault().items())
        if (item->getId() == id)
            details->setText(item->detail(showSecret));
}

// ---- actions ---------------------------------------------------------------------

void VaultTab::onOpenOrCreate() {
    guarded([this] {
        Vault& vault = manager.getVault();
        if (vault.exists()) {
            vault.unlock(secretInput->value());
        } else {
            if (std::string(secretInput->value()) != confirmInput->value())
                throw ValidationException("the two passwords are not the same");
            vault.create(secretInput->value());
        }
        refresh();
    });
}

void VaultTab::onLock() {
    manager.getVault().lock();
    refresh();
}

void VaultTab::onSaveNote() {
    guarded([this] {
        manager.getVault().addNote(noteTitle->value(), noteText->value());
        noteTitle->value("");
        noteText->value("");
        refresh();
    });
}

void VaultTab::onSavePassword() {
    guarded([this] {
        manager.getVault().addPassword(site->value(), userName->value(), passwordInput->value());
        site->value("");
        userName->value("");
        passwordInput->value("");
        onPasswordTyped();
        refresh();
    });
}

void VaultTab::onGeneratePassword() {
    guarded([this] {
        passwordInput->value(PasswordEntry::generate(14).c_str());
        onPasswordTyped();
    });
}

void VaultTab::onDelete() {
    guarded([this] {
        int id = table->selectedId();
        if (fl_choice("Delete this item for ever?", "Cancel", "Delete", nullptr) == 1) {
            manager.getVault().removeItem(id);
            refresh();
        }
    });
}

void VaultTab::onToggleSecret() {
    showSecret = !showSecret;
    showButton->copy_label(showSecret ? "Hide password" : "Show password");
    showDetails();
}

void VaultTab::onSelect() { showDetails(); }

// Shows "Weak / OK / Strong" while typing a password.
void VaultTab::onPasswordTyped() {
    std::string typed = passwordInput->value();
    if (typed.empty()) {
        strengthLabel->copy_label("");
    } else {
        std::string rating = PasswordEntry::strength(typed);
        strengthLabel->copy_label(("How strong is it?  " + rating).c_str());
        strengthLabel->labelcolor(rating == "Weak"   ? theme::slotColor(theme::SlotCritical)
                                  : rating == "OK"   ? theme::slotColor(theme::SlotMedium)
                                                     : theme::slotColor(theme::SlotLow));
    }
    strengthLabel->redraw();
}
