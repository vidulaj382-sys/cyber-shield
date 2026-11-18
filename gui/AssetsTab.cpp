#include "AssetsTab.h"
#include "GuiHelpers.h"

#include <cstdlib>
#include <set>

using namespace cyber;

AssetsTab::AssetsTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "My Devices", "The computers, servers and routers we look after.", manager) {
    const int tableW = w - 340;

    search = new Fl_Input(x + 70, y + 4, 260, 30, "Search:");
    search->when(FL_WHEN_CHANGED); // filter while typing
    search->callback([](Fl_Widget*, void* d) { static_cast<AssetsTab*>(d)->refresh(); }, this);

    table = new DataTable(x, y + 44, tableW, h - 44);
    table->setColumns({"Id", "Kind", "Name", "IP number", "Risk", "Secure", "Alerts"},
                      {38, 78, 100, 96, 78, 56});
    table->callback([](Fl_Widget*, void* d) { static_cast<AssetsTab*>(d)->onSelect(); }, this);

    // ---- right column: add / change a device ----
    const int fx = x + tableW + 14, rw = w - tableW - 14, fieldX = fx + 118, fieldW = rw - 118;
    auto* heading = new Fl_Box(fx, y + 4, rw, 26, "Add or change a device (Admin only)");
    theme::heading(heading);
    heading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    form = new Fl_Group(fx, y + 36, rw, 290);
    name = new Fl_Input(fieldX, y + 40, fieldW, 28, "Name:");
    ip = new Fl_Input(fieldX, y + 75, fieldW, 28, "Number (IP):");
    criticality = new Fl_Int_Input(fieldX, y + 110, fieldW, 28, "Important? 1-5:");
    criticality->value("3");
    type = new Fl_Choice(fieldX, y + 145, fieldW, 28, "Kind:");
    for (const char* kind : {"Workstation", "Server", "Router"})
        type->add(kind);
    type->value(0);
    extra = new Fl_Input(fieldX, y + 180, fieldW, 28, "Extra info:");
    extra->tooltip("Workstation: owner   Server: services   Router: uplink");

    const int half = (rw - 8) / 2;
    auto* addBtn = new FlatButton(fx, y + 220, half, 30, "Add device");
    theme::button(addBtn, theme::blue);
    ON_CLICK(AssetsTab, addBtn, onAdd);
    saveBtn = new FlatButton(fx + half + 8, y + 220, half, 30, "Save changes");
    theme::button(saveBtn, theme::green);
    saveBtn->tooltip("Click a device in the table, change the boxes, then press this");
    ON_CLICK(AssetsTab, saveBtn, onSave);

    const int third = (rw - 16) / 3;
    removeBtn = new FlatButton(fx, y + 258, third, 30, "Remove");
    theme::button(removeBtn, theme::red);
    ON_CLICK(AssetsTab, removeBtn, onRemove);
    undoBtn = new FlatButton(fx + third + 8, y + 258, third, 30, "Undo");
    theme::button(undoBtn, theme::amber);
    ON_CLICK(AssetsTab, undoBtn, onUndo);
    redoBtn = new FlatButton(fx + 2 * (third + 8), y + 258, third, 30, "Redo");
    theme::button(redoBtn, theme::amber);
    ON_CLICK(AssetsTab, redoBtn, onRedo);
    form->end();

    // ---- right column: the security checklist of the selected device ----
    auto* checkHeading = new Fl_Box(fx, y + 306, rw, 24, "Security checklist of the selected device");
    theme::heading(checkHeading);
    checkHeading->labelsize(14);
    checkHeading->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    checklist = new Fl_Group(fx, y + 332, rw, 160);
    const auto& items = Asset::checklistItems();
    for (size_t i = 0; i < items.size(); ++i) {
        checks[i] = new Fl_Check_Button(fx, y + 334 + static_cast<int>(i) * 25, rw, 24, items[i].c_str());
        checks[i]->labelcolor(theme::text);
        checks[i]->labelsize(13);
        checks[i]->callback([](Fl_Widget* clicked, void* d) {
            static_cast<AssetsTab*>(d)->onCheckClicked(clicked);
        }, this);
    }
    checklist->end();

    complianceLabel = new Fl_Box(fx, y + 488, rw, 24, "Click a device to see its checklist.");
    complianceLabel->labelfont(FL_HELVETICA_BOLD);
    complianceLabel->labelsize(13);
    complianceLabel->labelcolor(theme::muted);
    complianceLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    note = new Fl_Box(fx, y + 510, rw, 34);
    theme::hint(note);
    note->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    end();
}

void AssetsTab::refresh() {
    // The search box uses the core's searchAssets (std::copy_if + std::sort).
    std::set<const Asset*> matches;
    for (const Asset* a : manager.searchAssets(search->value()))
        matches.insert(a);

    table->clearRows();
    for (const AssetRiskRow& row : manager.riskRanking()) { // riskiest device first
        const Asset* a = row.asset;
        if (!matches.count(a))
            continue;
        auto* monitored = dynamic_cast<const Monitored*>(a); // only servers and routers have alerts
        table->addRow(a->getId(),
                      {"#" + std::to_string(a->getId()), a->type(), a->getName(), a->getIp(),
                       std::to_string(row.risk.percent()) + " " + row.risk.level(),
                       std::to_string(a->compliancePercent()) + "%",
                       monitored ? std::to_string(monitored->getAlerts()) : "-"},
                      theme::rowColor(row.risk.severity())); // colour = risk
    }
    table->rebuild();
    onSelect();

    const Person* user = manager.currentUser();
    bool canEdit = user && user->canManageAssets();
    setEnabled(form, canEdit);
    setEnabled(checklist, canEdit);
    setEnabled(undoBtn, canEdit && manager.canUndoAssetChange());
    setEnabled(redoBtn, canEdit && manager.canRedoAssetChange());
    note->copy_label(canEdit ? "Click a column name to sort the table. Row colour = risk."
                             : "You can look at the devices, but only an Admin can change them.");
}

// A device was clicked: copy its data into the boxes so it can be edited.
void AssetsTab::onSelect() {
    int id = table->selectedIdOrZero();
    const Asset* asset = id ? manager.getAssets().findById(id) : nullptr;
    if (asset != nullptr) {
        name->value(asset->getName().c_str());
        ip->value(asset->getIp().c_str());
        criticality->value(std::to_string(asset->getCriticality()).c_str());
        extra->value(asset->extraInfo().c_str());
        const std::string kind = asset->type();
        type->value(kind == "Workstation" ? 0 : kind == "Server" ? 1 : 2);
    }
    showChecklist(asset);
}

void AssetsTab::showChecklist(const Asset* asset) {
    loadingChecks = true;
    for (size_t i = 0; i < Asset::checklistItems().size(); ++i)
        checks[i]->value(asset && asset->isChecked(Asset::checklistItems()[i]) ? 1 : 0);
    loadingChecks = false;

    if (asset == nullptr) {
        complianceLabel->copy_label("Click a device to see its checklist.");
        complianceLabel->labelcolor(theme::muted);
    } else {
        int percent = asset->compliancePercent();
        complianceLabel->copy_label(("Compliance: " + std::to_string(percent) + "% of the checks are done").c_str());
        complianceLabel->labelcolor(percent >= 80 ? theme::slotColor(theme::SlotLow)
                                    : percent >= 50 ? theme::slotColor(theme::SlotMedium)
                                                    : theme::slotColor(theme::SlotCritical));
    }
    complianceLabel->redraw();
}

void AssetsTab::onCheckClicked(Fl_Widget* clicked) {
    if (loadingChecks)
        return;
    guarded([this, clicked] {
        int id = table->selectedId();
        for (size_t i = 0; i < Asset::checklistItems().size(); ++i)
            if (checks[i] == clicked)
                manager.setAssetCheck(id, Asset::checklistItems()[i], checks[i]->value() != 0);
        refresh(); // the risk changed too
    });
    // If the change was refused (for example: no device selected), show the real state again.
    int id = table->selectedIdOrZero();
    showChecklist(id ? manager.getAssets().findById(id) : nullptr);
}

void AssetsTab::onAdd() {
    guarded([this] {
        const char* kinds[] = {"Workstation", "Server", "Router"};
        manager.addAsset(kinds[type->value()], name->value(), ip->value(),
                         std::atoi(criticality->value()), extra->value());
        name->value("");
        ip->value("");
        extra->value("");
        table->selectId(0); // nothing selected, so the boxes stay empty
        refresh();
    });
}

void AssetsTab::onSave() {
    guarded([this] {
        manager.editAsset(table->selectedId(), name->value(), ip->value(),
                          std::atoi(criticality->value()), extra->value());
        refresh();
    });
}

void AssetsTab::onRemove() {
    guarded([this] {
        int id = table->selectedId();
        if (fl_choice("Remove device #%d? (You can press Undo afterwards.)", "Cancel", "Remove", nullptr, id) == 1) {
            manager.removeAsset(id);
            refresh();
        }
    });
}

void AssetsTab::onUndo() {
    guarded([this] {
        manager.undoAssetChange();
        refresh();
    });
}

void AssetsTab::onRedo() {
    guarded([this] {
        manager.redoAssetChange();
        refresh();
    });
}
