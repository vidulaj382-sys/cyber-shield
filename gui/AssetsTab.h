#pragma once
// My Devices: search, a sortable table with a colour-coded risk, add / edit / remove,
// undo / redo, and a security checklist for the selected device.
#include <FL/Fl_Box.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Int_Input.H>

#include "DataTable.h"
#include "TabPage.h"

class AssetsTab : public TabPage {
public:
    AssetsTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onAdd();
    void onSave();
    void onRemove();
    void onUndo();
    void onRedo();
    void onSelect();
    void onCheckClicked(Fl_Widget* clicked);
    void showChecklist(const cyber::Asset* asset);

    Fl_Input* search;
    DataTable* table;
    Fl_Group* form; // everything that only an Admin may use
    Fl_Input* name;
    Fl_Input* ip;
    Fl_Int_Input* criticality;
    Fl_Choice* type;
    Fl_Input* extra;
    FlatButton* saveBtn;
    FlatButton* removeBtn;
    FlatButton* undoBtn;
    FlatButton* redoBtn;
    Fl_Group* checklist;
    Fl_Check_Button* checks[6];
    Fl_Box* complianceLabel;
    Fl_Box* note;
    bool loadingChecks = false; // true while we tick the boxes ourselves
};
