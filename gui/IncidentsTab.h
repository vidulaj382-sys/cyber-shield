#pragma once
// Problems (incidents): a sortable, searchable table, a TIMELINE for the selected problem,
// report / fix / undo / assign, and file save / load.
#include <string>
#include <vector>

#include <FL/Fl_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Input.H>

#include "Console.h"
#include "DataTable.h"
#include "TabPage.h"

class IncidentsTab : public TabPage {
public:
    IncidentsTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onReport();
    void onResolve();
    void onUndo();
    void onAssign();
    void onSelect();
    void onSave();
    void onLoad();
    void onExport();
    void onImport();
    void fillAssignees();

    Fl_Input* search;
    DataTable* table;
    Console* timeline;
    Fl_Input* title;
    Fl_Input* asset;
    Fl_Choice* severity;
    Fl_Choice* assignee;
    FlatButton* resolveBtn;
    FlatButton* undoBtn;
    FlatButton* assignBtn;
    FlatButton* loadBtn;
    FlatButton* importBtn;
    std::vector<std::string> assigneeNames; // the real user names, in the same order as the choice
};
