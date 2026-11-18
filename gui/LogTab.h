#pragma once
// History: the AUDIT TRAIL. Who did what and when, read from cybershield.log,
// with filters by level (INFO / WARN / ERROR) and by user (or any word).
#include <FL/Fl_Box.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Input.H>

#include "DataTable.h"
#include "TabPage.h"

class LogTab : public TabPage {
public:
    LogTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    Fl_Choice* level;
    Fl_Input* user;
    Fl_Box* summary;
    DataTable* table;
};
