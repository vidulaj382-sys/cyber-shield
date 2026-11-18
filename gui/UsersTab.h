#pragma once
// People: Admin-only list, add and remove of user accounts. Employees are shown in
// their hidden form. A new password is rated live (Password class), weak ones are refused.
#include <map>
#include <string>

#include <FL/Fl_Box.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>

#include "DataTable.h"
#include "TabPage.h"

class UsersTab : public TabPage {
public:
    UsersTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onAdd();
    void onRemove();
    void onPasswordTyped();

    Fl_Input* search;
    DataTable* table;
    Fl_Group* form;
    Fl_Input* username;
    Fl_Secret_Input* password;
    Fl_Box* strengthLabel;
    Fl_Choice* role;
    Fl_Box* note;
    std::map<int, std::string> realNames; // row id -> the real user name (never shown)
};
