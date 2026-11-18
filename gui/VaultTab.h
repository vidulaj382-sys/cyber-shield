#pragma once
// Safe Box: a locked place for secret notes (documents) and passwords.
// Two views on one page: the LOCKED view (padlock + password) and the OPEN view.
#include <vector>

#include <FL/Fl_Box.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Multiline_Input.H>
#include <FL/Fl_Secret_Input.H>

#include "Console.h"
#include "DataTable.h"
#include "FlatButton.h"
#include "LockIcon.h"
#include "TabPage.h"

class VaultTab : public TabPage {
public:
    VaultTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void buildLockedView(int x, int y, int w, int h);
    void buildOpenView(int x, int y, int w, int h);

    void onOpenOrCreate();
    void onLock();
    void onSaveNote();
    void onSavePassword();
    void onGeneratePassword();
    void onDelete();
    void onToggleSecret();
    void onSelect();
    void onPasswordTyped();
    void showDetails();

    // locked view
    Fl_Group* lockedView;
    LockIcon* lockIcon;
    Fl_Box* lockedTitle;
    Fl_Box* lockedText;
    Fl_Secret_Input* secretInput;
    Fl_Secret_Input* confirmInput;
    FlatButton* openButton;

    // open view
    Fl_Group* openView;
    Fl_Input* search;
    DataTable* table;
    Console* details;
    Fl_Input* noteTitle;
    Fl_Multiline_Input* noteText;
    Fl_Input* site;
    Fl_Input* userName;
    Fl_Input* passwordInput;
    Fl_Box* strengthLabel;
    FlatButton* showButton;
    bool showSecret = false;
};
