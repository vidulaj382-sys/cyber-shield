#pragma once
// Report: the generated security report, with a button to save it as .txt.
#include "Console.h"
#include "TabPage.h"

class ReportTab : public TabPage {
public:
    ReportTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onSave();

    Console* console;
};
