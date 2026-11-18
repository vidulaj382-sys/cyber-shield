#pragma once
// Log Analyzer: open any text log file (like a server log) and find the suspicious lines:
// failed logins, port scans and dangerous commands.
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Input.H>

#include "Console.h"
#include "StatusBanner.h"
#include "TabPage.h"

class LogAnalyzerTab : public TabPage {
public:
    LogAnalyzerTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onBrowse();
    void onAnalyze();

    Fl_Input* path;
    Fl_Check_Button* makeProblems;
    FlatButton* analyzeBtn;
    FlatButton* browseBtn;
    StatusBanner* banner;
    Console* counts;
    Console* lines;
};
