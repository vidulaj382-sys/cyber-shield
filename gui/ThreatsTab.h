#pragma once
// Threats: scan text / IPs / numbers, scan queue and console output.
#include <string>
#include <vector>

#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Int_Input.H>
#include <FL/Fl_Multiline_Input.H>

#include "Console.h"
#include "TabPage.h"

class ThreatsTab : public TabPage {
public:
    ThreatsTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onScanText();
    void onQueue();
    void onRunQueue();
    void onScanNumbers();
    void show(const std::vector<std::string>& lines);

    Fl_Input* source;
    Fl_Multiline_Input* sample;
    Fl_Int_Input* failedLogins;
    Fl_Int_Input* requests;
    Fl_Button* scanBtn;
    Fl_Button* runQueueBtn;
    Fl_Button* numbersBtn;
    Console* console;
    std::string queueLabel;
};
