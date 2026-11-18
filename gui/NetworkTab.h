#pragma once
// Network Map: every device drawn as a node, coloured by its risk.
#include <FL/Fl_Box.H>

#include "NetworkMap.h"
#include "TabPage.h"

class NetworkTab : public TabPage {
public:
    NetworkTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    NetworkMap* map;
    Fl_Box* info;
};
