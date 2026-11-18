#pragma once
// A drawing of the network: every device is a round node around a central hub,
// coloured by its risk. Custom widget = subclass of Fl_Widget that overrides draw().
// Click a node to select it.
#include <string>
#include <vector>

#include <FL/Fl_Widget.H>

#include "../core/Types.h"

class NetworkMap : public Fl_Widget {
public:
    struct Node {
        std::string name;
        std::string kind;
        int risk = 0;                                  // 0..100
        cyber::Severity level = cyber::Severity::Low;  // decides the colour
        std::string info;                              // text shown when the node is selected
    };

    NetworkMap(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

    void setNodes(const std::vector<Node>& newNodes);
    int selectedIndex() const { return picked; }
    std::string selectedInfo() const;

protected:
    void draw() override;
    int handle(int event) override;

private:
    void positionOf(int index, int& px, int& py) const; // where node number 'index' is drawn

    std::vector<Node> nodes;
    int picked = -1;
};
