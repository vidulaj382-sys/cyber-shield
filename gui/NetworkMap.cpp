#include "NetworkMap.h"
#include "Theme.h"

#include <cmath>

#include <FL/fl_draw.H>

namespace {
const int kNodeRadius = 28;
const int kHubRadius = 34;
const double kPi = 3.14159265358979;
} // namespace

void NetworkMap::setNodes(const std::vector<Node>& newNodes) {
    nodes = newNodes;
    if (picked >= static_cast<int>(nodes.size()))
        picked = -1;
    redraw();
}

std::string NetworkMap::selectedInfo() const {
    if (picked < 0 || picked >= static_cast<int>(nodes.size()))
        return "";
    return nodes[picked].info;
}

void NetworkMap::positionOf(int index, int& px, int& py) const {
    // Nodes are spread evenly on an ellipse around the middle of the widget.
    const int cx = x() + w() / 2, cy = y() + h() / 2 + 8;
    const double rx = w() / 2.0 - 80, ry = h() / 2.0 - 70;
    double angle = -kPi / 2 + 2 * kPi * index / static_cast<double>(nodes.empty() ? 1 : nodes.size());
    px = cx + static_cast<int>(rx * std::cos(angle));
    py = cy + static_cast<int>(ry * std::sin(angle));
}

void NetworkMap::draw() {
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::card);

    // Legend
    fl_font(FL_HELVETICA_BOLD, 13);
    fl_color(theme::accent);
    fl_draw("Network map - colour = risk", x() + 16, y() + 8, 300, 22, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    const char* names[] = {"Low", "Medium", "High", "Critical"};
    fl_font(FL_HELVETICA, 12);
    for (int i = 0; i < 4; ++i) {
        int lx = x() + w() - 360 + i * 88;
        fl_color(theme::severityColor(static_cast<cyber::Severity>(i + 1)));
        fl_pie(lx, y() + 14, 12, 12, 0, 360);
        fl_color(theme::muted);
        fl_draw(names[i], lx + 18, y() + 8, 66, 24, FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    }

    const int cx = x() + w() / 2, cy = y() + h() / 2 + 8;

    // Lines from the hub to every device.
    fl_line_style(FL_SOLID, 2);
    for (size_t i = 0; i < nodes.size(); ++i) {
        int px, py;
        positionOf(static_cast<int>(i), px, py);
        fl_color(theme::grid);
        fl_line(cx, cy, px, py);
    }
    fl_line_style(FL_SOLID, 1);

    // The hub.
    fl_color(theme::accent);
    fl_pie(cx - kHubRadius, cy - kHubRadius, kHubRadius * 2, kHubRadius * 2, 0, 360);
    fl_color(FL_WHITE);
    fl_font(FL_HELVETICA_BOLD, 13);
    fl_draw("Network", cx - 34, cy - 10, 68, 20, FL_ALIGN_CENTER);

    // The devices.
    for (size_t i = 0; i < nodes.size(); ++i) {
        int px, py;
        positionOf(static_cast<int>(i), px, py);
        const Node& node = nodes[i];

        if (static_cast<int>(i) == picked) { // ring around the selected node
            fl_color(theme::text);
            fl_pie(px - kNodeRadius - 5, py - kNodeRadius - 5, (kNodeRadius + 5) * 2, (kNodeRadius + 5) * 2, 0, 360);
        }
        fl_color(theme::severityColor(node.level));
        fl_pie(px - kNodeRadius, py - kNodeRadius, kNodeRadius * 2, kNodeRadius * 2, 0, 360);

        fl_color(FL_WHITE);
        fl_font(FL_HELVETICA_BOLD, 15);
        fl_draw(std::to_string(node.risk).c_str(), px - kNodeRadius, py - 10, kNodeRadius * 2, 20, FL_ALIGN_CENTER);

        fl_color(theme::text);
        fl_font(FL_HELVETICA_BOLD, 12);
        fl_draw(node.name.c_str(), px - 60, py + kNodeRadius + 2, 120, 16, FL_ALIGN_CENTER);
        fl_color(theme::muted);
        fl_font(FL_HELVETICA, 11);
        fl_draw(node.kind.c_str(), px - 60, py + kNodeRadius + 16, 120, 14, FL_ALIGN_CENTER);
    }

    if (nodes.empty()) {
        fl_color(theme::muted);
        fl_font(FL_HELVETICA, 14);
        fl_draw("There are no devices yet. Add some on the My Devices page.", x(), y(), w(), h(), FL_ALIGN_CENTER);
    }
}

int NetworkMap::handle(int event) {
    if (event == FL_PUSH) {
        for (size_t i = 0; i < nodes.size(); ++i) {
            int px, py;
            positionOf(static_cast<int>(i), px, py);
            int dx = Fl::event_x() - px, dy = Fl::event_y() - py;
            if (dx * dx + dy * dy <= kNodeRadius * kNodeRadius) {
                picked = static_cast<int>(i);
                redraw();
                do_callback(); // tell the page that a device was clicked
                return 1;
            }
        }
        picked = -1;
        redraw();
        do_callback();
        return 1;
    }
    return Fl_Widget::handle(event);
}
