#include "NetworkTab.h"
#include "GuiHelpers.h"

using namespace cyber;

NetworkTab::NetworkTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Network Map", "See all your devices at once. The redder a node, the riskier it is.", manager) {
    map = new NetworkMap(x, y, w, h - 64);
    map->callback([](Fl_Widget*, void* d) {
        auto* self = static_cast<NetworkTab*>(d);
        std::string text = self->map->selectedInfo();
        self->info->copy_label(text.empty() ? "Click a device to see the details." : text.c_str());
    }, this);

    info = new Fl_Box(x, y + h - 52, w, 52, "Click a device to see the details.");
    info->box(FL_RFLAT_BOX);
    info->color(theme::card);
    info->labelcolor(theme::text);
    info->labelsize(14);
    info->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    end();
}

void NetworkTab::refresh() {
    std::vector<NetworkMap::Node> nodes;
    for (const AssetRiskRow& row : manager.riskRanking()) {
        const Asset* a = row.asset;
        auto* monitored = dynamic_cast<const Monitored*>(a);
        NetworkMap::Node node;
        node.name = a->getName();
        node.kind = a->type();
        node.risk = row.risk.percent();
        node.level = row.risk.severity();
        node.info = "  " + a->getName() + " (" + a->type() + ")   IP " + a->getIp() +
                    "   Risk " + std::to_string(row.risk.percent()) + "% " + row.risk.level() +
                    "   Checklist " + std::to_string(a->compliancePercent()) + "% done" +
                    (monitored ? "   Alerts " + std::to_string(monitored->getAlerts()) : "");
        nodes.push_back(node);
    }
    map->setNodes(nodes);
    info->copy_label("Click a device to see the details.");
}
