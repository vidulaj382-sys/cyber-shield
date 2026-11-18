#include "DashboardTab.h"
#include "GuiHelpers.h"

#include <FL/Fl_Box.H>

using namespace cyber;

DashboardTab::DashboardTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Home", "Is everything safe today? Start here.", manager) {
    const int gap = 14;
    const int bannerH = 66;
    banner = new StatusBanner(x, y, w, bannerH);

    // Sits on top of the banner, on the right. Only an Admin can use it.
    sampleBtn = new FlatButton(x + w - 190, y + 16, 174, 34, "Load sample data");
    theme::button(sampleBtn, theme::slate);
    sampleBtn->tooltip("Adds example devices and problems so you can try everything (Admin only)");
    ON_CLICK(DashboardTab, sampleBtn, onLoadSample);

    const int cardY = y + bannerH + gap;
    const int cardWidth = (w - 3 * gap) / 4;
    assetsCard = new StatCard(x, cardY, cardWidth, 96, "DEVICES WE PROTECT");
    incidentsCard = new StatCard(x + (cardWidth + gap), cardY, cardWidth, 96, "PROBLEMS TO FIX");
    threatsCard = new StatCard(x + 2 * (cardWidth + gap), cardY, cardWidth, 96, "ATTACKS CAUGHT");
    resolvedCard = new StatCard(x + 3 * (cardWidth + gap), cardY, cardWidth, 96, "PROBLEMS FIXED");

    const int rowY = cardY + 96 + gap;
    const int rowH = y + h - rowY;
    const int chartWidth = w * 55 / 100;
    chart = new BarChart(x, rowY, chartWidth, rowH);

    const int colX = x + chartWidth + gap;
    const int colW = w - chartWidth - gap;
    gauge = new RiskGauge(colX, rowY, colW, 180);

    latest = new DataTable(colX, rowY + 180 + gap + 24, colW, rowH - 180 - gap - 24, "Newest problems");
    latest->setColumns({"Id", "How serious", "What happened"}, {60, 90});
    latest->align(FL_ALIGN_TOP_LEFT);
    theme::heading(latest);

    end();
}

void DashboardTab::onLoadSample() {
    guarded([this] {
        std::string message = manager.loadSampleData();
        refresh();
        fl_message("%s\n\nLook at My Devices and Problems to see them.", message.c_str());
    });
}

void DashboardTab::refresh() {
    const Person* user = manager.currentUser();
    setEnabled(sampleBtn, user && user->canManageAssets());

    DashboardStats stats = manager.getStats();
    int total = static_cast<int>(manager.getIncidents().size());
    int open = stats.openIncidents;

    // The big message at the top, in plain words.
    if (open == 0) {
        banner->set("All clear! Everything looks safe.",
                    "There are no problems to fix right now. Great job!",
                    theme::slotColor(theme::SlotLow));
    } else if (stats.risk.percent() < 50) {
        banner->set("Be careful: " + std::to_string(open) + (open == 1 ? " problem needs" : " problems need") + " fixing.",
                    "Open the Problems page and mark each one as fixed when you have dealt with it.",
                    theme::slotColor(theme::SlotMedium));
    } else {
        banner->set("Danger! " + std::to_string(open) + (open == 1 ? " problem needs" : " problems need") + " your attention.",
                    "Some of them are serious. Open the Problems page and start with the red ones.",
                    theme::slotColor(theme::SlotCritical));
    }

    assetsCard->set(std::to_string(stats.assets), "computers, servers, routers", theme::accent);
    incidentsCard->set(std::to_string(open), open == 0 ? "nothing to do" : "waiting for you",
                       open == 0 ? theme::slotColor(theme::SlotLow)
                                 : theme::slotColor(theme::SlotCritical));
    threatsCard->set(std::to_string(stats.threatsDetected), "since the app started",
                     theme::slotColor(theme::SlotHigh));
    resolvedCard->set(std::to_string(total - open), "out of " + std::to_string(total) + " in total",
                      theme::slotColor(theme::SlotLow));

    Fl_Color riskColor = theme::slotColor(theme::SlotLow);
    if (stats.risk.percent() >= 75)
        riskColor = theme::slotColor(theme::SlotCritical);
    else if (stats.risk.percent() >= 50)
        riskColor = theme::slotColor(theme::SlotHigh);
    else if (stats.risk.percent() >= 25)
        riskColor = theme::slotColor(theme::SlotMedium);
    gauge->set(stats.risk.percent(), stats.risk.level(), riskColor);

    chart->setData(stats.openBySeverity);

    // Newest five problems, newest first.
    latest->clearRows();
    int shown = 0;
    const auto& incidents = manager.getIncidents();
    for (auto it = incidents.rbegin(); it != incidents.rend() && shown < 5; ++it, ++shown) {
        latest->addRow(it->getId(),
                       {"INC-" + std::to_string(it->getId()), severityName(it->getSeverity()), it->getTitle()},
                       it->isOpen() ? theme::rowColor(it->getSeverity())
                                    : theme::rowColor(theme::SlotResolved));
    }
    latest->rebuild();
}
