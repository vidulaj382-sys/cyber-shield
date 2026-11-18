#pragma once
// Dashboard: four stat cards, a bar chart, a risk gauge and the newest incidents.
#include <vector>


#include "BarChart.h"
#include "DataTable.h"
#include "FlatButton.h"
#include "RiskGauge.h"
#include "StatCard.h"
#include "StatusBanner.h"
#include "TabPage.h"

class DashboardTab : public TabPage {
public:
    DashboardTab(int x, int y, int w, int h, cyber::SecurityManager& manager);
    void refresh() override;

private:
    void onLoadSample();

    StatusBanner* banner;
    FlatButton* sampleBtn;
    StatCard* assetsCard;
    StatCard* incidentsCard;
    StatCard* threatsCard;
    StatCard* resolvedCard;
    BarChart* chart;
    RiskGauge* gauge;
    DataTable* latest;
};
