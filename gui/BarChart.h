#pragma once
// Bar chart of incidents by severity, drawn with FLTK drawing functions.
#include <FL/Fl_Widget.H>

#include "../core/SeverityCounts.h"

class BarChart : public Fl_Widget {
public:
    BarChart(int x, int y, int w, int h);

    void setData(const cyber::SeverityCounts& counts);

protected:
    void draw() override;

private:
    int values[4]; // Low, Medium, High, Critical
};
