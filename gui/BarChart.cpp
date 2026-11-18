#include "BarChart.h"
#include "Theme.h"

#include <string>

#include <FL/fl_draw.H>

using cyber::Severity;

BarChart::BarChart(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {
    for (int& v : values)
        v = 0;
}

void BarChart::setData(const cyber::SeverityCounts& counts) {
    for (int i = 0; i < 4; ++i)
        values[i] = counts.count(static_cast<Severity>(i + 1));
    redraw();
}

void BarChart::draw() {
    fl_draw_box(FL_RFLAT_BOX, x(), y(), w(), h(), theme::card);

    fl_color(theme::accent);
    fl_font(FL_HELVETICA_BOLD, 14);
    fl_draw("Open problems, by how serious they are", x() + 16, y() + 8, w() - 32, 24,
            FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    // Plot area and a scale that is always a multiple of 4 (so grid lines are whole numbers).
    const int left = x() + 44, right = x() + w() - 20;
    const int top = y() + 46, bottom = y() + h() - 36;
    int largest = 0;
    for (int v : values)
        if (v > largest)
            largest = v;
    const int scale = largest <= 4 ? 4 : ((largest + 3) / 4) * 4;

    // Horizontal grid lines with their numbers.
    fl_font(FL_HELVETICA, 11);
    for (int i = 0; i <= 4; ++i) {
        int lineY = bottom - (bottom - top) * i / 4;
        fl_color(theme::grid);
        fl_line(left, lineY, right, lineY);
        fl_color(theme::muted);
        fl_draw(std::to_string(scale * i / 4).c_str(), x() + 8, lineY - 8, 30, 16,
                FL_ALIGN_RIGHT | FL_ALIGN_INSIDE);
    }

    // One bar per severity.
    const int slot = (right - left) / 4;
    const int barWidth = slot * 55 / 100;
    for (int i = 0; i < 4; ++i) {
        Severity severity = static_cast<Severity>(i + 1);
        int barHeight = (bottom - top) * values[i] / scale;
        int barX = left + slot * i + (slot - barWidth) / 2;

        if (barHeight > 0)
            fl_draw_box(FL_RFLAT_BOX, barX, bottom - barHeight, barWidth, barHeight,
                        theme::severityColor(severity));

        fl_color(theme::text);
        fl_font(FL_HELVETICA_BOLD, 13);
        fl_draw(std::to_string(values[i]).c_str(), barX, bottom - barHeight - 22, barWidth, 20,
                FL_ALIGN_CENTER | FL_ALIGN_INSIDE);

        fl_color(theme::muted);
        fl_font(FL_HELVETICA, 12);
        fl_draw(cyber::severityName(severity).c_str(), barX - 10, bottom + 6, barWidth + 20, 20,
                FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    }
}
