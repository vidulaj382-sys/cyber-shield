#pragma once
// Half-circle gauge that shows the overall risk score (0..100 %).
#include <string>
#include <FL/Fl_Widget.H>

class RiskGauge : public Fl_Widget {
public:
    RiskGauge(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}

    void set(int newPercent, const std::string& newLevel, Fl_Color newColor);

protected:
    void draw() override;

private:
    int percent = 0;
    std::string level = "Low";
    Fl_Color arcColor = FL_GREEN;
};
