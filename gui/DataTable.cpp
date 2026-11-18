#include "DataTable.h"
#include "GuiHelpers.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "../core/Utils.h"

namespace {

// Reads a number from text like "12", "#12", "INC-7", "72 High" or "50%". False when it is not one.
bool numberOf(const std::string& cell, double& number) {
    std::string t = cell;
    if (!t.empty() && t[0] == '#')
        t = t.substr(1);
    else if (t.compare(0, 4, "INC-") == 0)
        t = t.substr(4);
    if (t.empty() || !std::isdigit(static_cast<unsigned char>(t[0])))
        return false;
    number = std::atof(t.c_str());
    return true;
}

} // namespace

DataTable::DataTable(int x, int y, int w, int h, const char* label)
    : Fl_Hold_Browser(x, y, w, h, label) {
    theme::list(this);
}

void DataTable::setColumns(const std::vector<std::string>& names, const std::vector<int>& widths) {
    header = names;
    widthArray = widths;
    widthArray.push_back(0); // FLTK wants the list to end with 0
    column_widths(widthArray.data());
    sortColumn = -1;
}

void DataTable::clearRows() { rows.clear(); }

void DataTable::addRow(int id, const std::vector<std::string>& cells, const std::string& colorPrefix) {
    rows.push_back({id, cells, colorPrefix});
}

void DataTable::setFilter(const std::string& text) {
    filter = cyber::util::toLower(cyber::util::trim(text));
    rebuild();
}

bool DataTable::lessThan(const Row& a, const Row& b) const {
    const std::string& left = a.cells[sortColumn];
    const std::string& right = b.cells[sortColumn];
    double x = 0, y = 0;
    if (numberOf(left, x) && numberOf(right, y))
        return ascending ? x < y : x > y;      // numbers are compared as numbers
    std::string l = cyber::util::toLower(left), r = cyber::util::toLower(right);
    return ascending ? l < r : l > r;           // everything else as text
}

void DataTable::rebuild() {
    int keep = selectedIdOrZero(); // remember the selection
    clear();
    shownIds.clear();

    // The first line shows the column names (the sorted one gets an arrow).
    std::string head = "@b" + theme::rowColor(theme::SlotHeader);
    for (size_t i = 0; i < header.size(); ++i) {
        head += (i == 0 ? "" : "\t") + header[i];
        if (static_cast<int>(i) == sortColumn)
            head += ascending ? "  ^" : "  v";
    }
    add(head.c_str());

    // Keep the rows that match the search.
    std::vector<const Row*> visible;
    for (const Row& row : rows) {
        std::string all;
        for (const std::string& cell : row.cells)
            all += cyber::util::toLower(cell) + " ";
        if (filter.empty() || all.find(filter) != std::string::npos)
            visible.push_back(&row);
    }

    if (sortColumn >= 0) {
        std::stable_sort(visible.begin(), visible.end(),
                         [this](const Row* a, const Row* b) { return lessThan(*a, *b); });
    }

    for (const Row* row : visible) {
        std::string line = row->color.empty() ? "" : row->color + "@."; // "@." ends the colour code
        for (size_t i = 0; i < row->cells.size(); ++i)
            line += (i == 0 ? "" : "\t") + safeText(row->cells[i]);
        add(line.c_str());
        shownIds.push_back(row->id);
    }
    selectId(keep);
}

int DataTable::selectedIdOrZero() const {
    int line = value(); // 1-based, 0 = nothing; line 1 is the header
    if (line < 2 || line - 2 >= static_cast<int>(shownIds.size()))
        return 0;
    return shownIds[line - 2];
}

int DataTable::selectedId() const {
    int id = selectedIdOrZero();
    if (id == 0)
        throw cyber::ValidationException("select a row in the list first");
    return id;
}

void DataTable::selectId(int id) {
    value(0);
    for (size_t i = 0; id != 0 && i < shownIds.size(); ++i)
        if (shownIds[i] == id) {
            value(static_cast<int>(i) + 2);
            return;
        }
}

void DataTable::sortByColumnAt(int pixelX) {
    int column = 0, left = 4; // 4 pixels of padding before the first column
    for (size_t i = 0; i < header.size(); ++i) {
        column = static_cast<int>(i);
        int width = widthArray[i];
        if (width == 0 || pixelX < left + width)
            break;
        left += width;
    }
    if (column == sortColumn)
        ascending = !ascending; // same column again: reverse
    else {
        sortColumn = column;
        ascending = true;
    }
    rebuild();
    value(0); // the header line is not a real selection
}

int DataTable::handle(int event) {
    int result = Fl_Hold_Browser::handle(event);
    if (event == FL_RELEASE && value() == 1) { // the column-name line was clicked
        sortByColumnAt(Fl::event_x() - x());
        return 1;
    }
    return result;
}
