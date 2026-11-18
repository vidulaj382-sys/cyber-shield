#pragma once
// A table for every list in the app:
//   - click a COLUMN NAME (the first line) to sort by it; click again to reverse
//   - setFilter() keeps only the rows that contain some text (the search box)
//   - each row remembers an id, so selection survives sorting and filtering
// It is a normal Fl_Hold_Browser with a few extra abilities (inheritance + overriding).
#include <string>
#include <vector>

#include <FL/Fl_Hold_Browser.H>

class DataTable : public Fl_Hold_Browser {
public:
    DataTable(int x, int y, int w, int h, const char* label = nullptr);

    // Column titles and widths in pixels (use 0 for "the rest" on the last column).
    void setColumns(const std::vector<std::string>& names, const std::vector<int>& widths);

    void clearRows();
    // colorPrefix is a row colour such as theme::rowColor(...), or "" for the normal colour.
    void addRow(int id, const std::vector<std::string>& cells, const std::string& colorPrefix = "");

    void setFilter(const std::string& text); // search; empty text shows everything
    void rebuild();                          // draw the rows with the current search and sort

    int selectedIdOrZero() const;            // 0 when nothing is selected
    int selectedId() const;                  // throws ValidationException when nothing is selected
    void selectId(int id);

protected:
    int handle(int event) override;

private:
    struct Row {
        int id;
        std::vector<std::string> cells;
        std::string color;
    };

    void sortByColumnAt(int pixelX);
    bool lessThan(const Row& a, const Row& b) const;

    std::vector<Row> rows;
    std::vector<int> shownIds;      // id of every line that is shown (after the header)
    std::vector<std::string> header;
    std::vector<int> widthArray;    // column widths ending with 0, as FLTK wants them
    std::string filter;
    int sortColumn = -1;
    bool ascending = true;
};
