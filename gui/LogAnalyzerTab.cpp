#include "LogAnalyzerTab.h"
#include "GuiHelpers.h"

#include <unistd.h> // getcwd / chdir

#include <FL/Fl_Native_File_Chooser.H>

#include "../core/Utils.h"

using namespace cyber;

LogAnalyzerTab::LogAnalyzerTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Log Analyzer", "Open a log file and we will mark the suspicious lines for you.", manager) {
    path = new Fl_Input(x, y + 26, w - 290, 36, "Log file:");
    path->align(FL_ALIGN_TOP_LEFT);
    path->value("sample_data/server.log");

    browseBtn = new FlatButton(x + w - 280, y + 26, 120, 36, "Browse...");
    theme::button(browseBtn, theme::slate);
    ON_CLICK(LogAnalyzerTab, browseBtn, onBrowse);
    analyzeBtn = new FlatButton(x + w - 150, y + 26, 150, 36, "Analyze it!");
    theme::button(analyzeBtn, theme::blue);
    analyzeBtn->labelsize(14);
    ON_CLICK(LogAnalyzerTab, analyzeBtn, onAnalyze);

    makeProblems = new Fl_Check_Button(x, y + 72, 420, 24, "Also add what we find to the Problems page");
    makeProblems->labelcolor(theme::text);
    makeProblems->labelsize(13);

    banner = new StatusBanner(x, y + 106, w, 74);
    banner->set("No file analyzed yet", "Press Analyze it! to look at the sample file, or Browse... to pick your own.",
                theme::muted);

    const int half = 300;
    counts = new Console(x, y + 206, half, h - 206, "What we found", theme::text);
    lines = new Console(x + half + 12, y + 206, w - half - 12, h - 206, "Suspicious lines", theme::text);
    counts->println("The counters will show up here.");
    lines->println("The suspicious lines will show up here.");

    end();
}

void LogAnalyzerTab::refresh() {
    const Person* user = manager.currentUser();
    bool allowed = user && user->canScan();
    setEnabled(analyzeBtn, allowed);
    setEnabled(browseBtn, allowed);
    setEnabled(path, allowed);
    setEnabled(makeProblems, allowed);
    if (!allowed)
        banner->set("Only an Admin can analyze log files", "Ask an Admin to look at the log for you.", theme::muted);
}

void LogAnalyzerTab::onBrowse() {
    // The Windows file chooser can change the working directory, and this program
    // uses relative file names - so remember it and put it back.
    char before[1024];
    bool saved = getcwd(before, sizeof before) != nullptr;

    Fl_Native_File_Chooser chooser;
    chooser.title("Choose a log file");
    chooser.type(Fl_Native_File_Chooser::BROWSE_FILE);
    chooser.filter("Log files\t*.{log,txt}\nAll files\t*");
    if (chooser.show() == 0)
        path->value(chooser.filename());

    if (saved)
        chdir(before);
}

void LogAnalyzerTab::onAnalyze() {
    guarded([this] {
        LogReport report = manager.analyzeLogFile(path->value(), makeProblems->value() != 0);

        int bad = static_cast<int>(report.findings.size());
        if (bad == 0)
            banner->set("Nothing suspicious found", "We looked at " + std::to_string(report.totalLines) +
                        " lines and they all look normal.", theme::slotColor(theme::SlotLow));
        else
            banner->set("Found " + std::to_string(bad) + " suspicious lines",
                        "out of " + std::to_string(report.totalLines) + " lines." +
                        (makeProblems->value() ? " Problems were added to the Problems page." : ""),
                        bad >= 10 ? theme::slotColor(theme::SlotCritical) : theme::slotColor(theme::SlotHigh));

        // Counters: std::map<std::string, int> of kinds, and the busiest sources.
        counts->clear();
        if (report.byCategory.empty())
            counts->println("Nothing to count.");
        for (const auto& entry : report.byCategory)
            counts->println(entry.first + ": " + std::to_string(entry.second));
        if (!report.bySource.empty()) {
            counts->println("");
            counts->println("Busiest addresses:");
            for (const auto& top : util::topCounts(report.bySource, 5)) // function template
                counts->println("  " + top.first + "  (" + std::to_string(top.second) + " lines)");
        }

        lines->clear();
        for (const LogFinding& f : report.findings)
            lines->println("[DETECTED] line " + std::to_string(f.lineNumber) + "  " + f.category + ":  " + f.text);
        if (report.findings.empty())
            lines->println("[CLEAN] No suspicious lines.");
    });
}
