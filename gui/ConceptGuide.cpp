#include "ConceptGuide.h"

#include <map>
#include <vector>

namespace conceptguide {

namespace {

// One line of the guide.
struct Entry {
    const char* topic; // the syllabus idea
    const char* where; // file and class
    const char* use;   // what it does in THIS app
};

const std::map<std::string, std::vector<Entry>>& guide() {
    static const std::map<std::string, std::vector<Entry>> data = {
        {"Home", {
            {"Custom widgets (inheritance + overriding)", "gui/StatCard, BarChart, RiskGauge, StatusBanner",
             "Each is a child of Fl_Widget and overrides draw() to paint the cards, the chart and the gauge."},
            {"Operator overloading: operator+", "core/RiskScore.cpp, RiskScore::operator+",
             "Adds the risk points of every open problem to make the danger level."},
            {"Copy constructor + dynamic memory", "core/SeverityCounts.cpp",
             "Keeps the chart numbers in a new int[4] array. The copy constructor makes a deep copy, so two objects never share one array."},
            {"Function template", "core/Utils.h, util::countIf<Container, Test>",
             "Counts open problems in any container (used by SecurityManager::getStats)."},
            {"Callback with std::function", "core/SecurityManager.h setAlertHandler(); gui/MainWindow.cpp raiseAlert()",
             "The core says 'a CRITICAL threat was found' without knowing about the screen. The window plugs in a function that shows the blinking red bar, the toast and the beep."},
            {"Timers", "gui/AlertBar.cpp, gui/Toast.cpp, gui/SplashWindow.cpp (Fl::add_timeout)",
             "The blinking banner, the pop-up that closes itself and the splash loading bar all run on FLTK timers."},
            {"Dark / light theme", "gui/Theme.h setPalette(); main.cpp App::switchTheme()",
             "The colours are variables. Changing them and building the windows again gives the other look."},
            {"Pure virtual function", "gui/TabPage.h, TabPage::refresh() = 0",
             "Every page promises to reload itself. MainWindow calls refresh() on all pages through the base class."}}},

        {"My Devices", {
            {"Abstract class + pure virtual functions", "core/Asset.h, Asset::type(), details(), extraInfo()",
             "Asset is only an idea. You can only create a real Workstation, Server or Router."},
            {"Hierarchical + multiple inheritance", "core/Asset.h",
             "Workstation, Server and Router inherit from Asset. Server and Router also inherit from Monitored, so they can raise alerts."},
            {"Command pattern: undo / redo with TWO STACKS", "core/AssetCommand.h (AddAssetCommand, RemoveAssetCommand, EditAssetCommand); SecurityManager assetUndo / assetRedo",
             "Every change is a small object that can do and undo itself. Undo pops one stack and pushes onto the other. A new change clears the redo stack."},
            {"Polymorphism", "core/AssetCommand.h, AssetCommand::execute() / undo()",
             "The manager only holds unique_ptr<AssetCommand>. The right child runs, whatever kind of change it is."},
            {"Operator overloading: operator< and operator+", "core/AssetRisk.h",
             "Risk parts (importance, alerts, open problems, missing checks) are added with +. Devices are ordered with < by std::sort, riskiest first."},
            {"STL sort, set, copy_if", "SecurityManager::riskRanking(), Asset::passed (std::set), searchAssets()",
             "Ranks devices by risk; remembers which checklist items are done; filters by the search text."},
            {"Security checklist", "core/Asset.h, checklistItems(), compliancePercent()",
             "Six checks per device ('Firewall is on' ...). The compliance percentage feeds the risk."},
            {"Click a column to sort", "gui/DataTable.cpp",
             "A Fl_Hold_Browser child that sorts rows with std::stable_sort and filters them with the search box. Numbers sort as numbers."},
            {"dynamic_cast (cross-cast)", "SecurityManager::riskOf(), gui/AssetsTab.cpp",
             "Asks an Asset* 'are you Monitored?' - only a Server or Router says yes, so only they have alerts."},
            {"Class template", "core/Repository.h, Repository<Asset>",
             "One generic box that owns the devices: add, remove, findById, findIf."}}},

        {"Network Map", {
            {"Custom widget with draw() and handle()", "gui/NetworkMap.cpp",
             "Draws the hub, the lines and a round node per device with FLTK drawing functions. handle() finds which node you clicked."},
            {"Operator overloading", "core/AssetRisk.h",
             "The node colour comes from AssetRisk::severity(); nodes are laid out from the riskRanking() list."},
            {"Struct as plain data", "NetworkMap::Node",
             "The page converts core data into simple nodes, so the widget needs no knowledge of the core."}}},

        {"Attack Detector", {
            {"Abstract class + pure virtual function", "core/Threat.h, Threat::detect() = 0",
             "Every attack type must know how to detect itself."},
            {"Runtime polymorphism", "core/SecurityManager.cpp, scan()",
             "A loop over Threat* pointers calls detect() - the right version runs for malware, phishing, brute force or DDoS."},
            {"Function overloading", "SecurityManager::scan (3 versions), BruteForceThreat::detect(string / int), DDoSThreat::detect(string / int)",
             "Same name for scanning text, a single text, or two numbers."},
            {"Virtual destructor + upcasting", "core/Threat.h, SecurityManager constructor",
             "new MalwareThreat() is stored as a Threat*, and delete on it cleans up the child class correctly."},
            {"dynamic_cast (downcast)", "core/SecurityManager.h, findThreat<T>()",
             "Finds the BruteForce or DDoS detector so its detect(int) can be used."},
            {"STL queue", "core/SecurityManager.h, scanQueue",
             "'Check it later' puts samples in a line; first in, first out."},
            {"Stack unwinding", "core/SecurityManager.cpp, class ScanGuard",
             "Writes 'Scan finished' in the log even if the scan throws an error."},
            {"Alert callback", "SecurityManager::recordThreat()",
             "A CRITICAL detection calls the alert handler: blinking bar, toast and sound."}}},

        {"Link Checker", {
            {"Inheritance + overriding", "core/LinkThreat.h, class LinkThreat : Threat",
             "Another kind of threat. It overrides detect(), advice() and explanation()."},
            {"struct returned by value", "core/LinkThreat.h, LinkReport",
             "Carries the score, the website name and the reasons back to the screen."},
            {"STL set and vector", "core/LinkThreat.cpp",
             "set<string> badSites and shorteners (fast lookup); vector<string> scammerWords."},
            {"Exceptions", "core/LinkThreat.cpp, ValidationException",
             "'not a link' or 'contains spaces' is refused with a friendly message."},
            {"Automatic incident", "core/SecurityManager.cpp, checkLink()",
             "A dangerous link creates a problem on the Problems page automatically."}}},

        {"Log Analyzer", {
            {"Text file handling", "core/LogAnalyzer.cpp, analyzeFile()",
             "Reads any log file; a missing file gives a FileException that the screen shows as a message."},
            {"STL map as a counter", "LogReport::byCategory and bySource (std::map<string,int>)",
             "Counts how many lines of each kind, and how many suspicious lines each IP address caused."},
            {"Function templates", "core/Utils.h, util::countUp<Key> and util::topCounts<Key>",
             "countUp adds one to any map key; topCounts returns the busiest N keys (sorted with std::sort)."},
            {"Two-pass algorithm", "LogAnalyzer::analyzeText()",
             "Pass 1 remembers which ports each IP touched. Pass 2 marks a line as a port scan when one IP touched 5 or more different ports."},
            {"Role check", "SecurityManager::analyzeLogFile(), canScan()",
             "Only an Admin may analyze logs. It can also create problems from the findings."}}},

        {"Safe Box", {
            {"Abstract class + hierarchy", "core/VaultItem.h, SecureNote.h, PasswordEntry.h",
             "VaultItem is the idea of 'something we can lock away'. SecureNote and PasswordEntry are the real kinds."},
            {"Class template reuse", "core/Vault.h, Repository<VaultItem>",
             "The same Repository template that stores devices now owns the Safe Box items."},
            {"Scrambling the file", "core/Vault.cpp, core/XorCipher.h",
             "Notes and passwords are scrambled with XorCipher before they are written to disk."},
            {"Binary file I/O", "core/Vault.cpp save() and unlock(); core/VaultItem.cpp bytes::putText / getText",
             "Writes a magic header 'CSV1', a password check, then the scrambled items as raw bytes."},
            {"Static member functions", "core/PasswordEntry.h strength() and generate()",
             "Rate a password (with the Password class) and make a random one, without making an object."},
            {"Encapsulation + RAII", "core/Vault.h, ~Vault()",
             "The secret key is private, only exists while unlocked, and is overwritten by lock(). Copying is deleted."},
            {"Exceptions", "VaultLockedException, AuthException, FileException",
             "Locked box, wrong password and damaged file each have their own error."}}},

        {"Problems", {
            {"Timeline: std::vector of structs", "core/Incident.h, IncidentEvent; Incident::addEvent()",
             "Each problem keeps a list of events (reported, assigned, fixed, fix undone) with time and person."},
            {"Operator overloading", "core/Incident.h, <<, >>, == and <; operator<< for IncidentEvent",
             "<< prints a timeline line; < orders by seriousness; >> reads a line from the text file."},
            {"Versioned binary file", "core/Incident.cpp, readBinary(); SecurityManager kMagicV1 / kMagicV2",
             "New files ('CSH2') store the timeline. Old files ('CSH1') still open, just without one."},
            {"Static member", "core/Incident.h, Incident::nextId",
             "Gives each new problem the next number (INC-1, INC-2, ...)."},
            {"Friend function", "core/Incident.h, incidentSummary()",
             "Reads the private fields to build a one-line summary."},
            {"STL stack", "core/SecurityManager.h, undoStack",
             "'Undo last fix' takes the newest fix first (last in, first out)."},
            {"Search and sort", "gui/DataTable.cpp",
             "Type to filter, click a column name to sort."},
            {"Privacy", "SecurityManager::timelineLines(), maskPrivateNames()",
             "Employee names in the timeline are shown hidden (e******e)."}}},

        {"My Report", {
            {"Friend class", "core/ReportWriter.h, friend class of SecurityManager",
             "The report writer may read the manager's private lists."},
            {"Text file I/O", "core/SecurityManager.cpp, saveReport()",
             "Writes the report to security_report.txt."},
            {"Operator overloading", "Asset::operator<< and RiskScore::operator<<",
             "Print a device or the danger level straight into the report."},
            {"STL algorithm sort", "core/ReportWriter.cpp",
             "Sorts problems by priority using Incident::operator<."},
            {"Privacy", "core/SecurityManager.cpp, maskPrivateNames()",
             "Before the report leaves the program, every employee name is replaced by the hidden form (e******e)."}}},

        {"History", {
            {"Audit trail", "core/AuditTrail.h / .cpp",
             "Reads cybershield.log back and splits every line into time, level and message."},
            {"Filters", "AuditTrail::filter(), SecurityManager::auditView()",
             "Show only INFO, WARN or ERROR lines, or only lines that mention a user. Not case sensitive."},
            {"STL map", "AuditTrail::countByLevel() -> std::map<string,int>",
             "The counters 'INFO 120  WARN 4' come from a map, filled with the util::countUp template."},
            {"Static members + text file I/O", "core/Logger.h / .cpp",
             "Every action is appended to the log with the time. Logger::info(...) needs no object."},
            {"Exception handling inside a class", "core/Logger.cpp",
             "If the log cannot be written, the error is caught so the app never crashes."},
            {"Privacy", "SecurityManager::auditView()",
             "Employee names in the log are hidden from other people."}}},

        {"People", {
            {"Password class with operators", "core/Password.h / .cpp",
             "score(), rating() and tip() give the strength meter. operator< compares strength, operator== compares text, operator+ adds characters, operator<< prints stars."},
            {"String handling", "core/Password.cpp",
             "Checks length, upper and lower case, digits, symbols, repeated letters and common words."},
            {"Virtual base class (diamond)", "core/Person.h, Employee.h, Admin.h, SecurityOfficer.h",
             "Person is shared by Employee and Admin. SecurityOfficer inherits both with only ONE Person inside. It is kept to show the diamond; it is not a login role."},
            {"Overriding for privacy", "core/Person.h nameForOthers(); core/Employee.h override",
             "An Employee hides its real name (e******e). The Admin's People page shows only that and a count of problems reported."},
            {"Upcasting + factory", "core/SecurityManager.cpp, makeUser()",
             "Builds the right child class and keeps it as a Person* in a std::map."},
            {"Exceptions", "AuthException, AccessDeniedException, ValidationException",
             "Wrong password, not allowed or a weak new password -> a clear message box."}}}
    };
    return data;
}

// Makes text safe to put inside HTML.
std::string escape(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '&') out += "&amp;";
        else out += c;
    }
    return out;
}
} // namespace

std::string htmlFor(const std::string& pageTitle) {
    std::string html = "<html><body>";
    auto found = guide().find(pageTitle);
    if (found == guide().end())
        return html + "<p>No notes for this page.</p></body></html>";

    for (const Entry& e : found->second) {
        html += "<p><b><font color=\"#38bdf8\">" + escape(e.topic) + "</font></b><br>";
        html += "<font color=\"#8291aa\">Where: </font>" + escape(e.where) + "<br>";
        html += "<font color=\"#8291aa\">Use: </font>" + escape(e.use) + "</p>";
    }
    return html + "</body></html>";
}

} // namespace conceptguide
