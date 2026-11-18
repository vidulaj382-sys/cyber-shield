#include "SecurityManager.h"
#include "Logger.h"
#include "ReportWriter.h"
#include "Utils.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>

namespace cyber {

namespace {

const char kMagicV1[4] = {'C', 'S', 'H', '1'}; // old files: incidents without a timeline
const char kMagicV2[4] = {'C', 'S', 'H', '2'}; // current files: incidents with a timeline
const std::size_t kMaxSampleSize = 10000;    // longest sample we agree to scan

// Unit IV: stack unwinding. The destructor runs when scan() ends, EVEN when
// an exception is thrown in the middle of it, so "finished" is always logged.
class ScanGuard {
public:
    explicit ScanGuard(const std::string& source) : source(source) {
        Logger::info("Scan started: " + source);
    }
    ~ScanGuard() { Logger::info("Scan finished: " + source); }

private:
    std::string source;
};

} // namespace

// ---- construction -------------------------------------------------------

SecurityManager::SecurityManager() {
    // Dynamic allocation; stored through base-class pointers (upcasting).
    users["admin"] = new Admin("admin", "admin123");
    users["employee"] = new Employee("employee", "emp123");

    threats.push_back(new MalwareThreat());
    threats.push_back(new PhishingThreat());
    threats.push_back(new BruteForceThreat(5));
    threats.push_back(new DDoSThreat(1000));

    assets += new Server("web-01", "10.0.0.10", 5, "http, https");
    assets += new Server("db-01", "10.0.0.20", 5, "postgres");
    assets += new Router("edge-rtr", "10.0.0.1", 4, "ISP uplink");
    assets += new Workstation("hr-laptop", "10.0.1.15", 2, "HR team");

    Logger::info("Cyber Shield started");
}

SecurityManager::~SecurityManager() {
    for (auto& entry : users)
        delete entry.second; // virtual destructor -> correct derived cleanup
    for (Threat* t : threats)
        delete t;
    for (auto& entry : vaults)
        delete entry.second;
    Logger::info("Cyber Shield shut down");
}

// ---- helpers ------------------------------------------------------------

void SecurityManager::requireLogin() const {
    if (current == nullptr)
        throw AuthException("no user is logged in");
}

void SecurityManager::require(bool allowed, const std::string& action) const {
    requireLogin();
    if (!allowed) {
        Logger::warn(current->getName() + " denied: " + action);
        throw AccessDeniedException(action);
    }
}

// Factory: builds the right derived class and returns it as a Person*.
Person* SecurityManager::makeUser(const std::string& username, const std::string& password,
                                  const std::string& role) const {
    if (role == "Admin")
        return new Admin(username, password);
    if (role == "Employee")
        return new Employee(username, password);
    throw ValidationException("unknown role '" + role + "'");
}

// ---- authentication -----------------------------------------------------

Person* SecurityManager::login(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty())
        throw ValidationException("username and password are required");
    if (blocked.count(username))
        throw AuthException("account '" + username + "' is locked after a brute-force attempt");

    auto it = users.find(username);
    if (it == users.end() || !it->second->checkPassword(password)) {
        int attempts = ++failedLogins[username];
        Logger::warn("Failed login for '" + username + "' (attempt " + std::to_string(attempts) + ")");

        BruteForceThreat* bf = findThreat<BruteForceThreat>();
        if (bf && bf->detect(attempts)) {
            blocked.insert(username);
            ++threatStats[bf->getName()];
            addIncident("Brute-force attack on account " + username, "Login Portal",
                        bf->getSeverity(), "system");
            throw AuthException("too many failed attempts - account locked");
        }
        throw AuthException("wrong username or password (attempt " + std::to_string(attempts) + ")");
    }

    failedLogins.erase(username);
    current = it->second;
    Logger::info(current->describe() + " logged in");
    return current;
}

void SecurityManager::logout() {
    for (auto& entry : vaults)
        entry.second->lock(); // every Safe Box locks itself when someone logs out
    if (current)
        Logger::info(current->getName() + " logged out");
    current = nullptr;
}

// ---- users --------------------------------------------------------------

void SecurityManager::addUser(const std::string& username, const std::string& password,
                              const std::string& role) {
    require(current && current->canManageUsers(), "manage users");
    if (username.empty() || username.size() > 20 ||
        username.find_first_of(" |") != std::string::npos)
        throw ValidationException("username must be 1-20 characters without spaces");
    Password strength(password); // the Password class scores it and gives a tip
    if (strength.rating() == "Weak")
        throw ValidationException("that password is too weak. " + strength.tip());
    if (users.count(username))
        throw ValidationException("user '" + username + "' already exists");

    users[username] = makeUser(username, password, role);
    Logger::info("User added: " + users[username]->describe());
}

void SecurityManager::removeUser(const std::string& username) {
    require(current && current->canManageUsers(), "manage users");
    auto it = users.find(username);
    if (it == users.end())
        throw NotFoundException("user '" + username + "'");
    if (it->second == current)
        throw ValidationException("you cannot remove the account you are using");

    delete it->second;
    users.erase(it);
    Logger::info("User removed: " + username);
}

std::vector<const Person*> SecurityManager::listUsers() const {
    require(current && current->canManageUsers(), "view user accounts");
    std::vector<const Person*> list;
    for (const auto& entry : users)
        list.push_back(entry.second);
    return list;
}

std::string SecurityManager::displayName(const std::string& username) const {
    requireLogin();
    auto it = users.find(username);
    if (it == users.end() || it->second == current)
        return username; // system names like "scanner", or your own name
    return it->second->nameForOthers(); // virtual: an Employee hides the name
}

int SecurityManager::problemsReportedBy(const std::string& username) const {
    return util::countIf(incidents, [&](const Incident& i) { return i.getReporter() == username; });
}

// Replaces every name that should stay private (other people's employee names).
std::string SecurityManager::maskPrivateNames(const std::string& text) const {
    std::string result = text;
    for (const auto& entry : users) {
        const Person* person = entry.second;
        if (person != current && person->nameForOthers() != entry.first)
            result = util::replaceWord(result, entry.first, person->nameForOthers());
    }
    return result;
}

// ---- assets -------------------------------------------------------------

Asset& SecurityManager::addAsset(Asset* asset) {
    if (asset == nullptr)
        throw ValidationException("asset is null");

    // We own the pointer, so free it before refusing.
    if (!current || !current->canManageAssets()) {
        delete asset;
        require(false, "manage assets");
    }
    if (assets.findIf([&](const Asset& a) { return a.getName() == asset->getName(); })) {
        std::string name = asset->getName();
        delete asset;
        throw ValidationException("an asset named '" + name + "' already exists");
    }
    if (assets.findIf([&](const Asset& a) { return a == *asset; })) { // Asset::operator==
        std::string ip = asset->getIp();
        delete asset;
        throw ValidationException("an asset with IP " + ip + " already exists");
    }
    assets.add(asset);
    rememberAssetChange(std::unique_ptr<AssetCommand>(new AddAssetCommand(AssetSpec::of(*asset))));
    Logger::info("Asset added: " + asset->describe());
    return *asset;
}

Asset& SecurityManager::addAsset(const std::string& name, const std::string& ip, int criticality) {
    require(current && current->canManageAssets(), "manage assets");
    return addAsset(new Workstation(name, ip, criticality));
}

Asset& SecurityManager::addAsset(const std::string& name, const std::string& ip, int criticality,
                                 const std::string& services) {
    require(current && current->canManageAssets(), "manage assets");
    return addAsset(new Server(name, ip, criticality, services));
}

Asset& SecurityManager::addAsset(const std::string& type, const std::string& name,
                                 const std::string& ip, int criticality,
                                 const std::string& extra) {
    require(current && current->canManageAssets(), "manage assets");
    if (type == "Workstation")
        return addAsset(new Workstation(name, ip, criticality, extra));
    if (type == "Server")
        return addAsset(new Server(name, ip, criticality, extra));
    if (type == "Router")
        return addAsset(new Router(name, ip, criticality, extra));
    throw ValidationException("unknown asset type '" + type + "'");
}

void SecurityManager::removeAsset(int id) {
    require(current && current->canManageAssets(), "manage assets");
    Asset* asset = assets.findById(id);
    if (asset == nullptr)
        throw NotFoundException("asset #" + std::to_string(id));
    std::unique_ptr<AssetCommand> command(new RemoveAssetCommand(*asset));
    command->execute(assets);
    rememberAssetChange(std::move(command));
    Logger::info("Asset removed: #" + std::to_string(id));
}

void SecurityManager::rememberAssetChange(std::unique_ptr<AssetCommand> command) {
    assetUndo.push(std::move(command));
    while (!assetRedo.empty()) // a new change makes the old "redo" history meaningless
        assetRedo.pop();
}

void SecurityManager::editAsset(int id, const std::string& name, const std::string& ip,
                                int criticality, const std::string& extra) {
    require(current && current->canManageAssets(), "manage assets");
    Asset* asset = assets.findById(id);
    if (asset == nullptr)
        throw NotFoundException("asset #" + std::to_string(id));

    // Check everything BEFORE changing anything, so a bad edit changes nothing.
    if (name.empty() || ip.empty())
        throw ValidationException("name and IP address are required");
    if (criticality < 1 || criticality > 5)
        throw ValidationException("criticality must be between 1 and 5");
    if (assets.findIf([&](const Asset& a) { return &a != asset && (a.getName() == name || a.getIp() == ip); }))
        throw ValidationException("another device already uses that name or IP address");

    AssetSpec before = AssetSpec::of(*asset);
    AssetSpec after = before;
    after.name = name;
    after.ip = ip;
    after.criticality = criticality;
    after.extra = extra;

    std::unique_ptr<AssetCommand> command(new EditAssetCommand(id, before, after));
    command->execute(assets);
    rememberAssetChange(std::move(command));
    Logger::info("Asset changed: " + asset->describe());
}

void SecurityManager::setAssetCheck(int id, const std::string& item, bool done) {
    require(current && current->canManageAssets(), "manage assets");
    Asset* asset = assets.findById(id);
    if (asset == nullptr)
        throw NotFoundException("asset #" + std::to_string(id));
    asset->setChecked(item, done);
    Logger::info(asset->getName() + ": '" + item + "' marked " + (done ? "done" : "not done"));
}

std::string SecurityManager::undoAssetChange() {
    require(current && current->canManageAssets(), "manage assets");
    if (assetUndo.empty())
        throw ValidationException("there is nothing to undo");
    std::unique_ptr<AssetCommand> command = std::move(assetUndo.top());
    assetUndo.pop();
    command->undo(assets);
    std::string text = "Undone: " + command->describe();
    assetRedo.push(std::move(command)); // it can now be redone
    Logger::info(current->getName() + " " + text);
    return text;
}

std::string SecurityManager::redoAssetChange() {
    require(current && current->canManageAssets(), "manage assets");
    if (assetRedo.empty())
        throw ValidationException("there is nothing to redo");
    std::unique_ptr<AssetCommand> command = std::move(assetRedo.top());
    assetRedo.pop();
    command->execute(assets);
    std::string text = "Done again: " + command->describe();
    assetUndo.push(std::move(command));
    Logger::info(current->getName() + " " + text);
    return text;
}

// ---- risk per device ------------------------------------------------------------

AssetRisk SecurityManager::riskOf(const Asset& asset) const {
    AssetRisk risk(asset.getCriticality() * 6);                         // how important: up to 30

    if (auto* monitored = dynamic_cast<const Monitored*>(&asset))        // alerts: up to 30
        risk = risk + AssetRisk(std::min(monitored->getAlerts() * 10, 30));

    int openProblems = util::countIf(incidents, [&](const Incident& i) {
        return i.isOpen() && i.getAsset() == asset.getName();
    });
    risk = risk + AssetRisk(std::min(openProblems * 10, 30));            // open problems: up to 30

    return risk + AssetRisk((100 - asset.compliancePercent()) / 10);     // missing checks: up to 10
}

std::vector<AssetRiskRow> SecurityManager::riskRanking() const {
    std::vector<AssetRiskRow> rows;
    for (const Asset* asset : assets)
        rows.push_back({asset, riskOf(*asset)});
    // std::sort with AssetRisk::operator< : the riskiest device first.
    std::sort(rows.begin(), rows.end(),
              [](const AssetRiskRow& a, const AssetRiskRow& b) { return b.risk < a.risk; });
    return rows;
}

std::vector<const Asset*> SecurityManager::searchAssets(const std::string& text) const {
    std::string wanted = util::toLower(text);
    std::vector<const Asset*> found;

    // STL algorithm: copy_if keeps the assets whose name contains the text.
    std::copy_if(assets.begin(), assets.end(), std::back_inserter(found),
                 [&](const Asset* a) {
                     return util::toLower(a->getName()).find(wanted) != std::string::npos;
                 });
    // STL algorithm: sort by name using Asset::operator<.
    std::sort(found.begin(), found.end(),
              [](const Asset* a, const Asset* b) { return *a < *b; });
    return found;
}

// ---- threats ------------------------------------------------------------

// One detection = record statistics, block the source, open an incident and
// raise an alert on the asset (when the asset is Monitored).
std::string SecurityManager::recordThreat(const Threat& threat, const std::string& source) {
    ++threatStats[threat.getName()];
    blocked.insert(source);
    addIncident(threat.getName() + " detected", source, threat.getSeverity(), "scanner");
    if (threat.getSeverity() == Severity::Critical && alertHandler) // tell the screen
        alertHandler("CRITICAL: " + threat.getName() + " detected from " + source);

    Asset* target = assets.findIf([&](const Asset& a) { return a.getName() == source; });
    if (auto* monitored = dynamic_cast<Monitored*>(target)) // cross-cast to the second base
        monitored->raiseAlert();

    Logger::warn(threat.getName() + " detected from " + source);
    return "[DETECTED] " + threat.getName() + " (" + severityName(threat.getSeverity()) +
           ") from " + source + " -> " + threat.advice() +
           "\n    What is this? " + threat.explanation();
}

std::vector<std::string> SecurityManager::scan(const std::string& source, const std::string& sample) {
    require(current && current->canScan(), "run threat scans");
    if (source.empty())
        throw ValidationException("source is empty");
    if (sample.empty())
        throw ValidationException("sample text is empty");
    if (sample.size() > kMaxSampleSize)
        throw ThreatException("sample is too large to scan (limit " +
                              std::to_string(kMaxSampleSize) + " characters)");

    ScanGuard guard(source);
    std::vector<std::string> results;
    for (const Threat* t : threats) { // polymorphic call through the base class
        if (t->detect(sample))
            results.push_back(recordThreat(*t, source));
    }
    if (results.empty())
        results.push_back("[CLEAN] No threats found in sample from " + source);
    return results;
}

// Overload: scan a sample when we do not know where it came from.
std::vector<std::string> SecurityManager::scan(const std::string& sample) {
    return scan("manual-scan", sample);
}

// Overload: scan two numbers instead of text.
std::vector<std::string> SecurityManager::scan(const std::string& source, int failedLogins,
                                               int requestsPerSecond) {
    require(current && current->canScan(), "run threat scans");
    if (source.empty())
        throw ValidationException("source is empty");
    if (failedLogins < 0 || requestsPerSecond < 0)
        throw ValidationException("numbers cannot be negative");

    BruteForceThreat* bruteForce = findThreat<BruteForceThreat>();
    DDoSThreat* ddos = findThreat<DDoSThreat>();
    if (bruteForce == nullptr || ddos == nullptr)
        throw ThreatException("a required detector is not installed");

    ScanGuard guard(source);
    std::vector<std::string> results;
    if (bruteForce->detect(failedLogins)) // detect(int) overload
        results.push_back(recordThreat(*bruteForce, source));
    if (ddos->detect(requestsPerSecond))  // detect(int) overload
        results.push_back(recordThreat(*ddos, source));
    if (results.empty())
        results.push_back("[CLEAN] " + std::to_string(failedLogins) + " failed logins and " +
                          std::to_string(requestsPerSecond) + " requests/sec from " + source +
                          " are below the limits");
    return results;
}

void SecurityManager::queueSample(const std::string& source, const std::string& sample) {
    requireLogin(); // any role may submit a sample
    if (source.empty() || sample.empty())
        throw ValidationException("both source and sample are required");
    scanQueue.push({source, sample});
    Logger::info(current->getName() + " queued a sample from " + source);
}

std::vector<std::string> SecurityManager::runQueue() {
    require(current && current->canScan(), "run threat scans");
    if (scanQueue.empty())
        throw ValidationException("the scan queue is empty");

    std::vector<std::string> results;
    while (!scanQueue.empty()) { // FIFO: first submitted, first scanned
        auto job = scanQueue.front();
        scanQueue.pop();
        for (const std::string& line : scan(job.first, job.second))
            results.push_back(line);
    }
    return results;
}

// ---- link checker and Safe Box -----------------------------------------

LinkReport SecurityManager::checkLink(const std::string& url) {
    requireLogin(); // every role may check a link
    LinkReport report = linkChecker.analyze(url);
    Logger::info("Link checked: " + report.host + " -> " + report.verdict());
    if (report.verdict() == "Dangerous") {
        ++threatStats[linkChecker.getName()];
        blocked.insert(report.host);
        addIncident("Dangerous link: " + report.host, report.host, linkChecker.getSeverity(),
                    current->getName());
        Logger::warn("Dangerous link found: " + report.host);
    }
    return report;
}

Vault& SecurityManager::getVault() {
    requireLogin();
    Vault*& vault = vaults[current->getName()]; // creates an empty slot the first time
    if (vault == nullptr)
        vault = new Vault("vault_" + current->getName() + ".dat");
    return *vault;
}

// ---- incidents ----------------------------------------------------------

Incident& SecurityManager::addIncident(const std::string& title, const std::string& asset,
                                       Severity severity, const std::string& reporter) {
    incidents.emplace_back(title, asset, severity, reporter);
    Logger::info("Incident created: " + incidentSummary(incidents.back()));
    return incidents.back();
}

const Incident& SecurityManager::reportIncident(const std::string& title, const std::string& asset,
                                                Severity severity) {
    requireLogin(); // every role can report
    if (title.empty() || asset.empty())
        throw ValidationException("title and asset are required");
    if (title.find('|') != std::string::npos || asset.find('|') != std::string::npos)
        throw ValidationException("the '|' character is not allowed");
    return addIncident(title, asset, severity, current->getName());
}

Incident& SecurityManager::findIncident(int id) {
    auto it = std::find_if(incidents.begin(), incidents.end(),
                           [id](const Incident& i) { return i.getId() == id; });
    if (it == incidents.end())
        throw NotFoundException("incident INC-" + std::to_string(id));
    return *it;
}

void SecurityManager::resolveIncident(int id) {
    require(current && current->canResolve(), "resolve incidents");
    Incident& inc = findIncident(id);
    if (!inc.isOpen())
        throw ValidationException("INC-" + std::to_string(id) + " is already resolved");
    inc.resolve(current->getName());
    undoStack.push(id);
    Logger::info(current->getName() + " resolved INC-" + std::to_string(id));
}

void SecurityManager::assignIncident(int id, const std::string& username) {
    require(current && current->canResolve(), "assign incidents");
    if (!users.count(username))
        throw NotFoundException("user '" + username + "'");
    findIncident(id).assign(current->getName(), username);
    Logger::info(current->getName() + " assigned INC-" + std::to_string(id) + " to " + username);
}

std::vector<std::string> SecurityManager::timelineLines(int id) const {
    requireLogin();
    auto found = std::find_if(incidents.begin(), incidents.end(),
                              [id](const Incident& i) { return i.getId() == id; });
    if (found == incidents.end())
        throw NotFoundException("incident INC-" + std::to_string(id));

    std::vector<std::string> lines;
    for (const IncidentEvent& event : found->getEvents()) {
        std::ostringstream line;
        line << event; // operator<<
        lines.push_back(maskPrivateNames(line.str())); // employee names stay private
    }
    return lines;
}

void SecurityManager::undoResolve() {
    require(current && current->canResolve(), "resolve incidents");
    if (undoStack.empty())
        throw ValidationException("nothing to undo");
    int id = undoStack.top(); // LIFO: undo the most recent resolve first
    undoStack.pop();
    findIncident(id).reopen(current->getName());
    Logger::info(current->getName() + " re-opened INC-" + std::to_string(id));
}

std::string SecurityManager::loadSampleData() {
    require(current && current->canManageAssets(), "load sample data");

    // ---- sample devices (skipped when a device with that name or IP exists) ----
    struct SampleAsset { const char* type; const char* name; const char* ip; int level; const char* extra; };
    const SampleAsset sampleAssets[] = {
        {"Server", "mail-01", "10.0.0.30", 4, "smtp, imap"},
        {"Server", "backup-01", "10.0.0.40", 4, "nightly backups"},
        {"Router", "fw-01", "10.0.0.2", 5, "firewall"},
        {"Workstation", "ceo-laptop", "10.0.1.5", 5, "CEO"},
        {"Workstation", "reception-pc", "10.0.1.20", 2, "front desk"},
        {"Workstation", "lab-pc-07", "10.0.2.17", 1, "school lab"}};

    int addedAssets = 0;
    for (const SampleAsset& a : sampleAssets) {
        bool exists = assets.findIf([&](const Asset& x) {
            return x.getName() == a.name || x.getIp() == a.ip;
        });
        if (!exists) {
            addAsset(a.type, a.name, a.ip, a.level, a.extra);
            ++addedAssets;
        }
    }

    // ---- sample problems: a mix of sizes, some already fixed ----
    struct SampleIncident { const char* title; const char* asset; Severity severity; bool fixed; };
    const SampleIncident sampleIncidents[] = {
        {"Fake bank email reached the staff", "mail-01", Severity::High, false},
        {"Ransomware note found on a laptop", "ceo-laptop", Severity::Critical, false},
        {"Many wrong passwords on the login page", "web-01", Severity::High, true},
        {"Website slow because of too many visitors", "web-01", Severity::Critical, true},
        {"Backup job failed last night", "backup-01", Severity::Medium, false},
        {"Firewall software is out of date", "fw-01", Severity::Medium, false},
        {"USB stick plugged in without asking", "reception-pc", Severity::Low, true},
        {"Weak password found on a lab computer", "lab-pc-07", Severity::Low, false}};

    int addedIncidents = 0;
    for (const SampleIncident& s : sampleIncidents) {
        bool exists = std::any_of(incidents.begin(), incidents.end(), [&](const Incident& i) {
            return i.getTitle() == s.title && i.getAsset() == s.asset;
        });
        if (exists)
            continue;
        Incident& added = addIncident(s.title, s.asset, s.severity, "sample");
        if (s.fixed)
            added.resolve();
        ++addedIncidents;
    }

    Logger::info(current->getName() + " loaded sample data: " + std::to_string(addedAssets) +
                 " devices, " + std::to_string(addedIncidents) + " problems");
    return "Added " + std::to_string(addedAssets) + " devices and " +
           std::to_string(addedIncidents) + " problems.";
}

void SecurityManager::loadDemoIncidents() {
    addIncident("Suspicious login at night", "web-01", Severity::Medium, "system");
    addIncident("USB drive found in server room", "db-01", Severity::Low, "system");
    addIncident("Router firmware out of date", "edge-rtr", Severity::High, "system");
}

// ---- persistence --------------------------------------------------------

void SecurityManager::writeBinary(const std::string& path) const {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        throw FileException(path, "cannot open for writing");

    int count = static_cast<int>(incidents.size());
    out.write(kMagicV2, sizeof kMagicV2);
    out.write(reinterpret_cast<const char*>(&count), sizeof count);
    for (const Incident& inc : incidents)
        inc.writeBinary(out);
    if (!out)
        throw FileException(path, "write failed (disk full?)");
}

void SecurityManager::readBinary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw FileException(path, "file does not exist or cannot be opened");

    char magic[4];
    int count = 0;
    if (!in.read(magic, sizeof magic))
        throw FileException(path, "not a Cyber Shield data file");
    bool hasTimeline = std::equal(magic, magic + 4, kMagicV2);
    if (!hasTimeline && !std::equal(magic, magic + 4, kMagicV1))
        throw FileException(path, "not a Cyber Shield data file");
    if (!in.read(reinterpret_cast<char*>(&count), sizeof count) || count < 0)
        throw FileException(path, "corrupt header");

    std::list<Incident> loaded; // load fully first, so a bad file changes nothing
    try {
        for (int i = 0; i < count; ++i)
            loaded.push_back(Incident::readBinary(in, hasTimeline));
    } catch (const CyberException& e) {
        throw FileException(path, std::string("corrupt record: ") + e.what());
    }
    incidents.swap(loaded);
    undoStack = std::stack<int>();
}

void SecurityManager::saveIncidents(const std::string& path) const {
    requireLogin();
    writeBinary(path);
    Logger::info(current->getName() + " saved " + std::to_string(incidents.size()) +
                 " incidents to " + path);
}

void SecurityManager::loadIncidents(const std::string& path) {
    require(current && current->canManageUsers(), "load incident data");
    readBinary(path);
    Logger::info(current->getName() + " loaded " + std::to_string(incidents.size()) +
                 " incidents from " + path);
}

void SecurityManager::exportIncidents(const std::string& path) const {
    requireLogin();
    std::ofstream out(path);
    if (!out)
        throw FileException(path, "cannot open for writing");
    for (const Incident& inc : incidents)
        out << inc << '\n'; // operator<<
    if (!out)
        throw FileException(path, "write failed");
    Logger::info("Exported incidents to " + path);
}

void SecurityManager::importIncidents(const std::string& path) {
    require(current && current->canManageUsers(), "import incident data");
    std::ifstream in(path);
    if (!in)
        throw FileException(path, "file does not exist or cannot be opened");

    std::list<Incident> loaded;
    Incident inc;
    int line = 0;
    while (in.peek() != EOF) {
        ++line;
        if (!(in >> inc)) // operator>>
            throw FileException(path, "malformed data on line " + std::to_string(line));
        loaded.push_back(inc);
    }
    incidents.swap(loaded);
    undoStack = std::stack<int>();
    Logger::info(current->getName() + " imported " + std::to_string(incidents.size()) +
                 " incidents from " + path);
}

bool SecurityManager::autoLoad(const std::string& path) {
    try {
        readBinary(path);
        Logger::info("Restored " + std::to_string(incidents.size()) + " incidents from " + path);
        return true;
    } catch (const FileException& e) {
        Logger::warn(std::string("Starting with no saved incidents. ") + e.what());
        return false;
    }
}

void SecurityManager::autoSave(const std::string& path) const {
    try {
        writeBinary(path);
    } catch (const FileException& e) {
        Logger::error(e.what());
    }
}

// ---- statistics and reporting ------------------------------------------

DashboardStats SecurityManager::getStats() const {
    DashboardStats stats;
    stats.assets = static_cast<int>(assets.size());
    // Function template util::countIf works on any container.
    stats.openIncidents = util::countIf(incidents, [](const Incident& i) { return i.isOpen(); });
    for (const Incident& inc : incidents) {
        if (!inc.isOpen())
            continue;
        stats.openBySeverity.add(inc.getSeverity());
        stats.risk = stats.risk + RiskScore::forSeverity(inc.getSeverity()); // operator+
    }
    for (const auto& entry : threatStats)
        stats.threatsDetected += entry.second;
    return stats;
}

std::string SecurityManager::buildReport() const {
    return ReportWriter::build(*this);
}

void SecurityManager::saveReport(const std::string& path) const {
    requireLogin();
    std::ofstream out(path);
    if (!out)
        throw FileException(path, "cannot open for writing");
    out << buildReport();
    if (!out)
        throw FileException(path, "write failed");
    Logger::info(current->getName() + " saved the report to " + path);
}

std::string SecurityManager::readLog() const {
    requireLogin();
    return maskPrivateNames(Logger::readAll()); // employee names stay private
}

AuditView SecurityManager::auditView(const std::string& level, const std::string& text) const {
    requireLogin();
    AuditTrail trail = AuditTrail::fromFile(Logger::file());

    AuditView view;
    view.levelCounts = trail.countByLevel();
    view.total = static_cast<int>(trail.all().size());

    std::string wanted = util::toLower(util::trim(text));
    for (AuditEntry entry : trail.filter(level, "")) {
        entry.message = maskPrivateNames(entry.message); // employee names stay private
        if (wanted.empty() || util::toLower(entry.message).find(wanted) != std::string::npos)
            view.entries.push_back(entry);
    }
    return view;
}

LogReport SecurityManager::analyzeLogFile(const std::string& path, bool createProblems) {
    require(current && current->canScan(), "analyze log files");
    LogReport report = LogAnalyzer().analyzeFile(path);
    Logger::info(current->getName() + " analyzed log file " + path + ": " +
                 std::to_string(report.findings.size()) + " suspicious lines");

    if (createProblems) {
        for (const auto& entry : report.byCategory) {
            if (entry.second < 3)
                continue; // one or two odd lines are not a problem yet
            std::string where = "log file";
            for (const LogFinding& f : report.findings)
                if (f.category == entry.first && !f.source.empty()) {
                    where = f.source; // the first address that caused it
                    break;
                }
            Severity severity = entry.first == "Dangerous command" ? Severity::Critical : Severity::High;
            addIncident("Log analysis: " + std::to_string(entry.second) + " lines of " + entry.first,
                        where, severity, current->getName());
        }
    }
    return report;
}

} // namespace cyber
