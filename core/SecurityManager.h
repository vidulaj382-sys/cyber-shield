#pragma once
// Facade over the core: the GUI talks only to this class.
// Role checks, validation and logging all happen here, never in the GUI.
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <stack>
#include <string>
#include <utility>
#include <vector>

#include "Admin.h"
#include "AssetCommand.h"
#include "AssetRisk.h"
#include "AuditTrail.h"
#include "Asset.h"
#include "Employee.h"
#include "Incident.h"
#include "LinkThreat.h"
#include "LogAnalyzer.h"
#include "Password.h"
#include "Person.h"
#include "Repository.h"
#include "RiskScore.h"
#include "SeverityCounts.h"
#include "Threat.h"
#include "Vault.h"

namespace cyber {

// Numbers shown on the dashboard.
struct DashboardStats {
    int assets = 0;
    int openIncidents = 0;
    int threatsDetected = 0;
    RiskScore risk;
    SeverityCounts openBySeverity; // copied by value -> uses the copy constructor
};

// One device with its risk (used to rank devices and draw the network map).
struct AssetRiskRow {
    const Asset* asset;
    AssetRisk risk;
};

// What the History page shows: the filtered lines plus counters.
struct AuditView {
    std::vector<AuditEntry> entries;        // after the filters
    std::map<std::string, int> levelCounts; // over the whole log: {"INFO": 120, "WARN": 4}
    int total = 0;                          // lines in the whole log
};

class SecurityManager {
public:
    SecurityManager();
    ~SecurityManager();

    // The manager owns raw pointers, so copying it would double-delete.
    SecurityManager(const SecurityManager&) = delete;
    SecurityManager& operator=(const SecurityManager&) = delete;

    // ---- authentication -------------------------------------------------
    Person* login(const std::string& username, const std::string& password);
    void logout();
    Person* currentUser() const { return current; }

    // ---- users (Admin only) --------------------------------------------
    void addUser(const std::string& username, const std::string& password,
                 const std::string& role);
    void removeUser(const std::string& username);
    std::vector<const Person*> listUsers() const;
    // The name to SHOW for a user name: the real one for yourself, the private
    // form (e******e) for employees you are not.
    std::string displayName(const std::string& username) const;
    int problemsReportedBy(const std::string& username) const;

    // ---- assets (function overloading) ---------------------------------
    Asset& addAsset(Asset* asset); // takes ownership
    Asset& addAsset(const std::string& name, const std::string& ip, int criticality);
    Asset& addAsset(const std::string& name, const std::string& ip, int criticality,
                    const std::string& services);
    Asset& addAsset(const std::string& type, const std::string& name, const std::string& ip,
                    int criticality, const std::string& extra);
    void removeAsset(int id);
    void editAsset(int id, const std::string& name, const std::string& ip, int criticality,
                   const std::string& extra);
    void setAssetCheck(int id, const std::string& item, bool done); // the security checklist

    // Undo / redo of device changes (two stacks of command objects).
    std::string undoAssetChange();
    std::string redoAssetChange();
    bool canUndoAssetChange() const { return !assetUndo.empty(); }
    bool canRedoAssetChange() const { return !assetRedo.empty(); }

    // Risk of one device, and all devices from the riskiest to the safest.
    AssetRisk riskOf(const Asset& asset) const;
    std::vector<AssetRiskRow> riskRanking() const;
    const Repository<Asset>& getAssets() const { return assets; }
    std::vector<const Asset*> searchAssets(const std::string& text) const;

    // ---- threats (function overloading: three scan() versions) ----------
    std::vector<std::string> scan(const std::string& source, const std::string& sample);
    std::vector<std::string> scan(const std::string& sample);
    std::vector<std::string> scan(const std::string& source, int failedLogins,
                                  int requestsPerSecond);

    void queueSample(const std::string& source, const std::string& sample);
    std::vector<std::string> runQueue();
    std::size_t pendingScans() const { return scanQueue.size(); }

    // ---- link checker (any role) -----------------------------------------
    LinkReport checkLink(const std::string& url);

    // ---- Safe Box: one vault per user ------------------------------------
    Vault& getVault();

    // ---- incidents ------------------------------------------------------
    const Incident& reportIncident(const std::string& title, const std::string& asset,
                                   Severity severity);
    void resolveIncident(int id);
    void assignIncident(int id, const std::string& username);
    std::vector<std::string> timelineLines(int id) const; // the incident's timeline, as text
    void undoResolve();
    bool canUndo() const { return !undoStack.empty(); }
    const std::list<Incident>& getIncidents() const { return incidents; }
    void loadDemoIncidents(); // sample data for the very first start

    // Adds a realistic set of sample devices and problems (Admin only).
    // Items that already exist are skipped, so pressing it twice is harmless.
    // Returns a short sentence such as "Added 5 devices and 8 problems."
    std::string loadSampleData();

    // ---- persistence ----------------------------------------------------
    void saveIncidents(const std::string& path) const;   // binary
    void loadIncidents(const std::string& path);         // binary, Admin only
    void exportIncidents(const std::string& path) const; // text via operator<<
    void importIncidents(const std::string& path);       // text via operator>>, Admin only
    bool autoLoad(const std::string& path);              // startup, never throws
    void autoSave(const std::string& path) const;        // shutdown, never throws

    // ---- reporting ------------------------------------------------------
    DashboardStats getStats() const;
    std::string buildReport() const;
    void saveReport(const std::string& path) const;
    std::string readLog() const;
    AuditView auditView(const std::string& level, const std::string& text) const;

    // Reads any log file and reports suspicious lines (Admin only).
    // With createProblems = true, every kind of finding also becomes a problem.
    LogReport analyzeLogFile(const std::string& path, bool createProblems);

    // Called whenever a CRITICAL threat is detected, so the screen can warn the user.
    void setAlertHandler(std::function<void(const std::string&)> handler) { alertHandler = handler; }
    const std::set<std::string>& getBlockedSources() const { return blocked; }

private:
    // The report printer is a friend CLASS: it may read the private data.
    friend class ReportWriter;

    std::string maskPrivateNames(const std::string& text) const;
    void requireLogin() const;
    void require(bool allowed, const std::string& action) const;
    Person* makeUser(const std::string& username, const std::string& password,
                     const std::string& role) const;
    Incident& addIncident(const std::string& title, const std::string& asset,
                          Severity severity, const std::string& reporter);
    Incident& findIncident(int id);
    void rememberAssetChange(std::unique_ptr<AssetCommand> command);
    std::string recordThreat(const Threat& threat, const std::string& source);
    void writeBinary(const std::string& path) const;
    void readBinary(const std::string& path);

    // Function template member: finds the detector of one concrete type
    // (a DOWNCAST from Threat* to T* using dynamic_cast).
    template <typename T>
    T* findThreat() const {
        for (Threat* t : threats)
            if (T* match = dynamic_cast<T*>(t))
                return match;
        return nullptr;
    }

    Repository<Asset> assets;                                  // owns Asset objects
    std::map<std::string, Person*> users;                      // username -> user
    std::vector<Threat*> threats;                              // upcast detectors
    LinkThreat linkChecker;                                    // checks links on demand
    std::map<std::string, Vault*> vaults;                      // username -> Safe Box
    std::list<Incident> incidents;
    std::set<std::string> blocked;                             // locked accounts / sources
    std::stack<std::unique_ptr<AssetCommand>> assetUndo;      // device changes that can be undone
    std::stack<std::unique_ptr<AssetCommand>> assetRedo;      // ... and redone
    std::function<void(const std::string&)> alertHandler;
    std::stack<int> undoStack;                                 // ids of resolved incidents
    std::queue<std::pair<std::string, std::string>> scanQueue; // (source, sample)
    std::map<std::string, int> failedLogins;
    std::map<std::string, int> threatStats;                    // threat name -> detections
    Person* current = nullptr;
};

} // namespace cyber
