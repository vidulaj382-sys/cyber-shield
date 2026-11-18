// Tiny console tests for the core (no framework, plain asserts).
// Build and run with:  sh build.sh   (it compiles and runs these tests too)
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>
#include <iostream>
#include <iterator>
#include <string>

#include "../core/Logger.h"
#include "../core/XorCipher.h"
#include "../core/PasswordEntry.h"
#include "../core/SecurityOfficer.h"
#include "../core/SecurityManager.h"

using namespace cyber;

// Runs one test function and prints its name.
#define RUN(test)                          \
    do {                                   \
        test();                            \
        std::cout << "  ok  " #test "\n";  \
    } while (0)

// True when 'action' throws an exception of type E.
template <typename E, typename F>
bool throwsError(F action) {
    try {
        action();
    } catch (const E&) {
        return true;
    }
    return false;
}

// ---- login ----------------------------------------------------------------
void testLogin() {
    SecurityManager m;
    assert(m.currentUser() == nullptr);

    Person* admin = m.login("admin", "admin123");
    assert(admin->roleName() == "Admin");
    m.logout();
    assert(m.login("employee", "emp123")->roleName() == "Employee");
    m.logout();

    assert(throwsError<AuthException>([&] { m.login("admin", "wrong"); }));
    assert(throwsError<ValidationException>([&] { m.login("", ""); }));
    assert(throwsError<AuthException>([&] { m.login("nobody", "x"); }));
}

void testBruteForceLocksAccount() {
    SecurityManager m;
    for (int i = 0; i < 5; ++i)
        assert(throwsError<AuthException>([&] { m.login("admin", "bad"); }));
    // Even the correct password is refused now, and an incident was opened.
    assert(throwsError<AuthException>([&] { m.login("admin", "admin123"); }));
    assert(m.getIncidents().size() == 1);
}

void testRolePermissions() {
    SecurityManager m;
    m.login("employee", "emp123");
    assert(throwsError<AccessDeniedException>([&] { m.addAsset("pc", "1.2.3.4", 2); }));
    assert(throwsError<AccessDeniedException>([&] { m.scan("web-01", "trojan"); }));
    assert(throwsError<AccessDeniedException>([&] { m.addUser("bob", "pass", "Employee"); }));
    m.reportIncident("Lost badge", "office", Severity::Low); // everyone may report
    m.logout();

    m.login("admin", "admin123");
    m.addAsset("pc", "1.2.3.4", 2);
    m.addAsset("Router", "gw-02", "10.9.9.9", 4, "fibre");
    assert(m.getAssets().size() == 6);
}

void testDuplicateAssetRejected() {
    SecurityManager m;
    m.login("admin", "admin123");
    assert(throwsError<ValidationException>([&] { m.addAsset("web-01", "9.9.9.9", 3); }));
    assert(throwsError<ValidationException>([&] { m.addAsset("new", "10.0.0.10", 3); })); // same IP
    assert(throwsError<ValidationException>([&] { m.addAsset("x", "1.1.1.1", 9); }));      // bad criticality
}

void testSearchAssets() {
    SecurityManager m;
    m.login("employee", "emp123");
    assert(m.searchAssets("").size() == 4);
    assert(m.searchAssets("WEB").size() == 1); // case-insensitive
    assert(m.searchAssets("zzz").empty());
}

void testUserManagement() {
    SecurityManager m;
    m.login("admin", "admin123");
    m.addUser("eve", "Secret123", "Employee");
    assert(m.listUsers().size() == 3);
    assert(throwsError<ValidationException>([&] { m.addUser("zed", "Secret123", "Analyst"); })); // no such role
    assert(throwsError<ValidationException>([&] { m.addUser("eve", "Secret123", "Admin"); }));
    assert(throwsError<ValidationException>([&] { m.addUser("tom", "abc", "Admin"); }));
    assert(throwsError<ValidationException>([&] { m.removeUser("admin"); })); // not yourself
    m.removeUser("eve");
    assert(m.listUsers().size() == 2);
    m.logout();
    assert(m.login("employee", "emp123")->roleName() == "Employee");
}

void testDiamondInheritance() {
    SecurityOfficer officer("sam", "pw12");
    Person* person = &officer;                       // upcast
    assert(dynamic_cast<Employee*>(person) != nullptr); // downcast to one parent
    assert(dynamic_cast<Admin*>(person) != nullptr);    // ...and to the other
    assert(person->roleName() == "Security Officer");
    assert(person->canScan() && !person->canManageAssets());
    assert(person->checkPassword("pw12") && !person->checkPassword("PW12"));
}

// ---- threat detection ----------------------------------------------------
void testThreatDetection() {
    MalwareThreat malware;
    PhishingThreat phishing;
    BruteForceThreat bruteForce(3);
    DDoSThreat ddos(500);

    assert(malware.detect("Attachment invoice.exe.zip"));
    assert(malware.detect("beacon to 185.220.101.1"));
    assert(!malware.detect("hello world"));

    assert(phishing.detect("URGENT click here to verify your account"));
    assert(!phishing.detect("urgent meeting at 3pm")); // only one keyword

    assert(bruteForce.detect(3) && !bruteForce.detect(2));
    assert(bruteForce.detect(std::string("FAILED login\nFAILED login\nFAILED login")));

    assert(ddos.detect(500) && !ddos.detect(499));
    assert(ddos.detect(std::string("SYN flood from 9.9.9.9")));
}

void testScanCreatesIncidents() {
    SecurityManager m;
    m.login("admin", "admin123");

    auto clean = m.scan("web-01", "nothing to see");
    assert(clean[0].find("[CLEAN]") == 0);
    assert(m.getIncidents().empty());

    auto hit = m.scan("web-01", "trojan found, urgent: click here http://x");
    assert(hit.size() == 2); // malware + phishing
    assert(m.getIncidents().size() == 2);

    auto numbers = m.scan("edge-rtr", 9, 5000); // brute force + DDoS
    assert(numbers.size() == 2);
    assert(m.getIncidents().size() == 4);
    assert(m.getStats().threatsDetected == 4);

    assert(m.scan("some text").size() == 1); // single-argument overload
    assert(throwsError<ValidationException>([&] { m.scan("web-01", ""); }));
    assert(throwsError<ValidationException>([&] { m.scan("web-01", -1, 0); }));
    assert(throwsError<ThreatException>([&] { m.scan("web-01", std::string(20000, 'a')); }));
}

void testScanQueue() {
    SecurityManager m;
    m.login("admin", "admin123");
    m.queueSample("pc-1", "ransomware note");
    m.queueSample("pc-2", "hello");
    assert(m.pendingScans() == 2);
    auto results = m.runQueue();
    assert(results.size() == 2);
    assert(m.pendingScans() == 0);
    assert(throwsError<ValidationException>([&] { m.runQueue(); })); // empty queue
}

// ---- incidents ---------------------------------------------------------
void testResolveAndUndo() {
    SecurityManager m;
    m.login("admin", "admin123");
    int first = m.reportIncident("First", "web-01", Severity::High).getId();
    int second = m.reportIncident("Second", "db-01", Severity::Low).getId();

    m.resolveIncident(first);
    m.resolveIncident(second);
    assert(m.getStats().openIncidents == 0);

    m.undoResolve(); // undoes the LAST resolve first (stack)
    assert(m.getStats().openIncidents == 1);
    assert(m.getIncidents().back().isOpen());

    m.undoResolve();
    assert(m.getStats().openIncidents == 2);
    assert(!m.canUndo());
    assert(throwsError<ValidationException>([&] { m.undoResolve(); }));
    assert(throwsError<NotFoundException>([&] { m.resolveIncident(9999); }));
}

void testRiskScoreAndStats() {
    SecurityManager m;
    m.login("admin", "admin123");
    m.reportIncident("A", "web-01", Severity::Critical);
    m.reportIncident("B", "web-01", Severity::Low);
    DashboardStats stats = m.getStats();
    assert(stats.risk.getPoints() == 11); // 10 + 1, added with operator+
    assert(stats.openBySeverity.count(Severity::Critical) == 1);

    DashboardStats copy = stats; // copy constructor of SeverityCounts
    stats.openBySeverity.add(Severity::Critical);
    assert(copy.openBySeverity.count(Severity::Critical) == 1); // deep copy
    assert(RiskScore(100).percent() == 100);                    // capped
}

// ---- files -------------------------------------------------------------
void testBinarySaveLoadRoundTrip() {
    const char* file = "test_incidents.dat";
    SecurityManager m;
    m.login("admin", "admin123");
    m.reportIncident("Disk failure", "db-01", Severity::High);
    int id = m.reportIncident("Phish report", "hr-laptop", Severity::Medium).getId();
    m.resolveIncident(id);
    m.saveIncidents(file);

    SecurityManager other;
    other.login("admin", "admin123");
    other.loadIncidents(file);
    assert(other.getIncidents().size() == 2);
    assert(other.getIncidents().front().getTitle() == "Disk failure");
    assert(!other.getIncidents().back().isOpen());
    std::remove(file);
}

void testTextExportImportRoundTrip() {
    const char* file = "test_incidents.txt";
    SecurityManager m;
    m.login("admin", "admin123");
    m.reportIncident("Port scan", "edge-rtr", Severity::Medium);
    m.exportIncidents(file);

    SecurityManager other;
    other.login("admin", "admin123");
    other.importIncidents(file);
    assert(other.getIncidents().size() == 1);
    assert(other.getIncidents().front().getAsset() == "edge-rtr");
    std::remove(file);
}

void testFileErrors() {
    SecurityManager m;
    m.login("admin", "admin123");
    assert(throwsError<FileException>([&] { m.loadIncidents("does_not_exist.dat"); }));
    assert(throwsError<FileException>([&] { m.importIncidents("does_not_exist.txt"); }));

    // A corrupt binary file must be refused and must not change anything.
    const char* bad = "test_corrupt.dat";
    {
        std::ofstream out(bad, std::ios::binary);
        out << "this is not a cyber shield file";
    }
    m.reportIncident("keep me", "web-01", Severity::Low);
    assert(throwsError<FileException>([&] { m.loadIncidents(bad); }));
    assert(m.getIncidents().size() == 1);

    // A truncated file (valid header, missing records) is corrupt too.
    m.saveIncidents(bad);
    {
        std::ifstream in(bad, std::ios::binary);
        std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::ofstream out(bad, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size() / 2));
    }
    assert(throwsError<FileException>([&] { m.loadIncidents(bad); }));
    std::remove(bad);

    // A malformed text line is refused.
    const char* badText = "test_bad.txt";
    {
        std::ofstream out(badText);
        out << "not|enough|fields\n";
    }
    assert(throwsError<FileException>([&] { m.importIncidents(badText); }));
    std::remove(badText);
}

void testReportAndLog() {
    SecurityManager m;
    m.login("admin", "admin123");
    std::string report = m.buildReport();
    assert(report.find("SECURITY REPORT") != std::string::npos);
    assert(report.find("USER ACCOUNTS") != std::string::npos); // admin-only section
    m.saveReport("test_report.txt");
    std::remove("test_report.txt");
    assert(m.readLog().find("admin") != std::string::npos);
    m.logout();
    m.login("employee", "emp123");
    assert(m.buildReport().find("USER ACCOUNTS") == std::string::npos);
}

// ---- link checker ------------------------------------------------------
void testLinkChecker() {
    LinkThreat checker;
    assert(checker.analyze("https://www.wikipedia.org/wiki/Cat").verdict() == "Safe");
    assert(checker.analyze("http://example.com").verdict() == "Suspicious");        // only http
    assert(checker.analyze("http://192.168.4.4/login").verdict() == "Dangerous");   // IP + words
    assert(checker.analyze("https://bit.ly/abc").verdict() == "Suspicious");        // shortener
    assert(checker.analyze("https://evil.example/").verdict() == "Dangerous");      // known bad site
    assert(checker.analyze("https://mybank.com@scam.xyz/verify").verdict() == "Dangerous");
    assert(checker.analyze("HTTPS://Evil.Example/").host == "evil.example");        // not case sensitive
    assert(checker.detect("http://free-prizes-bank-login.top/verify"));
    assert(!checker.detect("https://www.google.com"));

    assert(throwsError<ValidationException>([&] { checker.analyze(""); }));
    assert(throwsError<ValidationException>([&] { checker.analyze("not a link"); }));
    assert(throwsError<ValidationException>([&] { checker.analyze("hello"); }));
}

void testCheckLinkCreatesIncident() {
    SecurityManager m;
    assert(throwsError<AuthException>([&] { m.checkLink("https://google.com"); })); // login needed
    m.login("employee", "emp123"); // every role may check links
    assert(m.checkLink("https://www.google.com").verdict() == "Safe");
    assert(m.getIncidents().empty());
    assert(m.checkLink("http://45.155.205.233/free-gift/login").verdict() == "Dangerous");
    assert(m.getIncidents().size() == 1);
    assert(m.getStats().threatsDetected == 1);
}

// ---- Safe Box ------------------------------------------------------------
void testCipherRoundTrip() {
    XorCipher xorCipher("key123");
    std::string secret = xorCipher.encrypt("my diary");
    assert(secret != "my diary");
    assert(xorCipher.decrypt(secret) == "my diary");
    assert(XorCipher("wrong").decrypt(secret) != "my diary");
}

void testPasswordTools() {
    assert(PasswordEntry::strength("abc") == "Weak");
    assert(PasswordEntry::strength("Sunny2024") == "OK");
    assert(PasswordEntry::strength("Tr0ub4dor&3xyz") == "Strong");
    std::string generated = PasswordEntry::generate(14);
    assert(generated.size() == 14);
    assert(PasswordEntry::strength(generated) != "Weak");
    assert(throwsError<ValidationException>([&] { PasswordEntry::generate(3); }));
}

void testVaultLockAndUnlock() {
    const char* file = "test_vault.dat";
    std::remove(file);
    {
        Vault vault(file);
        assert(!vault.exists());
        assert(throwsError<VaultLockedException>([&] { vault.items(); }));
        assert(throwsError<ValidationException>([&] { vault.create("abc"); })); // too short

        vault.create("open-sesame");
        assert(vault.isUnlocked() && vault.exists());
        vault.addNote("Diary", "I like cats");
        vault.addPassword("mail.example", "sam", "Zebra!2024xx");
        assert(vault.items().size() == 2);
        assert(throwsError<ValidationException>([&] { vault.create("again1"); })); // already exists

        vault.lock();
        assert(!vault.isUnlocked());
        assert(throwsError<VaultLockedException>([&] { vault.addNote("x", "y"); }));
    }

    // A brand new object (like restarting the app) can unlock the saved file.
    Vault again(file);
    assert(throwsError<AuthException>([&] { again.unlock("wrong-one"); }));
    assert(!again.isUnlocked());
    again.unlock("open-sesame");
    assert(again.items().size() == 2);
    assert(again.items()[1]->detail(true).find("Zebra!2024xx") != std::string::npos);
    assert(again.items()[1]->detail(false).find("Zebra") == std::string::npos); // hidden

    int firstId = again.items()[0]->getId();
    again.removeItem(firstId);
    assert(again.items().size() == 1);
    assert(throwsError<NotFoundException>([&] { again.removeItem(firstId); }));
    again.lock();

    // The file itself must not contain readable secrets.
    std::ifstream in(file, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    assert(bytes.find("Zebra") == std::string::npos);
    assert(bytes.find("mail.example") == std::string::npos);
    in.close();
    std::remove(file);
}

void testVaultCorruptFile() {
    const char* file = "test_vault_bad.dat";
    {
        std::ofstream out(file, std::ios::binary);
        out << "garbage garbage garbage";
    }
    Vault vault(file);
    assert(throwsError<FileException>([&] { vault.unlock("whatever"); }));

    // Cut a good file in half: it must be refused, not crash.
    std::remove(file);
    {
        Vault good(file);
        good.create("pass1234");
        good.addNote("A", "B");
    }
    std::string content;
    {
        std::ifstream in(file, std::ios::binary);
        content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size() / 2));
    }
    Vault damaged(file);
    assert(throwsError<FileException>([&] { damaged.unlock("pass1234"); }));
    assert(throwsError<FileException>([&] { Vault("no_such_vault.dat").unlock("pass1234"); }));
    std::remove(file);
}

void testManagerVaultLocksOnLogout() {
    SecurityManager m;
    assert(throwsError<AuthException>([&] { m.getVault(); }));
    m.login("employee", "emp123");
    Vault& vault = m.getVault();
    std::remove("vault_employee.dat");
    vault.create("my-secret");
    assert(vault.isUnlocked());
    m.logout();
    assert(!vault.isUnlocked()); // logging out locks the Safe Box
    std::remove("vault_employee.dat");
}

void testLoadSampleData() {
    SecurityManager m;
    m.login("employee", "emp123");
    assert(throwsError<AccessDeniedException>([&] { m.loadSampleData(); })); // Admin only
    m.logout();

    m.login("admin", "admin123");
    std::string message = m.loadSampleData();
    assert(message == "Added 6 devices and 8 problems.");
    assert(m.getAssets().size() == 10);       // 4 original + 6 sample
    assert(m.getIncidents().size() == 8);
    DashboardStats stats = m.getStats();
    assert(stats.openIncidents == 5);          // 3 of the samples are already fixed
    assert(stats.openBySeverity.count(Severity::Critical) == 1);

    // Pressing it again must not create duplicates.
    assert(m.loadSampleData() == "Added 0 devices and 0 problems.");
    assert(m.getIncidents().size() == 8);
}

// The files in sample_data/ must really behave as the README there says.
void testSampleDataFiles() {
    SecurityManager m;
    m.login("admin", "admin123");
    m.importIncidents("sample_data/incidents.txt");
    assert(m.getIncidents().size() == 8);
    assert(m.getStats().openIncidents == 5);

    // threat_samples.txt
    SecurityManager s;
    s.login("admin", "admin123");
    assert(s.scan("pc", "Please open invoice_march.exe.zip from the finance team")[0].find("Malware") != std::string::npos);
    assert(s.scan("pc", "Your password has been suspended. Login now to keep your bank account")[0].find("Phishing") != std::string::npos);
    assert(s.scan("pc", "Dear user, it is urgent: click here to verify your account")[0].find("Phishing") != std::string::npos);
    assert(s.scan("pc", "login FAILED for admin\nlogin FAILED for admin\nlogin FAILED for admin\nlogin FAILED for admin\nlogin FAILED for admin")[0].find("Brute") != std::string::npos);
    assert(s.scan("pc", "massive SYN flood detected")[0].find("DDoS") != std::string::npos);
    assert(s.scan("pc", "Hello team, the meeting is at 3pm in room 12.")[0].find("[CLEAN]") == 0);
    assert(s.scan("pc", 7, 2500).size() == 2);

    // links.txt
    LinkThreat checker;
    for (const char* url : {"https://www.wikipedia.org/wiki/Cat", "https://www.google.com",
                            "https://github.com/torvalds/linux"})
        assert(checker.analyze(url).verdict() == "Safe");
    for (const char* url : {"http://example.com", "https://bit.ly/my-new-game",
                            "https://cool-site.xyz/home"})
        assert(checker.analyze(url).verdict() == "Suspicious");
    for (const char* url : {"http://185.220.101.1/verify-your-bank-account/login",
                            "https://mybank.com@scam.xyz/verify", "https://evil.example/free-gift",
                            "http://free-prizes-bank-login.top/verify/account"})
        assert(checker.analyze(url).verdict() == "Dangerous");
}

// ---- privacy: employees are hidden from the admin ------------------------
void testEmployeeNamesArePrivate() {
    assert(util::maskName("employee") == "e******e");
    assert(util::maskName("al") == "**");
    assert(util::replaceWord("employee (Employee) said employee-pc", "employee", "e******e") ==
           "e******e (Employee) said e******e-pc"); // whole words only; capital E is another word
    assert(util::replaceWord("remployee employeeX", "employee", "?") == "remployee employeeX");

    Employee sam("samantha", "pw12");
    assert(sam.nameForOthers() == "s******a"); // virtual: the Employee version runs
    Admin boss("boss", "pw12");
    assert(boss.nameForOthers() == "boss");     // admins are shown normally

    SecurityManager m;
    m.login("employee", "emp123");
    m.reportIncident("Lost badge", "office", Severity::Low);
    assert(m.displayName("employee") == "employee"); // you see your own name
    assert(m.displayName("admin") == "admin");
    m.logout();

    m.login("admin", "admin123");
    assert(m.displayName("employee") == "e******e"); // the admin does not
    assert(m.displayName("scanner") == "scanner");   // system names are not people
    assert(m.problemsReportedBy("employee") == 1);

    std::string report = m.buildReport();
    assert(report.find("USER ACCOUNTS") != std::string::npos);
    assert(report.find("e******e (Employee)") != std::string::npos);
    assert(report.find("employee (") == std::string::npos);   // real name never printed
    assert(report.find("by employee") == std::string::npos);  // not in the problem list either
    assert(report.find("by e******e") != std::string::npos);

    std::string log = m.readLog();
    assert(log.find("e******e") != std::string::npos);
    assert(log.find("employee logged in") == std::string::npos);
    m.logout();

    m.login("employee", "emp123"); // ...but the employee sees their own name in the log
    assert(m.readLog().find("employee") != std::string::npos);
}

// ---- the new features --------------------------------------------------------
void testPasswordClass() {
    Password weak("abc"), ok("Sunny2024"), strong("Tr0ub4dor&3xyz");
    assert(weak.rating() == "Weak" && ok.rating() == "OK" && strong.rating() == "Strong");
    assert(weak < ok && ok < strong && !(strong < weak)); // operator<
    assert(weak == Password("abc") && !(weak == ok));     // operator==
    assert((ok + "!").text() == "Sunny2024!");            // operator+
    assert(Password("password1").rating() == "Weak");     // very common
    assert(Password("aaaaaaaaaaaa").rating() == "Weak");  // one repeated letter
    assert(Password("").tip().find("Type") == 0);
    assert(Password("Abcdefgh1").tip().find("symbol") != std::string::npos);

    std::ostringstream out;
    out << strong;
    assert(out.str().find("Tr0ub") == std::string::npos && out.str().find("Strong") != std::string::npos);

    SecurityManager m; // creating a user with a weak password is refused, with a tip
    m.login("admin", "admin123");
    assert(throwsError<ValidationException>([&] { m.addUser("bob", "abc", "Employee"); }));
    m.addUser("bob", "Blue#Sky2024", "Employee");
}

void testHexHelpers() {
    bool ok = false;
    assert(util::toHex("Hi") == "4869");
    assert(util::fromHex("4869", ok) == "Hi" && ok);
    util::fromHex("48z9", ok);
    assert(!ok);
    util::fromHex("486", ok);
    assert(!ok);
}

void testAssetRiskAndChecklist() {
    SecurityManager m;
    m.login("admin", "admin123");

    Asset* laptop = nullptr;
    for (const Asset* a : m.getAssets())
        if (a->getName() == "hr-laptop")
            laptop = const_cast<Asset*>(a);
    assert(laptop != nullptr);
    int base = m.riskOf(*laptop).percent(); // level 2 -> 12, nothing checked -> +10 = 22
    assert(base == 22);

    // Ticking the checklist lowers the risk and raises compliance.
    for (const std::string& item : Asset::checklistItems())
        m.setAssetCheck(laptop->getId(), item, true);
    assert(laptop->compliancePercent() == 100);
    assert(m.riskOf(*laptop).percent() == 12);
    m.setAssetCheck(laptop->getId(), "Firewall is on", false);
    assert(laptop->compliancePercent() == 83);
    assert(throwsError<ValidationException>([&] { m.setAssetCheck(laptop->getId(), "Wear a hat", true); }));

    // Open problems on the device raise its risk.
    m.reportIncident("Odd popups", "hr-laptop", Severity::Low);
    assert(m.riskOf(*laptop).percent() > 12);

    // Ranking: riskiest first, using operator< and std::sort.
    std::vector<AssetRiskRow> ranking = m.riskRanking();
    assert(ranking.size() == m.getAssets().size());
    for (std::size_t i = 1; i < ranking.size(); ++i)
        assert(!(ranking[i - 1].risk < ranking[i].risk));
    assert(ranking.front().asset->getName() == "web-01" || ranking.front().asset->getName() == "db-01");

    AssetRisk sum = AssetRisk(40) + AssetRisk(70); // operator+ is capped at 100%
    assert(sum.percent() == 100 && sum.level() == "Critical");
    assert(AssetRisk(10) < AssetRisk(30));
    assert(AssetRisk(10).level() == "Low" && AssetRisk(30).level() == "Medium");
}

void testAssetUndoRedo() {
    SecurityManager m;
    m.login("employee", "emp123");
    assert(throwsError<AccessDeniedException>([&] { m.undoAssetChange(); }));
    m.logout();

    m.login("admin", "admin123");
    assert(!m.canUndoAssetChange() && !m.canRedoAssetChange());
    assert(throwsError<ValidationException>([&] { m.undoAssetChange(); }));

    int original = static_cast<int>(m.getAssets().size());
    Asset& added = m.addAsset("Server", "test-01", "10.5.5.5", 3, "ssh");
    int id = added.getId();
    m.setAssetCheck(id, "Firewall is on", true);
    assert(m.getAssets().size() == static_cast<std::size_t>(original + 1));

    // edit
    m.editAsset(id, "test-02", "10.5.5.6", 4, "ssh, http");
    assert(added.getName() == "test-02" && added.getCriticality() == 4 && added.getIp() == "10.5.5.6");
    assert(throwsError<ValidationException>([&] { m.editAsset(id, "web-01", "10.5.5.6", 4, ""); })); // name taken
    assert(throwsError<ValidationException>([&] { m.editAsset(id, "x", "10.0.0.10", 4, ""); }));     // IP taken
    assert(throwsError<ValidationException>([&] { m.editAsset(id, "x", "9.9.9.9", 9, ""); }));       // bad level
    assert(added.getName() == "test-02"); // a refused edit changes nothing

    // remove
    m.removeAsset(id);
    assert(m.getAssets().size() == static_cast<std::size_t>(original));

    // undo the removal: same device, same id, same checklist
    assert(m.undoAssetChange().find("removing") != std::string::npos);
    Asset* back = m.getAssets().findById(id);
    assert(back != nullptr && back->getName() == "test-02" && back->isChecked("Firewall is on"));
    assert(m.canRedoAssetChange());

    // undo the edit
    m.undoAssetChange();
    assert(m.getAssets().findById(id)->getName() == "test-01");
    assert(m.getAssets().findById(id)->getCriticality() == 3);

    // redo the edit and the removal
    m.redoAssetChange();
    assert(m.getAssets().findById(id)->getName() == "test-02");
    m.redoAssetChange();
    assert(m.getAssets().findById(id) == nullptr);
    assert(!m.canRedoAssetChange());
    assert(throwsError<ValidationException>([&] { m.redoAssetChange(); }));

    // undo everything: the add is undone too
    m.undoAssetChange(); // removal
    m.undoAssetChange(); // edit
    m.undoAssetChange(); // add
    assert(m.getAssets().size() == static_cast<std::size_t>(original));

    // a NEW change clears the redo stack
    assert(m.canRedoAssetChange());
    m.addAsset("Workstation", "fresh-pc", "10.7.7.7", 2, "");
    assert(!m.canRedoAssetChange());
}

void testIncidentTimeline() {
    SecurityManager m;
    m.login("employee", "emp123");
    int id = m.reportIncident("Lost badge", "office", Severity::Low).getId();
    m.logout();

    m.login("admin", "admin123");
    m.assignIncident(id, "employee");
    m.resolveIncident(id);
    m.undoResolve();
    m.resolveIncident(id);
    assert(throwsError<NotFoundException>([&] { m.assignIncident(id, "nobody"); }));

    std::vector<std::string> lines = m.timelineLines(id);
    assert(lines.size() == 5); // reported, assigned, fixed, fix undone, fixed
    assert(lines[0].find("Reported the problem") != std::string::npos);
    assert(lines[1].find("Assigned to e******e") != std::string::npos); // the employee name is hidden
    assert(lines[1].find("admin") != std::string::npos);
    assert(lines[4].find("Marked as fixed") != std::string::npos);

    // The timeline survives a save and load.
    m.saveIncidents("test_timeline.dat");
    SecurityManager other;
    other.login("admin", "admin123");
    other.loadIncidents("test_timeline.dat");
    assert(other.timelineLines(id).size() == 5);
    std::remove("test_timeline.dat");

    IncidentEvent event{0, "sam", "did a thing"};
    std::ostringstream out;
    out << event;
    assert(out.str().find("sam  did a thing") != std::string::npos);
}

void testOldIncidentFileStillLoads() {
    // The old "CSH1" format had no timeline. It must still be readable.
    struct OldRecord { int id; char title[96]; char asset[48]; char reporter[32]; int severity; int status; };
    const char* file = "test_old_format.dat";
    {
        std::ofstream out(file, std::ios::binary);
        out.write("CSH1", 4);
        int count = 1;
        out.write(reinterpret_cast<const char*>(&count), sizeof count);
        OldRecord r{};
        r.id = 77;
        std::strcpy(r.title, "Old problem");
        std::strcpy(r.asset, "web-01");
        std::strcpy(r.reporter, "system");
        r.severity = 3;
        r.status = 0;
        out.write(reinterpret_cast<const char*>(&r), sizeof r);
    }
    SecurityManager m;
    m.login("admin", "admin123");
    m.loadIncidents(file);
    assert(m.getIncidents().size() == 1 && m.getIncidents().front().getId() == 77);
    assert(m.timelineLines(77).empty()); // old files have no history
    std::remove(file);
}

void testAuditTrail() {
    AuditEntry entry;
    assert(AuditTrail::parseLine("2026-11-18 12:30:05 [WARN ] Failed login for 'bob' (attempt 2)", entry));
    assert(entry.time == "2026-11-18 12:30:05" && entry.level == "WARN");
    assert(entry.message == "Failed login for 'bob' (attempt 2)");
    assert(!AuditTrail::parseLine("just some text", entry));
    assert(!AuditTrail::parseLine("", entry));

    SecurityManager m;
    m.login("employee", "emp123"); // writes an INFO line
    m.logout();
    for (int i = 0; i < 2; ++i)
        assert(throwsError<AuthException>([&] { m.login("admin", "wrong"); })); // two WARN lines
    m.login("admin", "admin123");

    AuditView all = m.auditView("All", "");
    assert(all.total > 0 && !all.entries.empty());
    assert(all.levelCounts.at("WARN") >= 2 && all.levelCounts.at("INFO") >= 3);

    AuditView warnings = m.auditView("WARN", "");
    for (const AuditEntry& e : warnings.entries)
        assert(e.level == "WARN");
    assert(warnings.entries.size() >= 2);

    AuditView mine = m.auditView("All", "ADMIN"); // user filter, not case sensitive
    assert(!mine.entries.empty());
    for (const AuditEntry& e : mine.entries)
        assert(util::toLower(e.message).find("admin") != std::string::npos);

    AuditView hidden = m.auditView("All", "employee"); // the real employee name is private
    for (const AuditEntry& e : hidden.entries)
        assert(e.message.find("employee") == std::string::npos);
    AuditView masked = m.auditView("All", "e******e");
    assert(!masked.entries.empty());

    assert(throwsError<FileException>([&] { AuditTrail::fromFile("no_such.log"); }));
}

void testLogAnalyzer() {
    LogAnalyzer analyzer;
    LogReport report = analyzer.analyzeFile("sample_data/server.log");
    assert(report.totalLines == 24);
    assert(report.byCategory.at("Failed login") == 9);
    assert(report.byCategory.at("Port scan") == 8); // 7 firewall lines from one IP + the nmap line
    assert(report.byCategory.at("Dangerous command") == 2);
    assert(report.findings.size() == 19);
    assert(report.bySource.at("185.220.101.1") == 6);
    assert(report.bySource.at("203.0.113.9") == 8);

    // topCounts: the template that finds the busiest sources
    auto top = util::topCounts(report.bySource, 2);
    assert(top.size() == 2 && top[0].first == "203.0.113.9" && top[0].second == 8);
    assert(top[1].first == "185.220.101.1");

    // normal lines are not marked, and one visitor on one port is not a scan
    LogReport clean = analyzer.analyzeText("GET /index.html 200\n"
                                           "IN=eth0 SRC=10.0.0.5 DST=10.0.0.10 DPT=443\n");
    assert(clean.findings.empty() && clean.totalLines == 2);
    assert(throwsError<FileException>([&] { analyzer.analyzeFile("no_such.log"); }));

    // Through the manager: Admin only, and it can create problems.
    SecurityManager m;
    m.login("employee", "emp123");
    assert(throwsError<AccessDeniedException>([&] { m.analyzeLogFile("sample_data/server.log", false); }));
    m.logout();
    m.login("admin", "admin123");
    m.analyzeLogFile("sample_data/server.log", false);
    assert(m.getIncidents().empty());
    m.analyzeLogFile("sample_data/server.log", true);
    assert(m.getIncidents().size() == 2); // failed logins and port scans (2 dangerous lines is under 3)
}

void testCriticalAlertHandler() {
    SecurityManager m;
    std::vector<std::string> alerts;
    m.setAlertHandler([&](const std::string& text) { alerts.push_back(text); });
    m.login("admin", "admin123");

    m.scan("web-01", "urgent: click here to verify your account"); // phishing = High: no alert
    assert(alerts.empty());
    m.scan("web-01", "a trojan arrived"); // malware = Critical
    assert(alerts.size() == 1 && alerts[0].find("CRITICAL") == 0 && alerts[0].find("Malware") != std::string::npos);
    m.scan("edge-rtr", 0, 5000); // DDoS = Critical
    assert(alerts.size() == 2);

    m.setAlertHandler(nullptr); // removing the handler is safe
    m.scan("web-01", "another trojan");
}

int main() {
    Logger::setFile("test_run.log"); // keep test output out of the real log
    std::cout << "Cyber Shield core tests\n";
    RUN(testLogin);
    RUN(testBruteForceLocksAccount);
    RUN(testRolePermissions);
    RUN(testDuplicateAssetRejected);
    RUN(testSearchAssets);
    RUN(testUserManagement);
    RUN(testDiamondInheritance);
    RUN(testThreatDetection);
    RUN(testScanCreatesIncidents);
    RUN(testScanQueue);
    RUN(testResolveAndUndo);
    RUN(testRiskScoreAndStats);
    RUN(testBinarySaveLoadRoundTrip);
    RUN(testTextExportImportRoundTrip);
    RUN(testFileErrors);
    RUN(testReportAndLog);
    RUN(testLinkChecker);
    RUN(testCheckLinkCreatesIncident);
    RUN(testCipherRoundTrip);
    RUN(testPasswordTools);
    RUN(testVaultLockAndUnlock);
    RUN(testVaultCorruptFile);
    RUN(testManagerVaultLocksOnLogout);
    RUN(testLoadSampleData);
    RUN(testSampleDataFiles);
    RUN(testEmployeeNamesArePrivate);
    RUN(testPasswordClass);
    RUN(testHexHelpers);
    RUN(testAssetRiskAndChecklist);
    RUN(testAssetUndoRedo);
    RUN(testIncidentTimeline);
    RUN(testOldIncidentFileStillLoads);
    RUN(testAuditTrail);
    RUN(testLogAnalyzer);
    RUN(testCriticalAlertHandler);
    std::remove("test_run.log");
    std::cout << "All tests passed.\n";
    return 0;
}
