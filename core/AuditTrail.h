#pragma once
// The audit trail: "who did what and when", read back from the activity log.
// Unit IV: text file reading. Unit III: std::map for the counters.
#include <map>
#include <string>
#include <vector>

namespace cyber {

// One line of the log, split into its parts.
struct AuditEntry {
    std::string time;    // "2026-11-18 12:30:05"
    std::string level;   // "INFO", "WARN" or "ERROR"
    std::string message; // what happened (it names the user who did it)
};

class AuditTrail {
public:
    // Reads a log file written by Logger. Lines that do not fit the format are skipped.
    // Throws FileException when the file cannot be opened.
    static AuditTrail fromFile(const std::string& path);

    // Parses one line, returns false when it does not look like a log line.
    static bool parseLine(const std::string& line, AuditEntry& entry);

    // Keeps the entries of one level ("All" keeps every level) whose message
    // contains the given text (empty text keeps everything). Not case sensitive.
    std::vector<AuditEntry> filter(const std::string& level, const std::string& text) const;

    // How many entries of each level: {"INFO": 120, "WARN": 5}.
    std::map<std::string, int> countByLevel() const;

    const std::vector<AuditEntry>& all() const { return entries; }

private:
    std::vector<AuditEntry> entries;
};

} // namespace cyber
