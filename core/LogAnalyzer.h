#pragma once
// Reads ANY text log file (like a server log) and marks the suspicious lines:
// failed logins, port scans and dangerous commands.
// Unit IV: file handling.  Unit III: std::map counters + function templates.
#include <map>
#include <string>
#include <vector>

namespace cyber {

struct LogFinding {
    int lineNumber = 0;
    std::string category; // "Failed login", "Port scan" or "Dangerous command"
    std::string source;   // the IP address on that line, if there is one
    std::string text;     // the line itself
};

struct LogReport {
    int totalLines = 0;
    std::vector<LogFinding> findings;
    std::map<std::string, int> byCategory; // how many lines of each kind
    std::map<std::string, int> bySource;   // how many suspicious lines per IP address
};

class LogAnalyzer {
public:
    LogReport analyzeFile(const std::string& path) const; // throws FileException
    LogReport analyzeText(const std::string& text) const;

    // A source that touches this many different ports is called a port scan.
    static const int kScanPorts = 5;
};

} // namespace cyber
