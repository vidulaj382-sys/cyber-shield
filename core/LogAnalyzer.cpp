#include "LogAnalyzer.h"
#include "Exceptions.h"
#include "Utils.h"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

namespace cyber {

namespace {

bool containsAny(const std::string& line, const std::vector<std::string>& words) {
    for (const std::string& word : words)
        if (line.find(word) != std::string::npos)
            return true;
    return false;
}

// First IPv4 address on the line ("10.0.0.5"), or "" when there is none.
std::string findIp(const std::string& line) {
    for (std::size_t start = 0; start < line.size(); ++start) {
        if (!std::isdigit(static_cast<unsigned char>(line[start])) ||
            (start > 0 && (std::isdigit(static_cast<unsigned char>(line[start - 1])) || line[start - 1] == '.')))
            continue;
        std::size_t end = start;
        int dots = 0;
        while (end < line.size() &&
               (std::isdigit(static_cast<unsigned char>(line[end])) || line[end] == '.')) {
            if (line[end] == '.')
                ++dots;
            ++end;
        }
        std::string candidate = line.substr(start, end - start);
        if (dots == 3 && candidate.back() != '.')
            return candidate;
        start = end;
    }
    return "";
}

// Number after "dpt=" (firewall logs), or -1.
int findPort(const std::string& lowerLine) {
    std::size_t at = lowerLine.find("dpt=");
    if (at == std::string::npos)
        return -1;
    return std::atoi(lowerLine.c_str() + at + 4);
}

void add(LogReport& report, int lineNumber, const std::string& category, const std::string& line) {
    LogFinding finding;
    finding.lineNumber = lineNumber;
    finding.category = category;
    finding.source = findIp(line);
    finding.text = line;
    report.findings.push_back(finding);
    util::countUp(report.byCategory, category);            // function template
    if (!finding.source.empty())
        util::countUp(report.bySource, finding.source);
}
} // namespace

LogReport LogAnalyzer::analyzeText(const std::string& text) const {
    const std::vector<std::string> failedWords = {"failed password", "failed login", "login failed",
                                                  "authentication failure", "invalid user"};
    const std::vector<std::string> scanWords = {"port scan", "portscan", "nmap"};
    const std::vector<std::string> dangerWords = {"chmod 777", "nc -e", "/etc/shadow", "rm -rf /",
                                                  "| sh", "base64 -d"};

    // Pass 1: split into lines and remember which ports each IP touched.
    std::vector<std::string> lines;
    std::map<std::string, std::set<int>> portsBySource;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back(line);
        int port = findPort(util::toLower(line));
        std::string ip = findIp(line);
        if (port >= 0 && !ip.empty())
            portsBySource[ip].insert(port);
    }

    // Pass 2: judge every line.
    LogReport report;
    report.totalLines = static_cast<int>(lines.size());
    for (std::size_t i = 0; i < lines.size(); ++i) {
        std::string lower = util::toLower(lines[i]);
        int number = static_cast<int>(i) + 1;
        std::string ip = findIp(lines[i]);

        bool manyPorts = !ip.empty() && findPort(lower) >= 0 &&
                         portsBySource[ip].size() >= static_cast<std::size_t>(kScanPorts);
        if (containsAny(lower, failedWords))
            add(report, number, "Failed login", lines[i]);
        else if (containsAny(lower, scanWords) || manyPorts)
            add(report, number, "Port scan", lines[i]);
        else if (containsAny(lower, dangerWords))
            add(report, number, "Dangerous command", lines[i]);
    }
    return report;
}

LogReport LogAnalyzer::analyzeFile(const std::string& path) const {
    std::ifstream in(path);
    if (!in)
        throw FileException(path, "file does not exist or cannot be opened");
    std::ostringstream text;
    text << in.rdbuf();
    return analyzeText(text.str());
}

} // namespace cyber
