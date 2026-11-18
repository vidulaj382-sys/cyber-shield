#include "AuditTrail.h"
#include "Exceptions.h"
#include "Utils.h"

#include <fstream>

namespace cyber {

bool AuditTrail::parseLine(const std::string& line, AuditEntry& entry) {
    // Format written by Logger:  2026-11-18 12:30:05 [INFO ] message
    if (line.size() < 28 || line[19] != ' ' || line[20] != '[')
        return false;
    std::size_t close = line.find(']', 21);
    if (close == std::string::npos)
        return false;

    entry.time = line.substr(0, 19);
    entry.level = util::trim(line.substr(21, close - 21));
    entry.message = close + 2 <= line.size() ? line.substr(close + 2) : "";
    return !entry.level.empty();
}

AuditTrail AuditTrail::fromFile(const std::string& path) {
    std::ifstream in(path);
    if (!in)
        throw FileException(path, "the log file does not exist yet");

    AuditTrail trail;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        AuditEntry entry;
        if (parseLine(line, entry))
            trail.entries.push_back(entry);
    }
    return trail;
}

std::vector<AuditEntry> AuditTrail::filter(const std::string& level, const std::string& text) const {
    std::string wanted = util::toLower(util::trim(text));
    std::vector<AuditEntry> result;
    for (const AuditEntry& entry : entries) {
        if (level != "All" && !level.empty() && entry.level != level)
            continue;
        if (!wanted.empty() && util::toLower(entry.message).find(wanted) == std::string::npos)
            continue;
        result.push_back(entry);
    }
    return result;
}

std::map<std::string, int> AuditTrail::countByLevel() const {
    std::map<std::string, int> counts;
    for (const AuditEntry& entry : entries)
        util::countUp(counts, entry.level); // the function template from Utils.h
    return counts;
}

} // namespace cyber
