#include "Incident.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "Exceptions.h"

namespace cyber {

namespace {
// Fixed-size record so each incident occupies the same number of bytes on disk.
struct IncidentRecord {
    int id;
    char title[96];
    char asset[48];
    char reporter[32];
    int severity;
    int status;
};

// One timeline event on disk.
struct EventRecord {
    long long when;
    char who[32];
    char what[64];
};

template <size_t N>
void copyField(char (&dest)[N], const std::string& src) {
    std::memset(dest, 0, N);
    std::strncpy(dest, src.c_str(), N - 1);
}
} // namespace

int Incident::nextId = 1;

Incident::Incident() : Incident(0, "", "", Severity::Low, Status::Open, "") {}

Incident::Incident(const std::string& title, const std::string& asset, Severity severity,
                   const std::string& reporter)
    : Incident(nextId, title, asset, severity, Status::Open, reporter) {
    addEvent(reporter, "Reported the problem"); // the first line of every timeline
}

Incident::Incident(int id, const std::string& title, const std::string& asset,
                   Severity severity, Status status, const std::string& reporter)
    : id(id), title(title), asset(asset), severity(severity), status(status),
      reporter(reporter) {
    nextId = std::max(nextId, id + 1);
}

// ---- timeline ----------------------------------------------------------------

void Incident::addEvent(const std::string& who, const std::string& what) {
    events.push_back({std::time(nullptr), who, what});
}

void Incident::resolve(const std::string& who) {
    status = Status::Resolved;
    addEvent(who, "Marked as fixed");
}

void Incident::reopen(const std::string& who) {
    status = Status::Open;
    addEvent(who, "Opened again (fix undone)");
}

void Incident::assign(const std::string& who, const std::string& assignee) {
    addEvent(who, "Assigned to " + assignee);
}

std::ostream& operator<<(std::ostream& out, const IncidentEvent& event) {
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M", std::localtime(&event.when));
    return out << stamp << "  " << event.who << "  " << event.what;
}

bool Incident::operator<(const Incident& other) const {
    if (severity != other.severity)
        return severity > other.severity;
    return id < other.id;
}

std::ostream& operator<<(std::ostream& out, const Incident& inc) {
    return out << inc.id << '|' << inc.title << '|' << inc.asset << '|'
               << static_cast<int>(inc.severity) << '|' << static_cast<int>(inc.status)
               << '|' << inc.reporter;
}

std::istream& operator>>(std::istream& in, Incident& inc) {
    std::string line;
    if (!std::getline(in, line))
        return in;

    std::stringstream ss(line);
    std::string field[6];
    for (std::string& f : field) {
        if (!std::getline(ss, f, '|')) {
            in.setstate(std::ios::failbit);
            return in;
        }
    }
    try {
        int sev = std::stoi(field[3]);
        int st = std::stoi(field[4]);
        inc = Incident(std::stoi(field[0]), field[1], field[2], toSeverity(sev),
                       st == 1 ? Status::Resolved : Status::Open, field[5]);
    } catch (...) {
        in.setstate(std::ios::failbit); // malformed line
    }
    return in;
}

std::string incidentSummary(const Incident& inc) {
    return "INC-" + std::to_string(inc.id) + " [" + severityName(inc.severity) + "] " +
           inc.title + " on " + inc.asset + " (" +
           (inc.status == Status::Open ? "OPEN" : "RESOLVED") + ", by " + inc.reporter + ")";
}

void Incident::writeBinary(std::ostream& out) const {
    IncidentRecord r{};
    r.id = id;
    copyField(r.title, title);
    copyField(r.asset, asset);
    copyField(r.reporter, reporter);
    r.severity = static_cast<int>(severity);
    r.status = static_cast<int>(status);
    out.write(reinterpret_cast<const char*>(&r), sizeof r);

    // Then the timeline: how many events, then each event.
    int count = static_cast<int>(events.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof count);
    for (const IncidentEvent& event : events) {
        EventRecord e{};
        e.when = static_cast<long long>(event.when);
        copyField(e.who, event.who);
        copyField(e.what, event.what);
        out.write(reinterpret_cast<const char*>(&e), sizeof e);
    }
}

Incident Incident::readBinary(std::istream& in, bool withEvents) {
    IncidentRecord r{};
    if (!in.read(reinterpret_cast<char*>(&r), sizeof r))
        throw FileException("incidents", "truncated record");
    r.title[sizeof r.title - 1] = '\0';
    r.asset[sizeof r.asset - 1] = '\0';
    r.reporter[sizeof r.reporter - 1] = '\0';
    Incident incident(r.id, r.title, r.asset, toSeverity(r.severity),
                      r.status == 1 ? Status::Resolved : Status::Open, r.reporter);

    if (withEvents) { // the timeline (files of the old format have none)
        int count = 0;
        if (!in.read(reinterpret_cast<char*>(&count), sizeof count) || count < 0 || count > 1000)
            throw FileException("incidents", "corrupt timeline");
        for (int i = 0; i < count; ++i) {
            EventRecord e{};
            if (!in.read(reinterpret_cast<char*>(&e), sizeof e))
                throw FileException("incidents", "truncated timeline");
            e.who[sizeof e.who - 1] = '\0';
            e.what[sizeof e.what - 1] = '\0';
            incident.events.push_back({static_cast<std::time_t>(e.when), e.who, e.what});
        }
    }
    return incident;
}

} // namespace cyber
