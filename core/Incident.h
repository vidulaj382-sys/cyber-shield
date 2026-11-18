#pragma once
// Unit III: operator overloading (<<, >>, <, ==). Unit I: friend function.
// Unit IV: binary (de)serialisation of a fixed-size record plus a list of events.
#include <ctime>
#include <istream>
#include <ostream>
#include <string>
#include <vector>
#include "Types.h"

namespace cyber {

enum class Status { Open = 0, Resolved = 1 };

// One line of an incident's TIMELINE: when, who and what happened.
struct IncidentEvent {
    std::time_t when;
    std::string who;
    std::string what;
};

// "2026-11-18 12:30  admin  Marked as fixed"
std::ostream& operator<<(std::ostream& out, const IncidentEvent& event);

class Incident {
public:
    Incident();
    Incident(const std::string& title, const std::string& asset, Severity severity,
             const std::string& reporter);
    Incident(int id, const std::string& title, const std::string& asset, Severity severity,
             Status status, const std::string& reporter);

    int getId() const { return id; }
    const std::string& getTitle() const { return title; }
    const std::string& getAsset() const { return asset; }
    Severity getSeverity() const { return severity; }
    Status getStatus() const { return status; }
    const std::string& getReporter() const { return reporter; }
    bool isOpen() const { return status == Status::Open; }

    // Changing the status also writes a line in the timeline.
    void resolve(const std::string& who = "system");
    void reopen(const std::string& who = "system");
    void assign(const std::string& who, const std::string& assignee);

    // The timeline (oldest first).
    void addEvent(const std::string& who, const std::string& what);
    const std::vector<IncidentEvent>& getEvents() const { return events; }

    // Most severe first, then oldest first.
    bool operator<(const Incident& other) const;
    bool operator==(const Incident& other) const { return id == other.id; }

    // Text form: id|title|asset|severity|status|reporter   (the timeline is not included)
    friend std::ostream& operator<<(std::ostream& out, const Incident& inc);
    friend std::istream& operator>>(std::istream& in, Incident& inc);

    // Friend function: a readable one-line summary built from private data.
    friend std::string incidentSummary(const Incident& inc);

    void writeBinary(std::ostream& out) const;
    // withEvents = false reads the old "CSH1" file format, which had no timeline.
    static Incident readBinary(std::istream& in, bool withEvents = true);

    static void resetIdCounter(int next) { nextId = next; }
    static int peekNextId() { return nextId; }

private:
    int id;
    std::string title;
    std::string asset;
    Severity severity;
    Status status;
    std::string reporter;
    std::vector<IncidentEvent> events;

    static int nextId;
};

std::string incidentSummary(const Incident& inc);

} // namespace cyber
