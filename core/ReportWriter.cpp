#include "ReportWriter.h"
#include "SecurityManager.h"

#include <algorithm>
#include <sstream>

#include "Logger.h"

namespace cyber {

std::string ReportWriter::build(const SecurityManager& m) {
    std::ostringstream r;
    r << "CYBER SHIELD - SECURITY REPORT\n"
      << "==============================\n";
    if (m.current)
        r << "Generated for: " << m.current->describe() << "\n";

    DashboardStats stats = m.getStats();
    r << "\nSUMMARY\n"
      << "  Assets:            " << stats.assets << '\n'
      << "  Open incidents:    " << stats.openIncidents << '\n'
      << "  Threats detected:  " << stats.threatsDetected << '\n'
      << "  Overall risk:      " << stats.risk << '\n';

    r << "\nASSETS (" << m.assets.size() << ")\n";
    for (const Asset* a : m.assets) {
        r << "  " << *a; // operator<< on Asset
        if (auto* monitored = dynamic_cast<const Monitored*>(a)) // Servers and Routers only
            r << " alerts=" << monitored->getAlerts();
        r << '\n';
    }

    r << "\nOPEN INCIDENTS BY SEVERITY\n";
    for (int s = 4; s >= 1; --s) {
        Severity sev = static_cast<Severity>(s);
        r << "  " << severityName(sev) << ": " << stats.openBySeverity.count(sev) << '\n';
    }

    std::vector<Incident> sorted(m.incidents.begin(), m.incidents.end());
    std::sort(sorted.begin(), sorted.end()); // uses Incident::operator<
    r << "\nINCIDENTS BY PRIORITY (" << sorted.size() << ")\n";
    for (const Incident& i : sorted)
        r << "  " << incidentSummary(i) << '\n';

    r << "\nTHREAT DETECTIONS\n";
    if (m.threatStats.empty())
        r << "  none this session\n";
    for (const auto& entry : m.threatStats)
        r << "  " << entry.first << ": " << entry.second << '\n';

    r << "\nBLOCKED SOURCES / LOCKED ACCOUNTS (" << m.blocked.size() << ")\n";
    for (const std::string& b : m.blocked)
        r << "  " << b << '\n';

    // Admin-only section, chosen by the role's permission.
    if (m.current && m.current->canManageUsers()) {
        r << "\nUSER ACCOUNTS (admin view)\n";
        for (const auto& entry : m.users)
            r << "  " << entry.second->describe() << '\n';
        r << "\nSYSTEM\n"
          << "  Live entities: " << Entity::liveCount() << '\n'
          << "  Next incident id: " << Incident::peekNextId() << '\n'
          << "  Scans waiting: " << m.scanQueue.size() << '\n'
          << "  Log entries this session: " << Logger::entriesWritten() << " ("
          << Logger::file() << ")\n";
    }

    if (m.current && m.current->canManageUsers())
        r << "\nPRIVACY NOTE: employee names are hidden (e******e) to protect their privacy.\n";

    // Every name that should stay private is hidden before the report leaves this class.
    return m.maskPrivateNames(r.str());
}

} // namespace cyber
