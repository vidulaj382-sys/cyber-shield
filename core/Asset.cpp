#include "Asset.h"
#include "Exceptions.h"

#include <algorithm>

namespace cyber {

Asset::Asset(const std::string& name, const std::string& ip, int criticality)
    : Entity(name), ip(ip), criticality(criticality) {
    if (name.empty())
        throw ValidationException("asset name is empty");
    if (ip.empty())
        throw ValidationException("IP address is empty");
    if (criticality < 1 || criticality > 5)
        throw ValidationException("criticality must be between 1 and 5");
}

std::string Asset::describe() const {
    return Entity::describe() + " [" + type() + "] ip=" + ip +
           " criticality=" + std::to_string(criticality) + " " + details();
}

void Asset::setIp(const std::string& newIp) {
    if (newIp.empty())
        throw ValidationException("IP address is empty");
    ip = newIp;
}

void Asset::setCriticality(int level) {
    if (level < 1 || level > 5)
        throw ValidationException("criticality must be between 1 and 5");
    criticality = level;
}

// ---- security checklist ---------------------------------------------------

const std::vector<std::string>& Asset::checklistItems() {
    static const std::vector<std::string> items = {
        "Operating system is up to date", "Firewall is on",       "Antivirus is installed",
        "Backups are working",            "Strong passwords used", "Unused ports are closed"};
    return items;
}

bool Asset::isChecked(const std::string& item) const {
    return passed.count(item) > 0;
}

void Asset::setChecked(const std::string& item, bool done) {
    const auto& items = checklistItems();
    if (std::find(items.begin(), items.end(), item) == items.end())
        throw ValidationException("unknown checklist item '" + item + "'");
    if (done)
        passed.insert(item);
    else
        passed.erase(item);
}

int Asset::compliancePercent() const {
    return static_cast<int>(passed.size() * 100 / checklistItems().size());
}

std::ostream& operator<<(std::ostream& out, const Asset& a) {
    return out << a.describe(); // virtual call -> the right text for each type
}

Workstation::Workstation(const std::string& name, const std::string& ip, int criticality,
                         const std::string& owner)
    : Asset(name, ip, criticality), owner(owner) {}

std::string Workstation::details() const {
    return "owner=" + (owner.empty() ? std::string("-") : owner);
}

Server::Server(const std::string& name, const std::string& ip, int criticality,
               const std::string& services)
    : Asset(name, ip, criticality), services(services) {}

std::string Server::details() const {
    return "services=" + (services.empty() ? std::string("-") : services);
}

Router::Router(const std::string& name, const std::string& ip, int criticality,
               const std::string& uplink)
    : Asset(name, ip, criticality), uplink(uplink) {}

std::string Router::details() const {
    return "uplink=" + (uplink.empty() ? std::string("-") : uplink);
}

} // namespace cyber
