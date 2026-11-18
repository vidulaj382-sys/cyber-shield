#pragma once
// Unit II: abstract class Asset (pure virtual functions) with three
// concrete children = hierarchical inheritance. Server and Router also
// inherit from Monitored = multiple inheritance.
//
//   Entity                Monitored
//     |                  (raises alerts)
//   Asset (abstract)          |
//     +-- Workstation         |      Workstation: Asset only
//     +-- Server ------------+      Server:      Asset + Monitored
//     +-- Router ------------+      Router:      Asset + Monitored
#include <ostream>
#include <set>
#include <string>
#include <vector>
#include "Entity.h"

namespace cyber {

class Asset : public Entity {
public:
    Asset(const std::string& name, const std::string& ip, int criticality);
    ~Asset() override = default;

    virtual std::string type() const = 0;    // pure virtual
    virtual std::string details() const = 0; // pure virtual: type-specific info as a sentence
    virtual std::string extraInfo() const = 0;                       // the raw type-specific text
    virtual void setExtraInfo(const std::string& text) = 0;          // change it
    std::string describe() const override;

    const std::string& getIp() const { return ip; }
    int getCriticality() const { return criticality; }

    // Changing a device (all of them check their input).
    void setIp(const std::string& newIp);
    void setCriticality(int level);

    // ---- security checklist: "Firewall is on", "Backups are working" ... ----
    static const std::vector<std::string>& checklistItems();
    bool isChecked(const std::string& item) const;
    void setChecked(const std::string& item, bool done);
    const std::set<std::string>& passedChecks() const { return passed; }
    void setPassedChecks(const std::set<std::string>& checks) { passed = checks; }
    int compliancePercent() const;  // share of the checklist that is done

    // Operator overloading: two assets are "the same" when they share an IP.
    bool operator==(const Asset& other) const { return ip == other.ip; }
    bool operator<(const Asset& other) const { return name < other.name; }

    friend std::ostream& operator<<(std::ostream& out, const Asset& a);

protected:
    std::string ip;
    int criticality; // 1 (low) .. 5 (mission critical)

private:
    std::set<std::string> passed; // checklist items that are done
};

// Second base class used for multiple inheritance: things that raise alerts.
class Monitored {
public:
    virtual ~Monitored() = default;
    void raiseAlert() { ++alerts; }
    int getAlerts() const { return alerts; }

private:
    int alerts = 0;
};

class Workstation : public Asset {
public:
    Workstation(const std::string& name, const std::string& ip, int criticality,
                const std::string& owner = "");
    std::string type() const override { return "Workstation"; }
    std::string details() const override;
    std::string extraInfo() const override { return owner; }
    void setExtraInfo(const std::string& text) override { owner = text; }

private:
    std::string owner;
};

class Server : public Asset, public Monitored {
public:
    Server(const std::string& name, const std::string& ip, int criticality,
           const std::string& services);
    std::string type() const override { return "Server"; }
    std::string details() const override;
    std::string extraInfo() const override { return services; }
    void setExtraInfo(const std::string& text) override { services = text; }

private:
    std::string services;
};

class Router : public Asset, public Monitored {
public:
    Router(const std::string& name, const std::string& ip, int criticality,
           const std::string& uplink);
    std::string type() const override { return "Router"; }
    std::string details() const override;
    std::string extraInfo() const override { return uplink; }
    void setExtraInfo(const std::string& text) override { uplink = text; }

private:
    std::string uplink;
};

} // namespace cyber
