#pragma once
// Unit II: abstract Threat (pure virtual detect()) overridden by every
// concrete threat = hierarchical inheritance + runtime polymorphism.
#include <set>
#include <string>
#include <vector>
#include "Types.h"

namespace cyber {

class Threat {
public:
    Threat(const std::string& name, Severity severity);
    virtual ~Threat() = default; // virtual destructor: safe delete via Threat*

    virtual bool detect(const std::string& data) const = 0; // pure virtual
    virtual std::string advice() const { return "Investigate the source."; }
    // A plain-English description, so anyone can understand what was found.
    virtual std::string explanation() const { return "Something suspicious was found."; }

    const std::string& getName() const { return name; }
    Severity getSeverity() const { return severity; }

    static int totalDetections() { return detections; }

protected:
    static void recordDetection() { ++detections; }

    std::string name;
    Severity severity;

private:
    static int detections; // static member shared by all threats
};

class MalwareThreat : public Threat {
public:
    MalwareThreat();
    bool detect(const std::string& data) const override;
    std::string advice() const override;
    std::string explanation() const override;

private:
    std::set<std::string> signatures; // known bad words and known bad IPs
};

class PhishingThreat : public Threat {
public:
    PhishingThreat();
    bool detect(const std::string& data) const override;
    std::string advice() const override;
    std::string explanation() const override;

private:
    std::vector<std::string> keywords;
};

class BruteForceThreat : public Threat {
public:
    explicit BruteForceThreat(int threshold = 5);

    // Function overloading: inspect a log text, or a plain attempt count.
    bool detect(const std::string& logText) const override;
    bool detect(int failedAttempts) const;

    std::string advice() const override;
    std::string explanation() const override;
    int getThreshold() const { return threshold; }

private:
    int threshold;
};

class DDoSThreat : public Threat {
public:
    explicit DDoSThreat(int requestsPerSecondLimit = 1000);

    // Function overloading: inspect a text, or a request rate.
    bool detect(const std::string& trafficText) const override;
    bool detect(int requestsPerSecond) const;

    std::string advice() const override;
    std::string explanation() const override;
    int getLimit() const { return limit; }

private:
    int limit;
};

} // namespace cyber
