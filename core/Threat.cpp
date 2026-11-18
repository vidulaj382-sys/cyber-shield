#include "Threat.h"
#include "Utils.h"

namespace cyber {

namespace {
int countOccurrences(const std::string& text, const std::string& word) {
    int count = 0;
    for (size_t pos = text.find(word); pos != std::string::npos; pos = text.find(word, pos + 1))
        ++count;
    return count;
}
} // namespace

int Threat::detections = 0;

Threat::Threat(const std::string& name, Severity severity) : name(name), severity(severity) {}

// ---- Malware -------------------------------------------------------------
MalwareThreat::MalwareThreat()
    : Threat("Malware", Severity::Critical),
      signatures{"trojan", "ransomware", "keylogger", "rootkit", "worm",
                 "powershell -enc", "eval(base64", ".exe.zip",
                 "185.220.101.1", "45.155.205.233"} { // two known-bad IPs
}

bool MalwareThreat::detect(const std::string& data) const {
    std::string text = util::toLower(data);
    for (const std::string& sig : signatures) {
        if (text.find(sig) != std::string::npos) {
            recordDetection();
            return true;
        }
    }
    return false;
}

std::string MalwareThreat::advice() const {
    return "Isolate the host, run a full AV scan and restore from a clean backup.";
}

std::string MalwareThreat::explanation() const {
    return "Malware is a harmful program that can break or spy on a computer, like a germ for computers.";
}

// ---- Phishing ------------------------------------------------------------
PhishingThreat::PhishingThreat()
    : Threat("Phishing", Severity::High),
      keywords{"verify your account", "urgent", "click here", "password",
               "bank", "suspended", "login now", "http://"} {}

bool PhishingThreat::detect(const std::string& data) const {
    std::string text = util::toLower(data);
    int hits = 0;
    for (const std::string& k : keywords)
        if (text.find(k) != std::string::npos)
            ++hits;
    if (hits >= 2) { // one suspicious word alone is not enough
        recordDetection();
        return true;
    }
    return false;
}

std::string PhishingThreat::advice() const {
    return "Block the sender, delete the message and warn affected users.";
}

std::string PhishingThreat::explanation() const {
    return "Phishing is a fake message that tricks you into giving away secrets, like fishing with bait.";
}

// ---- Brute force ---------------------------------------------------------
BruteForceThreat::BruteForceThreat(int threshold)
    : Threat("Brute-Force", Severity::High), threshold(threshold) {}

bool BruteForceThreat::detect(const std::string& logText) const {
    return detect(countOccurrences(util::toLower(logText), "failed"));
}

bool BruteForceThreat::detect(int failedAttempts) const {
    if (failedAttempts >= threshold) {
        recordDetection();
        return true;
    }
    return false;
}

std::string BruteForceThreat::advice() const {
    return "Lock the account, block the source IP and enforce MFA.";
}

std::string BruteForceThreat::explanation() const {
    return "Brute force means a robot tries thousands of passwords until one of them works.";
}

// ---- DDoS ----------------------------------------------------------------
DDoSThreat::DDoSThreat(int requestsPerSecondLimit)
    : Threat("DDoS", Severity::Critical), limit(requestsPerSecondLimit) {}

bool DDoSThreat::detect(const std::string& trafficText) const {
    std::string text = util::toLower(trafficText);
    const char* words[] = {"syn flood", "udp flood", "http flood", "ping flood", "ddos"};
    for (const char* word : words) {
        if (text.find(word) != std::string::npos) {
            recordDetection();
            return true;
        }
    }
    return false;
}

bool DDoSThreat::detect(int requestsPerSecond) const {
    if (requestsPerSecond >= limit) {
        recordDetection();
        return true;
    }
    return false;
}

std::string DDoSThreat::advice() const {
    return "Enable rate limiting, contact the ISP and switch on DDoS protection.";
}

std::string DDoSThreat::explanation() const {
    return "A DDoS attack sends a crowd of fake visitors to a website so real people cannot get in.";
}

} // namespace cyber
