#pragma once
// Unit II: one more concrete Threat. It looks at a web link (URL) and gives
// it a "danger score" by adding points for every warning sign it finds.
#include <set>
#include <string>
#include <vector>
#include "Threat.h"

namespace cyber {

// Everything we learned about one link.
struct LinkReport {
    std::string url;
    std::string host;                 // the website name inside the link
    int score = 0;                    // more points = more dangerous
    std::vector<std::string> reasons; // plain-English warning signs

    std::string verdict() const;      // "Safe", "Suspicious" or "Dangerous"
};

class LinkThreat : public Threat {
public:
    LinkThreat();

    // Throws ValidationException when the text does not look like a link.
    LinkReport analyze(const std::string& url) const;

    // Threat's pure virtual function: true when the link is Dangerous.
    bool detect(const std::string& url) const override;

    std::string advice() const override;
    std::string explanation() const override;

private:
    std::set<std::string> badSites;          // our list of known bad websites
    std::set<std::string> shorteners;        // sites that hide the real address
    std::vector<std::string> oddEndings;     // unusual ending like .xyz
    std::vector<std::string> scammerWords;   // words scammers love
};

} // namespace cyber
