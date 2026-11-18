#include "LinkThreat.h"
#include "Exceptions.h"
#include "Utils.h"

namespace cyber {

namespace {
const int kDangerousScore = 4;
const int kSuspiciousScore = 2;

bool looksLikeIpAddress(const std::string& host) {
    int dots = 0;
    for (char c : host) {
        if (c == '.')
            ++dots;
        else if (c < '0' || c > '9')
            return false;
    }
    return dots == 3;
}

int countChar(const std::string& text, char wanted) {
    int count = 0;
    for (char c : text)
        if (c == wanted)
            ++count;
    return count;
}

bool endsWith(const std::string& text, const std::string& ending) {
    return text.size() >= ending.size() &&
           text.compare(text.size() - ending.size(), ending.size(), ending) == 0;
}
} // namespace

std::string LinkReport::verdict() const {
    if (score >= kDangerousScore)
        return "Dangerous";
    if (score >= kSuspiciousScore)
        return "Suspicious";
    return "Safe";
}

LinkThreat::LinkThreat()
    : Threat("Dangerous Link", Severity::High),
      badSites{"evil.example", "phish.example", "free-money.example", "malware-download.example"},
      shorteners{"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"},
      oddEndings{".zip", ".xyz", ".tk", ".top", ".click", ".gq", ".ml", ".cf"},
      scammerWords{"login", "verify", "secure", "account", "update", "free", "prize",
                   "winner", "bank", "password", "gift", "bonus"} {}

LinkReport LinkThreat::analyze(const std::string& rawUrl) const {
    std::string url = util::trim(rawUrl);
    if (url.empty())
        throw ValidationException("please paste a link first");
    if (url.find(' ') != std::string::npos)
        throw ValidationException("a link cannot contain spaces");
    if (url.size() > 2000)
        throw ValidationException("this link is far too long");

    LinkReport report;
    report.url = url;
    std::string lower = util::toLower(url);

    // 1. Cut the link into pieces: scheme://host/rest
    std::string rest = lower;
    if (util::startsWith(rest, "https://")) {
        rest = rest.substr(8);
    } else if (util::startsWith(rest, "http://")) {
        rest = rest.substr(7);
        report.score += 2;
        report.reasons.push_back("It starts with http, not https, so it is not protected.");
    } else if (rest.find("://") != std::string::npos) {
        rest = rest.substr(rest.find("://") + 3);
        report.score += 2;
        report.reasons.push_back("It uses an unusual kind of address.");
    }

    std::string authority = rest.substr(0, rest.find_first_of("/?#"));
    if (authority.find('@') != std::string::npos) {
        report.score += 3;
        report.reasons.push_back("It has an @ sign, which can hide the real website.");
        authority = authority.substr(authority.rfind('@') + 1);
    }
    std::string host = authority.substr(0, authority.find(':')); // remove a port number
    if (host.empty() || host.find('.') == std::string::npos)
        throw ValidationException("this does not look like a web link (try https://example.com)");
    report.host = host;

    // 2. Look for warning signs.
    if (badSites.count(host)) {
        report.score += 5;
        report.reasons.push_back("This website is on our list of known bad websites.");
    }
    if (looksLikeIpAddress(host)) {
        report.score += 3;
        report.reasons.push_back("It uses a number instead of a website name.");
    }
    if (shorteners.count(host)) {
        report.score += 2;
        report.reasons.push_back("It is a shortened link, so you cannot see where it really goes.");
    }
    if (host.find("xn--") != std::string::npos) {
        report.score += 3;
        report.reasons.push_back("It may use look-alike letters to copy a real website.");
    }
    for (const std::string& ending : oddEndings) {
        if (endsWith(host, ending)) {
            report.score += 2;
            report.reasons.push_back("It ends with " + ending + ", which scammers often use.");
            break;
        }
    }
    if (countChar(host, '.') >= 4) {
        report.score += 2;
        report.reasons.push_back("The website name has too many parts.");
    }
    if (countChar(host, '-') >= 3) {
        report.score += 1;
        report.reasons.push_back("The website name has lots of dashes.");
    }

    std::string foundWords;
    int wordPoints = 0;
    for (const std::string& word : scammerWords) {
        if (lower.find(word) != std::string::npos && wordPoints < 3) {
            ++wordPoints;
            foundWords += (foundWords.empty() ? "" : ", ") + word;
        }
    }
    if (wordPoints > 0) {
        report.score += wordPoints;
        report.reasons.push_back("It has words scammers love: " + foundWords + ".");
    }
    if (url.size() > 75) {
        report.score += 1;
        report.reasons.push_back("The link is very long.");
    }

    if (report.reasons.empty())
        report.reasons.push_back("No warning signs were found.");
    return report;
}

bool LinkThreat::detect(const std::string& url) const {
    if (analyze(url).verdict() == "Dangerous") {
        recordDetection();
        return true;
    }
    return false;
}

std::string LinkThreat::advice() const {
    return "Do not click it. Delete the message and tell a grown-up or the security team.";
}

std::string LinkThreat::explanation() const {
    return "A dangerous link can take you to a fake or harmful website that steals your secrets.";
}

} // namespace cyber
