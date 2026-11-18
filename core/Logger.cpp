#include "Logger.h"
#include "Exceptions.h"

#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>

namespace cyber {

std::string Logger::filePath = "cybershield.log";
int Logger::entries = 0;

void Logger::setFile(const std::string& path) { filePath = path; }
const std::string& Logger::file() { return filePath; }

std::string Logger::readAll() {
    std::ifstream in(filePath);
    if (!in)
        throw FileException(filePath, "log file does not exist yet");
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

void Logger::write(const std::string& level, const std::string& msg) {
    try {
        std::ofstream out(filePath, std::ios::app);
        if (!out)
            throw FileException(filePath, "cannot open log file for writing");

        char stamp[32];
        std::time_t now = std::time(nullptr);
        std::strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        out << stamp << " [" << level << "] " << msg << '\n';
        if (!out)
            throw FileException(filePath, "write failed");
        ++entries;
    } catch (const FileException& e) {
        // Logging must never crash the application.
        std::cerr << e.what() << '\n';
    }
}

} // namespace cyber
