#pragma once
// Unit IV: text file logging (append-only, timestamped).
#include <string>

namespace cyber {

class Logger {
public:
    static void setFile(const std::string& path);
    static const std::string& file();

    static void info(const std::string& msg)  { write("INFO ", msg); }
    static void warn(const std::string& msg)  { write("WARN ", msg); }
    static void error(const std::string& msg) { write("ERROR", msg); }

    static int entriesWritten() { return entries; }

    // Reads the whole log back (for the Log tab). Throws FileException.
    static std::string readAll();

private:
    static void write(const std::string& level, const std::string& msg);

    static std::string filePath; // static data members (Unit I)
    static int entries;
};

} // namespace cyber
