#pragma once
// "Concepts on this page": for every page, a list of the OOP concepts used,
// WHERE in the code they are, and WHAT they are used for.
// Handy for explaining the project to a teacher.
#include <string>

namespace conceptguide {

// Returns a small HTML page (for Fl_Help_View) describing the page with this title.
std::string htmlFor(const std::string& pageTitle);

} // namespace conceptguide
