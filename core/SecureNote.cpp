#include "SecureNote.h"
#include "Exceptions.h"

namespace cyber {

SecureNote::SecureNote(const std::string& title, const std::string& text)
    : VaultItem(title), text(text) {
    if (title.empty())
        throw ValidationException("give your note a title");
    if (text.size() > 5000)
        throw ValidationException("a note can have at most 5000 characters");
}

std::string SecureNote::detail(bool) const { // notes have no hidden part
    return name + "\n\n" + text;
}

void SecureNote::write(std::string& out) const {
    bytes::putText(out, name);
    bytes::putText(out, text);
}

} // namespace cyber
