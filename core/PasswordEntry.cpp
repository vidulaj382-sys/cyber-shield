#include "PasswordEntry.h"
#include "Exceptions.h"
#include "Password.h"

#include <cctype>
#include <random>

namespace cyber {

PasswordEntry::PasswordEntry(const std::string& site, const std::string& username,
                             const std::string& password)
    : VaultItem(site), username(username), password(password) {
    if (site.empty())
        throw ValidationException("write the website or app name");
    if (password.empty())
        throw ValidationException("the password cannot be empty");
}

std::string PasswordEntry::summary() const {
    return name + "  (" + (username.empty() ? "no user name" : username) + ")";
}

std::string PasswordEntry::detail(bool showSecret) const {
    return "Website: " + name + "\nUser name: " + username + "\nPassword: " +
           (showSecret ? password : std::string(password.size(), '*')) +
           "\nStrength: " + strength(password);
}

void PasswordEntry::write(std::string& out) const {
    bytes::putText(out, name);
    bytes::putText(out, username);
    bytes::putText(out, password);
}

std::string PasswordEntry::strength(const std::string& password) {
    return Password(password).rating(); // the Password class does the scoring
}

std::string PasswordEntry::generate(int length) {
    if (length < 8 || length > 64)
        throw ValidationException("a generated password needs 8 to 64 characters");
    const std::string letters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*?";
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<std::size_t> pick(0, letters.size() - 1);
    std::string result;
    for (int i = 0; i < length; ++i)
        result += letters[pick(engine)];
    return result;
}

} // namespace cyber
