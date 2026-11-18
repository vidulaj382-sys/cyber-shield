#pragma once
// One saved password: website, user name and the password itself.
#include "VaultItem.h"

namespace cyber {

class PasswordEntry : public VaultItem {
public:
    PasswordEntry(const std::string& site, const std::string& username,
                  const std::string& password);

    int typeCode() const override { return 2; }
    std::string kind() const override { return "Password"; }
    std::string summary() const override;
    std::string detail(bool showSecret) const override;
    void write(std::string& out) const override;

    // Static helpers (no object needed).
    static std::string strength(const std::string& password); // Weak / OK / Strong
    static std::string generate(int length = 12);             // a random strong password

private:
    std::string username;
    std::string password;
};

} // namespace cyber
