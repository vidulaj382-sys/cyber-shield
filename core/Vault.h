#pragma once
// The Safe Box: secret notes and saved passwords, locked with ONE secret password.
//  - While locked, nothing can be read and nothing is kept in memory.
//  - On disk everything is scrambled (XorCipher) and written as a binary file.
// Uses the class template Repository<T> to own the items.
#include <string>

#include "Repository.h"
#include "VaultItem.h"

namespace cyber {

class Vault {
public:
    explicit Vault(const std::string& filePath);
    ~Vault();

    // The vault owns heap objects, so it must not be copied.
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    bool exists() const;                      // has a Safe Box file been created yet?
    bool isUnlocked() const { return unlocked; }

    void create(const std::string& secretPassword);  // first time only
    void unlock(const std::string& secretPassword);  // throws AuthException if wrong
    void lock();                                     // forget everything in memory

    void addNote(const std::string& title, const std::string& text);
    void addPassword(const std::string& site, const std::string& username,
                     const std::string& password);
    void removeItem(int id);

    const Repository<VaultItem>& items() const;      // throws if locked

private:
    void requireUnlocked() const;
    void save() const;
    static void checkSecretPassword(const std::string& secretPassword);

    std::string filePath;
    bool unlocked = false;
    std::string key;                 // the secret password, only while unlocked
    Repository<VaultItem> entries;
};

} // namespace cyber
