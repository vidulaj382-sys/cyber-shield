#include "Vault.h"
#include "XorCipher.h"
#include "Exceptions.h"
#include "Logger.h"
#include "PasswordEntry.h"
#include "SecureNote.h"
#include "Utils.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <vector>

namespace cyber {

namespace {
const char kMagic[4] = {'C', 'S', 'V', '1'}; // first bytes of every Safe Box file

// Reads one item (its type number, then its fields) from the decrypted bytes.
VaultItem* readItem(const std::string& data, std::size_t& pos) {
    std::uint32_t type = bytes::getNumber(data, pos);
    if (type == 1) {
        std::string title = bytes::getText(data, pos);
        std::string text = bytes::getText(data, pos);
        return new SecureNote(title, text);
    }
    if (type == 2) {
        std::string site = bytes::getText(data, pos);
        std::string user = bytes::getText(data, pos);
        std::string pass = bytes::getText(data, pos);
        return new PasswordEntry(site, user, pass);
    }
    throw FileException("safe box", "the file is damaged (unknown item type)");
}
} // namespace

Vault::Vault(const std::string& filePath) : filePath(filePath) {}

Vault::~Vault() { lock(); }

bool Vault::exists() const {
    std::ifstream in(filePath, std::ios::binary);
    return in.good();
}

void Vault::checkSecretPassword(const std::string& secretPassword) {
    if (secretPassword.size() < 4)
        throw ValidationException("the secret password needs at least 4 characters");
}

void Vault::requireUnlocked() const {
    if (!unlocked)
        throw VaultLockedException();
}

// ---- lock / unlock --------------------------------------------------------

void Vault::create(const std::string& secretPassword) {
    if (exists())
        throw ValidationException("a Safe Box already exists - unlock it instead");
    checkSecretPassword(secretPassword);
    entries.clear();
    key = secretPassword;
    unlocked = true;
    save();
    Logger::info("A Safe Box was created");
}

void Vault::unlock(const std::string& secretPassword) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
        throw FileException(filePath, "there is no Safe Box yet - create one first");
    std::string file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    if (file.size() < 4 || !std::equal(kMagic, kMagic + 4, file.begin()))
        throw FileException(filePath, "this is not a Safe Box file");

    std::size_t pos = 4;
    std::string storedHash = bytes::getText(file, pos);
    std::string scrambled = bytes::getText(file, pos);

    if (storedHash != util::hashPassword(secretPassword)) {
        Logger::warn("Wrong Safe Box password was tried");
        throw AuthException("that is not the right secret password");
    }

    // Unscramble, then build the items. Nothing changes until everything worked.
    std::string plain = XorCipher(secretPassword).decrypt(scrambled);
    std::vector<VaultItem*> loaded;
    try {
        std::size_t at = 0;
        std::uint32_t count = bytes::getNumber(plain, at);
        for (std::uint32_t i = 0; i < count; ++i)
            loaded.push_back(readItem(plain, at));
    } catch (...) {
        for (VaultItem* item : loaded) // clean up, then pass the error on (stack unwinding)
            delete item;
        throw;
    }

    entries.clear();
    for (VaultItem* item : loaded)
        entries.add(item);
    key = secretPassword;
    unlocked = true;
    Logger::info("The Safe Box was unlocked");
}

void Vault::lock() {
    entries.clear();
    std::fill(key.begin(), key.end(), '\0'); // overwrite the secret before forgetting it
    key.clear();
    if (unlocked)
        Logger::info("The Safe Box was locked");
    unlocked = false;
}

// ---- items -----------------------------------------------------------------

void Vault::addNote(const std::string& title, const std::string& text) {
    requireUnlocked();
    entries.add(new SecureNote(title, text));
    save();
}

void Vault::addPassword(const std::string& site, const std::string& username,
                        const std::string& password) {
    requireUnlocked();
    entries.add(new PasswordEntry(site, username, password));
    save();
}

void Vault::removeItem(int id) {
    requireUnlocked();
    if (!entries.remove(id))
        throw NotFoundException("Safe Box item #" + std::to_string(id));
    save();
}

const Repository<VaultItem>& Vault::items() const {
    requireUnlocked();
    return entries;
}

// ---- saving ------------------------------------------------------------------

void Vault::save() const {
    std::string plain;
    bytes::putNumber(plain, static_cast<std::uint32_t>(entries.size()));
    for (const VaultItem* item : entries) {
        bytes::putNumber(plain, static_cast<std::uint32_t>(item->typeCode()));
        item->write(plain);
    }

    std::string file(kMagic, sizeof kMagic);
    bytes::putText(file, util::hashPassword(key));    // lets us check the password later
    bytes::putText(file, XorCipher(key).encrypt(plain));  // the scrambled items

    std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
    if (!out)
        throw FileException(filePath, "cannot open the Safe Box file for writing");
    out.write(file.data(), static_cast<std::streamsize>(file.size()));
    if (!out)
        throw FileException(filePath, "writing the Safe Box failed");
}

} // namespace cyber
