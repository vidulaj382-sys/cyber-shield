#pragma once
// Unit II: abstract base class for everything that can live in the Safe Box.
// SecureNote and PasswordEntry are the two concrete kinds.
#include <cstdint>
#include <string>
#include "Entity.h"

namespace cyber {

// Tiny helpers that write / read numbers and text as bytes (binary file I/O).
namespace bytes {
void putNumber(std::string& out, std::uint32_t value);
void putText(std::string& out, const std::string& text);
std::uint32_t getNumber(const std::string& in, std::size_t& pos); // throws FileException
std::string getText(const std::string& in, std::size_t& pos);     // throws FileException
} // namespace bytes

class VaultItem : public Entity {
public:
    explicit VaultItem(const std::string& name) : Entity(name) {}
    ~VaultItem() override = default;

    virtual int typeCode() const = 0;                    // 1 = note, 2 = password
    virtual std::string kind() const = 0;                // "Note" or "Password"
    virtual std::string summary() const = 0;             // one line for the list
    virtual std::string detail(bool showSecret) const = 0; // full text for the viewer
    virtual void write(std::string& out) const = 0;      // adds the fields as bytes
};

} // namespace cyber
