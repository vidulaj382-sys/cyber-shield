#pragma once
// A secret document: a title and some text.
#include "VaultItem.h"

namespace cyber {

class SecureNote : public VaultItem {
public:
    SecureNote(const std::string& title, const std::string& text);

    int typeCode() const override { return 1; }
    std::string kind() const override { return "Note"; }
    std::string summary() const override { return getName(); }
    std::string detail(bool showSecret) const override;
    void write(std::string& out) const override;

private:
    std::string text;
};

} // namespace cyber
