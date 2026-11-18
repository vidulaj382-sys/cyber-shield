#pragma once
// Undo / redo for device changes.
// Every change (add, remove, edit) is a small COMMAND object that knows how to
// do itself and how to undo itself. SecurityManager keeps two stacks of them:
// the undo stack and the redo stack.
// Unit II: abstract class + pure virtual functions + polymorphism.
// (Four small related classes live in this one file pair.)
#include <set>
#include <string>

#include "Asset.h"
#include "Repository.h"

namespace cyber {

// A plain copy of everything about a device (so it can be rebuilt later).
struct AssetSpec {
    int id = 0;                 // 0 = no id known yet
    std::string type, name, ip, extra;
    int criticality = 3;
    std::set<std::string> passed;

    static AssetSpec of(const Asset& asset);
    Asset* build() const;                  // makes a NEW device of the right kind (caller owns it)
    void applyTo(Asset& asset) const;      // copies name, ip, level, extra and checklist into it
};

class AssetCommand {
public:
    virtual ~AssetCommand() = default;
    virtual void execute(Repository<Asset>& assets) = 0;
    virtual void undo(Repository<Asset>& assets) = 0;
    virtual std::string describe() const = 0;
};

// "Added device X"
class AddAssetCommand : public AssetCommand {
public:
    // The spec describes a device that was ALREADY added.
    explicit AddAssetCommand(const AssetSpec& spec) : spec(spec) {}
    void execute(Repository<Asset>& assets) override; // used by redo: adds it again
    void undo(Repository<Asset>& assets) override;
    std::string describe() const override { return "adding " + spec.name; }

private:
    AssetSpec spec;
};

// "Removed device X"
class RemoveAssetCommand : public AssetCommand {
public:
    explicit RemoveAssetCommand(const Asset& asset) : spec(AssetSpec::of(asset)) {}
    void execute(Repository<Asset>& assets) override;
    void undo(Repository<Asset>& assets) override;
    std::string describe() const override { return "removing " + spec.name; }

private:
    AssetSpec spec;
};

// "Changed device X"
class EditAssetCommand : public AssetCommand {
public:
    EditAssetCommand(int id, const AssetSpec& before, const AssetSpec& after)
        : id(id), before(before), after(after) {}
    void execute(Repository<Asset>& assets) override;
    void undo(Repository<Asset>& assets) override;
    std::string describe() const override { return "changing " + before.name; }

private:
    int id;
    AssetSpec before, after;
};

} // namespace cyber
