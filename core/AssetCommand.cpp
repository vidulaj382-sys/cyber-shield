#include "AssetCommand.h"
#include "Exceptions.h"

namespace cyber {

// ---- AssetSpec -----------------------------------------------------------

AssetSpec AssetSpec::of(const Asset& asset) {
    AssetSpec spec;
    spec.id = asset.getId();
    spec.type = asset.type();
    spec.name = asset.getName();
    spec.ip = asset.getIp();
    spec.extra = asset.extraInfo();
    spec.criticality = asset.getCriticality();
    spec.passed = asset.passedChecks();
    return spec;
}

Asset* AssetSpec::build() const {
    Asset* asset = nullptr;
    if (type == "Server")
        asset = new Server(name, ip, criticality, extra);
    else if (type == "Router")
        asset = new Router(name, ip, criticality, extra);
    else
        asset = new Workstation(name, ip, criticality, extra);
    asset->setPassedChecks(passed);
    if (id > 0)
        asset->restoreId(id); // the rebuilt device keeps its old id
    return asset;
}

void AssetSpec::applyTo(Asset& asset) const {
    asset.setName(name);
    asset.setIp(ip);
    asset.setCriticality(criticality);
    asset.setExtraInfo(extra);
    asset.setPassedChecks(passed);
}

namespace {
Asset& find(Repository<Asset>& assets, int id) {
    Asset* asset = assets.findById(id);
    if (asset == nullptr)
        throw NotFoundException("device #" + std::to_string(id));
    return *asset;
}
} // namespace

// ---- Add -------------------------------------------------------------------

void AddAssetCommand::execute(Repository<Asset>& assets) {
    assets.add(spec.build());
}

void AddAssetCommand::undo(Repository<Asset>& assets) {
    spec = AssetSpec::of(find(assets, spec.id)); // remember its latest state for a redo
    assets.remove(spec.id);
}

// ---- Remove ------------------------------------------------------------------

void RemoveAssetCommand::execute(Repository<Asset>& assets) {
    spec = AssetSpec::of(find(assets, spec.id));
    assets.remove(spec.id);
}

void RemoveAssetCommand::undo(Repository<Asset>& assets) {
    assets.add(spec.build());
}

// ---- Edit ----------------------------------------------------------------------

void EditAssetCommand::execute(Repository<Asset>& assets) {
    after.applyTo(find(assets, id));
}

void EditAssetCommand::undo(Repository<Asset>& assets) {
    before.applyTo(find(assets, id));
}

} // namespace cyber
