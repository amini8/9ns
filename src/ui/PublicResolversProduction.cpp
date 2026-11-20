#include "ui/PublicResolversDialog.h"

#include "transports/Upstream.h"

namespace {

PublicResolversDialog::Services productionServices() {
    PublicResolversDialog::Services services;
    services.load = [](bool refresh, std::string& error) { return resolvers::loadAll(refresh, error); };
    services.probe = [](const UpstreamConfig& config, uint32_t& rttMs, std::string& error) {
        auto upstream = Upstream::create(config);
        return upstream->ping(rttMs, error);
    };
    return services;
}

}  // namespace

PublicResolversDialog::PublicResolversDialog(Config& config, QWidget* parent)
    : PublicResolversDialog(config, productionServices(), parent) {}
