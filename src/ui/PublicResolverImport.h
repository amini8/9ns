#pragma once

#include <optional>
#include <string>
#include <vector>

#include "core/Config.h"
#include "web/PublicResolversLoader.h"

namespace resolvers {

bool resolverCandidate(const PublicDnsItem& item, UpstreamConfig& upstream, std::string& error);

// Output is replaced only after the entire selection and resulting configuration validate.
bool importCandidate(const Config& original, const std::vector<PublicDnsItem>& selection,
                     const std::optional<std::string>& poolName, Config& candidate, std::string& error);

}  // namespace resolvers
