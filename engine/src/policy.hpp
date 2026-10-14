//
// Engine-internal execution policy: which operations a resource supports and how risky a change to it
// is (architecture.md, "Mutation safety model"). Discovery reports these; plan/apply enforce them.
//

#ifndef FORTI_ENGINE_POLICY_HPP
#define FORTI_ENGINE_POLICY_HPP

#include <forti/engine/catalog.hpp>

#include <string_view>
#include <vector>

namespace forti::engine::detail {

    enum class Risk { low, elevated, critical };

    std::string_view to_string(Risk risk);

    // Mutating operations the resource supports: create/update/delete (tables), update (singletons),
    // action (monitor POST). Reads are always supported.
    std::vector<std::string_view> write_operations(const Resource& resource);

    // Risk of changing `resource`. Monitor actions are never below elevated (forti-api gap G6: their
    // side effects are not catalogued).
    Risk risk_of(const Resource& resource);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_POLICY_HPP
