//
// Engine-internal: builds SDK clients from profiles. Engine::client() caches one per profile; apply's
// management connectivity probe needs a fresh one (new connection, no reused TLS session), so the
// construction lives here once.
//

#ifndef FORTI_ENGINE_SESSION_HPP
#define FORTI_ENGINE_SESSION_HPP

#include <forti/engine/engine.hpp>

#include <forti_api/client.hpp>

#include <memory>
#include <optional>

namespace forti::engine::detail {

    // A new client for `profile`; secrets are resolved now. `retries` overrides Config::retries.
    std::shared_ptr<fortiapi::Client> make_client(const Options& options, SecretStore& secrets, const Profile& profile,
                                                  std::optional<unsigned> retries = std::nullopt);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_SESSION_HPP
