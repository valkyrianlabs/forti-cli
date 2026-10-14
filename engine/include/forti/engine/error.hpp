//
// forti::engine::Failure: the one error type front-ends see. Every SDK exception (ApiError,
// TransportError, DecodeError) is translated into a stable code, a message and structured details.
// Nothing here may carry a credential: messages come from the SDK (which never includes the API key)
// or from the engine itself.
//

#ifndef FORTI_ENGINE_ERROR_HPP
#define FORTI_ENGINE_ERROR_HPP

#include <nlohmann/json.hpp>

#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>

namespace forti::engine {

    enum class Code {
        internal,           // a bug or an unexpected state
        usage,              // malformed request or arguments
        config,             // missing/invalid profile, credentials or config file
        connection,         // DNS, connect, TLS, timeout: no usable reply
        auth,               // HTTP 401/403
        not_found,          // the object does not exist
        unknown_resource,   // the path is not a known resource
        validation,         // schema violation: unknown/read-only attribute, undecodable value
        api,                // any other FortiOS error
        stale_plan,         // the device changed since the plan was made
        approval_required,  // apply without a valid human approval
        policy_denied,      // the profile or risk policy forbids the operation
        partial_failure,    // apply stopped part-way
        outcome_unknown,    // a mutation may or may not have reached the device
    };

    std::string_view to_string(Code code);

    // Process exit status for the CLI (architecture.md, "Error codes and CLI exit codes").
    int exit_code(Code code);

    class Failure : public std::runtime_error {
        Code code_;
        nlohmann::json details_;

    public:
        Failure(Code code, const std::string& message, nlohmann::json details = nlohmann::json::object())
                : std::runtime_error(message), code_(code), details_(std::move(details)) {}

        [[nodiscard]] Code code() const { return code_; }
        [[nodiscard]] const nlohmann::json& details() const { return details_; }

        // {"code": "...", "message": "...", "details": {...}}
        [[nodiscard]] nlohmann::json to_json() const;
    };

    // Translates an exception (Failure, fortiapi::*, std::exception) into a Failure. Use inside a
    // catch block: `catch (...) { auto failure = translate(std::current_exception()); }`.
    Failure translate(std::exception_ptr error);

}  // namespace forti::engine

#endif  // FORTI_ENGINE_ERROR_HPP
