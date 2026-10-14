#include <forti/engine/error.hpp>

#include <forti_api/client.hpp>

namespace forti::engine {

    std::string_view to_string(Code code) {
        switch (code) {
            case Code::internal: return "internal";
            case Code::usage: return "usage";
            case Code::config: return "config";
            case Code::connection: return "connection";
            case Code::auth: return "auth";
            case Code::not_found: return "not_found";
            case Code::unknown_resource: return "unknown_resource";
            case Code::validation: return "validation";
            case Code::api: return "api";
            case Code::stale_plan: return "stale_plan";
            case Code::approval_required: return "approval_required";
            case Code::policy_denied: return "policy_denied";
            case Code::partial_failure: return "partial_failure";
            case Code::management_connectivity_lost: return "management_connectivity_lost";
            case Code::outcome_unknown: return "outcome_unknown";
        }
        return "internal";
    }

    int exit_code(Code code) {
        switch (code) {
            case Code::internal: return 1;
            case Code::usage: return 2;
            case Code::config: return 3;
            case Code::connection:
            case Code::auth: return 4;
            case Code::not_found:
            case Code::unknown_resource: return 5;
            case Code::validation:
            case Code::api: return 6;
            case Code::stale_plan:
            case Code::approval_required:
            case Code::policy_denied: return 7;
            case Code::partial_failure:
            case Code::management_connectivity_lost:
            case Code::outcome_unknown: return 8;
        }
        return 1;
    }

    nlohmann::json Failure::to_json() const {
        nlohmann::json out = {{"code", to_string(code_)}, {"message", what()}};
        if (!details_.empty()) out["details"] = details_;
        return out;
    }

    namespace {

        nlohmann::json api_details(const fortiapi::ApiError& error) {
            nlohmann::json details = {{"method", fortiapi::to_string(error.method())},
                                      {"path", error.path()},
                                      {"http_status", error.http_status()}};
            if (int code = error.fortios_error()) details["fortios_error"] = code;
            const auto& body = error.body();
            if (body.is_object()) {
                if (auto it = body.find("cli_error"); it != body.end()) details["cli_error"] = *it;
                if (auto it = body.find("error"); it != body.end() && it->is_string()) details["error"] = *it;
            }
            return details;
        }

    }  // namespace

    Failure translate(std::exception_ptr error) {
        try {
            std::rethrow_exception(error);
        } catch (const Failure& failure) {
            return failure;
        } catch (const fortiapi::ApiError& api) {
            long status = api.http_status();
            Code code = status == 401 || status == 403 ? Code::auth : status == 404 ? Code::not_found : Code::api;
            return {code, api.what(), api_details(api)};
        } catch (const fortiapi::TransportError& transport) {
            return {Code::connection, transport.what(),
                    {{"curl_code", transport.code()}, {"before_send", transport.before_send()}}};
        } catch (const fortiapi::DecodeError& decode) {
            return {Code::api, decode.what(), {{"decode", true}}};
        } catch (const fortiapi::Error& sdk) {
            return {Code::config, sdk.what()};
        } catch (const nlohmann::json::exception& json) {
            return {Code::usage, std::string("invalid JSON: ") + json.what()};
        } catch (const std::exception& other) {
            return {Code::internal, other.what()};
        } catch (...) {
            return {Code::internal, "unknown error"};
        }
    }

}  // namespace forti::engine
