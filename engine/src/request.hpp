//
// Engine-internal: parsing the JSON requests of the engine contract. Requests are strict: an unknown
// key is an error, so a misspelled option never silently changes what a read returns or what a plan
// does. Every helper throws Failure(usage) and names the offending field.
//

#ifndef FORTI_ENGINE_REQUEST_HPP
#define FORTI_ENGINE_REQUEST_HPP

#include <forti/engine/error.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace forti::engine::detail {

    // `what` names the request or sub-object in messages ("read", "operations[2]").
    inline void allow_keys(const nlohmann::json& object, std::initializer_list<std::string_view> allowed,
                           std::string_view what) {
        if (!object.is_object()) throw Failure(Code::usage, std::format("{}: expected a JSON object", what));
        std::vector<std::string> unknown;
        for (auto it = object.begin(); it != object.end(); ++it)
            if (std::ranges::find(allowed, std::string_view(it.key())) == allowed.end()) unknown.push_back(it.key());
        if (!unknown.empty()) {
            std::string list;
            for (const auto& key: unknown) list += (list.empty() ? "" : ", ") + key;
            throw Failure(Code::usage, std::format("{}: unknown field(s): {}", what, list),
                          {{"unknown", unknown}, {"allowed", allowed}});
        }
    }

    inline std::string field_name(std::string_view what, const char* key) {
        return what.empty() ? std::format("\"{}\"", key) : std::format("{}: \"{}\"", what, key);
    }

    // A string field ("" when absent or null). Integers are accepted as their decimal text (keys).
    inline std::string text(const nlohmann::json& object, const char* key, std::string_view what = {}) {
        auto it = object.find(key);
        if (it == object.end() || it->is_null()) return {};
        if (it->is_string()) return it->get<std::string>();
        if (it->is_number_integer()) return it->dump();
        throw Failure(Code::usage, field_name(what, key) + " must be a string");
    }

    inline std::size_t number(const nlohmann::json& object, const char* key, std::size_t fallback) {
        auto it = object.find(key);
        if (it == object.end() || it->is_null()) return fallback;
        if (!it->is_number_unsigned() && !(it->is_number_integer() && it->get<long long>() >= 0))
            throw Failure(Code::usage, field_name({}, key) + " must be a non-negative integer");
        return it->get<std::size_t>();
    }

    // A string or an array of strings.
    inline std::vector<std::string> strings(const nlohmann::json& object, const char* key) {
        auto it = object.find(key);
        if (it == object.end() || it->is_null()) return {};
        if (it->is_string()) return {it->get<std::string>()};
        if (!it->is_array()) throw Failure(Code::usage, field_name({}, key) + " must be a string or an array of strings");
        std::vector<std::string> out;
        for (const auto& item: *it) {
            if (!item.is_string()) throw Failure(Code::usage, field_name({}, key) + " must contain only strings");
            out.push_back(item.get<std::string>());
        }
        return out;
    }

    inline bool flag(const nlohmann::json& object, const char* key) {
        auto it = object.find(key);
        if (it == object.end() || it->is_null()) return false;
        if (!it->is_boolean()) throw Failure(Code::usage, field_name({}, key) + " must be true or false");
        return it->get<bool>();
    }

    inline void validate_vdom(std::string_view vdom) {
        bool valid = vdom.size() <= 31;
        for (char c: vdom) valid = valid && (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.');
        if (!valid) throw Failure(Code::usage, std::format("invalid VDOM name: {}", vdom));
    }

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_REQUEST_HPP
