//
// `forti cert create|list|show|use|remove`: client certificates for FortiOS PKI (peer)
// authentication of the REST API user. A certificate is a named set in <home>/certs/<name>/, issued
// by the forti CA (<home>/ca/) unless --own-ca, and needs no profile: one certificate can serve
// several FortiGates. See certs.hpp for the files.
//

#include "certs.hpp"
#include "commands.hpp"
#include "setup_support.hpp"

#include <algorithm>
#include <format>
#include <ostream>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;
    using engine::Profile;
    using engine::ProfileSet;
    using engine::ProfileStore;
    using engine::SecretRef;
    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        constexpr unsigned default_days = 1095;

        // How to read the password, as a command to copy (the password itself is never printed).
        std::string password_command(const Profile& profile, const engine::Paths& paths, std::string_view store_kind) {
            switch (profile.cert_password.source) {
                case SecretRef::Source::file: return "cat " + shell_path(profile.cert_password.path);
                case SecretRef::Source::store:
                    if (store_kind == "keychain")
                        return shell_join({"security", "find-generic-password", "-s", "forti", "-a", profile.cert_password_account(), "-w"});
                    if (store_kind == "file") {
                        std::string account = profile.cert_password_account();
                        std::ranges::replace(account, '/', '.');
                        return "sed -n 2p " + shell_path(paths.config / "credentials" / account);
                    }
                    return "";
                default: return "";
            }
        }

        const Profile& existing_profile(const ProfileSet& set, const std::string& name) {
            engine::validate_profile_name(name);
            auto it = set.profiles.find(name);
            if (it == set.profiles.end())
                throw Failure(Code::config, std::format("no profile named \"{}\"", name),
                              {{"hint", std::format("create it first: forti configure --profile {}", name)}});
            return it->second;
        }

        // The default profile, if there is one to pick without asking.
        std::optional<std::string> default_profile(const ProfileSet& set) {
            if (set.profiles.empty()) return std::nullopt;
            try {
                return set.select("").name;
            } catch (const Failure&) {
                return std::nullopt;
            }
        }

        // The certificate a command acts on: NAME, else the one --profile (or the default profile) uses,
        // else the one named after that profile.
        std::string selected_certificate(const Args& args, const engine::Paths& paths, const ProfileSet& set, std::string_view usage) {
            if (args.positional.size() == 2) {
                certs::validate_name(args.positional[1]);
                return args.positional[1];
            }
            std::optional<std::string> profile = args.value("profile");
            if (profile) existing_profile(set, *profile);
            else profile = default_profile(set);
            if (!profile)
                throw Failure(Code::usage, std::format("name the certificate: {}", usage), {{"hint", "forti cert list shows them"}});
            const Profile& p = set.profiles.at(*profile);
            if (auto name = certs::used_by(paths, p)) return *name;
            return *profile;
        }

        // Erases `profile`'s stored certificate password when it no longer comes from the store.
        void drop_stale_password(engine::SecretStore& store, const Profile& profile, const SecretRef& before) {
            if (before.source != SecretRef::Source::store || profile.cert_password.source == SecretRef::Source::store) return;
            try {
                store.erase(profile.cert_password_account());
            } catch (const Failure&) {
                // A stale store entry is harmless: the profile no longer refers to it.
            }
        }

        void render_steps_footer(std::ostream& out, const json& data) {
            const json& fortigate = data["fortigate"];
            if (data.value("fortigate_unchanged", false)) {
                out << "\nThe FortiGate needs no change: the certificate has the same CA and CN as before.\n";
            } else {
                out << "\n" << styled("On the FortiGate (FortiOS CLI):", Style::bold) << "\n\n";
                for (const auto& step: fortigate["steps"]) out << step.get<std::string>() << "\n";
            }
            if (data.contains("profile") && data["profile"].is_string())
                out << std::format("\nThen check the connection: forti doctor --profile {}\n", data["profile"].get<std::string>());
            else
                out << std::format("\nUse it: `forti configure` offers it, or `forti cert use {} --profile NAME`.\n",
                                   data.value("name", ""));
        }

        // ---- create ----

        int run_create(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            if (args.positional.size() > 2) throw Failure(Code::usage, "usage: forti cert create [NAME] [--profile NAME]");

            // The profile it is for: --profile; or, without a NAME, the default profile (when there is one).
            std::optional<std::string> attach_to = args.value("profile");
            if (attach_to) existing_profile(set, *attach_to);
            std::string name;
            if (args.positional.size() == 2) name = args.positional[1];
            else {
                if (!attach_to) attach_to = default_profile(set);
                name = attach_to.value_or("default");
            }
            certs::validate_name(name);
            if (args.flag("keychain") && !attach_to)
                throw Failure(Code::usage, "--keychain keeps the password under a profile: pass --profile NAME");

            unsigned days = default_days;
            if (auto text = args.value("days")) {
                std::size_t value = to_count("days", *text);
                if (value == 0 || value > 36500) throw Failure(Code::usage, "--days must be between 1 and 36500");
                days = static_cast<unsigned>(value);
            }

            auto& store = context.engine.secrets();
            Profile* profile = attach_to ? &set.profiles.at(*attach_to) : nullptr;
            certs::CreateOptions options{.own_ca = args.flag("own-ca"), .days = days, .replace = args.flag("force")};
            if (args.flag("keychain"))
                options.keep_password = [&](const std::string& password) {
                    store.put(profile->cert_password_account(), password, profile->secret_binding());
                };
            json data = certs::create(paths, set, name, options);

            if (profile) {
                SecretRef before = profile->cert_password;
                if (args.flag("keychain")) {
                    profile->client_cert = certs::Set(paths, name).client_p12.string();
                    profile->cert_password = {SecretRef::Source::store, {}, {}, {}};
                } else certs::attach(*profile, paths, set, store, name);
                drop_stale_password(store, *profile, before);
                profiles.save(set);
                data["profile"] = profile->name;
                data["used_by"] = certs::describe(paths, set, name)["used_by"];
                data["password_source"] = describe_source(profile->cert_password, store.kind());
                data["password_command"] = password_command(*profile, paths, store.kind());
            } else {
                data["profile"] = nullptr;
                data["password_command"] = "cat " + shell_path(certs::Set(paths, name).client_pass);
            }
            data["fortigate"] = certs::fortigate(paths, name);

            return emit(context.output, engine::ok(std::move(data), attach_to ? json{{"profile", *attach_to}} : json::object()),
                        [](std::ostream& out, const json& data, const json&) {
                std::string expires = data.value("expires", "");
                out << styled(std::format("{} certificate \"{}\"", data.value("replaced", false) ? "Replaced" : "Created",
                                          data.value("name", "")), Style::bold)
                    << std::format(" (CN {}, issued by the {}, valid {} days{})\n", data.value("cn", ""), data.value("issuer", ""),
                                   data.value("days", 0), expires.empty() ? "" : ", until " + expires.substr(0, 10));
                if (data["profile"].is_string()) out << std::format("for profile {}\n", data["profile"].get<std::string>());
                if (data.value("forti_ca_created", false)) out << "Made the forti CA: FortiGates import it once, for every certificate it issues.\n";
                out << "\n";
                const json& files = data["files"];
                auto line = [&](std::string_view label, const std::string& key, std::string_view note) {
                    if (!files.contains(key)) return;
                    std::string path = display_path(files[key].get<std::string>());
                    if (note.empty()) out << std::format("  {:<15} {}\n", label, path);
                    else out << std::format("  {:<15} {:<44} ", label, path) << styled(note, Style::dim) << "\n";
                };
                line("CA certificate", "ca_cert", "the FortiGate imports it");
                line("CA key", "ca_key", "private: never copy it to the FortiGate");
                line("forti CA key", "forti_ca_key", "private: never copy it to the FortiGate");
                line("client cert", "client_cert", "");
                line("client bundle", "client_p12", "a profile's client_cert");
                line("password", "client_pass", "a profile's certificate password");
                if (data.contains("fingerprint_sha256"))
                    out << std::format("  {:<15} {}\n", "SHA-256", data["fingerprint_sha256"].get<std::string>());
                out << "\nThe password is never printed. ";
                std::string command = data.value("password_command", "");
                if (!command.empty()) out << "To read it:\n  " << command << "\n";
                else out << "It is in the " << data.value("password_source", "") << ".\n";
                render_steps_footer(out, data);
            });
        }

        // ---- list ----

        int run_list(Context& context, const Args& args) {
            if (args.positional.size() != 1) throw Failure(Code::usage, "usage: forti cert list");
            const auto& paths = context.engine.options().paths;
            ProfileSet set = ProfileStore(paths).load();
            json data = {{"forti_ca", certs::forti_ca(paths)}, {"certificates", certs::list(paths, set)}};
            return emit(context.output, engine::ok(std::move(data)), [](std::ostream& out, const json& data, const json&) {
                const json& ca = data["forti_ca"];
                if (ca.value("exists", false))
                    out << styled("forti CA", Style::bold) << "  " << display_path(ca.value("path", ""))
                        << std::format("  (FortiGate name {}, until {})\n", ca.value("fortigate_name", "?"), ca.value("expires", "?").substr(0, 10));
                else out << styled("forti CA", Style::bold) << "  not made yet (forti cert create makes it)\n";
                const json& list = data["certificates"];
                if (list.empty()) {
                    out << "\nNo certificates. Make one: forti cert create [NAME], or choose \"create\" in forti configure.\n";
                    return;
                }
                std::size_t width = 4;
                for (const auto& cert: list) width = std::max(width, cert.value("name", "").size());
                out << "\n" << std::format("  {:<{}}  {:<9}  {:<10}  {}\n", "NAME", width, "ISSUER", "EXPIRES", "USED BY");
                for (const auto& cert: list) {
                    std::string users;
                    for (const auto& user: cert["used_by"]) users += (users.empty() ? "" : ", ") + user.get<std::string>();
                    std::string expires = cert.value("expires", "?").substr(0, 10);
                    if (cert.value("expired", false)) expires += " EXPIRED";
                    out << std::format("  {:<{}}  {:<9}  {:<10}  {}\n", cert.value("name", ""), width, cert.value("issuer", ""), expires,
                                       users.empty() ? "-" : users);
                }
            });
        }

        // ---- show ----

        int run_show(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileSet set = ProfileStore(paths).load();
            std::string name = selected_certificate(args, paths, set, "forti cert show NAME");
            certs::Set files(paths, name);
            if (!files.exists())
                throw Failure(Code::config, std::format("no certificate named \"{}\" in {}", name, display_path(paths.certs())),
                              {{"hint", std::format("forti cert list shows them; forti cert create {} makes one", name)}});
            json data = certs::describe(paths, set, name);
            json file_list = json::object();
            for (auto [key, path]: {std::pair{"ca_cert", files.ca_cert}, std::pair{"ca_key", files.ca_key},
                                    std::pair{"client_cert", files.client_cert}, std::pair{"client_p12", files.client_p12},
                                    std::pair{"client_pass", files.client_pass}}) {
                std::error_code error;
                if (fs::exists(fs::symlink_status(path, error)))
                    file_list[key] = {{"path", path.string()}, {"mode", std::format("{:04o}", file_mode(path))}};
            }
            data["files"] = file_list;
            json users = json::array();
            for (const auto& user: data["used_by"]) {
                const Profile& profile = set.profiles.at(user.get<std::string>());
                json entry = {{"profile", profile.name},
                              {"password_source", describe_source(profile.cert_password, context.engine.secrets().kind())}};
                if (auto command = password_command(profile, paths, context.engine.secrets().kind()); !command.empty())
                    entry["password_command"] = command;
                users.push_back(entry);
            }
            data["profiles"] = users;
            return emit(context.output, engine::ok(std::move(data)), [](std::ostream& out, const json& data, const json&) {
                out << styled(std::format("Certificate \"{}\"", data.value("name", "")), Style::bold) << "  "
                    << display_path(data.value("dir", "")) << "\n\n";
                out << std::format("  {:<12} {}\n", "subject", data.value("subject", "?"));
                out << std::format("  {:<12} {}\n", "issuer", data.value("issuer", ""));
                std::string expiry = data.value("expires", "?");
                if (data.value("expired", false)) out << std::format("  {:<12} {} ", "expires", expiry) << styled("EXPIRED", Style::red) << "\n";
                else out << std::format("  {:<12} {} ({} days left)\n", "expires", expiry, data.value("days_left", 0LL));
                out << std::format("  {:<12} {}\n", "SHA-256", data.value("fingerprint_sha256", "?"));
                out << "\n  files\n";
                for (auto it = data["files"].begin(); it != data["files"].end(); ++it)
                    out << std::format("    {:<12} {}  {}\n", it.key(), it.value().value("mode", ""), display_path(it.value().value("path", "")));
                if (data["profiles"].empty()) out << "\n  not used by a profile (forti cert use NAME --profile PROFILE)\n";
                else {
                    out << "\n  used by\n";
                    for (const auto& user: data["profiles"]) {
                        out << std::format("    {:<12} password from the {}\n", user.value("profile", ""), user.value("password_source", ""));
                        if (user.contains("password_command")) out << std::format("    {:<12} read it: {}\n", "", user["password_command"].get<std::string>());
                    }
                }
            });
        }

        // ---- use ----

        int run_use(Context& context, const Args& args) {
            if (args.positional.size() != 2) throw Failure(Code::usage, "usage: forti cert use NAME [--profile PROFILE]");
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            std::string name = args.positional[1];
            std::optional<std::string> target = args.value("profile");
            if (target) existing_profile(set, *target);
            else target = default_profile(set);
            if (!target) throw Failure(Code::usage, "which profile? pass --profile NAME", {{"hint", "forti profile list shows them"}});
            Profile& profile = set.profiles.at(*target);
            auto& store = context.engine.secrets();
            SecretRef before = profile.cert_password;
            Profile updated = profile;
            updated.cert_password = {};
            if (auto password = certs::attach(updated, paths, set, store, name))
                store.put(updated.cert_password_account(), *password, updated.secret_binding());
            profile = updated;
            drop_stale_password(store, profile, before);
            profiles.save(set);
            json data = {{"name", name}, {"profile", profile.name},
                         {"password_source", describe_source(profile.cert_password, store.kind())},
                         {"fortigate", certs::fortigate(paths, name)}};
            return emit(context.output, engine::ok(std::move(data), {{"profile", profile.name}}), [](std::ostream& out, const json& data, const json&) {
                out << std::format("Profile {} now uses certificate \"{}\" (password from the {}).\n", data.value("profile", ""),
                                   data.value("name", ""), data.value("password_source", ""));
                out << "\nIf this profile's FortiGate does not accept it yet, skip what it already has of:\n";
                render_steps_footer(out, data);
            });
        }

        // ---- remove ----

        int run_remove(Context& context, const Args& args) {
            const auto& paths = context.engine.options().paths;
            ProfileStore profiles(paths);
            ProfileSet set = profiles.load();
            std::string name = selected_certificate(args, paths, set, "forti cert remove NAME");
            certs::Set files(paths, name);
            if (!files.exists())
                throw Failure(Code::config, std::format("no certificate named \"{}\" in {}", name, display_path(paths.certs())));
            // The profiles first, so none points at files that are gone.
            json detached = json::array();
            for (auto& [profile_name, profile]: set.profiles) {
                if (profile.client_cert.empty() || !path_within(profile.client_cert, files.dir)) continue;
                if (profile.cert_password.source == SecretRef::Source::store) context.engine.secrets().erase(profile.cert_password_account());
                profile.client_cert.clear();
                profile.cert_password = {};
                detached.push_back(profile_name);
            }
            if (!detached.empty()) profiles.save(set);
            std::error_code error;
            fs::remove_all(files.dir, error);
            if (error) throw Failure(Code::config, std::format("cannot remove {}: {}", files.dir.string(), error.message()));
            json data = {{"name", name}, {"removed", files.dir.string()}, {"profiles_updated", detached}};
            return emit(context.output, engine::ok(std::move(data)), [](std::ostream& out, const json& data, const json&) {
                out << std::format("Removed certificate \"{}\" ({}).\n", data.value("name", ""), display_path(data.value("removed", "")));
                for (const auto& profile: data["profiles_updated"])
                    out << std::format("Profile {} no longer uses a client certificate. If its FortiGate API user requires one\n"
                                       "(peer-auth), it cannot connect until it gets another (forti cert use NAME --profile {})\n"
                                       "or peer-auth is disabled for that API user.\n",
                                       profile.get<std::string>(), profile.get<std::string>());
            });
        }

        int run_cert(Context& context, const Args& args) {
            std::string action = args.positional.empty() ? "" : args.positional[0];
            if (action.empty()) throw Failure(Code::usage, "usage: forti cert create|list|show|use|remove (forti cert --help)");
            if (action != "create" && (args.value("days") || args.flag("force") || args.flag("keychain") || args.flag("own-ca")))
                throw Failure(Code::usage, "--days, --force, --keychain and --own-ca apply to forti cert create only");
            if (action == "create") return run_create(context, args);
            if (action == "list") return run_list(context, args);
            if (args.positional.size() > 2) throw Failure(Code::usage, std::format("usage: forti cert {} [NAME]", action));
            if (action == "show") return run_show(context, args);
            if (action == "use") return run_use(context, args);
            if (action == "remove") return run_remove(context, args);
            throw Failure(Code::usage, std::format("unknown cert action \"{}\"", action),
                          {{"hint", "forti cert create | list | show | use | remove"}});
        }

    }  // namespace

    std::vector<Command> cert_commands() {
        return {
            {"cert", "Create, list, show, use or remove client certificates",
             "usage: forti cert create [NAME] [--profile PROFILE] [--own-ca] [--days N] [--force] [--keychain]\n"
             "       forti cert list\n"
             "       forti cert show [NAME]\n"
             "       forti cert use NAME [--profile PROFILE]\n"
             "       forti cert remove [NAME]\n"
             "\n"
             "A client certificate lets FortiOS require PKI authentication from the REST API user on top of\n"
             "its API key. Certificates are named and need no profile: one certificate can serve several\n"
             "FortiGates. `forti configure` offers to create or reuse one; these commands do it directly.\n"
             "\n"
             "create makes <home>/certs/NAME/ (CN forti-NAME; client.p12 holds the certificate and its key),\n"
             "issued by the forti CA (<home>/ca/, made on\n"
             "first use: a FortiGate imports it once and trusts every certificate it issues), or with\n"
             "--own-ca by a CA of its own. NAME defaults to the profile's name. With --profile, or without\n"
             "NAME when there is a default profile, the profile uses it at once. It then prints the FortiGate\n"
             "commands, ready to paste: import the CA, create a PKI user (user peer) and a peer group, and\n"
             "enable peer-auth for the API user. The password (client.pass, 0600) is never printed. Needs\n"
             "the openssl command.\n"
             "  --profile P   the profile that uses it\n"
             "  --own-ca      a CA for this certificate only (each FortiGate imports that CA as well)\n"
             "  --days N      validity (default 1095)\n"
             "  --force       replace an existing certificate of that name (issued by the forti CA again,\n"
             "                the FortiGate needs no change: same CA, same CN)\n"
             "  --keychain    keep the password in the secret store of --profile instead of client.pass\n"
             "\n"
             "list shows the forti CA and every certificate: issuer, expiry and the profiles using it.\n"
             "show prints one (NAME, else the certificate of --profile or the default profile).\n"
             "use points a profile (--profile, else the default) at a certificate.\n"
             "remove deletes a certificate and detaches it from every profile that used it.\n",
             {{"days"}, {"force", "keychain", "own-ca"}, {}},
             run_cert},
        };
    }

}  // namespace forti::cli
