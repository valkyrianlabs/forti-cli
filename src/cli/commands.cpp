#include "commands.hpp"

#include <charconv>
#include <format>

namespace forti::cli {

    using engine::Code;
    using engine::Failure;

    OptionSpec global_options() {
        return {{"profile", "vdom"}, {"json", "help"}, {{'p', "profile"}, {'h', "help"}}};
    }

    std::size_t to_count(std::string_view name, const std::string& text) {
        std::size_t value = 0;
        auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (ec != std::errc() || end != text.data() + text.size())
            throw Failure(Code::usage, std::format("--{} expects a non-negative integer", name));
        return value;
    }

    int run_engine(Context& context, const std::function<nlohmann::json()>& operation, const Renderer& render) {
        return emit(context.output, engine::Engine::envelope(operation), render);
    }

    const std::vector<Command>& commands() {
        static const std::vector<Command> table = [] {
            std::vector<Command> all;
            for (auto group: {setup_commands, read_commands, plan_commands, install_commands})
                for (auto& command: group()) all.push_back(std::move(command));
            return all;
        }();
        return table;
    }

}  // namespace forti::cli
