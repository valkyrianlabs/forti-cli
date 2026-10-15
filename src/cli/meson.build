# Everything but main() is a static library, so tests drive the whole CLI (cli::run) in-process.
cli_sources = files(
    'app.cpp',
    'args.cpp',
    'commands.cpp',
    'commands_install.cpp',
    'commands_plan.cpp',
    'commands_read.cpp',
    'commands_setup.cpp',
    'output.cpp',
)

forti_cli_lib = static_library('forti-cli', cli_sources,
                               cpp_args : ['-DFORTI_VERSION="@0@"'.format(meson.project_version())],
                               dependencies : [forti_engine_dep, forti_install_dep],
                               implicit_include_directories : false)

forti_cli_dep = declare_dependency(include_directories : include_directories('.'),
                                   link_with : forti_cli_lib,
                                   dependencies : [forti_engine_dep, forti_install_dep])

forti_exe = executable('forti', 'main.cpp',
                       dependencies : forti_cli_dep,
                       implicit_include_directories : false,
                       install : not meson.is_subproject())
