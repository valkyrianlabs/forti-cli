# `forti completion SHELL` prints the scripts in completions/, embedded at build time.
completion_scripts = custom_target('completion-scripts',
                                   input : [completion_embed, completion_bash, completion_zsh, completion_fish],
                                   output : 'completion_scripts.hpp',
                                   command : [import('python').find_installation(), '@INPUT0@', '@OUTPUT@',
                                              'bash=@INPUT1@', 'zsh=@INPUT2@', 'fish=@INPUT3@'])

cli_sources = files(
    'app.cpp',
    'args.cpp',
    'certs.cpp',
    'commands.cpp',
    'commands_cert.cpp',
    'commands_history.cpp',
    'commands_home.cpp',
    'commands_install.cpp',
    'commands_plan.cpp',
    'commands_read.cpp',
    'commands_setup.cpp',
    'completion.cpp',
    'output.cpp',
    'setup_support.cpp',
    'tty.cpp',
)

# Everything but main() is a static library, so tests drive the whole CLI (cli::run) in-process.
forti_cli_lib = static_library('forti-cli', cli_sources, completion_scripts,
                               cpp_args : ['-DFORTI_VERSION="@0@"'.format(meson.project_version())],
                               dependencies : [forti_engine_dep, forti_install_dep],
                               include_directories : include_directories('.'),
                               implicit_include_directories : false)

forti_cli_dep = declare_dependency(include_directories : include_directories('.'),
                                   link_with : forti_cli_lib,
                                   dependencies : [forti_engine_dep, forti_install_dep])

forti_exe = executable('forti', 'main.cpp',
                       dependencies : forti_cli_dep,
                       implicit_include_directories : false,
                       install : not meson.is_subproject())
