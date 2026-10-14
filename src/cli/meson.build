cli_sources = files(
    'args.cpp',
    'commands.cpp',
    'commands_install.cpp',
    'commands_plan.cpp',
    'commands_read.cpp',
    'commands_setup.cpp',
    'main.cpp',
    'output.cpp',
)

forti_exe = executable('forti', cli_sources,
                       cpp_args : ['-DFORTI_VERSION="@0@"'.format(meson.project_version())],
                       dependencies : forti_engine_dep,
                       implicit_include_directories : false,
                       install : true)
