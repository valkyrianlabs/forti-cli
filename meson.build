project('forti-cli', 'cpp',
        version : '0.1.0',
        meson_version : '>=1.3.0',
        license : 'MIT',
        default_options : ['warning_level=3', 'cpp_std=c++23', 'buildtype=release', 'b_ndebug=if-release'])

# forti-api is the only FortiOS implementation. A system install (pkg-config forti-api) wins; the
# wrap is the source-build fallback.
forti_api_dep = dependency('forti-api', version : '>=1.0.0')

# The command engine shared with forti-mcp, which consumes this project as a subproject and uses only
# `forti-engine`; the CLI, installers and tests are not built there.
subdir('engine')

if not meson.is_subproject()
    subdir('src')
    subdir('tests')
    install_man('doc/forti.1')
endif
