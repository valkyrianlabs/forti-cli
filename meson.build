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
elif get_option('subproject_cli')
    # forti-mcp's integration tests drive `forti` too (approvals, shared state). Built, never installed.
    subdir('src')
endif

# The mock FortiOS server and test harness (Python 3 stdlib), for consumers' integration tests:
# subproject('forti-cli').get_variable('mock_fortios_dir').
mock_fortios_dir = meson.current_source_dir() / 'tests' / 'mock-fortios'
