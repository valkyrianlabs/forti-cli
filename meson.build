project('forti-cli', 'cpp',
        version : '0.3.1',
        meson_version : '>=1.3.0',
        license : 'MIT',
        default_options : ['warning_level=3', 'cpp_std=c++23', 'buildtype=release', 'b_ndebug=if-release', 'forti-api:tests=disabled'])

# Release builds (packages, the release workflow) are buildtype=release: -O3, tested as built.
# Pull-request CI builds unoptimized (-O0) and tests that build (.github/workflows/ci.yml).
cxx = meson.get_compiler('cpp')
if not get_option('debug') and host_machine.system() != 'darwin' and cxx.has_link_argument('-Wl,--gc-sections')
    add_project_arguments('-ffunction-sections', '-fdata-sections', language : 'cpp')
    add_project_link_arguments('-Wl,--gc-sections', language : 'cpp')
endif

# Nothing here is a shared library, so nothing needs exporting. With default visibility every
# `inline constexpr` table of forti-api's runtime schema is a weak exported symbol, and dyld coalesced
# about 13,000 of them on every start (25 ms of a 27 ms `forti --version`); hidden, the static linker
# settles them once.
add_project_arguments(cxx.get_supported_arguments('-fvisibility=hidden', '-fvisibility-inlines-hidden'), language : 'cpp')

# forti-api is the only FortiOS implementation. A system install (pkg-config forti-api) wins; the
# wrap is the source-build fallback.
forti_api_dep = dependency('forti-api', version : '>=1.1.0')

# The command engine shared with forti-mcp, which consumes this project as a subproject and uses only
# `forti-engine`; the CLI, installers and tests are not built there.
subdir('engine')

if not meson.is_subproject()
    subdir('completions')
    subdir('src')
    subdir('tests')
    install_man('doc/forti.1')
elif get_option('subproject_cli')
    # forti-mcp's integration tests drive `forti` too (approvals, shared state). Built, never installed.
    subdir('completions')
    subdir('src')
endif

# The mock FortiOS server and test harness (Python 3 stdlib), for consumers' integration tests:
# subproject('forti-cli').get_variable('mock_fortios_dir').
mock_fortios_dir = meson.current_source_dir() / 'tests' / 'mock-fortios'
