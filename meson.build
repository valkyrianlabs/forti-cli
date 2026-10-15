project('forti-cli', 'cpp',
        version : '0.1.0',
        meson_version : '>=1.3.0',
        license : 'MIT',
        default_options : ['warning_level=3', 'cpp_std=c++23', 'buildtype=release', 'optimization=s',
                           'b_ndebug=if-release', 'forti-api:tests=disabled'])

# Release profile (.claude/context/release.md, "Build profile" has the measurements). Size-optimized:
# the executable is mostly instantiated SDK code that runs once per request against a network API,
# so -O3 buys nothing measurable but nearly doubles the binary (Apple clang 21, stripped: 23.5 MB at
# -O3, 12.4 MB at optimization=s, which meson maps to -Oz on clang and -Os on GCC) and compiles
# slower with more memory per shard. `--buildtype=release` keeps optimization=s (set here, not implied
# by the build type); debug and debugoptimized builds are unaffected. No LTO by default: full LTO
# saves another 5 MB for a 78 s, 5.9 GB link, and thin LTO is clang-only.
#
# On ELF targets, non-debug builds also garbage-collect unreferenced sections. (Mach-O links atom by
# atom already; -dead_strip measured under 1% there, so there is no Darwin branch.)
cxx = meson.get_compiler('cpp')
if not get_option('debug') and host_machine.system() != 'darwin' and cxx.has_link_argument('-Wl,--gc-sections')
    add_project_arguments('-ffunction-sections', '-fdata-sections', language : 'cpp')
    add_project_link_arguments('-Wl,--gc-sections', language : 'cpp')
endif

# forti-api is the only FortiOS implementation. A system install (pkg-config forti-api) wins; the
# wrap is the source-build fallback.
forti_api_dep = dependency('forti-api', version : '>=1.0.1')

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
