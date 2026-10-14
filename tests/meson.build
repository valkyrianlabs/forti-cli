# Network-free tests (CI runs them; nothing here talks to a FortiGate). The engine is exercised
# through a scripted fortiapi::Transport (support/fake_transport.hpp).
gtest_dep = dependency('gtest', main : true, required : get_option('tests'))
if gtest_dep.found()
    test('unit', executable('unitTests',
                            'unit/test_catalog.cpp',
                            'unit/test_read.cpp',
                            'unit/test_profiles.cpp',
                            'unit/test_plan.cpp',
                            # test_plan.cpp also checks engine internals (SHA-256 vectors, digests, redaction).
                            include_directories : include_directories('support', '../engine/src'),
                            dependencies : [forti_engine_dep, gtest_dep],
                            implicit_include_directories : false),
         suite : 'unit')

    # The CLI in-process (cli::run): arguments, configure, profiles, doctor, rendering, exit codes.
    # test_keychain.cpp runs only with FORTI_TEST_KEYCHAIN=1 (it writes to the login keychain).
    test('cli', executable('cliTests',
                           'unit/test_cli.cpp',
                           'unit/test_setup.cpp',
                           'unit/test_keychain.cpp',
                           include_directories : include_directories('support'),
                           dependencies : [forti_cli_dep, gtest_dep],
                           implicit_include_directories : false),
         suite : 'unit')

    # src/install: .mcp.json and config.toml edits, and the client adapters against fake
    # `claude`/`codex` scripts (no real client, no real home directory).
    test('install', executable('installTests',
                               'install/test_files.cpp',
                               'install/test_adapters.cpp',
                               dependencies : [forti_install_dep, gtest_dep],
                               implicit_include_directories : false),
         suite : 'unit', timeout : 120)
endif

# Real binaries end to end: `forti` through libcurl and verified TLS against a stateful mock FortiOS
# (mock-fortios/, Python 3 stdlib + openssl; skipped when openssl is missing). Plus a static check that
# no code outside forti-api builds URLs or talks HTTP, sockets, DNS or TLS.
python3 = find_program('python3', required : false)
if python3.found() and not get_option('tests').disabled()
    test('cli-e2e', python3, args : [files('integration/test_cli.py')],
         env : {'FORTI_BINARY' : forti_exe.full_path(), 'PYTHONDONTWRITEBYTECODE' : '1'},
         depends : forti_exe, suite : 'integration', timeout : 300)
    test('no-second-http-stack', python3,
         args : [files('integration/scan_http.py'), '--root', meson.project_source_root() / 'engine',
                 '--root', meson.project_source_root() / 'src', '--binary', forti_exe.full_path()],
         depends : forti_exe, suite : 'integration')
else
    message('python3 not found: the integration suite is not built')
endif
