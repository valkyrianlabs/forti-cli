# Network-free tests (CI runs them; nothing here talks to a FortiGate). The engine is exercised
# through a scripted fortiapi::Transport (support/fake_transport.hpp).
gtest_dep = dependency('gtest', main : true, required : get_option('tests'))

# Sanitizer builds leave the engine shards uninstrumented (engine/meson.build). libc++ annotates
# std::vector for ASan, so a vector filled by an uninstrumented shard and read by instrumented code
# is reported as a "container-overflow" that is not one. Every other ASan check stays on.
test_env = environment()
if get_option('b_sanitize').contains('address')
    test_env.set('ASAN_OPTIONS', 'detect_container_overflow=0')
endif
if gtest_dep.found()
    test('unit', executable('unitTests',
                            'unit/test_catalog.cpp',
                            'unit/test_read.cpp',
                            'unit/test_profiles.cpp',
                            'unit/test_plan.cpp',
                            'unit/test_security.cpp',
                            'unit/test_security2.cpp',
                            # test_plan.cpp also checks engine internals (SHA-256 vectors, digests, redaction).
                            include_directories : include_directories('support', '../engine/src'),
                            dependencies : [forti_engine_dep, gtest_dep],
                            implicit_include_directories : false),
         suite : 'unit', env : test_env)

    # The CLI in-process (cli::run): arguments, configure, profiles, doctor, home, cert, rendering, exit
    # codes. test_home.cpp runs `forti cert` with each local openssl (skipped when there is none).
    # test_keychain.cpp runs only with FORTI_TEST_KEYCHAIN=1 (it writes to the login keychain).
    test('cli', executable('cliTests',
                           'unit/test_cli.cpp',
                           'unit/test_setup.cpp',
                           'unit/test_home.cpp',
                           'unit/test_keychain.cpp',
                           'unit/test_cli_security.cpp',
                           'unit/test_install_cli.cpp',
                           include_directories : include_directories('support'),
                           dependencies : [forti_cli_dep, gtest_dep],
                           implicit_include_directories : false),
         suite : 'unit', env : test_env)

    # src/install: .mcp.json and config.toml edits, and the client adapters against fake
    # `claude`/`codex` scripts (no real client, no real home directory).
    test('install', executable('installTests',
                               'install/test_files.cpp',
                               'install/test_adapters.cpp',
                               'install/test_install_security.cpp',
                               'install/test_workspace.cpp',
                               dependencies : [forti_install_dep, gtest_dep],
                               implicit_include_directories : false),
         suite : 'unit', env : test_env, timeout : 120)
endif

# Real binaries end to end: `forti` through libcurl and verified TLS against a stateful mock FortiOS
# (mock-fortios/, Python 3 stdlib + openssl; skipped when openssl is missing). Plus a static check that
# no code outside forti-api builds URLs or talks HTTP, sockets, DNS or TLS.
python3 = find_program('python3', required : false)
if python3.found() and not get_option('tests').disabled()
    integration_env = environment({'FORTI_BINARY' : forti_exe.full_path(), 'PYTHONDONTWRITEBYTECODE' : '1'})
    if get_option('b_sanitize').contains('address')
        integration_env.set('ASAN_OPTIONS', 'detect_container_overflow=0')
    endif
    test('cli-e2e', python3, args : [files('integration/test_cli.py')],
         env : integration_env,
         depends : forti_exe, suite : 'integration', timeout : 300)
    test('mcp-install-e2e', python3, args : [files('integration/test_mcp_install.py')],
         env : integration_env,
         depends : forti_exe, suite : 'integration', timeout : 120)
    test('no-second-http-stack', python3,
         args : [files('integration/scan_http.py'), '--root', meson.project_source_root() / 'engine',
                 '--root', meson.project_source_root() / 'src', '--binary', forti_exe.full_path()],
         depends : forti_exe, suite : 'integration')
else
    message('python3 not found: the integration suite is not built')
endif
