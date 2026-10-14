# Network-free tests (CI runs them; nothing here talks to a FortiGate). The engine is exercised
# through a scripted fortiapi::Transport (support/fake_transport.hpp).
gtest_dep = dependency('gtest', main : true, required : get_option('tests'))
if gtest_dep.found()
    test('unit', executable('unitTests',
                            'unit/test_catalog.cpp',
                            'unit/test_read.cpp',
                            'unit/test_profiles.cpp',
                            include_directories : include_directories('support'),
                            dependencies : [forti_engine_dep, gtest_dep],
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
