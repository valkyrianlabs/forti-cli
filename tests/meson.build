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
endif
