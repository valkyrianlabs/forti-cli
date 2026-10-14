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
endif
