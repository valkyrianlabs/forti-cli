# forti-engine: the command semantics shared by `forti` and `forti-mcp` (catalog, profiles,
# discover/read/plan/apply, approvals, audit). Internal: static, never installed.
#
# catalog_shard.cpp instantiates the SDK's typed operations for 1/N of the registry per translation
# unit (forti-api gap G3): one TU over all 534 endpoints needs 4-5 GB of RAM, eight need ~1.2 GB each.

engine_inc = include_directories('include')
shards = get_option('engine_shards')

shard_libs = []
foreach k : range(shards)
    shard_libs += static_library('forti-engine-shard@0@'.format(k), 'src/catalog_shard.cpp',
                                 cpp_args : ['-DFORTI_SHARD=@0@'.format(k), '-DFORTI_SHARDS=@0@'.format(shards)],
                                 include_directories : engine_inc,
                                 dependencies : forti_api_dep,
                                 implicit_include_directories : false)
endforeach

engine_sources = files(
    'src/approval.cpp',
    'src/catalog.cpp',
    'src/engine.cpp',
    'src/error.cpp',
    'src/plan.cpp',
    'src/plan_store.cpp',
    'src/policy.cpp',
    'src/profile.cpp',
    'src/secrets.cpp',
    'src/sha256.cpp',
)

engine_deps = [forti_api_dep]
if host_machine.system() == 'darwin'
    engine_sources += files('src/keychain_macos.cpp')
    engine_deps += dependency('appleframeworks', modules : ['Security', 'CoreFoundation'])
endif

engine_lib = static_library('forti-engine', engine_sources,
                            cpp_args : ['-DFORTI_SHARDS=@0@'.format(shards)],
                            include_directories : engine_inc,
                            dependencies : engine_deps,
                            link_with : shard_libs,
                            implicit_include_directories : false)

forti_engine_dep = declare_dependency(include_directories : engine_inc,
                                      link_with : engine_lib,
                                      dependencies : engine_deps)
meson.override_dependency('forti-engine', forti_engine_dep)
