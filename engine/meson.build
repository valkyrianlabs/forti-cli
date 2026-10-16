# forti-engine: the command semantics shared by `forti` and `forti-mcp` (catalog, profiles,
# discover/read/plan/apply, approvals, audit). Internal: static, never installed.
#
# The resource catalog and its validation come from forti-api's runtime schema (fortiapi::schema),
# tables compiled once in schema_ops.cpp: no generated model is instantiated here.

engine_inc = include_directories('include')

engine_sources = files(
    'src/approval.cpp',
    'src/catalog.cpp',
    'src/engine.cpp',
    'src/error.cpp',
    'src/plan.cpp',
    'src/plan_store.cpp',
    'src/policy.cpp',
    'src/profile.cpp',
    'src/schema_ops.cpp',
    'src/secrets.cpp',
    'src/sha256.cpp',
)

engine_deps = [forti_api_dep]
if host_machine.system() == 'darwin'
    engine_sources += files('src/keychain_macos.cpp')
    engine_deps += dependency('appleframeworks', modules : ['Security', 'CoreFoundation'])
endif

engine_lib = static_library('forti-engine', engine_sources,
                            include_directories : engine_inc,
                            dependencies : engine_deps,
                            implicit_include_directories : false)

forti_engine_dep = declare_dependency(include_directories : engine_inc,
                                      link_with : engine_lib,
                                      dependencies : engine_deps)
meson.override_dependency('forti-engine', forti_engine_dep)
