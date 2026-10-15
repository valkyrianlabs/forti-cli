# AI client adapters for `forti install mcp` and `forti mcp status|repair|uninstall`. CLI-only code:
# it uses the engine's Failure type and Paths (the forti home, the workspace scope's directory).

python = import('python').find_installation()
skill_header = custom_target('forti-skill-header',
                             input : meson.project_source_root() / 'skill' / 'forti' / 'SKILL.md',
                             output : 'forti_skill.hpp',
                             command : [python, files('embed_skill.py'), '@INPUT@', '@OUTPUT@'])

install_sources = files(
    'claude.cpp',
    'client.cpp',
    'codex.cpp',
    'files.cpp',
    'installer.cpp',
    'mcp_json.cpp',
    'process.cpp',
    'toml_table.cpp',
    'workspace.cpp',
)

install_lib = static_library('forti-install', install_sources, skill_header,
                             include_directories : include_directories('.'),
                             dependencies : forti_engine_dep,
                             implicit_include_directories : false)

forti_install_dep = declare_dependency(include_directories : include_directories('.'),
                                       sources : skill_header,
                                       link_with : install_lib,
                                       dependencies : forti_engine_dep)
