# Shell completion scripts. Static files: the candidates come from `forti __complete` at Tab time, so
# nothing here depends on the build and cross builds need not run forti. src/cli embeds the same files
# for `forti completion SHELL`.
completion_bash = files('forti.bash')
completion_zsh = files('_forti')
completion_fish = files('forti.fish')
completion_embed = files('embed.py')

if not meson.is_subproject() and not get_option('completions').disabled()
    datadir = get_option('datadir')
    install_data(completion_bash, install_dir : datadir / 'bash-completion' / 'completions', rename : 'forti')
    install_data(completion_zsh, install_dir : datadir / 'zsh' / 'site-functions')
    install_data(completion_fish, install_dir : datadir / 'fish' / 'vendor_completions.d')
endif
