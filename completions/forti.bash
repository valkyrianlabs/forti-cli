# bash completion for forti(1)                             -*- shell-script -*-
#
# Installed as share/bash-completion/completions/forti (bash-completion loads it on first use), or:
#   source <(forti completion bash)
#
# The candidates come from forti itself (`forti __complete WHAT [PREFIX]`), so the script stays right
# as commands and options change. That call reads only profile names and the plans directory: no
# device, no secret. Works with or without the bash-completion package.

_forti_query() {
    "$_forti_bin" __complete "$@" 2>/dev/null
}

# The lines of $1 that start with $2. Not `compgen -W`: it would expand $(...) in a candidate.
_forti_reply() {
    local candidate
    COMPREPLY=()
    while IFS= read -r candidate; do
        [[ -n $candidate && $candidate == "$2"* ]] && COMPREPLY+=("$candidate")
    done <<<"$1"
}

_forti() {
    local cur=${COMP_WORDS[COMP_CWORD]} prev=
    ((COMP_CWORD > 0)) && prev=${COMP_WORDS[COMP_CWORD - 1]}
    local _forti_bin=${COMP_WORDS[0]}
    local cmd= word valued= valued_for=- skip= i
    local -a args=()
    COMPREPLY=()

    # The command and its positional arguments, without options and option values.
    for ((i = 1; i < COMP_CWORD; i++)); do
        word=${COMP_WORDS[i]}
        if [[ -n $skip ]]; then
            [[ $word == = ]] || skip=   # --profile=lab: bash splits it at the '='
            continue
        fi
        case $word in
            --*=* | - | =) ;;
            -*)
                if [[ $valued_for != "$cmd" ]]; then
                    valued=$'\n'$(_forti_query valued "$cmd")$'\n'
                    valued_for=$cmd
                fi
                [[ $valued == *$'\n'"$word"$'\n'* ]] && skip=1
                ;;
            *)
                if [[ -z $cmd ]]; then cmd=$word; else args+=("$word"); fi
                ;;
        esac
    done

    # An option's value.
    if [[ -n $skip ]]; then
        [[ $prev == = ]] && prev=${COMP_WORDS[COMP_CWORD - 2]}
        case $prev in
            -p | --profile) _forti_reply "$(_forti_query profiles)" "$cur" ;;
            --mode) _forti_reply "$(_forti_query modes)" "$cur" ;;
            -f | --file | --ca-bundle | --client-cert | --cert-password-file | --project-dir)
                local IFS=$'\n'
                COMPREPLY=($(compgen -f -- "$cur"))
                ;;
        esac
        return 0
    fi

    if [[ $cur == -* ]]; then
        _forti_reply "$(_forti_query options "$cmd")" "$cur"
        return 0
    fi
    if [[ -z $cmd ]]; then
        _forti_reply "$(_forti_query commands)" "$cur"
        return 0
    fi

    local what= sub=${args[0]-} n=${#args[@]}
    case $cmd in
        help) ((n == 0)) && what=commands ;;
        get | discover | set | create | delete) ((n == 0)) && what=resources ;;
        apply | approve | rollback) ((n == 0)) && what=plans ;;
        plan)
            if ((n == 0)); then
                what=subcommands
            elif ((n == 1)); then
                case $sub in
                    set | create | delete | action) what=resources ;;
                    show | approve) what=plans ;;
                esac
            fi
            ;;
        profile)
            if ((n == 0)); then
                what=subcommands
            elif [[ $sub == mode ]]; then
                ((n == 1)) && what="profiles modes"
                ((n == 2)) && what=modes
            elif ((n == 1)); then
                case $sub in
                    show | set | rename | copy | default | remove) what=profiles ;;
                esac
            fi
            ;;
        *) ((n == 0)) && what=subcommands ;;
    esac

    local w candidates=
    for w in $what; do
        case $w in
            subcommands) candidates+=$(_forti_query subcommands "$cmd")$'\n' ;;
            resources) candidates+=$(_forti_query resources "$cur")$'\n' ;;
            *) candidates+=$(_forti_query "$w")$'\n' ;;
        esac
    done
    [[ -n $candidates ]] || return 0
    _forti_reply "$candidates" "$cur"
    # A resource directory ("firewall/") is completed further, not ended with a space.
    if [[ ${#COMPREPLY[@]} -eq 1 && ${COMPREPLY[0]} == */ ]]; then
        compopt -o nospace 2>/dev/null
    fi
    return 0
}

complete -F _forti forti
