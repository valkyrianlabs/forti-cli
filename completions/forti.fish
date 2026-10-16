# fish completion for forti(1). Installed as share/fish/vendor_completions.d/forti.fish, or:
#   forti completion fish | source
#
# The candidates come from forti itself (`forti __complete WHAT [PREFIX]`), so the script stays right
# as commands and options change. That call reads only profile names and the plans directory: no
# device, no secret.

function __forti_query
    set -l bin (commandline -opc)[1]
    command $bin __complete $argv 2>/dev/null
end

# Options whose value is a file or directory (given to fish's own file completion below).
function __forti_wants_file
    set -l tokens (commandline -opc)
    contains -- $tokens[-1] -f --file --ca-bundle --client-cert --cert-password-file --project-dir
end

function __forti_complete
    set -l tokens (commandline -opc)
    set -l cur (commandline -ct)
    set -e tokens[1]

    # The command and its positional arguments, without options and option values.
    set -l cmd
    set -l args
    set -l valued
    set -l valued_for -
    set -l skip
    for word in $tokens
        if test -n "$skip"
            set skip
            continue
        end
        switch $word
            case '--*=*' -
            case '-*'
                if test "$valued_for" != "$cmd"
                    set valued (__forti_query valued $cmd)
                    set valued_for $cmd
                end
                contains -- $word $valued; and set skip 1
            case '*'
                if test -z "$cmd"
                    set cmd $word
                else
                    set -a args $word
                end
        end
    end

    # An option's value: --opt VALUE, or --opt=VALUE (candidates keep the "--opt=").
    set -l option
    set -l lead
    if test -n "$skip"
        set option $tokens[-1]
    else if string match -q -- '--*=*' $cur
        set option (string split -m 1 = -- $cur)[1]
        set lead "$option="
    end
    if test -n "$option"
        switch $option
            case -p --profile
                __forti_query profiles | string replace -r -- '^' "$lead"
            case --mode
                __forti_query modes | string replace -r -- '^' "$lead"
        end
        return
    end

    if string match -q -- '-*' $cur
        __forti_query options $cmd
        return
    end
    if test -z "$cmd"
        __forti_query commands
        return
    end

    set -l n (count $args)
    set -l sub $args[1]
    set -l what
    switch $cmd
        case help
            test $n -eq 0; and set what commands
        case get discover set create delete
            test $n -eq 0; and set what resources
        case apply approve rollback
            test $n -eq 0; and set what plans
        case plan
            if test $n -eq 0
                set what subcommands
            else if test $n -eq 1
                switch $sub
                    case set create delete action
                        set what resources
                    case show approve
                        set what plans
                end
            end
        case profile
            if test $n -eq 0
                set what subcommands
            else if test "$sub" = mode
                test $n -eq 1; and set what profiles modes
                test $n -eq 2; and set what modes
            else if test $n -eq 1
                switch $sub
                    case show set rename copy default remove
                        set what profiles
                end
            end
        case '*'
            test $n -eq 0; and set what subcommands
    end

    for w in $what
        switch $w
            case resources
                __forti_query resources $cur
            case subcommands
                __forti_query subcommands $cmd
            case '*'
                __forti_query $w
        end
    end
end

complete -c forti -f -a '(__forti_complete)'
complete -c forti -n __forti_wants_file -F
