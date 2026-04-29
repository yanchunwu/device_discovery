_infer_iot_raw_interfaces() {
    local cur="$1"
    local iface
    local ifaces=()

    for iface in /sys/class/net/*; do
        [[ -e "$iface" ]] || continue
        ifaces+=("$(basename "$iface")")
    done

    COMPREPLY=($(compgen -W "${ifaces[*]}" -- "$cur"))
}

_infer_iot_raw_has_interface_arg() {
    local i
    local word

    for ((i = 1; i < COMP_CWORD; ++i)); do
        word="${COMP_WORDS[i]}"
        case "$word" in
            -i|--interface)
                ((++i))
                if ((i < COMP_CWORD)) && [[ -n "${COMP_WORDS[i]}" ]]; then
                    return 0
                fi
                ;;
            -n|--packets|-t|--timeout|-o|--output|--probe-cidr|--rotate-size|--retain)
                ((++i))
                ;;
            -l|--loop|-q|--quiet)
                ;;
            --)
                ((++i))
                break
                ;;
            -*)
                ;;
            *)
                return 0
                ;;
        esac
    done

    for ((; i < COMP_CWORD; ++i)); do
        word="${COMP_WORDS[i]}"
        [[ "$word" == -* ]] || return 0
    done

    return 1
}

_infer_iot_raw() {
    local cur prev
    local opts="-h --help -i --interface -n --packets -t --timeout -o --output --probe-cidr --rotate-size --retain -l --loop -q --quiet"

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev=""
    if ((COMP_CWORD > 0)); then
        prev="${COMP_WORDS[COMP_CWORD - 1]}"
    fi

    case "$prev" in
        -i|--interface)
            _infer_iot_raw_interfaces "$cur"
            return 0
            ;;
        -n|--packets|-t|--timeout|-o|--output|--probe-cidr|--rotate-size|--retain)
            return 0
            ;;
        -l|--loop|-q|--quiet)
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
        return 0
    fi

    if [[ -z "$cur" ]] && ((COMP_CWORD == 1)); then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
        return 0
    fi

    if ! _infer_iot_raw_has_interface_arg; then
        _infer_iot_raw_interfaces "$cur"
    fi
}

complete -F _infer_iot_raw infer_iot_raw ./infer_iot_raw bin/infer_iot_raw ./bin/infer_iot_raw
