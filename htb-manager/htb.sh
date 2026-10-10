# htb shell integration -- source this from your ~/.bashrc or ~/.zshrc:
#
#     source ~/.local/share/htb/htb.sh
#
# Provides the `htb` shell function. Most subcommands just forward to htb.py.
# But `up`, `switch` and `target` need to change the CURRENT shell -- export
# LHOST / TARGET and cd into the box workdir -- which a child process cannot do.
# For those we run htb.py with --emit-env: it prints shell commands to stdout
# while all human-readable output goes to stderr (shown normally), and we eval
# only the captured stdout.
#
# Override the script path with HTB_PY if you put htb.py somewhere else.

HTB_PY="${HTB_PY:-$HOME/.local/bin/htb.py}"

htb() {
    case "$1" in
        up|switch|target)
            local _htb_out _htb_rc
            _htb_out="$(python3 "$HTB_PY" "$@" --emit-env)"
            _htb_rc=$?
            [ $_htb_rc -eq 0 ] && [ -n "$_htb_out" ] && eval "$_htb_out"
            return $_htb_rc
            ;;
        *)
            python3 "$HTB_PY" "$@"
            ;;
    esac
}

# Live current tun IP, for use in payloads/listeners: `nc $(lhost) 4444`,
# msfvenom LHOST=$(lhost), etc. Unlike the static $LHOST exported at connect
# time, this re-reads the interface every call, so it stays correct across VPN
# reconnects that hand you a new address. Prints nothing if no tunnel is up.
lhost() {
    python3 "$HTB_PY" lhost
}

# --- bash completion: subcommands, plus profile names for up/switch ---------- #
if [ -n "$BASH_VERSION" ]; then
    _htb_complete() {
        local cur prev
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        case "$prev" in
            htb)
                COMPREPLY=( $(compgen -W \
                    "up down switch status lhost list target untarget" -- "$cur") )
                ;;
            up|switch)
                local profiles
                profiles=$(ls "$HOME/htb-vpns"/*.ovpn 2>/dev/null \
                    | xargs -n1 basename 2>/dev/null | sed 's/\.ovpn$//')
                COMPREPLY=( $(compgen -W "$profiles" -- "$cur") )
                ;;
        esac
    }
    complete -F _htb_complete htb
fi

# --- zsh completion: basic profile completion for up/switch ------------------ #
# Wrapped in an eval of a quoted heredoc: bash parses the whole file at source
# time, and would choke on the zsh-only `(up|switch)` glob even though this
# block is guarded. A quoted heredoc is literal text to bash, so it never
# parses the zsh syntax; the eval only runs (and zsh parses it) under zsh.
if [ -n "$ZSH_VERSION" ]; then
    eval "$(cat <<'ZSH_COMPLETION'
_htb_zsh() {
    local -a subs profiles
    subs=(up down switch status lhost list target untarget)
    if (( CURRENT == 2 )); then
        compadd -- $subs
    elif (( CURRENT == 3 )) && [[ "$words[2]" == (up|switch) ]]; then
        profiles=(${(f)"$(ls $HOME/htb-vpns/*.ovpn 2>/dev/null \
            | xargs -n1 basename 2>/dev/null | sed 's/\.ovpn$//')"})
        compadd -- $profiles
    fi
}
compdef _htb_zsh htb 2>/dev/null
ZSH_COMPLETION
)"
fi
