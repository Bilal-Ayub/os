# Escrow OS: keep the agent shims FIRST on PATH, so that typing an agent's name
# (claude, codex, gemini, ...) starts it inside an escrow session.
#
# Why "keep" and not just "add": on Ubuntu, /etc/profile.d runs before
# ~/.profile, which then puts ~/.local/bin (where npm and pipx install agent
# CLIs) in front of everything. And terminal tabs on the desktop are non-login
# shells that never read /etc/profile at all. So this file is sourced from
#   /etc/profile.d/escrow.sh   login shells and the desktop session
#   /etc/bash.bashrc           every interactive bash, incl. terminal tabs
# and in interactive bash it also runs before each prompt (PROMPT_COMMAND),
# i.e. after ~/.profile and ~/.bashrc have had their say.
#
# This makes escrow the DEFAULT; it is not a security boundary: anyone can
# still run the real binary by its full path. POSIX sh: no subprocesses.

_escrow_path() {
    _escrow_d="${ESCROW_SHIM_DIR:-/usr/lib/escrow/shims}"
    if [ -d "$_escrow_d" ]; then
        _escrow_rest=":${PATH}:"
        while :; do  # drop every copy of the shim dir ...
            case "$_escrow_rest" in
                *":${_escrow_d}:"*)
                    _escrow_rest="${_escrow_rest%%:"${_escrow_d}":*}:${_escrow_rest#*:"${_escrow_d}":}" ;;
                *) break ;;
            esac
        done
        _escrow_rest="${_escrow_rest#:}"
        _escrow_rest="${_escrow_rest%:}"
        PATH="${_escrow_d}${_escrow_rest:+:${_escrow_rest}}"  # ... and put one in front
        export PATH
    fi
    unset _escrow_d _escrow_rest
}

_escrow_path
if [ -n "${BASH_VERSION:-}" ] && [ -n "${PS1:-}" ]; then
    case ";${PROMPT_COMMAND:-};" in
        *";_escrow_path;"*) ;;
        *) PROMPT_COMMAND="_escrow_path${PROMPT_COMMAND:+;${PROMPT_COMMAND}}" ;;
    esac
fi
