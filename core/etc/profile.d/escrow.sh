# Escrow OS: put the agent shims first on PATH so that AI agent CLIs
# (claude, codex, gemini, ...) always start inside an escrow session.
# Registry: /etc/escrow/agents.d/<agent>.toml
case ":${PATH}:" in
    *:/usr/lib/escrow/shims:*) ;;
    *) PATH="/usr/lib/escrow/shims:${PATH}"; export PATH ;;
esac
