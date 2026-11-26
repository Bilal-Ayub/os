# Escrow OS: put the agent shims first on PATH so that AI agent CLIs
# (claude, codex, gemini, ...) always start inside an escrow session.
# Registry: /etc/escrow/agents.d/<agent>.toml. The logic lives in
# /etc/escrow/path.sh, which /etc/bash.bashrc also sources (terminal tabs).
if [ -r /etc/escrow/path.sh ]; then . /etc/escrow/path.sh; fi
