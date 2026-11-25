"""Commit-time policy gate: flag staged changes that are risky to accept.

A diff can be long, and a human skimming it can miss the one line that
matters. These rules mark changes that give code a way to run later
(persistence), widen access, or destroy a lot at once. `escrow commit`
refuses flagged changes unless the user passes --accept-risk, and the
override is recorded in the ledger.
"""

import os
import stat

MASS_DELETE = 50  # files

_HOME_RULES = [
    # (path relative to $HOME, prefix?, reason)
    (".bashrc", False, "shell startup file: runs in every new shell"),
    (".bash_profile", False, "shell startup file: runs at login"),
    (".bash_login", False, "shell startup file: runs at login"),
    (".profile", False, "shell startup file: runs at login"),
    (".bash_logout", False, "shell file: runs at logout"),
    (".zshrc", False, "shell startup file: runs in every new shell"),
    (".zprofile", False, "shell startup file: runs at login"),
    (".config/fish/config.fish", False, "shell startup file: runs in every new shell"),
    (".inputrc", False, "readline config: can bind keys to commands"),
    (".ssh", True, "SSH access (authorized_keys, config, keys)"),
    (".gnupg", True, "GPG keys and trust"),
    (".config/autostart", True, "desktop autostart: runs at login"),
    (".config/systemd/user", True, "systemd user service: can run in the background"),
    (".local/share/systemd", True, "systemd user unit"),
    (".local/bin", True, "on PATH: can shadow real commands"),
    ("bin", True, "on PATH: can shadow real commands"),
    (".gitconfig", False, "git config: can set hooks, aliases, credential helpers"),
    (".config/git", True, "git config: can set hooks, aliases, credential helpers"),
    (".npmrc", False, "npm config: registry and install scripts"),
    (".pypirc", False, "Python package upload credentials"),
    (".netrc", False, "login credentials for network tools"),
    (".git-credentials", False, "git credentials"),
    (".docker", True, "Docker credentials and config"),
    (".kube", True, "Kubernetes credentials"),
    (".aws", True, "AWS credentials"),
    (".config/escrow", True, "escrow configuration"),
]


def _reason(path, home):
    if path.startswith("/etc/"):
        return "system configuration"
    if "/.git/hooks/" in path or path.endswith("/.git/hooks"):
        return "git hook: runs on git commands"
    if path.endswith("/.git/config"):
        return "repository git config: can set hooks (core.hooksPath) and helpers"
    if path.endswith(("/.envrc", "/.vscode/tasks.json", "/.vscode/settings.json")):
        return "runs automatically when the folder is opened"
    for rel, prefix, reason in _HOME_RULES:
        target = os.path.join(home, rel)
        if path == target or (prefix and path.startswith(target + "/")):
            return reason
    return None


def _count_files(path):
    n = 0
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            for _, _, files in os.walk(path):
                n += len(files)
        else:
            n = 1
    except OSError:
        pass
    return n


def assess(changes, home):
    """Set c.risk on every flagged change. Returns a list of global warnings."""
    deleted = 0
    for c in changes:
        reason = _reason(c.path, home)
        if c.upper and c.kind in ("A", "M") and c.ftype == "file":
            try:
                mode = os.lstat(c.upper).st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    reason = "setuid/setgid bit"
            except OSError:
                pass
        if c.kind == "D":
            deleted += _count_files(c.path)
        c.risk = reason
    warnings = []
    if deleted >= MASS_DELETE:
        warnings.append(f"mass deletion: {deleted} files would be deleted")
    return warnings


def risky(changes):
    return [c for c in changes if getattr(c, "risk", None)]
