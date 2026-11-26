"""Escrow: run AI agents as reversible transactions.

Every agent process runs on a copy-on-write (overlayfs) layer inside its own
user/mount/PID namespaces, with a seccomp filter and cgroup v2 limits. Nothing
it writes reaches the real files until a human reviews the diff and commits.
"""

__version__ = "0.3.2"
