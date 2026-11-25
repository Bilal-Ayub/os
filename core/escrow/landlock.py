"""Landlock: unprivileged, stackable access control (Linux 5.13+).

An unprivileged process builds a ruleset, then calls landlock_restrict_self().
From then on, it and all its children are confined. The rules can only ever
be tightened.

Escrow uses Landlock for two things:
  * scoping (ABI 6+), on every profile: the agent cannot connect to *abstract*
    unix sockets created outside its sandbox (e.g. an X11 or D-Bus endpoint;
    abstract sockets have no file, so mounts cannot hide them) and cannot
    signal processes outside it.
  * the `strict` profile: filesystem allowlist. The system is readable. Only
    the project directory, agent state dirs and temp dirs are writable or
    readable inside $HOME. Everything else in $HOME (Documents, other
    projects, ...) returns EACCES.

If the kernel lacks Landlock, or has an older ABI, escrow warns and continues
with the namespace sandbox (best effort, as the kernel docs recommend).
"""

import ctypes
import os
import platform
import struct

SYS = {"x86_64": (444, 445, 446), "aarch64": (444, 445, 446)}
CREATE_RULESET_VERSION = 1
RULE_PATH_BENEATH = 1

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR = 1 << 4, 1 << 5, 1 << 6, 1 << 7
MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK = 1 << 8, 1 << 9, 1 << 10, 1 << 11
MAKE_SYM, REFER, TRUNCATE, IOCTL_DEV = 1 << 12, 1 << 13, 1 << 14, 1 << 15
SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_SIGNAL = 1 << 0, 1 << 1

FILE_ONLY = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV

# Inside $HOME, `strict` allows these (relative to $HOME) besides the project.
HOME_ALLOW_RW = [".claude", ".claude.json", ".codex", ".gemini", ".copilot", ".config",
                 ".cache", ".local", ".npm", ".npmrc", ".cargo", ".rustup", ".bun",
                 ".nvm", ".pyenv", ".aider", ".goose", ".bash_history", ".python_history"]
HOME_ALLOW_RO = [".bashrc", ".profile", ".bash_logout", ".gitconfig", ".inputrc",
                 ".vimrc", ".ssh", ".aws", ".gnupg", ".netrc", ".git-credentials", ".pypirc",
                 ".docker", ".kube"]  # shielded paths stay readable so decoys can trip


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _nr():
    return SYS.get(platform.machine())


def abi_version():
    nr = _nr()
    if not nr:
        return 0
    v = _libc().syscall(nr[0], None, ctypes.c_size_t(0), ctypes.c_uint32(CREATE_RULESET_VERSION))
    return v if v > 0 else 0


def _fs_mask(abi):
    mask = (1 << 13) - 1  # ABI 1: bits 0..12
    if abi >= 2:
        mask |= REFER
    if abi >= 3:
        mask |= TRUNCATE
    if abi >= 5:
        mask |= IOCTL_DEV
    return mask


def _add(fd, path, access, abi_mask):
    try:
        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        if not os.path.isdir(path):
            access &= FILE_ONLY
        access &= abi_mask
        attr = struct.pack("=Qi", access, pfd)  # struct is __attribute__((packed))
        buf = ctypes.create_string_buffer(attr, len(attr))
        r = _libc().syscall(_nr()[1], ctypes.c_int(fd), ctypes.c_int(RULE_PATH_BENEATH),
                            buf, ctypes.c_uint32(0))
        return r == 0
    finally:
        os.close(pfd)


def apply(mode, home, cwd):
    """Confine the calling process. mode: 'scope' or 'strict'.
    Returns a short description of what was enforced (or why not)."""
    abi = abi_version()
    if abi < 1:
        return "landlock: unavailable in this kernel (skipped)"
    fs = _fs_mask(abi) if mode == "strict" else 0
    scoped = (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if abi >= 6 else 0
    if not fs and not scoped:
        return f"landlock: ABI {abi} has no scoping (needs 6); skipped"
    if abi >= 6:
        attr = struct.pack("=QQQ", fs, 0, scoped)
    elif abi >= 4:
        attr = struct.pack("=QQ", fs, 0)
    else:
        attr = struct.pack("=Q", fs)
    buf = ctypes.create_string_buffer(attr, len(attr))
    libc = _libc()
    fd = libc.syscall(_nr()[0], buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if fd < 0:
        e = ctypes.get_errno()
        return f"landlock: create_ruleset failed ({os.strerror(e)}); skipped"
    try:
        if fs:
            ro = EXECUTE | READ_FILE | READ_DIR
            rw = fs  # everything this ABI knows
            for top in sorted(os.listdir("/")):
                p = "/" + top
                if p == home or (home.startswith(p + "/")):
                    continue  # $HOME's ancestors are handled below
                if p in ("/tmp", "/dev"):
                    _add(fd, p, rw, fs)
                else:
                    _add(fd, p, ro, fs)
            _add(fd, "/var/tmp", rw, fs)
            _add(fd, "/dev/shm", rw, fs)
            # ancestors of $HOME other than $HOME itself: everything but $HOME readable
            parent = os.path.dirname(home)
            while parent and parent != "/":
                for name in os.listdir(parent):
                    p = os.path.join(parent, name)
                    if p != home and not home.startswith(p + "/"):
                        _add(fd, p, ro, fs)
                parent = os.path.dirname(parent)
            for rel in HOME_ALLOW_RW:
                _add(fd, os.path.join(home, rel), rw, fs)
            for rel in HOME_ALLOW_RO:
                _add(fd, os.path.join(home, rel), ro, fs)
            _add(fd, f"/run/user/{os.getuid()}", rw, fs)
            _add(fd, cwd, rw, fs)  # the project (if cwd == $HOME, all of $HOME)
        libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS (required)
        if libc.syscall(_nr()[2], ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
            e = ctypes.get_errno()
            return f"landlock: restrict_self failed ({os.strerror(e)}); skipped"
    finally:
        os.close(fd)
    what = []
    if fs:
        what.append(f"filesystem allowlist ({os.path.basename(cwd) or cwd} + agent dirs writable)")
    if scoped:
        what.append("abstract-socket + signal scoping")
    return f"landlock ABI {abi}: " + ", ".join(what)
