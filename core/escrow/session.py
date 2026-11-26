"""Session bookkeeping: where sessions live, their metadata, their status.

A session directory looks like this:

    <state root>/<id>/
        meta.json     what was run, when, with which limits, and its status
        upper/<top>/  overlayfs upper layers: everything the agent wrote
        work/<top>/   overlayfs scratch directories (kernel-owned)
        net.log       strace record of every connect() the agent made
        undo/<n>/     undo journal of each commit: backups of the originals
"""

import json
import os
import pwd
import secrets
import shutil
import stat
import sys
import time

# Top-level directories whose writes are staged in the overlay.
STAGED_DIRS = ["/home", "/etc", "/opt", "/srv", "/usr"]
SYSTEM_STATE = "/var/lib/escrow"

RUNNING, PENDING, COMMITTED, DISCARDED, CLEAN, UNDONE = (
    "running", "pending", "committed", "discarded", "no-changes", "undone")


class EscrowError(Exception):
    """An error we report to the user as a one-line message."""


def warn(msg):
    print(f"escrow: warning: {msg}", file=sys.stderr)


def username():
    return pwd.getpwuid(os.getuid()).pw_name


def _inside_staged(path):
    real = os.path.realpath(path)
    return any(real == d or real.startswith(d + "/") for d in STAGED_DIRS)


def state_root(create=True, quiet=False):
    """Return this user's session directory, creating it safely."""
    env = os.environ.get("ESCROW_STATE_DIR")
    if env:
        root = env
    elif os.path.isdir(SYSTEM_STATE) and os.access(SYSTEM_STATE, os.W_OK | os.X_OK):
        root = os.path.join(SYSTEM_STATE, username())
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        root = os.path.join(runtime, "escrow")
        if create and not quiet:
            warn(f"{SYSTEM_STATE} is missing (is the escrow package installed?); "
                 f"using {root}, which does not survive a reboot")
    if _inside_staged(root):
        raise EscrowError(f"state directory {root} is inside a staged directory "
                          f"({', '.join(STAGED_DIRS)}); overlayfs cannot use it")
    if any(c in root for c in ",:\\"):
        raise EscrowError(f"state directory {root} must not contain ',' ':' or '\\'")
    if create:
        os.makedirs(root, mode=0o700, exist_ok=True)
    if os.path.lexists(root):
        st = os.lstat(root)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            raise EscrowError(f"{root} is not a directory owned by you; refusing to use it")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(root, 0o700)
    return root


def _write_json(path, data):
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _proc_starttime(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # comm may contain spaces; fields after the closing ')' are fixed.
        return int(data[data.rindex(")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


class Session:
    def __init__(self, root, sid):
        self.root = root
        self.id = int(sid)
        self.dir = os.path.join(root, str(self.id))
        self.upper = os.path.join(self.dir, "upper")
        self.work = os.path.join(self.dir, "work")
        self.netlog = os.path.join(self.dir, "net.log")
        self.meta_path = os.path.join(self.dir, "meta.json")
        self._meta = None

    @property
    def meta(self):
        if self._meta is None:
            with open(self.meta_path) as f:
                self._meta = json.load(f)
        return self._meta

    def save(self):
        _write_json(self.meta_path, self.meta)

    def update(self, **kw):
        self.meta.update(kw)
        self.save()

    def is_running(self):
        m = self.meta
        if m.get("status") != RUNNING:
            return False
        pid = m.get("pid")
        return pid is not None and _proc_starttime(pid) == m.get("pid_start")

    @property
    def status(self):
        st = self.meta.get("status")
        if st == RUNNING and not self.is_running():
            return PENDING  # escrow run was killed; its changes are still staged
        return st

    def upper_dirs(self):
        """(real top-level dir, upper dir) pairs for this session."""
        out = []
        for d in self.meta.get("staged", STAGED_DIRS):
            up = os.path.join(self.upper, d.lstrip("/"))
            if os.path.isdir(up):
                out.append((d, up))
        return out

    def remove_layers(self):
        for path in (self.upper, self.work, os.path.join(self.dir, "base")):
            force_rmtree(path)


def force_rmtree(path):
    """rmtree that also handles overlayfs' mode-000 work dir and read-only dirs
    (both are owned by the user, so u+rwx is always allowed)."""
    def unlock(p):
        st = os.lstat(p)
        if stat.S_ISDIR(st.st_mode):
            if stat.S_IMODE(st.st_mode) & 0o700 != 0o700:
                os.chmod(p, stat.S_IMODE(st.st_mode) | 0o700)
            for name in os.listdir(p):
                unlock(os.path.join(p, name))
    if os.path.lexists(path):
        unlock(path)
        shutil.rmtree(path)


def session_ids(root):
    try:
        names = os.listdir(root)
    except FileNotFoundError:
        return []
    return sorted(int(n) for n in names if n.isdigit()
                  and os.path.exists(os.path.join(root, n, "meta.json")))


def stageable_dirs():
    """STAGED_DIRS that overlayfs can use from inside a user namespace.

    A dir with other filesystems mounted below it (e.g. /usr on WSL2, which has
    /usr/lib/wsl/*) cannot be an unprivileged overlay lower layer: the kernel
    refuses to clone a mount with "locked" children, because that could reveal
    what those mounts hide. Such dirs are made read-only instead (sandbox.py),
    which is safe: the agent then cannot write there at all."""
    mounts = []
    try:
        with open("/proc/self/mountinfo") as f:
            mounts = [line.split()[4] for line in f]
    except OSError:
        pass
    out = []
    for d in STAGED_DIRS:
        if not os.path.isdir(d) or os.path.islink(d):
            continue
        if any(m.startswith(d + "/") for m in mounts):
            if d == "/home":
                warn("/home has filesystems mounted inside it, so it can only be "
                     "read-only in the session, not staged")
            continue
        out.append(d)
    return out


def new_session(root, cmd, profile, cwd, limits):
    sid = max((int(n) for n in os.listdir(root) if n.isdigit()), default=0) + 1
    while True:
        try:
            os.mkdir(os.path.join(root, str(sid)), 0o700)
            break
        except FileExistsError:
            sid += 1
    s = Session(root, sid)
    staged = stageable_dirs()
    for d in staged:
        os.makedirs(os.path.join(s.upper, d.lstrip("/")), mode=0o755)
        os.makedirs(os.path.join(s.work, d.lstrip("/")), mode=0o700)
    s._meta = {
        "id": sid,
        "cmd": cmd,
        "profile": profile,
        "cwd": cwd,
        "user": username(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "staged": staged,
        "limits": limits,
        "unit": f"escrow-{sid}-{secrets.token_hex(2)}",
        "start_ns": time.time_ns(),
        "end_ns": None,
        "exit_code": None,
        "status": RUNNING,
        "pid": os.getpid(),
        "pid_start": _proc_starttime(os.getpid()),
        "netlog": None,
        "cgroup": None,
    }
    s.save()
    return s


def get_session(root, sid=None):
    ids = session_ids(root)
    if not ids:
        raise EscrowError("no sessions yet (start one with: escrow run -- <command>)")
    if sid is None:
        sid = ids[-1]
    if int(sid) not in ids:
        raise EscrowError(f"no session {sid}")
    return Session(root, sid)
