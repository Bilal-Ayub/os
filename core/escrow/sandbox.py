"""Build the agent's private view of the system and start the agent in it.

This runs as `escrow-enter <session dir>`, already inside the session's cgroup
(systemd-run scope) and, if strace is installed, under the network tracer.

Process layout:

    P0 escrow-enter   unshare(user, mount, pid[, net]), id maps, all mounts
     └─ P1            PID 1 of the new PID namespace: mounts /proc, reaps
         └─ P2        the agent: no_new_privs + seccomp, then exec

Everything P0 does is unprivileged: creating a user namespace gives it a full
capability set *inside that namespace only*, which is enough to mount
overlayfs and tmpfs there. The agent itself runs as the user's normal uid with
no capabilities, so it can write only where the user could, and those writes
land in the overlay's upper layer.
"""

import ctypes
import fcntl
import json
import select
import os
import signal
import socket
import struct
import sys
import time

from . import landlock, seccomp, shield
from .session import EscrowError

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_RELATIME = 1 << 21
MS_STRICTATIME = 1 << 24

# Private, throw-away tmpfs inside the session (never committed).
PRIVATE_TMPFS = ["/tmp", "/var/tmp", "/dev/shm"]
# Never touched: kernel/virtual filesystems.
LEAVE_ALONE = {"/proc", "/sys", "/dev", "/run", "/tmp"}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                        ctypes.c_ulong, ctypes.c_char_p]


def _b(s):
    return None if s is None else os.fsencode(s)


def mount(source, target, fstype=None, flags=0, data=None):
    if _libc.mount(_b(source), _b(target), _b(fstype), flags, _b(data)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount {fstype or ''} on {target}: {os.strerror(e)}")


def log(msg):
    print(f"escrow: {msg}", file=sys.stderr)


# ---------------------------------------------------------------- mount table

def _unescape(s):
    return s.encode().decode("unicode_escape") if "\\" in s else s


def mountinfo():
    """List of (mount point, per-mount options) from /proc/self/mountinfo."""
    out = []
    with open("/proc/self/mountinfo") as f:
        for line in f:
            parts = line.split()
            out.append((_unescape(parts[4]), parts[5].split(",")))
    return out


def _flags_for(opts):
    """Mount flags that must be kept when remounting (the kernel locks them
    for mounts inherited into a user namespace)."""
    flags = 0
    for name, bit in (("nosuid", MS_NOSUID), ("nodev", MS_NODEV),
                      ("noexec", MS_NOEXEC), ("nodiratime", MS_NODIRATIME)):
        if name in opts:
            flags |= bit
    if "noatime" in opts:
        flags |= MS_NOATIME
    elif "relatime" in opts:
        flags |= MS_RELATIME
    else:
        flags |= MS_STRICTATIME
    return flags


def _under(path, top):
    return path == top or path.startswith(top.rstrip("/") + "/")


def make_readonly(top):
    """Bind `top` onto itself (so it is a mount point) and remount it and
    everything mounted below it read-only."""
    mount(top, top, None, MS_BIND | MS_REC)
    failed = []
    for mp, opts in mountinfo():
        if _under(mp, top):
            try:
                mount(None, mp, None, MS_REMOUNT | MS_BIND | MS_RDONLY | _flags_for(opts))
            except OSError as e:
                failed.append(f"{mp} ({e.strerror})")
    return failed


# ---------------------------------------------------------------- setup steps

def write_id_maps(uid, gid):
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {uid} 1")
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {gid} 1")


def loopback_up():
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        ifr = struct.pack("16sH14x", b"lo", 0)
        flags = struct.unpack("16sH14x", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP))


def stage_overlays(meta, session_dir):
    """Mount an overlay on every staged top-level dir.

    `userxattr` stores overlay metadata in user.overlay.* xattrs (required
    in a user namespace). It also disables redirect_dir, so renaming a lower
    directory fails with EXDEV and tools fall back to copy + delete; every
    change is then a plain file in upper, which is what `commit` expects."""
    for d in meta["staged"]:
        rel = d.lstrip("/")
        upper = os.path.join(session_dir, "upper", rel)
        work = os.path.join(session_dir, "work", rel)
        opts = f"lowerdir={d},upperdir={upper},workdir={work},userxattr"
        mount("overlay", d, "overlay", 0, opts)


def lock_down_rest(meta):
    """Everything that is not staged becomes read-only or private, so no
    write can bypass the transaction."""
    staged = set(meta["staged"])
    tops = ["/" + n for n in sorted(os.listdir("/"))]
    # cgroupfs too: systemd's user manager owns the scope's control files with
    # the user's uid, so without this the agent could raise its own pids.max.
    for top in tops + ["/sys/fs/cgroup"]:
        if top in staged or top in LEAVE_ALONE or os.path.islink(top) or not os.path.isdir(top):
            continue
        try:
            failed = make_readonly(top)
            if failed:
                log(f"warning: still writable: {', '.join(failed)}")
        except OSError as e:
            log(f"warning: could not make {top} read-only ({e.strerror})")
    for path in PRIVATE_TMPFS + [f"/run/user/{meta['uid']}"]:
        if os.path.isdir(path):
            mode = "0700" if path.startswith("/run/user/") else "1777"
            mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, f"mode={mode}")


def install_shield(meta, session_dir):
    """Secret shield + decoys (see shield.py). Returns the decoy paths."""
    home = meta.get("home") or os.environ.get("HOME", "")
    if not meta.get("shield", True) or not home or not os.path.isdir(home):
        return []
    # Open the record first: the scratch tmpfs below may cover the state dir
    # (when it lives in $XDG_RUNTIME_DIR).
    with open(os.path.join(session_dir, "shield.json"), "w") as f:
        scratch = f"/run/user/{meta['uid']}"
        mount("tmpfs", scratch, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700")
        watched, created, canary = shield.install(home, mount, MS_NOSUID | MS_NODEV, scratch)
        json.dump({"created": created, "decoys": watched, "canary": canary}, f)
    return watched


# ---------------------------------------------------------------- processes

def _exit_code(status):
    code = os.waitstatus_to_exitcode(status)
    return 128 - code if code < 0 else code


def _ignore_job_signals():
    for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(sig, signal.SIG_IGN)


def _event(fd, event, **data):
    if fd is None:
        return
    rec = {"time": time.strftime("%H:%M:%S"), "event": event, **data}
    try:
        os.write(fd, (json.dumps(rec) + "\n").encode())
    except OSError:
        pass


def exec_agent(meta, events_fd):
    """P2: become the agent."""
    try:
        os.chdir(meta["cwd"])  # re-resolve the cwd through the new mounts
    except OSError:
        os.chdir(os.environ.get("HOME", "/"))
        log(f"warning: {meta['cwd']} is not visible in the session; starting in $HOME")
    signal.set_wakeup_fd(-1)
    for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU,
                signal.SIGPIPE, signal.SIGXFSZ, signal.SIGTERM, signal.SIGCHLD):
        signal.signal(sig, signal.SIG_DFL)
    env = dict(os.environ)
    env.pop("DBUS_SESSION_BUS_ADDRESS", None)
    env["ESCROW_SESSION"] = str(meta["id"])
    env["ESCROW_PROFILE"] = meta["profile"]
    home = meta.get("home") or env.get("HOME", "/")
    mode = "strict" if meta["profile"] == "strict" else "scope"
    try:
        note = landlock.apply(mode, home, os.getcwd())
    except OSError as e:
        note = f"landlock: error {e} (skipped)"
    _event(events_fd, "landlock", detail=note)
    if mode == "strict" and "filesystem" not in note:
        log(f"FATAL: the strict profile needs Landlock filesystem rules: {note}")
        os._exit(125)
    try:
        seccomp.install()
    except OSError as e:
        log(f"FATAL: could not install the seccomp filter: {e}")
        os._exit(125)
    cmd = meta["cmd"]
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as e:
        log(f"cannot run {cmd[0]}: {e.strerror}")
        os._exit(127)


RED = "\033[1;41;97m"
RESET = "\033[0m"


def _tripped(paths, events_fd, home):
    """Stop every agent process, then let the user decide (kill by default)."""
    os.kill(-1, signal.SIGSTOP)  # from PID 1: every process in the namespace but us
    shown = ", ".join(p.replace(home, "~", 1) for p in paths)
    _event(events_fd, "tripwire", paths=paths)
    msg = (f"\n{RED} ESCROW TRIPWIRE {RESET} the agent opened decoy secret(s): {shown}\n"
           "  Your real keys were never visible to it, but it went looking for them.\n"
           "  All agent processes are FROZEN. The session is marked TAINTED.\n")
    try:
        tty = open("/dev/tty", "r+")
    except OSError:
        tty = None
    if tty is None:
        print(msg + "  No terminal: killing the agent.", file=sys.stderr, flush=True)
        _event(events_fd, "tripwire-kill", by="no terminal")
        os.kill(-1, signal.SIGKILL)
        return
    with tty:
        tty.write(msg)
        while True:
            tty.write("  [k]ill the agent (recommended) or [r]esume it? ")
            tty.flush()
            ans = tty.readline().strip().lower()
            if ans in ("k", "kill", ""):
                _event(events_fd, "tripwire-kill", by="user")
                os.kill(-1, signal.SIGKILL)
                return
            if ans in ("r", "resume"):
                _event(events_fd, "tripwire-resume", by="user")
                os.kill(-1, signal.SIGCONT)
                return


def init_process(meta, events_fd, decoys):
    """P1: PID 1 of the session. Watches the decoys and reaps children. When
    the agent exits, P1 exits and the kernel kills anything left in the
    namespace."""
    try:
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    except OSError as e:
        log(f"warning: could not mount a private /proc ({e.strerror}); "
            "the agent can see host processes")
    _libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0: the agent can't open /proc/1/*
    wire = None
    if decoys:
        try:
            wire = shield.Tripwire(decoys)
        except OSError as e:
            log(f"warning: tripwire unavailable ({e})")
    wake_r, wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    signal.set_wakeup_fd(wake_w)
    signal.signal(signal.SIGCHLD, lambda *_: None)
    agent = os.fork()
    if agent == 0:
        os.close(wake_r)
        exec_agent(meta, events_fd)
    _ignore_job_signals()
    signal.signal(signal.SIGTERM, lambda *_: os.kill(agent, signal.SIGTERM))
    home = meta.get("home") or "~"
    watch = [wake_r] + ([wire.fd] if wire else [])
    while True:
        while True:  # reap everything that has exited
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                os._exit(1)
            if pid == 0:
                break
            if pid == agent:
                os._exit(_exit_code(status))
        try:
            ready, _, _ = select.select(watch, [], [], 1.0)
        except InterruptedError:
            continue
        if wake_r in ready:
            try:
                os.read(wake_r, 4096)
            except BlockingIOError:
                pass
        if wire and wire.fd in ready:
            hits = wire.read()
            if hits:
                _tripped(hits, events_fd, home)


def enter(session_dir):
    """P0. Returns the agent's exit code (125 = sandbox setup failed)."""
    with open(os.path.join(session_dir, "meta.json")) as f:
        meta = json.load(f)
    if os.getuid() == 0:
        raise EscrowError("escrow refuses to run agents as root")
    if os.environ.get("ESCROW_SESSION"):
        raise EscrowError("already inside an escrow session")
    if meta["uid"] != os.getuid():
        raise EscrowError("session belongs to another user")

    flags = os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWPID
    if meta["profile"] == "offline":
        flags |= os.CLONE_NEWNET
    try:
        os.unshare(flags)
    except OSError as e:
        hint = ""
        if e.errno == 1 and os.path.exists("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"):
            hint = " (AppArmor blocks user namespaces: is /etc/apparmor.d/escrow loaded?)"
        raise EscrowError(f"cannot create namespaces: {e.strerror}{hint}")
    write_id_maps(meta["uid"], meta["gid"])
    mount(None, "/", None, MS_REC | MS_PRIVATE)
    stage_overlays(meta, session_dir)
    events_fd = os.open(os.path.join(session_dir, "events.jsonl"),
                        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    decoys = install_shield(meta, session_dir)
    lock_down_rest(meta)
    if meta["profile"] == "offline":
        loopback_up()
    _libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0

    init = os.fork()  # first child in the new PID namespace = PID 1
    if init == 0:
        try:
            init_process(meta, events_fd, decoys)
        finally:
            os._exit(125)
    os.close(events_fd)
    _ignore_job_signals()
    signal.signal(signal.SIGTERM, lambda *_: os.kill(init, signal.SIGTERM))
    while True:
        try:
            _, status = os.waitpid(init, 0)
            return _exit_code(status)
        except InterruptedError:
            continue


def main(argv):
    if len(argv) != 2:
        print("usage: escrow-enter <session dir>  (internal; use `escrow run`)", file=sys.stderr)
        return 2
    try:
        return enter(argv[1])
    except (EscrowError, OSError) as e:
        log(f"sandbox setup failed: {e}")
        return 125
