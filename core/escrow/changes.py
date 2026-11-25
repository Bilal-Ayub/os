"""Turn an overlayfs upper layer into a list of changes, show them, apply them.

How overlayfs records changes in the upper layer:
  * a new or modified file      -> a full copy of the file in upper
  * a deleted file or directory -> a "whiteout": character device 0/0
  * a directory that was deleted and re-created ("replaced")
                                -> an upper dir with xattr user.overlay.opaque=y,
                                   which hides everything below it in lower
"""

import difflib
import filecmp
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys

ADDED, MODIFIED, DELETED, REPLACED = "A", "M", "D", "R"
OPAQUE_XATTR = "user.overlay.opaque"


class Change:
    __slots__ = ("kind", "path", "upper", "ftype", "note", "risk")

    def __init__(self, kind, path, upper, ftype, note=""):
        self.kind, self.path, self.upper, self.ftype, self.note = kind, path, upper, ftype, note
        self.risk = None

    def __repr__(self):
        return f"Change({self.kind} {self.path} {self.ftype})"


def _ftype(st):
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    return "other"


def is_whiteout(st):
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def is_opaque(path):
    try:
        return os.getxattr(path, OPAQUE_XATTR, follow_symlinks=False) in (b"y", b"x")
    except OSError:
        return False


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def _same(up, real, st_up, st_real):
    if _ftype(st_up) != _ftype(st_real):
        return False
    if stat.S_ISLNK(st_up.st_mode):
        return os.readlink(up) == os.readlink(real)
    if stat.S_IMODE(st_up.st_mode) != stat.S_IMODE(st_real.st_mode):
        return False
    if st_up.st_size != st_real.st_size:
        return False
    try:
        return filecmp.cmp(up, real, shallow=False)
    except OSError:
        return False


def _walk(updir, realdir, opaque, out):
    try:
        names = sorted(os.listdir(updir))
    except OSError:
        return
    if opaque:  # lower entries hidden by an opaque dir are deletions
        try:
            for name in sorted(os.listdir(realdir)):
                if name not in names:
                    rp = os.path.join(realdir, name)
                    out.append(Change(DELETED, rp, None, _ftype(os.lstat(rp))))
        except (FileNotFoundError, NotADirectoryError):
            pass
    for name in names:
        up = os.path.join(updir, name)
        rp = os.path.join(realdir, name)
        st = os.lstat(up)
        real = _lstat(rp)
        if is_whiteout(st):
            if real is not None:  # (a whiteout for a path that no longer exists is a no-op)
                out.append(Change(DELETED, rp, up, _ftype(real)))
        elif stat.S_ISDIR(st.st_mode):
            sub_opaque = opaque or is_opaque(up)
            if real is None or not stat.S_ISDIR(real.st_mode):
                note = "" if real is None else f"replaces a {_ftype(real)}"
                out.append(Change(ADDED, rp, up, "dir", note))
                _walk(up, rp, False, out)
            else:
                if is_opaque(up) and not opaque:
                    out.append(Change(REPLACED, rp, up, "dir", "deleted and re-created"))
                elif stat.S_IMODE(st.st_mode) != stat.S_IMODE(real.st_mode):
                    out.append(Change(MODIFIED, rp, up, "dir",
                                      f"mode {stat.S_IMODE(real.st_mode):o} -> {stat.S_IMODE(st.st_mode):o}"))
                _walk(up, rp, sub_opaque, out)
        elif stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            if real is None:
                out.append(Change(ADDED, rp, up, _ftype(st)))
            elif not _same(up, rp, st, real):
                note = "" if _ftype(st) == _ftype(real) else f"replaces a {_ftype(real)}"
                out.append(Change(MODIFIED, rp, up, _ftype(st), note))
        else:
            out.append(Change(ADDED if real is None else MODIFIED, rp, up, "other",
                              "special file: will not be committed"))


def _shield_mountpoints(session):
    try:
        with open(os.path.join(session.dir, "shield.json")) as f:
            return set(json.load(f).get("created", []))
    except (OSError, ValueError):
        return set()


def scan(session):
    """All pending changes of a session, sorted by path."""
    out = []
    for top, up in session.upper_dirs():
        _walk(up, top, False, out)
    # Mount points escrow itself created for the secret shield (e.g. ~/.aws when
    # it did not exist) are empty dirs in upper: not the agent's doing.
    hidden = _shield_mountpoints(session)
    if hidden:
        out = [c for c in out if not (c.path in hidden and c.kind == ADDED and c.ftype == "dir"
                                      and c.upper and not os.listdir(c.upper))]
    out.sort(key=lambda c: c.path)
    return out


def select(changes, prefixes):
    if not prefixes:
        return list(changes)
    prefixes = [os.path.abspath(p).rstrip("/") or "/" for p in prefixes]
    return [c for c in changes
            if any(c.path == p or c.path.startswith(p + "/") for p in prefixes)]


# ---------------------------------------------------------------- display

COLORS = {ADDED: "32", MODIFIED: "33", DELETED: "31", REPLACED: "35"}


def color(text, code, enabled=None):
    enabled = sys.stdout.isatty() if enabled is None else enabled
    return f"\033[{code}m{text}\033[0m" if enabled and code else text


def _size(path):
    try:
        n = os.lstat(path).st_size
    except OSError:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def stat_lines(changes):
    lines = []
    for c in changes:
        extra = []
        if c.ftype == "dir":
            extra.append("dir")
        elif c.ftype == "symlink" and c.upper:
            extra.append(f"symlink -> {os.readlink(c.upper)}")
        elif c.kind in (ADDED, MODIFIED) and c.upper:
            extra.append(_size(c.upper))
        if c.note:
            extra.append(c.note)
        suffix = f"  ({', '.join(e for e in extra if e)})" if any(extra) else ""
        risk = color(f"   ! RISK: {c.risk}", "1;31") if c.risk else ""
        lines.append(f"{color(c.kind, COLORS[c.kind])}  {c.path}{suffix}{risk}")
    return lines


def summary(changes):
    counts = {k: 0 for k in (ADDED, MODIFIED, DELETED, REPLACED)}
    for c in changes:
        counts[c.kind] += 1
    return (f"{counts[ADDED]} added, {counts[MODIFIED]} modified, "
            f"{counts[DELETED]} deleted, {counts[REPLACED]} replaced")


def _text(path, limit=1 << 20):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


def diff_lines(c):
    """Unified-diff style body for one change."""
    if c.ftype != "file":
        return []
    if c.kind == DELETED:
        old = _text(c.path)
        return [f"--- {c.path}", "+++ /dev/null"] + (
            ["-" + l.rstrip("\n") for l in old] if old is not None else ["Binary or large file deleted"])
    old = [] if c.kind == ADDED else _text(c.path)
    new = _text(c.upper)
    if old is None or new is None:
        return [f"Binary files {c.path} and staged copy differ"]
    out = list(difflib.unified_diff(old, new, fromfile=c.path if c.kind != ADDED else "/dev/null",
                                    tofile=f"{c.path} (staged)", lineterm=""))
    return [l.rstrip("\n") for l in out]


def print_diff(changes, out=sys.stdout):
    tty = out.isatty()
    for c in changes:
        lines = diff_lines(c)
        if not lines:
            continue
        for l in lines:
            code = ""
            if l.startswith(("+++", "---")):
                code = "1"
            elif l.startswith("+"):
                code = "32"
            elif l.startswith("-"):
                code = "31"
            elif l.startswith("@@"):
                code = "36"
            print(color(l, code, tty), file=out)
        print(file=out)


# ---------------------------------------------------------------- commit

class Conflict(Exception):
    def __init__(self, paths, mergeable=()):
        super().__init__(f"{len(paths)} conflicting path(s)")
        self.paths = paths
        self.mergeable = list(mergeable)  # 3-way merge possible, but with conflicts


# ---------------------------------------------------------------- 3-way merge
#
# Commit is optimistic concurrency control: if a file changed on disk after the
# session started, the agent's copy was based on an old version. Instead of
# giving up, escrow tries a 3-way merge, like git does for branches:
#     base   = the file as it was when the agent worked on it
#     ours   = the file on disk now (someone else's newer edits)
#     theirs = the agent's staged copy
# Non-overlapping edits merge cleanly. Overlapping ones are a real conflict.
# The base is snapshotted when the agent exits, for every file it modified that
# had not changed on disk since the session started.

MERGE_LIMIT = 5 << 20


def base_path(session, real):
    return os.path.join(session.dir, "base", real.lstrip("/"))


def snapshot_bases(session, changes):
    start = session.meta["start_ns"]
    n = 0
    for c in changes:
        if c.kind != MODIFIED or c.ftype != "file":
            continue
        st = _lstat(c.path)
        if st is None or not stat.S_ISREG(st.st_mode) or st.st_size > MERGE_LIMIT:
            continue
        if max(st.st_mtime_ns, st.st_ctime_ns) > start:
            continue  # already changed on disk: no trustworthy base
        dst = base_path(session, c.path)
        try:
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            shutil.copyfile(c.path, dst)
            n += 1
        except OSError:
            pass
    return n


def three_way(session, c):
    """(merged bytes, number of conflicts) or None if a merge is impossible."""
    base = base_path(session, c.path)
    git = shutil.which("git")
    if c.kind != MODIFIED or c.ftype != "file" or not git or not os.path.isfile(base):
        return None
    if any(_text(p, MERGE_LIMIT) is None for p in (c.path, base, c.upper)):
        return None
    r = subprocess.run([git, "merge-file", "-p", "-L", "on disk now", "-L", "before the agent",
                        "-L", "agent (staged)", c.path, base, c.upper], capture_output=True)
    if not 0 <= r.returncode <= 127:
        return None
    return r.stdout, r.returncode


def conflicts(changes, start_ns):
    """Paths whose real file changed after the session started (first committer
    wins: optimistic concurrency control with backward validation)."""
    bad = []
    for c in changes:
        if c.ftype == "dir" and c.kind != DELETED:
            continue  # a dir's mtime changes whenever any entry changes
        st = _lstat(c.path)
        if st is not None and max(st.st_mtime_ns, st.st_ctime_ns) > start_ns:
            bad.append(c.path)
    return bad


def _remove_real(path):
    st = _lstat(path)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _install_file(c, data=None):
    """Write the staged copy (or merged `data`) next to the target, then
    rename() over it, so a reader sees either the old file or the new one,
    never half of each."""
    parent = os.path.dirname(c.path)
    os.makedirs(parent, exist_ok=True)
    real = _lstat(c.path)
    if real is not None and stat.S_ISDIR(real.st_mode):
        shutil.rmtree(c.path)
    tmp = os.path.join(parent, f".escrow-{secrets.token_hex(4)}-{os.path.basename(c.path)}"[:255])
    if c.ftype == "symlink":
        os.symlink(os.readlink(c.upper), tmp)
    elif data is not None:
        with open(tmp, "wb") as f:
            f.write(data)
        shutil.copymode(c.upper, tmp)
    else:
        shutil.copyfile(c.upper, tmp)
        shutil.copystat(c.upper, tmp)
    os.replace(tmp, c.path)


def apply(session, changes, force=False, markers=False):
    """Commit the given changes to the real filesystem.
    force: the agent's copy wins every conflict. markers: write conflicting
    3-way merges with <<<<<<< markers instead of refusing.
    Returns (done, skipped, merged) where merged = {path: n_conflicts}."""
    merged = {}
    if not force:
        by_path = {c.path: c for c in changes}
        unresolved, mergeable = [], []
        for path in conflicts(changes, session.meta["start_ns"]):
            res = three_way(session, by_path[path])
            if res is None:
                unresolved.append(path)
            elif res[1] == 0 or markers:
                merged[path] = res
            else:
                unresolved.append(path)
                mergeable.append(path)
        if unresolved:
            raise Conflict(unresolved, mergeable)
    done, skipped = [], []
    # 1. directories, parents first
    for c in sorted((c for c in changes if c.ftype == "dir" and c.kind != DELETED),
                    key=lambda c: c.path.count("/")):
        mode = stat.S_IMODE(os.lstat(c.upper).st_mode)
        real = _lstat(c.path)
        if c.kind == REPLACED:
            pass  # hidden lower entries arrive as separate DELETED changes
        elif real is not None and not stat.S_ISDIR(real.st_mode):
            os.unlink(c.path)
            real = None
        if real is None:
            os.makedirs(c.path, exist_ok=True)
        os.chmod(c.path, mode)
        done.append(c)
    # 2. files and symlinks
    for c in changes:
        if c.kind in (ADDED, MODIFIED) and c.ftype in ("file", "symlink"):
            _install_file(c, merged[c.path][0] if c.path in merged else None)
            done.append(c)
        elif c.kind in (ADDED, MODIFIED) and c.ftype == "other":
            skipped.append(c)
    # 3. deletions, deepest first
    for c in sorted((c for c in changes if c.kind == DELETED),
                    key=lambda c: c.path.count("/"), reverse=True):
        _remove_real(c.path)
        done.append(c)
    _forget(session, done)
    for c in done:
        try:
            os.unlink(base_path(session, c.path))
        except OSError:
            pass
    return done, skipped, {p: n for p, (_, n) in merged.items()}


def _forget(session, done):
    """Drop committed entries from the upper layer so they stop being pending."""
    upper_paths = set()
    for c in done:
        if c.upper and (c.ftype != "dir" or c.kind == DELETED):
            try:
                os.unlink(c.upper)
            except FileNotFoundError:
                pass
        elif c.upper:
            upper_paths.add(c.upper)
    # prune upper dirs that are now empty, unless they still carry an
    # uncommitted "opaque" (replace) marker
    for top, up in session.upper_dirs():
        for dirpath, dirnames, filenames in os.walk(up, topdown=False):
            if dirpath == up or os.listdir(dirpath):
                continue
            if is_opaque(dirpath) and dirpath not in upper_paths:
                continue
            try:
                os.rmdir(dirpath)
            except OSError:
                pass
