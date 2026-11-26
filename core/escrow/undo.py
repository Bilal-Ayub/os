"""Undo a commit: a write-ahead undo log.

Before `escrow commit` touches a real path, the original is copied into the
session's undo journal, and the journal is written to disk. Only then does the
commit start. So the log always describes the state before the commit, even if
the commit crashed half-way (the same rule as a database's undo log or a
journaling file system: log first, then change).

    <session>/undo/<n>/journal.json   one journal per commit (partial commits
                                       make several)
    <session>/undo/<n>/files/<i>      backup of the original of entry i

Each journal entry says how to reverse one change:
    remove   the commit created this file or symlink: delete it
    rmdir    the commit created this dir: delete it if it is empty
    restore  the commit overwrote or deleted this path: put the backup back
    chmod    the commit changed this dir's mode: put the old mode back

After the commit, each entry also records what the path looks like now
("after": a sha256 for files). `escrow undo` refuses if a path no longer looks
like that: somebody changed it after the commit, and undoing would destroy
their work (optimistic concurrency again, as at commit time).

Undo covers files only. It cannot take back network effects (an upload or a
`git push` already happened).
"""

import json
import os
import secrets
import shutil
import stat
import time

from . import changes, ledger
from .session import warn


class Conflict(Exception):
    def __init__(self, paths):
        super().__init__(f"{len(paths)} path(s) changed since the commit")
        self.paths = paths


def _root(session):
    return os.path.join(session.dir, "undo")


def _write(jdir, data):
    path = os.path.join(jdir, "journal.json")
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def _fingerprint(path):
    """What a path looks like: None, 'dir', 'symlink:<target>', 'file:<sha256>'."""
    st = _lstat(path)
    if st is None:
        return None
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISLNK(st.st_mode):
        return "symlink:" + os.readlink(path)
    if stat.S_ISREG(st.st_mode):
        return "file:" + (ledger.file_sha256(path) or "?")
    return "other"


def _copy(src, dst):
    """Copy a file, symlink or whole tree, keeping modes and times."""
    st = os.lstat(src)
    if stat.S_ISDIR(st.st_mode):
        shutil.copytree(src, dst, symlinks=True)
    elif stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(src), dst)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)


# ---------------------------------------------------------------- record

def prepare(session, chs):
    """Back up everything `chs` will overwrite or delete, and write the
    journal, before the commit changes anything. Returns the journal dir."""
    root = _root(session)
    os.makedirs(root, mode=0o700, exist_ok=True)
    n = max((int(x) for x in os.listdir(root) if x.isdigit()), default=0) + 1
    jdir = os.path.join(root, str(n))
    files = os.path.join(jdir, "files")
    os.makedirs(files, mode=0o700)
    entries = []
    for c in chs:
        if c.ftype == "other" and c.kind != changes.DELETED:
            continue  # special files are never committed
        real = _lstat(c.path)
        e = {"path": c.path, "kind": c.kind}
        if real is None:
            if c.kind == changes.DELETED:
                continue  # nothing there to delete
            e["action"] = "rmdir" if c.ftype == "dir" else "remove"
        elif c.ftype == "dir" and c.kind != changes.DELETED and stat.S_ISDIR(real.st_mode):
            e["action"], e["mode"] = "chmod", stat.S_IMODE(real.st_mode)
        else:
            e["action"] = "restore"
            e["backup"] = str(len(entries))
            try:
                _copy(c.path, os.path.join(files, e["backup"]))
            except (OSError, shutil.Error) as err:
                warn(f"cannot back up {c.path} ({err}); this change cannot be undone")
                e["lost"] = True
        entries.append(e)
    data = {"session": session.id, "commit": n, "time_ns": time.time_ns(),
            "complete": False, "reverted": False, "entries": entries}
    _write(jdir, data)
    return jdir


def finish(jdir):
    """Record what every journalled path looks like right after the commit."""
    data = load(jdir)
    for e in data["entries"]:
        e["after"] = _fingerprint(e["path"])
    data["complete"] = True
    _write(jdir, data)


# ---------------------------------------------------------------- replay

def load(jdir):
    with open(os.path.join(jdir, "journal.json")) as f:
        return json.load(f)


def pending(session):
    """(journal dir, data) of commits not undone yet, newest first."""
    root = _root(session)
    try:
        names = sorted((int(x) for x in os.listdir(root) if x.isdigit()), reverse=True)
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        jdir = os.path.join(root, str(n))
        try:
            data = load(jdir)
        except (OSError, ValueError):
            continue
        if not data.get("reverted"):
            out.append((jdir, data))
    return out


def changed_since_commit(journals):
    bad = []
    for _, data in journals:
        for e in data["entries"]:
            if "after" in e and _fingerprint(e["path"]) != e["after"]:
                bad.append(e["path"])
    return bad


def _restore(backup, path):
    """Put `backup` at `path`: copy it next to the target, then rename it over."""
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    tmp = os.path.join(parent, f".escrow-undo-{secrets.token_hex(4)}-{os.path.basename(path)}"[:255])
    _copy(backup, tmp)
    cur = _lstat(path)
    if cur is not None and (stat.S_ISDIR(cur.st_mode) or os.path.isdir(tmp)):
        changes._remove_real(path)  # rename() cannot replace a dir, or put a dir over a file
    os.replace(tmp, path)


def revert(session, force=False):
    """Undo every commit of the session that is not undone yet, newest first.
    Returns counts and the paths that could not be put back."""
    journals = pending(session)
    if not force:
        bad = changed_since_commit(journals)
        if bad:
            raise Conflict(bad)
    res = {"commits": [], "restored": 0, "removed": 0, "kept": [], "lost": []}
    depth = lambda e: e["path"].count("/")
    for jdir, data in journals:
        es = data["entries"]
        # 1. what the commit created: files first, deepest first, then dirs
        for e in sorted((e for e in es if e["action"] == "remove"), key=depth, reverse=True):
            if _lstat(e["path"]) is not None:
                changes._remove_real(e["path"])
                res["removed"] += 1
        for e in sorted((e for e in es if e["action"] == "rmdir"), key=depth, reverse=True):
            try:
                os.rmdir(e["path"])
                res["removed"] += 1
            except FileNotFoundError:
                pass
            except OSError:
                res["kept"].append(e["path"])  # someone put new files in it
        # 2. what the commit overwrote or deleted, parents first
        for e in sorted((e for e in es if e["action"] == "restore"), key=depth):
            if e.get("lost"):
                res["lost"].append(e["path"])
                continue
            _restore(os.path.join(jdir, "files", e["backup"]), e["path"])
            res["restored"] += 1
        # 3. old dir modes
        for e in es:
            if e["action"] == "chmod" and os.path.isdir(e["path"]):
                os.chmod(e["path"], e["mode"])
        data["reverted"] = True
        data["reverted_ns"] = time.time_ns()
        _write(jdir, data)
        res["commits"].append(data["commit"])
    return res
