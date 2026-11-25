"""Hash-chained, append-only ledger of everything escrow does.

Each record stores the hash of the previous record, and its own hash is
    sha256(canonical JSON of the record including "prev")
Changing, deleting or reordering any record breaks every hash after it, and
`escrow verify` finds the first broken link. This makes the log tamper-EVIDENT,
not tamper-proof: someone who can rewrite the whole file can rebuild the chain.
To guard against that, keep a copy of the head hash somewhere else, e.g. in a
commit message. The file lives in the per-user state dir, which agents cannot
see or write.
"""

import fcntl
import hashlib
import json
import os
import time

GENESIS = "0" * 64


def path(root):
    return os.path.join(root, "ledger.jsonl")


def _digest(record):
    body = {k: v for k, v in record.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _last(f):
    f.seek(0)
    last = None
    for line in f:
        if line.strip():
            last = line
    return json.loads(last) if last else None


def append(root, event, **data):
    """Append one record (process-safe via flock). Returns the record."""
    p = path(root)
    fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        prev = _last(f)
        record = {"seq": (prev["seq"] + 1) if prev else 1,
                  "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                  "event": event, **data,
                  "prev": prev["hash"] if prev else GENESIS}
        record["hash"] = _digest(record)
        f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return record


def records(root):
    try:
        with open(path(root)) as f:
            return [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError:
        return []


def verify(root):
    """Return (ok, n_records, head_hash_or_problem)."""
    prev, n = GENESIS, 0
    try:
        f = open(path(root))
    except FileNotFoundError:
        return True, 0, GENESIS
    with f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                return False, n, f"line {lineno}: not valid JSON"
            if r.get("prev") != prev:
                return False, n, f"record seq {r.get('seq')} (line {lineno}): previous-hash link broken"
            if _digest(r) != r.get("hash"):
                return False, n, f"record seq {r.get('seq')} (line {lineno}): content does not match its hash"
            prev, n = r["hash"], n + 1
    return True, n, prev


def file_sha256(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for block in iter(lambda: f.read(1 << 16), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()
