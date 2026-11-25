"""Read the strace network log of a session.

strace runs *outside* the sandbox, tracing only connect() (via a seccomp
pre-filter, so other syscalls run at full speed). Lines look like:

  4242  14:02:11.123456 connect(3, {sa_family=AF_INET, sin_port=htons(80),
        sin_addr=inet_addr("93.184.215.14")}, 16) = -1 EINPROGRESS (...)

Data sent over a connection cannot be recalled by Discard, so the review
screen shows these as irreversible.
"""

import os
import re

_LINE = re.compile(r"^(?P<pid>\d+)\s+(?P<time>[\d:.]+)\s+(?P<rest>.*)$")
_INET = re.compile(r'sin_port=htons\((?P<port>\d+)\), sin_addr=inet_addr\("(?P<addr>[^"]+)"\)')
_INET6 = re.compile(r'sin6_port=htons\((?P<port>\d+)\).*?inet_pton\(AF_INET6, "(?P<addr>[^"]+)"')
_UNIX = re.compile(r'sun_path=(?P<path>@?"[^"]*")')
_RESULT = re.compile(r"\)\s+=\s+(?P<ret>-?\d+)(?:\s+(?P<err>[A-Z0-9_]+))?")


class Connection:
    __slots__ = ("time", "pid", "family", "addr", "port", "result")

    def __init__(self, time, pid, family, addr, port, result):
        self.time, self.pid, self.family = time, pid, family
        self.addr, self.port, self.result = addr, port, result

    @property
    def local(self):
        return self.family == "unix" or self.addr.startswith("127.") or self.addr in ("::1", "0.0.0.0", "::")

    def describe(self):
        if self.family == "unix":
            return f"unix socket {self.addr}"
        host = f"[{self.addr}]" if ":" in self.addr else self.addr
        tag = " (DNS)" if self.port == 53 else ""
        return f"{host}:{self.port}{tag}"


def _result(text):
    m = _RESULT.search(text)
    if not m:
        return "?"
    if m.group("ret") == "0":
        return "connected"
    err = m.group("err") or "error"
    return "attempted (async)" if err == "EINPROGRESS" else f"failed: {err}"


def parse(path):
    """List of Connection, in order. Missing log -> None."""
    if not path or not os.path.exists(path):
        return None
    conns, pending = [], {}
    with open(path, errors="replace") as f:
        for raw in f:
            m = _LINE.match(raw.strip())
            if not m:
                continue
            pid, t, rest = m.group("pid"), m.group("time"), m.group("rest")
            if rest.startswith("<... connect resumed>"):
                c = pending.pop(pid, None)
                if c:
                    c.result = _result(rest)
                continue
            if not rest.startswith("connect("):
                continue
            c = None
            for fam, rx in (("ipv4", _INET), ("ipv6", _INET6)):
                mm = rx.search(rest)
                if mm:
                    c = Connection(t, int(pid), fam, mm.group("addr"), int(mm.group("port")), "?")
                    break
            if c is None:
                mm = _UNIX.search(rest)
                if mm:
                    c = Connection(t, int(pid), "unix", mm.group("path").strip('"'), 0, "?")
            if c is None:
                continue
            if "<unfinished ...>" in rest:
                pending[pid] = c
            else:
                c.result = _result(rest)
            conns.append(c)
    return conns


def report(conns, include_unix=False):
    """Human-readable lines, one per distinct destination."""
    if conns is None:
        return ["(no network log: strace was not available for this session)"]
    seen = {}
    for c in conns:
        if c.family == "unix" and not include_unix:
            continue
        key = (c.family, c.addr, c.port)
        if key not in seen:
            seen[key] = [c, 0]
        seen[key][1] += 1
    unix = sum(1 for c in conns if c.family == "unix")
    lines = []
    for c, n in seen.values():
        where = "local" if c.local else "REMOTE"
        times = f" x{n}" if n > 1 else ""
        lines.append(f"{c.time}  {where:6}  {c.describe()}  {c.result}{times}")
    if not lines:
        lines.append("no network connections")
    if unix and not include_unix:
        lines.append(f"(+{unix} local unix-socket connections; escrow log --all shows them)")
    return lines


def remote_count(conns):
    if not conns:
        return 0
    return len({(c.addr, c.port) for c in conns if not c.local})
