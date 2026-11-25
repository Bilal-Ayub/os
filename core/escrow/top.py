"""`escrow top`: an htop-style view of running agent sessions.

Every session runs in its own cgroup v2 (a systemd scope), so the kernel
already accounts its resources. This view joins those cgroup files with what
escrow knows about the session:

  CPU%     delta of cpu.stat usage_usec over the refresh interval
  MEM      memory.current / memory.max
  TASKS    pids.current / pids.max
  PSI      "some avg10" from cpu.pressure and memory.pressure: the share of the
           last 10 s in which the session's tasks were stalled waiting for CPU
           or memory (pressure stall information)
  STAGED   size of the overlay upper layer and number of staged entries
  NET      remote destinations contacted so far (from the strace log)
"""

import os
import subprocess
import sys
import time

from . import netlog
from .session import Session, session_ids


def cgroup_path(unit):
    out = subprocess.run(["systemctl", "--user", "show", "-p", "ControlGroup", "--value", unit],
                         capture_output=True, text=True)
    cg = out.stdout.strip()
    return "/sys/fs/cgroup" + cg if cg else None


def _read(cg, name):
    try:
        with open(os.path.join(cg, name)) as f:
            return f.read().strip()
    except OSError:
        return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _psi(text):
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("some"):
            for part in line.split():
                if part.startswith("avg10="):
                    return float(part[6:])
    return None


def sample(cg):
    cpu = _read(cg, "cpu.stat") or ""
    usage = next((int(l.split()[1]) for l in cpu.splitlines() if l.startswith("usage_usec")), None)
    return {
        "usage_usec": usage,
        "mem": _int(_read(cg, "memory.current")),
        "mem_max": _read(cg, "memory.max"),
        "pids": _int(_read(cg, "pids.current")),
        "pids_max": _read(cg, "pids.max"),
        "frozen": _read(cg, "cgroup.freeze") == "1",
        "psi_cpu": _psi(_read(cg, "cpu.pressure")),
        "psi_mem": _psi(_read(cg, "memory.pressure")),
    }


def staged(upper):
    size = n = 0
    for dirpath, dirnames, files in os.walk(upper):
        for name in files:
            n += 1
            try:
                size += os.lstat(os.path.join(dirpath, name)).st_blocks * 512
            except OSError:
                pass
    return size, n


def _h(n):
    if n is None:
        return "?"
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def _limit(v):
    if v in (None, "max"):
        return "max"
    i = _int(v)
    return _h(i) if i is not None and i > 100000 else str(v)


def rows(root, prev, interval):
    out = []
    for sid in session_ids(root):
        s = Session(root, sid)
        if not s.is_running():
            continue
        unit = s.meta.get("cgroup")
        cg = cgroup_path(unit) if unit else None
        st = sample(cg) if cg else {}
        cpu = None
        last = prev.get(sid)
        if st.get("usage_usec") is not None and last and last.get("usage_usec") is not None:
            cpu = (st["usage_usec"] - last["usage_usec"]) / (interval * 1e6) * 100
        prev[sid] = st
        size, n = staged(s.upper)
        conns = netlog.parse(s.meta.get("netlog"))
        state = "FROZEN" if st.get("frozen") else ("tainted" if _tripped(s) else "running")
        out.append({
            "id": sid, "profile": s.meta["profile"], "state": state,
            "cpu": "-" if cpu is None else f"{cpu:5.1f}",
            "mem": f"{_h(st.get('mem'))}/{_limit(st.get('mem_max'))}" if cg else "no cgroup",
            "tasks": f"{st.get('pids', '?')}/{_limit(st.get('pids_max'))}" if cg else "-",
            "psi": (f"{st['psi_cpu']:.0f}/{st['psi_mem']:.0f}"
                    if cg and st.get("psi_cpu") is not None and st.get("psi_mem") is not None else "-"),
            "staged": f"{_h(size)} ({n})",
            "net": "-" if conns is None else str(netlog.remote_count(conns)),
            "cmd": " ".join(s.meta["cmd"]),
        })
    return out


def _tripped(s):
    try:
        with open(os.path.join(s.dir, "events.jsonl")) as f:
            return any('"tripwire"' in line for line in f)
    except OSError:
        return False


HEADER = f"{'ID':>3}  {'PROFILE':<8} {'STATE':<8} {'CPU%':>5}  {'MEM':<15} {'TASKS':<9} {'PSI c/m':<8} {'STAGED':<12} {'NET':>3}  COMMAND"


def render(table, width):
    lines = [HEADER]
    for r in table:
        line = (f"{r['id']:>3}  {r['profile']:<8} {r['state']:<8} {r['cpu']:>5}  {r['mem']:<15} "
                f"{r['tasks']:<9} {r['psi']:<8} {r['staged']:<12} {r['net']:>3}  {r['cmd']}")
        lines.append(line[:width])
    if not table:
        lines.append("  (no running sessions)")
    return lines


def run(root, interval=2.0, once=False):
    prev = {}
    rows(root, prev, interval)  # first sample: CPU% needs two readings
    if once:
        time.sleep(min(interval, 1.0))
        for line in render(rows(root, prev, min(interval, 1.0)), 200):
            print(line)
        return 0
    try:
        while True:
            time.sleep(interval)
            width = os.get_terminal_size().columns if sys.stdout.isatty() else 200
            table = rows(root, prev, interval)
            sys.stdout.write("\033[H\033[2J")
            print(f"escrow top  (every {interval:g}s; Ctrl-C to quit; "
                  "escrow freeze|thaw|kill ID in another terminal)\n")
            for line in render(table, width):
                print(line)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print()
        return 0
