"""The `escrow` command line."""

import argparse
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import time

from . import __version__, changes, explain, ledger, netlog, policy, top
from .session import (CLEAN, COMMITTED, DISCARDED, PENDING, RUNNING, EscrowError,
                      get_session, new_session, session_ids, state_root, warn, Session)

PROFILES = {
    # name: (network, files, description)
    "coding": ("allowed, logged", "home writable (staged)",
               "normal coding agent; network allowed and logged"),
    "strict": ("allowed, logged", "only the project + agent dirs in $HOME (Landlock)",
               "like coding, but the rest of your home folder is invisible"),
    "offline": ("none (loopback only)", "home writable (staged)",
                "no network at all (private network namespace)"),
}
DEFAULT_LIMITS = {"memory": "4G", "cpu": "200%", "tasks": "512"}


def _enter_path():
    pkg = os.path.dirname(os.path.abspath(__file__))
    base = os.path.dirname(pkg)
    for cand in (os.path.join(base, "escrow-enter"),
                 os.path.join(base, "libexec", "escrow-enter"),
                 "/usr/lib/escrow/escrow-enter"):
        if os.path.exists(cand):
            return cand
    raise EscrowError("escrow-enter helper not found")


def _have_user_systemd():
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return shutil.which("systemd-run") and os.path.exists(os.path.join(runtime, "bus"))


def _fmt_time(ns):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ns / 1e9)) if ns else "-"


def _session(args, root=None):
    root = root or state_root(quiet=True)
    return get_session(root, getattr(args, "id", None))


def _split_id(items):
    """`escrow commit 3 a b` / `escrow commit a b`: optional leading id."""
    if items and items[0].isdigit():
        return int(items[0]), items[1:]
    return None, items


def _events(s):
    try:
        with open(os.path.join(s.dir, "events.jsonl")) as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


def _tainted(s):
    return [e for e in _events(s) if e.get("event") == "tripwire"]


def _assessed(s, items):
    found = changes.scan(s)
    selected = changes.select(found, items)
    warnings = policy.assess(selected, s.meta.get("home") or os.path.expanduser("~"))
    return selected, warnings


def _cgroup_dir(s):
    unit = s.meta.get("cgroup")
    if not unit or not s.is_running():
        raise EscrowError(f"session {s.id} is not running (or has no cgroup)")
    cg = top.cgroup_path(unit)
    if not cg:
        raise EscrowError(f"cannot find the cgroup of {unit}")
    return cg


# ---------------------------------------------------------------- run

def cmd_run(args):
    if os.environ.get("ESCROW_SESSION"):
        raise EscrowError(f"already inside escrow session {os.environ['ESCROW_SESSION']}; "
                          "nested sessions are not allowed")
    if os.getuid() == 0:
        raise EscrowError("run escrow as a normal user, not root")
    cmd = args.command or [os.environ.get("SHELL", "/bin/bash")]
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise EscrowError("nothing to run")
    root = state_root()
    limits = {"memory": args.memory, "cpu": args.cpu, "tasks": str(args.tasks)}
    s = new_session(root, cmd, args.profile, os.getcwd(), limits)
    s.meta["home"] = os.path.realpath(os.path.expanduser("~"))
    s.meta["shield"] = not args.no_shield

    launch = [_enter_path(), s.dir]
    strace = shutil.which("strace")
    if strace:
        launch = [strace, "-f", "--seccomp-bpf", "-qq", "-tt", "-e", "trace=connect",
                  "-e", "signal=none", "-o", s.netlog, "--"] + launch
        s.meta["netlog"] = s.netlog
    else:
        warn("strace is not installed: network connections will NOT be logged")
    if not args.no_cgroup and _have_user_systemd():
        launch = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
                  f"--unit={s.meta['unit']}",
                  "-p", f"MemoryMax={args.memory}", "-p", "MemorySwapMax=0",
                  "-p", f"CPUQuota={args.cpu}",
                  "-p", f"TasksMax={args.tasks}", "--"] + launch
        s.meta["cgroup"] = f"{s.meta['unit']}.scope"
    else:
        if not args.no_cgroup:
            warn("no systemd user session: running WITHOUT cgroup limits")
        s.meta["unit"] = None
    s.save()
    ledger.append(root, "session-start", session=s.id, cmd=cmd, profile=args.profile,
                  cwd=s.meta["cwd"], limits=limits, shield=s.meta["shield"])

    print(f"escrow: session {s.id} [{args.profile}] {' '.join(cmd)}", file=sys.stderr)
    print("escrow: writes are staged; nothing reaches your files until you commit", file=sys.stderr)
    old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGQUIT)}
    try:
        code = subprocess.run(launch).returncode
    finally:
        for sig, h in old.items():
            signal.signal(sig, h)
    code = 128 - code if code < 0 else code

    pending = changes.scan(s)
    status = PENDING if pending else CLEAN
    if pending:
        changes.snapshot_bases(s, pending)  # common ancestors for a later 3-way merge
    else:
        s.remove_layers()
    trips = _tainted(s)
    s.update(end_ns=time.time_ns(), exit_code=code, status=status, tainted=bool(trips))
    conns = netlog.parse(s.meta.get("netlog"))
    ledger.append(root, "session-end", session=s.id, exit_code=code,
                  changes=changes.summary(pending), tainted=bool(trips),
                  tripwire=[p for e in trips for p in e.get("paths", [])],
                  remote_destinations=netlog.remote_count(conns),
                  netlog_sha256=ledger.file_sha256(s.netlog) if conns is not None else None)

    print(file=sys.stderr)
    if code == 125:
        print(f"escrow: session {s.id}: sandbox setup failed (see message above)", file=sys.stderr)
        return 125
    print(f"escrow: session {s.id} finished (exit {code}): {changes.summary(pending)}", file=sys.stderr)
    if trips:
        print(f"escrow: session {s.id} is TAINTED: the agent opened decoy secrets. "
              "Discard is recommended.", file=sys.stderr)
    if conns is not None:
        print(f"escrow: {netlog.remote_count(conns)} remote destination(s) contacted "
              f"(escrow log {s.id})", file=sys.stderr)
    if pending:
        print(f"escrow: review with `escrow review {s.id}` "
              f"(or escrow diff / commit / discard {s.id})", file=sys.stderr)
    return code


# ---------------------------------------------------------------- inspect

def cmd_ls(args):
    root = state_root(quiet=True)
    ids = session_ids(root)
    if args.quiet:
        for sid in ids:
            print(sid)
        return 0
    if not ids:
        print("no sessions")
        return 0
    print(f"{'ID':>3}  {'STATUS':<10} {'PROFILE':<8} {'STARTED':<19}  {'CHANGES':>7}  COMMAND")
    for sid in ids:
        s = Session(root, sid)
        st = s.status
        n = len(changes.scan(s)) if st in (RUNNING, PENDING) else 0
        cmd = " ".join(s.meta["cmd"])
        flag = "!" if s.meta.get("tainted") else " "
        print(f"{sid:>3}{flag} {st:<10} {s.meta['profile']:<8} {_fmt_time(s.meta['start_ns'])}  "
              f"{n:>7}  {cmd[:60]}")
    if any(Session(root, i).meta.get("tainted") for i in ids):
        print("(! = tainted: the agent opened decoy secrets)")
    return 0


def _print_warnings(selected, warnings):
    n = len(policy.risky(selected))
    if n:
        print(changes.color(f"\n{n} change(s) flagged as risky (persistence, credentials or "
                            "config that runs code).", "1;31"))
    for w in warnings:
        print(changes.color(f"WARNING: {w}", "1;31"))


def cmd_diff(args):
    s = _session(args)
    pending, warnings = _assessed(s, args.paths)
    if not pending:
        print(f"session {s.id}: no pending changes")
        return 0
    if s.is_running():
        print(f"(session {s.id} is still running; this is a live view)\n")
    for line in changes.stat_lines(pending):
        print(line)
    print(f"\n{changes.summary(pending)}")
    _print_warnings(pending, warnings)
    if not args.stat:
        print()
        changes.print_diff(pending)
    return 0


def cmd_log(args):
    s = _session(args)
    m = s.meta
    print(f"session   {s.id}  ({s.status}){'  TAINTED' if m.get('tainted') else ''}")
    print(f"command   {' '.join(m['cmd'])}")
    net, files, _ = PROFILES.get(m["profile"], ("?", "?", ""))
    print(f"profile   {m['profile']}  network: {net}; files: {files}")
    print(f"cwd       {m['cwd']}")
    print(f"started   {_fmt_time(m['start_ns'])}")
    print(f"ended     {_fmt_time(m['end_ns'])}   exit code: {m['exit_code']}")
    lim = m["limits"]
    cg = m.get("cgroup") or "none (no cgroup limits applied)"
    print(f"cgroup    {cg}  memory={lim['memory']} cpu={lim['cpu']} tasks={lim['tasks']}")
    print(f"shield    {'on (decoy secrets + tripwire)' if m.get('shield', True) else 'off'}")
    print(f"layers    {s.dir}")
    ev = _events(s)
    if ev:
        print("\nevents:")
        for e in ev:
            detail = e.get("detail") or ", ".join(e.get("paths", [])) or e.get("by", "")
            print(f"  {e.get('time', '')}  {e['event']:<16} {detail}")
    print("\nnetwork (connect() calls made by the agent):")
    for line in netlog.report(netlog.parse(m.get("netlog")), include_unix=args.all):
        print("  " + line)
    return 0


# ---------------------------------------------------------------- decide

def _check_decidable(s):
    if s.is_running():
        raise EscrowError(f"session {s.id} is still running; wait for the agent to exit")
    if s.status in (COMMITTED, DISCARDED, CLEAN):
        raise EscrowError(f"session {s.id} is already {s.status}")


def _confirm(prompt, assume_yes):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise EscrowError("not a terminal: pass --yes to confirm")
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def _do_commit(s, selected, force, accept_risk, markers=False):
    risky = policy.risky(selected)
    if risky and not accept_risk:
        print("escrow: REFUSED: these changes are flagged as risky:", file=sys.stderr)
        for c in risky:
            print(f"  {c.path}: {c.risk}", file=sys.stderr)
        print("escrow: nothing was committed. Commit other paths, discard, or re-run with "
              "--accept-risk after reading the diff.", file=sys.stderr)
        return 1
    try:
        done, skipped, merged = changes.apply(s, selected, force=force, markers=markers)
    except changes.Conflict as e:
        print("escrow: CONFLICT: these files changed on disk after the session started,",
              file=sys.stderr)
        print("        and could not be merged automatically:", file=sys.stderr)
        for p in e.paths:
            hint = ("  (overlapping edits; --markers writes <<<<<<< conflict markers)"
                    if p in e.mergeable else "")
            print(f"  {p}{hint}", file=sys.stderr)
        print("escrow: nothing was committed. Commit other paths, use --markers to resolve "
              "by hand, or --force to let the agent's copy win.", file=sys.stderr)
        return 1
    for p, n in merged.items():
        how = "merged cleanly (3-way)" if n == 0 else f"merged with {n} conflict(s) marked: edit it"
        print(f"escrow: {p}: {how}")
    for c in skipped:
        warn(f"skipped {c.path} ({c.note})")
    ledger.append(s.root, "commit", session=s.id, forced=force, merged=merged,
                  accepted_risks=[{"path": c.path, "risk": c.risk} for c in risky],
                  changes=[{"kind": c.kind, "path": c.path,
                            "sha256": ledger.file_sha256(c.path) if c.ftype == "file"
                            and c.kind != changes.DELETED else None} for c in done])
    remaining = changes.scan(s)
    if remaining:
        s.update(status=PENDING)
        print(f"escrow: committed {len(done)} change(s); {len(remaining)} still pending "
              f"in session {s.id}")
    else:
        s.remove_layers()
        s.update(status=COMMITTED, decided_ns=time.time_ns())
        print(f"escrow: committed {len(done)} change(s); session {s.id} is closed")
    return 0


def cmd_commit(args):
    args.id, paths = _split_id(args.items)
    s = _session(args)
    _check_decidable(s)
    selected, warnings = _assessed(s, paths)
    if not selected:
        print("escrow: nothing to commit" + (" under those paths" if paths else ""))
        return 0
    for line in changes.stat_lines(selected):
        print(line)
    _print_warnings(selected, warnings)
    if s.meta.get("tainted"):
        print(changes.color(f"WARNING: session {s.id} is tainted (the agent went for your "
                            "secrets). Discard is recommended.", "1;31"))
    if not _confirm(f"Commit these {len(selected)} change(s) to the real filesystem?", args.yes):
        print("escrow: aborted")
        return 1
    return _do_commit(s, selected, args.force, args.accept_risk, args.markers)


def _do_discard(s):
    n = len(changes.scan(s))
    s.remove_layers()
    s.update(status=DISCARDED, decided_ns=time.time_ns())
    ledger.append(s.root, "discard", session=s.id, changes_dropped=n)
    print(f"escrow: discarded session {s.id}; your files were never touched")
    return 0


def cmd_discard(args):
    s = _session(args)
    _check_decidable(s)
    n = len(changes.scan(s))
    if not _confirm(f"Throw away all {n} staged change(s) of session {s.id}?", args.yes):
        print("escrow: aborted")
        return 1
    return _do_discard(s)


def cmd_review(args):
    s = _session(args)
    _check_decidable(s)
    if args.explain:
        _explain(s)
        print()
    pending, warnings = _assessed(s, [])
    conns = netlog.parse(s.meta.get("netlog"))
    print(f"Session {s.id}: {' '.join(s.meta['cmd'])}  (exit {s.meta['exit_code']})\n")
    trips = _tainted(s)
    if trips:
        paths = sorted({p for e in trips for p in e.get("paths", [])})
        print(changes.color("TAINTED: the agent opened decoy secrets: " + ", ".join(paths), "1;41;97"))
        print("Discard is recommended.\n")
    print("Staged file changes (reversible: nothing has been written yet):")
    for line in changes.stat_lines(pending) or ["none"]:
        print("  " + line)
    print(f"  {changes.summary(pending)}")
    _print_warnings(pending, warnings)
    print("\nNetwork activity (IRREVERSIBLE: this already happened; Discard cannot undo it):")
    for line in netlog.report(conns):
        print("  " + line)
    print()
    if not sys.stdin.isatty():
        print(f"Decide with: escrow commit {s.id} [paths] --yes   or   escrow discard {s.id} --yes")
        return 0
    while True:
        ans = input("[c]ommit all, [d]iscard all, [v]iew full diff, [q]uit (decide later): ").strip().lower()
        if ans in ("v", "view"):
            changes.print_diff(pending)
        elif ans in ("c", "commit"):
            accept = False
            if policy.risky(pending):
                accept = input("Risky changes included. Type 'accept risk' to commit them anyway: "
                               ).strip().lower() == "accept risk"
                if not accept:
                    print("escrow: not committed")
                    continue
            return _do_commit(s, pending, force=False, accept_risk=accept)
        elif ans in ("d", "discard"):
            return _do_discard(s)
        elif ans in ("q", "quit", ""):
            print(f"escrow: session {s.id} stays pending")
            return 0


# ---------------------------------------------------------------- explain

def _explain(s):
    """Print the local model's advisory summary of a session."""
    pending, warnings = _assessed(s, [])
    verified = [f"RISKY change {c.path}: {c.risk}" for c in policy.risky(pending)] + warnings
    trips = sorted({p for e in _tainted(s) for p in e.get("paths", [])})
    if trips:
        verified.append("TRIPWIRE: the agent opened decoy secret files " + ", ".join(trips))
    conflicts = changes.conflicts(pending, s.meta["start_ns"])
    if conflicts:
        verified.append(f"{len(conflicts)} file(s) changed on disk since the session started")
    conns = netlog.parse(s.meta.get("netlog"))
    net = netlog.report(conns)
    buf = io.StringIO()
    changes.print_diff(pending, out=buf)
    stat = [l for l in changes.stat_lines(pending)]
    prompt = explain.build_prompt(s.meta, stat, buf.getvalue(), verified, net)
    print("Asking the local model (advisory only; the diff was written by the agent and may "
          "try to manipulate the summary)...", file=sys.stderr)
    try:
        data, url, model = explain.explain(prompt)
    except explain.ExplainError as e:
        print(f"escrow: explain: {e}", file=sys.stderr)
        return 1
    risk_color = {"low": "32", "medium": "33", "high": "1;31"}.get(data.get("risk"), "")
    print(f"\nAI summary ({model} at {url}; advisory):")
    print(f"  {data.get('summary', '').strip()}")
    print(f"  risk: {changes.color(str(data.get('risk', '?')).upper(), risk_color)}"
          f"   suggestion: {data.get('recommendation', '?')}")
    for c in data.get("concerns") or []:
        print(f"  - {c}")
    if verified:
        print("\nVerified by escrow (not by the model):")
        for v in verified:
            print(changes.color(f"  ! {v}", "1;31"))
    return 0


def cmd_explain(args):
    s = _session(args)
    if s.status not in (PENDING, RUNNING):
        raise EscrowError(f"session {s.id} is {s.status}: nothing to explain")
    return _explain(s)


# ---------------------------------------------------------------- control

def cmd_control(args):
    """freeze / thaw / kill a running session through its cgroup."""
    s = _session(args)
    cg = _cgroup_dir(s)
    target, value = {"freeze": ("cgroup.freeze", "1"), "thaw": ("cgroup.freeze", "0"),
                     "kill": ("cgroup.kill", "1")}[args.action]
    with open(os.path.join(cg, target), "w") as f:
        f.write(value)
    ledger.append(s.root, args.action, session=s.id)
    print(f"escrow: session {s.id}: {args.action} done ({target})")
    return 0


def cmd_top(args):
    return top.run(state_root(quiet=True), args.interval, args.once)


def cmd_ledger(args):
    root = state_root(quiet=True)
    recs = ledger.records(root)
    if args.session is not None:
        recs = [r for r in recs if r.get("session") == args.session]
    for r in recs[-args.n:] if args.n else recs:
        extra = {k: v for k, v in r.items() if k not in ("seq", "time", "event", "session", "prev", "hash")}
        detail = json.dumps(extra, ensure_ascii=False)
        if len(detail) > 140 and not args.full:
            detail = detail[:137] + "..."
        print(f"{r['seq']:>4}  {r['time']}  {r['event']:<14} s{r.get('session', '-')}  {detail}")
    return 0


def cmd_verify(args):
    ok, n, info = ledger.verify(state_root(quiet=True))
    if ok:
        print(f"ledger OK: {n} record(s), chain intact. Head: {info}")
        return 0
    print(f"ledger BROKEN after {n} valid record(s): {info}")
    return 1


# ---------------------------------------------------------------- main

def build_parser():
    p = argparse.ArgumentParser(
        prog="escrow",
        description="Run AI agents as reversible transactions: every write is staged "
                    "on a copy-on-write layer until you review and commit it.")
    p.add_argument("--version", action="version", version=f"escrow {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    r = sub.add_parser("run", help="run a command (an agent) inside a new session")
    r.add_argument("--profile", choices=sorted(PROFILES), default="coding",
                   help="coding: network logged; strict: also hide the rest of $HOME; "
                        "offline: no network")
    r.add_argument("--memory", default=DEFAULT_LIMITS["memory"], help="cgroup MemoryMax (default 4G)")
    r.add_argument("--cpu", default=DEFAULT_LIMITS["cpu"], help="cgroup CPUQuota (default 200%%)")
    r.add_argument("--tasks", type=int, default=int(DEFAULT_LIMITS["tasks"]),
                   help="cgroup TasksMax (default 512)")
    r.add_argument("--no-cgroup", action="store_true", help="do not apply cgroup limits")
    r.add_argument("--no-shield", action="store_true",
                   help="let the agent see your real ~/.ssh, ~/.aws, ... (no decoys)")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- command [args...] (default: $SHELL)")
    r.set_defaults(func=cmd_run)

    ls = sub.add_parser("ls", help="list sessions")
    ls.add_argument("-q", "--quiet", action="store_true", help="only print session ids")
    ls.set_defaults(func=cmd_ls)

    d = sub.add_parser("diff", help="show staged changes (risky ones are flagged)")
    d.add_argument("id", nargs="?", type=int)
    d.add_argument("paths", nargs="*")
    d.add_argument("--stat", action="store_true", help="only the list of changed paths")
    d.set_defaults(func=cmd_diff)

    l = sub.add_parser("log", help="show session details, events and network activity")
    l.add_argument("id", nargs="?", type=int)
    l.add_argument("--all", action="store_true", help="include unix-socket connections")
    l.set_defaults(func=cmd_log)

    v = sub.add_parser("review", help="review a session and decide: commit or discard")
    v.add_argument("id", nargs="?", type=int)
    v.add_argument("--explain", action="store_true", help="first show a local AI summary")
    v.set_defaults(func=cmd_review)

    e = sub.add_parser("explain", help="plain-English summary of a session by a local LLM (advisory)")
    e.add_argument("id", nargs="?", type=int)
    e.set_defaults(func=cmd_explain)

    t = sub.add_parser("top", help="live view of running sessions (cgroup CPU, memory, tasks, PSI)")
    t.add_argument("-i", "--interval", type=float, default=2.0, help="seconds between refreshes")
    t.add_argument("--once", action="store_true", help="print one snapshot and exit")
    t.set_defaults(func=cmd_top)

    c = sub.add_parser("commit", help="apply staged changes (all, or only some paths)")
    c.add_argument("items", nargs="*", metavar="[ID] [PATH ...]")
    c.add_argument("--force", action="store_true", help="overwrite files changed since the session started")
    c.add_argument("--accept-risk", action="store_true", help="also commit changes flagged as risky")
    c.add_argument("--markers", action="store_true",
                   help="on overlapping edits, write the 3-way merge with conflict markers")
    c.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    c.set_defaults(func=cmd_commit)

    x = sub.add_parser("discard", help="throw away all staged changes of a session")
    x.add_argument("id", nargs="?", type=int)
    x.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    x.set_defaults(func=cmd_discard)

    for action, text in (("freeze", "pause every process of a running session (cgroup.freeze)"),
                         ("thaw", "resume a frozen session"),
                         ("kill", "kill every process of a running session (cgroup.kill)")):
        a = sub.add_parser(action, help=text)
        a.add_argument("id", nargs="?", type=int)
        a.set_defaults(func=cmd_control, action=action)

    g = sub.add_parser("ledger", help="show the hash-chained audit ledger")
    g.add_argument("--session", type=int, help="only records of this session")
    g.add_argument("-n", type=int, default=0, help="only the last N records")
    g.add_argument("--full", action="store_true", help="do not shorten long records")
    g.set_defaults(func=cmd_ledger)

    sub.add_parser("verify", help="check the ledger's hash chain").set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except EscrowError as e:
        print(f"escrow: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
