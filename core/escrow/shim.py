"""Make escrow the default for every agent CLI.

/usr/lib/escrow/shims/ is kept first on PATH (by /etc/escrow/path.sh) and
holds one symlink per known agent (claude, codex, gemini, ...), all pointing
to escrow-shim. The shim looks up the agent's profile in
/etc/escrow/agents.d/<name>.toml, finds the real binary further down PATH and
runs it through `escrow run`. Inside a session (ESCROW_SESSION is set) it runs
the real binary directly, so sessions never nest.
"""

import os
import sys
import tomllib

AGENTS_DIR = os.environ.get("ESCROW_AGENTS_DIR", "/etc/escrow/agents.d")


def load_agent(name):
    path = os.path.join(AGENTS_DIR, f"{name}.toml")
    try:
        with open(path, "rb") as f:
            conf = tomllib.load(f)
    except FileNotFoundError:
        conf = {}
    conf.setdefault("profile", "coding")
    conf.setdefault("enabled", True)
    return conf


def find_real(name, shim_dir):
    shim_dir = os.path.realpath(shim_dir)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or os.path.realpath(d) == shim_dir:
            continue
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            if os.path.realpath(cand) == os.path.realpath(os.path.join(shim_dir, name)):
                continue
            return cand
    return None


def main(argv):
    name = os.path.basename(argv[0])
    shim_dir = os.path.dirname(os.path.abspath(argv[0]))
    real = find_real(name, shim_dir)
    if real is None:
        print(f"escrow-shim: {name} is not installed (no '{name}' on PATH after {shim_dir})",
              file=sys.stderr)
        return 127
    conf = load_agent(name)
    if os.environ.get("ESCROW_SESSION") or not conf["enabled"]:
        os.execv(real, [real] + argv[1:])
    escrow = os.environ.get("ESCROW_BIN", "/usr/bin/escrow")
    cmd = [escrow, "run", "--profile", conf["profile"]]
    for key in ("memory", "cpu", "tasks"):
        if key in conf:
            cmd += [f"--{key}", str(conf[key])]
    os.execv(escrow, cmd + ["--", real] + argv[1:])
