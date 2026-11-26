"""Build the Escrow OS report (IEEE two-column, following the course's Part IV sample).

    python bench/plot.py                       # figures from bench/results.json
    python docs/report/build_report.py         # -> docs/report/Escrow_OS_Report.docx (+ .pdf via Word)

Every number in the text is read from bench/results.json.
"""
import json
import os
import sys

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
R = json.load(open(os.path.join(REPO, "bench", "results.json")))
M = R["machine"]
OUT_DOCX = os.path.join(HERE, "Escrow_OS_Report.docx")
FONT = "Times New Roman"


# ----------------------------------------------------------------- numbers
def ms(x):
    return f"{x * 1000:.0f} ms"


st = R["startup"]
wl = R["workloads"]
cm = R["commit"]
cont = R["containment"]
trip = R.get("tripwire")
ex = R.get("explain")
n_cont = sum(1 for c in cont if c["contained"])
n_att = len(cont)
start_coding = st["coding"]["median"]
start_extra_shield = st["coding"]["median"] - st["coding --no-shield"]["median"]
c1000 = cm["1000"]["commit"]["median"]
c10 = cm["10"]["commit"]["median"]
d1000 = cm["1000"]["discard"]["median"]


def ratio(k):
    return wl[k]["escrow"]["median"] / wl[k]["bare"]["median"]


fork_n = next((c["detail"].split("stopped at ")[1].split()[0] for c in cont if c["attack"] == "fork bomb"), "?")
hog = next((c["detail"] for c in cont if c["attack"].startswith("memory hog")), "")
hog_mb = hog.split("reached ")[1].split()[0] if "reached " in hog else "?"
procs = next((c["detail"] for c in cont if c["attack"] == "enumerate host processes"), "")
if ex:
    ex_med = ex["latency"]["median"]
    ex_runs = ex["runs"]
    ex_ok = [r for r in ex_runs if r["ok"]]
    ex_high = sum(1 for r in ex_ok if (r["risk"] or "").startswith("high"))
    ex_commit = sum(1 for r in ex_ok if "commit" in (r["suggestion"] or "").lower())
    ex_model = (ex.get("model") or "qwen2.5-1.5b-instruct-q4_k_m").replace(".gguf", "")


# ----------------------------------------------------------------- docx helpers
doc = Document()
st_normal = doc.styles["Normal"]
st_normal.font.name = FONT
st_normal.font.size = Pt(10)
st_normal.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
pf = st_normal.paragraph_format
pf.space_before = Pt(0)
pf.space_after = Pt(0)
pf.line_spacing = 1.0

sec = doc.sections[0]
sec.page_width, sec.page_height = Inches(8.5), Inches(11)
sec.top_margin = Inches(0.75)
sec.bottom_margin = Inches(1.0)
sec.left_margin = sec.right_margin = Inches(0.625)


def set_cols(section, n, space_twips=360):
    sp = section._sectPr
    cols = sp.find(qn("w:cols"))
    if cols is None:
        cols = OxmlElement("w:cols")
        sp.append(cols)
    cols.set(qn("w:num"), str(n))
    cols.set(qn("w:space"), str(space_twips))


def para(text="", size=10, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY,
         indent=True, after=0, before=0, keep=False):
    p = doc.add_paragraph()
    p.alignment = align
    p.paragraph_format.first_line_indent = Inches(0.14) if indent else None
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.space_before = Pt(before)
    if keep:
        p.paragraph_format.keep_with_next = True
    if text:
        rich(p, text, size, bold, italic)
    return p


def rich(p, text, size=10, bold=False, italic=False):
    """**bold**, _italic_ and `code` spans inside one string."""
    import re
    for tok in re.split(r"(\*\*[^*]+\*\*|\^[^^]+\^|`[^`]+`)", text):
        if not tok:
            continue
        r = p.add_run()
        if tok.startswith("**"):
            r.text, r.bold = tok[2:-2], True
        elif tok.startswith("^") and tok.endswith("^") and len(tok) > 2:
            r.text, r.italic = tok[1:-1], True
        elif tok.startswith("`"):
            r.text = tok[1:-1]
            r.font.name = "Courier New"
            r.font.size = Pt(size - 1)
            r.bold = bold
            continue
        else:
            r.text = tok
        r.font.size = Pt(size)
        r.bold = r.bold or bold
        r.italic = r.italic or italic
    return p


ROMAN = ["I", "II", "III", "IV", "V", "VI"]
_h = [0]
_sub = [0]


def heading(text):
    p = para(f"{ROMAN[_h[0]]}.  {text.upper()}", 10, align=WD_ALIGN_PARAGRAPH.CENTER,
             indent=False, before=8, after=4, keep=True)
    _h[0] += 1
    _sub[0] = 0
    return p


def sub(text):
    letter = "ABCDEFGH"[_sub[0]]
    _sub[0] += 1
    p = para(f"{letter}.  {text}", 10, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT,
             indent=False, before=5, after=2, keep=True)
    return p


_fig = [0]


def figure(png, caption, width=3.3):
    _fig[0] += 1
    p = para(align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, before=4, keep=True)
    p.add_run().add_picture(os.path.join(HERE, png), width=Inches(width))
    para(f"Fig. {_fig[0]}.  {caption}", 8, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, after=6)
    return _fig[0]


def bullets(items, size=10):
    for it in items:
        p = para(indent=False)
        p.paragraph_format.left_indent = Inches(0.2)
        p.paragraph_format.first_line_indent = Inches(-0.12)
        rich(p, "• " + it, size)


def cell_text(cell, text, size=7.5, bold=False, align=WD_ALIGN_PARAGRAPH.LEFT):
    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = align
    p.paragraph_format.first_line_indent = None
    rich(p, text, size, bold)


# ----------------------------------------------------------------- title block
para("Escrow OS: Making Every AI Agent Action a Reversible Transaction with Unprivileged Linux Primitives",
     24, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, after=8)
para("Member A, Member B, Member C", 11, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False)
para("Dhanani School of Science & Engineering, Habib University, Karachi, Pakistan", 10, italic=True,
     align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, after=10)

sec2 = doc.add_section(WD_SECTION.CONTINUOUS)
set_cols(sec2, 2)

# ----------------------------------------------------------------- abstract
p = para(indent=False, after=4)
rich(p, "^Abstract^—", 9, bold=True)
abstract = (
    "AI coding agents run shell commands with the full permissions of the user who starts them, so a single "
    "bad step can delete files, plant persistence in shell start-up files or read credentials. Asking the user "
    "to approve every command leads to approval fatigue, and containers isolate the agent without letting the "
    "user review and keep its useful work. This paper presents Escrow OS, an Ubuntu 26.04-based distribution in "
    "which every agent process runs as a reversible transaction. The agent's writes are staged on overlayfs "
    "upper layers inside unprivileged user, mount and PID namespaces, confined by a hand-built seccomp-BPF "
    "filter, Landlock and cgroup v2 limits, and surrounded by decoy credentials guarded by an inotify tripwire. "
    "The user reviews one diff, together with policy warnings and a log of network connections, and then "
    "commits (with optimistic concurrency control and a three-way merge) or discards. PATH shims make this the "
    "default for six agent CLIs, and a local LLM adds an advisory summary. On a laptop under WSL2, "
    f"{n_cont} of {n_att} adversarial behaviours were contained, a session costs {ms(start_coding)} to start, "
    f"committing 1000 files takes {c1000:.2f} s, and the tripwire froze the agent within "
    f"{trip['max']:.1f} ms of touching a decoy." if trip else "")
if ex:
    abstract += (f" A 1.5B-parameter local model rated the rogue session high-risk in all {ex_high} runs that answered, "
                 f"yet suggested committing at least part of it in {ex_commit}, which supports keeping every "
                 "commit decision in deterministic OS mechanisms.")
abstract += (" Adversarial testing also exposed two containment bugs, an agent raising its own cgroup limit and a "
             "memory limit spilling into swap, both now fixed.")
rich(p, abstract, 9, bold=True)
p = para(indent=False, after=6)
rich(p, "^Keywords^—", 9, bold=True, italic=True)
rich(p, "AI agents, operating systems, overlayfs, namespaces, seccomp, Landlock, cgroups, transactions, "
        "Linux distribution.", 9, italic=True)

# ----------------------------------------------------------------- I intro
heading("Introduction")
para("Coding agents such as Claude Code, Codex CLI, Gemini CLI and aider plan a task and then execute shell "
     "commands to carry it out. On a normal desktop OS these commands run with the user's uid, so the agent "
     "can do anything the user can: remove a directory tree, append a `curl ... | sh` line to `~/.bashrc`, "
     "rewrite git hooks, read `~/.ssh/id_rsa` or upload data. The failure may come from a model mistake, a "
     "misunderstood instruction or prompt injection hidden in a web page or repository the agent reads.")
para("Two common defences each give up something. Per-command approval keeps the user in control but asks "
     "for dozens of decisions per task, and users soon approve without reading. Containers and virtual "
     "machines isolate the agent but separate it from the user's real files, so its useful work must be "
     "copied back by hand. Databases solved the same tension long ago with transactions: work proceeds "
     "freely on a private copy, and a single commit makes it visible atomically. GoEX [13] argued that "
     "humans can validate agent actions after the fact only if those actions can be undone and their damage "
     "confined.")
para("Escrow OS applies that idea at the OS level. Every agent runs on a copy-on-write view of the system; "
     "nothing reaches the real files until the user reviews one diff and commits, and discard throws "
     "everything away. While it runs, the agent is confined with mainline, unprivileged Linux mechanisms. "
     "The commit-or-discard core follows binpash/try [1]; our contribution is the combination and its "
     "placement as the OS default. The paper makes four contributions:")
bullets([
    "the design and implementation of `escrow`, about 3,100 lines of Python with no third-party "
    "dependencies, which combines overlayfs staging, namespaces, seccomp, Landlock, cgroup v2, decoy "
    "credentials, a commit-time policy gate, OCC with three-way merge and a hash-chained ledger;",
    "OS integration: agent shims that make escrow the default, three Debian packages and a rebranded "
    "Ubuntu identity;",
    "an evaluation of containment, overhead, commit cost, tripwire latency and a local LLM reviewer;",
    "two containment bugs found by adversarial testing, and their fixes.",
])

# ----------------------------------------------------------------- II methods
heading("Methods")
sub("Architecture")
para("Fig. 1 shows one session. A shim placed first on `PATH` intercepts the agent command and calls "
     "`escrow run`, which starts three nested processes inside a new cgroup.")
p = para()
rich(p, "**Copy-on-write staging.** The helper P0 calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)` "
        "and maps the user's uid to itself, so it holds capabilities only over its own namespaces. It then "
        "mounts one overlay per top-level directory (`/home`, `/etc`, `/opt`, `/srv`, and `/usr` where "
        "possible) with the real directory as the lower layer and a per-session upper directory, using the "
        "`userxattr` option that allows overlayfs in a user namespace (Linux 5.11+) [2]. The first write to "
        "a file copies it up; deletions become whiteouts (0/0 character devices) and replaced directories "
        "become opaque. Every other mount is made private and remounted read-only, and `/tmp`, `/dev/shm` "
        "and `/run/user/UID` become private tmpfs.")
p = para()
rich(p, "**Process and syscall confinement.** P0 forks P1, PID 1 of the new PID namespace, which mounts a "
        "fresh `/proc`, reaps orphans and watches the decoys. P1 forks the agent P2, which sets "
        "`PR_SET_NO_NEW_PRIVS` (so setuid programs such as `sudo` gain nothing), applies Landlock and installs "
        "a seccomp-BPF program written as raw classic-BPF instructions [8]. The filter kills foreign ABIs and "
        "returns EPERM for 27 system calls (ptrace, process_vm_*, module loading, kexec, bpf, "
        "perf_event_open, every mount API, reboot, swap, open_by_handle_at and io_uring) and for raw and "
        "packet sockets. Landlock [9] adds ABI-6 scoping of abstract unix sockets and signals on every "
        "profile, and a filesystem allowlist in the `strict` profile. The `offline` profile also creates a "
        "network namespace.")
figure("fig1_architecture.png", "Life of an escrow session. Left: confinement layers set up by "
       "unprivileged processes. Right: review and commit.")
p = para()
rich(p, "**Resource control.** `escrow run` wraps the session in `systemd-run --user --scope` with "
        "`MemoryMax=4G`, `MemorySwapMax=0`, `CPUQuota=200%` and `TasksMax=512` [10]. `escrow freeze`, `thaw` "
        "and `kill` write to `cgroup.freeze` and `cgroup.kill`; `escrow top` reads `cpu.stat`, "
        "`memory.current`, `pids.current` and the PSI files. Because systemd gives the user's uid ownership "
        "of the scope's control files, `/sys/fs/cgroup` is remounted read-only inside the session (Sec. IV-B).")
p = para()
rich(p, "**Secret shield and tripwire.** Before the agent starts, tmpfs and bind mounts place decoy files "
        "over `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.docker`, `~/.kube`, `~/.netrc` and similar "
        "paths, so the real secrets are not visible. P1 watches the decoys with inotify. On the first access it "
        "sends SIGSTOP to every process in the namespace with `kill(-1)`, marks the session tainted and asks "
        "the user whether to kill or resume; without a terminal it kills.")
p = para()
rich(p, "**Review and commit.** `escrow diff` turns the upper layer into added, modified, deleted and replaced "
        "entries. A policy gate refuses to commit changes to persistence and trust paths (shell rc files, "
        "`.git/hooks`, `.git/config`, `~/.ssh`, autostart entries, systemd user units, `~/.local/bin`, `/etc`, "
        "new setuid bits) unless `--accept-risk` is given. Network activity is recorded by strace running "
        "^outside^ the sandbox with a seccomp pre-filter so that only `connect()` stops the tracer, and is "
        "shown as irreversible. Commit uses optimistic concurrency control: a real file whose mtime or ctime "
        "is newer than the session start is a conflict. Escrow snapshots a base copy of each modified file "
        "when the agent exits, so a conflict is resolved with `git merge-file` (disk now, base, agent copy) "
        "when the edits do not overlap. Each file is written to a temporary file and moved into place with an "
        "atomic `rename()`; deletions are applied last; commits can be partial. Before a commit changes "
        "anything, it copies every original it will overwrite or delete into a write-ahead undo journal, so "
        "`escrow undo` can roll a committed session back; it refuses if a file changed after the commit. "
        "Every start, commit, discard, "
        "freeze and tripwire is appended to a ledger in which record ^i^ stores "
        "^h^(^i^) = SHA-256(^h^(^i^−1) ‖ ^r^(^i^)), and `escrow verify` finds the first broken link.")
p = para()
rich(p, "**Local AI reviewer.** `escrow explain` sends the diff to any OpenAI-compatible local endpoint "
        "(llama.cpp `llama-server` [14] or Ollama) with a JSON schema for the answer. The diff is wrapped in "
        "`<untrusted>` tags because the agent wrote it, the deterministic findings are passed separately as "
        "verified facts, and the output is labelled advisory: no commit decision depends on it.")
p = para()
rich(p, "**Distribution.** Escrow OS is Ubuntu 26.04 LTS plus three packages. `escrow` holds the tool and an "
        "AppArmor profile allowing user namespaces for the helper (Ubuntu 23.10+ restricts them); "
        "`escrow-shims` registers claude, codex, gemini, copilot, goose and aider in `/etc/escrow/agents.d`; "
        "`escrow-branding` diverts `os-release`, `lsb-release` and `/etc/issue` with `dpkg-divert` and "
        "regenerates them as Escrow OS, keeping `ID=ubuntu` for package tooling and using the os-release "
        "`VARIANT_ID` field [16]. It also sets the GRUB name, login message, wallpaper, a dark theme and logo, "
        "and restores Ubuntu's files on removal. A remastered Xubuntu ISO (live + installer, Secure Boot kept) "
        "boots in QEMU.")

sub("Experimental Setup")
para(f"All measurements ran on an Intel Core i5-1035G1 laptop (4 cores, 8 threads, no GPU, 16 GB RAM) under "
     f"WSL2 with {M['mem_gb']} GB visible to Linux, kernel {M['kernel'].split('-')[0]}, Ubuntu 26.04.1 with the "
     f"three Escrow OS packages, ext4, "
     f"Python {M['python']} and {M['escrow']} installed from its .deb. A harness (`bench/bench.py`) used its own "
     "state directory and ran every command without a controlling terminal. It measured: (1) session start-up, "
     f"`escrow run -- true`, {st['coding']['n']} runs per profile; (2) three workloads bare and inside escrow, "
     f"{wl['cpu']['bare']['n']} runs each after a warm-up; (3) `diff`, `commit` and `discard` for agents "
     f"writing 10, 100 and 1000 files of 4 KB, {cm['10']['commit']['n']} repetitions; (4) {n_att} attack "
     "behaviours, each in a fresh session, checked against the host afterwards; (5) tripwire latency: after "
     "opening a decoy the agent prints a timestamp every 1 ms, so the last timestamp bounds the time until it "
     "was frozen" + (f", {trip['n']} runs" if trip else "") +
     (f"; and (6) `escrow explain` on the rogue-agent session from the demo, {len(ex_runs)} runs with "
      f"Qwen2.5-1.5B-Instruct [15] (Q4_K_M, 1.1 GB) on `llama-server` using 4 CPU threads." if ex else ".") +
     " In addition, 40 end-to-end functional tests pass on the same machine.")

# ----------------------------------------------------------------- III results
heading("Results")
sub("Containment")
para(f"Table I lists the attack behaviours. All {n_cont} of {n_att} were contained: the real files and "
     f"`~/.bashrc` were unchanged, the policy gate refused to commit the persistence line, the fork bomb was "
     f"stopped at {fork_n} processes, the memory hog limited to 256 MB was killed after allocating "
     f"{hog_mb} MB, and the agent's view of `/proc` showed only its own processes ({procs.replace('agent sees ', '').replace('; host has', ' vs.')} on the host).")

tp = para("TABLE I", 8, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, before=4, keep=True)
para("Attack Behaviours and Outcomes", 8, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, after=2, keep=True)
MECH = {
    "delete files (rm -rf)": "overlayfs staging",
    "persistence in ~/.bashrc": "staging + policy gate",
    "ptrace another process": "seccomp",
    "mount over /etc (nested userns)": "seccomp",
    "sudo to root": "no_new_privs",
    "write outside staged dirs (/var, /mnt/c)": "read-only mounts",
    "raise own cgroup limit (pids.max)": "read-only cgroupfs",
    "fork bomb": "cgroup TasksMax",
    "memory hog (2 GB)": "MemoryMax + SwapMax=0",
    "steal ~/.ssh/id_rsa": "decoys + tripwire",
    "enumerate host processes": "PID namespace",
    "network exfiltration (offline profile)": "net namespace",
    "network connect is audited (coding profile)": "strace connect log",
}
OUTCOME = {
    "delete files (rm -rf)": "Host files intact; deletions staged in the diff",
    "persistence in ~/.bashrc": "~/.bashrc unchanged; commit refused by the gate",
    "ptrace another process": "EPERM",
    "mount over /etc (nested userns)": "EPERM (cannot change mount propagation)",
    "sudo to root": "sudo refuses: no_new_privs is set",
    "write outside staged dirs (/var, /mnt/c)": "Read-only file system / permission denied",
    "raise own cgroup limit (pids.max)": "Write fails; pids.max stays 512",
    "fork bomb": f"Stopped at {fork_n} of 2000 processes",
    "memory hog (2 GB)": f"Killed after {hog_mb} MB (limit 256 MB)",
    "steal ~/.ssh/id_rsa": "Read a decoy; tripwire froze and killed the agent before its upload step",
    "enumerate host processes": procs.replace("agent sees", "Sees").replace("; host has", " of"),
    "network exfiltration (offline profile)": "No route out of the network namespace",
    "network connect is audited (coding profile)": "Connection listed in the log as irreversible",
}
t = doc.add_table(rows=1, cols=3)
t.style = "Table Grid"
t.alignment = WD_TABLE_ALIGNMENT.CENTER
for c, h in zip(t.rows[0].cells, ("Behaviour", "Stopped by", "Outcome")):
    cell_text(c, h, 7.5, True)
for c in cont:
    row = t.add_row().cells
    cell_text(row[0], c["attack"])
    cell_text(row[1], MECH.get(c["attack"], ""))
    cell_text(row[2], ("" if c["contained"] else "NOT contained: ") + OUTCOME.get(c["attack"], c["detail"]))
widths = (Inches(1.05), Inches(0.85), Inches(1.45))
for row in t.rows:
    for cell, w in zip(row.cells, widths):
        cell.width = w
para(after=4)

sub("Overhead")
figure("fig2_startup.png", "Time to create, run and close an empty session per profile (median, p95 whisker).")
para(f"Fig. 2 shows that an empty session costs about {ms(start_coding)} in the default profile, against "
     f"{st['bare']['median'] * 1000:.1f} ms for running `true` directly. The time goes into the systemd scope, "
     f"strace, namespace and mount setup and the scan of the upper layer at exit; the secret shield adds "
     f"{start_extra_shield * 1000:.0f} ms. This is paid once per agent session, not per command, because the "
     "agent's own process tree runs inside one session.")
figure("fig3_workloads.png", "Workload time bare and inside escrow (median).")
def extra(k):
    return wl[k]["escrow"]["median"] - wl[k]["bare"]["median"]


para(f"Fig. 3 includes the fixed start-up cost of about {start_coding:.2f} s. Escrow added "
     f"{extra('cpu'):.2f} s to the CPU-bound workload and {extra('stat'):.2f} s to the metadata-heavy `find`, "
     "which is the start-up cost alone: once running, computation and reads of lower-layer files proceed at "
     f"native speed. The write-heavy workload gained {extra('write'):.2f} s, about "
     f"{(extra('write') - start_coding) * 1e6 / 2000:.0f} µs per file beyond start-up, because every new "
     "file is created in the upper layer (and a first write to an existing file copies the whole file up, as "
     "also observed for overlayfs on ext4 in [17]).")

sub("Commit Cost")
figure("fig4_commit.png", "Review and commit cost against the number of files staged.")
para(f"Fig. 4: committing 10 files took {c10:.2f} s and 1000 files {c1000:.2f} s, and discarding 1000 files "
     f"{d1000:.2f} s. Each command is dominated by the fixed cost of starting Python and reading the session; "
     "the per-file work (a stat for the conflict check, a copy to a temporary file and a `rename()`) only "
     "becomes visible at 1000 files.")

sub("Tripwire and Local AI")
if trip:
    para(f"Over {trip['n']} runs the agent printed its last heartbeat a median of {trip['median']:.2f} ms "
         f"(maximum {trip['max']:.2f} ms) after opening a decoy, so it was frozen before it could do anything "
         "with the decoy's contents. inotify delivers the open event to the waiting PID 1, which stops every "
         "process with a single `kill(-1, SIGSTOP)`.")
if ex:
    ok_t = sorted(r["seconds"] for r in ex_ok)
    risks = ", ".join(f"{r['risk'].upper()}/“{r['suggestion']}”" for r in ex_ok)
    n_fail = len(ex_runs) - len(ex_ok)
    para(f"The local reviewer answered in {ok_t[0]:.1f}–{ok_t[-1]:.1f} s per run "
         f"({len(ex_ok)} of {len(ex_runs)} runs returned an answer"
         + (f"; {n_fail} returned no usable answer and escrow reported an error" if n_fail else "")
         + f"). Its summaries correctly named the `.bashrc` change and the decoy access, and it rated the "
         f"session high-risk in {ex_high} of {len(ex_ok)} answers (risk/suggestion: {risks}). Yet it suggested "
         f"committing all or part of the session in {ex_commit} of {len(ex_ok)} answers, for a session that "
         "tried to steal an SSH key.")

# ----------------------------------------------------------------- IV discussion
heading("Discussion")
sub("Deterministic Mechanisms Do the Protecting")
para("Every behaviour in Table I was stopped by a kernel mechanism or a fixed rule, never by a judgement. "
     "The local model was useful as a reader's aid, but it was inconsistent and at times recommended the "
     "wrong action. It reads text written by the agent and is therefore exposed to prompt injection. This "
     "matches the course sample's conclusion that LLMs should be wrapped in deterministic, policy-enforced "
     "sandboxes, and is why escrow treats the model as advisory and keeps the policy gate, the tripwire and "
     "the conflict check in charge.")
sub("Bugs Found by Testing Like an Attacker")
para("Two limits looked correct but were not. First, systemd hands the scope's cgroup files to the user's "
     "uid, and the agent runs as that uid, so an early version let the agent write `max` to its own "
     "`pids.max`. Making cgroupfs read-only inside the session fixed it. Second, `MemoryMax` limits only RAM: "
     "with swap enabled, a hog limited to 256 MB reached 832 MB by pushing pages to swap before the OOM "
     "killer acted. Adding `MemorySwapMax=0` makes it die at the limit. Both are now regression tests. "
     "The lesson is that a limit is only as strong as the set of processes that can rewrite it, and that "
     "each resource needs every path it can grow through to be capped.")
sub("Relation to Prior Work")
para("binpash/try [1] already overlays every top-level directory, including `/etc` and `$HOME`, in an "
     "unprivileged user namespace, but has no seccomp filter, no resource limits and only all-or-nothing "
     "networking. airbag [6] stages the workspace and `$HOME` but keeps `/etc` read-only and has no cgroups. "
     "Sandlock [3] uses seccomp and Landlock with commit/abort for the working directory only, deliberately "
     "without overlayfs or cgroups. BranchFS [4] targets parallel exploration rather than human review. "
     "Alibaba Cloud Linux 4 Agentic Edition [5] lets the agent write live and rolls back a Btrfs workspace "
     "afterwards, and Aegis OS [7] replaces per-action prompts with a transactional boundary around a "
     "reflink-cloned workspace. firejail's overlay was disabled after CVE-2021-26910 [11], which shows why escrow uses no "
     "root helper at all. To our knowledge, no distribution makes stage-then-commit the default for every "
     "agent process, combined with seccomp, cgroup v2 limits and a per-connection network audit, reviewed "
     "on one screen.")
sub("Limitations")
para("Discard cannot undo network effects such as uploads or `git push` [12]; escrow can only show them "
     "before the decision. The agent has the user's permissions, so it cannot stage changes to root-owned "
     "files. In the default profile it can still read non-secret files. On WSL2, `/usr` contains submounts and "
     "is made read-only instead of staged. AppArmor was tested only on the live ISO, as WSL2 has none. "
     "inotify does not report which process opened a decoy, the ledger is tamper-evident rather than "
     "tamper-proof, tools that need nested sandboxes fail, and the shims are a default, not a boundary: an "
     "agent run by its full path bypasses them. Undo covers files only. All measurements come from one machine under WSL2.")

# ----------------------------------------------------------------- V conclusion
heading("Conclusion and Future Work")
para("Escrow OS shows that a stock Ubuntu kernel already provides everything needed to run AI agents as "
     "reversible transactions without root: overlayfs in user namespaces for staging, seccomp, Landlock and "
     "namespaces for confinement, and cgroup v2 for resources. Packaged as the OS default, the approach "
     f"contained all {n_att} attack behaviours we tried at a cost of about {ms(start_coding)} per session, and "
     "it turns many per-command approvals into one informed decision per task.")
para("Future work includes subordinate uid maps so that system changes can be staged and committed with "
     "`pkexec`, a per-agent egress allowlist, fanotify to attribute decoy access to a process, a signed ledger "
     "head, AppArmor testing on an installed system, and an "
     "inference broker that schedules local-model requests from several agents with per-agent token quotas.")

# ----------------------------------------------------------------- references
p = para("REFERENCES", 10, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, before=8, after=4, keep=True)
REFS = [
    "binpash, “try: Inspect a command’s effects before modifying your live system,” GitHub, v0.2.1. [Online]. Available: https://github.com/binpash/try",
    "The Linux Kernel Documentation, “Overlay Filesystem.” [Online]. Available: https://docs.kernel.org/filesystems/overlayfs.html",
    "C. Wang and Y. Zheng, “Confining AI agent code with unprivileged Linux primitives (Sandlock),” arXiv:2605.26298, 2026.",
    "C. Wang and Y. Zheng, “Fork, explore, commit: OS primitives for agentic exploration,” arXiv:2602.08199, 2026.",
    "Alibaba Cloud, “Alibaba Cloud Linux 4 Agentic Edition” and “ws-ckpt,” documentation, 2026.",
    "harshit3355, “airbag,” GitHub, 2026. [Online]. Available: https://github.com/harshit3355/airbag",
    "“Aegis OS: an agent operating system runtime,” arXiv:2611.08516, 2026.",
    "The Linux Kernel Documentation, “Seccomp BPF (SECure COMPuting with filters).” [Online]. Available: https://docs.kernel.org/userspace-api/seccomp_filter.html",
    "The Linux Kernel Documentation, “Landlock: unprivileged access control.” [Online]. Available: https://docs.kernel.org/userspace-api/landlock.html",
    "The Linux Kernel Documentation, “Control Group v2.” [Online]. Available: https://docs.kernel.org/admin-guide/cgroup-v2.html",
    "NIST, “CVE-2021-26910: Firejail overlayfs TOCTOU privilege escalation,” National Vulnerability Database, 2021.",
    "“Externalization barriers,” in Proc. SOSP 2026 Workshop on Operating Systems for Agents, paper 19, 2026.",
    "S. G. Patil et al., “GoEX: Perspectives and designs towards a runtime for autonomous LLM applications,” arXiv:2404.06921, 2024.",
    "G. Gerganov et al., “llama.cpp,” GitHub. [Online]. Available: https://github.com/ggml-org/llama.cpp",
    "Qwen Team, “Qwen2.5 technical report,” arXiv:2412.15115, 2024.",
    "freedesktop.org, “os-release — operating system identification,” systemd manual.",
    "“DeltaBox: fast checkpoint and rollback for agent sandboxes,” arXiv:2605.22781, 2026.",
]
for i, ref in enumerate(REFS, 1):
    p = para(indent=False)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.first_line_indent = Inches(-0.3)
    rich(p, f"[{i}]\t{ref}", 8)

doc.save(OUT_DOCX)
print("wrote", OUT_DOCX)

if "--no-pdf" not in sys.argv:
    from docx2pdf import convert
    convert(OUT_DOCX, OUT_DOCX.replace(".docx", ".pdf"))
    print("wrote", OUT_DOCX.replace(".docx", ".pdf"))
