"""Turn bench/results.json into the report figures (greyscale, IEEE column width).

    python bench/plot.py          (needs matplotlib)  -> docs/report/fig*.png
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "docs", "report")
W = 3.4  # inches: one IEEE column

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.spines.top": False,
    "axes.spines.right": False, "savefig.dpi": 300, "savefig.bbox": "tight",
})


def results():
    with open(os.path.join(HERE, "results.json")) as f:
        return json.load(f)


def save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    fig.savefig(os.path.join(OUT, name))
    plt.close(fig)
    print("wrote", name)


def fig_arch():
    fig, ax = plt.subplots(figsize=(W, 3.5))
    ax.set_xlim(0, 10)
    ax.set_ylim(1.4, 12.4)
    ax.axis("off")

    def box(x, y, w, h, text, fc="white"):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                    fc=fc, ec="black", lw=0.6))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=5.4, linespacing=1.1)

    def arrow(x1, y1, x2, y2, label=None, dx=0.0):
        ax.annotate("", (x2, y2), (x1, y1), arrowprops=dict(arrowstyle="-|>", lw=0.6, color="black",
                                                          shrinkA=0, shrinkB=0))
        if label:
            ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + 0.2, label, fontsize=5, ha="center", style="italic")

    L, LW = 0.05, 4.7
    box(L, 11.1, LW, 1.1, "agent CLI (claude, codex, ...)\nstarted through a PATH shim", "#eeeeee")
    arrow(L + LW / 2, 11.1, L + LW / 2, 10.6)
    box(L, 9.2, LW, 1.4, "systemd user scope = cgroup v2\nMemoryMax, MemorySwapMax=0,\nCPUQuota, TasksMax")
    arrow(L + LW / 2, 9.2, L + LW / 2, 8.7)
    box(L, 5.9, LW, 2.8, "escrow-enter (P0, unprivileged)\nuser + mount + PID (+ net) namespaces\n"
        "overlayfs on /home /etc /opt /srv\ndecoys over ~/.ssh ~/.aws ...\nall else read-only, incl. cgroupfs")
    arrow(L + LW / 2, 5.9, L + LW / 2, 5.4)
    box(L, 3.9, LW, 1.5, "P1 = PID 1 of the namespace\nreaper + inotify tripwire\n(SIGSTOP all on decoy access)")
    arrow(L + LW / 2, 3.9, L + LW / 2, 3.4)
    box(L, 1.6, LW, 1.8, "P2 = the agent\nLandlock + no_new_privs\n+ seccomp-BPF (EPERM on\nptrace, mount, bpf, ...)", "#eeeeee")

    Rx, RW = 5.3, 4.65
    box(Rx, 10.2, RW, 2.0, "upper layer = staged changes\nnew/modified files, whiteouts\n(deletions), opaque dirs", "#dddddd")
    arrow(L + LW, 7.3, Rx, 10.6)
    ax.text(L + LW + 0.05, 9.4, "writes", fontsize=5, style="italic", ha="left")
    arrow(Rx + RW / 2, 10.2, Rx + RW / 2, 9.7)
    box(Rx, 7.3, RW, 2.4, "escrow diff / review\npolicy gate (risky paths)\nnetwork log (irreversible)\nlocal LLM summary (advisory)")
    hw = (RW - 0.25) / 2
    arrow(Rx + hw / 2, 7.3, Rx + hw / 2, 6.8)
    arrow(Rx + RW - hw / 2, 7.3, Rx + RW - hw / 2, 6.8)
    box(Rx, 4.7, hw, 2.1, "commit\nOCC check,\n3-way merge,\nrename()")
    box(Rx + RW - hw, 4.7, hw, 2.1, "discard\ndelete the\nupper layer")
    arrow(Rx + hw / 2, 4.7, Rx + hw / 2, 4.2)
    arrow(Rx + RW - hw / 2, 4.7, Rx + RW - hw / 2, 4.2)
    box(Rx, 1.6, hw, 2.6, "real files\n(lower layer;\nuntouched\nuntil commit)", "#dddddd")
    box(Rx + RW - hw, 1.6, hw, 2.6, "hash-chained\nledger\n(escrow\nverify)", "#eeeeee")
    save(fig, "fig1_architecture.png")


def fig_startup(R):
    s = R["startup"]
    names = ["coding", "coding --no-shield", "strict", "offline"]
    labels = ["coding", "coding,\nno shield", "strict", "offline"]
    med = [s[n]["median"] * 1000 for n in names]
    p95 = [s[n]["p95"] * 1000 for n in names]
    fig, ax = plt.subplots(figsize=(W, 1.8))
    bars = ax.bar(labels, med, color="#bbbbbb", edgecolor="black", lw=0.6, width=0.55)
    ax.errorbar(range(len(names)), med, yerr=[[0] * len(med), [p - m for p, m in zip(p95, med)]],
                fmt="none", ecolor="black", capsize=3, lw=0.7)
    for b, m in zip(bars, med):
        ax.text(b.get_x() + b.get_width() / 2, m / 2, f"{m:.0f}", ha="center", fontsize=7)
    ax.set_ylabel("Start-up + teardown (ms)")
    ax.set_xlabel("escrow profile")
    save(fig, "fig2_startup.png")


def fig_workloads(R):
    w = R["workloads"]
    names = list(w)
    label = {"cpu": "CPU-bound\n(Python loop)", "stat": "metadata\n(find /usr/share)",
             "write": "write 2000\nx 4 KB files"}
    bare = [w[n]["bare"]["median"] for n in names]
    esc = [w[n]["escrow"]["median"] for n in names]
    x = list(range(len(names)))
    fig, ax = plt.subplots(figsize=(W, 1.8))
    ax.bar([i - 0.18 for i in x], bare, 0.36, color="white", edgecolor="black", lw=0.6, label="bare")
    ax.bar([i + 0.18 for i in x], esc, 0.36, color="#888888", edgecolor="black", lw=0.6, label="inside escrow")
    for i, (b, e) in enumerate(zip(bare, esc)):
        ax.text(i - 0.18, b, f"{b:.2f}", ha="center", va="bottom", fontsize=6)
        ax.text(i + 0.18, e, f"{e:.2f}", ha="center", va="bottom", fontsize=6)
    ax.set_xticks(x)
    ax.set_xticklabels([label.get(n, n) for n in names])
    ax.set_ylabel("Wall time (s), median")
    ax.set_ylim(0, max(bare + esc) * 1.35)
    ax.legend(frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.12))
    save(fig, "fig3_workloads.png")


def fig_commit(R):
    c = R["commit"]
    ns = sorted(int(k) for k in c)
    fig, ax = plt.subplots(figsize=(W, 1.8))
    for key, style, lab in (("diff", "o--", "escrow diff --stat"), ("commit", "s-", "escrow commit"),
                            ("discard", "^:", "escrow discard")):
        ax.plot(ns, [c[str(n)][key]["median"] for n in ns], style, color="black", ms=4, lw=0.8, label=lab)
    ax.set_xscale("log")
    ax.set_xticks(ns)
    ax.set_xticklabels([str(n) for n in ns])
    ax.minorticks_off()
    ax.set_xlabel("Files staged by the agent (4 KB each)")
    ax.set_ylabel("Time (s), median")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False)
    save(fig, "fig4_commit.png")


if __name__ == "__main__":
    fig_arch()
    R = results()
    fig_startup(R)
    fig_workloads(R)
    fig_commit(R)
