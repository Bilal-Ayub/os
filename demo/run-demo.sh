#!/usr/bin/env bash
# Escrow OS demo: a rogue agent runs, the real files are untouched, the user
# reviews the diff, discards everything, then a second run commits one file.
#   usage: demo/run-demo.sh            (uses `escrow` on PATH, else the repo copy)
#          PAUSE=1 demo/run-demo.sh    (wait for Enter between steps, for live demos)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
D="${DEMO_DIR:-$HOME/escrow-demo}"
if command -v escrow >/dev/null && [ -z "${ESCROW_DEV:-}" ]; then ESCROW=(escrow)
else ESCROW=(sh "$HERE/../dev-escrow"); fi

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; [ -n "${PAUSE:-}" ] && read -r -p "(Enter) "; true; }
fingerprint() { (cd "$D" && find . -type f -exec sha256sum {} + | sort; sha256sum "$HOME/.bashrc") | sha256sum | cut -c1-16; }

step "1. Set up a demo home folder: $D"
rm -rf "$D"
mkdir -p "$D/notes" "$D/photos/2026" "$D/project"
echo "Bank PIN reminder: do not lose this file" > "$D/notes/important.txt"
head -c 4096 /dev/urandom > "$D/photos/2026/holiday.jpg"
printf 'def add(a, b):\n    return a + b\n' > "$D/project/calc.py"
touch "$HOME/.bashrc"
sleep 0.1
BEFORE=$(fingerprint)
find "$D" -type f | sort
echo "fingerprint of demo folder + ~/.bashrc: $BEFORE"

step "2. Run the rogue agent through escrow"
"${ESCROW[@]}" run -- "$HERE/rogue-agent.sh"
SID=$("${ESCROW[@]}" ls -q | tail -1)

step "3. The real files are untouched"
find "$D" -type f | sort
AFTER=$(fingerprint)
echo "fingerprint now: $AFTER"
[ "$BEFORE" = "$AFTER" ] && echo "UNCHANGED: nothing the agent did reached the disk" || { echo "CHANGED?!"; exit 1; }

step "4. What the agent tried to do (escrow diff)"
"${ESCROW[@]}" diff "$SID"

step "5. Session details, tripwire event and network activity (escrow log)"
"${ESCROW[@]}" log "$SID"

step "6. Try to commit everything: the policy gate refuses the ~/.bashrc change"
"${ESCROW[@]}" commit "$SID" --yes

step "7. Discard everything"
"${ESCROW[@]}" discard "$SID" --yes
"${ESCROW[@]}" ls

step "8. Second run: a useful agent edit plus junk; commit only the useful file"
"${ESCROW[@]}" run -- sh -c "printf 'def add(a, b):\n    \"\"\"Add two numbers.\"\"\"\n    return a + b\n' > '$D/project/calc.py'; echo junk > '$D/project/tmp.log'"
SID=$("${ESCROW[@]}" ls -q | tail -1)
"${ESCROW[@]}" diff "$SID" --stat
"${ESCROW[@]}" commit "$SID" "$D/project/calc.py" --yes
echo "--- calc.py on disk now:"; cat "$D/project/calc.py"
if [ -e "$D/project/tmp.log" ]; then echo "--- tmp.log on disk: yes"; else echo "--- tmp.log on disk: no (still pending in session $SID)"; fi
"${ESCROW[@]}" discard "$SID" --yes

step "9. Two agents edit the same README at the same time: the second commit is 3-way merged"
printf '# Demo project\n\nA tiny calculator.\n\n## Usage\nimport calc\n' > "$D/project/README.md"
sleep 0.1
"${ESCROW[@]}" run -- sed -i 's/A tiny calculator./A tiny, well-tested calculator./' "$D/project/README.md" 2>/dev/null
A=$("${ESCROW[@]}" ls -q | tail -1)
"${ESCROW[@]}" run -- sed -i 's/import calc/import calc\ncalc.add(2, 3)  # -> 5/' "$D/project/README.md" 2>/dev/null
B=$("${ESCROW[@]}" ls -q | tail -1)
echo "--- agent A (session $A) commits first:"; "${ESCROW[@]}" commit "$A" --yes | tail -1
echo "--- agent B (session $B) worked on the old version; its commit is merged:"; "${ESCROW[@]}" commit "$B" --yes | tail -2
echo "--- README.md on disk now:"; cat "$D/project/README.md"

step "10. Audit trail: hash-chained ledger, then verify the chain"
"${ESCROW[@]}" ledger -n 8
"${ESCROW[@]}" verify

step "Demo finished"
