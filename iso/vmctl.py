#!/usr/bin/env python3
"""Drive the boot-test VM through its QEMU monitor socket (stdlib only).

  vmctl.py shot FILE.ppm        screendump
  vmctl.py type 'text\\n'       type text (\\n = Enter)
  vmctl.py typefile FILE        type a file's contents verbatim
  vmctl.py key ctrl-alt-t      send one key combo
  vmctl.py cmd 'info status'    raw monitor command
"""
import os, socket, sys, time

SOCK = os.path.expanduser("~/iso-build/vm/mon.sock")

KEYS = {" ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal",
        "/": "slash", ".": "dot", ",": "comma", ";": "semicolon", "'": "apostrophe",
        "\\": "backslash", "[": "bracket_left", "]": "bracket_right", "`": "grave_accent"}
SHIFTED = {"_": "minus", "+": "equal", "?": "slash", ">": "dot", "<": "comma",
           ":": "semicolon", '"': "apostrophe", "|": "backslash", "{": "bracket_left",
           "}": "bracket_right", "~": "grave_accent", "!": "1", "@": "2", "#": "3",
           "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9", ")": "0"}


def monitor(cmds):
    s = socket.socket(socket.AF_UNIX)
    s.connect(SOCK)
    s.settimeout(2)
    out = b""
    def drain():
        nonlocal out
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
                if out.endswith(b"(qemu) "):
                    break
        except socket.timeout:
            pass
    drain()
    for c in cmds:
        s.sendall(c.encode() + b"\n")
        drain()
        time.sleep(0.03)
    s.close()
    return out.decode(errors="replace")


def keyname(ch):
    if ch.isalpha() and ch.isupper():
        return "shift-" + ch.lower()
    if ch.isalnum():
        return ch
    if ch in KEYS:
        return KEYS[ch]
    if ch in SHIFTED:
        return "shift-" + SHIFTED[ch]
    raise SystemExit(f"no key for {ch!r}")


def main():
    op, arg = sys.argv[1], sys.argv[2]
    if op == "shot":
        monitor([f"screendump {arg}"])
    elif op == "type":
        text = arg.encode().decode("unicode_escape")
        monitor([f"sendkey {keyname(c)}" for c in text])
    elif op == "typefile":
        with open(arg) as f:
            monitor([f"sendkey {keyname(c)}" for c in f.read()])
    elif op == "key":
        monitor([f"sendkey {arg}"])
    else:
        print(monitor([arg]))


main()
