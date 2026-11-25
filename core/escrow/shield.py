"""Secret shield and honeytoken tripwire.

The overlay stops an agent's *writes*, but it can still *read* everything you
can, e.g. your SSH keys, and upload them. Inside the session, escrow mounts a
private tmpfs over each credential directory (and binds a fake file over each
credential file). The agent sees believable decoys instead of your secrets.

Each decoy holds a per-session canary marker. PID 1 of the session watches
the decoys with inotify. If anything opens one, PID 1 stops every agent
process (SIGSTOP), records a "tripwire" event and marks the session tainted.
The user then chooses to kill or resume. With no terminal, it kills.

Nothing here touches the real files: the mounts exist only in the session's
private mount namespace.
"""

import ctypes
import os
import secrets
import struct

# (path relative to $HOME, kind, create the mount point if missing)
SHIELDED = [
    (".ssh", "dir", True),
    (".aws", "dir", True),
    (".gnupg", "dir", False),
    (".config/gh", "dir", False),
    (".docker", "dir", False),
    (".kube", "dir", False),
    (".azure", "dir", False),
    (".config/gcloud", "dir", False),
    (".netrc", "file", False),
    (".git-credentials", "file", False),
    (".pypirc", "file", False),
]


def _decoys(canary):
    """Decoy contents. Keys are paths relative to $HOME."""
    b64 = lambda n: secrets.token_urlsafe(n).replace("-", "A").replace("_", "B")
    key = "\n".join(b64(48)[:64] for _ in range(12))
    akid = "AKIA" + secrets.token_hex(8).upper()
    tok = "ghp_" + b64(27)[:36]
    return {
        ".ssh/id_rsa": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key}\n"
                       f"{canary}\n-----END OPENSSH PRIVATE KEY-----\n",
        ".ssh/id_ed25519": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key[:300]}\n"
                           f"{canary}\n-----END OPENSSH PRIVATE KEY-----\n",
        ".ssh/config": "Host prod-db\n    HostName 10.20.0.15\n    User deploy\n"
                       "    IdentityFile ~/.ssh/id_rsa\n",
        ".aws/credentials": f"[default]\naws_access_key_id = {akid}\n"
                            f"aws_secret_access_key = {b64(30)[:40]}\n# {canary}\n",
        ".aws/config": "[default]\nregion = eu-west-1\n",
        ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {tok}\n    user: dev\n"
                                f"    # {canary}\n",
        ".docker/config.json": '{"auths": {"https://index.docker.io/v1/": '
                               f'{{"auth": "{b64(30)}", "note": "{canary}"}}}}}}\n',
        ".kube/config": f"apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n"
                        f"    token: {b64(40)}  # {canary}\n",
        ".netrc": f"machine api.example.com login deploy password {b64(18)}  # {canary}\n",
        ".git-credentials": f"https://dev:{tok}@github.com\n",
        ".pypirc": f"[pypi]\nusername = __token__\npassword = pypi-{b64(40)}  # {canary}\n",
    }


def install(home, mount, tmpfs_flags, scratch):
    """Mount the shield (runs in P0, inside the session's mount namespace,
    after the overlays). `scratch` is a private tmpfs dir used to hold decoy
    files while they are bind-mounted. Returns (decoy paths to watch,
    mount points that had to be created in the overlay)."""
    canary = f"escrow-canary-{secrets.token_hex(6)}"
    contents = _decoys(canary)
    watched, created = [], []
    for rel, kind, create in SHIELDED:
        target = os.path.join(home, rel)
        exists = os.path.lexists(target)
        if kind == "dir":
            if exists and (os.path.islink(target) or not os.path.isdir(target)):
                continue
            if not exists:
                if not create:
                    continue
                os.makedirs(target, mode=0o700)
                created.append(target)
            mount("tmpfs", target, "tmpfs", tmpfs_flags, "mode=0700,size=1m")
            for name, text in contents.items():
                if os.path.dirname(name) == rel:
                    path = os.path.join(home, name)
                    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
                        f.write(text)
                    if not name.endswith(("config", "config.json")) or rel in (".docker", ".kube"):
                        watched.append(path)
        else:
            if not exists or not os.path.isfile(target) or os.path.islink(target):
                continue
            src = os.path.join(scratch, f"decoy-{secrets.token_hex(4)}")
            with open(os.open(src, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
                f.write(contents.get(rel, f"{canary}\n"))
            mount(src, target, None, 0x1000)  # MS_BIND
            os.unlink(src)  # the bind mount keeps the inode alive
            watched.append(target)
    return watched, created, canary


# ---------------------------------------------------------------- tripwire

IN_ACCESS = 0x1
IN_OPEN = 0x20
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000
_EVENT = struct.Struct("iIII")  # wd, mask, cookie, len


class Tripwire:
    """inotify watch on every decoy file (works through bind mounts because
    inotify watches inodes, not paths)."""

    def __init__(self, paths):
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        self.wd = {}
        for p in paths:
            wd = libc.inotify_add_watch(self.fd, os.fsencode(p), IN_OPEN | IN_ACCESS)
            if wd >= 0:
                self.wd[wd] = p

    def read(self):
        """Paths opened or read since the last call."""
        hits = []
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return hits
        i = 0
        while i + _EVENT.size <= len(data):
            wd, mask, _, n = _EVENT.unpack_from(data, i)
            i += _EVENT.size + n
            p = self.wd.get(wd)
            if p and p not in hits:
                hits.append(p)
        return hits
