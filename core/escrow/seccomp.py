"""A hand-built seccomp-BPF filter (no libseccomp needed).

The kernel runs this small classic-BPF program on every system call the agent
makes. It sees `struct seccomp_data`:

    offset 0   int   nr                    system call number
    offset 4   u32   arch                  AUDIT_ARCH_* of the calling ABI
    offset 8   u64   instruction_pointer
    offset 16  u64   args[6]               (little-endian: low 32 bits first)

Denied calls fail with EPERM instead of killing the agent, so well-written
programs degrade gracefully. A foreign ABI (e.g. 32-bit int 0x80 or x32 on
x86_64) kills the process, because its syscall numbers mean different things.
"""

import ctypes
import errno
import platform
import struct

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

# classic BPF opcodes
BPF_LD_W_ABS = 0x20   # A = *(u32 *)(data + k)
BPF_JEQ_K = 0x15      # if A == k goto jt else jf
BPF_JGE_K = 0x35      # if A >= k goto jt else jf
BPF_AND_K = 0x54      # A &= k
BPF_RET_K = 0x06      # return k

AF_PACKET = 17
SOCK_RAW = 3

ARCHES = {
    "x86_64": {
        "audit_arch": 0xC000003E,
        "socket": 41,
        "deny": {
            "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
            "init_module": 175, "finit_module": 313, "delete_module": 176,
            "kexec_load": 246, "kexec_file_load": 320,
            "bpf": 321, "perf_event_open": 298,
            "mount": 165, "umount2": 166, "pivot_root": 155,
            "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
            "fsmount": 432, "fspick": 433, "mount_setattr": 442,
            "reboot": 169, "swapon": 167, "swapoff": 168,
            "open_by_handle_at": 304,
            "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        },
    },
    "aarch64": {
        "audit_arch": 0xC00000B7,
        "socket": 198,
        "deny": {
            "ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271,
            "init_module": 105, "finit_module": 273, "delete_module": 106,
            "kexec_load": 104, "kexec_file_load": 294,
            "bpf": 280, "perf_event_open": 241,
            "mount": 40, "umount2": 39, "pivot_root": 41,
            "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
            "fsmount": 432, "fspick": 433, "mount_setattr": 442,
            "reboot": 142, "swapon": 224, "swapoff": 225,
            "open_by_handle_at": 265,
            "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        },
    },
}
ARCHES["amd64"] = ARCHES["x86_64"]
ARCHES["arm64"] = ARCHES["aarch64"]


def _ins(code, k, jt=0, jf=0):
    return struct.pack("=HBBI", code, jt, jf, k)


def build_filter(machine=None):
    """Return (bytes of the BPF program, list of denied syscall names)."""
    machine = machine or platform.machine()
    if machine not in ARCHES:
        raise OSError(errno.ENOSYS, f"no seccomp table for architecture {machine}")
    a = ARCHES[machine]
    eperm = SECCOMP_RET_ERRNO | errno.EPERM
    prog = [
        _ins(BPF_LD_W_ABS, 4),                      # A = arch
        _ins(BPF_JEQ_K, a["audit_arch"], 1, 0),     # native ABI? skip the kill
        _ins(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        _ins(BPF_LD_W_ABS, 0),                      # A = syscall number
    ]
    if machine in ("x86_64", "amd64"):              # x32 ABI sets bit 30
        prog += [_ins(BPF_JGE_K, 0x40000000, 0, 1),
                 _ins(BPF_RET_K, SECCOMP_RET_KILL_PROCESS)]
    for nr in sorted(set(a["deny"].values())):
        prog += [_ins(BPF_JEQ_K, nr, 0, 1), _ins(BPF_RET_K, eperm)]
    socket_block = [
        _ins(BPF_LD_W_ABS, 16),                     # A = args[0] (domain)
        _ins(BPF_JEQ_K, AF_PACKET, 0, 1),
        _ins(BPF_RET_K, eperm),
        _ins(BPF_LD_W_ABS, 24),                     # A = args[1] (type | flags)
        _ins(BPF_AND_K, 0xF),
        _ins(BPF_JEQ_K, SOCK_RAW, 0, 1),
        _ins(BPF_RET_K, eperm),
    ]
    prog += [_ins(BPF_JEQ_K, a["socket"], 0, len(socket_block))]
    prog += socket_block
    prog += [_ins(BPF_RET_K, SECCOMP_RET_ALLOW)]
    names = sorted(a["deny"]) + ["socket(AF_PACKET)", "socket(SOCK_RAW)"]
    return b"".join(prog), names


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def set_no_new_privs():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, "prctl(PR_SET_NO_NEW_PRIVS)")


def install():
    """Install the filter on the calling process (inherited by all children)."""
    code, names = build_filter()
    buf = ctypes.create_string_buffer(code, len(code))
    prog = _SockFprog(len(code) // 8, ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    set_no_new_privs()  # lets an unprivileged process install a filter
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        e = ctypes.get_errno()
        raise OSError(e, "prctl(PR_SET_SECCOMP)")
    return names
