"""Irreversible confinement for a fresh, single-threaded Linux scan worker.

Call before reading/parsing untrusted input, after applying the caller's resource
limits. This module never changes host settings or resource limits. A successful
return means both Landlock and a native-ABI seccomp allowlist are installed.
A SandboxUnavailable exception means the worker must exit; it may already be
partially restricted. Never call this from the API/monitor process.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import platform
import stat
import sys
import sysconfig
from collections.abc import Iterable

try:
    import fcntl
except ImportError:  # The read-only capability probe also works on other OSes.
    fcntl = None


class SandboxUnavailable(RuntimeError):
    """The requested boundary could not be installed; terminate this worker."""

    def __init__(self, message: str, *, partial: bool = False):
        super().__init__(message)
        self.partial = partial


# Native Linux UAPI numbers for the explicitly supported 64-bit architectures.
# Linux v6.6 asm-generic/unistd.h and arch/x86/entry/syscalls/syscall_64.tbl.
_SYSCALLS = {"x86_64": (444, 445, 446), "aarch64": (444, 445, 446)}
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_GET_SECCOMP = 21
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_READ_FILE = 1 << 2
_LANDLOCK_READ_DIR = 1 << 3
# ABI 3 includes all filesystem rights through TRUNCATE (bit 14).
_LANDLOCK_FS_ABI3 = (1 << 15) - 1
_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM
_SCMP_ACT_KILL_PROCESS = 0x80000000
_SCMP_FLTATR_ACT_BADARCH = 2
_SCMP_CMP_EQ = 4
_SCMP_CMP_MASKED_EQ = 7
# Pin allowed roots for worker lifetime (also required by WSL/9p dentries).
_ANCHOR_FDS: list[int] = []


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    # The kernel UAPI declares this structure packed (size 12, not 16).
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _ArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


# The default is EPERM, including unknown/new syscalls. No socket, exec, clone,
# fork, ptrace, process_vm_*, io_uring, mount, metadata-write, IPC or fd-dup APIs.
# Reads reach designated stdio pipes and newly opened Landlock-readable files;
# inherited descriptors are closed before enforcement. mmap cannot write a
# readonly fd. Landlock may permit reopening own anonymous pipes via /proc.
_READ_ONLY_SYSCALLS = (
    "read", "readv", "pread64", "preadv", "preadv2", "close", "close_range",
    "lseek", "fstat", "newfstatat", "stat", "lstat", "statx", "getdents64",
    "readlink", "readlinkat", "access", "faccessat", "faccessat2", "getcwd",
    "mmap", "mmap2", "mprotect", "munmap", "mremap", "brk", "madvise",
    "futex", "futex_time64", "clock_gettime", "clock_gettime64", "gettimeofday",
    "time", "clock_nanosleep", "clock_nanosleep_time64", "nanosleep",
    "sched_yield", "sched_getaffinity", "getrandom", "getpid", "getppid",
    "gettid", "getuid", "geteuid", "getgid", "getegid", "getresuid",
    "getresgid", "getgroups", "uname", "getrlimit", "ugetrlimit", "getrusage",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
    "restart_syscall", "poll", "ppoll", "ppoll_time64", "select", "pselect6",
    "pselect6_time64", "exit", "exit_group",
)


def _libc_and_numbers():
    machine = platform.machine().lower()
    if (sys.platform != "linux" or fcntl is None
            or ctypes.sizeof(ctypes.c_void_p) != 8 or machine not in _SYSCALLS):
        raise SandboxUnavailable("Sandbox requires native 64-bit Linux x86_64 or aarch64")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    return libc, _SYSCALLS[machine]


def _load_seccomp():
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        lib.seccomp_api_get.restype = ctypes.c_uint
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
        lib.seccomp_release.restype = None
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
        lib.seccomp_attr_set.restype = ctypes.c_int
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.c_int, ctypes.c_uint,
                                               ctypes.POINTER(_ArgCmp)]
        lib.seccomp_rule_add_array.restype = ctypes.c_int
    except (OSError, AttributeError) as exc:
        raise SandboxUnavailable("System libseccomp.so.2 is unavailable or incompatible") from exc
    if lib.seccomp_api_get() < 3:
        raise SandboxUnavailable("libseccomp/kernel API 3 or newer is required")
    return lib


def _landlock_abi(libc, numbers) -> int:
    result = libc.syscall(ctypes.c_long(numbers[0]), ctypes.c_void_p(),
                          ctypes.c_size_t(0), ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION))
    if result < 0:
        code = ctypes.get_errno()
        raise SandboxUnavailable(f"Landlock unavailable: {errno.errorcode.get(code, code)}")
    if result < 3:
        raise SandboxUnavailable(f"Landlock ABI {result} lacks the required ABI 3 filesystem rights")
    return int(result)


def probe_capabilities() -> dict:
    """Read-only availability probe; this does not claim that a worker is confined."""
    try:
        libc, numbers = _libc_and_numbers()
        abi = _landlock_abi(libc, numbers)
        seccomp = _load_seccomp()
        return {"available": True, "landlock_abi": abi,
                "libseccomp_api": seccomp.seccomp_api_get(), "error": None}
    except SandboxUnavailable as exc:
        return {"available": False, "landlock_abi": None,
                "libseccomp_api": None, "error": str(exc)}


def default_read_roots() -> tuple[Path, ...]:
    """Trusted runtime/package leaves, never cwd, all of sys.path, home or data."""
    paths: list[Path] = [Path(__file__).resolve().parent]
    for name in ("stdlib", "platstdlib", "purelib", "platlib"):
        value = sysconfig.get_path(name)
        if value:
            paths.append(Path(value))
    # PyInstaller onedir keeps its Python runtime/dependencies under _MEIPASS.
    if getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None):
        paths.append(Path(sys._MEIPASS))
    multiarch = sysconfig.get_config_var("MULTIARCH")
    if isinstance(multiarch, str) and multiarch and "/" not in multiarch:
        paths.extend((Path("/lib") / multiarch, Path("/usr/lib") / multiarch))
    paths.extend((Path("/lib64"), Path("/usr/lib64"), Path("/etc/ld.so.cache")))
    # Existing Python stdlib zip archives are runtime files, not parent grants.
    for prefix in {Path(sys.base_prefix), Path(sys.prefix)}:
        paths.append(prefix / "lib" / f"python{sys.version_info.major}{sys.version_info.minor}.zip")
    return _normalize_roots(path for path in paths if path.exists())


def _normalize_roots(read_roots: Iterable[os.PathLike | str]) -> tuple[Path, ...]:
    forbidden = {Path(p) for p in ("/", "/home", "/root", "/tmp", "/run", "/var",
                                   "/proc", "/sys", "/dev", "/etc", "/mnt", "/media")}
    normalized: list[Path] = []
    try:
        for value in read_roots:
            path = Path(value).resolve(strict=True)
            if path in forbidden or not (path.is_dir() or path.is_file()):
                raise SandboxUnavailable(f"Refusing broad or non-regular read root: {path}")
            if path not in normalized:
                normalized.append(path)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        if isinstance(exc, SandboxUnavailable):
            raise
        raise SandboxUnavailable("A trusted read root cannot be resolved") from exc
    if not normalized or len(normalized) > 64:
        raise SandboxUnavailable("Sandbox requires between 1 and 64 trusted read roots")
    return tuple(normalized)


def _check_worker_context():
    try:
        if len(os.listdir("/proc/self/task")) != 1:
            raise SandboxUnavailable("Landlock confinement requires a fresh single-threaded worker")
        # Current permissions alone are insufficient: r--s mappings opened from
        # O_RDWR descriptors can retain VM_MAYWRITE after those fds are closed.
        # Immutable locale caches also use r--s, but have no VmFlags 'mw'.
        import re
        permissions = None
        vm_flags = None
        mapping_count = 0

        def verify_mapping():
            if permissions is None:
                return
            if vm_flags is None:
                raise SandboxUnavailable("Cannot verify mapping write capabilities: VmFlags missing")
            shared = permissions[3] == "s" or bool({"sh", "ms"} & vm_flags)
            if shared and (permissions[1] == "w" or bool({"wr", "mw"} & vm_flags)):
                raise SandboxUnavailable("Worker has a pre-existing writable shared mapping or shared mapping with write capability")

        with open("/proc/self/smaps", encoding="utf-8") as mapping:
            for line in mapping:
                fields = line.split(None, 5)
                if fields and re.fullmatch(r"[0-9a-fA-F]+-[0-9a-fA-F]+", fields[0]):
                    verify_mapping()
                    if len(fields) < 5 or re.fullmatch(r"[r-][w-][x-][ps]", fields[1]) is None:
                        raise SandboxUnavailable("Cannot verify worker mapping permissions")
                    permissions = fields[1]
                    vm_flags = None
                    mapping_count += 1
                elif line.startswith("VmFlags:"):
                    if permissions is None or vm_flags is not None:
                        raise SandboxUnavailable("Cannot verify worker mapping capabilities")
                    vm_flags = set(line.partition(":")[2].split())
                    if not vm_flags:
                        raise SandboxUnavailable("Cannot verify mapping write capabilities: VmFlags empty")
        verify_mapping()
        if not mapping_count:
            raise SandboxUnavailable("Cannot verify worker mappings: smaps is empty")
        null_stat = os.stat(os.devnull)
        for descriptor in (0, 1, 2):
            info = os.fstat(descriptor)
            is_null = stat.S_ISCHR(info.st_mode) and info.st_rdev == null_stat.st_rdev
            if not stat.S_ISFIFO(info.st_mode) and not is_null:
                raise SandboxUnavailable("Worker stdin/stdout/stderr must be pipes or /dev/null")
            direction = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            expected = os.O_RDONLY if descriptor == 0 else os.O_WRONLY
            if direction != expected:
                raise SandboxUnavailable("Worker stdio pipe direction is invalid")
    except (OSError, UnicodeError) as exc:
        raise SandboxUnavailable("Cannot verify worker threads, mappings or standard descriptors") from exc


def _build_filter(lib):
    context = lib.seccomp_init(_SCMP_ACT_ERRNO_EPERM)
    if not context:
        raise SandboxUnavailable("Cannot allocate seccomp filter")

    def allow(name: str, comparisons: tuple[_ArgCmp, ...] = (), *, required: bool = False):
        number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        if number < 0:
            if required:
                raise SandboxUnavailable(f"Required syscall is not available for the native ABI: {name}")
            return
        array = (_ArgCmp * len(comparisons))(*comparisons) if comparisons else None
        result = lib.seccomp_rule_add_array(context, _SCMP_ACT_ALLOW, number, len(comparisons), array)
        if result != 0:
            raise SandboxUnavailable(f"Cannot add seccomp rule {name}: {result}")

    try:
        if lib.seccomp_attr_set(context, _SCMP_FLTATR_ACT_BADARCH, _SCMP_ACT_KILL_PROCESS) != 0:
            raise SandboxUnavailable("Cannot enforce seccomp native architecture checks")
        for syscall in _READ_ONLY_SYSCALLS:
            allow(syscall, required=syscall in {"read", "close", "mmap", "exit_group"})
        # Preserve exactly the designated output channels. No pwrite/sendfile,
        # fd duplication, pipe creation or socket APIs can repurpose them.
        for syscall in ("write", "writev"):
            for descriptor in (1, 2):
                allow(syscall, (_ArgCmp(0, _SCMP_CMP_EQ, descriptor, 0),), required=True)
        # Landlock denies writes too; this independently rejects write-capable
        # open flags and O_PATH handles. openat2 pointer arguments are not allowed.
        unsafe_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        unsafe_flags |= getattr(os, "O_PATH", 0) | (getattr(os, "O_TMPFILE", 0) & ~os.O_DIRECTORY)
        allow("open", (_ArgCmp(1, _SCMP_CMP_MASKED_EQ, unsafe_flags, 0),))
        allow("openat", (_ArgCmp(2, _SCMP_CMP_MASKED_EQ, unsafe_flags, 0),), required=True)
        for command in (fcntl.F_GETFD, fcntl.F_SETFD, fcntl.F_GETFL):
            allow("fcntl", (_ArgCmp(1, _SCMP_CMP_EQ, command, 0),), required=True)
        # Allow introspection of the already-installed restrictions, not changes.
        for command in (_PR_GET_NO_NEW_PRIVS, _PR_GET_SECCOMP):
            allow("prctl", (_ArgCmp(0, _SCMP_CMP_EQ, command, 0),), required=True)
        allow("prlimit64", (_ArgCmp(0, _SCMP_CMP_EQ, 0, 0),
                             _ArgCmp(2, _SCMP_CMP_EQ, 0, 0)))
        return context
    except BaseException:
        lib.seccomp_release(context)
        raise


def _build_landlock(libc, numbers, roots: tuple[Path, ...]) -> tuple[int, list[int]]:
    attributes = _RulesetAttr(_LANDLOCK_FS_ABI3)
    descriptor = libc.syscall(ctypes.c_long(numbers[0]), ctypes.byref(attributes),
                              ctypes.c_size_t(ctypes.sizeof(attributes)), ctypes.c_uint(0))
    if descriptor < 0:
        raise SandboxUnavailable(f"Cannot create Landlock ruleset: errno {ctypes.get_errno()}")
    anchors: list[int] = []
    try:
        for root in roots:
            expected = root.stat()
            parent = os.open(root, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            anchors.append(parent)
            actual = os.fstat(parent)
            if (expected.st_dev, expected.st_ino, stat.S_IFMT(expected.st_mode)) != (
                actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)
            ):
                raise SandboxUnavailable("A trusted read root changed during sandbox setup")
            rights = _LANDLOCK_READ_FILE
            if stat.S_ISDIR(actual.st_mode):
                rights |= _LANDLOCK_READ_DIR
            rule = _PathBeneathAttr(rights, parent)
            result = libc.syscall(ctypes.c_long(numbers[1]), ctypes.c_int(descriptor),
                                   ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                                   ctypes.byref(rule), ctypes.c_uint(0))
            if result != 0:
                raise SandboxUnavailable(f"Cannot add Landlock read root: errno {ctypes.get_errno()}")
        return int(descriptor), anchors
    except BaseException:
        for anchor in anchors:
            os.close(anchor)
        os.close(descriptor)
        raise


def _close_inherited_descriptors(keep: set[int]):
    # Called while still unrestricted and single-threaded. listdir closes its
    # temporary directory handle before returning the list.
    try:
        descriptors = [int(name) for name in os.listdir("/proc/self/fd") if name.isdigit()]
        for descriptor in descriptors:
            if descriptor > 2 and descriptor not in keep:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
    except OSError as exc:
        raise SandboxUnavailable("Cannot close inherited worker descriptors") from exc


def apply_sandbox(read_roots: Iterable[os.PathLike | str] | None = None) -> dict:
    """Install Landlock + seccomp or raise SandboxUnavailable and require exit.

    read_roots, when provided, is the complete trusted allowlist, not untrusted
    document input. Directories grant readonly descendants; files grant that leaf.
    Do not put secrets in these roots. stdin/out/err must already be pipe-backed
    (or /dev/null); all other inherited descriptors are closed. The caller must
    arrange a clean environment before process creation and keep its existing
    memory/CPU/wall-time/output caps. There is no unsandboxed fallback here.
    """
    libc, numbers = _libc_and_numbers()
    abi = _landlock_abi(libc, numbers)
    seccomp = _load_seccomp()
    roots = default_read_roots() if read_roots is None else _normalize_roots(read_roots)
    _check_worker_context()
    context = _build_filter(seccomp)
    ruleset = -1
    restricted = False
    anchors: list[int] = []
    try:
        ruleset, anchors = _build_landlock(libc, numbers, roots)
        _close_inherited_descriptors({ruleset, *anchors})
        # Recheck after preparation; no untrusted data has been parsed yet.
        _check_worker_context()
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise SandboxUnavailable(f"Cannot set NO_NEW_PRIVS: errno {ctypes.get_errno()}")
        if libc.syscall(ctypes.c_long(numbers[2]), ctypes.c_int(ruleset), ctypes.c_uint(0)) != 0:
            raise SandboxUnavailable(f"Cannot enforce Landlock ruleset: errno {ctypes.get_errno()}")
        restricted = True
        _ANCHOR_FDS.extend(anchors)
        anchors = []
        os.close(ruleset)
        ruleset = -1
        result = seccomp.seccomp_load(context)
        if result != 0:
            raise SandboxUnavailable(f"Cannot load seccomp allowlist: {result}", partial=True)
        return {
            "active": True,
            "mechanism": "landlock+seccomp",
            "landlock_abi": abi,
            "limitations": [
                "Only trusted runtime/package roots remain readable; do not store secrets there.",
                "File metadata and own anonymous stdio pipes remain visible; no namespace isolation.",
                "The caller must start a clean worker with a minimal environment before parsing input.",
                "Existing memory, CPU, wall-time and output limits remain the caller's responsibility.",
            ],
        }
    except SandboxUnavailable as exc:
        if restricted:
            exc.partial = True
        raise
    except (OSError, ValueError, AttributeError) as exc:
        raise SandboxUnavailable("Sandbox installation failed; terminate this worker",
                                 partial=restricted) from exc
    finally:
        for anchor in anchors:
            os.close(anchor)
        if ruleset >= 0:
            os.close(ruleset)
        seccomp.seccomp_release(context)
