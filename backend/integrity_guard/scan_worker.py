"""One document per isolated process; never imports or executes the document."""

import json
import os
import sys

_job_handle = None


def constrain_memory():
    global _job_handle
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    else:
        # Windows process memory ceiling using a Job Object. Keep the handle alive.
        import ctypes
        from ctypes import wintypes

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        _job_handle = kernel.CreateJobObjectW(None, None)
        limits = EXTENDED()
        limits.BasicLimitInformation.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        limits.ProcessMemoryLimit = 512 * 1024**2
        if not _job_handle or not kernel.SetInformationJobObject(_job_handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise RuntimeError("Cannot install scanner memory limit")
        if not kernel.AssignProcessToJobObject(_job_handle, kernel.GetCurrentProcess()):
            raise RuntimeError("Cannot isolate scanner process in job")


def main():
    constrain_memory()
    sandbox = {"active": False, "mechanism": "resource-limits", "limitations": ["Filesystem and network confinement is available on Linux only."]}
    if sys.platform == "linux":
        from integrity_guard.linux_sandbox import apply_sandbox, SandboxUnavailable
        try:
            sandbox = apply_sandbox()
        except SandboxUnavailable:
            sys.stderr.write("SANDBOX_UNAVAILABLE\n")
            return 70
    from integrity_guard.scanner import Scanner
    from integrity_guard.extractor_registry import get_registry
    # Explicit packaged bootstrap is repeated in every fresh confined worker.
    # Documents cannot register a handler or select an import path.
    get_registry()
    data = sys.stdin.buffer.read(10 * 1024**2 + 1)
    report = Scanner().scan_bytes(data, sys.argv[1])
    report["sandbox"] = sandbox
    sys.stdout.buffer.write(json.dumps(report, ensure_ascii=True, allow_nan=False).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
