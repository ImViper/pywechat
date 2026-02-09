"""
Viper Hook Injector -- DLL injection via CreateRemoteThread + LoadLibraryW.
不修改 upstream 代码，通过 ctypes 调用 Win32 API。

Typical usage::

    from pyweixin.hook_injector import inject_dll, find_wechat_pid

    pid = find_wechat_pid()
    if pid:
        inject_dll(pid, r"C:\\path\\to\\pywechat_hook.dll")
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
from typing import Optional

import psutil

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------------------------------------------------------------------
# Find WeChat main process (mirrors upstream WeChatTools logic)
# ---------------------------------------------------------------------------

def find_wechat_pid() -> Optional[int]:
    """Return the PID of the WeChat main process (Weixin.exe, non-child)."""
    candidates = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if proc.info["name"] == "Weixin.exe":
            candidates.append(proc)
    # Main process has no --type argument in cmdline
    for proc in candidates:
        cmdline = proc.info.get("cmdline") or []
        if not any("--type" in arg for arg in cmdline):
            return proc.info["pid"]
    return None


# ---------------------------------------------------------------------------
# DLL injection
# ---------------------------------------------------------------------------

def inject_dll(pid: int, dll_path: str) -> bool:
    """Inject *dll_path* into process *pid* via CreateRemoteThread + LoadLibraryW.

    Returns True on success.
    """
    dll_path = os.path.abspath(dll_path)
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"DLL not found: {dll_path}")

    dll_bytes = (dll_path + "\0").encode("utf-16-le")

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError(f"OpenProcess failed for pid {pid} "
                       f"(error {ctypes.get_last_error()})")
    try:
        # Allocate memory in target for the DLL path string
        remote_mem = kernel32.VirtualAllocEx(
            h_process, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not remote_mem:
            raise OSError("VirtualAllocEx failed")

        # Write DLL path
        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            h_process, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(written)
        )
        if not ok:
            raise OSError("WriteProcessMemory failed")

        # Resolve LoadLibraryW address
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not load_library_addr:
            raise OSError("GetProcAddress(LoadLibraryW) failed")

        # Create remote thread
        thread_id = wt.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process,
            None,
            0,
            load_library_addr,
            remote_mem,
            0,
            ctypes.byref(thread_id),
        )
        if not h_thread:
            raise OSError(f"CreateRemoteThread failed (error {ctypes.get_last_error()})")

        # Wait for LoadLibraryW to finish
        kernel32.WaitForSingleObject(h_thread, INFINITE)

        # Cleanup
        kernel32.CloseHandle(h_thread)
        kernel32.VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE)
        return True
    finally:
        kernel32.CloseHandle(h_process)


# ---------------------------------------------------------------------------
# DLL ejection (FreeLibrary via remote thread)
# ---------------------------------------------------------------------------

DLL_NAME = "pywechat_hook.dll"


def _find_module_in_process(pid: int, module_name: str) -> Optional[int]:
    """Return the base address of *module_name* in process *pid*, or None."""
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            if module_name.lower() in m.path.lower():
                # psutil memory_maps().path is the file path; we need
                # the base address via ctypes enumeration instead.
                return _enum_module_base(pid, module_name)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return None


def _enum_module_base(pid: int, module_name: str) -> Optional[int]:
    """Enumerate loaded modules to find base address of *module_name*."""
    import ctypes.wintypes as wt2

    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return None
    try:
        h_mods = (ctypes.c_void_p * 1024)()
        cb_needed = wt2.DWORD()
        if not psapi.EnumProcessModulesEx(
            h_process, ctypes.byref(h_mods), ctypes.sizeof(h_mods),
            ctypes.byref(cb_needed), 0x03  # LIST_MODULES_ALL
        ):
            return None
        count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(count):
            mod_name = ctypes.create_unicode_buffer(260)
            psapi.GetModuleBaseNameW(h_process, h_mods[i], mod_name, 260)
            if mod_name.value.lower() == module_name.lower():
                return h_mods[i]
    finally:
        kernel32.CloseHandle(h_process)
    return None


def eject_dll(pid: int, module_name: str = DLL_NAME) -> bool:
    """Eject (FreeLibrary) the DLL from the target process."""
    h_mod = _find_module_in_process(pid, module_name)
    if h_mod is None:
        return False

    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False
    try:
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        free_library_addr = kernel32.GetProcAddress(h_kernel32, b"FreeLibrary")
        if not free_library_addr:
            return False

        thread_id = wt.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, free_library_addr, h_mod, 0,
            ctypes.byref(thread_id),
        )
        if not h_thread:
            return False
        kernel32.WaitForSingleObject(h_thread, INFINITE)
        kernel32.CloseHandle(h_thread)
        return True
    finally:
        kernel32.CloseHandle(h_process)


def is_dll_loaded(pid: int, module_name: str = DLL_NAME) -> bool:
    """Check if the DLL is loaded in the target process."""
    return _find_module_in_process(pid, module_name) is not None
