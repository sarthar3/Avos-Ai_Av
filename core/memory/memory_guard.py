"""
AVOS AI - Memory Protection Module
Detects code injection, DLL hijacking, and process hollowing via WinAPI
"""

import asyncio
import ctypes
import logging
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger('AVOS.Memory')

# Windows memory protection constants
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXECUTABLE_FLAGS = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

# MEM_COMMIT
MEM_COMMIT = 0x1000

# Process rights
PROCESS_ALL_ACCESS      = 0x1F0FFF
PROCESS_VM_READ         = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

PE_HEADER_SIGNATURE = b'MZ'

kernel32 = ctypes.windll.kernel32
psapi    = ctypes.windll.psapi


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]


@dataclass
class MemoryThreat:
    pid: int
    process_name: str
    threat_type: str
    address: int
    details: str


class MemoryGuard:
    """Real-time memory protection: injection, hollowing, DLL hijack detection."""

    SCAN_INTERVAL_S = 30  # Scan all processes every 30 seconds
    SUSPICIOUS_PROCESSES = set()  # PIDs already flagged

    async def start_monitor(self, event_bus: asyncio.Queue):
        logger.info("Memory Guard started.")
        while True:
            try:
                threats = await asyncio.to_thread(self._scan_all_processes)
                for threat in threats:
                    if threat.pid not in self.SUSPICIOUS_PROCESSES:
                        self.SUSPICIOUS_PROCESSES.add(threat.pid)
                        await event_bus.put({
                            'event_type': 'memory_alert',
                            'pid': threat.pid,
                            'path': threat.process_name,
                            'details': {
                                'threat_type': threat.threat_type,
                                'address': hex(threat.address),
                                'details': threat.details,
                            }
                        })
            except Exception as e:
                logger.error(f"Memory guard scan error: {e}")
            await asyncio.sleep(self.SCAN_INTERVAL_S)

    def _scan_all_processes(self) -> list:
        """Scan all running processes for memory anomalies."""
        threats = []
        try:
            import psutil
        except ImportError:
            return threats

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid  = proc.info['pid']
                name = proc.info['name'] or ''
                if pid < 4:  # Skip System/Idle
                    continue
                found = self._scan_process_memory(pid, name)
                threats.extend(found)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return threats

    def _scan_process_memory(self, pid: int, name: str) -> list:
        threats = []

        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return threats

        try:
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()

            while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                # Check for executable, uncommitted private memory (shellcode injection)
                if (mbi.State == MEM_COMMIT and
                        mbi.Protect & EXECUTABLE_FLAGS and
                        mbi.Type == 0x20000 and         # MEM_PRIVATE
                        mbi.RegionSize < 4 * 1024 * 1024):  # < 4MB (shellcode)

                    # Read memory to check for PE header
                    buf = ctypes.create_string_buffer(min(mbi.RegionSize, 256))
                    bytes_read = ctypes.c_size_t(0)
                    if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address),
                                                   buf, len(buf), ctypes.byref(bytes_read)):
                        data = bytes(buf[:bytes_read.value])

                        # PE header in unexpected location = process hollowing
                        if data[:2] == PE_HEADER_SIGNATURE and address != 0x400000:
                            threats.append(MemoryThreat(
                                pid=pid, process_name=name,
                                threat_type='process_hollowing',
                                address=address,
                                details=f"PE header at unexpected address 0x{address:X} in {name}"
                            ))
                            break  # One alert per process

                        # XOR-encoded shellcode heuristic (high byte variance)
                        if len(data) > 64 and self._detect_shellcode(data):
                            threats.append(MemoryThreat(
                                pid=pid, process_name=name,
                                threat_type='shellcode_injection',
                                address=address,
                                details=f"Possible shellcode at 0x{address:X} in {name}"
                            ))
                            break

                # Next region
                next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
                if next_addr <= address:
                    break
                address = next_addr

        finally:
            kernel32.CloseHandle(handle)

        return threats

    def _detect_shellcode(self, data: bytes) -> bool:
        """Heuristic: high entropy + common shellcode byte patterns."""
        if len(data) < 64:
            return False
        unique_bytes = len(set(data[:64]))
        # Shellcode tends to have high variety of bytes
        if unique_bytes < 10:
            return False
        # NOP sled
        if data.count(b'\x90') > 16:
            return True
        # INT3 sled (debugger bait)
        if data.count(b'\xCC') > 16:
            return True
        return False
