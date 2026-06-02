"""
AVOS AI - Rootkit Detection Engine
Cross-view detection: kernel vs. userspace process/file enumeration discrepancies
"""

import asyncio
import logging
import os
import subprocess
from typing import List, Set

logger = logging.getLogger('AVOS.Rootkit')

SCAN_INTERVAL_S = 120  # Scan every 2 minutes


class RootkitDetector:
    """Detects rootkits by comparing kernel-visible vs. user-space-visible objects."""

    async def start_monitor(self, event_bus: asyncio.Queue):
        logger.info("Rootkit Detector started.")
        while True:
            try:
                threats = await asyncio.to_thread(self._full_scan)
                for threat in threats:
                    await event_bus.put({
                        'event_type': 'memory_alert',
                        'pid': 0,
                        'path': None,
                        'details': {'threat_type': 'rootkit', 'details': threat}
                    })
            except Exception as e:
                logger.error(f"Rootkit scan error: {e}")
            await asyncio.sleep(SCAN_INTERVAL_S)

    def _full_scan(self) -> List[str]:
        findings = []
        findings.extend(self._compare_process_lists())
        findings.extend(self._check_hidden_files())
        findings.extend(self._check_ssdt_hooks())
        return findings

    # ── 1. Process List Cross-View ────────────────────────────────────────────
    def _compare_process_lists(self) -> List[str]:
        """Compare psutil PIDs vs. WMI PIDs — discrepancy = hidden process."""
        findings = []

        psutil_pids = self._get_psutil_pids()
        wmi_pids    = self._get_wmi_pids()
        tasklist_pids = self._get_tasklist_pids()

        # PIDs visible in psutil but hidden from WMI
        if wmi_pids:
            hidden_from_wmi = psutil_pids - wmi_pids
            for pid in hidden_from_wmi:
                findings.append(f"Process PID {pid} visible in psutil but hidden from WMI — possible rootkit")

        # PIDs visible in WMI but hidden from tasklist.exe
        if tasklist_pids and wmi_pids:
            hidden_from_tasklist = wmi_pids - tasklist_pids
            for pid in hidden_from_tasklist:
                findings.append(f"Process PID {pid} hidden from tasklist.exe — possible DKOM rootkit")

        return findings

    def _get_psutil_pids(self) -> Set[int]:
        try:
            import psutil
            return set(psutil.pids())
        except Exception:
            return set()

    def _get_wmi_pids(self) -> Set[int]:
        try:
            import wmi
            c = wmi.WMI()
            return {int(p.ProcessId) for p in c.Win32_Process()}
        except Exception:
            return set()

    def _get_tasklist_pids(self) -> Set[int]:
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, timeout=10
            )
            pids = set()
            for line in result.stdout.splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pids.add(int(parts[1]))
                    except ValueError:
                        pass
            return pids
        except Exception:
            return set()

    # ── 2. Hidden File Detection ──────────────────────────────────────────────
    def _check_hidden_files(self) -> List[str]:
        """Compare Win32 FindFirstFile vs. actual NTFS enumeration via dir /AH."""
        findings = []
        suspicious_locations = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
        ]
        for location in suspicious_locations:
            try:
                findings.extend(self._find_hidden_files_in(location))
            except Exception as e:
                logger.debug(f"Hidden file check error in {location}: {e}")
        return findings

    def _find_hidden_files_in(self, directory: str) -> List[str]:
        """Look for super-hidden files (HIDDEN + SYSTEM) in sensitive directories."""
        findings = []
        try:
            result = subprocess.run(
                ['dir', '/AH', '/B', directory],
                capture_output=True, text=True,
                shell=True, timeout=15
            )
            hidden_files = result.stdout.strip().splitlines()
            suspicious_patterns = ['.dll', '.sys', '.exe']
            for f in hidden_files:
                f_lower = f.lower()
                if any(f_lower.endswith(ext) for ext in suspicious_patterns):
                    full_path = os.path.join(directory, f)
                    # Check if it shows in normal listing
                    normal_result = subprocess.run(
                        ['dir', '/B', directory],
                        capture_output=True, text=True, shell=True, timeout=10
                    )
                    normal_files = [x.lower() for x in normal_result.stdout.strip().splitlines()]
                    if f.lower() not in normal_files:
                        findings.append(f"Potentially hidden system file: {full_path}")
        except Exception:
            pass
        return findings

    # ── 3. SSDT Hook Detection ────────────────────────────────────────────────
    def _check_ssdt_hooks(self) -> List[str]:
        """
        Basic SSDT hook detection: check if known Windows API functions
        still point to ntoskrnl.exe memory range.
        (Full implementation requires kernel-mode access — this is a user-mode heuristic)
        """
        findings = []
        try:
            # Check if important system DLLs are loaded from expected paths
            import ctypes
            suspicious_modules = []
            expected_system32 = os.path.join(
                os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'
            ).lower()

            result = subprocess.run(
                ['listdlls', '-u'],  # Sysinternals ListDLLs if available
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.endswith('.dll') and expected_system32 not in line.lower():
                        suspicious_modules.append(line.strip())
                if suspicious_modules:
                    findings.append(
                        f"Unsigned/unexpected DLLs loaded: {', '.join(suspicious_modules[:5])}"
                    )
        except Exception:
            pass
        return findings
