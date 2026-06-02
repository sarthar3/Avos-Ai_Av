"""
AVOS AI - USB Monitor & Autorun Guard
Auto-scan USB drives + protect startup registry entries
"""

import asyncio
import logging
import winreg
import time
from typing import Callable

logger = logging.getLogger('AVOS.USB')

AUTORUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]


class USBMonitor:
    """Monitor for removable media insertion and auto-scan."""

    def __init__(self, on_usb_inserted: Callable):
        self.on_usb_inserted = on_usb_inserted
        self._known_drives: set = set()
        self._running = False

    async def start(self):
        self._running = True
        self._known_drives = self._get_removable_drives()
        logger.info(f"USB Monitor started. Current drives: {self._known_drives}")

        while self._running:
            try:
                current_drives = await asyncio.to_thread(self._get_removable_drives)
                new_drives = current_drives - self._known_drives

                for drive in new_drives:
                    logger.info(f"New USB drive detected: {drive}")
                    await self.on_usb_inserted(drive)

                self._known_drives = current_drives
            except Exception as e:
                logger.error(f"USB monitor error: {e}")

            await asyncio.sleep(3)  # Poll every 3 seconds

    def _get_removable_drives(self) -> set:
        """Get set of removable drive letters."""
        try:
            import win32api
            import win32file
            drives = set()
            for drive in win32api.GetLogicalDriveStrings().split('\x00'):
                if drive and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    drives.add(drive)
            return drives
        except ImportError:
            # Fallback: use subprocess
            import subprocess
            drives = set()
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'where', 'DriveType=2', 'get', 'DeviceID'],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and line.endswith(':'):
                    drives.add(line + '\\')
            return drives
        except Exception:
            return set()


class AutorunGuard:
    """Monitor Windows startup registry for unauthorized changes."""

    def __init__(self, on_change: Callable):
        self.on_change = on_change
        self._known_entries: dict = {}
        self._running = False

    async def start(self):
        self._running = True
        self._known_entries = self._get_all_autorun_entries()
        logger.info(f"Autorun Guard started. {len(self._known_entries)} entries tracked.")

        while self._running:
            try:
                current = await asyncio.to_thread(self._get_all_autorun_entries)

                # Find new/modified entries
                for key, value in current.items():
                    if key not in self._known_entries:
                        logger.warning(f"NEW autorun entry: [{key}] = {value}")
                        await self.on_change(key, value)
                    elif self._known_entries[key] != value:
                        logger.warning(f"MODIFIED autorun entry: [{key}] = {value}")
                        await self.on_change(key, value)

                self._known_entries = current
            except Exception as e:
                logger.error(f"Autorun guard error: {e}")

            await asyncio.sleep(10)  # Check every 10 seconds

    def _get_all_autorun_entries(self) -> dict:
        """Read all startup registry entries."""
        entries = {}
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, 'HKLM'),
            (winreg.HKEY_CURRENT_USER,  'HKCU'),
        ]

        for hive, hive_name in hives:
            for reg_path in AUTORUN_KEYS:
                try:
                    with winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                full_key = f"{hive_name}\\{reg_path}\\{name}"
                                entries[full_key] = value
                                i += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.debug(f"Registry read error {reg_path}: {e}")

        return entries

    def remove_autorun_entry(self, reg_path: str, name: str):
        """Remove a startup entry from the registry."""
        try:
            hive = winreg.HKEY_LOCAL_MACHINE
            with winreg.OpenKey(hive, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, name)
            logger.info(f"Removed autorun entry: {name}")
        except Exception as e:
            logger.error(f"Failed to remove autorun entry {name}: {e}")
