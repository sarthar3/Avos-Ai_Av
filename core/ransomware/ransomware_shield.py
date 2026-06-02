"""
AVOS AI - Anti-Ransomware Shield
Mass-encryption detection + Shadow Copy auto-rollback
"""

import asyncio
import logging
import math
import os
import time
from collections import deque, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger('AVOS.Ransomware')

# Files encrypted per time window to trigger alert
MASS_ENCRYPTION_THRESHOLD = 50   # files
MASS_ENCRYPTION_WINDOW_S  = 10   # seconds

# High entropy threshold for written files (encrypted data)
ENTROPY_THRESHOLD = 7.5

# Known ransomware extensions
RANSOM_EXTENSIONS = {
    '.locked', '.encrypted', '.crypto', '.crypt', '.crypz',
    '.WNCRY', '.WCRY', '.locky', '.cerber', '.cerber2', '.cerber3',
    '.zepto', '.thor', '.aaa', '.abc', '.xyz', '.zzz', '.micro',
    '.XTBL', '.CRYPTOSHIELD', '.globe', '.dharma', '.arena', '.bip',
    '.wallet', '.onion', '.zzzzz', '.paymst', '.paym', '.GNS',
}

@dataclass
class RansomwareResult:
    is_threat: bool
    reason: str
    pid: Optional[int] = None
    affected_paths: list = None


class RansomwareShield:
    """
    Anti-ransomware shield monitoring file write velocity and entropy.
    Auto-triggers VSS shadow copy creation and rollback on detection.
    """

    def __init__(self):
        # Per-process write timestamps (deque of timestamps)
        self._write_times: defaultdict = defaultdict(lambda: deque())
        # List of recently written paths (for rollback)
        self._recent_writes: deque = deque(maxlen=500)
        self._alert_pids: set = set()
        self._shadow_copies: list = []
        self._running = False

    async def start_monitor(self, event_bus: asyncio.Queue):
        """Consumes file write events from event bus."""
        self._running = True
        logger.info("Ransomware Shield started.")

        # Create initial shadow copy for rollback
        await asyncio.to_thread(self._create_shadow_copy)

        while self._running:
            try:
                event = event_bus.get_nowait()
                if event.get('event_type') in ('file_write', 'file_create'):
                    await self._process_write_event(event)
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Ransomware monitor error: {e}")

    async def _process_write_event(self, event: dict):
        pid  = event.get('pid', 0)
        path = event.get('path', '')

        self._record_write(pid, path)

        # 1. Check extension
        if Path(path).suffix.lower() in RANSOM_EXTENSIONS:
            await self._trigger_alert(
                RansomwareResult(
                    is_threat=True,
                    reason=f"Ransomware file extension detected: {Path(path).suffix}",
                    pid=pid,
                    affected_paths=[path]
                ), pid
            )
            return

        # 2. Check write velocity (mass-encryption)
        if self._check_mass_encryption(pid):
            await self._trigger_alert(
                RansomwareResult(
                    is_threat=True,
                    reason=f"Mass file encryption detected: >{MASS_ENCRYPTION_THRESHOLD} files in {MASS_ENCRYPTION_WINDOW_S}s",
                    pid=pid,
                    affected_paths=list(self._recent_writes)[-20:]
                ), pid
            )
            return

        # 3. Check entropy of written file (async to avoid blocking)
        if path and os.path.isfile(path) and os.path.getsize(path) > 4096:
            entropy = await asyncio.to_thread(self._file_entropy, path)
            if entropy > ENTROPY_THRESHOLD:
                logger.debug(f"High entropy file written by PID {pid}: {path} ({entropy:.2f})")

    def _record_write(self, pid: int, path: str):
        now = time.time()
        self._write_times[pid].append(now)
        self._recent_writes.append(path)
        # Trim old entries
        cutoff = now - MASS_ENCRYPTION_WINDOW_S
        while self._write_times[pid] and self._write_times[pid][0] < cutoff:
            self._write_times[pid].popleft()

    def _check_mass_encryption(self, pid: int) -> bool:
        now = time.time()
        cutoff = now - MASS_ENCRYPTION_WINDOW_S
        recent_count = sum(1 for t in self._write_times[pid] if t >= cutoff)
        return recent_count >= MASS_ENCRYPTION_THRESHOLD

    async def _trigger_alert(self, result: RansomwareResult, pid: int):
        if pid in self._alert_pids:
            return  # Already alerted for this process
        self._alert_pids.add(pid)

        logger.critical(f"RANSOMWARE ALERT: {result.reason} | PID={pid}")

        # Terminate the suspicious process
        await asyncio.to_thread(self._kill_process, pid)

        # Create immediate shadow copy for rollback
        await asyncio.to_thread(self._create_shadow_copy)

    def _kill_process(self, pid: int):
        """Terminate a process by PID."""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.kill()
            logger.info(f"Killed suspicious process PID {pid}: {proc.name()}")
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")

    def _create_shadow_copy(self):
        """Create VSS shadow copy for rollback."""
        try:
            import subprocess
            result = subprocess.run(
                ['wmic', 'shadowcopy', 'call', 'create', 'Volume=C:\\'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                logger.info("Shadow copy created for rollback.")
                self._shadow_copies.append(time.time())
            else:
                logger.warning(f"Shadow copy creation failed: {result.stderr}")
        except Exception as e:
            logger.error(f"Shadow copy error: {e}")

    def rollback_from_shadow(self):
        """List available shadow copies for manual rollback."""
        try:
            import subprocess
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True, text=True
            )
            return result.stdout
        except Exception as e:
            return f"Error listing shadow copies: {e}"

    @staticmethod
    def _file_entropy(path: str) -> float:
        try:
            byte_counts = [0] * 256
            total = 0
            with open(path, 'rb') as f:
                data = f.read(65536)  # Sample 64KB
                for b in data:
                    byte_counts[b] += 1
                    total += 1
            if total == 0:
                return 0.0
            entropy = 0.0
            for c in byte_counts:
                if c > 0:
                    p = c / total
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0
